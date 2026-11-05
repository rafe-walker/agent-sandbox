import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import {
  setupNetwork,
  teardownNetwork,
  cleanupStale,
  NET_PREFIX,
} from '../src/net.js';
import { netEnforcedProbe } from '../src/net-probes.js';
import { runInSandbox } from '../src/launcher.js';
import { requireCapsOrSkip } from './helpers/caps.js';

const run = requireCapsOrSkip();

function listNetns(): string[] {
  try {
    return execFileSync('ip', ['-o', 'netns', 'list'])
      .toString()
      .split('\n')
      .map((l) => l.split(/[ (]/)[0]?.trim() ?? '')
      .filter(Boolean);
  } catch {
    return [];
  }
}

function listTables(): string[] {
  try {
    return execFileSync('nft', ['list', 'tables']).toString().split('\n');
  } catch {
    return [];
  }
}

describe('validation (no caps needed)', () => {
  it('rejects empty and out-of-range gateway ports', async () => {
    await expect(setupNetwork({ gatewayPorts: [] })).rejects.toThrow(/at least one/);
    await expect(setupNetwork({ gatewayPorts: [0] })).rejects.toThrow(/invalid gateway port|requires root|requires Linux/);
    await expect(setupNetwork({ gatewayPorts: [70000] })).rejects.toThrow(/invalid gateway port|requires root|requires Linux/);
  });
});

describe.skipIf(!run)('network cage (requires root)', () => {
  it('sets up and tears down, leaving no resources', async () => {
    const h = await setupNetwork({ gatewayPorts: [20111] });
    expect(h.netns.startsWith(NET_PREFIX)).toBe(true);
    expect(h.vethHost.length).toBeLessThanOrEqual(15);
    expect(listNetns()).toContain(h.netns);
    expect(listTables().some((l) => l.includes(h.table))).toBe(true);

    await teardownNetwork(h);
    expect(listNetns()).not.toContain(h.netns);
    expect(listTables().some((l) => l.includes(h.table))).toBe(false);
  });

  it('is idempotent: setup after a stale same-id setup succeeds', async () => {
    const h1 = await setupNetwork({ gatewayPorts: [20112], attemptId: 'deadbeef' });
    // leak it (simulate crash: do not teardown), then set up the same id again
    const h2 = await setupNetwork({ gatewayPorts: [20112], attemptId: 'deadbeef' });
    expect(h2.netns).toBe(h1.netns);
    expect(listNetns().filter((n) => n === h2.netns).length).toBe(1);
    await teardownNetwork(h2);
  });

  it('cleanupStale removes leftover asbx_ resources', async () => {
    const h = await setupNetwork({ gatewayPorts: [20113], attemptId: 'cafe0001' });
    // simulate crash: do not tear down
    const cleaned = await cleanupStale();
    expect(cleaned.netns).toContain(h.netns);
    expect(listNetns()).not.toContain(h.netns);
    expect(listTables().some((l) => l.includes(h.table))).toBe(false);
  });

  it('only the gateway port is reachable; DNS/IPv6/external denied', async () => {
    const res = await netEnforcedProbe().run();
    expect(res.status, res.detail).toBe('pass');
  });

  it('positive control: with the drop rule removed, a bad port becomes reachable', async () => {
    const gwPort = 20550;
    const badPort = 20551;
    const h = await setupNetwork({ gatewayPorts: [gwPort] });
    const server = net.createServer((s) => {
      s.on('error', () => {});
      s.end('ok');
    });
    const badServer = net.createServer((s) => {
      s.on('error', () => {});
      s.end('bad');
    });
    try {
      await new Promise<void>((r) => server.listen(gwPort, h.hostIp, () => r()));
      await new Promise<void>((r) => badServer.listen(badPort, h.hostIp, () => r()));

      const script = (p: number) =>
        `timeout 2 bash -c "exec 3<>/dev/tcp/${h.hostIp}/${p}" 2>/dev/null && echo OPEN || echo closed`;

      // Baseline: bad port closed.
      const before = await runInSandbox(script(badPort), { netns: h.netns });
      expect(before.stdout?.trim()).toBe('closed');

      // Disable the protection: insert an accept for the bad port before drop.
      execFileSync('nft', [
        'insert',
        'rule',
        'inet',
        h.table,
        'input',
        'iifname',
        h.vethHost,
        'ip',
        'daddr',
        h.hostIp,
        'tcp',
        'dport',
        String(badPort),
        'accept',
      ]);
      const after = await runInSandbox(script(badPort), { netns: h.netns });
      expect(after.stdout?.trim()).toBe('OPEN');
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
      await new Promise<void>((r) => badServer.close(() => r()));
      await teardownNetwork(h);
    }
  });
});

describe.skipIf(!run)('concurrent cages get distinct subnets', () => {
  it('4 concurrent setups: unique /30s, and each sandbox reaches only its OWN gateway', async () => {
    const ids = ['ab000001', 'ab000002', 'ab000003', 'ab000004']; // same prefix
    const port = 20660;
    const handles = await Promise.all(ids.map((attemptId) => setupNetwork({ gatewayPorts: [port], attemptId })));
    const servers: net.Server[] = [];
    try {
      expect(new Set(handles.map((h) => h.hostIp)).size).toBe(ids.length);
      for (const [i, h] of handles.entries()) {
        const srv = net.createServer((s) => {
          s.on('error', () => {});
          s.end(`gw-${i}\n`);
        });
        srv.on('error', () => {});
        await new Promise<void>((r) => srv.listen(port, h.hostIp, () => r()));
        servers.push(srv);
      }
      for (const [i, h] of handles.entries()) {
        const r = await runInSandbox(
          `python3 -I -c "import socket;s=socket.create_connection(('${h.hostIp}',${port}),timeout=3);print(s.recv(64).decode().strip())" 2>&1 || echo FAIL`,
          { netns: h.netns },
        );
        expect(r.stdout?.trim()).toBe(`gw-${i}`);
      }
    } finally {
      for (const s of servers) await new Promise<void>((r) => s.close(() => r()));
      for (const h of handles) await teardownNetwork(h);
    }
  }, 60_000);
});

describe.skipIf(!run)('subnet lock crash recovery', () => {
  it('a lock left by a dead process is broken, not waited on', async () => {
    const { NET_LOCK_PATH } = await import('../src/net.js');
    const { spawnSync } = await import('node:child_process');
    const { writeFile, mkdir } = await import('node:fs/promises');
    const path = await import('node:path');
    const dead = spawnSync('/bin/true').pid!; // exited: its pid is not alive
    await mkdir(path.dirname(NET_LOCK_PATH), { recursive: true });
    await writeFile(NET_LOCK_PATH, String(dead), { flag: 'wx' });
    const t = Date.now();
    const h = await setupNetwork({ gatewayPorts: [20671] });
    expect(Date.now() - t).toBeLessThan(10_000);
    await teardownNetwork(h);
  });
});
