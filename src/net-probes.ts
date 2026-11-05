/**
 * The `net_enforced` capability probe. It stands up a real cage, listens on the
 * gateway port host-side, then measures from inside the sandbox that:
 *   - the gateway port is reachable,
 *   - a non-gateway port on the host is not,
 *   - an external host is not,
 *   - a DNS-style port is not.
 * Everything is torn down afterwards.
 */
import net from 'node:net';
import type { CapabilityProbe } from './preflight.js';
import type { CapabilityResult } from './report.js';
import { setupNetwork, teardownNetwork } from './net.js';
import { runInSandbox } from './launcher.js';
import { canLaunch } from './launcher-probes.js';

function connectivityScript(hostIp: string, gwPort: number, badPort: number): string {
  return [
    'reach() {',
    '  timeout 2 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null && echo "$3=OPEN" || echo "$3=closed"',
    '  exec 3>&- 2>/dev/null || true',
    '}',
    `reach ${hostIp} ${gwPort} gw`,
    `reach ${hostIp} ${badPort} bad`,
    'reach 1.1.1.1 443 ext',
    `reach ${hostIp} 53 dns`,
    // IPv6 loopback should be unusable (disabled in the ns).
    '(timeout 2 bash -c "exec 3<>/dev/tcp/::1/1" 2>/dev/null && echo v6=OPEN || echo v6=closed)',
  ].join('\n');
}

export function netEnforcedProbe(): CapabilityProbe {
  return {
    name: 'net_enforced',
    async run(): Promise<CapabilityResult> {
      const gwPort = 20000 + Math.floor(Math.random() * 10000);
      const badPort = gwPort + 1;
      const handle = await setupNetwork({ gatewayPorts: [gwPort] });
      const server = net.createServer((sock) => {
        // The sandbox probe RSTs the connection; swallow the reset.
        sock.on('error', () => {});
        sock.end('ok');
      });
      server.on('error', () => {});
      try {
        await new Promise<void>((resolve, reject) => {
          server.once('error', reject);
          server.listen(gwPort, handle.hostIp, () => resolve());
        });

        const r = await runInSandbox(connectivityScript(handle.hostIp, gwPort, badPort), {
          netns: handle.netns,
        });
        const out = r.stdout ?? '';
        const got = Object.fromEntries(
          out
            .trim()
            .split('\n')
            .map((l) => l.split('='))
            .filter((p) => p.length === 2)
            .map(([k, v]) => [k!.trim(), v!.trim()]),
        );

        const problems: string[] = [];
        if (got.gw !== 'OPEN') problems.push('gateway port not reachable');
        if (got.bad !== 'closed') problems.push('non-gateway host port reachable');
        if (got.ext !== 'closed') problems.push('external host reachable');
        if (got.dns !== 'closed') problems.push('DNS port reachable');
        if (got.v6 !== 'closed') problems.push('IPv6 reachable');

        if (problems.length > 0) return { status: 'fail', detail: problems.join('; ') };
        return { status: 'pass', detail: 'only the gateway port is reachable; no DNS/IPv6/egress' };
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
        await teardownNetwork(handle);
      }
    },
  };
}

export function canEnforceNet(): boolean {
  return canLaunch();
}
