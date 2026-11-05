import { describe, it, expect } from 'vitest';
import {
  allocateWorker,
  releaseWorker,
  runInSandbox,
  buildBwrapArgs,
  makeReadableSource,
  cleanupDir,
  WORKER_PREFIX,
  type Worker,
} from '../src/launcher.js';
import { launcherProbes } from '../src/launcher-probes.js';
import { requireCapsOrSkip } from './helpers/caps.js';
import { execFileSync } from 'node:child_process';

const run = requireCapsOrSkip();

describe('buildBwrapArgs (pure, no caps needed)', () => {
  const worker: Worker = { name: 'asbx_wtest', uid: 60000, gid: 60000 };

  it('always unshares user/pid/ipc/uts and drops caps', () => {
    const a = buildBwrapArgs({ worker, command: ['/bin/true'] }, true);
    for (const f of ['--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts', '--unshare-net']) {
      expect(a).toContain(f);
    }
    expect(a).toContain('--die-with-parent');
    expect(a).toContain('--new-session');
    const capIdx = a.indexOf('--cap-drop');
    expect(a[capIdx + 1]).toBe('ALL');
    expect(a).toContain('--proc');
    expect(a).toContain('--dev');
    // no /run bind
    expect(a).not.toContain('/run');
  });

  it('omits --unshare-net when joining a prepared netns', () => {
    const a = buildBwrapArgs({ worker, command: ['/bin/true'], netns: 'asbx_ns' }, false);
    expect(a).not.toContain('--unshare-net');
  });

  it('binds the source read-only', () => {
    const a = buildBwrapArgs({ worker, command: ['/bin/true'], sourceDir: '/x' }, true);
    expect(a).toContain('/src');
  });
});

describe.skipIf(!run)('launcher (requires Linux + root + bwrap)', () => {
  it('allocates a worker with a PRIVATE group, not a shared one', async () => {
    const w = await allocateWorker();
    try {
      expect(w.name.startsWith(WORKER_PREFIX)).toBe(true);
      expect(w.uid).toBeGreaterThan(0);
      // the primary group name must equal the user name (private group)
      const grp = execFileSync('id', ['-gn', w.name]).toString().trim();
      expect(grp).toBe(w.name);
      // and must not be a well-known shared group
      expect(['docker', 'sudo', 'root', 'wheel']).not.toContain(grp);
    } finally {
      await releaseWorker(w);
    }
    // uid removed
    expect(() => execFileSync('id', ['-u', w.name], { stdio: 'ignore' })).toThrow();
  });

  it('runs a command, drops to the worker uid, isolates pid namespace', async () => {
    const r = await runInSandbox('id -u; echo pid=$$; ls /proc | grep -cE "^[0-9]+$"');
    expect(r.exitCode).toBe(0);
    const [uid, pidLine, procCount] = (r.stdout ?? '').trim().split('\n');
    expect(Number(uid)).not.toBe(0);
    expect(Number(pidLine?.replace('pid=', ''))).toBeLessThanOrEqual(10);
    expect(Number(procCount)).toBeLessThan(20);
    expect(r.survivors).toBe(0);
  });

  it('isolates the network (only loopback) by default', async () => {
    const r = await runInSandbox('ip -o addr 2>/dev/null | wc -l; ip -o addr 2>/dev/null');
    // only lo should be present
    expect(Number((r.stdout ?? '0').trim().split('\n')[0])).toBeLessThanOrEqual(2);
  });

  it('enforces a wall-clock kill on a hung process', async () => {
    const w = await allocateWorker();
    const start = Date.now();
    const r = await import('../src/launcher.js').then((m) =>
      m.launch({ worker: w, command: ['/bin/sh', '-c', 'sleep 60'], wallClockMs: 1500, capture: true }),
    );
    expect(r.timedOut).toBe(true);
    expect(Date.now() - start).toBeLessThan(10000);
    expect(r.survivors).toBe(0);
  });

  it('kills detached children with the PID namespace', async () => {
    const w = await allocateWorker();
    const r = await import('../src/launcher.js').then((m) =>
      m.launch({
        worker: w,
        // detach a child that would outlive the parent if the ns did not reap it
        command: ['/bin/sh', '-c', 'setsid sh -c "sleep 60" & echo spawned; sleep 0.3'],
        wallClockMs: 5000,
        capture: true,
      }),
    );
    expect(r.stdout).toMatch(/spawned/);
    // After teardown, nothing owned by the worker uid may survive.
    expect(r.survivors).toBe(0);
  });

  it('read-only source bind cannot be written', async () => {
    const src = await makeReadableSource({ 'data.txt': 'readable-content' });
    try {
      const r = await runInSandbox(
        'cat /src/data.txt; (echo x > /src/evil 2>/dev/null && echo WROTE) || echo readonly',
        { sourceDir: src },
      );
      expect(r.stdout).toMatch(/readable-content/);
      expect(r.stdout).toMatch(/readonly/);
      expect(r.stdout).not.toMatch(/WROTE/);
    } finally {
      await cleanupDir(src);
    }
  });
});

describe.skipIf(!run)('launcher capability probes', () => {
  it('uid_separated / pid_ns / mount_ns / fds_clean / creds_absent all pass', async () => {
    for (const probe of launcherProbes()) {
      const res = await probe.run();
      expect(res.status, `${probe.name}: ${res.detail}`).toBe('pass');
    }
  });
});

describe.skipIf(!run)('harness env never reaches ANY process in the sandbox', () => {
  it('no planted harness canary in any visible /proc/*/environ, cmdline or fd (incl. pid 1)', async () => {
    const { credScanScript, parseCredScan } = await import('../src/launcher-probes.js');
    const canary = 'asbx-harness-canary-' + Math.random().toString(36).slice(2);
    const prev = process.env.ASBX_HARNESS_CANARY;
    process.env.ASBX_HARNESS_CANARY = canary;
    try {
      const r = await runInSandbox(credScanScript(canary));
      const scan = parseCredScan(r.stdout ?? '');
      expect(scan, r.stdout).toBeDefined();
      expect(scan!.procs).toBeGreaterThan(0);
      expect(scan!.where).toBe('pid1=0 environ=0 cmdline=0 fd=0');
    } finally {
      if (prev === undefined) delete process.env.ASBX_HARNESS_CANARY;
      else process.env.ASBX_HARNESS_CANARY = prev;
    }
  });
});

describe.skipIf(!run)('synthetic /etc (no host DNS/config leaks)', () => {
  it('has passwd/group/nsswitch/hosts but no resolv.conf, shadow, or other host files', async () => {
    const r = await runInSandbox(
      [
        'for f in resolv.conf shadow hostname machine-id gshadow sudoers; do test -e /etc/$f && echo "LEAK:$f"; done',
        'for f in passwd group nsswitch.conf hosts; do test -e /etc/$f || echo "MISSING:$f"; done',
        'echo user=$(id -un)',
      ].join('\n'),
    );
    const out = r.stdout ?? '';
    expect(out).not.toMatch(/LEAK:/);
    expect(out).not.toMatch(/MISSING:/);
    expect(out).toMatch(/user=asbx_w[0-9a-f]+/);
  });
});

describe('shared invocation: production env is minimal (no caps needed)', () => {
  it('the spawn env for a production launch is exactly MINIMAL_ENV, with --clearenv', async () => {
    const { buildSandboxInvocation, MINIMAL_ENV } = await import('../src/launcher.js');
    process.env.ASBX_HARNESS_CANARY = 'asbx-harness-canary-static';
    try {
      const inv = buildSandboxInvocation({ worker: { name: 'asbx_wtest', uid: 60000, gid: 60000 }, command: ['/bin/true'] }, '/tmp/x');
      expect(inv.env).toEqual({ ...MINIMAL_ENV });
      expect(JSON.stringify(inv)).not.toContain('asbx-harness-canary-static');
      expect(inv.args).toContain('--clearenv');
    } finally {
      delete process.env.ASBX_HARNESS_CANARY;
    }
  });
});

describe.skipIf(!run)('creds scan positive control', () => {
  it('the all-process scan DOES see the canary when env cleaning is disabled', async () => {
    const { launchWith, allocateWorker: alloc } = await import('../src/launcher.js');
    const { credScanScript, parseCredScan } = await import('../src/launcher-probes.js');
    const canary = 'asbx-harness-canary-' + Math.random().toString(36).slice(2);
    process.env.ASBX_HARNESS_CANARY = canary;
    try {
      const w = await alloc();
      const r = await launchWith(
        { worker: w, command: ['/bin/sh', '-c', credScanScript(canary)] },
        { envClean: false },
        { capture: true },
      );
      const scan = parseCredScan(r.stdout ?? '');
      // The hit must come from environ (pid 1 included), not a self-match.
      expect(scan?.environ).toBeGreaterThan(0);
      expect(scan?.pid1).toBeGreaterThan(0);
      expect(scan?.cmdline).toBe(0);
    } finally {
      delete process.env.ASBX_HARNESS_CANARY;
    }
  });
});
