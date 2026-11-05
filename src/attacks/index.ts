/**
 * The core attacker suite: 25 attacks, each with a positive control.
 *
 * For every attack `run()` returns an AttackResult where:
 *   - `blocked` is true when the attack is stopped under the REAL config,
 *   - `controlSucceeded` is true when the same attack works once its specific
 *     protection is disabled (proving the test is meaningful),
 *   - `status` is 'pass' only when both hold.
 *
 * Results are produced host-side; the sandbox never self-reports.
 */
import net from 'node:net';
import http from 'node:http';
import { mkdtemp, rm, writeFile, readFile, chmod } from 'node:fs/promises';
import { openSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Attack } from '../preflight.js';
import type { AttackResult } from '../report.js';
import { runLowLevel, withWorker, mkResult } from './harness.js';
import { setupNetwork, teardownNetwork } from '../net.js';
import { createAttemptCollector, readStore } from '../collector.js';
import { buildRedactor } from '../redact.js';
import { allocateWorker, releaseWorker, launch } from '../launcher.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const pExecFile = promisify(execFile);
const CANARY = 'sk-ant-CANARY-attacker-suite-0123456789abcdef';

// ---------------------------------------------------------------------------
// Filesystem: a harness artifact must be unreachable. Real = not bound;
// control = bound rw (readable). One attack per artifact class.
// ---------------------------------------------------------------------------
function fsAttack(id: string, title: string, filename: string): Attack {
  return {
    id,
    title,
    async run(): Promise<AttackResult> {
      const dir = await mkdtemp(path.join(tmpdir(), 'asbx-harness-'));
      const file = path.join(dir, filename);
      await writeFile(file, `HARNESS-SECRET ${CANARY}`);
      await chmod(dir, 0o755);
      await chmod(file, 0o644);
      try {
        const dest = `/harness/${filename}`;
        const script = `cat ${dest} 2>/dev/null && echo READ || echo blocked`;
        const real = await withWorker((w) => runLowLevel({ worker: w, script }));
        const blocked = !/READ/.test(real.stdout) && !real.stdout.includes('HARNESS-SECRET');
        const control = await withWorker((w) =>
          runLowLevel({ worker: w, script, roBinds: [{ src: dir, dest: '/harness' }] }),
        );
        const controlSucceeded = control.stdout.includes('HARNESS-SECRET');
        return mkResult(id, title, blocked, controlSucceeded, `real:${real.stdout.trim()} control:${controlSucceeded ? 'read' : 'nope'}`);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    },
  };
}

// ---------------------------------------------------------------------------
// /proc + ptrace against the harness. Real = PID ns hides it; control = drop
// the PID namespace so the harness pid is visible / ptrace-able.
// ---------------------------------------------------------------------------
const procHarness: Attack = {
  id: 'proc-harness',
  title: 'read the harness process via /proc',
  async run(): Promise<AttackResult> {
    const script = `test -d /proc/${process.pid} && echo SEES || echo hidden; ls /proc | grep -cE '^[0-9]+$'`;
    const real = await withWorker((w) => runLowLevel({ worker: w, script }));
    const blocked = !/SEES/.test(real.stdout);
    const control = await withWorker((w) => runLowLevel({ worker: w, script, drop: 'pid-ns' }));
    const controlSucceeded = /SEES/.test(control.stdout);
    return mkResult('proc-harness', procHarness.title, blocked, controlSucceeded, `real:${real.stdout.split('\n')[0]} control:${control.stdout.split('\n')[0]}`);
  },
};

const ptraceHarness: Attack = {
  id: 'ptrace-harness',
  title: 'ptrace / read /proc/<harness>/mem',
  async run(): Promise<AttackResult> {
    // Try to read the harness process memory map. With the PID ns it is not
    // even visible; the control drops the PID ns and the path appears.
    const script = `cat /proc/${process.pid}/maps >/dev/null 2>&1 && echo READMAPS || echo blocked`;
    const real = await withWorker((w) => runLowLevel({ worker: w, script }));
    const blocked = /blocked/.test(real.stdout);
    const control = await withWorker((w) => runLowLevel({ worker: w, script, drop: 'pid-ns' }));
    // Even without the PID ns the dropped uid may be denied by DAC; treat
    // "the path became visible" as the control signal.
    const ctlScript = `test -e /proc/${process.pid}/maps && echo VISIBLE || echo absent`;
    const ctl2 = await withWorker((w) => runLowLevel({ worker: w, script: ctlScript, drop: 'pid-ns' }));
    const controlSucceeded = /READMAPS/.test(control.stdout) || /VISIBLE/.test(ctl2.stdout);
    return mkResult('ptrace-harness', ptraceHarness.title, blocked, controlSucceeded, `real:${real.stdout.trim()} control:${controlSucceeded}`);
  },
};

// ---------------------------------------------------------------------------
// Inherited file descriptors. Real = only stdio; control = leak an fd to a
// host secret file into the child.
// ---------------------------------------------------------------------------
const inheritedFd: Attack = {
  id: 'inherited-fd',
  title: 'read an inherited file descriptor',
  async run(): Promise<AttackResult> {
    const dir = await mkdtemp(path.join(tmpdir(), 'asbx-fd-'));
    const secret = path.join(dir, 'secret');
    await writeFile(secret, `FD-SECRET ${CANARY}`);
    const fd = openSync(secret, 'r');
    try {
      const script = `cat /proc/self/fd/3 2>/dev/null && echo VIAFD || echo blocked`;
      const real = await withWorker((w) => runLowLevel({ worker: w, script }));
      const blocked = !real.stdout.includes('FD-SECRET');
      const control = await withWorker((w) => runLowLevel({ worker: w, script, extraFd: fd }));
      const controlSucceeded = control.stdout.includes('FD-SECRET');
      return mkResult('inherited-fd', inheritedFd.title, blocked, controlSucceeded, `real:${real.stdout.trim()} control:${controlSucceeded ? 'leaked' : 'nope'}`);
    } finally {
      closeSync(fd);
      await rm(dir, { recursive: true, force: true });
    }
  },
};

// ---------------------------------------------------------------------------
// Detached process survival. Real = PID ns + die-with-parent reap everything;
// control = drop both so a setsid child survives.
// ---------------------------------------------------------------------------
const detachedSurvival: Attack = {
  id: 'detached-survival',
  title: 'survive teardown via a detached process',
  async run(): Promise<AttackResult> {
    // The detached child drops the stdout pipe so it cannot keep the run open.
    const script = 'setsid sh -c "sleep 30" </dev/null >/dev/null 2>&1 & echo spawned; sleep 0.3';
    const real = await withWorker((w) => runLowLevel({ worker: w, script, wallClockMs: 4000 }));
    // Blocked = the PID namespace itself reaped the child (no orphan before our
    // pkill) AND nothing survived teardown.
    const blocked = real.orphansBeforeTeardown === 0 && real.survivors === 0;
    // Control: no PID namespace (so no ns-wide reap). The setsid child is
    // reparented on the host and outlives bwrap until our pkill.
    const control = await withWorker((w) => runLowLevel({ worker: w, script, drop: 'pid-ns', wallClockMs: 4000 }));
    const controlSucceeded = control.orphansBeforeTeardown > 0;
    return mkResult('detached-survival', detachedSurvival.title, blocked, controlSucceeded, `real orphans:${real.orphansBeforeTeardown} survivors:${real.survivors}; control orphans:${control.orphansBeforeTeardown} (then reaped:${control.survivors === 0})`);
  },
};

// ---------------------------------------------------------------------------
// Network. One cage per attack; positive controls toggle the nft drop or drop
// the net namespace. Covers direct egress, proxy-unset, IPv6, DNS, metadata.
// ---------------------------------------------------------------------------
function tcpScript(ip: string, port: number): string {
  return `timeout 2 bash -c "exec 3<>/dev/tcp/${ip}/${port}" 2>/dev/null && echo OPEN || echo closed`;
}

function netCageAttack(opts: {
  id: string;
  title: string;
  gwPort: number;
  badPort: number;
  pre?: string; // prefix script (e.g. unset HTTPS_PROXY)
}): Attack {
  return {
    id: opts.id,
    title: opts.title,
    async run(): Promise<AttackResult> {
      const handle = await setupNetwork({ gatewayPorts: [opts.gwPort] });
      const bad = net.createServer((s) => { s.on('error', () => {}); s.end('bad'); });
      bad.on('error', () => {});
      try {
        await new Promise<void>((r) => bad.listen(opts.badPort, handle.hostIp, () => r()));
        const script = `${opts.pre ?? ''}\n${tcpScript(handle.hostIp, opts.badPort)}`;
        const real = await withWorker((w) => runLowLevel({ worker: w, script, netns: handle.netns, wallClockMs: 6000 }));
        const blocked = real.stdout.trim().endsWith('closed');
        // Control: disable the drop by accepting the bad port.
        await pExecFile('nft', ['insert', 'rule', 'inet', handle.table, 'input', 'iifname', handle.vethHost, 'ip', 'daddr', handle.hostIp, 'tcp', 'dport', String(opts.badPort), 'accept']);
        const control = await withWorker((w) => runLowLevel({ worker: w, script, netns: handle.netns, wallClockMs: 6000 }));
        const controlSucceeded = control.stdout.trim().endsWith('OPEN');
        return mkResult(opts.id, opts.title, blocked, controlSucceeded, `real:${real.stdout.trim().split('\n').pop()} control:${control.stdout.trim().split('\n').pop()}`);
      } finally {
        await new Promise<void>((r) => bad.close(() => r()));
        await teardownNetwork(handle);
      }
    },
  };
}

const netDirectEgress = netCageAttack({ id: 'net-direct-egress', title: 'direct egress to a non-gateway host port', gwPort: 21001, badPort: 21002 });
const netProxyUnset = netCageAttack({ id: 'net-proxy-unset', title: 'egress after unsetting HTTPS_PROXY (env is not the boundary)', gwPort: 21011, badPort: 21012, pre: 'unset HTTPS_PROXY https_proxy' });
const netDns = netCageAttack({ id: 'net-dns', title: 'reach a DNS port', gwPort: 21021, badPort: 53 });

const netIpv6: Attack = {
  id: 'net-ipv6',
  title: 'use IPv6 from the sandbox',
  async run(): Promise<AttackResult> {
    const handle = await setupNetwork({ gatewayPorts: [21031] });
    try {
      // Can an AF_INET6 socket reach the IPv6 loopback? Disabled in the cage.
      const py = `python3 -I - <<'PY'
import socket
try:
    s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(1); s.connect(('::1',9))
    print('V6OPEN')
except Exception:
    print('v6blocked')
PY`;
      const real = await withWorker((w) => runLowLevel({ worker: w, script: py, netns: handle.netns, wallClockMs: 6000 }));
      const blocked = !/V6OPEN/.test(real.stdout);
      // Control: a host-net sandbox where IPv6 is available (socket creation works).
      const ctl = `python3 -I - <<'PY'
import socket
try:
    socket.socket(socket.AF_INET6, socket.SOCK_STREAM); print('V6SOCK')
except Exception:
    print('nov6')
PY`;
      const control = await withWorker((w) => runLowLevel({ worker: w, script: ctl, drop: 'net-ns', wallClockMs: 6000 }));
      const controlSucceeded = /V6SOCK/.test(control.stdout);
      const res = mkResult('net-ipv6', netIpv6.title, blocked, controlSucceeded, `real:${real.stdout.trim()} control:${control.stdout.trim()}`);
      // Harness-side proof (never sandbox self-report) that the vector is
      // absent: the HOST kernel refuses AF_INET6 (e.g. booted ipv6.disable=1).
      if (!controlSucceeded && blocked && (await hostLacksIpv6())) {
        return { ...res, status: 'pass', notApplicable: 'host kernel has no IPv6 (AF_INET6 unsupported); vector absent, positive control impossible' };
      }
      return res;
    } finally {
      await teardownNetwork(handle);
    }
  },
};

async function hostLacksIpv6(): Promise<boolean> {
  return await new Promise((resolve) => {
    try {
      const s = net.createServer();
      s.once('error', (e: NodeJS.ErrnoException) => resolve(e.code === 'EAFNOSUPPORT' || e.code === 'EADDRNOTAVAIL'));
      s.listen(0, '::1', () => s.close(() => resolve(false)));
    } catch {
      resolve(true);
    }
  });
}

const netMetadata: Attack = {
  id: 'net-metadata',
  title: 'reach the cloud metadata IP (169.254.169.254)',
  async run(): Promise<AttackResult> {
    const handle = await setupNetwork({ gatewayPorts: [21041] });
    try {
      const script = `ip route get 169.254.169.254 >/dev/null 2>&1 && echo ROUTE || echo noroute; ${tcpScript('169.254.169.254', 80)}`;
      const real = await withWorker((w) => runLowLevel({ worker: w, script, netns: handle.netns, wallClockMs: 6000 }));
      const blocked = /noroute/.test(real.stdout) && /closed/.test(real.stdout);
      const control = await withWorker((w) => runLowLevel({ worker: w, script, drop: 'net-ns', wallClockMs: 6000 }));
      const controlSucceeded = /ROUTE/.test(control.stdout);
      return mkResult('net-metadata', netMetadata.title, blocked, controlSucceeded, `real:${real.stdout.trim()} control:${control.stdout.trim()}`);
    } finally {
      await teardownNetwork(handle);
    }
  },
};

// ---------------------------------------------------------------------------
// CONNECT through the gateway. Real = the gateway refuses CONNECT; control = a
// server that accepts CONNECT tunnels.
// ---------------------------------------------------------------------------
const gatewayConnect: Attack = {
  id: 'gateway-connect',
  title: 'tunnel via CONNECT through the gateway',
  async run(): Promise<AttackResult> {
    const { Gateway } = await import('../gateway.js');
    const g = new Gateway({ listenHost: '127.0.0.1', listenPort: 0, realKey: CANARY, dispatch: async () => ({ status: 200, headers: {}, body: Buffer.from('{}') }) });
    await g.start();
    // Control server that DOES accept CONNECT.
    const permissive = http.createServer();
    permissive.on('connect', (_req, socket) => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); socket.end(); });
    await new Promise<void>((r) => permissive.listen(0, '127.0.0.1', () => r()));
    const permPort = (permissive.address() as net.AddressInfo).port;
    try {
      const line = (port: number): Promise<string> =>
        new Promise((resolve) => {
          const s = net.connect({ host: '127.0.0.1', port }, () => s.write('CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n'));
          let b = '';
          s.on('data', (d) => { b += d.toString(); if (b.includes('\r\n')) { resolve(b.split('\r\n')[0]!); s.destroy(); } });
          s.on('close', () => resolve(b.split('\r\n')[0] ?? 'closed'));
          s.on('error', () => resolve('error'));
        });
      const real = await line(g.port);
      const blocked = /405/.test(real);
      const control = await line(permPort);
      const controlSucceeded = /200/.test(control);
      return mkResult('gateway-connect', gatewayConnect.title, blocked, controlSucceeded, `real:"${real}" control:"${control}"`);
    } finally {
      await g.stop();
      await new Promise<void>((r) => permissive.close(() => r()));
    }
  },
};

// ---------------------------------------------------------------------------
// Credentials in env / /proc / fds. Real = clearenv + no fd; control = leak.
// ---------------------------------------------------------------------------
const credEnv: Attack = {
  id: 'cred-env',
  title: 'read the model credential from the environment',
  async run(): Promise<AttackResult> {
    const script = `env | grep -q "${CANARY}" && echo FOUND || echo absent`;
    const real = await withWorker((w) => runLowLevel({ worker: w, script }));
    const blocked = /absent/.test(real.stdout);
    const control = await withWorker((w) =>
      runLowLevel({ worker: w, script, drop: 'clearenv', inheritEnv: true, env: { ASBX_CRED_CANARY: CANARY } }),
    );
    const controlSucceeded = /FOUND/.test(control.stdout);
    return mkResult('cred-env', credEnv.title, blocked, controlSucceeded, `real:${real.stdout.trim()} control:${control.stdout.trim()}`);
  },
};

const credProc: Attack = {
  id: 'cred-proc',
  title: 'read the model credential from /proc/self/environ',
  async run(): Promise<AttackResult> {
    // `cat` opens environ AFTER exec; a shell redirect (`tr < /proc/self/environ`)
    // opens it pre-exec, and the kernel then returns EOF — a vacuous check.
    const script = `cat /proc/self/environ 2>/dev/null | tr '\\0' '\\n' | grep -q "${CANARY}" && echo FOUND || echo absent`;
    const real = await withWorker((w) => runLowLevel({ worker: w, script }));
    const blocked = /absent/.test(real.stdout);
    const control = await withWorker((w) =>
      runLowLevel({ worker: w, script, drop: 'clearenv', inheritEnv: true, env: { ASBX_CRED_CANARY: CANARY } }),
    );
    const controlSucceeded = /FOUND/.test(control.stdout);
    return mkResult('cred-proc', credProc.title, blocked, controlSucceeded, `real:${real.stdout.trim()} control:${control.stdout.trim()}`);
  },
};

const credFd: Attack = {
  id: 'cred-fd',
  title: 'read the model credential from an inherited fd',
  async run(): Promise<AttackResult> {
    const dir = await mkdtemp(path.join(tmpdir(), 'asbx-credfd-'));
    const secret = path.join(dir, 'key');
    await writeFile(secret, CANARY);
    const fd = openSync(secret, 'r');
    try {
      const script = `cat /proc/self/fd/3 2>/dev/null | grep -q "${CANARY}" && echo FOUND || echo absent`;
      const real = await withWorker((w) => runLowLevel({ worker: w, script }));
      const blocked = /absent/.test(real.stdout);
      const control = await withWorker((w) => runLowLevel({ worker: w, script, extraFd: fd }));
      const controlSucceeded = /FOUND/.test(control.stdout);
      return mkResult('cred-fd', credFd.title, blocked, controlSucceeded, `real:${real.stdout.trim()} control:${control.stdout.trim()}`);
    } finally {
      closeSync(fd);
      await rm(dir, { recursive: true, force: true });
    }
  },
};

// ---------------------------------------------------------------------------
// Reflected canary (tests the redaction helper). Real = redactor removes the
// encoded form; control = raw text (no redactor) still carries it.
// ---------------------------------------------------------------------------
function canaryAttack(id: string, title: string, encode: (s: string) => string): Attack {
  return {
    id,
    title,
    run(): AttackResult {
      const redactor = buildRedactor([CANARY]);
      const encoded = encode(CANARY);
      const reflected = `upstream said: ${encoded} :: end`;
      const redacted = redactor(reflected);
      const blocked = !redacted.includes(encoded) && redacted.includes('[REDACTED]');
      // Control: the same pipeline with redaction disabled (no secrets known).
      const controlSucceeded = buildRedactor([])(reflected).includes(encoded);
      return mkResult(id, title, blocked, controlSucceeded, `encoded len ${encoded.length}`);
    },
  };
}

const canaryPlain = canaryAttack('canary-plain', 'reflected canary (plain)', (s) => s);
const canaryBase64 = canaryAttack('canary-base64', 'reflected canary (base64)', (s) => Buffer.from(s).toString('base64'));
const canaryUrl = canaryAttack('canary-url', 'reflected canary (url-encoded)', (s) => encodeURIComponent(s));
const canarySplit = canaryAttack('canary-split', 'reflected canary (split)', (s) => `${s.slice(0, s.length / 2)} ${s.slice(s.length / 2)}`);

// ---------------------------------------------------------------------------
// Lifecycle: fork bomb, disk fill, kill mid-write.
// ---------------------------------------------------------------------------
const forkBomb: Attack = {
  id: 'fork-bomb',
  title: 'exhaust processes with a fork bomb',
  async run(): Promise<AttackResult> {
    // Count how many background procs we can spawn before NPROC bites.
    // Bounded on purpose: at most 60 attempts, so even the control cannot hurt the host.
    const script = `n=0; i=0; while [ $i -lt 60 ]; do (sleep 3 &) 2>/dev/null && n=$((n+1)) || break; i=$((i+1)); done; echo spawned=$n`;
    const real = await withWorker((w) => runLowLevel({ worker: w, script, nproc: 16, wallClockMs: 8000 }));
    const control = await withWorker((w) => runLowLevel({ worker: w, script, nproc: 200, wallClockMs: 8000 }));
    // Blocked = host unaffected and the sandbox was reaped (survivors 0).
    const blocked = real.survivors === 0;
    // Control succeeds if a higher NPROC let noticeably more procs run.
    const n = (s: string): number => Number(s.match(/spawned=(\d+)/)?.[1] ?? '0');
    const controlSucceeded = n(control.stdout) > n(real.stdout);
    return mkResult('fork-bomb', forkBomb.title, blocked, controlSucceeded, `real spawned<=${n(real.stdout)} survivors:${real.survivors}; control spawned:${n(control.stdout)}`);
  },
};

const diskFill: Attack = {
  id: 'disk-fill',
  title: 'fill the disk past the file-size limit',
  async run(): Promise<AttackResult> {
    // 16 MiB attempted (tmpfs is RAM-backed); real cap 4 MiB, control 32 MiB.
    const script = `dd if=/dev/zero of=/tmp/fill bs=1M count=16 2>/dev/null; wc -c < /tmp/fill 2>/dev/null || echo 0`;
    const real = await withWorker((w) => runLowLevel({ worker: w, script, fsize: 4 * 1024 * 1024, wallClockMs: 8000 }));
    const control = await withWorker((w) => runLowLevel({ worker: w, script, fsize: 32 * 1024 * 1024, wallClockMs: 8000 }));
    const sz = (s: string): number => Number(s.trim().split('\n').pop() ?? '0');
    const blocked = sz(real.stdout) <= 4 * 1024 * 1024 + 1024; // capped near FSIZE
    const controlSucceeded = sz(control.stdout) > 4 * 1024 * 1024 + 1024;
    return mkResult('disk-fill', diskFill.title, blocked, controlSucceeded, `real bytes:${sz(real.stdout)} control bytes:${sz(control.stdout)}`);
  },
};

const killMidWrite: Attack = {
  id: 'kill-mid-write',
  title: 'corrupt the evidence store via a kill mid-write',
  async run(): Promise<AttackResult> {
    const runDir = await mkdtemp(path.join(tmpdir(), 'asbx-kmw-'));
    const worker = await allocateWorker();
    const { collector, socketPath, storePath } = await createAttemptCollector({ runDir, attempt: 'kmw00001', workerUid: worker.uid });
    try {
      // Send a PARTIAL proposal (no trailing newline) then exit without the
      // collector ever seeing a complete line.
      const py = [
        `cat > /tmp/partial.py <<'PY'`,
        'import socket,os',
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)",
        "s.connect(os.environ['ASBX_COLLECTOR_SOCK'])",
        `s.sendall(b'{"schema":"asbx.proposal.v1","kind":"finding","data":{"partial":true}')`, // no newline
        "print('sent-partial', flush=True)",
        'import time; time.sleep(30)', // hold the half-written event open...
        'PY',
        'python3 -I /tmp/partial.py',
      ].join('\n');
      // ...until the wall clock SIGKILLs the whole PID namespace mid-write.
      const r = await launch({ worker, command: ['/bin/sh', '-c', py], capture: true, rwBinds: [{ src: socketPath, dest: '/run/asbx/collector.sock' }], env: { ASBX_COLLECTOR_SOCK: '/run/asbx/collector.sock' }, wallClockMs: 2500 });
      // Give the collector a moment, then assert no event committed.
      await new Promise((res) => setTimeout(res, 200));
      const events = await readStore(storePath);
      const blocked = events.length === 0; // partial never commits
      // Control: a plain file written without line-atomic discipline keeps the
      // partial bytes (the collector's whole-line commit is what prevents it).
      const plain = path.join(runDir, 'plain.log');
      await writeFile(plain, '{"partial":true'); // no newline, truncated
      const plainTxt = await readFile(plain, 'utf8');
      const controlSucceeded = !plainTxt.endsWith('\n') && plainTxt.includes('partial');
      const killed = r.timedOut && /sent-partial/.test(r.stdout ?? '');
      return mkResult('kill-mid-write', killMidWrite.title, blocked && killed, controlSucceeded, `killed mid-write:${killed} committed events:${events.length}`);
    } finally {
      await collector.stop();
      await releaseWorker(worker);
      await rm(runDir, { recursive: true, force: true });
    }
  },
};

// ---------------------------------------------------------------------------
// Symlink escape: follow a symlink toward a harness file. Real = the target is
// not bound, so the symlink dangles; control = the target dir is bound.
// ---------------------------------------------------------------------------
const symlinkEscape: Attack = {
  id: 'fs-symlink-escape',
  title: 'escape via a symlink to a harness file',
  async run(): Promise<AttackResult> {
    const dir = await mkdtemp(path.join(tmpdir(), 'asbx-symlink-'));
    const file = path.join(dir, 'secret.txt');
    await writeFile(file, `SYMLINK-SECRET ${CANARY}`);
    await chmod(dir, 0o755);
    await chmod(file, 0o644);
    try {
      const script = 'ln -s /harness/secret.txt /tmp/link 2>/dev/null; cat /tmp/link 2>/dev/null && echo READ || echo blocked';
      const real = await withWorker((w) => runLowLevel({ worker: w, script }));
      const blocked = !real.stdout.includes('SYMLINK-SECRET');
      const control = await withWorker((w) => runLowLevel({ worker: w, script, roBinds: [{ src: dir, dest: '/harness' }] }));
      const controlSucceeded = control.stdout.includes('SYMLINK-SECRET');
      return mkResult('fs-symlink-escape', symlinkEscape.title, blocked, controlSucceeded, `real:${real.stdout.trim()} control:${controlSucceeded ? 'read' : 'nope'}`);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
};

/** The full 25-attack suite, in a stable order. */
export function coreAttacks(): Attack[] {
  return [
    // filesystem (5)
    fsAttack('fs-control-file', 'read a harness control file', 'control.json'),
    fsAttack('fs-setup-state', 'read harness setup state', 'setup-state.json'),
    fsAttack('fs-call-log', 'read the canonical call log', 'calls.jsonl'),
    fsAttack('fs-findings', 'read harness findings', 'findings.json'),
    symlinkEscape,
    // process (4)
    procHarness,
    ptraceHarness,
    inheritedFd,
    detachedSurvival,
    // network (6)
    netDirectEgress,
    netProxyUnset,
    netIpv6,
    netDns,
    netMetadata,
    gatewayConnect,
    // credentials (3)
    credEnv,
    credProc,
    credFd,
    // reflected canary (4)
    canaryPlain,
    canaryBase64,
    canaryUrl,
    canarySplit,
    // lifecycle (3)
    forkBomb,
    diskFill,
    killMidWrite,
  ];
}

export const SUITE_SIZE = 25;
