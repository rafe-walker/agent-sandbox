/**
 * The launcher.
 *
 * Runs an untrusted command inside a per-worker boundary:
 *   prlimit (rlimits) -> setpriv (dedicated uid/gid, clear groups, drop caps)
 *     -> [ip netns exec <ns>] -> bwrap (namespaces, ro system, fresh HOME)
 *
 * The dedicated uid/gid is allocated with a PRIVATE group (never a shared gid
 * such as `docker`). File descriptors are clean by construction — Node only
 * passes the stdio we hand the child — and the launcher can assert this from
 * inside the sandbox. Teardown kills the PID namespace and verifies no process
 * owned by the worker uid survived, including detached children.
 *
 * Requires root (uid allocation + `ip netns exec`). On a non-root / non-Linux
 * host every entry point fails loudly rather than running the command
 * unsandboxed.
 */
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const pExecFileRaw = promisify(execFile);

/**
 * The ONLY environment any spawned helper or sandbox chain gets. Never inherit
 * process.env: the harness env holds credentials (GITHUB_TOKEN, the model key,
 * proxy URLs), and every process in the chain (prlimit, setpriv, bwrap, which
 * becomes pid 1 in the agent's PID namespace) keeps its env readable at
 * /proc/<pid>/environ by the worker uid.
 */
export const MINIMAL_ENV: Readonly<Record<string, string>> = Object.freeze({
  PATH: '/usr/sbin:/usr/bin:/sbin:/bin',
});

function pExecFile(cmd: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  return pExecFileRaw(cmd, args, { env: { ...MINIMAL_ENV } });
}

export const WORKER_PREFIX = 'asbx_w';

export interface Worker {
  name: string;
  uid: number;
  gid: number;
}

function requireLinuxRoot(): void {
  if (process.platform !== 'linux') {
    throw new Error('the launcher requires Linux (native macOS is dev-only)');
  }
  if (typeof process.geteuid !== 'function' || process.geteuid() !== 0) {
    throw new Error('the launcher requires root to allocate a worker uid and program the netns');
  }
}

/**
 * Allocate a dedicated system uid with a PRIVATE group. `useradd -r -U`
 * creates a group of the same name, so the worker never lands in a pre-existing
 * shared group (on this host `useradd --system` alone picked up `docker`).
 */
export async function allocateWorker(): Promise<Worker> {
  requireLinuxRoot();
  const name = WORKER_PREFIX + randomBytes(4).toString('hex');
  await pExecFile('useradd', [
    '--system',
    '--user-group', // private group, do NOT reuse an existing gid
    '--no-create-home',
    '--shell',
    '/usr/sbin/nologin',
    name,
  ]);
  const { stdout: u } = await pExecFile('id', ['-u', name]);
  const { stdout: g } = await pExecFile('id', ['-g', name]);
  return { name, uid: Number(u.trim()), gid: Number(g.trim()) };
}

async function countOwned(uid: number): Promise<number> {
  // Count LIVE processes only: a zombie (state Z) runs no code and is just
  // awaiting reaping by host init (bwrap's ns-init briefly lingers as one).
  try {
    const { stdout } = await pExecFile('ps', ['-o', 'stat=', '-u', String(uid)]);
    return stdout.split('\n').filter((s) => s.trim() && !s.trim().startsWith('Z')).length;
  } catch {
    return 0; // ps exits 1 when none match
  }
}

/**
 * Kill anything the worker still owns, verify nothing survived, then remove the
 * uid and its private group. `survivors` is the count that remained AFTER the
 * kill + a settle poll (0 is healthy) — not a pre-kill snapshot, which would
 * race the kernel's PID-namespace reap. Idempotent and safe for a crashed run.
 */
export async function releaseWorker(worker: Worker): Promise<{ survivors: number }> {
  if (process.platform !== 'linux') return { survivors: 0 };
  // SIGKILL everything owned by the uid (covers detached children too).
  try {
    await pExecFile('pkill', ['-9', '-u', String(worker.uid)]);
  } catch {
    /* none to kill */
  }
  // Poll until the kernel has reaped the PID namespace, up to ~2s.
  let survivors = await countOwned(worker.uid);
  for (let i = 0; survivors > 0 && i < 40; i++) {
    await new Promise((r) => setTimeout(r, 50));
    try {
      await pExecFile('pkill', ['-9', '-u', String(worker.uid)]);
    } catch {
      /* none */
    }
    survivors = await countOwned(worker.uid);
  }
  try {
    await pExecFile('userdel', [worker.name]);
  } catch {
    /* already gone */
  }
  return { survivors };
}

export interface Bind {
  src: string;
  dest: string;
}

export interface Rlimits {
  /** RLIMIT_NPROC */
  nproc: number;
  /** RLIMIT_AS, bytes */
  as: number;
  /** RLIMIT_FSIZE, bytes */
  fsize: number;
  /** RLIMIT_NOFILE */
  nofile: number;
}

export const DEFAULT_RLIMITS: Rlimits = {
  nproc: 128,
  as: 2 * 1024 * 1024 * 1024, // 2 GiB
  fsize: 256 * 1024 * 1024, // 256 MiB
  nofile: 256,
};

export interface LaunchOptions {
  worker: Worker;
  /** argv executed inside the sandbox. */
  command: string[];
  /** Read-only bind of the source checkout (must be readable by others). */
  sourceDir?: string;
  /** Additional read-only binds. */
  roBinds?: Bind[];
  /** Read-write binds (e.g. the collector socket dir). Use sparingly. */
  rwBinds?: Bind[];
  /** Environment inside the sandbox. The model credential must NOT be here. */
  env?: Record<string, string>;
  /** Working directory inside the sandbox. Defaults to HOME. */
  cwd?: string;
  rlimits?: Partial<Rlimits>;
  /** Hard wall-clock limit; the PID namespace is SIGKILLed when it elapses. */
  wallClockMs?: number;
  /**
   * Name of a prepared netns (from the network module). When set, bwrap does
   * NOT create its own net namespace; the whole process runs under
   * `ip netns exec <ns>` so it inherits the veth-connected namespace. When
   * unset, bwrap fully isolates the network (only loopback).
   */
  netns?: string;
  /** Capture stdout/stderr instead of inheriting. */
  capture?: boolean;
  /** Gateway IP to publish as `gateway` in the synthetic /etc/hosts. */
  gatewayIp?: string;
}

export interface LaunchResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  stdout?: string;
  stderr?: string;
  /** Worker-owned processes still alive AFTER teardown (must be 0). */
  survivors: number;
}

const SANDBOX_HOME = '/home/agent';
const SANDBOX_SRC = '/src';

/**
 * Positive-control overrides. ONLY the attacker suite passes these, to prove a
 * protection matters by switching exactly one off. `launch()` never takes
 * them; production runs always get every protection.
 */
export interface UnsafeControls {
  pidNs?: false;
  netNs?: false;
  /** false = no --clearenv AND the chain inherits the harness env. */
  envClean?: false;
  dieWithParent?: false;
}

/** Build the bwrap argument vector (exported for inspection / tests). */
export function buildBwrapArgs(
  opts: LaunchOptions,
  isolateNet: boolean,
  etcDir?: string,
  controls: UnsafeControls = {},
): string[] {
  const a: string[] = ['--unshare-user'];
  if (controls.pidNs !== false) a.push('--unshare-pid');
  a.push('--unshare-ipc', '--unshare-uts');
  if (isolateNet && controls.netNs !== false) a.push('--unshare-net');
  if (controls.dieWithParent !== false) a.push('--die-with-parent');
  a.push('--new-session', '--cap-drop', 'ALL');
  // bwrap inherits the parent env unless cleared. (The parent's env itself is
  // ALSO minimal: see buildSandboxInvocation. --clearenv alone is not enough,
  // because bwrap's own pid-1 process keeps the env it was started with.)
  if (controls.envClean !== false) a.push('--clearenv');
  a.push(
    // read-only system
    '--ro-bind', '/usr', '/usr',
    '--symlink', 'usr/bin', '/bin',
    '--symlink', 'usr/sbin', '/sbin',
    '--symlink', 'usr/lib', '/lib',
    '--symlink', 'usr/lib64', '/lib64',
  );
  // A synthetic /etc (passwd/group/nsswitch/hosts + CA bundle + loader cache):
  // never the host /etc, which leaks resolv.conf, hostname, shadow, etc.
  if (etcDir !== undefined) a.push('--ro-bind', etcDir, '/etc');
  else a.push('--dir', '/etc');
  a.push(
    // fresh, isolated filesystem surfaces
    '--proc', '/proc',
    '--dev', '/dev',
    '--tmpfs', '/tmp',
    '--tmpfs', '/dev/shm',
    '--dir', SANDBOX_HOME,
    '--chdir', opts.cwd ?? SANDBOX_HOME,
    // Minimal env after --clearenv. Caller-supplied env is appended below and
    // overrides these. The model credential must never be among them.
    '--setenv', 'HOME', SANDBOX_HOME,
    '--setenv', 'PATH', '/usr/bin:/bin',
    '--setenv', 'TMPDIR', '/tmp',
  );
  // Explicitly NOT bound: /run, and any harness directory.
  if (opts.sourceDir) a.push('--ro-bind', opts.sourceDir, SANDBOX_SRC);
  for (const b of opts.roBinds ?? []) a.push('--ro-bind', b.src, b.dest);
  for (const b of opts.rwBinds ?? []) a.push('--bind', b.src, b.dest);
  for (const [k, v] of Object.entries(opts.env ?? {})) a.push('--setenv', k, v);
  a.push('--', ...opts.command);
  return a;
}

export interface SandboxInvocation {
  cmd: string;
  args: string[];
  /** The exact env the chain is spawned with. */
  env: Record<string, string>;
}

/**
 * The single source of the sandbox command line AND its environment, shared by
 * production `launch()` and the attacker suite. Pure.
 */
export function buildSandboxInvocation(
  opts: LaunchOptions,
  etcDir?: string,
  controls: UnsafeControls = {},
): SandboxInvocation {
  const rlimits = { ...DEFAULT_RLIMITS, ...opts.rlimits };
  const isolateNet = opts.netns === undefined;
  const argv: string[] = [];
  if (opts.netns !== undefined) argv.push('ip', 'netns', 'exec', opts.netns);
  // prlimit applies the rlimits to the whole subtree.
  argv.push(
    'prlimit',
    `--nproc=${rlimits.nproc}`,
    `--as=${rlimits.as}`,
    `--fsize=${rlimits.fsize}`,
    `--nofile=${rlimits.nofile}`,
  );
  // setpriv drops to the dedicated uid/gid, clears supplementary groups and
  // the inheritable+ambient capability sets.
  argv.push(
    'setpriv',
    `--reuid=${opts.worker.uid}`,
    `--regid=${opts.worker.gid}`,
    '--clear-groups',
    '--inh-caps=-all',
    '--',
    'bwrap',
    ...buildBwrapArgs(opts, isolateNet, etcDir, controls),
  );
  const [cmd, ...args] = argv;
  if (!cmd) throw new Error('empty command vector');
  const env: Record<string, string> =
    controls.envClean === false
      ? Object.fromEntries(Object.entries(process.env).filter((e): e is [string, string] => e[1] !== undefined))
      : { ...MINIMAL_ENV };
  return { cmd, args, env };
}

/** Write the synthetic /etc for one launch. Root-owned, world-readable. */
export async function prepareSyntheticEtc(worker: Worker, gatewayIp?: string): Promise<string> {
  const { writeFile, mkdir } = await import('node:fs/promises');
  const { existsSync } = await import('node:fs');
  const dir = await mkdtemp(path.join(tmpdir(), 'asbx-etc-'));
  await chmod(dir, 0o755);
  const files: Record<string, string> = {
    passwd:
      'root:x:0:0:root:/root:/usr/sbin/nologin\n' +
      `${worker.name}:x:${worker.uid}:${worker.gid}::${SANDBOX_HOME}:/bin/sh\n` +
      'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n',
    group: `root:x:0:\n${worker.name}:x:${worker.gid}:\nnogroup:x:65534:\n`,
    'nsswitch.conf': 'passwd: files\ngroup: files\nhosts: files\n',
    hosts: '127.0.0.1 localhost\n' + (gatewayIp ? `${gatewayIp} gateway\n` : ''),
  };
  for (const [name, body] of Object.entries(files)) {
    await writeFile(path.join(dir, name), body, { mode: 0o644 });
    await chmod(path.join(dir, name), 0o644);
  }
  // Mount points for the few host files that carry no host-specific secrets.
  await mkdir(path.join(dir, 'ssl', 'certs'), { recursive: true, mode: 0o755 });
  await mkdir(path.join(dir, 'alternatives'), { mode: 0o755 });
  return Promise.resolve(dir).then(async (d) => {
    const extra: Array<[string, string]> = [];
    if (existsSync('/etc/ssl/certs/ca-certificates.crt')) extra.push(['/etc/ssl/certs/ca-certificates.crt', 'ssl/certs/ca-certificates.crt']);
    if (existsSync('/etc/ld.so.cache')) extra.push(['/etc/ld.so.cache', 'ld.so.cache']);
    for (const [, rel] of extra) await writeFile(path.join(d, rel), '', { mode: 0o644 });
    syntheticEtcBinds.set(d, [
      ...extra.map(([src, rel]) => ({ src, dest: `/etc/${rel}` })),
      ...(existsSync('/etc/alternatives') ? [{ src: '/etc/alternatives', dest: '/etc/alternatives' }] : []),
    ]);
    return d;
  });
}

// Host files bound read-only on top of a synthetic /etc (CA bundle, loader
// cache, alternatives symlinks). Keyed by the synthetic dir.
const syntheticEtcBinds = new Map<string, Bind[]>();

export interface RunInvocationOptions {
  capture?: boolean;
  wallClockMs?: number;
  /** Positive-control only: leak a host fd as fd 3. */
  extraFd?: number;
}

export interface InvocationResult extends LaunchResult {
  /** Live worker-owned processes after the chain exited, BEFORE our pkill. */
  orphansBeforeTeardown: number;
}

/**
 * The single launch path. Production `launch()` and the attacker suite both
 * call this; only the suite ever passes `controls`.
 */
export async function launchWith(
  opts: LaunchOptions,
  controls: UnsafeControls = {},
  run: RunInvocationOptions = {},
): Promise<InvocationResult> {
  requireLinuxRoot();
  const etcDir = await prepareSyntheticEtc(opts.worker, opts.gatewayIp);
  const etcBinds = syntheticEtcBinds.get(etcDir) ?? [];
  syntheticEtcBinds.delete(etcDir);
  const inv = buildSandboxInvocation(
    { ...opts, roBinds: [...etcBinds, ...(opts.roBinds ?? [])] },
    etcDir,
    controls,
  );
  const capture = run.capture ?? opts.capture ?? false;
  const wallClockMs = run.wallClockMs ?? opts.wallClockMs;
  try {
    return await new Promise<InvocationResult>((resolve) => {
      // stdio: only 0/1/2 are inherited/captured. No extra fd is passed (unless
      // a positive control asks), so the child's fd table is clean.
      const stdio: Array<'ignore' | 'pipe' | 'inherit' | number> = capture
        ? ['ignore', 'pipe', 'pipe']
        : ['inherit', 'inherit', 'inherit'];
      if (run.extraFd !== undefined) stdio[3] = run.extraFd;
      const child = spawn(inv.cmd, inv.args, { stdio, env: inv.env });
      let stdout = '';
      let stderr = '';
      child.stdout?.on('data', (d: Buffer) => (stdout += d.toString()));
      child.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
      let timedOut = false;
      let timer: NodeJS.Timeout | undefined;
      if (wallClockMs !== undefined) {
        timer = setTimeout(() => {
          timedOut = true;
          // Kill bwrap: die-with-parent + the PID namespace reap every
          // descendant, detached or not.
          child.kill('SIGKILL');
        }, wallClockMs);
        timer.unref();
      }
      const out = (): { stdout?: string; stderr?: string } => (capture ? { stdout, stderr } : {});
      child.on('error', (err) => {
        if (timer) clearTimeout(timer);
        resolve({ exitCode: null, signal: null, timedOut, survivors: 0, orphansBeforeTeardown: 0, ...(capture ? { stdout, stderr: stderr + `\nspawn error: ${err.message}` } : {}) });
      });
      child.on('close', (code, signal) => {
        if (timer) clearTimeout(timer);
        // Let the kernel finish reaping the PID namespace, measure what it
        // left, then kill + verify no survivors and remove the uid.
        void new Promise((r) => setTimeout(r, 400))
          .then(() => countOwned(opts.worker.uid))
          .then((orphansBeforeTeardown) =>
            releaseWorker(opts.worker).then(
              ({ survivors }) => resolve({ exitCode: code, signal, timedOut, survivors, orphansBeforeTeardown, ...out() }),
              () => resolve({ exitCode: code, signal, timedOut, survivors: -1, orphansBeforeTeardown, ...out() }),
            ),
          );
      });
    });
  } finally {
    await rm(etcDir, { recursive: true, force: true });
  }
}

/**
 * Launch the command with every protection on. Builds the full
 * prlimit->setpriv->[netns]->bwrap pipeline with a minimal env, enforces a
 * wall-clock kill, and tears the worker down afterwards, verifying no survivors.
 */
export async function launch(opts: LaunchOptions): Promise<LaunchResult> {
  const { orphansBeforeTeardown: _o, ...r } = await launchWith(opts);
  return r;
}

/**
 * Convenience: allocate a worker, run a shell script inside, and capture
 * output. Primarily for the attacker suite and tests. Always releases the
 * worker, even on error.
 */
export async function runInSandbox(
  script: string,
  opts: Omit<LaunchOptions, 'worker' | 'command'> & { worker?: Worker } = {},
): Promise<LaunchResult> {
  const worker = opts.worker ?? (await allocateWorker());
  try {
    return await launch({
      ...opts,
      worker,
      command: ['/bin/sh', '-c', script],
      capture: true,
    });
  } catch (e) {
    await releaseWorker(worker);
    throw e;
  }
}

/**
 * A shell snippet that asserts, FROM INSIDE the sandbox, that only the allowed
 * file descriptors are open. Prints `FDS_OK` or `FDS_LEAK:<list>`.
 */
export function fdAssertionScript(allowed: number[] = [0, 1, 2]): string {
  const allow = allowed.join(' ');
  return [
    'allow="' + allow + '"',
    'leak=""',
    'for fd in /proc/self/fd/*; do',
    '  n=$(basename "$fd")',
    '  case " $allow " in *" $n "*) ;; *)',
    // /proc/self/fd/* itself opens a transient dir handle for the glob; its
    // readlink points at the fd directory or fails (already closed). Skip both.
    '    tgt=$(readlink "$fd" 2>/dev/null || echo "?");',
    '    case "$tgt" in /proc/*/fd|"?") ;; *) leak="$leak $n:$tgt";; esac;;',
    '  esac',
    'done',
    'if [ -n "$leak" ]; then echo "FDS_LEAK:$leak"; else echo FDS_OK; fi',
  ].join('\n');
}

/** Helper for tests/callers: make a dir world-readable for the ro source bind. */
export async function makeReadableSource(contents: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'asbx-src-'));
  await chmod(dir, 0o755);
  const { writeFile } = await import('node:fs/promises');
  for (const [name, body] of Object.entries(contents)) {
    const p = path.join(dir, name);
    await writeFile(p, body);
    await chmod(p, 0o644);
  }
  return dir;
}

export async function cleanupDir(dir: string): Promise<void> {
  await rm(dir, { recursive: true, force: true });
}
