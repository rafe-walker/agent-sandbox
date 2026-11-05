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

const pExecFile = promisify(execFile);

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

/**
 * Remove every leftover `asbx_w*` worker uid (and its private group) from
 * crashed runs: kill what it owns, then userdel. NOT run automatically — a
 * concurrent run on the same host would lose its workers. Call it explicitly
 * (`agent-sandbox cleanup`) when no other run is active.
 */
export async function cleanupStaleWorkers(): Promise<string[]> {
  if (process.platform !== 'linux') return [];
  const removed: string[] = [];
  let passwd = '';
  try {
    passwd = (await pExecFile('getent', ['passwd'])).stdout;
  } catch {
    return removed;
  }
  for (const line of passwd.split('\n')) {
    const [name, , uidStr, gidStr] = line.split(':');
    if (!name?.startsWith(WORKER_PREFIX)) continue;
    await releaseWorker({ name, uid: Number(uidStr), gid: Number(gidStr) });
    removed.push(name);
  }
  return removed;
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
  as: 1024 * 1024 * 1024, // 1 GiB (shared host; cap memory-heavy work)
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

/** Build the bwrap argument vector (exported for inspection / tests). */
export function buildBwrapArgs(opts: LaunchOptions, isolateNet: boolean): string[] {
  const a: string[] = [
    '--unshare-user',
    '--unshare-pid',
    '--unshare-ipc',
    '--unshare-uts',
  ];
  if (isolateNet) a.push('--unshare-net');
  a.push(
    '--die-with-parent',
    '--new-session',
    '--cap-drop',
    'ALL',
    // CRITICAL: bwrap inherits the parent env unless cleared. Without this the
    // harness's GITHUB_TOKEN / credentials leak straight into the sandbox.
    '--clearenv',
    // read-only system
    '--ro-bind',
    '/usr',
    '/usr',
    '--symlink',
    'usr/bin',
    '/bin',
    '--symlink',
    'usr/sbin',
    '/sbin',
    '--symlink',
    'usr/lib',
    '/lib',
    '--symlink',
    'usr/lib64',
    '/lib64',
    '--ro-bind',
    '/etc',
    '/etc',
    // fresh, isolated filesystem surfaces
    '--proc',
    '/proc',
    '--dev',
    '/dev',
    '--tmpfs',
    '/tmp',
    '--tmpfs',
    '/dev/shm',
    '--dir',
    SANDBOX_HOME,
    '--chdir',
    opts.cwd ?? SANDBOX_HOME,
    // Minimal env after --clearenv. Caller-supplied env is appended below and
    // overrides these. The model credential must never be among them.
    '--setenv',
    'HOME',
    SANDBOX_HOME,
    '--setenv',
    'PATH',
    '/usr/bin:/bin',
    '--setenv',
    'TMPDIR',
    '/tmp',
  );
  // Explicitly NOT bound: /run, and any harness directory.
  if (opts.sourceDir) a.push('--ro-bind', opts.sourceDir, SANDBOX_SRC);
  for (const b of opts.roBinds ?? []) a.push('--ro-bind', b.src, b.dest);
  for (const b of opts.rwBinds ?? []) a.push('--bind', b.src, b.dest);
  for (const [k, v] of Object.entries(opts.env ?? {})) a.push('--setenv', k, v);
  a.push('--', ...opts.command);
  return a;
}

/**
 * Launch the command. Builds the full prlimit->setpriv->[netns]->bwrap
 * pipeline, enforces a wall-clock kill, and tears the worker down afterwards,
 * verifying no survivors.
 */
export async function launch(opts: LaunchOptions): Promise<LaunchResult> {
  requireLinuxRoot();
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
    ...buildBwrapArgs(opts, isolateNet),
  );

  const [cmd, ...args] = argv;
  if (!cmd) throw new Error('empty command vector');

  return await new Promise<LaunchResult>((resolve) => {
    // stdio: only 0/1/2 are inherited/captured. No extra fd is passed, so the
    // child's fd table is clean by construction.
    const child = spawn(cmd, args, {
      stdio: opts.capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    });
    let stdout = '';
    let stderr = '';
    if (opts.capture) {
      child.stdout?.on('data', (d: Buffer) => (stdout += d.toString()));
      child.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
    }
    let timedOut = false;
    let timer: NodeJS.Timeout | undefined;
    if (opts.wallClockMs !== undefined) {
      timer = setTimeout(() => {
        timedOut = true;
        // Kill bwrap (pid-ns init proxy): die-with-parent + the PID namespace
        // means every descendant, detached or not, is reaped with it.
        child.kill('SIGKILL');
      }, opts.wallClockMs);
      timer.unref();
    }
    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      resolve({
        exitCode: null,
        signal: null,
        timedOut,
        survivors: 0,
        ...(opts.capture ? { stdout, stderr: stderr + `\nspawn error: ${err.message}` } : {}),
      });
    });
    child.on('close', (code, signal) => {
      if (timer) clearTimeout(timer);
      // Teardown: kill + verify no worker-owned survivors, then remove the uid.
      releaseWorker(opts.worker).then(
        ({ survivors }) =>
          resolve({
            exitCode: code,
            signal,
            timedOut,
            survivors,
            ...(opts.capture ? { stdout, stderr } : {}),
          }),
        () =>
          resolve({
            exitCode: code,
            signal,
            timedOut,
            survivors: -1,
            ...(opts.capture ? { stdout, stderr } : {}),
          }),
      );
    });
  });
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
