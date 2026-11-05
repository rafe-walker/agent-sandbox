/**
 * Shared machinery for the attacker suite.
 *
 * Every attack is run twice: once under the REAL sandbox config (must be
 * blocked) and once under a CONTROL where exactly one protection is disabled
 * (must succeed, proving the test is meaningful). The control launcher builds a
 * bwrap argv with a named protection removed, so a control is a genuine
 * demonstration rather than a stub.
 */
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { AttackResult } from '../report.js';
import { allocateWorker, releaseWorker, type Worker } from '../launcher.js';

export type Protection =
  | 'none'
  | 'pid-ns'
  | 'net-ns'
  | 'clearenv'
  | 'mount-ns'
  | 'die-with-parent'
  | 'fd-close';

export interface SandboxRun {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  /** Worker-owned processes after teardown's pkill (should be 0). */
  survivors: number;
  /** Worker-owned processes alive after bwrap exited but BEFORE our pkill —
   *  i.e. what the namespace itself failed to reap. */
  orphansBeforeTeardown: number;
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

const SANDBOX_HOME = '/home/agent';
const pExecFile = promisify(execFile);

/**
 * Low-level runner used by both real and control paths. `drop` names a
 * protection to remove; `extraBinds` and `extraFd`/`netns` let an attack set up
 * its scenario. Always releases the worker and reports survivors.
 */
export async function runLowLevel(opts: {
  worker: Worker;
  script: string;
  drop?: Protection;
  roBinds?: Array<{ src: string; dest: string }>;
  rwBinds?: Array<{ src: string; dest: string }>;
  env?: Record<string, string>;
  inheritEnv?: boolean; // for the clearenv control
  extraFd?: number; // a host fd number to leak into the child (fd-close control)
  netns?: string;
  nproc?: number;
  fsize?: number;
  wallClockMs?: number;
}): Promise<SandboxRun> {
  const drop = opts.drop ?? 'none';
  const a: string[] = ['--unshare-user', '--unshare-ipc', '--unshare-uts'];
  if (drop !== 'pid-ns') a.push('--unshare-pid');
  if (drop !== 'net-ns' && opts.netns === undefined) a.push('--unshare-net');
  if (drop !== 'die-with-parent') a.push('--die-with-parent');
  a.push('--new-session', '--cap-drop', 'ALL');
  if (drop !== 'clearenv') a.push('--clearenv');
  a.push(
    '--ro-bind', '/usr', '/usr',
    '--symlink', 'usr/bin', '/bin',
    '--symlink', 'usr/sbin', '/sbin',
    '--symlink', 'usr/lib', '/lib',
    '--symlink', 'usr/lib64', '/lib64',
    '--ro-bind', '/etc', '/etc',
    '--proc', '/proc',
    '--dev', '/dev',
    '--tmpfs', '/tmp',
    '--tmpfs', '/dev/shm',
    '--dir', SANDBOX_HOME,
    '--chdir', SANDBOX_HOME,
    '--setenv', 'HOME', SANDBOX_HOME,
    '--setenv', 'PATH', '/usr/bin:/bin',
  );
  for (const b of opts.roBinds ?? []) a.push('--ro-bind', b.src, b.dest);
  for (const b of opts.rwBinds ?? []) a.push('--bind', b.src, b.dest);
  for (const [k, v] of Object.entries(opts.env ?? {})) a.push('--setenv', k, v);
  a.push('--', '/bin/sh', '-c', opts.script);

  const prlimit = ['prlimit'];
  prlimit.push(`--nproc=${opts.nproc ?? 128}`);
  prlimit.push(`--as=${1024 * 1024 * 1024}`);
  prlimit.push(`--fsize=${opts.fsize ?? 256 * 1024 * 1024}`);
  prlimit.push('--nofile=256');

  const argv: string[] = [];
  if (opts.netns !== undefined) argv.push('ip', 'netns', 'exec', opts.netns);
  argv.push(
    ...prlimit,
    'setpriv',
    `--reuid=${opts.worker.uid}`,
    `--regid=${opts.worker.gid}`,
    '--clear-groups',
    '--inh-caps=-all',
    '--',
    'bwrap',
    ...a,
  );

  const [cmd, ...args] = argv;
  // stdio: 0/1/2, plus an optional leaked fd 3 for the fd-close control.
  const stdio: Array<'ignore' | 'pipe' | number> = ['ignore', 'pipe', 'pipe'];
  if (opts.extraFd !== undefined) stdio[3] = opts.extraFd;

  return await new Promise<SandboxRun>((resolve) => {
    const child = spawn(cmd!, args, {
      stdio,
      ...(opts.inheritEnv ? {} : { env: minimalEnv(opts.env) }),
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
    let timer: NodeJS.Timeout | undefined;
    if (opts.wallClockMs !== undefined) {
      timer = setTimeout(() => child.kill('SIGKILL'), opts.wallClockMs);
      timer.unref();
    }
    child.on('error', (e) => {
      if (timer) clearTimeout(timer);
      resolve({ stdout, stderr: stderr + `\nspawn error: ${e.message}`, exitCode: null, survivors: 0, orphansBeforeTeardown: 0 });
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      // Let the kernel finish reaping the PID namespace, then measure what it
      // left behind before our own pkill hides it.
      void new Promise((r) => setTimeout(r, 400))
        .then(() => countOwned(opts.worker.uid))
        .then((orphansBeforeTeardown) =>
          releaseWorker(opts.worker).then(({ survivors }) =>
            resolve({ stdout, stderr, exitCode: code, survivors, orphansBeforeTeardown }),
          ),
        );
    });
  });
}

/** Env for the harness side of the child process (not the sandbox env). The
 *  clearenv control passes inheritEnv:true so the harness env (with a planted
 *  canary) reaches bwrap, which then does NOT clear it. */
function minimalEnv(extra?: Record<string, string>): Record<string, string> {
  return { PATH: process.env.PATH ?? '/usr/bin:/bin', ...(extra ?? {}) };
}

export async function withWorker<T>(fn: (w: Worker) => Promise<T>): Promise<T> {
  const w = await allocateWorker();
  try {
    return await fn(w);
  } finally {
    await releaseWorker(w);
  }
}

export function mkResult(
  id: string,
  title: string,
  blocked: boolean,
  controlSucceeded: boolean,
  detail: string,
): AttackResult {
  return {
    id,
    title,
    blocked,
    controlSucceeded,
    status: blocked && controlSucceeded ? 'pass' : 'fail',
    detail,
  };
}
