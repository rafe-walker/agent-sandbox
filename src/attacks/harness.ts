/**
 * Shared machinery for the attacker suite.
 *
 * Every attack is run twice: once under the REAL sandbox config (must be
 * blocked) and once under a CONTROL where exactly one protection is disabled
 * (must succeed, proving the test is meaningful). The control launcher builds a
 * bwrap argv with a named protection removed, so a control is a genuine
 * demonstration rather than a stub.
 */
import type { AttackResult } from '../report.js';
import {
  allocateWorker,
  releaseWorker,
  launchWith,
  type Worker,
  type Bind,
  type LaunchOptions,
  type UnsafeControls,
} from '../launcher.js';

/**
 * The single protection a positive control may disable. 'fd-close' is
 * expressed by leaking an fd (`extraFd`), 'mount-ns' by adding a bind.
 */
export type Protection = 'none' | 'pid-ns' | 'net-ns' | 'clearenv' | 'die-with-parent';

export interface SandboxRun {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  /** Worker-owned processes after teardown's pkill (should be 0). */
  survivors: number;
  /** Live worker-owned processes after the chain exited but BEFORE our pkill,
   *  i.e. what the namespace itself failed to reap. */
  orphansBeforeTeardown: number;
}

export interface LowLevelOptions {
  worker: Worker;
  script: string;
  drop?: Protection;
  roBinds?: Bind[];
  rwBinds?: Bind[];
  env?: Record<string, string>;
  /** A host fd number to leak into the child as fd 3 (fd-close control). */
  extraFd?: number;
  netns?: string;
  nproc?: number;
  fsize?: number;
  wallClockMs?: number;
}

/** Map a dropped protection to the launcher's UnsafeControls. 'none' = {}. */
export function controlsFor(drop: Protection): UnsafeControls {
  switch (drop) {
    case 'none':
      return {};
    case 'pid-ns':
      return { pidNs: false };
    case 'net-ns':
      return { netNs: false };
    case 'clearenv':
      return { envClean: false };
    case 'die-with-parent':
      return { dieWithParent: false };
  }
}

/** The LaunchOptions the suite uses for a scenario (pure, for comparison). */
export function suiteLaunchOptions(opts: Omit<LowLevelOptions, 'drop' | 'extraFd' | 'wallClockMs'>): LaunchOptions {
  return {
    worker: opts.worker,
    command: ['/bin/sh', '-c', opts.script],
    ...(opts.roBinds ? { roBinds: opts.roBinds } : {}),
    ...(opts.rwBinds ? { rwBinds: opts.rwBinds } : {}),
    ...(opts.env ? { env: opts.env } : {}),
    ...(opts.netns !== undefined ? { netns: opts.netns } : {}),
    rlimits: {
      ...(opts.nproc !== undefined ? { nproc: opts.nproc } : {}),
      ...(opts.fsize !== undefined ? { fsize: opts.fsize } : {}),
    },
  };
}

/**
 * Run one scenario through the EXACT production launch path (`launchWith`),
 * optionally with one protection disabled for a positive control. The suite
 * never builds its own command line or env, so what it measures is what real
 * runs get. Always releases the worker and reports survivors.
 */
export async function runLowLevel(opts: LowLevelOptions): Promise<SandboxRun> {
  const r = await launchWith(suiteLaunchOptions(opts), controlsFor(opts.drop ?? 'none'), {
    capture: true,
    ...(opts.wallClockMs !== undefined ? { wallClockMs: opts.wallClockMs } : {}),
    ...(opts.extraFd !== undefined ? { extraFd: opts.extraFd } : {}),
  });
  return {
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    exitCode: r.exitCode,
    survivors: r.survivors,
    orphansBeforeTeardown: r.orphansBeforeTeardown,
  };
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
