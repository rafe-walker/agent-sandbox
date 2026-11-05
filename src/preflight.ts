/**
 * The preflight runner.
 *
 * It measures capabilities and runs the attacker suite, then derives the
 * capability report. The actual capability probes and attacks are registered
 * by the launcher / network / collector / attacker-suite modules in the later
 * stacked PRs; this runner is their orchestrator and is pure with respect to
 * whatever probe set it is handed.
 */
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { MINIMAL_ENV } from './launcher.js';
import {
  derivePublishable,
  foldSuite,
  type AttackResult,
  type CapabilityName,
  type CapabilityReport,
  type CapabilityResult,
} from './report.js';
import { assertImplemented, type Profile } from './profiles.js';
import { SUITE_VERSION } from './version.js';

const pExecFileRaw = promisify(execFile);
// Never inherit the harness env (credentials, proxy URLs) in a helper.
function pExecFile(cmd: string, args: string[], opts: { timeout?: number } = {}): Promise<{ stdout: string; stderr: string }> {
  return pExecFileRaw(cmd, args, { ...opts, env: { ...MINIMAL_ENV } });
}

export interface CapabilityProbe {
  readonly name: CapabilityName;
  run(): Promise<CapabilityResult> | CapabilityResult;
}

export interface Attack {
  readonly id: string;
  readonly title: string;
  run(): Promise<AttackResult> | AttackResult;
}

export interface PreflightOptions {
  profile: Profile;
  capabilityProbes?: readonly CapabilityProbe[];
  attacks?: readonly Attack[];
  /** Injectable clock for deterministic tests. */
  now?: () => Date;
}

export function hostInfo(): CapabilityReport['host'] {
  return {
    platform: process.platform,
    release: os.release(),
    arch: process.arch,
    euid: typeof process.geteuid === 'function' ? process.geteuid() : -1,
  };
}

export interface Prereq {
  name: string;
  ok: boolean;
  detail: string;
}

/**
 * Host prerequisites for `linux-sandbox`. These are reported but, on their own,
 * do NOT make a run publishable — only measured capabilities do. They exist so
 * a missing tool fails loudly and early instead of mid-suite.
 */
export async function checkPrereqs(): Promise<Prereq[]> {
  const out: Prereq[] = [];

  out.push({
    name: 'platform-linux',
    ok: process.platform === 'linux',
    detail: process.platform,
  });

  // `ip` prints its version for `-V`, not `--version` (which it rejects).
  const versionArg: Record<string, string> = { bwrap: '--version', ip: '-V', nft: '--version' };
  for (const bin of ['bwrap', 'ip', 'nft']) {
    let ok = false;
    let detail = 'not found';
    try {
      const { stdout } = await pExecFile(bin, [versionArg[bin] ?? '--version'], { timeout: 5000 });
      ok = true;
      detail = stdout.split('\n')[0]?.trim() ?? 'present';
    } catch (e) {
      detail = (e instanceof Error ? e.message.split('\n')[0] : undefined) ?? 'not found';
    }
    out.push({ name: `bin:${bin}`, ok, detail });
  }

  // Unprivileged user namespaces. Absent file is treated as "enabled" (common
  // on modern kernels that dropped the sysctl), present-and-0 as disabled.
  let usernsOk = true;
  let usernsDetail = 'sysctl absent (assumed enabled)';
  try {
    const { readFile } = await import('node:fs/promises');
    const v = (await readFile('/proc/sys/kernel/unprivileged_userns_clone', 'utf8')).trim();
    usernsOk = v !== '0';
    usernsDetail = `unprivileged_userns_clone=${v}`;
  } catch {
    /* absent — keep assumed-enabled */
  }
  out.push({ name: 'user-namespaces', ok: usernsOk, detail: usernsDetail });

  return out;
}

async function runProbe(p: CapabilityProbe): Promise<[CapabilityName, CapabilityResult]> {
  try {
    const r = await p.run();
    return [p.name, r];
  } catch (e) {
    return [p.name, { status: 'fail', detail: e instanceof Error ? e.message : String(e) }];
  }
}

async function runAttack(a: Attack): Promise<AttackResult> {
  try {
    return await a.run();
  } catch (e) {
    return {
      id: a.id,
      title: a.title,
      blocked: false,
      controlSucceeded: false,
      status: 'fail',
      detail: `attack threw: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

/**
 * Run the preflight and produce the capability report. Never throws for a
 * degraded host (except when an unimplemented profile is selected): it records
 * the degradation and returns a non-publishable report.
 */
export async function runPreflight(opts: PreflightOptions): Promise<CapabilityReport> {
  assertImplemented(opts.profile);
  const now = opts.now ?? (() => new Date());
  const probes = opts.capabilityProbes ?? [];
  const attacks = opts.attacks ?? [];

  const capEntries = await Promise.all(probes.map(runProbe));
  const capabilities: Partial<Record<CapabilityName, CapabilityResult>> = {};
  for (const [name, res] of capEntries) capabilities[name] = res;

  // Attacks run serially: each manipulates namespaces / nftables / uids and
  // must not race another. Determinism over speed here.
  const attackResults: AttackResult[] = [];
  for (const a of attacks) attackResults.push(await runAttack(a));

  const suite = foldSuite(attackResults, SUITE_VERSION);
  const { publishable, reasons } = derivePublishable({
    profile: opts.profile,
    capabilities,
    suite,
  });

  return {
    schemaVersion: 1,
    profile: opts.profile,
    createdAt: now().toISOString(),
    host: hostInfo(),
    capabilities,
    suite,
    publishable,
    reasons,
  };
}
