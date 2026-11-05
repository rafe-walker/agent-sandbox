/**
 * The capability report.
 *
 * It records *measured* capabilities (not assumed ones), the attacker-suite
 * version and result, and the derived `publishable` verdict. There is no
 * silent downgrade: a degraded host still produces a report, but `publishable`
 * is false and the reason is explicit.
 */
import { z } from 'zod';
import { PROFILES, PUBLISHABLE_PROFILE, type Profile } from './profiles.js';
import { SUITE_VERSION } from './version.js';

/**
 * The measured capability names. Each is a boundary the attacker suite and the
 * runtime depend on. `net_enforced` and `evidence_writer_separated` require the
 * network and collector pieces respectively; when those are not exercised the
 * capability is reported `not-probed`, which is NOT a pass.
 */
export const CAPABILITY_NAMES = [
  'uid_separated', // agent runs as a dedicated uid/gid, not the harness uid
  'pid_ns', // agent is in its own PID namespace (ptrace/./proc wall, no Yama)
  'mount_ns', // agent has a private mount namespace (ro system, no harness dirs)
  'net_enforced', // egress is enforced below the app layer (netns + nftables)
  'creds_absent', // the model credential is not present in the sandbox
  'fds_clean', // only stdio + deliberate sockets are inherited
  'evidence_writer_separated', // the agent cannot write canonical evidence
] as const;
export type CapabilityName = (typeof CAPABILITY_NAMES)[number];

export const probeStatusSchema = z.enum(['pass', 'fail', 'not-probed']);
export type ProbeStatus = z.infer<typeof probeStatusSchema>;

export const capabilityResultSchema = z.object({
  status: probeStatusSchema,
  detail: z.string().max(2000).optional(),
});
export type CapabilityResult = z.infer<typeof capabilityResultSchema>;

export const attackResultSchema = z.object({
  id: z.string().max(128),
  title: z.string().max(400),
  /** The protection held (attack blocked). */
  blocked: z.boolean(),
  /** The positive control confirmed the attack succeeds when protection is off. */
  controlSucceeded: z.boolean(),
  status: probeStatusSchema,
  detail: z.string().max(4000).optional(),
  /**
   * Set ONLY when the harness (not the sandbox) proved the attack vector does
   * not exist on this host (e.g. the kernel has no IPv6), so no positive
   * control is possible. The attack must still be blocked; it is counted and
   * listed in the report, never hidden.
   */
  notApplicable: z.string().max(400).optional(),
});
export type AttackResult = z.infer<typeof attackResultSchema>;

export const suiteResultSchema = z.object({
  version: z.string(),
  /** 'pass' only when every attack was blocked AND its control succeeded. */
  result: probeStatusSchema,
  ran: z.number().int().nonnegative(),
  blocked: z.number().int().nonnegative(),
  failed: z.number().int().nonnegative(),
  notApplicable: z.number().int().nonnegative(),
  attacks: z.array(attackResultSchema),
});
export type SuiteResult = z.infer<typeof suiteResultSchema>;

export const capabilityReportSchema = z.object({
  schemaVersion: z.literal(1),
  profile: z.enum(PROFILES),
  createdAt: z.string(),
  host: z.object({
    platform: z.string(),
    release: z.string(),
    arch: z.string(),
    euid: z.number().int(),
  }),
  // Partial: a degraded host may not have probed every capability. A missing
  // key is treated as "not probed" (non-publishable) by derivePublishable.
  capabilities: z.partialRecord(z.enum(CAPABILITY_NAMES), capabilityResultSchema),
  suite: suiteResultSchema,
  publishable: z.boolean(),
  /** Why the run is / is not publishable. Always populated. */
  reasons: z.array(z.string()),
});
export type CapabilityReport = z.infer<typeof capabilityReportSchema>;

/**
 * Required capabilities for a publishable `linux-sandbox` run. Every one of
 * these must be measured `pass`.
 */
export const REQUIRED_CAPABILITIES: readonly CapabilityName[] = CAPABILITY_NAMES;

/**
 * Derive the publishability verdict. This is the single source of truth for
 * the invariant: publishable iff profile is linux-sandbox AND every required
 * capability passed AND the attacker suite passed. Pure and deterministic.
 */
export function derivePublishable(input: {
  profile: Profile;
  capabilities: Partial<Record<CapabilityName, CapabilityResult>>;
  suite: SuiteResult;
}): { publishable: boolean; reasons: string[] } {
  const reasons: string[] = [];

  if (input.profile !== PUBLISHABLE_PROFILE) {
    reasons.push(
      `profile is "${input.profile}"; only "${PUBLISHABLE_PROFILE}" is publishable`,
    );
  }

  for (const name of REQUIRED_CAPABILITIES) {
    const r = input.capabilities[name];
    if (!r) {
      reasons.push(`capability "${name}" was not probed`);
    } else if (r.status !== 'pass') {
      reasons.push(
        `capability "${name}" is "${r.status}"${r.detail ? ` (${r.detail})` : ''}`,
      );
    }
  }

  if (input.suite.result !== 'pass') {
    reasons.push(`attacker suite result is "${input.suite.result}"`);
  }
  if (input.suite.version !== SUITE_VERSION) {
    reasons.push(
      `attacker suite version "${input.suite.version}" != expected "${SUITE_VERSION}"`,
    );
  }

  return { publishable: reasons.length === 0, reasons };
}

/** Fold per-attack results into a suite verdict. Fails closed. */
export function foldSuite(attacks: AttackResult[], version = SUITE_VERSION): SuiteResult {
  const ran = attacks.length;
  const blocked = attacks.filter((a) => a.blocked).length;
  // An N/A attack is excused only from its positive control; it must still be
  // blocked. Everything else needs blocked AND a successful control.
  const failed = attacks.filter(
    (a) => a.status === 'fail' || !a.blocked || (!a.notApplicable && !a.controlSucceeded),
  ).length;
  const notApplicable = attacks.filter((a) => a.notApplicable).length;
  // Pass only when at least one attack ran and none failed.
  const result: ProbeStatus = ran === 0 ? 'not-probed' : failed === 0 ? 'pass' : 'fail';
  return { version, result, ran, blocked, failed, notApplicable, attacks };
}

/** Human-readable one-screen summary of a report. */
export function formatReport(r: CapabilityReport): string {
  const lines: string[] = [];
  lines.push(`agent-sandbox capability report (schema v${r.schemaVersion})`);
  lines.push(`  profile:   ${r.profile}`);
  lines.push(`  host:      ${r.host.platform} ${r.host.release} ${r.host.arch} euid=${r.host.euid}`);
  lines.push(`  created:   ${r.createdAt}`);
  lines.push('  capabilities:');
  for (const name of CAPABILITY_NAMES) {
    const c = r.capabilities[name];
    const mark = !c ? '?' : c.status === 'pass' ? '+' : c.status === 'fail' ? 'x' : '?';
    lines.push(`    [${mark}] ${name}${c?.detail ? ` — ${c.detail}` : ''}`);
  }
  lines.push(
    `  attacker suite: v${r.suite.version} ${r.suite.result} ` +
      `(ran ${r.suite.ran}, blocked ${r.suite.blocked}, failed ${r.suite.failed}, n/a ${r.suite.notApplicable})`,
  );
  for (const a of r.suite.attacks) {
    const mark = a.notApplicable ? 'n/a' : a.status === 'pass' ? 'ok ' : 'FAIL';
    lines.push(`    [${mark}] ${a.id}${a.notApplicable ? ` — ${a.notApplicable}` : a.status !== 'pass' && a.detail ? ` — ${a.detail}` : ''}`);
  }
  lines.push(`  PUBLISHABLE: ${r.publishable ? 'yes' : 'NO'}`);
  if (!r.publishable) for (const why of r.reasons) lines.push(`    - ${why}`);
  return lines.join('\n');
}
