import { describe, it, expect } from 'vitest';
import {
  CAPABILITY_NAMES,
  derivePublishable,
  foldSuite,
  formatReport,
  capabilityReportSchema,
  type AttackResult,
  type CapabilityName,
  type CapabilityResult,
} from '../src/report.js';
import { SUITE_VERSION } from '../src/version.js';

function allPass(): Partial<Record<CapabilityName, CapabilityResult>> {
  const caps: Partial<Record<CapabilityName, CapabilityResult>> = {};
  for (const n of CAPABILITY_NAMES) caps[n] = { status: 'pass' };
  return caps;
}

const passingAttack: AttackResult = {
  id: 'a1',
  title: 'demo',
  blocked: true,
  controlSucceeded: true,
  status: 'pass',
};

describe('derivePublishable', () => {
  it('is publishable for linux-sandbox with all caps pass + suite pass', () => {
    const suite = foldSuite([passingAttack]);
    const { publishable, reasons } = derivePublishable({
      profile: 'linux-sandbox',
      capabilities: allPass(),
      suite,
    });
    expect(publishable).toBe(true);
    expect(reasons).toEqual([]);
  });

  it('is never publishable for dev', () => {
    const suite = foldSuite([passingAttack]);
    const { publishable, reasons } = derivePublishable({
      profile: 'dev',
      capabilities: allPass(),
      suite,
    });
    expect(publishable).toBe(false);
    expect(reasons.join(' ')).toMatch(/only "linux-sandbox" is publishable/);
  });

  it('fails closed when a capability was not probed', () => {
    const caps = allPass();
    delete caps.net_enforced;
    const { publishable, reasons } = derivePublishable({
      profile: 'linux-sandbox',
      capabilities: caps,
      suite: foldSuite([passingAttack]),
    });
    expect(publishable).toBe(false);
    expect(reasons.join(' ')).toMatch(/"net_enforced" was not probed/);
  });

  it('fails when a capability failed', () => {
    const caps = allPass();
    caps.creds_absent = { status: 'fail', detail: 'key found in env' };
    const { publishable, reasons } = derivePublishable({
      profile: 'linux-sandbox',
      capabilities: caps,
      suite: foldSuite([passingAttack]),
    });
    expect(publishable).toBe(false);
    expect(reasons.join(' ')).toMatch(/creds_absent.*key found in env/);
  });

  it('fails when the suite did not pass', () => {
    const failing: AttackResult = { ...passingAttack, blocked: false, status: 'fail' };
    const { publishable, reasons } = derivePublishable({
      profile: 'linux-sandbox',
      capabilities: allPass(),
      suite: foldSuite([failing]),
    });
    expect(publishable).toBe(false);
    expect(reasons.join(' ')).toMatch(/attacker suite result is "fail"/);
  });

  it('fails on a suite version mismatch', () => {
    const suite = foldSuite([passingAttack], '0.0.1-wrong');
    const { publishable, reasons } = derivePublishable({
      profile: 'linux-sandbox',
      capabilities: allPass(),
      suite,
    });
    expect(publishable).toBe(false);
    expect(reasons.join(' ')).toMatch(/version .* != expected/);
  });
});

describe('foldSuite', () => {
  it('is not-probed when empty (zero attacks never passes)', () => {
    expect(foldSuite([]).result).toBe('not-probed');
  });

  it('fails if an attack was not blocked', () => {
    const s = foldSuite([{ ...passingAttack, blocked: false }]);
    expect(s.result).toBe('fail');
    expect(s.failed).toBe(1);
  });

  it('fails if a positive control did not succeed', () => {
    const s = foldSuite([{ ...passingAttack, controlSucceeded: false }]);
    expect(s.result).toBe('fail');
  });

  it('excuses an N/A attack from its control but still requires it be blocked', () => {
    const na = { ...passingAttack, id: 'v6', controlSucceeded: false, notApplicable: 'host has no IPv6' };
    expect(foldSuite([na]).result).toBe('pass');
    expect(foldSuite([na]).notApplicable).toBe(1);
    expect(foldSuite([{ ...na, blocked: false }]).result).toBe('fail');
  });

  it('a missing control without an N/A reason fails', () => {
    expect(foldSuite([{ ...passingAttack, controlSucceeded: false }]).result).toBe('fail');
  });

  it('counts blocked attacks', () => {
    const s = foldSuite([passingAttack, { ...passingAttack, id: 'a2' }]);
    expect(s.blocked).toBe(2);
    expect(s.result).toBe('pass');
  });
});

describe('report shape', () => {
  it('validates against the schema and formats', () => {
    const report = {
      schemaVersion: 1 as const,
      profile: 'linux-sandbox' as const,
      createdAt: new Date().toISOString(),
      host: { platform: 'linux', release: '6.x', arch: 'x64', euid: 0 },
      capabilities: allPass(),
      suite: foldSuite([passingAttack]),
      publishable: true,
      reasons: [],
    };
    expect(() => capabilityReportSchema.parse(report)).not.toThrow();
    expect(formatReport(report)).toMatch(/PUBLISHABLE: yes/);
    expect(SUITE_VERSION).toBe(report.suite.version);
  });
});
