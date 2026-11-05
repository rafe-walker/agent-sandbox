import { describe, it, expect } from 'vitest';
import { runPreflight, checkPrereqs, type Attack, type CapabilityProbe } from '../src/preflight.js';
import { CAPABILITY_NAMES } from '../src/report.js';

const allPassProbes: CapabilityProbe[] = CAPABILITY_NAMES.map((name) => ({
  name,
  run: () => ({ status: 'pass' as const }),
}));

const okAttack: Attack = {
  id: 'demo',
  title: 'demo attack',
  run: () => ({
    id: 'demo',
    title: 'demo attack',
    blocked: true,
    controlSucceeded: true,
    status: 'pass' as const,
  }),
};

describe('runPreflight', () => {
  it('produces a publishable report for linux-sandbox when probes+suite pass', async () => {
    const r = await runPreflight({
      profile: 'linux-sandbox',
      capabilityProbes: allPassProbes,
      attacks: [okAttack],
      now: () => new Date('2026-11-05T00:00:00Z'),
    });
    expect(r.publishable).toBe(true);
    expect(r.createdAt).toBe('2026-11-05T00:00:00.000Z');
  });

  it('is non-publishable on a fresh checkout (no probes, no attacks)', async () => {
    const r = await runPreflight({ profile: 'linux-sandbox' });
    expect(r.publishable).toBe(false);
    expect(r.suite.result).toBe('not-probed');
  });

  it('captures a throwing probe as a failure, does not throw', async () => {
    const r = await runPreflight({
      profile: 'linux-sandbox',
      capabilityProbes: [
        ...allPassProbes.slice(1),
        {
          name: CAPABILITY_NAMES[0],
          run: () => {
            throw new Error('boom');
          },
        },
      ],
      attacks: [okAttack],
    });
    expect(r.publishable).toBe(false);
    expect(r.capabilities[CAPABILITY_NAMES[0]]?.status).toBe('fail');
    expect(r.capabilities[CAPABILITY_NAMES[0]]?.detail).toMatch(/boom/);
  });

  it('captures a throwing attack as a non-blocked failure', async () => {
    const r = await runPreflight({
      profile: 'linux-sandbox',
      capabilityProbes: allPassProbes,
      attacks: [
        {
          id: 'x',
          title: 'throws',
          run: () => {
            throw new Error('kaboom');
          },
        },
      ],
    });
    expect(r.suite.result).toBe('fail');
    expect(r.suite.attacks[0]?.blocked).toBe(false);
  });

  it('refuses the reserved microvm profile', async () => {
    await expect(runPreflight({ profile: 'microvm' })).rejects.toThrow(/microvm/);
  });
});

describe('checkPrereqs', () => {
  it('reports platform and binaries without throwing', async () => {
    const prereqs = await checkPrereqs();
    const names = prereqs.map((p) => p.name);
    expect(names).toContain('platform-linux');
    expect(names).toContain('bin:bwrap');
    expect(names).toContain('user-namespaces');
  });
});
