/**
 * The 25-attack core suite, run from inside the real sandbox config. Each
 * attack must be blocked AND its positive control must succeed (or, only for a
 * vector the HOST provably lacks, be explicitly marked notApplicable).
 * Results are produced host-side.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { coreAttacks, SUITE_SIZE } from '../src/attacks/index.js';
import { foldSuite, type AttackResult } from '../src/report.js';
import { cleanupStaleWorkers } from '../src/launcher.js';
import { cleanupStale } from '../src/net.js';
import { requireCapsOrSkip } from './helpers/caps.js';

const caps = requireCapsOrSkip();
const results: AttackResult[] = [];

describe('suite shape (no caps needed)', () => {
  it(`has exactly ${SUITE_SIZE} attacks with unique ids`, () => {
    const ids = coreAttacks().map((a) => a.id);
    expect(ids).toHaveLength(SUITE_SIZE);
    expect(new Set(ids).size).toBe(SUITE_SIZE);
  });
});

describe.skipIf(!caps)('core attacker suite (requires root)', () => {
  for (const attack of coreAttacks()) {
    it(`${attack.id}: ${attack.title}`, async () => {
      const r = await attack.run();
      results.push(r);
      expect(r.blocked, `not blocked: ${r.detail}`).toBe(true);
      if (r.notApplicable) {
        // Only IPv6 may be N/A, and only with a harness-side reason.
        expect(r.id).toBe('net-ipv6');
        expect(r.notApplicable).toMatch(/no IPv6/);
      } else {
        expect(r.controlSucceeded, `positive control failed: ${r.detail}`).toBe(true);
      }
      expect(r.status).toBe('pass');
    }, 60_000);
  }

  it('folds to a passing suite', () => {
    const s = foldSuite(results);
    expect(s.ran).toBe(SUITE_SIZE);
    expect(s.failed).toBe(0);
    expect(s.result).toBe('pass');
  });
});

afterAll(async () => {
  if (caps) {
    await cleanupStaleWorkers();
    await cleanupStale();
  }
});
