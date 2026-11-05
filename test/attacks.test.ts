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

describe('suite uses the exact production launch path (no caps needed)', () => {
  it('the attacker harness builds no command line and spawns nothing of its own', async () => {
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../src/attacks/harness.ts', import.meta.url), 'utf8');
    expect(src).not.toMatch(/\bspawn\(/);
    expect(src).not.toMatch(/['"]bwrap['"]/);
    expect(src).not.toMatch(/['"]setpriv['"]|['"]prlimit['"]/);
    expect(src).toMatch(/\blaunchWith\(/);
  });

  it("drop:'none' yields exactly the production invocation (argv AND env)", async () => {
    const { controlsFor, suiteLaunchOptions } = await import('../src/attacks/harness.js');
    const { buildSandboxInvocation } = await import('../src/launcher.js');
    const worker = { name: 'asbx_wtest', uid: 60000, gid: 60000 };
    const opts = suiteLaunchOptions({ worker, script: 'true', roBinds: [{ src: '/x', dest: '/y' }], netns: 'asbx_ns' });
    expect(controlsFor('none')).toEqual({});
    expect(buildSandboxInvocation(opts, '/tmp/e', controlsFor('none'))).toEqual(buildSandboxInvocation(opts, '/tmp/e'));
  });
});

describe('no spawn site inherits the harness env (no caps needed)', () => {
  it('every src file that imports node:child_process routes through MINIMAL_ENV', async () => {
    const { readdirSync, readFileSync, statSync } = await import('node:fs');
    const path = await import('node:path');
    const root = new URL('../src/', import.meta.url).pathname;
    const files: string[] = [];
    const walk = (d: string): void => {
      for (const n of readdirSync(d)) {
        const p = path.join(d, n);
        if (statSync(p).isDirectory()) walk(p);
        else if (p.endsWith('.ts')) files.push(p);
      }
    };
    walk(root);
    const offenders = files.filter((f) => {
      const src = readFileSync(f, 'utf8');
      return /from 'node:child_process'/.test(src) && !/MINIMAL_ENV/.test(src);
    });
    expect(offenders.map((f) => path.relative(root, f))).toEqual([]);
  });
});
