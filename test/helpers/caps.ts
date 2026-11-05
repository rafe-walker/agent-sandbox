import { execFileSync } from 'node:child_process';

/** Does this host support the linux-sandbox launcher (Linux + root + bwrap)? */
export function hasSandboxCaps(): boolean {
  if (process.platform !== 'linux') return false;
  if ((process.geteuid?.() ?? -1) !== 0) return false;
  try {
    execFileSync('bwrap', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Gate for capability-requiring tests. When AGENT_SANDBOX_REQUIRE_CAPS=1 (CI),
 * a missing capability is a HARD FAILURE, never a silent skip. Otherwise the
 * caller may skip. Returns true when the test should run.
 */
export function requireCapsOrSkip(): boolean {
  const has = hasSandboxCaps();
  if (!has && process.env.AGENT_SANDBOX_REQUIRE_CAPS === '1') {
    throw new Error(
      'AGENT_SANDBOX_REQUIRE_CAPS=1 but sandbox capabilities are missing ' +
        '(need Linux + root + bwrap). Failing closed instead of skipping.',
    );
  }
  return has;
}
