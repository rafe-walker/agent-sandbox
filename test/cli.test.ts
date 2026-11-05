/**
 * The escape-review repro, through the real CLI: fake credentials in the
 * harness env must not be readable from /proc/1/environ (bwrap) or any other
 * visible process. Fake values only; the test prints counts, never contents.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { requireCapsOrSkip } from './helpers/caps.js';

const caps = requireCapsOrSkip();
const CLI = new URL('../dist/cli.js', import.meta.url).pathname;

describe.skipIf(!caps)('cli run: harness creds never reach the sandbox', () => {
  it('fake GITHUB_TOKEN / ANTHROPIC_API_KEY / HTTPS_PROXY are absent from /proc/1/environ and every visible process', () => {
    const tag = 'asbxfake' + Math.random().toString(36).slice(2, 10);
    // The search pattern is assembled from two halves passed as $1 $2, so no
    // argv ever holds the whole secret. Joined with ${} braces to avoid the
    // "$patX" variable-name trap that would yield an empty (match-all) pattern.
    const h1 = tag.slice(0, 6);
    const h2 = tag.slice(6);
    const script = [
      'pat="${1}${2}"',
      'p1=$(cat /proc/1/environ | tr "\\0" "\\n" | grep -c -- "$pat")',
      'all=0; for f in /proc/[0-9]*/environ; do n=$(cat "$f" 2>/dev/null | tr "\\0" "\\n" | grep -c -- "$pat"); all=$((all+n)); done',
      'echo "pat=$pat pid1=$p1 all=$all"',
    ].join('\n');
    const r = spawnSync(process.execPath, [CLI, 'run', '--profile', 'linux-sandbox', '--wall-ms', '20000', '--', '/bin/sh', '-c', script, 'sh', h1, h2], {
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH ?? '/usr/bin:/bin',
        GITHUB_TOKEN: `${tag}-gh`,
        ANTHROPIC_API_KEY: `${tag}-key`,
        HTTPS_PROXY: `http://${tag}.invalid:1`,
      },
      timeout: 60_000,
    });
    expect(r.status, r.stderr).toBe(0);
    // pat must be the full non-empty tag: guards against the empty-pattern trap
    // that matches every line and would hide a real leak.
    expect(r.stdout).toContain(`pat=${tag} `);
    expect(r.stdout).toMatch(/pid1=0 all=0/);
  });
});
