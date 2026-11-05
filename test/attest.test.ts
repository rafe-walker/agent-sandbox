import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { mkdtemp, rm, readFile, stat, writeFile, chmod, symlink, mkdir } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  signPreflight,
  verifyPreflight,
  loadOrCreateHostKey,
  loadHostPublicKey,
  currentHostId,
  MAX_TTL_MS,
  PUBLIC_KEY_FILE,
  type SignedPreflight,
} from '../src/attest.js';
import { CAPABILITY_NAMES, foldSuite, type CapabilityReport } from '../src/report.js';
import { AGENT_SANDBOX_VERSION, SUITE_VERSION } from '../src/version.js';
import { runInSandbox } from '../src/launcher.js';
import { hasSandboxCaps, requireCapsOrSkip } from './helpers/caps.js';

const NOW = Date.parse('2026-11-05T12:00:00Z');

function goodReport(): CapabilityReport {
  const suite = foldSuite([{ id: 'a1', title: 't', blocked: true, controlSucceeded: true, status: 'pass' }]);
  return {
    schemaVersion: 1,
    profile: 'linux-sandbox',
    createdAt: new Date(NOW).toISOString(),
    host: { platform: 'linux', release: '6', arch: 'x64', euid: 0 },
    capabilities: Object.fromEntries(CAPABILITY_NAMES.map((n) => [n, { status: 'pass' as const }])),
    suite,
    publishable: true,
    reasons: [],
  };
}

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const opts = { now: NOW + 1000 };

function signed(report = goodReport(), o: Parameters<typeof signPreflight>[2] = {}): SignedPreflight {
  return signPreflight(report, { privateKey }, { now: NOW, ...o });
}

/** Re-encode an edited payload, keeping the original signature. */
function edit(s: SignedPreflight, f: (inner: { report: CapabilityReport; binding: Record<string, unknown> }) => void): SignedPreflight {
  const inner = JSON.parse(Buffer.from(s.payload, 'base64').toString('utf8'));
  f(inner);
  return { ...s, payload: Buffer.from(JSON.stringify(inner)).toString('base64') };
}

describe('signed preflight', () => {
  it('a genuine signed report verifies (object, string, raw-key and KeyObject forms)', () => {
    const s = signed();
    expect(verifyPreflight(s, pem, opts).ok).toBe(true);
    expect(verifyPreflight(JSON.stringify(s), publicKey, opts).ok).toBe(true);
    const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    expect(verifyPreflight(s, raw, opts).ok).toBe(true);
    const r = verifyPreflight(s, pem, opts);
    expect(r.ok && r.binding.host_id).toBe(currentHostId());
    expect(r.ok && r.binding.agent_sandbox_version).toBe(AGENT_SANDBOX_VERSION);
  });

  it('a hand-written report (bare, or wrapped with a made-up signature) fails', () => {
    const bare = goodReport();
    expect(verifyPreflight(bare, pem, opts)).toMatchObject({ ok: false, reason: expect.stringMatching(/envelope/) });
    const forged: SignedPreflight = {
      schema: 'agent-sandbox/signed-preflight@1',
      alg: 'ed25519',
      key_id: signed().key_id,
      payload: Buffer.from(JSON.stringify({ report: bare, binding: JSON.parse(Buffer.from(signed().payload, 'base64').toString()).binding })).toString('base64'),
      signature: Buffer.alloc(64, 7).toString('base64'),
    };
    expect(verifyPreflight(forged, pem, opts)).toMatchObject({ ok: false, reason: 'signature does not verify' });
  });

  it('an edited report fails: capability, publishable, attack, binding, nonce, whitespace', () => {
    const s = signed();
    const edits: Array<(i: { report: CapabilityReport; binding: Record<string, unknown> }) => void> = [
      (i) => (i.report.capabilities.net_enforced = { status: 'fail' }),
      (i) => (i.report.publishable = false),
      (i) => (i.report.suite.attacks[0]!.blocked = false),
      (i) => (i.binding.expires_at = new Date(NOW + 10 * 3600_000).toISOString()),
      (i) => (i.binding.host_id = '0'.repeat(64)),
      (i) => (i.binding.nonce = 'a'.repeat(32)),
    ];
    for (const e of edits) {
      const r = verifyPreflight(edit(s, e), pem, opts);
      expect(r.ok).toBe(false);
    }
    // Same JSON, different bytes: still rejected (signature is over bytes).
    const ws = { ...s, payload: Buffer.from(Buffer.from(s.payload, 'base64').toString() + ' ').toString('base64') };
    expect(verifyPreflight(ws, pem, opts).ok).toBe(false);
  });

  it('a report signed by another key fails, even with a matching key_id field', () => {
    const other = generateKeyPairSync('ed25519');
    const s = signPreflight(goodReport(), { privateKey: other.privateKey }, { now: NOW });
    expect(verifyPreflight(s, pem, opts)).toMatchObject({ ok: false, reason: 'signed by a different key' });
    expect(verifyPreflight({ ...s, key_id: signed().key_id }, pem, opts)).toMatchObject({ ok: false, reason: 'signature does not verify' });
  });

  it('a validly signed report for a self-inconsistent report fails (no trusting its own flag)', () => {
    const lie = goodReport();
    lie.capabilities.creds_absent = { status: 'fail' };
    expect(verifyPreflight(signed(lie), pem, opts)).toMatchObject({ ok: false, reason: expect.stringMatching(/disagrees/) });
    const totals = goodReport();
    totals.suite.attacks[0]!.controlSucceeded = false; // totals still say pass
    expect(verifyPreflight(signed(totals), pem, opts)).toMatchObject({ ok: false, reason: expect.stringMatching(/suite totals/) });
  });

  it('a non-publishable report does not verify unless the caller opts out', () => {
    const dev = { ...goodReport(), profile: 'dev' as const, publishable: false, reasons: ['x'] };
    expect(verifyPreflight(signed(dev), pem, opts)).toMatchObject({ ok: false, reason: expect.stringMatching(/not publishable/) });
    expect(verifyPreflight(signed(dev), pem, { ...opts, requirePublishable: false }).ok).toBe(true);
  });

  it('is bound to the host, the agent-sandbox version and the suite version', () => {
    const s = signed();
    expect(verifyPreflight(s, pem, { ...opts, hostId: 'f'.repeat(64) })).toMatchObject({ ok: false, reason: expect.stringMatching(/another host/) });
    expect(verifyPreflight(s, pem, { ...opts, version: '0.2.0' })).toMatchObject({ ok: false, reason: expect.stringMatching(/version/) });
    expect(verifyPreflight(s, pem, { ...opts, suiteVersion: '9' })).toMatchObject({ ok: false, reason: expect.stringMatching(/suite version/) });
    expect(verifyPreflight(signed(goodReport(), { hostId: 'a'.repeat(64) }), pem, opts).ok).toBe(false);
  });

  it('has a short validity window: expired, future, too-long TTL, consumer max age', () => {
    const s = signed(goodReport(), { ttlMs: 60_000 });
    expect(verifyPreflight(s, pem, { now: NOW + 59_000 }).ok).toBe(true);
    expect(verifyPreflight(s, pem, { now: NOW + 60_000 })).toMatchObject({ ok: false, reason: 'report has expired' });
    expect(verifyPreflight(s, pem, { now: NOW - 3600_000 })).toMatchObject({ ok: false, reason: expect.stringMatching(/future/) });
    expect(verifyPreflight(s, pem, { now: NOW + 30_000, maxAgeMs: 10_000 })).toMatchObject({ ok: false, reason: expect.stringMatching(/older/) });
    for (const bad of [Number.NaN, -1, Number.POSITIVE_INFINITY, Number('1e400')]) {
      expect(verifyPreflight(s, pem, { now: NOW + 1000, maxAgeMs: bad }).ok).toBe(false);
    }
    for (const bad of [0, -5, MAX_TTL_MS + 1, Number.NaN, 1.5]) {
      expect(() => signed(goodReport(), { ttlMs: bad })).toThrow(/ttlMs/);
    }
  });

  it('hostile input never throws and never verifies', () => {
    const deep = '['.repeat(100_000) + ']'.repeat(100_000);
    const inputs: unknown[] = [null, 42, 'not json', deep, '{"__proto__":{"ok":true}}', { ...signed(), extra: 1 }, { ...signed(), signature: 'x'.repeat(5000) }, Buffer.alloc(3 * 1024 * 1024, 0x20)];
    for (const i of inputs) {
      const r = verifyPreflight(i, pem, opts);
      expect(r.ok).toBe(false);
    }
    expect(verifyPreflight(signed(), 'not a key', opts)).toMatchObject({ ok: false, reason: expect.stringMatching(/public key/) });
    const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey;
    expect(verifyPreflight(signed(), rsa, opts)).toMatchObject({ ok: false, reason: expect.stringMatching(/not ed25519/) });
  });

  it('AGENT_SANDBOX_VERSION matches package.json', () => {
    const pkg = JSON.parse(readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')) as { version: string };
    expect(AGENT_SANDBOX_VERSION).toBe(pkg.version);
    expect(SUITE_VERSION).toBeTypeOf('string');
  });
});

describe('host key storage (root)', () => {
  const run = hasSandboxCaps() || process.env.AGENT_SANDBOX_REQUIRE_CAPS === '1';
  let base = '';
  beforeAll(async () => {
    if (run) base = await mkdtemp(path.join(tmpdir(), 'asbx-attest-'));
  });
  afterAll(async () => {
    if (base) await rm(base, { recursive: true, force: true });
  });

  it.runIf(run)('creates a 0600 root private key and 0644 public key, and reuses it', async () => {
    requireCapsOrSkip();
    const dir = path.join(base, 'k1');
    const k = await loadOrCreateHostKey({ dir });
    const st = await stat(path.join(dir, 'preflight-ed25519.key'));
    expect(st.mode & 0o777).toBe(0o600);
    expect(st.uid).toBe(0);
    expect((await stat(path.join(dir, PUBLIC_KEY_FILE))).mode & 0o777).toBe(0o644);
    const again = await loadOrCreateHostKey({ dir });
    expect(again.keyId).toBe(k.keyId);
    const pub = await loadHostPublicKey(dir);
    const s = signPreflight(goodReport(), k, { now: NOW });
    expect(verifyPreflight(s, pub, opts).ok).toBe(true);
    // The private key never reaches the signed output or the public file.
    const secret = (await readFile(path.join(dir, 'preflight-ed25519.key'), 'utf8')).split('\n')[1]!;
    expect(secret.length).toBeGreaterThan(20);
    expect(JSON.stringify(s) + Buffer.from(s.payload, 'base64').toString() + pub).not.toContain(secret);
    expect(await readFile(path.join(dir, PUBLIC_KEY_FILE), 'utf8')).toBe(createPublicKey(k.privateKey).export({ type: 'spki', format: 'pem' }).toString());
  });

  it.runIf(run)('refuses a key dir a sandbox can see, a loose key file, or a symlink', async () => {
    requireCapsOrSkip();
    await expect(loadOrCreateHostKey({ dir: '/etc/asbx-test-never' })).rejects.toThrow(/sandbox-visible/);
    await expect(loadOrCreateHostKey({ dir: '/usr/lib/asbx-test-never' })).rejects.toThrow(/sandbox-visible/);
    const src = path.join(base, 'src');
    await expect(loadOrCreateHostKey({ dir: path.join(src, 'k'), forbidUnder: [src] })).rejects.toThrow(/sandbox-visible/);
    await expect(loadOrCreateHostKey({ dir: 'relative/dir' })).rejects.toThrow(/absolute/);

    const loose = path.join(base, 'loose');
    await loadOrCreateHostKey({ dir: loose });
    await chmod(path.join(loose, 'preflight-ed25519.key'), 0o640);
    await expect(loadOrCreateHostKey({ dir: loose })).rejects.toThrow(/too open/);

    const ww = path.join(base, 'ww');
    await mkdir(ww, { mode: 0o777 });
    await chmod(ww, 0o777);
    await expect(loadOrCreateHostKey({ dir: path.join(ww, 'k') })).rejects.toThrow(/writable/);

    const link = path.join(base, 'link');
    const real = path.join(base, 'real');
    await loadOrCreateHostKey({ dir: real });
    await mkdir(link);
    await symlink(path.join(real, 'preflight-ed25519.key'), path.join(link, 'preflight-ed25519.key'));
    await expect(loadOrCreateHostKey({ dir: link })).rejects.toThrow(/regular file/);
    await writeFile(path.join(link, PUBLIC_KEY_FILE), 'x', { mode: 0o666 });
    await chmod(path.join(link, PUBLIC_KEY_FILE), 0o666);
    await expect(loadHostPublicKey(link)).rejects.toThrow(/too open/);
  });

  it.runIf(run)('a sandboxed agent cannot read the private key', async () => {
    requireCapsOrSkip();
    const dir = path.join(base, 'k-sbx');
    await loadOrCreateHostKey({ dir });
    const keyPath = path.join(dir, 'preflight-ed25519.key');
    const r = await runInSandbox(`cat ${keyPath} 2>&1; echo "rc=$?"`, { wallClockMs: 20_000 });
    expect(r.stdout).not.toMatch(/PRIVATE KEY/);
    expect(r.stdout).toMatch(/rc=[1-9]/);
    // Positive control: root on the host can read it, so the check above is meaningful.
    expect(await readFile(keyPath, 'utf8')).toMatch(/PRIVATE KEY/);
  });
});
