/**
 * Signed preflight reports.
 *
 * `preflight --sign` signs the capability report with a per-host Ed25519 key
 * so a consumer (mcp-audit, mcp-bench) can tell a report this host produced
 * from one somebody wrote by hand or edited. The private key is root-only
 * (0600 in a root-owned dir) and must live outside every path the launcher
 * binds into a sandbox. A signed report is bound to the host (machine id +
 * boot id + hostname + kernel), the agent-sandbox version and the suite
 * version, and is valid only for a short window.
 *
 * What a signature does NOT prove: that the kernel is honest, or that the
 * host is unchanged since the report was issued (beyond a reboot or a
 * version bump, which invalidate it). It proves "this host's root ran this
 * version of the preflight and got this result at issued_at".
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import { constants, readFileSync } from 'node:fs';
import { lstat, mkdir, open, chmod, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import { capabilityReportSchema, derivePublishable, foldSuite, type CapabilityReport } from './report.js';
import { AGENT_SANDBOX_VERSION, SUITE_VERSION } from './version.js';

export const SIGNED_PREFLIGHT_SCHEMA = 'agent-sandbox/signed-preflight@1';
export const DEFAULT_KEY_DIR = '/var/lib/agent-sandbox/attest';
export const PRIVATE_KEY_FILE = 'preflight-ed25519.key';
export const PUBLIC_KEY_FILE = 'preflight-ed25519.pub';
export const DEFAULT_TTL_MS = 60 * 60 * 1000; // 1 h
export const MAX_TTL_MS = 6 * 60 * 60 * 1000; // 6 h hard cap, signer and verifier
export const MAX_SIGNED_BYTES = 1024 * 1024;
/** Clock skew tolerated for issued_at in the future. */
export const MAX_SKEW_MS = 5 * 60 * 1000;

/**
 * Host paths a sandbox can see (see buildBwrapArgs / prepareSyntheticEtc).
 * The key dir must not be under any of them.
 */
export const SANDBOX_VISIBLE_PREFIXES: readonly string[] = ['/usr', '/etc', '/bin', '/sbin', '/lib', '/lib64'];

const bindingSchema = z
  .object({
    host_id: z.string().regex(/^[0-9a-f]{64}$/),
    agent_sandbox_version: z.string().max(64),
    suite_version: z.string().max(64),
    key_id: z.string().regex(/^[0-9a-f]{64}$/),
    issued_at: z.string().max(40),
    expires_at: z.string().max(40),
    nonce: z.string().regex(/^[0-9a-f]{32}$/),
  })
  .strict();
export type PreflightBinding = z.infer<typeof bindingSchema>;

const payloadSchema = z.object({ report: capabilityReportSchema, binding: bindingSchema }).strict();

const envelopeSchema = z
  .object({
    schema: z.literal(SIGNED_PREFLIGHT_SCHEMA),
    alg: z.literal('ed25519'),
    key_id: z.string().regex(/^[0-9a-f]{64}$/),
    payload: z.string().max(MAX_SIGNED_BYTES).regex(/^[A-Za-z0-9+/]*={0,2}$/),
    signature: z.string().regex(/^[A-Za-z0-9+/]{86}==$/),
  })
  .strict();
export type SignedPreflight = z.infer<typeof envelopeSchema>;

export interface HostKey {
  privateKey: KeyObject;
  publicKeyPem: string;
  keyId: string;
}

export type VerifyResult =
  | { ok: true; report: CapabilityReport; binding: PreflightBinding; keyId: string }
  | { ok: false; reason: string };

export interface VerifyOptions {
  /** Default: Date.now(). */
  now?: number;
  /** Default: currentHostId(). Pass the consumer's own host id. */
  hostId?: string;
  /** Default: this build's AGENT_SANDBOX_VERSION. */
  version?: string;
  /** Default: this build's SUITE_VERSION. */
  suiteVersion?: string;
  /** Consumers may tighten the window below the signer's TTL. */
  maxAgeMs?: number;
  /** Default true: a non-publishable report never verifies. */
  requirePublishable?: boolean;
}

function readOr(p: string): string {
  try {
    return readFileSync(p, 'utf8').trim();
  } catch {
    return '';
  }
}

/**
 * Stable id of this host and boot: sha256 over machine-id, boot_id, hostname
 * and kernel release. A reboot or kernel change invalidates every report.
 */
export function currentHostId(): string {
  const parts = {
    machine_id: readOr('/etc/machine-id'),
    boot_id: readOr('/proc/sys/kernel/random/boot_id'),
    hostname: os.hostname(),
    release: os.release(),
  };
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}

function rawPublicKey(pub: KeyObject): Buffer {
  const der = pub.export({ type: 'spki', format: 'der' });
  // Ed25519 SPKI is a fixed 12-byte prefix + 32-byte key.
  return der.subarray(der.length - 32);
}

export function keyIdOf(pub: KeyObject): string {
  return createHash('sha256').update(rawPublicKey(pub)).digest('hex');
}

function toPublicKey(k: string | Buffer | KeyObject): KeyObject {
  let key: KeyObject;
  if (typeof k === 'object' && 'type' in k && typeof (k as KeyObject).export === 'function') {
    key = (k as KeyObject).type === 'private' ? createPublicKey(k as KeyObject) : (k as KeyObject);
  } else if (Buffer.isBuffer(k) && k.length === 32) {
    key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), k]), format: 'der', type: 'spki' });
  } else {
    key = createPublicKey(typeof k === 'string' ? k : k.toString('utf8'));
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error(`public key is ${String(key.asymmetricKeyType)}, not ed25519`);
  return key;
}

function isUnder(p: string, prefix: string): boolean {
  const rel = path.relative(prefix, p);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Refuse a key dir a sandbox could see, or one a non-root user could swap:
 * every existing ancestor must be a root-owned real directory that is not
 * group/other-writable (a root-owned sticky dir such as /tmp is accepted).
 */
async function assertSafeDir(dir: string, forbidUnder: readonly string[]): Promise<void> {
  if (!path.isAbsolute(dir)) throw new Error(`key dir must be absolute: ${dir}`);
  const norm = path.resolve(dir);
  for (const pre of [...SANDBOX_VISIBLE_PREFIXES, ...forbidUnder]) {
    if (isUnder(norm, path.resolve(pre))) throw new Error(`key dir ${norm} is under sandbox-visible path ${pre}`);
  }
  const chain: string[] = [];
  for (let p = norm; ; p = path.dirname(p)) {
    chain.unshift(p);
    if (p === path.dirname(p)) break;
  }
  for (const p of chain) {
    let st;
    try {
      st = await lstat(p);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return; // created below by root
      throw e;
    }
    if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`key dir ancestor ${p} is not a real directory`);
    if (st.uid !== 0) throw new Error(`key dir ancestor ${p} is not owned by root`);
    const sticky = (st.mode & 0o1000) !== 0;
    if ((st.mode & 0o022) !== 0 && !(sticky && p !== norm)) throw new Error(`key dir ancestor ${p} is group/other-writable`);
  }
}

async function assertKeyFile(p: string, mode: 'private' | 'public'): Promise<void> {
  const st = await lstat(p);
  if (!st.isFile()) throw new Error(`${p} is not a regular file`);
  if (st.uid !== 0) throw new Error(`${p} is not owned by root`);
  if (st.nlink !== 1) throw new Error(`${p} has ${st.nlink} hard links`);
  const forbidden = mode === 'private' ? 0o077 : 0o022;
  if ((st.mode & forbidden) !== 0) throw new Error(`${p} mode ${(st.mode & 0o777).toString(8)} is too open`);
}

async function readNoFollow(p: string): Promise<string> {
  const fh = await open(p, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const st = await fh.stat();
    if (!st.isFile() || st.size > 16 * 1024) throw new Error(`${p} is not a small regular file`);
    return await fh.readFile('utf8');
  } finally {
    await fh.close();
  }
}

function requireRoot(what: string): void {
  if ((process.geteuid?.() ?? -1) !== 0) throw new Error(`${what} requires root (the key is root-only)`);
}

/**
 * Load this host's preflight signing key, creating it on first use. Root
 * only. The private half is 0600 root; the public half is 0644 next to it.
 */
export async function loadOrCreateHostKey(opts: { dir?: string; forbidUnder?: readonly string[] } = {}): Promise<HostKey> {
  requireRoot('loadOrCreateHostKey');
  const raw = opts.dir ?? DEFAULT_KEY_DIR;
  if (!path.isAbsolute(raw)) throw new Error(`key dir must be absolute: ${raw}`);
  const dir = path.resolve(raw);
  await assertSafeDir(dir, opts.forbidUnder ?? []);
  await mkdir(dir, { recursive: true, mode: 0o755 });
  await assertSafeDir(dir, opts.forbidUnder ?? []);
  const privPath = path.join(dir, PRIVATE_KEY_FILE);
  const pubPath = path.join(dir, PUBLIC_KEY_FILE);
  let privPem: string;
  try {
    await assertKeyFile(privPath, 'private');
    privPem = await readNoFollow(privPath);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    const { privateKey } = generateKeyPairSync('ed25519');
    privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    // why: O_EXCL so a racing creator or a planted file is never overwritten or followed.
    const fh = await open(privPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      await fh.writeFile(privPem);
      await fh.chmod(0o600);
    } finally {
      await fh.close();
    }
  }
  const privateKey = createPrivateKey(privPem);
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error(`${privPath} is not an ed25519 key`);
  const pub = createPublicKey(privateKey);
  const publicKeyPem = pub.export({ type: 'spki', format: 'pem' }).toString();
  // The public half is derived, so (re)write it atomically every time.
  const tmp = `${pubPath}.${randomBytes(6).toString('hex')}.tmp`;
  await writeFile(tmp, publicKeyPem, { mode: 0o644, flag: 'wx' });
  await chmod(tmp, 0o644);
  await rename(tmp, pubPath);
  return { privateKey, publicKeyPem, keyId: keyIdOf(pub) };
}

/**
 * Read the host public key a consumer should trust, with the same ownership
 * checks (root-owned, not group/other-writable, no symlinks).
 */
export async function loadHostPublicKey(dir: string = DEFAULT_KEY_DIR): Promise<string> {
  if (!path.isAbsolute(dir)) throw new Error(`key dir must be absolute: ${dir}`);
  const d = path.resolve(dir);
  await assertSafeDir(d, []);
  const p = path.join(d, PUBLIC_KEY_FILE);
  await assertKeyFile(p, 'public');
  const pem = await readNoFollow(p);
  toPublicKey(pem);
  return pem;
}

/** Sign a capability report for this host. */
export function signPreflight(
  report: CapabilityReport,
  key: Pick<HostKey, 'privateKey'>,
  opts: { now?: number; ttlMs?: number; hostId?: string } = {},
): SignedPreflight {
  const ttl = opts.ttlMs ?? DEFAULT_TTL_MS;
  if (!Number.isSafeInteger(ttl) || ttl <= 0 || ttl > MAX_TTL_MS) throw new Error(`ttlMs must be an integer in (0, ${MAX_TTL_MS}]`);
  const now = opts.now ?? Date.now();
  const parsed = capabilityReportSchema.parse(report);
  const pub = createPublicKey(key.privateKey);
  const keyId = keyIdOf(pub);
  const binding: PreflightBinding = {
    host_id: opts.hostId ?? currentHostId(),
    agent_sandbox_version: AGENT_SANDBOX_VERSION,
    suite_version: SUITE_VERSION,
    key_id: keyId,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttl).toISOString(),
    nonce: randomBytes(16).toString('hex'),
  };
  const payload = Buffer.from(JSON.stringify({ report: parsed, binding }), 'utf8');
  const signature = edSign(null, signedMessage(payload), key.privateKey);
  return {
    schema: SIGNED_PREFLIGHT_SCHEMA,
    alg: 'ed25519',
    key_id: keyId,
    payload: payload.toString('base64'),
    signature: signature.toString('base64'),
  };
}

function signedMessage(payload: Buffer): Buffer {
  // why: domain separation, so a signature over some other blob is never a valid preflight signature.
  return Buffer.concat([Buffer.from(SIGNED_PREFLIGHT_SCHEMA + '\n', 'utf8'), payload]);
}

/**
 * Verify a signed preflight. Never throws; every failure is `{ ok: false }`.
 * Checks, in order: envelope shape and size, the Ed25519 signature over the
 * exact payload bytes, the payload schema, key id, host, agent-sandbox and
 * suite versions, the validity window, and (by default) that the report is
 * publishable as re-derived here, not as it claims.
 */
export function verifyPreflight(
  signed: unknown,
  pubkey: string | Buffer | KeyObject,
  opts: VerifyOptions = {},
): VerifyResult {
  const no = (reason: string): VerifyResult => ({ ok: false, reason });
  try {
    let obj: unknown = signed;
    if (typeof signed === 'string' || Buffer.isBuffer(signed)) {
      const text = signed.toString();
      if (Buffer.byteLength(text) > MAX_SIGNED_BYTES * 2) return no('signed report is too large');
      obj = JSON.parse(text);
    }
    const env = envelopeSchema.safeParse(obj);
    if (!env.success) return no('not a signed agent-sandbox preflight (envelope shape)');
    let pub: KeyObject;
    try {
      pub = toPublicKey(pubkey);
    } catch (e) {
      return no(`bad public key: ${e instanceof Error ? e.message : String(e)}`);
    }
    const keyId = keyIdOf(pub);
    if (env.data.key_id !== keyId) return no('signed by a different key');
    const payload = Buffer.from(env.data.payload, 'base64');
    if (payload.toString('base64') !== env.data.payload) return no('payload is not canonical base64');
    const sig = Buffer.from(env.data.signature, 'base64');
    if (!edVerify(null, signedMessage(payload), pub, sig)) return no('signature does not verify');

    let inner: unknown;
    try {
      inner = JSON.parse(payload.toString('utf8'));
    } catch {
      return no('payload is not JSON');
    }
    const p = payloadSchema.safeParse(inner);
    if (!p.success) return no('payload does not match the report schema');
    const { report, binding } = p.data;
    if (binding.key_id !== keyId) return no('binding key id mismatch');
    if (binding.host_id !== (opts.hostId ?? currentHostId())) return no('report was issued for another host or boot');
    if (binding.agent_sandbox_version !== (opts.version ?? AGENT_SANDBOX_VERSION)) {
      return no(`agent-sandbox version ${binding.agent_sandbox_version} != ${opts.version ?? AGENT_SANDBOX_VERSION}`);
    }
    const suiteVersion = opts.suiteVersion ?? SUITE_VERSION;
    if (binding.suite_version !== suiteVersion || report.suite.version !== suiteVersion) return no('attacker suite version mismatch');

    const now = opts.now ?? Date.now();
    const issued = Date.parse(binding.issued_at);
    const expires = Date.parse(binding.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expires)) return no('bad validity timestamps');
    if (expires <= issued || expires - issued > MAX_TTL_MS) return no('validity window is empty or longer than the maximum');
    if (issued - now > MAX_SKEW_MS) return no('report is issued in the future');
    if (now >= expires) return no('report has expired');
    const maxAge = opts.maxAgeMs;
    if (maxAge !== undefined && (!Number.isFinite(maxAge) || maxAge < 0 || now - issued > maxAge)) return no('report is older than the consumer allows');

    const refold = foldSuite(report.suite.attacks, report.suite.version);
    if (refold.result !== report.suite.result || refold.ran !== report.suite.ran || refold.failed !== report.suite.failed || refold.blocked !== report.suite.blocked) {
      return no('suite totals disagree with its attack list');
    }
    const derived = derivePublishable({ profile: report.profile, capabilities: report.capabilities, suite: report.suite });
    if (derived.publishable !== report.publishable) return no('report publishable flag disagrees with its own contents');
    if ((opts.requirePublishable ?? true) && !derived.publishable) return no(`report is not publishable: ${derived.reasons.join('; ')}`);
    return { ok: true, report, binding, keyId };
  } catch (e) {
    return no(`verification error: ${e instanceof Error ? e.message : String(e)}`);
  }
}
