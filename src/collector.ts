/**
 * The trusted evidence collector.
 *
 * A per-attempt UNIX socket under a root-owned dir (default
 * `/run/agent-sandbox/<attempt>/`). The agent submits *proposals*; the
 * collector assigns ids/timestamps/seq itself, derives the attempt identity
 * from the connection (NOT from any field the agent supplies), validates and
 * size-bounds every event, and appends to a canonical store the agent cannot
 * reach. It returns a receipt.
 *
 * Caller-identity note (honest deviation): Node core exposes no getsockopt, so
 * we cannot read SO_PEERCRED directly. We get the SAME property by:
 *   - one socket per attempt (attempt identity = which socket, root-controlled),
 *   - the socket owned by the single worker uid at mode 0600 in a 0700
 *     root-owned dir, so only that uid can connect.
 * The agent therefore can neither forge another attempt's identity nor reach
 * another attempt's socket or the store. See DECISIONS.md.
 */
import net from 'node:net';
import { mkdir, chmod, chown, rm, appendFile, readFile, stat } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { z } from 'zod';

export const PROPOSAL_SCHEMA = 'asbx.proposal.v1';
export const MAX_PROPOSAL_BYTES = 64 * 1024; // 64 KiB per proposal line
export const MAX_DEPTH = 32;

/** Proposal accepted from inside the sandbox. The agent may ONLY set kind+data;
 *  anything it sends for id/attempt/ts/seq is ignored. */
export const proposalSchema = z
  .object({
    schema: z.literal(PROPOSAL_SCHEMA),
    kind: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[a-z0-9][a-z0-9._-]*$/i, 'kind must be a simple token'),
    data: z.unknown(),
  })
  .strict();

export type Proposal = z.infer<typeof proposalSchema>;

export interface Receipt {
  ok: true;
  id: string;
  seq: number;
  ts: string;
  attempt: string;
}
export interface Rejection {
  ok: false;
  error: string;
}

export interface CollectorOptions {
  socketPath: string;
  /** Canonical append-only store. MUST be outside any sandbox bind. */
  storePath: string;
  /** Attempt id this socket belongs to. Collector-assigned, not agent-supplied. */
  attempt: string;
  /** uid allowed to connect; the socket is chowned to it at 0600. */
  workerUid?: number;
}

/** Reject objects that are too deeply nested (hostile-input guard). */
function tooDeep(v: unknown, depth = 0): boolean {
  if (depth > MAX_DEPTH) return true;
  if (v && typeof v === 'object') {
    for (const val of Object.values(v as Record<string, unknown>)) {
      if (tooDeep(val, depth + 1)) return true;
    }
  }
  return false;
}

/** Strip prototype-polluting keys defensively (we never merge, but store clean). */
function hasDangerousKeys(v: unknown, depth = 0): boolean {
  if (depth > MAX_DEPTH) return true;
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    for (const k of Object.keys(v as Record<string, unknown>)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') return true;
      if (hasDangerousKeys((v as Record<string, unknown>)[k], depth + 1)) return true;
    }
  } else if (Array.isArray(v)) {
    for (const item of v) if (hasDangerousKeys(item, depth + 1)) return true;
  }
  return false;
}

export class Collector {
  private server?: net.Server;
  private seq = 0;

  constructor(private readonly opts: CollectorOptions) {}

  async start(): Promise<void> {
    // The socket's dir is traverse-only (0711): bwrap resolves the bind source
    // as the dropped worker uid, which must reach the socket but must not list,
    // create, or delete here. The socket itself is 0600 chowned to the worker;
    // the canonical store lives under a separate 0700 dir (see
    // createAttemptCollector) that the worker cannot traverse at all.
    await mkdir(path.dirname(this.opts.socketPath), { recursive: true, mode: 0o711 });
    await chmod(path.dirname(this.opts.socketPath), 0o711).catch(() => {});
    await rm(this.opts.socketPath, { force: true });

    this.server = net.createServer((sock) => this.onConnection(sock));
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.opts.socketPath, () => resolve());
    });
    // Only the worker uid may connect.
    await chmod(this.opts.socketPath, 0o600);
    if (this.opts.workerUid !== undefined) {
      await chown(this.opts.socketPath, this.opts.workerUid, this.opts.workerUid).catch(() => {});
    }
  }

  async stop(): Promise<void> {
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()));
    await rm(this.opts.socketPath, { force: true });
  }

  /** Number of events written to the canonical store. */
  async count(): Promise<number> {
    try {
      const txt = await readFile(this.opts.storePath, 'utf8');
      return txt.split('\n').filter((l) => l.trim()).length;
    } catch {
      return 0;
    }
  }

  private onConnection(sock: net.Socket): void {
    sock.on('error', () => {});
    let buf = '';
    let closed = false;
    sock.setEncoding('utf8');
    sock.on('data', (chunk: string) => {
      if (closed) return;
      buf += chunk;
      if (buf.length > MAX_PROPOSAL_BYTES) {
        this.reply(sock, { ok: false, error: 'proposal exceeds size limit' });
        closed = true;
        sock.destroy();
        return;
      }
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      closed = true;
      void this.handleLine(sock, line);
    });
  }

  private async handleLine(sock: net.Socket, line: string): Promise<void> {
    const rej = (error: string): void => {
      this.reply(sock, { ok: false, error });
      sock.end();
    };
    if (line.length > MAX_PROPOSAL_BYTES) return rej('proposal exceeds size limit');

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return rej('invalid JSON');
    }
    if (tooDeep(parsed)) return rej('proposal too deeply nested');
    if (hasDangerousKeys(parsed)) return rej('proposal contains disallowed keys');

    const result = proposalSchema.safeParse(parsed);
    if (!result.success) return rej(`schema validation failed: ${result.error.issues[0]?.message ?? 'invalid'}`);

    // The collector assigns identity — never trusts agent-supplied ids/ts.
    const id = 'ev_' + randomBytes(12).toString('hex');
    const ts = new Date().toISOString();
    const seq = ++this.seq;
    const record = {
      id,
      seq,
      ts,
      attempt: this.opts.attempt, // derived from the socket, not the payload
      kind: result.data.kind,
      data: result.data.data,
    };
    try {
      await appendFile(this.opts.storePath, JSON.stringify(record) + '\n', { mode: 0o600 });
    } catch (e) {
      // roll back the seq on a write failure so counts stay honest
      this.seq -= 1;
      return rej(`store write failed: ${e instanceof Error ? e.message : 'error'}`);
    }
    const receipt: Receipt = { ok: true, id, seq, ts, attempt: this.opts.attempt };
    this.reply(sock, receipt);
    sock.end();
  }

  private reply(sock: net.Socket, msg: Receipt | Rejection): void {
    try {
      sock.write(JSON.stringify(msg) + '\n');
    } catch {
      /* peer gone */
    }
  }
}

/**
 * Set up the root-owned per-attempt layout and return the paths. The socket is
 * meant to be bind-mounted into the sandbox; the store is NOT and must stay
 * outside every bind.
 */
export async function createAttemptCollector(opts: {
  runDir: string;
  attempt: string;
  workerUid?: number;
}): Promise<{ collector: Collector; socketPath: string; storePath: string }> {
  const base = path.join(opts.runDir, opts.attempt);
  // Traverse-only so the worker uid can reach the socket dir but not the store.
  await mkdir(base, { recursive: true, mode: 0o711 });
  await chmod(base, 0o711).catch(() => {});
  await chmod(opts.runDir, 0o711).catch(() => {}); // ensure the parent is traversable

  const sockDir = path.join(base, 'sock'); // 0711 (set by Collector.start)
  const storeDir = path.join(base, 'store'); // 0700: fully opaque to the worker
  await mkdir(storeDir, { recursive: true, mode: 0o700 });
  await chmod(storeDir, 0o700).catch(() => {});

  const socketPath = path.join(sockDir, 'collector.sock');
  const storePath = path.join(storeDir, 'events.jsonl'); // never bind-mounted
  const collector = new Collector({
    socketPath,
    storePath,
    attempt: opts.attempt,
    ...(opts.workerUid !== undefined ? { workerUid: opts.workerUid } : {}),
  });
  await collector.start();
  return { collector, socketPath, storePath };
}

/** Read the appended events back (host-side, trusted). */
export async function readStore(storePath: string): Promise<Array<Record<string, unknown>>> {
  try {
    await stat(storePath);
  } catch {
    return [];
  }
  const txt = await readFile(storePath, 'utf8');
  return txt
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

/**
 * Submit a proposal to a collector socket (used by the sandbox-submit CLI and
 * tests). Resolves with the receipt or rejection.
 */
export function submitProposal(
  socketPath: string,
  kind: string,
  data: unknown,
): Promise<Receipt | Rejection> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(socketPath);
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('connect', () => {
      sock.write(JSON.stringify({ schema: PROPOSAL_SCHEMA, kind, data }) + '\n');
    });
    sock.on('data', (d: string) => {
      buf += d;
      if (buf.includes('\n')) {
        try {
          resolve(JSON.parse(buf.trim()) as Receipt | Rejection);
        } catch {
          reject(new Error('bad receipt'));
        }
        sock.end();
      }
    });
    sock.on('error', reject);
  });
}
