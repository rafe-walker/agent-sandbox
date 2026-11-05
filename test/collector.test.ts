import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  Collector,
  createAttemptCollector,
  readStore,
  submitProposal,
  MAX_PROPOSAL_BYTES,
  type Receipt,
} from '../src/collector.js';
import { evidenceWriterProbe } from '../src/collector-probes.js';
import { requireCapsOrSkip } from './helpers/caps.js';

const caps = requireCapsOrSkip();

const dirs: string[] = [];
async function tmp(): Promise<string> {
  const d = await mkdtemp(path.join(tmpdir(), 'asbx-col-'));
  dirs.push(d);
  return d;
}
afterEach(async () => {
  while (dirs.length) await rm(dirs.pop()!, { recursive: true, force: true });
});

async function fresh(): Promise<{ c: Collector; sock: string; store: string }> {
  const d = await tmp();
  const sock = path.join(d, 'c.sock');
  const store = path.join(d, 'events.jsonl');
  const c = new Collector({ socketPath: sock, storePath: store, attempt: 'att0001' });
  await c.start();
  return { c, sock, store };
}

describe('collector: proposals + receipts', () => {
  it('accepts a valid proposal, assigns id/ts/seq/attempt, appends to store', async () => {
    const { c, sock, store } = await fresh();
    try {
      const r = (await submitProposal(sock, 'finding', { note: 'hi' })) as Receipt;
      expect(r.ok).toBe(true);
      expect(r.id).toMatch(/^ev_/);
      expect(r.seq).toBe(1);
      expect(r.attempt).toBe('att0001');
      const events = await readStore(store);
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({ kind: 'finding', attempt: 'att0001', seq: 1 });
      expect(events[0]!.data).toEqual({ note: 'hi' });
    } finally {
      await c.stop();
    }
  });

  it('ignores agent-supplied id/attempt/ts (identity is collector-assigned)', async () => {
    const { c, sock, store } = await fresh();
    try {
      // Extra top-level fields are rejected by .strict(); identity confusion is
      // instead attempted via data, which must not become the record identity.
      const r = (await submitProposal(sock, 'finding', { id: 'ev_HACK', attempt: 'other', seq: 999 })) as Receipt;
      expect(r.id).not.toBe('ev_HACK');
      expect(r.attempt).toBe('att0001');
      const ev = (await readStore(store))[0]!;
      expect(ev.id).not.toBe('ev_HACK');
      expect(ev.attempt).toBe('att0001');
      expect(ev.seq).toBe(1);
    } finally {
      await c.stop();
    }
  });

  it('assigns monotonically increasing seq', async () => {
    const { c, sock } = await fresh();
    try {
      const a = (await submitProposal(sock, 'a', {})) as Receipt;
      const b = (await submitProposal(sock, 'b', {})) as Receipt;
      expect(b.seq).toBe(a.seq + 1);
    } finally {
      await c.stop();
    }
  });
});

describe('collector: hostile input (fails closed)', () => {
  it('rejects invalid JSON', async () => {
    const { c, sock } = await fresh();
    try {
      const net = await import('node:net');
      const resp = await new Promise<string>((resolve) => {
        const s = net.connect(sock);
        let b = '';
        s.setEncoding('utf8');
        s.on('connect', () => s.write('not json\n'));
        s.on('data', (d) => { b += d; if (b.includes('\n')) { resolve(b.trim()); s.end(); } });
      });
      expect(JSON.parse(resp).ok).toBe(false);
    } finally {
      await c.stop();
    }
  });

  it('rejects a wrong/missing schema tag', async () => {
    const { c, sock } = await fresh();
    try {
      const net = await import('node:net');
      const resp = await new Promise<string>((resolve) => {
        const s = net.connect(sock);
        let b = '';
        s.setEncoding('utf8');
        s.on('connect', () => s.write(JSON.stringify({ schema: 'wrong', kind: 'x', data: {} }) + '\n'));
        s.on('data', (d) => { b += d; if (b.includes('\n')) { resolve(b.trim()); s.end(); } });
      });
      expect(JSON.parse(resp).ok).toBe(false);
    } finally {
      await c.stop();
    }
  });

  it('rejects __proto__ / constructor keys', async () => {
    const { c, sock } = await fresh();
    try {
      const net = await import('node:net');
      const payload = '{"schema":"asbx.proposal.v1","kind":"x","data":{"__proto__":{"polluted":1}}}\n';
      const resp = await new Promise<string>((resolve) => {
        const s = net.connect(sock);
        let b = '';
        s.setEncoding('utf8');
        s.on('connect', () => s.write(payload));
        s.on('data', (d) => { b += d; if (b.includes('\n')) { resolve(b.trim()); s.end(); } });
      });
      expect(JSON.parse(resp).ok).toBe(false);
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    } finally {
      await c.stop();
    }
  });

  it('rejects an oversize proposal', async () => {
    const { c, sock } = await fresh();
    try {
      const net = await import('node:net');
      const big = 'x'.repeat(MAX_PROPOSAL_BYTES + 10);
      const resp = await new Promise<string>((resolve) => {
        const s = net.connect(sock);
        let b = '';
        s.setEncoding('utf8');
        s.on('connect', () => s.write(JSON.stringify({ schema: 'asbx.proposal.v1', kind: 'x', data: { big } }) + '\n'));
        s.on('data', (d) => { b += d; if (b.includes('\n')) { resolve(b.trim()); s.end(); } });
        s.on('error', () => resolve('{"ok":false}'));
      });
      expect(JSON.parse(resp).ok).toBe(false);
    } finally {
      await c.stop();
    }
  });

  it('rejects an invalid kind token', async () => {
    const { c, sock } = await fresh();
    try {
      const r = await submitProposal(sock, 'bad kind!', {});
      expect(r.ok).toBe(false);
    } finally {
      await c.stop();
    }
  });
});

describe('collector: layout', () => {
  it('createAttemptCollector keeps the store a sibling of the socket, never inside a bind', async () => {
    const runDir = await tmp();
    const { collector, socketPath, storePath } = await createAttemptCollector({ runDir, attempt: 'att0009' });
    try {
      expect(path.basename(socketPath)).toBe('collector.sock');
      expect(path.basename(storePath)).toBe('events.jsonl');
      // The store lives under a separate opaque dir, never alongside the socket.
      expect(path.dirname(socketPath)).not.toBe(path.dirname(storePath));
      const r = (await submitProposal(socketPath, 'finding', { x: 1 })) as Receipt;
      expect(r.ok).toBe(true);
    } finally {
      await collector.stop();
    }
  });
});

describe.skipIf(!caps)('collector: evidence_writer_separated probe (requires root)', () => {
  it('stores a proposal from inside the sandbox; store unreachable; identity collector-assigned', async () => {
    const res = await evidenceWriterProbe().run();
    expect(res.status, res.detail).toBe('pass');
  });
});
