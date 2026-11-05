import { describe, it, expect, afterEach } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import {
  Gateway,
  type Dispatch,
  type UpstreamRequest,
  type UpstreamResponse,
} from '../src/gateway.js';

const REAL_KEY = 'sk-ant-REALKEY-do-not-leak-0123456789abcdef';

/** A fake/recorded Anthropic upstream. Asserts the real key arrived and the
 *  session token did not, then returns canned responses. */
function fakeUpstream(
  script: (req: UpstreamRequest, calls: number) => UpstreamResponse,
): { dispatch: Dispatch; seen: UpstreamRequest[] } {
  const seen: UpstreamRequest[] = [];
  const dispatch: Dispatch = async (req) => {
    seen.push(req);
    return script(req, seen.length);
  };
  return { dispatch, seen };
}

function sse(events: Array<Record<string, unknown>>): UpstreamResponse {
  async function* gen(): AsyncIterable<Buffer> {
    for (const e of events) {
      yield Buffer.from(`event: ${String(e.type)}\ndata: ${JSON.stringify(e)}\n\n`, 'utf8');
    }
  }
  return {
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
    stream: gen(),
  };
}

const gateways: Gateway[] = [];
function track(g: Gateway): Gateway {
  gateways.push(g);
  return g;
}
afterEach(async () => {
  while (gateways.length) await gateways.pop()!.stop();
});

async function startGateway(dispatch: Dispatch): Promise<Gateway> {
  const g = track(new Gateway({ listenHost: '127.0.0.1', listenPort: 0, realKey: REAL_KEY, dispatch }));
  await g.start();
  return g;
}

function request(
  g: Gateway,
  opts: { method?: string; path: string; token?: string; body?: string; header?: 'x-api-key' | 'authorization' },
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (opts.token) {
      if (opts.header === 'authorization') headers['authorization'] = `Bearer ${opts.token}`;
      else headers['x-api-key'] = opts.token;
    }
    const req = http.request(
      { host: '127.0.0.1', port: g.port, method: opts.method ?? 'POST', path: opts.path, headers },
      (res) => {
        const parts: Buffer[] = [];
        res.on('data', (d: Buffer) => parts.push(d));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(parts).toString(), headers: res.headers }),
        );
      },
    );
    req.once('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

describe('gateway: auth + credential swap', () => {
  it('swaps the session token for the real key; the session token never goes upstream', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"ok":true,"usage":{"input_tokens":5,"output_tokens":7}}') }));
    const g = await startGateway(up.dispatch);
    const { sessionToken, attemptId } = g.registerAttempt();
    const res = await request(g, { path: '/v1/messages', token: sessionToken, body: '{"model":"x"}' });
    expect(res.status).toBe(200);
    const seen = up.seen[0]!;
    expect(seen.headers['x-api-key']).toBe(REAL_KEY);
    expect(JSON.stringify(seen.headers)).not.toContain(sessionToken);
    // provider-truth usage recorded
    expect(g.usage(attemptId)).toMatchObject({ requests: 1, inputTokens: 5, outputTokens: 7 });
  });

  it('accepts the token via Authorization: Bearer too', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: {}, body: Buffer.from('{}') }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt();
    const res = await request(g, { path: '/v1/messages', token: sessionToken, header: 'authorization', body: '{}' });
    expect(res.status).toBe(200);
  });

  it('401s an unknown or missing token', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: {}, body: Buffer.from('{}') }));
    const g = await startGateway(up.dispatch);
    expect((await request(g, { path: '/v1/messages', body: '{}' })).status).toBe(401);
    expect((await request(g, { path: '/v1/messages', token: 'asbx-sess-bogus', body: '{}' })).status).toBe(401);
    expect(up.seen.length).toBe(0);
  });
});

describe('gateway: path / method / host / CONNECT gates', () => {
  it('403s a non-allowlisted path', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: {}, body: Buffer.from('{}') }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt();
    expect((await request(g, { path: '/v1/complete', token: sessionToken, body: '{}' })).status).toBe(403);
    expect((await request(g, { path: '/admin', token: sessionToken, body: '{}' })).status).toBe(403);
    expect(up.seen.length).toBe(0);
  });

  it('403s an absolute-form (arbitrary host) target', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: {}, body: Buffer.from('{}') }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt();
    const res = await request(g, { path: 'http://evil.example/v1/messages', token: sessionToken, body: '{}' });
    expect(res.status).toBe(403);
  });

  it('405s a disallowed method', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: {}, body: Buffer.from('{}') }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt();
    expect((await request(g, { method: 'DELETE', path: '/v1/messages', token: sessionToken })).status).toBe(405);
  });

  it('refuses CONNECT', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: {}, body: Buffer.from('{}') }));
    const g = await startGateway(up.dispatch);
    const code = await new Promise<string>((resolve) => {
      const sock = net.connect({ host: '127.0.0.1', port: g.port }, () => {
        sock.write('CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n');
      });
      let buf = '';
      sock.on('data', (d) => {
        buf += d.toString();
        if (buf.includes('\r\n')) { resolve(buf.split('\r\n')[0]!); sock.destroy(); }
      });
      sock.on('close', () => resolve(buf.split('\r\n')[0] ?? 'closed'));
    });
    expect(code).toMatch(/405/);
  });
});

describe('gateway: streaming, retries, tool use', () => {
  it('streams SSE through and meters cumulative usage', async () => {
    const up = fakeUpstream(() =>
      sse([
        { type: 'message_start', message: { usage: { input_tokens: 11, output_tokens: 1 } } },
        { type: 'content_block_start', content_block: { type: 'text' } },
        { type: 'content_block_delta', delta: { type: 'text_delta', text: 'hi' } },
        { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 23 } },
        { type: 'message_stop' },
      ]),
    );
    const g = await startGateway(up.dispatch);
    const { sessionToken, attemptId } = g.registerAttempt();
    const res = await request(g, { path: '/v1/messages', token: sessionToken, body: '{"stream":true}' });
    expect(res.status).toBe(200);
    expect(res.body).toContain('event: message_start');
    expect(res.body).toContain('text_delta');
    expect(g.usage(attemptId)).toMatchObject({ inputTokens: 11, outputTokens: 23 });
  });

  it('passes a tool_use response through unchanged', async () => {
    const toolBody = JSON.stringify({
      type: 'message',
      content: [{ type: 'tool_use', id: 'tu_1', name: 'bash', input: { cmd: 'ls' } }],
      usage: { input_tokens: 9, output_tokens: 4 },
    });
    const up = fakeUpstream(() => ({ status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from(toolBody) }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt();
    const res = await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' });
    expect(JSON.parse(res.body).content[0]).toMatchObject({ type: 'tool_use', name: 'bash' });
  });

  it('forwards a retried call (client resends after a 529)', async () => {
    const up = fakeUpstream((_req, calls) =>
      calls === 1
        ? { status: 529, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"error":{"type":"overloaded_error"}}') }
        : { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"ok":true}') },
    );
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt();
    const first = await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' });
    expect(first.status).toBe(529);
    const second = await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' });
    expect(second.status).toBe(200);
    expect(up.seen.length).toBe(2);
  });
});

describe('gateway: budgets', () => {
  it('429s when the request budget is exhausted', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: {}, body: Buffer.from('{}') }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt({ maxRequests: 2 });
    expect((await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' })).status).toBe(200);
    expect((await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' })).status).toBe(200);
    expect((await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' })).status).toBe(429);
  });

  it('429s when the token budget is exceeded', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"usage":{"input_tokens":100,"output_tokens":100}}') }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt({ maxTokens: 150 });
    expect((await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' })).status).toBe(200);
    // after 200 tokens recorded, the next request is refused
    expect((await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' })).status).toBe(429);
  });

  it('429s when the wall-clock budget is exceeded', async () => {
    const up = fakeUpstream(() => ({ status: 200, headers: {}, body: Buffer.from('{}') }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt({ maxWallMs: 0 });
    await new Promise((r) => setTimeout(r, 5));
    expect((await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' })).status).toBe(429);
  });
});

describe('gateway: credential hygiene', () => {
  it('redacts the real key if an upstream error body echoes it', async () => {
    const up = fakeUpstream(() => ({
      status: 400,
      headers: { 'content-type': 'application/json' },
      body: Buffer.from(JSON.stringify({ error: { message: `bad key ${REAL_KEY}` } })),
    }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt();
    const res = await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' });
    expect(res.status).toBe(400);
    expect(res.body).not.toContain(REAL_KEY);
    expect(res.body).toContain('[REDACTED]');
  });

  it('strips credential-bearing response headers', async () => {
    const up = fakeUpstream(() => ({
      status: 200,
      headers: { 'content-type': 'application/json', 'x-api-key': REAL_KEY, 'set-cookie': 'sid=abc' },
      body: Buffer.from('{}'),
    }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt();
    const res = await request(g, { path: '/v1/messages', token: sessionToken, body: '{}' });
    expect(res.headers['x-api-key']).toBeUndefined();
    expect(res.headers['set-cookie']).toBeUndefined();
  });
});

describe('gateway: streamed bodies are redacted (sliding window)', () => {
  it('redacts the real key in SSE, including when split across chunk boundaries', async () => {
    const half = Math.floor(REAL_KEY.length / 2);
    const chunks = [
      `event: content_block_delta\ndata: {"delta":{"text":"echo ${REAL_KEY} end"}}\n\n`,
      `event: content_block_delta\ndata: {"delta":{"text":"split ${REAL_KEY.slice(0, half)}`,
      `${REAL_KEY.slice(half)} tail"}}\n\n`,
      `event: content_block_delta\ndata: {"delta":{"text":"b64 ${Buffer.from(REAL_KEY).toString('base64')}"}}\n\n`,
      'event: message_stop\ndata: {"type":"message_stop"}\n\n',
    ];
    const up = fakeUpstream(() => ({
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
      stream: (async function* () {
        for (const c of chunks) yield Buffer.from(c);
      })(),
    }));
    const g = await startGateway(up.dispatch);
    const { sessionToken } = g.registerAttempt();
    const res = await request(g, { path: '/v1/messages', token: sessionToken, body: '{"stream":true}' });
    expect(res.status).toBe(200);
    expect(res.body).not.toContain(REAL_KEY);
    expect(res.body).not.toContain(Buffer.from(REAL_KEY).toString('base64'));
    expect(res.body.match(/\[REDACTED\]/g)?.length).toBe(3);
    expect(res.body).toContain('message_stop'); // stream still delivered intact otherwise
  });
});
