/**
 * The model auth gateway.
 *
 * The real Anthropic key lives ONLY here. The agent is pointed at this server
 * with `ANTHROPIC_BASE_URL` and a random per-attempt session token; the gateway
 * swaps the session token for the real key, forwards to the pinned upstream
 * through the outer HTTPS proxy, and streams the response back. It:
 *   - allowlists the API paths the pinned Claude Code version uses,
 *   - refuses CONNECT and any non-allowlisted path,
 *   - never forwards to an arbitrary host (upstream host is fixed),
 *   - strips credential-bearing response headers and redacts the key from
 *     error bodies,
 *   - enforces per-attempt budgets (requests, tokens, wall-clock),
 *   - records provider-reported usage per request as the token meter.
 *
 * The upstream call is injectable (`dispatch`) so the compatibility test runs
 * against a fake/recorded Anthropic upstream with no paid calls.
 */
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { URL } from 'node:url';
import { buildRedactor, type Redactor } from './redact.js';

export const DEFAULT_UPSTREAM = 'https://api.anthropic.com';

/** Paths the pinned Claude Code (2.1.x) uses in API mode. Extend deliberately. */
export const DEFAULT_ALLOWED_PATHS: readonly RegExp[] = [
  /^\/v1\/messages(\?.*)?$/,
  /^\/v1\/messages\/count_tokens(\?.*)?$/,
  /^\/v1\/models(\/[A-Za-z0-9._-]+)?(\?.*)?$/,
];

/** Response headers that must never reach the agent (credential echoes). */
const STRIP_RESPONSE_HEADERS = new Set([
  'x-api-key',
  'authorization',
  'anthropic-organization-id',
  'request-id-signature',
  'set-cookie',
]);

export interface AttemptBudget {
  maxRequests: number;
  maxTokens: number;
  maxWallMs: number;
}

export const DEFAULT_BUDGET: AttemptBudget = {
  maxRequests: 200,
  maxTokens: 1_000_000,
  maxWallMs: 30 * 60 * 1000,
};

/**
 * Validate a budget. Every field must be a finite, non-negative safe integer.
 * NaN/Infinity/1e400/negatives/strings are rejected: `requests >= NaN` is
 * always false, so an unvalidated NaN would silently mean "unlimited".
 */
export function validateBudget(b: Partial<AttemptBudget>): AttemptBudget {
  const out: AttemptBudget = { ...DEFAULT_BUDGET };
  for (const key of ['maxRequests', 'maxTokens', 'maxWallMs'] as const) {
    if (!(key in b)) continue;
    const v: unknown = b[key];
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) {
      throw new Error(`invalid budget ${key}: ${String(v)} (need a non-negative safe integer)`);
    }
    out[key] = v;
  }
  return out;
}

export interface AttemptUsage {
  requests: number;
  /** Uncached input tokens, summed over every response of the attempt. */
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheCreationTokens: number;
  startedAt: number;
  overBudget: boolean;
  lastReason?: string;
}

export interface UpstreamRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: Buffer;
}

export interface UpstreamResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  /** Full body for buffered responses; omitted for streamed ones. */
  body?: Buffer;
  /** For SSE streaming: an async iterable of chunks. */
  stream?: AsyncIterable<Buffer>;
}

export type Dispatch = (req: UpstreamRequest) => Promise<UpstreamResponse>;

export interface GatewayConfig {
  listenHost: string;
  listenPort: number;
  /** The real Anthropic key. Read from env by `gatewayFromEnv`; never logged. */
  realKey: string;
  upstreamBaseUrl?: string;
  allowedPaths?: readonly RegExp[];
  /** Outer HTTPS proxy (e.g. process.env.HTTPS_PROXY). */
  proxyUrl?: string;
  /** CA bundle path for the outer proxy's re-terminated TLS. */
  caBundlePath?: string;
  /** Injectable upstream for tests. Defaults to real HTTPS-through-proxy. */
  dispatch?: Dispatch;
}

interface Attempt {
  id: string;
  token: string;
  budget: AttemptBudget;
  usage: AttemptUsage;
}

export class Gateway {
  private readonly server: http.Server;
  private readonly attempts = new Map<string, Attempt>(); // token -> attempt
  private readonly byId = new Map<string, Attempt>();
  private readonly upstream: URL;
  private readonly allowed: readonly RegExp[];
  private readonly dispatch: Dispatch;
  private readonly redactor: Redactor;

  constructor(private readonly cfg: GatewayConfig) {
    if (!cfg.realKey) throw new Error('gateway requires a real model key');
    this.upstream = new URL(cfg.upstreamBaseUrl ?? DEFAULT_UPSTREAM);
    this.allowed = cfg.allowedPaths ?? DEFAULT_ALLOWED_PATHS;
    this.redactor = buildRedactor([cfg.realKey]);
    this.dispatch =
      cfg.dispatch ??
      makeProxyDispatch(this.upstream, cfg.proxyUrl, cfg.caBundlePath);
    this.server = http.createServer((req, res) => void this.handle(req, res));
    // Refuse CONNECT outright: no tunnelling to arbitrary hosts.
    this.server.on('connect', (_req, socket) => {
      socket.write('HTTP/1.1 405 Method Not Allowed\r\n\r\n');
      socket.destroy();
    });
  }

  /** Register a per-attempt session token + budget. */
  registerAttempt(budget: Partial<AttemptBudget> = {}): { attemptId: string; sessionToken: string } {
    const id = randomBytes(8).toString('hex');
    const token = 'asbx-sess-' + randomBytes(24).toString('hex');
    const attempt: Attempt = {
      id,
      token,
      budget: validateBudget(budget),
      usage: { requests: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheCreationTokens: 0, startedAt: Date.now(), overBudget: false },
    };
    this.attempts.set(token, attempt);
    this.byId.set(id, attempt);
    return { attemptId: id, sessionToken: token };
  }

  usage(attemptId: string): AttemptUsage | undefined {
    const a = this.byId.get(attemptId);
    return a ? { ...a.usage } : undefined;
  }

  revokeAttempt(attemptId: string): void {
    const a = this.byId.get(attemptId);
    if (a) {
      this.attempts.delete(a.token);
      this.byId.delete(attemptId);
    }
  }

  get port(): number {
    const addr = this.server.address();
    return typeof addr === 'object' && addr ? addr.port : this.cfg.listenPort;
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.cfg.listenPort, this.cfg.listenHost, () => resolve());
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  private deny(res: http.ServerResponse, status: number, msg: string): void {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: { type: 'gateway_denied', message: msg } }));
  }

  private authAttempt(req: http.IncomingMessage): Attempt | undefined {
    const key = (req.headers['x-api-key'] as string | undefined)?.trim();
    const auth = (req.headers['authorization'] as string | undefined)?.replace(/^Bearer\s+/i, '').trim();
    const token = key || auth;
    return token ? this.attempts.get(token) : undefined;
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    try {
      // Method gate: only GET/POST. (CONNECT is handled/denied separately.)
      if (req.method !== 'GET' && req.method !== 'POST') {
        return this.deny(res, 405, `method ${req.method} not allowed`);
      }
      const path = req.url ?? '';
      // Reject absolute-form targets (proxy-style) that name another host.
      if (/^[a-z]+:\/\//i.test(path)) {
        return this.deny(res, 403, 'absolute-form request targets are refused');
      }
      if (!this.allowed.some((re) => re.test(path))) {
        return this.deny(res, 403, `path not allowlisted: ${path}`);
      }
      const attempt = this.authAttempt(req);
      if (!attempt) return this.deny(res, 401, 'unknown or missing session token');

      // Budget: wall-clock + request count (pre-check), token meter.
      const now = Date.now();
      if (now - attempt.usage.startedAt > attempt.budget.maxWallMs) {
        attempt.usage.overBudget = true;
        attempt.usage.lastReason = 'wall-clock budget exceeded';
        return this.deny(res, 429, 'attempt wall-clock budget exceeded');
      }
      if (attempt.usage.requests >= attempt.budget.maxRequests) {
        attempt.usage.overBudget = true;
        attempt.usage.lastReason = 'request budget exceeded';
        return this.deny(res, 429, 'attempt request budget exceeded');
      }
      if (totalTokens(attempt.usage) >= attempt.budget.maxTokens) {
        attempt.usage.overBudget = true;
        attempt.usage.lastReason = 'token budget exceeded';
        return this.deny(res, 429, 'attempt token budget exceeded');
      }
      attempt.usage.requests += 1;

      const body = await readBody(req);

      // Build the upstream request: swap the session token for the real key,
      // fix the host, drop hop-by-hop + inbound credential headers.
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        const lk = k.toLowerCase();
        if (['host', 'x-api-key', 'authorization', 'connection', 'content-length', 'proxy-authorization'].includes(lk)) {
          continue;
        }
        if (typeof v === 'string') headers[lk] = v;
      }
      headers['host'] = this.upstream.host;
      headers['x-api-key'] = this.cfg.realKey;
      if (!headers['anthropic-version']) headers['anthropic-version'] = '2023-06-01';

      const upstreamReq: UpstreamRequest = { method: req.method, path, headers, body };
      const upstream = await this.dispatch(upstreamReq);

      // Response headers: strip credential echoes; never pass Set-Cookie.
      const outHeaders: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(upstream.headers)) {
        if (v === undefined) continue;
        if (STRIP_RESPONSE_HEADERS.has(k.toLowerCase())) continue;
        if (k.toLowerCase() === 'content-length') continue; // may change after redaction
        outHeaders[k] = v;
      }

      if (upstream.stream) {
        res.writeHead(upstream.status, outHeaders);
        // Streamed bodies are redacted too, across chunk boundaries. The meter
        // reads the raw provider chunk (usage numbers never contain the key).
        const sr = this.redactor.stream();
        const decoder = new TextDecoder('utf-8');
        const m = new ResponseMeter();
        try {
          for await (const chunk of upstream.stream) {
            m.pushSse(chunk);
            const safe = sr.push(decoder.decode(chunk, { stream: true }));
            if (safe) res.write(safe);
          }
        } finally {
          // why: a cut stream still consumed what it reported; count it.
          m.addTo(attempt.usage);
        }
        const rest = sr.push(decoder.decode()) + sr.flush();
        if (rest) res.write(rest);
        res.end();
        return;
      }

      let outBody = upstream.body ?? Buffer.alloc(0);
      const m = new ResponseMeter();
      m.pushJson(outBody);
      m.addTo(attempt.usage);
      // Error bodies may echo the key: redact before sending to the agent.
      if (upstream.status >= 400) {
        const text = outBody.toString('utf8');
        outBody = Buffer.from(this.redactor(text), 'utf8');
      }
      res.writeHead(upstream.status, outHeaders);
      res.end(outBody);
    } catch (err) {
      // Never leak the key in an error. Redact the message defensively.
      const msg = this.redactor(err instanceof Error ? err.message : String(err));
      if (!res.headersSent) this.deny(res, 502, `upstream error: ${msg}`);
      else res.end();
    }
  }

}

/** Every token the provider reported for an attempt (budget and meter total). */
export function totalTokens(u: Pick<AttemptUsage, 'inputTokens' | 'outputTokens' | 'cacheReadTokens' | 'cacheCreationTokens'>): number {
  return u.inputTokens + u.outputTokens + u.cacheReadTokens + u.cacheCreationTokens;
}

const MAX_SSE_LINE = 1024 * 1024;

/**
 * Provider-reported usage of ONE response. Within a response each field is
 * the max seen (input is reported in message_start, output is cumulative in
 * message_delta); across responses the attempt totals are summed.
 */
class ResponseMeter {
  private inp = 0;
  private out = 0;
  private cacheRead = 0;
  private cacheCreate = 0;
  private buf = '';
  private readonly decoder = new TextDecoder('utf-8');

  pushJson(body: Buffer): void {
    this.apply(safeParse(body.toString('utf8')));
  }

  /** SSE: data lines may be split across chunks, so buffer up to each newline. */
  pushSse(chunk: Buffer): void {
    this.buf += this.decoder.decode(chunk, { stream: true });
    let i: number;
    while ((i = this.buf.indexOf('\n')) >= 0) {
      this.line(this.buf.slice(0, i));
      this.buf = this.buf.slice(i + 1);
    }
    if (this.buf.length > MAX_SSE_LINE) this.buf = ''; // an oversized line never carries usage we trust
  }

  private line(l: string): void {
    const m = /^data:\s*(\{.*\})\s*$/.exec(l);
    if (m) this.apply(safeParse(m[1]!));
  }

  private apply(obj: unknown): void {
    if (!obj || typeof obj !== 'object') return;
    const rec = obj as Record<string, unknown>;
    const usage =
      (rec.usage as Record<string, unknown> | undefined) ??
      ((rec.message as Record<string, unknown> | undefined)?.usage as Record<string, unknown> | undefined);
    if (!usage || typeof usage !== 'object') return;
    this.inp = Math.max(this.inp, toNum(usage.input_tokens) ?? 0);
    this.out = Math.max(this.out, toNum(usage.output_tokens) ?? 0);
    this.cacheRead = Math.max(this.cacheRead, toNum(usage.cache_read_input_tokens) ?? 0);
    this.cacheCreate = Math.max(this.cacheCreate, toNum(usage.cache_creation_input_tokens) ?? 0);
  }

  addTo(u: AttemptUsage): void {
    if (this.buf) this.line(this.buf);
    this.buf = '';
    u.inputTokens += this.inp;
    u.outputTokens += this.out;
    u.cacheReadTokens += this.cacheRead;
    u.cacheCreationTokens += this.cacheCreate;
    this.inp = this.out = this.cacheRead = this.cacheCreate = 0;
  }
}

function toNum(v: unknown): number | undefined {
  // Non-negative safe integers only: a negative, NaN, Infinity or 1e400 count could shrink or poison the meter.
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : undefined;
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const parts: Buffer[] = [];
    let size = 0;
    const MAX = 32 * 1024 * 1024; // 32 MiB inbound cap
    req.on('data', (d: Buffer) => {
      size += d.length;
      if (size > MAX) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      parts.push(d);
    });
    req.on('end', () => resolve(Buffer.concat(parts)));
    req.on('error', reject);
  });
}

/** Read the real key from env. Never logs it. */
export function gatewayFromEnv(cfg: Omit<GatewayConfig, 'realKey'>): Gateway {
  const realKey = process.env.ANTHROPIC_API_KEY;
  if (!realKey) throw new Error('ANTHROPIC_API_KEY is not set; the gateway needs the real key');
  return new Gateway({ ...cfg, realKey });
}

/**
 * Real upstream dispatch: HTTPS to the fixed upstream host, tunnelled through
 * the outer HTTPS proxy (CONNECT) when one is configured. Streams SSE through.
 * Not exercised in CI (the compat test injects a fake dispatch).
 */
export function makeProxyDispatch(
  upstream: URL,
  proxyUrl?: string,
  caBundlePath?: string,
): Dispatch {
  const ca = caBundlePath ? readFileSync(caBundlePath) : undefined;
  const host = upstream.hostname;
  const port = upstream.port ? Number(upstream.port) : 443;

  async function connectSocket(): Promise<net.Socket> {
    if (!proxyUrl) {
      return net.connect({ host, port });
    }
    const p = new URL(proxyUrl);
    const sock = net.connect({ host: p.hostname, port: Number(p.port || 80) });
    await new Promise<void>((resolve, reject) => {
      sock.once('error', reject);
      sock.once('connect', () => {
        sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
      });
      let buf = '';
      const onData = (d: Buffer): void => {
        buf += d.toString('latin1');
        if (buf.includes('\r\n\r\n')) {
          sock.removeListener('data', onData);
          if (/^HTTP\/1\.[01] 200/.test(buf)) resolve();
          else reject(new Error('proxy CONNECT failed: ' + buf.split('\r\n')[0]));
        }
      };
      sock.on('data', onData);
    });
    return sock;
  }

  return async (req: UpstreamRequest): Promise<UpstreamResponse> => {
    const socket = await connectSocket();
    const secure = tls.connect({ socket, servername: host, ...(ca ? { ca } : {}) });
    await new Promise<void>((resolve, reject) => {
      secure.once('secureConnect', () => resolve());
      secure.once('error', reject);
    });
    return await new Promise<UpstreamResponse>((resolve, reject) => {
      const r = https.request(
        { createConnection: () => secure, method: req.method, path: req.path, headers: req.headers, host },
        (resp) => {
          const isStream = (resp.headers['content-type'] ?? '').includes('text/event-stream');
          if (isStream) {
            resolve({ status: resp.statusCode ?? 502, headers: resp.headers, stream: resp as AsyncIterable<Buffer> });
          } else {
            const parts: Buffer[] = [];
            resp.on('data', (d: Buffer) => parts.push(d));
            resp.on('end', () =>
              resolve({ status: resp.statusCode ?? 502, headers: resp.headers, body: Buffer.concat(parts) }),
            );
          }
        },
      );
      r.once('error', reject);
      if (req.body.length) r.write(req.body);
      r.end();
    });
  };
}
