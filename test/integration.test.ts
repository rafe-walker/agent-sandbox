/**
 * End to end: sandbox (dedicated uid, bwrap) -> network cage -> gateway on the
 * cage's host IP -> fake Anthropic upstream. The sandbox holds only the session
 * token; the upstream must receive the real key; the sandbox env must not.
 */
import { describe, it, expect } from 'vitest';
import { setupNetwork, teardownNetwork } from '../src/net.js';
import { Gateway } from '../src/gateway.js';
import { runInSandbox } from '../src/launcher.js';
import { requireCapsOrSkip } from './helpers/caps.js';

const caps = requireCapsOrSkip();
const REAL = 'sk-ant-REALKEY-integration-0123456789abcdef';

describe.skipIf(!caps)('sandbox -> cage -> gateway -> fake upstream', () => {
  it('model call works on a session token; the real key never enters the sandbox', async () => {
    const port = 22041;
    const h = await setupNetwork({ gatewayPorts: [port] });
    const seen: string[] = [];
    const g = new Gateway({
      listenHost: h.hostIp,
      listenPort: port,
      realKey: REAL,
      dispatch: async (req) => {
        seen.push(req.headers['x-api-key'] ?? '');
        return { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"content":[{"type":"text","text":"PONG"}],"usage":{"input_tokens":3,"output_tokens":1}}') };
      },
    });
    await g.start();
    const { sessionToken, attemptId } = g.registerAttempt({ maxRequests: 5 });
    try {
      const py = [
        `cat > /tmp/call.py <<'PY'`,
        'import http.client, os',
        "c=http.client.HTTPConnection(os.environ['GW_HOST'], int(os.environ['GW_PORT']), timeout=5)",
        "c.request('POST','/v1/messages?beta=true',body='{}',headers={'x-api-key':os.environ['ANTHROPIC_API_KEY'],'content-type':'application/json'})",
        "r=c.getresponse(); print('STATUS', r.status); print(r.read().decode())",
        'PY',
        'python3 -I /tmp/call.py',
        'env | grep -c "REALKEY" || true',
      ].join('\n');
      const r = await runInSandbox(py, {
        netns: h.netns,
        env: { GW_HOST: h.hostIp, GW_PORT: String(port), ANTHROPIC_BASE_URL: `http://${h.hostIp}:${port}`, ANTHROPIC_API_KEY: sessionToken },
        wallClockMs: 15000,
      });
      const out = r.stdout ?? "";
      expect(out).toMatch(/STATUS 200/);
      expect(out).toMatch(/PONG/);
      expect(out).not.toContain(REAL);
      expect(out.trim().split('\n').pop()).toBe('0'); // REALKEY not in sandbox env
      expect(seen).toEqual([REAL]); // upstream got the real key
      expect(g.usage(attemptId)).toMatchObject({ requests: 1, inputTokens: 3, outputTokens: 1 });
    } finally {
      await g.stop();
      await teardownNetwork(h);
    }
  });
});
