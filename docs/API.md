# agent-sandbox API (v0.1)

All exports come from the package root (`import { ... } from 'agent-sandbox'`).
Everything that creates a uid, netns or nft table requires **Linux + root**, and
throws on any other host rather than running unsandboxed.

## Typical composition (harness side)

```ts
import {
  runPreflight, assembleCapabilityProbes, coreAttacks,
  setupNetwork, teardownNetwork, Gateway,
  createAttemptCollector, allocateWorker, launch,
} from 'agent-sandbox';

// 1. Gate: measure this host. Publish only when report.publishable.
const report = await runPreflight({
  profile: 'linux-sandbox',
  capabilityProbes: assembleCapabilityProbes({ sourceDir: '/path/to/checkout' }),
  attacks: coreAttacks(),
});

// 2. Per attempt: cage + gateway on the cage's host IP + collector.
const net = await setupNetwork({ gatewayPorts: [8443] });
const gw = new Gateway({
  listenHost: net.hostIp, listenPort: 8443,
  realKey: process.env.ANTHROPIC_API_KEY!,        // never enters the sandbox
  proxyUrl: process.env.HTTPS_PROXY, caBundlePath: '/root/.ccr/ca-bundle.crt',
});
await gw.start();
const { attemptId, sessionToken } = gw.registerAttempt({ maxRequests: 200, maxTokens: 500_000, maxWallMs: 1_800_000 });

const worker = await allocateWorker();
const col = await createAttemptCollector({ runDir: '/run/agent-sandbox', attempt: attemptId, workerUid: worker.uid });

// 3. Launch the agent.
const res = await launch({
  worker, netns: net.netns, sourceDir: '/path/to/checkout', wallClockMs: 1_800_000,
  rwBinds: [{ src: col.socketPath, dest: '/run/asbx/collector.sock' }],
  env: {
    ANTHROPIC_BASE_URL: `http://${net.hostIp}:8443`,
    ANTHROPIC_API_KEY: sessionToken,                // low-value, per attempt
    ASBX_COLLECTOR_SOCK: '/run/asbx/collector.sock',
  },
  command: ['claude', '-p', '...'],                 // the agent binary must be reachable inside (bind it ro)
});

// 4. Teardown + trusted readback.
const usage = gw.usage(attemptId);                  // provider-reported tokens
await col.collector.stop(); await gw.stop(); await teardownNetwork(net);
```

`launch` releases the worker uid itself and reports `survivors` (must be 0).

## Profiles and the report

| Export | Purpose |
|---|---|
| `PROFILES`, `isProfile`, `assertImplemented` | `dev`, `linux-sandbox`, `microvm` (reserved; throws). |
| `runPreflight({ profile, capabilityProbes, attacks })` | Runs probes (parallel) and attacks (serial), and returns a `CapabilityReport`. It never throws for a degraded host. |
| `derivePublishable` | The single source of the invariant: `linux-sandbox` AND all 7 capabilities `pass` AND suite `pass` AND matching suite version. |
| `foldSuite`, `formatReport`, `capabilityReportSchema` | Fold attack results, print a report, validate a stored one. |
| `assembleCapabilityProbes`, `coreAttacks`, `SUITE_SIZE` | The probes and the 25 attacks available on this host. |

`AttackResult.notApplicable` is set only when the harness proves the vector is
absent on the host (today: a kernel with no IPv6). The attack must still be
blocked, and N/A attacks are counted and listed.

## Signed preflight

| Export | Purpose |
|---|---|
| `loadOrCreateHostKey({ dir?, forbidUnder? })` | Root only. Per-host Ed25519 key in `DEFAULT_KEY_DIR` (`/var/lib/agent-sandbox/attest`): private 0600, public 0644. Refuses a dir under `SANDBOX_VISIBLE_PREFIXES` or `forbidUnder`, a symlink, a non-root or group/other-writable ancestor, or a loose key file. |
| `signPreflight(report, key, { ttlMs?, now? })` | Envelope `agent-sandbox/signed-preflight@1`: `{ schema, alg, key_id, payload (base64 of {report, binding}), signature }`. TTL default 1 h, max 6 h. |
| `verifyPreflight(signed, pubkey, { now?, hostId?, version?, suiteVersion?, maxAgeMs?, requirePublishable? })` | Never throws. `{ ok: true, report, binding, keyId }` only if the signature verifies over the exact payload bytes, the host/version/suite bindings match this process, the window holds, and `publishable` re-derives to true (unless `requirePublishable: false`). |
| `loadHostPublicKey(dir?)`, `currentHostId()`, `keyIdOf(pub)` | Consumer helpers. |

## Launcher

| Export | Purpose |
|---|---|
| `allocateWorker()` / `releaseWorker(w)` | Dedicated `asbx_w<hex>` uid with a **private** group. Release kills, verifies and `userdel`s. |
| `launch(opts)` | `prlimit -> setpriv -> [ip netns exec] -> bwrap`. Options: `command`, `sourceDir` (ro at `/src`), `roBinds`, `rwBinds`, `env` (after `--clearenv`), `cwd`, `rlimits` (NPROC/AS/FSIZE/NOFILE; defaults 128 / 1 GiB / 256 MiB / 256), `wallClockMs`, `netns`, `capture`. |
| `runInSandbox(script, opts)` | Allocate, run `/bin/sh -c`, capture output, release. |
| `buildBwrapArgs`, `fdAssertionScript` | Inspect the argv; assert open fds from inside. |
| `cleanupStaleWorkers()` | Remove leftover `asbx_w*` uids after a crash. Not automatic: it would kill a concurrent run's workers. |

## Network

| Export | Purpose |
|---|---|
| `setupNetwork({ gatewayPorts, attemptId? })` | netns + veth + our own `inet asbx_<id>` nft table. The only reachable address is `hostIp:gatewayPorts`. There is no default route, no DNS and no IPv6. Idempotent per id. |
| `teardownNetwork(h)`, `cleanupStale()` | Idempotent teardown; sweep leftover `asbx_` netns/tables/veths. |

## Gateway

| Export | Purpose |
|---|---|
| `new Gateway({ listenHost, listenPort, realKey, upstreamBaseUrl?, allowedPaths?, proxyUrl?, caBundlePath?, dispatch? })` | Model auth gateway. `dispatch` is injectable, for tests and fake upstreams. |
| `gatewayFromEnv(cfg)` | Same, but reads the real key from `$ANTHROPIC_API_KEY`. |
| `.registerAttempt(budget)` -> `{ attemptId, sessionToken }` | Budgets are validated: non-negative safe integers only (NaN/Infinity/negatives throw). |
| `.usage(id)`, `.revokeAttempt(id)` | Provider-reported usage meter; revoke a token. |
| `DEFAULT_ALLOWED_PATHS` | `/v1/messages[?…]`, `/v1/messages/count_tokens`, `/v1/models[/id]`. |
| `buildRedactor(secrets)` | Exact / JSON / URL / base64 / split redaction. A mitigation, not a proof. |

## Collector

| Export | Purpose |
|---|---|
| `createAttemptCollector({ runDir, attempt, workerUid })` | `<runDir>/<attempt>/sock/collector.sock` (0600, owned by the worker, dir 0711) and `<runDir>/<attempt>/store/events.jsonl` (dir 0700, never bound). |
| `submitProposal(socket, kind, data)` | Client. Inside the sandbox, use the `sandbox-submit` bin or any AF_UNIX client. |
| `readStore(path)`, `proposalSchema`, `MAX_PROPOSAL_BYTES` | Trusted readback; wire schema `asbx.proposal.v1` (`kind` + `data` only, strict, 64 KiB). |

## CLI

```
agent-sandbox preflight [--profile linux-sandbox|dev] [--source <dir>] [--json]
agent-sandbox run [--profile ...] [--source <dir>] [--wall-ms n] [--gateway-port p] [--env K=V ...] -- <cmd...>
agent-sandbox gateway --listen <host:port> [--max-requests n] [--max-tokens n] [--max-wall-ms n] [--ca <bundle>]
agent-sandbox collector --run-dir <d> --attempt <id> [--worker-uid <uid>]
agent-sandbox submit --socket <s> --kind <k> [--data <json>]
agent-sandbox cleanup
sandbox-submit --kind <k> [--data <json>]     # inside the sandbox; socket from $ASBX_COLLECTOR_SOCK
```

`preflight` exits 0 only when publishable. `gateway` prints
`{attemptId, ANTHROPIC_BASE_URL, ANTHROPIC_API_KEY}` as one JSON line. The
printed key is the **session token**; the real key is never printed. When
composing `run --gateway-port` with a gateway, the gateway must listen on the
cage's host IP, which `run` prints. The library composition above is the
supported integration path in v0.1.
