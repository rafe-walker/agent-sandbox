# agent-sandbox

Linux isolation for **untrusted AI agent processes**. It runs a headless agent
(e.g. `claude -p`, which may hold Bash and Write tools) in a boundary that the
agent cannot use to reach the harness that launched it, the host network, or
the model credential.

Two projects consume it: `mcp-audit` (private) and `mcp-bench`
(`rafe-walker/agent-memory-bench`, public). This repo integrates with neither
yet — it is a standalone library + CLI.

> Status: **v0.1**, pre-release. API and CLI may change.

## Threat model and trust assumptions (read this first)

The adversary is the **agent process itself**: untrusted code running with a
real shell, trying to read harness evidence, reach the network directly, steal
the model key, escape its uid, or survive teardown. agent-sandbox is built to
hold against that adversary. It is **not** a defense against a hostile kernel.

Honest limits — none of these are hidden:

- **Shared kernel.** All isolation here (namespaces, nftables, rlimits, uid
  separation) is kernel-enforced. A kernel LPE defeats it. For hostile
  *customer* code we reserve a `microvm` profile; it is **not implemented** in
  v0.1. `linux-sandbox` is for our own audits of third-party MCP servers.
- **An audited server that holds a token can leak it.** When we audit a remote
  MCP server, that server may be handed a (fine-grained, scoped, short-lived,
  revoked-after) token. Our gateway cannot stop the *server* from encoding that
  token into a response. Echoed-key redaction (exact / JSON-escaped / URL /
  base64 / split) is a **mitigation, not a proof**, and it fails closed on
  responses it cannot parse.
- **Native macOS is `dev` only** and never publishable. The supported path on
  macOS is a Linux VM running `linux-sandbox`.
- **`dev` profile is never publishable.** It runs the agent with no boundary
  and a loud warning. It exists for fast local iteration only.

A run is **publishable only** when the profile is `linux-sandbox` **and** the
preflight attacker suite passed on this host. There is no silent downgrade.

## Components

| Piece | What it does |
|---|---|
| **Profiles** | `dev`, `linux-sandbox`, `microvm` (reserved). |
| **Preflight** | Probes *measured* capabilities and runs the 26-test attacker suite, each with a positive control. Writes a host-side capability report. |
| **Launcher** | Dedicated uid+gid per worker; bwrap with user/pid/ipc/net/uts namespaces, `--die-with-parent`, `--new-session`, `--cap-drop ALL`; read-only system + source; fresh HOME, private /tmp + /dev/shm, new /proc, minimal /dev, no /run; fd allowlist; rlimits; wall-clock kill; PID-namespace teardown with a survivor check. |
| **Network** | Per-attempt netns + veth pair; host nftables that allow only the gateway ports; no DNS, no IPv6, no forwarding. Idempotent setup/teardown with crash cleanup. |
| **Gateway** | Holds the real Anthropic key. Agent gets `ANTHROPIC_BASE_URL` + a random per-attempt session token. Path allowlist, CONNECT refused, arbitrary hosts refused, credential-bearing errors/headers stripped, per-attempt token/request/time budgets, provider-truth usage meter. Forwards through the outer HTTPS proxy. |
| **Collector** | Root-owned UNIX socket bind-mounted in. Identifies the caller by `SO_PEERCRED` (never by agent-supplied fields), accepts versioned size-bounded schema-validated proposals, assigns ids/timestamps itself, appends to a store the agent cannot reach, returns receipts. Ships a `sandbox-submit` CLI for use inside the sandbox. |

## CLI

```
agent-sandbox preflight [--profile linux-sandbox|dev] [--source <dir>] [--json]
agent-sandbox run [--profile ...] [--source <dir>] [--wall-ms n] [--gateway-port p] [--env K=V ...] -- <cmd...>
agent-sandbox gateway --listen <host:port> [--max-requests n] [--max-tokens n] [--max-wall-ms n] [--ca <bundle>]
agent-sandbox collector --run-dir <d> --attempt <id> [--worker-uid <uid>]
agent-sandbox submit --socket <s> --kind <k> [--data <json>]
agent-sandbox cleanup          # remove asbx_ uids/netns/nft/veth left by a crashed run
sandbox-submit --kind <k> [--data <json>]   # inside the sandbox
```

`preflight` exits 0 only when the run is publishable. The library API and a
full harness composition are in [`docs/API.md`](./docs/API.md).

## Claude Code compatibility

Verified with the pinned **Claude Code 2.1.318**. `claude -p` with
`ANTHROPIC_BASE_URL` pointed at the gateway and `ANTHROPIC_API_KEY` set to the
per-attempt **session token** completes headless streaming against a fake
upstream. It sends `POST /v1/messages?beta=true`, and the gateway injects the
real key upstream, so the CLI does **not** need the real key in-process.
The `gateway-compat` test reproduces this; it is gated on the `claude`
binary and `AGENT_SANDBOX_CLAUDE_COMPAT=1`, and makes no paid calls.
Streaming, retries and tool use are covered against a fake upstream in
`gateway.test.ts`. If a future CLI insists on the real key in-process, the
compat test fails and the profile must not be used.

## Not enforced, or enforced differently (honest list)

- **cgroups.** The host has cgroup v1 only and no cgroup delegation, so
  CPU/memory are bounded with rlimits (NPROC, AS, FSIZE, NOFILE) plus a
  wall-clock SIGKILL, not cgroup limits. RLIMIT_NPROC is per-uid, which is
  why every worker gets its own uid.
- **SO_PEERCRED.** Node core has no `getsockopt`. Caller identity on the
  collector is enforced by socket ownership instead: one 0600 socket per
  attempt, owned by that attempt's uid. See DECISIONS.md.
- **IPv6 on kernels without IPv6.** The attack is reported `n/a` (still
  blocked) because no positive control is possible. On hosts with IPv6 it runs
  with a control.
- **The agent binary.** The sandbox binds only `/usr`, `/etc` and the source.
  An agent installed elsewhere (e.g. node under `/opt`) must be bind-mounted
  read-only by the caller.

## Testing

```
npm ci && npm run lint && npm run typecheck
sudo AGENT_SANDBOX_REQUIRE_CAPS=1 npm test   # root: allocates uids, programs nft
```

`AGENT_SANDBOX_REQUIRE_CAPS=1` turns a host that cannot sandbox into a test
failure instead of a skip; CI always sets it. Tests run with one worker.

## Requirements

- Linux with unprivileged user namespaces enabled.
- `bubblewrap` (`bwrap`), `iproute2` (`ip`), and `nft` (nftables).
- Root (or `CAP_NET_ADMIN` + the ability to create uids) for `linux-sandbox`:
  the launcher allocates a per-worker uid and programs host nftables.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
