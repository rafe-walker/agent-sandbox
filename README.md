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
agent-sandbox preflight         # probe capabilities + run attacker suite, print report
agent-sandbox run   -- <cmd>    # launch a command inside the sandbox
agent-sandbox gateway           # run the model auth gateway
agent-sandbox collector         # run the trusted evidence collector
```

See [`docs/`](./docs) for the library API.

## Requirements

- Linux with unprivileged user namespaces enabled.
- `bubblewrap` (`bwrap`), `iproute2` (`ip`), and `nft` (nftables).
- Root (or `CAP_NET_ADMIN` + the ability to create uids) for `linux-sandbox`:
  the launcher allocates a per-worker uid and programs host nftables.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
