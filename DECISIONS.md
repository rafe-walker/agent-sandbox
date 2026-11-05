# Decisions

Append-only log of architectural decisions. Newest last.

## 2026-11-05 — bubblewrap + dedicated uid over gVisor/microVM for v0.1

**Context**: Isolate untrusted agent processes on a shared-kernel Linux host.
**Decision**: `linux-sandbox` = a dedicated uid/gid per worker + bwrap
(user/pid/ipc/net/uts ns, die-with-parent, new-session, cap-drop ALL).
**Rationale**: The external council (ChatGPT/Gemini/Grok) unanimously held uid
alone to be necessary-but-insufficient and bwrap to be the right next tier at
our scale. gVisor/microVM-per-attempt is overkill for auditing our own choice
of third-party MCP servers.
**Alternatives**: gVisor, Firecracker microVM per attempt, `sudo -u` uid-only.
**Consequences**: Shared-kernel trust is explicit. `microvm` stays reserved for
hostile customer code.

## 2026-11-05 — The launcher allocates an isolated gid, never a shared one

**Context**: `useradd --system` on this host placed the new uid in the `docker`
group (highest free system gid). A sandbox uid in `docker` would be a trivial
escape.
**Decision**: Create a dedicated primary group per worker uid; never reuse an
existing gid; clear supplementary groups before exec.
**Consequences**: Teardown must remove both the uid and its group.

## 2026-11-05 — Measured capabilities, no silent downgrade

**Context**: Reviewers split on flag shape (profiles vs none/uid/bwrap).
**Decision**: Named profiles + a preflight that records *measured* capabilities
(uid_separated, pid_ns, mount_ns, net_enforced, creds_absent, fds_clean,
evidence_writer_separated) and the suite version/result. `publishable` is true
only for `linux-sandbox` with a passing preflight.
**Consequences**: A degraded host produces a non-publishable run, loudly, never
a quietly weaker one.

## 2026-11-05 — Network enforced by netns + host nftables, not env vars

**Context**: `HTTPS_PROXY` is a convention the agent can unset.
**Decision**: Per-attempt netns + veth; host nftables allow only the gateway
ports from the veth iface; `ip_forward` stays off so the sandbox cannot route
to the host's uplink; IPv6 and DNS denied.
**Consequences**: Names like `asbx_<hex>` (underscores; nft rejects hyphens in
unquoted identifiers, 15-char veth limit). Teardown removes netns, veth, table.

## 2026-11-05 — Collector caller-identity: filesystem ownership, not SO_PEERCRED

**Context**: The design calls for SO_PEERCRED to identify the caller uid on the
collector socket. Node's core `net` exposes no `getsockopt`, so SO_PEERCRED
cannot be read without a native addon (a new build dependency we do not want in
v0.1).
**Decision**: Enforce the same property with the filesystem: one socket per
attempt, the socket owned by that attempt's worker uid at mode 0600, inside a
root-owned 0711 (traverse-only) `sock/` dir; the canonical store lives under a
separate root-owned 0700 `store/` dir and is never bind-mounted. Attempt
identity is the socket the connection arrived on — never a field the agent
sends.
**Rationale**: Only the worker uid can open its 0600 socket; the agent cannot
list, create in, or delete from the 0711 dir, and cannot traverse the 0700
store dir at all. This yields the SO_PEERCRED guarantee (a wrong uid cannot
connect; identity is not agent-supplied) in pure Node.
**Alternatives**: a native SO_PEERCRED addon (rejected: build dep for v0.1);
a single shared socket with in-band attempt ids (rejected: agent-forgeable).
**Consequences**: bwrap resolves the bind source as the dropped worker uid, so
the socket path must be traverse-reachable (0711); documented here and in the
collector source. A native SO_PEERCRED check can be added later as
defence-in-depth without changing the model.

## 2026-11-05 — Attacker suite: every attack carries a genuine positive control

**Context**: A blocked attack proves nothing if the test could never have seen a
success. During the build two checks were found vacuous: a hardcoded
`controlSucceeded = true` for detached-process survival, and a
`/proc/self/environ` read via shell redirect, which returns EOF after exec.
**Decision**: Each attack runs twice: under the real config, and under a
control with exactly one protection removed (PID ns, net ns, clearenv, fd
closing, a bind, the nft drop, redaction, rlimit size). `pass` requires
blocked AND control succeeded.
**Exception**: `notApplicable`, allowed only when the HARNESS (not the
sandbox) proves the vector does not exist on the host (today: a kernel with no
IPv6). The attack must still be blocked, and N/A results are listed in the
report.
**Consequences**: The suite is slower (two launches per attack, ~1–4 s each)
but cannot pass by construction.

## 2026-11-05 — No default route inside the network cage

**Context**: The cage had a default route via the host veth. nftables plus
`ip_forward=0` still dropped everything, but 169.254.169.254 (which answers on
this VM's host network) was routable from the sandbox.
**Decision**: Install no default route. The only reachable address is the
on-link /30 peer (the gateway).
**Consequences**: Defence in depth: external and metadata destinations fail
with "network unreachable" before nftables is consulted.

## 2026-11-05 — One launch path for production and the attacker suite

**Context**: The escape review found the launch chain inherited the harness
env, so bwrap (pid 1 in the agent's PID namespace, running as the worker uid)
exposed the harness credentials at `/proc/1/environ`. Preflight still said
PUBLISHABLE, because the suite's runner had its own command line and env and
measured something other than what production ran.
**Decision**: `buildSandboxInvocation()` is the single, pure source of the
command line AND the environment, and `launchWith()` is the single runner.
`launch()` delegates to it with every protection on. The suite calls the same
function; positive controls switch exactly one protection off through an
explicit `UnsafeControls` argument that `launch()` never passes. Tests fail
if the suite harness builds its own command line or spawns anything, if
`drop:'none'` differs from the production invocation, or if any `src` file
imports `node:child_process` without `MINIMAL_ENV`.
**Consequences**: The preflight measures exactly what real runs get. Helpers
never inherit `process.env`. The capability probe and a dedicated attack scan
every visible process, not only themselves.

## 2026-11-05 — Preflight reports are Ed25519-signed per host

**Context**: mcp-audit and mcp-bench accepted a preflight report on its
contents alone, so a hand-written or edited JSON file passed as "linux-sandbox".
**Decision**: The preflight signs `{report, binding}` with a per-host Ed25519
key; the signature covers the exact payload bytes (base64 in the envelope, no
canonicalization) with a domain-separation prefix. The binding holds the host
id (sha256 of machine-id, boot_id, hostname, kernel release), the
agent-sandbox and suite versions, the key id, issue/expiry times and a nonce.
`verifyPreflight` fails closed and re-derives publishability.
**Rationale**: Ed25519 lets consumers verify with only the public key, so a
consumer process never holds signing material. Binding to boot_id makes a
reboot (possibly into another kernel) invalidate every report.
**Alternatives considered**: HMAC with a shared key (every verifier could
forge); signing canonical JSON (a second canonicalizer to keep in sync).
**Consequences**: The key is only as safe as root on the host. A consumer
must obtain the public key out of band or from the root-owned key dir
(`loadHostPublicKey`). Reports from before a reboot or upgrade must be
re-issued.
