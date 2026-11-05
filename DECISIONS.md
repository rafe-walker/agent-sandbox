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
