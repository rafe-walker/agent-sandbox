# Changelog

All notable changes to agent-sandbox. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses
semantic versioning once past 0.x.

## [Unreleased]

### Added
- The trusted evidence collector. A per-attempt UNIX socket under a root-owned
  dir; the agent submits versioned, schema-validated, size-bounded (64 KiB)
  proposals and the collector assigns the id, timestamp, seq and attempt
  identity itself, appending to a canonical store the agent cannot reach, and
  returns a receipt. Caller identity is enforced by filesystem ownership (the
  0600 socket is owned by the worker uid in a traverse-only 0711 `sock/` dir;
  the store sits under a separate opaque 0700 dir, never bind-mounted) because
  Node core cannot read SO_PEERCRED — same guarantee, see DECISIONS.md. Hostile
  input (bad JSON, wrong schema, `__proto__`/`constructor` keys, oversize,
  deep nesting, bad `kind`) fails closed. The `evidence_writer_separated` probe
  measures all of this from inside the sandbox and feeds the preflight.
- `sandbox-submit`, a tiny CLI (also `agent-sandbox submit`) for submitting a
  proposal from inside the sandbox; `agent-sandbox collector` runs the server.
- The model auth gateway. The real Anthropic key lives only here; the agent
  gets `ANTHROPIC_BASE_URL` + a random per-attempt session token, which the
  gateway swaps for the real key. It allowlists the API paths the pinned Claude
  Code (2.1.x) uses, refuses CONNECT and absolute-form/arbitrary-host targets,
  pins the upstream host, strips credential-bearing response headers, redacts
  the key from error bodies, enforces per-attempt request/token/wall-clock
  budgets, and records provider-reported usage per request as the token meter
  (SSE and buffered JSON). The upstream call is injectable so the compatibility
  test runs against a fake/recorded upstream with no paid calls; the real
  dispatch tunnels through the outer HTTPS proxy (CONNECT) with the CA bundle.
- Echoed-credential redaction helper (`buildRedactor`): exact, JSON-escaped,
  URL-encoded, base64 (std + url-safe) and split forms. Documented as a
  mitigation, not a proof.
- Base-URL compatibility test (gated on the `claude` binary +
  `AGENT_SANDBOX_CLAUDE_COMPAT=1`): spawns the real CLI against the gateway with
  a fake SSE upstream and asserts headless streaming round-trips with a session
  token only. An optional live Haiku smoke (<= $0.10) is gated off by default
  and never runs in CI.
- The per-attempt network cage. A dedicated netns joined by a veth pair; the
  launcher runs the sandbox under `ip netns exec` so it inherits the cage. Host
  nftables live in our OWN `inet asbx_<id>` table (the host's existing ruleset
  is never touched) and allow the sandbox to reach only the configured gateway
  TCP ports on the host veth IP — no DNS, IPv6 disabled and dropped, no
  forwarding (`ip_forward` stays off). `setupNetwork`/`teardownNetwork` are
  idempotent; `cleanupStale` removes every leftover `asbx_` netns/table/veth
  from crashed runs. The `net_enforced` probe measures reachability (gateway
  yes; non-gateway port, external host, DNS, IPv6 all no) and feeds the
  preflight.
- The launcher. Runs an untrusted command through
  `prlimit -> setpriv -> [ip netns exec] -> bwrap`: a dedicated per-worker uid
  with a PRIVATE group (never a shared gid such as `docker`); user/pid/ipc/uts
  namespaces (+ net isolation unless a prepared netns is joined),
  `--die-with-parent`, `--new-session`, `--cap-drop ALL`, and `--clearenv` so
  the harness environment (and its credentials) never cross; read-only `/usr`
  and `/etc` and a read-only source bind; a fresh HOME, private `/tmp` and
  `/dev/shm`, a new `/proc`, a minimal `/dev`, no `/run`; rlimits
  (NPROC/AS/FSIZE/NOFILE) and a wall-clock SIGKILL; fd hygiene (only stdio is
  inherited, assertable from inside). Teardown SIGKILLs the PID namespace and
  polls until no worker-owned process survives, including detached children,
  then removes the uid and its group.
- Launcher-backed capability probes (uid_separated, pid_ns, mount_ns,
  fds_clean, creds_absent) wired into the preflight, each a measured check run
  inside the real sandbox config. `creds_absent` plants a credential canary in
  the harness env and asserts `--clearenv` keeps it out.
- CI `sandbox` job runs the full suite as root with
  `AGENT_SANDBOX_REQUIRE_CAPS=1` so a host that cannot sandbox fails closed.
- Profiles (`dev`, `linux-sandbox`, `microvm` reserved), the capability report
  schema, and the preflight runner. The report records *measured* capabilities
  (uid_separated, pid_ns, mount_ns, net_enforced, creds_absent, fds_clean,
  evidence_writer_separated) plus the attacker-suite version and result.
  `derivePublishable` is the single source of truth for the invariant:
  publishable iff `linux-sandbox` AND every required capability passed AND the
  suite passed — no silent downgrade. `agent-sandbox preflight` prints the
  report and exits non-zero when not publishable. Capability probes and the
  attacker suite are registered by the later stacked modules.
- Scaffold: Apache-2.0 license, TypeScript (Node 22, strict) toolchain with
  vitest and ESLint, README stating the threat model and trust assumptions,
  SECURITY.md, DECISIONS.md, and GitHub Actions CI. The Linux CI job
  apt-installs bubblewrap and **fails closed** if namespace support is
  missing — it never skips the sandbox suite silently.
