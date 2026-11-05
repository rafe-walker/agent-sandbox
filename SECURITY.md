# Security policy

## What agent-sandbox defends

agent-sandbox isolates an **untrusted AI agent process** from the harness that
runs it. The adversary is the agent: it has a shell and file-write tools and is
assumed to actively try to escape. See the threat model in the README.

## What it does NOT defend against

- **A hostile kernel.** Every boundary here is kernel-enforced (namespaces,
  nftables, rlimits, uid separation). A kernel privilege-escalation defeats all
  of it. Use the reserved `microvm` profile for hostile customer code (not
  implemented in v0.1).
- **A malicious audited server leaking a token it legitimately holds.** Echoed-
  key redaction is a mitigation, not a proof.
- **Native macOS.** `dev` only, never publishable.

## Reporting

Email the maintainer (see `package.json` `author`). Do not open a public issue
for an unpatched vulnerability. Because this is pre-1.0 security tooling,
include the host kernel, the `agent-sandbox preflight` capability report, and a
reproducer.

## Publishability invariant

A run is publishable only when `profile === "linux-sandbox"` AND the preflight
attacker suite passed on that host. Any failed control makes the run
non-publishable. There is no silent downgrade path.
