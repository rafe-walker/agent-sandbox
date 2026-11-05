# Changelog

All notable changes to agent-sandbox. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses
semantic versioning once past 0.x.

## [Unreleased]

### Added
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
