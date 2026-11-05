# Changelog

All notable changes to agent-sandbox. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses
semantic versioning once past 0.x.

## [Unreleased]

### Added
- Scaffold: Apache-2.0 license, TypeScript (Node 22, strict) toolchain with
  vitest and ESLint, README stating the threat model and trust assumptions,
  SECURITY.md, DECISIONS.md, and GitHub Actions CI. The Linux CI job
  apt-installs bubblewrap and **fails closed** if namespace support is
  missing — it never skips the sandbox suite silently.
