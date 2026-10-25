# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-25

Hardening release driven by a review of v0.1.0. Every item below was first
reproduced with a failing test, then fixed, then locked in by a regression test.

### Fixed

- **Sandbox synchronization on session start.** A session that never changed
  mode kept the deployment sandbox default (usually `workspace-write`) even in
  inspect mode. The sandbox is now synchronized with the guard mode from the
  first touch of a session.
- **Sandbox sync failures are visible and retryable.** The "already synced"
  marker was written before the write succeeded and errors were swallowed, so a
  failed sync was reported as success and never retried. The marker is now
  written only after success, the failure is recorded, `/guard status` reports
  the real state (desired / applied / last error), and `retrySandboxSync()`
  re-attempts it.
- **Inspect mode can no longer approve unclassified tools.** An unknown tool
  (for example an MCP tool) reached the approval seam in inspect mode and could
  execute with side effects once approved. Inspect now denies unclassified
  tools outright, approval or not.
- **Read-only shell commands in inspect mode.** `git status`, `git log`,
  `git diff`, `git show`, `ls`, `cat`, and `echo` were classified as
  executions and blocked. A command is now classified as a read only when it is
  provably read-only: a single segment, no substitution constructs, no write
  target, and either only read-classified Git tags or a command on an explicit
  read-only allowlist. `git fetch` remains an execution (it writes refs).

### Added

- **Indirect protected-path heuristic.** A mutating command whose text names a
  protected location (`.ssh`, `.aws`, `.env`, `credentials`, the DSH home,
  …) is denied in every mode — including maintain — even when its write target
  could not be resolved (variables, nested shells, encoded payloads).
- Seven new regression tests (sandbox sync semantics, inspect unknown tools,
  inspect read-only commands, indirect protected writes, cross-platform develop
  experience, read-only classification, protected-mention detection).

### Changed

- `docs/THREAT_MODEL.md` now states the residual risk precisely: protected
  locations are guaranteed against *analyzed* operations, not against arbitrary
  approved opaque code, and lists the inspect-mode unclassified-tool rule.

## [0.1.0] - 2026-10-25

First release of DSH Boundary Guard.

### Added

- Three audited operating modes with OS-level meaning through the native DSH
  sandbox policy: `inspect` (read-only), `develop` (workspace-write), and
  `maintain` (time-boxed danger-full-access with per-operation approval).
- Policy engine with the fixed priority order: non-overridable safety
  constraints, explicit denials, approval requirements, allow rules, default
  denial. Every decision carries a stable reason code.
- Enforcement through the official extension points: the `tools/pre-execute`
  waterfall for approvable decisions and `ctx.tools.guard()` for final denials
  that no later listener can re-allow.
- Human approval through the official `ctx.approval` seam, with a sanitized
  presentation that shows the command, target paths, risk, and consequences.
- Cross-platform protected-path discovery: SSH keys, cloud credentials, API
  key files, `.env` files, other AI clients' global configuration, the DSH
  home, and the plugin's own installation. Protected paths are permanently
  non-writable in every mode.
- Path boundary checks with Windows case-insensitivity, UNC and `\\?\` folding,
  alternate data stream splitting, 8.3 short-name alias canonicalization,
  symlink/junction resolution through the deepest existing ancestor, and
  segment-wise containment.
- Shell command analysis for PowerShell, CMD, and Bash: git subcommands,
  package managers, remote operations, destructive commands, privilege
  escalation, system configuration, dynamic execution, redirections, and bulk
  operations. Unknown constructs are classified conservatively.
- Tool classification for the shipped DSH tool families, including sandbox
  escalation arguments and background execution.
- `/guard status`, `/guard inspect`, `/guard develop`, `/guard maintain`,
  `/guard audit`, `/guard snapshots`, and `/guard rollback` commands, available
  only through the trusted human command entry.
- Subagent mode inheritance: a delegated child session inherits its parent's
  restrictions verbatim, and an unknown parent fails closed to `inspect`.
- Durable per-session mode state through a session plugin record and a session
  projection; maintain grants never survive a process restart.
- Local structured audit logging (JSONL, size-rotated, age-retained) under the
  DSH home, with sanitized targets and no command text, file contents, or
  secrets.
- Optional workspace snapshots captured before approved mutations, with
  documented limits (files only; not a universal undo).
- Fail-closed behavior throughout: configuration failures reject plugin load,
  engine faults deny, and missing approval channels deny.

### Verified

- 104 automated tests: unit, integration against the real DSH tool pipeline
  (ToolRuntime, fs tools, the Windows ACL sandbox, the approval service, and
  the command registry), and 16 security regression tests (the 15 acceptance
  criteria plus a Windows 8.3 short-name alias regression).
- Real installation, composition, load, and removal through the official DSH
  plugin manager in an isolated profile, including from the packed bundle.

### Known limitations

- Shell and code analysis is heuristic; the DSH sandbox and OS permissions
  remain the enforcement boundary. See `docs/THREAT_MODEL.md`.
- A full LLM-driven session was not executed end to end because that requires
  provider credentials; verification stops at the model boundary. See
  `docs/COMPATIBILITY.md`.

[0.1.1]: https://github.com/xinian5216/dsh-boundary-guard/releases/tag/v0.1.1
[0.1.0]: https://github.com/xinian5216/dsh-boundary-guard/releases/tag/v0.1.0
