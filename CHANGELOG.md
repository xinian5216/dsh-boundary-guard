# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  alternate data stream splitting, symlink/junction resolution through the
  deepest existing ancestor, and segment-wise containment.
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

- 103 automated tests: unit, integration against the real DSH tool pipeline
  (ToolRuntime, fs tools, the Windows ACL sandbox, the approval service, and
  the command registry), and 15 security regression tests.
- Real installation, composition, load, and removal through the official DSH
  plugin manager in an isolated profile.

### Known limitations

- Shell and code analysis is heuristic; the DSH sandbox and OS permissions
  remain the enforcement boundary. See `docs/THREAT_MODEL.md`.
- A full LLM-driven session was not executed end to end because that requires
  provider credentials; verification stops at the model boundary. See
  `docs/COMPATIBILITY.md`.

[0.1.0]: https://github.com/PLACEHOLDER/dsh-boundary-guard/releases/tag/v0.1.0
