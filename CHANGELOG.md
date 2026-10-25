# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-10-25

Hardening release driven by a security review of v0.1.1. Every item below was
first reproduced with a failing test, then fixed, then locked in by a regression
test. 151 automated tests pass (unit, integration against the real DSH tool
pipeline, and security regressions) on Windows and Linux.

### Fixed

- **Inspect mode's read-only Git boundary was the command name, not an
  allowlist.** `git` sat in the read-only command set, so any `git …` invocation
  the analyzer could not otherwise classify produced no risk tags at all and was
  treated as provably read-only. That admitted, inside inspect mode's read-only
  boundary, `git -C <dir> push`, `git --git-dir=… push`, `git -c alias.x='!…' x`
  (arbitrary shell execution through a Git alias), `git config <key> <value>`,
  `git branch <name>`, `git tag <name>`, `git diff --output=<file>`,
  `git show --output=<file>`, `git reflog expire`, `git symbolic-ref HEAD …`,
  `git worktree add`, `git archive --output=…`, `git help`, and every other
  unlisted subcommand.
  The analyzer now parses Git global options (`-C`, `-c`, `--git-dir`,
  `--work-tree`, `--namespace`, `--exec-path`, `--super-prefix`, the pathspec and
  pager flags) to find the real subcommand, grants read-only only from an
  explicit subcommand **and** argument allowlist, tags the options that can make
  Git run a program the guard cannot analyze (`-c`/`--config`, `--config-env`,
  `--exec-path`, `--namespace`, `--super-prefix`, `-p`/`--paginate`) as dynamic
  execution, collects `-C`/`--git-dir`/`--work-tree` values as path inputs so the
  protected-path and out-of-workspace rules still apply, and tags any subcommand
  on no known list as `unknown-command` so the engine asks instead of allowing.
- **Sandbox synchronization did not fail closed.** A failed sandbox sync was
  recorded and then ignored: nothing in the execution path consulted the error,
  `retrySandboxSync()` was never called, and a `setSandboxMode()` call that
  returned without throwing was treated as proof that the OS sandbox was in that
  mode. A mode now counts as applied only when the write landed, finished inside
  a two-second budget, and — when the `sandboxPolicy` service is composed — was
  read back at least as restrictive as requested; a wider read-back is a failure.
  The execution path calls `ensureSandboxSynced()`, which retries once per tool
  call, and every mutating operation is denied with the new reason code
  `sandbox-unavailable` until the confirmation succeeds. Reads, searches,
  network, meta, jobs and delegate operations stay available.
- **`date -s` was inside the read-only allowlist.** A clock change (and a bare
  Windows `date`, which opens a prompt) was classified as a read. `date` is now
  read-only only without arguments or with `-u`/`--utc`/`--universal`.
- **Nested opaque shells were only detected on POSIX.** `sh -c` and `bash -c`
  were tagged dynamic execution, but Windows `cmd /c`, `cmd /k` and `cmd /r`
  were not, so an unanalyzable nested command was allowed without approval in
  develop mode. The Windows spellings are now tagged dynamic execution too.

### Changed

- `docs/THREAT_MODEL.md` documents the Git read-only boundary (new section B3),
  the sandbox confirmation rules, and two new residual limits (the Git allowlist
  is a heuristic; the guard confirms the mode the policy reports, not that the
  platform runner enforces it).
- `/guard status` distinguishes "applied and verified" from "written but not read
  back", shows what the sandbox policy reports when it diverges, and reports the
  last synchronization error.
- A security regression test that used the real user profile path (`~/.ssh`) now
  runs against an isolated temporary `HOME`/`USERPROFILE`, so the test, its
  failure path, and its cleanup can never touch a real user file.

### Security

- **Dependencies.** `zod` was pinned to 4.4.3, affected by GHSA-mrhx-c7xc-m3w5
  (memory exhaustion while validating oversized constrained collections, fixed in
  4.6.6); it is now 4.6.7, with a workspace override so the DSH packages that pin
  it exactly move too. `undici` arrived transitively at 8.11.2, affected by
  GHSA-4qv8-2p9j-2685, GHSA-f72v-6w45-q472 and GHSA-xjj6-f33q-929c (fixed in
  8.12.2); a workspace override moves it to 8.12.3. `pnpm audit` now reports no
  advisories, and the full test suite runs against both.

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

[0.1.2]: https://github.com/xinian5216/dsh-boundary-guard/releases/tag/v0.1.2
[0.1.1]: https://github.com/xinian5216/dsh-boundary-guard/releases/tag/v0.1.1
[0.1.0]: https://github.com/xinian5216/dsh-boundary-guard/releases/tag/v0.1.0
