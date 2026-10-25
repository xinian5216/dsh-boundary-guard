# Threat Model

This document states what DSH Boundary Guard protects, how, and — explicitly —
what it does **not** guarantee. It is written for operators deciding how much
to trust the guard, and for contributors changing it.

## Assets

1. **Credentials and secrets on the host**: SSH private keys, cloud provider
   credentials, API key files, `.env` files, token stores.
2. **Other AI tools' configuration**: Codex, Claude Code, OpenCode, Cursor and
   similar clients whose global configuration must not be rewritten by an
   agent.
3. **The DSH installation and this plugin's own state**: the DSH home
   (`$DSH_HOME`), the plugin's configuration, audit log, and snapshots.
4. **Workspace integrity**: accidental or malicious destruction of the user's
   project files, Git history, and dependency state.
5. **Remote effects**: pushes, publishes, deployments, uploads, and remote
   sessions.

## Trust boundaries and enforcement layers

| Layer | Mechanism | Guarantee |
|---|---|---|
| Policy gate | `tools/pre-execute` listener | Approvable decisions with audited reasons; bypassable in principle by another `prepend` listener |
| Final backstop | `ctx.tools.guard()` | Monotonic denial: no later listener can re-allow a denial |
| OS confinement | DSH sandbox policy + platform runner (Windows ACL restricted token, bwrap/Landlock/Seatbelt) | Real file-effect boundary for confined capabilities; the guard confirms the mode the policy reports and refuses mutations while it cannot (see C); partial on Windows (reads unconfined, hard-link and AppContainer caveats documented by DSH) |
| Human decision | `ctx.approval` seam | One-shot grants only; missing answerers fail closed |
| Human entry | `ctx.commands.register()` | Mode changes only through a user-typed slash command |

## Attack scenarios and the guard's answer

### A. The model tries to write outside the workspace

* Develop mode denies out-of-workspace writes by policy, and the sandbox
  confines writes to the session workspace at the OS level.
* Maintain mode widens the sandbox to `danger-full-access`; from that point the
  policy engine requires per-operation approval with the exact path shown, and
  the grant expires.

### B. The model tries to overwrite credentials or other AI clients' config

* Denied in every mode, including maintain, through two layers: the resolved
  write target (a path the analyzer proved the operation touches) and a
  text-mention heuristic that denies any *mutating* command whose text names a
  protected location (`.ssh`, `.aws`, `.env`, `credentials`, the DSH home, …),
  even when its write target could not be resolved.
* Both layers are enforced by the synchronous guard as well, so a plugin that
  prepends an `allow` cannot lift them.
* Known limit: an approved **opaque** script (encoded payload, obfuscated
  variable construction, a binary the analyzer cannot read) that references a
  protected location without naming it in text is not caught by the heuristic.
  In develop mode the OS sandbox still confines the effect; in maintain mode the
  approval prompt is the boundary. Treat protected locations as protected
  against *analyzed* operations, not against arbitrary approved code.

### B2. Inspect mode and unclassified tools

* Inspect mode denies tools the classifier cannot identify outright — including
  when a human approval is offered — because an unclassified tool may have
  arbitrary side effects that the read-only boundary must never admit.
* Provably read-only shell commands (single segment, no substitution, no write
  target, and either only read-classified Git tags or a command on the explicit
  read-only allowlist) are treated as reads, so `git status`, `git log`,
  `git diff`, `ls`, `cat`, and `echo` work in inspect mode. `git fetch` is
  deliberately not read-only: it writes refs and objects into the repository.

### B3. The Git read-only boundary

Inspect mode's read-only Git capability is granted by an explicit subcommand and
argument allowlist, never by the command name. The shell analyzer parses Git
global options (`-C <path>`, `-c <name>=<value>`, `--git-dir`, `--work-tree`,
`--namespace`, `--exec-path`, `--super-prefix`, the pathspec and pager flags) to
find the real subcommand, because a global option must never be able to disguise
a mutating subcommand as a read. A Git segment is treated as provably read-only
only when it is a single segment with no substitution construct, no redirect or
write targets, a subcommand on the read allowlist, arguments that satisfy that
subcommand's own rule, and no behavior-changing global option. The options that
can make Git run a program the guard cannot analyze — `-c`/`--config`,
`--config-env`, `--exec-path`, `--namespace`, `--super-prefix`, and the
pager-forcing `-p`/`--paginate` — are tagged `dynamic-execution` and require
approval, because they can define `alias.*`, `core.pager`, `credential.helper`,
or `diff.external`. Values of `-C`, `--git-dir`, and `--work-tree` are collected
as path inputs (read targets for a read-classified subcommand, write targets for
a mutating one) so the protected-path and out-of-workspace rules still apply.

Per-subcommand rules keep write side effects out of the read set: `config` reads
only with an explicit read flag or at most one positional and no write flag;
`branch` and `tag` read only with no positional and no create/delete/move flag;
`diff`, `show`, and `format-patch` are never reads when `--output` (or
`-o`/`--output-directory`) names a file, which is collected as a write target,
and `--ext-diff`/`--textconv` are dynamic execution; `reflog` reads only for a
bare `reflog` or `reflog show`; `symbolic-ref` reads only with at most one
positional; `worktree list`, `stash list`/`show`, and `notes list`/`show` read;
`remote show` is a network read rather than a local read; and any subcommand on
no known list — including a bare `git`, `git help`, `git fsck`, and
`git bisect` — is tagged `unknown-command` so the engine asks instead of
silently allowing it.

Residual limits of the Git rules: the analyzer is a heuristic, not a sandbox. It
does not model every Git subcommand — an unlisted one is escalated for approval
rather than proven safe, which is the intended failure mode. It does not follow
`include.path` indirection, aliases defined in a repository's own configuration
rather than on the command line, or programs Git may invoke through
`core.pager`/`diff.external` when those are not named on the command line; those
are covered by tagging the options that set them. The `--output` file of
`diff`/`show`/`format-patch` is collected as a write target; other file-writing
options of other subcommands are not exhaustively enumerated, which is why
unrecognized subcommands are escalated rather than allowed.

### C. The model tries to raise its own privileges

* Mode state changes only through the `/guard` command family, which runs on
  the human command plane and never becomes a model message.
* No tool, prompt, or session event can write a mode record; tool calls are
  tested to leave mode state untouched.
* Maintain grants are bounded by `maintain.maxDurationMs`, never survive a
  process restart, and fall back to `develop` on expiry.
* Subagent children inherit the parent's mode verbatim; an unknown parent
  fails closed to `inspect`.
* The OS sandbox is synchronized with the guard mode from the first touch of a
  session (not only on mode changes), and a mode counts as applied only when
  the write landed, finished inside a two-second budget, and — when the
  `sandboxPolicy` service is composed — was read back at least as restrictive
  as requested; a wider read-back is a failure, not a success.
* A session whose sandbox cannot be confirmed is not silently degraded: the
  execution path calls `ensureSandboxSynced`, which retries the write once per
  execution, and every mutating operation (`write`/`delete`/`execute`/`admin`)
  is denied with reason `sandbox-unavailable` until the confirmation succeeds.
  Reads, searches, network, meta, jobs and delegate operations are unaffected,
  so the session stays inspectable and repairable, and a transient failure
  recovers on the next call without a restart.
* A failed mode change never leaves the previous, wider mode looking current:
  `/guard status` reports the required mode, the mode last applied
  successfully, whether that write was read back, and what the policy reports
  now. Known limit: the guard can confirm that the policy *says* the right
  mode, not that the platform runner enforces it — that remains the runner's
  guarantee.

### D. The model rewrites a denied command to evade analysis

* Shell analysis is heuristic. A rewritten command that the analyzer does not
  recognize becomes `dynamic-execution` (approval required) rather than being
  allowed silently, and destructive or remote patterns are matched across
  segments and the whole command string. Nested opaque shells are treated the
  same way on every platform: `sh -c`, `bash -c`, and Windows `cmd /c|/k|/r` are
  dynamic execution because their inner text is parsed by another shell.
* The sandbox still confines the *effect*: in develop mode an obfuscated write
  outside the workspace fails at the OS level regardless of what the analyzer
  understood.

### E. Path tricks

* Windows case-insensitivity, drive-letter normalization, UNC and `\\?\`
  folding, alternate data streams, segment-wise containment, Windows 8.3
  short-name aliases (workspace roots and targets are compared in canonical
  form), and symlink / junction resolution through the deepest existing
  ancestor are all handled.
* Known limit: **time-of-check to time-of-use races**. The policy check and the
  tool execution are separate steps; a symlink swapped in between can in
  principle evade the policy layer. The OS sandbox is the backstop for
  confined capabilities.

### F. Approval fatigue and silent retries

* Approvals are one-shot grants bound to the exact call; nothing is remembered
  for "similar" operations.
* Rejection, cancellation, and unavailability all produce a denial with a
  distinct reason; the operation never executes.
* A denial never escalates to a wider-permission retry.

### G. Plugin or configuration failure

* Invalid configuration rejects plugin load (loud), it does not fall back to a
  permissive policy.
* An engine fault denies with `internal-error`.
* A session without a workspace root fails closed for writes.
* If the projection registry is absent, mode state is in-memory only; the
  configured default applies to new sessions. This is a documented degradation,
  not a silent widening.

### H. Audit tampering

* The audit log lives under the DSH home, which the policy protects from agent
  writes. This is a policy boundary, not an OS-level one: an agent running with
  `danger-full-access` in maintain mode could in principle rewrite the log with
  host-level tools. Operators who need tamper-evidence should protect
  `$DSH_HOME` with OS permissions or ship logs off-host.

## What is NOT guaranteed

1. **Complete shell parsing.** The analyzer cannot prove that an arbitrary
   script is safe. Opaque constructs are treated as dynamic execution and
   require approval; the sandbox confines effects in develop mode, but in
   maintain mode the OS confinement is off and approval is the boundary.
2. **Blocking all side effects.** Network egress, database writes, remote
   servers, and out-of-band process effects are outside the file sandbox's
   vocabulary. Remote operations are detected heuristically and gated by
   approval.
3. **TOCTOU-free path checks.** See E.
4. **Snapshots as an undo system.** Snapshots capture only the files the guard
   saw change, before approved mutations. Databases, remote systems, and
   process side effects are not recoverable from them.
5. **Secrecy of the audit log.** See H.
6. **Protection against a hostile plugin.** A plugin registered with `prepend`
   can run before the guard's `pre-execute` listener. The `ctx.tools.guard()`
   backstop still denies the non-overridable rules, but approvals decided by
   other listeners are outside this plugin's control.
7. **Kernel-level isolation.** The Windows ACL runner restricts writes; reads
   remain unconfined, and DSH documents hard-link and AppContainer caveats.
8. **Behavior on untested DSH versions.** The plugin declares
   `engines.dsh: ">=0.2.1-rc.3 <0.3.0"` and is verified against `0.2.1-rc.3`.
   Other versions may behave differently.
9. **Protected locations against arbitrary approved code.** The two layers in B
   cover analyzed operations. An approved opaque script that reaches a protected
   location without naming it in text is a documented residual risk; in maintain
   mode the approval prompt is the only boundary.
10. **Every Git subcommand.** The read-only Git boundary is an allowlist, so an
    unlisted subcommand is escalated for approval instead of proven safe. Git
    options and configuration that make Git run another program are tagged
    dynamic execution, but configuration read from the repository's own files
    (`include.path`, repository-local aliases) is not followed. See B3.
11. **That the platform runner enforces the confirmed mode.** The guard confirms
    what the sandbox policy service reports, and refuses to run mutations while
    it cannot confirm it. Whether the OS-level runner then enforces that mode is
    the runner's guarantee (see the table above and item 7).

## Security-relevant configuration defaults

| Setting | Default | Rationale |
|---|---|---|
| `defaultMode` | `develop` | Daily driver; workspace-write with approval for risky operations |
| `unknownToolPolicy` | `ask` | Unrecognized tools are shown to the human, not run silently |
| `audit.enabled` | `true` | Local, sanitized audit trail |
| `snapshot.enabled` | `false` | Opt-in convenience, not a guarantee |
| `maintain.requireConfirmation` | `true` | Entering maintain mode needs an explicit human confirmation |
| `maintain.maxDurationMs` | `1800000` | 30-minute ceiling on any maintain grant |
