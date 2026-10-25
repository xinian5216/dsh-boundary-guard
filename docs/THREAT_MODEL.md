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
| OS confinement | DSH sandbox policy + platform runner (Windows ACL restricted token, bwrap/Landlock/Seatbelt) | Real file-effect boundary for confined capabilities; partial on Windows (reads unconfined, hard-link and AppContainer caveats documented by DSH) |
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

* Denied in every mode, including maintain. This is the permanent floor and is
  also enforced by the synchronous guard, so a plugin that prepends an `allow`
  cannot lift it.

### C. The model tries to raise its own privileges

* Mode state changes only through the `/guard` command family, which runs on
  the human command plane and never becomes a model message.
* No tool, prompt, or session event can write a mode record; tool calls are
  tested to leave mode state untouched.
* Maintain grants are bounded by `maintain.maxDurationMs`, never survive a
  process restart, and fall back to `develop` on expiry.
* Subagent children inherit the parent's mode verbatim; an unknown parent
  fails closed to `inspect`.

### D. The model rewrites a denied command to evade analysis

* Shell analysis is heuristic. A rewritten command that the analyzer does not
  recognize becomes `dynamic-execution` (approval required) rather than being
  allowed silently, and destructive or remote patterns are matched across
  segments and the whole command string.
* The sandbox still confines the *effect*: in develop mode an obfuscated write
  outside the workspace fails at the OS level regardless of what the analyzer
  understood.

### E. Path tricks

* Windows case-insensitivity, drive-letter normalization, UNC and `\\?\`
  folding, alternate data streams, segment-wise containment, and symlink /
  junction resolution through the deepest existing ancestor are all handled.
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

## Security-relevant configuration defaults

| Setting | Default | Rationale |
|---|---|---|
| `defaultMode` | `develop` | Daily driver; workspace-write with approval for risky operations |
| `unknownToolPolicy` | `ask` | Unrecognized tools are shown to the human, not run silently |
| `audit.enabled` | `true` | Local, sanitized audit trail |
| `snapshot.enabled` | `false` | Opt-in convenience, not a guarantee |
| `maintain.requireConfirmation` | `true` | Entering maintain mode needs an explicit human confirmation |
| `maintain.maxDurationMs` | `1800000` | 30-minute ceiling on any maintain grant |
