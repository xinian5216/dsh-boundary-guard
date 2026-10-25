# Compatibility

## Verified environment

| Component | Version |
|---|---|
| DeepSeek Harness (desktop) | 0.2.1-rc.3 |
| Cordis | 4.0.5 |
| Node.js | 24.x |
| Platform verified | Windows 11 x64 |
| Platform tested (unit/integration) | Linux semantics for pure path helpers; the pipeline tests run on Windows |

The plugin declares `engines.dsh: ">=0.2.1-rc.3 <0.3.0"`, so the official
installer admits it on any 0.2.x runtime. Only `0.2.1-rc.3` has been verified
end to end; treat other versions as untested.

## Extension points used

| API | Package | Use |
|---|---|---|
| `tools/pre-execute` waterfall | `@deepseek-ai/dsh-tools` | Approvable allow/deny/ask decisions |
| `ctx.tools.guard()` | `@deepseek-ai/dsh-tools` | Monotonic final denials |
| `ctx.tools.register()` | `@deepseek-ai/dsh-tools` | Not used by this plugin |
| `ctx.approval.request()` | `@deepseek-ai/dsh-user-approval` | Human approval with sanitized presentation |
| `ctx.commands.register()` | `@deepseek-ai/dsh-commands` | The `/guard` command family |
| `ctx.userQuestions.ask()` | `@deepseek-ai/dsh-user-questions` | Maintain-mode and rollback confirmation |
| `setSandboxMode()` | `@deepseek-ai/dsh-sandbox-policy` | Per-session sandbox mode for each guard mode |
| `ctx.sandboxPolicy.overrideOf()` | `@deepseek-ai/dsh-sandbox-policy` | Read-back that confirms a sandbox-mode write actually landed |
| `ctx.sessionProjections` | `@deepseek-ai/dsh-session-projection` | Durable mode state fold |
| `appendPluginRecord()` | `@deepseek-ai/dsh-session` | Durable mode-change records |
| `ctx.workingDirectory.get()` | `@deepseek-ai/dsh-working-directory` | Effective working directory for relative paths |
| `resolveDshHome()` semantics | `@deepseek-ai/dsh-home-paths` | Storage location discovery |

Optional services (`sessionProjections`, `workingDirectory`, `approval`,
`userQuestions`) are consumed through `ctx.inject()` or `ctx.get()`, so the
plugin still loads when they are absent and degrades in documented ways.

## What was verified on a real DSH installation

Performed in an isolated DSH home with a profile created from the shipped
`headless` template:

1. `dsh plugin --profile <p> add <bundle>` installs the bundle through the
   official plugin manager (pnpm) and records it in `dsh.profile.bundles`.
2. `dsh --profile <p> --dump-config` shows the composed `boundary-guard` entry
   with the configured values.
3. Booting the profile loads the plugin: its storage directory is created and
   the run proceeds to the model boundary, failing only on the absent provider
   credential.
4. `dsh plugin --profile <p> remove dsh-boundary-guard` deselects the bundle
   and removes the dependency.

Not performed: a full LLM-driven session (running a task end to end with a
model), because that requires provider credentials that must not be used for
verification. Behavioral verification is covered by the integration tests,
which compose the real ToolRuntime, the real fs and pwsh tools, the real
Windows ACL sandbox provider, the real approval service, and the real command
registry, and then execute real tool calls.

## Platform notes

### Windows

- The sandbox chain resolves to the ACL restricted-token runner. Writes are
  confined to the session workspace (plus a private temp directory) under
  `workspace-write`; reads remain unconfined, as documented by DSH.
- Protected-path discovery includes the Windows credential stores and uses
  case-insensitive, drive-letter-normalized comparison.
- Alternate data streams (`file.txt:stream`) are split off before comparison.

### Linux and macOS

- The sandbox chain resolves to bwrap, Landlock, or Seatbelt through DSH's
  local provider.
- Pure path helpers are unit-tested against POSIX semantics; the protected-path
  catalog covers the POSIX credential locations.
- The pipeline tests are written platform-neutrally; the shell stack tests run
  wherever a shell tool is composed.

## Interoperation

- The plugin does not modify DSH, and it does not write to Codex, Claude Code,
  OpenCode, or any other tool's configuration.
- It does not require any other AI tool to expose credentials.
- The `/permission` command and the plugin both write the session's sandbox
  mode. The guard re-asserts its own mode mapping on its own transitions
  (mode switches and maintain expiry) and after a failed confirmation; it does
  not fight an explicit user change made through the permission selector between
  transitions. A user change that leaves the sandbox wider than the guard mode
  requires is reported by `/guard status` (as a divergence from the read-back)
  rather than silently overwritten.

## Upgrade notes

- 0.1.x stores mode state in session plugin records under the
  `plugin:dsh-boundary-guard/` namespace. Records from a future version with an
  incompatible shape are ignored (the fold falls back to the configured
  default), never guessed at.
- No migration is required from earlier versions; 0.1.0 is the first release.
- 0.1.2 adds no new persisted state: the sandbox-confirmation bookkeeping is
  in-memory per process, and the mode record format is unchanged.
