# DSH Boundary Guard

A mode-based operation boundary for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness):
three audited operating modes, approval-gated high-risk operations, permanently
protected credential and configuration locations, and a sanitized local audit
trail.

The plugin is a **policy layer built on DSH's own mechanisms** — the
`tools/pre-execute` waterfall, the monotonic `ctx.tools.guard()` backstop, the
sandbox policy service, the approval seam, and the human command registry. It
does not patch DSH internals, and it does not promise to stop every possible
side effect. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the exact
guarantees and limits.

> Not a sandbox replacement, not a guarantee of absolute safety. It raises the
> cost of accidents and misuse, and it makes high-risk operations visible.

## Modes

| Mode | Sandbox file policy | What it is for |
|---|---|---|
| `inspect` | `read-only` | Analysis and investigation. Reads, searches, read-only Git from an explicit subcommand allowlist (`status`, `log`, `diff`, `show`, `branch -a`, `config --list`, `reflog`, `stash list`, …) and read-only shell commands (`ls`, `cat`, `echo`). All writes, executions, unclassified tools and unlisted Git subcommands are blocked — approvals cannot lift that. |
| `develop` | `workspace-write` | Daily development. Writes inside the workspace; risky operations ask for approval. |
| `maintain` | `danger-full-access` | Time-boxed maintenance. Every high-risk operation asks individually; protected paths stay blocked. |

Mode changes happen only through the `/guard` commands (the human command
plane). No tool, prompt, or model message can raise the mode. A `maintain`
grant is bounded by `maintain.maxDurationMs`, never survives a process restart,
and falls back to `develop` on expiry. Subagent children inherit their parent's
mode verbatim; an unknown parent fails closed to `inspect`.

Each mode's sandbox file policy is not just requested but **confirmed**: the
guard writes the session's sandbox mode, reads it back from the sandbox policy
service, and retries once per tool call when the confirmation fails. A session
whose sandbox cannot be confirmed refuses every mutating operation
(`sandbox-unavailable`) instead of running with weaker confinement than the mode
promises; reads, searches and delegation keep working so the session stays
inspectable and repairable. `/guard status` reports what was applied, whether it
was read back, and any failure.

## Install

Requirements: DeepSeek Harness `0.2.1-rc.3` or any `0.2.x` runtime
(`engines.dsh: ">=0.2.1-rc.3 <0.3.0"`), Node.js 24.

Download the packed bundle from the
[v0.1.2 release](https://github.com/xinian5216/dsh-boundary-guard/releases/tag/v0.1.2)
(`dsh-boundary-guard-0.1.2.tgz`; SHA-256 in the attached `SHA256SUMS`) and install
it with the official plugin manager:

```sh
# From the release tarball
dsh plugin --profile <profile> add ./dsh-boundary-guard-0.1.2.tgz

# Or from a local build
git clone https://github.com/xinian5216/dsh-boundary-guard.git
cd dsh-boundary-guard
pnpm install && pnpm run build && pnpm pack
dsh plugin --profile <profile> add ./dsh-boundary-guard-0.1.2.tgz
```

In the Web client you can also use **Plugins → Install** and point it at the
tarball. The profile must already contain the DSH base composition (every shipped
profile does); the plugin depends on it for `@deepseek-ai/cordis` and the tool
pipeline. A registry listing is future work; the release tarball is the verified
distribution channel.

Verify an installation end to end with
[`examples/verify-install.ps1`](examples/verify-install.ps1), which reproduces the
install / compose / load / remove checks in an isolated DSH home.

## Uninstall

```sh
dsh plugin --profile <profile> remove dsh-boundary-guard
```

Removal deselects the bundle and unloads its listeners. The audit log and
snapshots under `$DSH_HOME/boundary-guard` are left in place; delete them
yourself if you want them gone.

To disable without removing, use the Web client's **Plugins** page toggle for the
bundle (it edits the profile's bundle selection), or remove the entry from
`dsh.profile.bundles` in `$DSH_HOME/profiles/<profile>/package.json`.

## Commands

Commands run on the trusted human command plane; the model cannot invoke them.

| Command | Effect |
|---|---|
| `/guard status` | Current mode, sandbox file policy (applied / read back / last error), workspace, audit and snapshot status, protected-location count |
| `/guard inspect` | Enter inspect mode (sandbox `read-only`) |
| `/guard develop` | Enter develop mode (sandbox `workspace-write`) |
| `/guard maintain [minutes]` | Request maintain mode with confirmation and a bounded lifetime (default and maximum: 30 minutes) |
| `/guard audit [count]` | Sanitized summary of the last audit records (default 20) |
| `/guard snapshots` | List workspace snapshots |
| `/guard rollback <id>` | Restore one snapshot after confirmation |

## What is protected by default

- SSH keys and cloud credentials (`~/.ssh`, `~/.aws`, `~/.azure`, gcloud,
  Kubernetes, Docker, GnuPG, cargo/gem/GitHub CLI credentials)
- API key and token files by name, anywhere: `.env`, `.env.*`, `*.pem`,
  `*.key`, `*.p12`, `*.pfx`, `.netrc`, `.npmrc`, `.pypirc`,
  `.git-credentials`, `credentials`, `access_tokens`
- Other AI clients' global configuration (`~/.codex`, `~/.claude`,
  `~/.claude.json`, `~/.cursor`, `~/.opencode`, `~/.aider`)
- The DSH home, the shared agent home (`~/.agents`), and this plugin's own
  installation
- Windows credential stores (`%USERPROFILE%\AppData\*\Microsoft\Credentials`,
  `Microsoft\Protect`)

Protected locations can never be written, deleted, or administered — in any
mode, including maintain. Reading credential material requires approval in
develop and maintain modes and is denied in inspect mode.

## What requires approval

In develop and maintain modes the guard asks (through DSH's approval UI) for:
deleting files, overwriting high-value configuration (`package.json`,
lockfiles, `tsconfig`, CI workflows, Dockerfiles…), bulk operations, dependency
and system installation, Git state changes, history rewrites and remote writes,
remote sessions and uploads, destructive commands, privilege escalation, system
configuration changes, dynamic execution the guard cannot fully analyze
(including nested opaque shells such as `cmd /c` and Git invocations that set
`alias.*`, `core.pager` or `diff.external` through `-c`), sandbox-escalation
arguments, out-of-workspace writes (maintain only), Git subcommands outside the
read allowlist, and unrecognized tools.

Approvals are one-shot grants for the exact call. Rejection, cancellation, and
an unavailable approval channel all deny the operation — never a silent retry.

## Audit

Every decision is appended as JSONL under
`$DSH_HOME/boundary-guard/audit/` with: time, session id, mode, tool family,
operation, risk, decision, reason code, sanitized targets, tags, and the
approval outcome. The log never contains command text, file contents, or
secrets. `/guard audit` prints a sanitized summary.

## Development

```sh
pnpm install
pnpm run typecheck
pnpm test          # unit + integration + security regression
pnpm run build     # emits lib/ for the bundle
```

- `tests/unit` — pure functions (paths, protected set, policy engine, shell
  analysis, sanitization, mode manager).
- `tests/integration` — the real DSH pipeline: ToolRuntime, fs and pwsh tools,
  the Windows ACL sandbox provider, the approval service, and the command
  registry.
- `tests/security` — the acceptance regressions (mode isolation, protected
  paths, approval outcomes, symlink escapes, subagent inheritance, fail-closed
  configuration, audit secrecy, multi-session isolation, unload) plus the
  per-release hardening regressions: the Inspect-mode boundary against
  unclassified tools and look-alike Git commands, sandbox-sync failure and
  recovery, and the cross-platform develop experience.

## Documentation

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — guarantees and limits
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — every field and storage path
- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) — verified versions, extension
  points, platform notes
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities
- [CONTRIBUTING.md](CONTRIBUTING.md) — development rules
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE).
