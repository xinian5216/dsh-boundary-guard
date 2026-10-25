# Configuration

DSH Boundary Guard is configured through its bundle entry in
`cordis.patch.yml`. All fields are optional; the defaults below are the
supported configuration.

```yaml
- insert:
    - id: boundary-guard
      name: 'dsh-boundary-guard'
      config:
        defaultMode: develop
        unknownToolPolicy: ask
        additionalWritableRoots: []
        audit:
          enabled: true
          maxFileBytes: 8388608
          retainDays: 90
        snapshot:
          enabled: false
          maxSnapshots: 20
          maxFileBytes: 4194304
        maintain:
          maxDurationMs: 1800000
          requireConfirmation: true
```

Invalid configuration fails the plugin load with a descriptive error — it never
falls back to a permissive policy.

## Reference

| Field | Type | Default | Meaning |
|---|---|---|---|
| `defaultMode` | `inspect` \| `develop` \| `maintain` | `develop` | Mode a fresh session starts in |
| `unknownToolPolicy` | `ask` \| `deny` | `ask` | Decision for tools the classifier cannot identify |
| `additionalWritableRoots` | string[] | `[]` | Extra absolute directories writable in develop mode (`~` is expanded) |
| `audit.enabled` | boolean | `true` | Enable the local JSONL audit log |
| `audit.dir` | string | `$DSH_HOME/boundary-guard/audit` | Audit directory (absolute, `~` expanded) |
| `audit.maxFileBytes` | number | `8388608` | Rotate the audit file after this many bytes |
| `audit.retainDays` | number | `90` | Delete audit files older than this |
| `snapshot.enabled` | boolean | `false` | Capture workspace files before approved mutations |
| `snapshot.dir` | string | `$DSH_HOME/boundary-guard/snapshots` | Snapshot directory |
| `snapshot.maxSnapshots` | number | `20` | Snapshots retained per workspace |
| `snapshot.maxFileBytes` | number | `4194304` | Maximum bytes captured per file |
| `maintain.maxDurationMs` | number | `1800000` | Upper bound on any maintain grant |
| `maintain.requireConfirmation` | boolean | `true` | Require an explicit human confirmation to enter maintain |

## Storage locations

Everything the plugin writes lives under the DSH home, which the policy engine
protects from agent writes:

```
$DSH_HOME/boundary-guard/audit/audit-<date>-<n>.jsonl
$DSH_HOME/boundary-guard/snapshots/ws-<hash>/<snapshot-id>/manifest.json
$DSH_HOME/boundary-guard/snapshots/ws-<hash>/<snapshot-id>/files/...
```

`$DSH_HOME` defaults to `~/.dsh` and honors the `DSH_HOME` environment
variable. Snapshot directories are keyed by a SHA-256 hash of the workspace
root so no personal paths appear in directory names; the real root is recorded
inside each manifest.

## Changing protected locations

The protected set is discovered from the machine (home directory, DSH home,
shared agent home, the plugin's own install root) plus a built-in catalog:

- `~/.ssh`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker`,
  `~/.gnupg`, `~/.cargo/credentials`, `~/.gem/credentials`, `~/.config/gh`
- credential file names anywhere: `.env`, `.env.*`, `id_rsa`, `id_ed25519`,
  `*.pem`, `*.key`, `*.p12`, `*.pfx`, `.netrc`, `.npmrc`, `.pypirc`,
  `.git-credentials`, `credentials`, `credentials.json`, `access_tokens`
- other AI clients: `~/.codex`, `~/.claude`, `~/.claude.json`, `~/.cursor`,
  `~/.opencode`, `~/.aider`
- Windows: `%USERPROFILE%\AppData\Roaming\Microsoft\Credentials`,
  `%USERPROFILE%\AppData\Local\Microsoft\Credentials`,
  `%USERPROFILE%\AppData\Roaming\Microsoft\Protect`
- the DSH home, the shared agent home (`~/.agents`), and the plugin's own
  installation directory

There is deliberately **no** configuration option to remove entries from this
set. To protect additional locations, add them to
`additionalWritableRoots` semantics is the opposite direction; instead treat
extra sensitive trees as part of your workspace hygiene or file an issue. The
protected set can only be changed by modifying the plugin's source.

## Working with the mode from configuration

`defaultMode` decides where *new* sessions start. Existing sessions keep their
own mode (recorded in the session log). Use `/guard inspect`, `/guard develop`,
or `/guard maintain` to change the current session.
