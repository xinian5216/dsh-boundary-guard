# Contributing

Thanks for helping improve DSH Boundary Guard. This project is a security
control, so changes are reviewed with that lens.

## Development setup

```sh
pnpm install
pnpm run typecheck
pnpm test
pnpm run build
```

The test suite runs on Node.js 24 with native TypeScript type stripping; no
build step is required before testing.

## Project layout

| Path | Role |
|---|---|
| `src/index.ts` | Plugin entry: wiring, lifecycle, disposal |
| `src/config.ts` | Configuration schema, defaults, validation |
| `src/types.ts` | Shared vocabulary (modes, decisions, reason codes) |
| `src/mode/` | Mode manager, expiry, inheritance, durable state |
| `src/policy/engine.ts` | The pure decision function |
| `src/tools/` | Tool classification and shell command analysis |
| `src/boundary/` | Path normalization and protected-path discovery |
| `src/approval/adapter.ts` | Approval request construction and outcome mapping |
| `src/audit/` | Sanitization and the local JSONL audit log |
| `src/snapshot/store.ts` | Optional workspace snapshots |
| `src/commands.ts` | The `/guard` command family |
| `tests/unit/` | Pure-function tests |
| `tests/integration/` | Real DSH pipeline tests |
| `tests/security/` | Security regression tests |

## Rules for changes

1. **Never weaken the default.** New behavior must fail closed. If you add a
   rule, place it in the correct priority tier and give it a stable reason
   code.
2. **No monkey patching.** Use only documented DSH extension points
   (`tools/pre-execute`, `ctx.tools.guard()`, `ctx.approval`,
   `ctx.commands.register()`, the sandbox policy service, session projections,
   session plugin records).
3. **Tests are mandatory.** Every behavioral change needs a test; every
   security-relevant change needs a security regression test. Tests that
   create or destroy files must use an isolated temporary workspace.
4. **Synthetic fixtures only.** Never commit real credentials, tokens,
   personal paths, or configuration copied from a real machine.
5. **Document limits honestly.** If a rule is heuristic, say so in
   `docs/THREAT_MODEL.md` rather than implying a guarantee.
6. **Keep dependencies minimal and pinned.** Runtime dependencies are limited
   to the DSH packages the plugin genuinely calls plus `schemastery` and
   `zod`; everything else is a dev dependency.

## Commit and review expectations

- Commits should be focused and explain the security-relevant behavior.
- CI runs type checking, the full test suite, the build, and a secret scan.
- A change that alters the policy priority order or the protected-path set
  requires an explicit note in the pull request describing the new boundary.

## Release process

1. Update `CHANGELOG.md`.
2. Run `pnpm run verify` (typecheck, tests, build).
3. Tag `vX.Y.Z` and publish the release with the packed bundle and its
   SHA-256 checksum.
