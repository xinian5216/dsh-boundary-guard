# Security Policy

## Supported versions

Only the latest released version of DSH Boundary Guard receives security
fixes. The plugin is a security control itself, so updates should be applied
promptly.

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub Security
Advisories on the repository ("Report a vulnerability"), or by opening a
private disclosure to the maintainers. Do not file public issues for security
problems.

Include:

- the affected version and the DSH version,
- a description of the bypass or weakness and its impact,
- reproduction steps, ideally against a disposable workspace,
- whether the issue involves protected-path discovery, shell analysis, or the
  policy engine.

You can expect an acknowledgement within 7 days and a status update at least
every 14 days until resolution.

## Scope

In scope:

- the policy engine and its priority order,
- protected-path discovery and matching,
- path boundary checks (separators, streams, links, races),
- shell and tool classification,
- mode management, inheritance, and expiry,
- audit sanitization and storage,
- the approval adapter and its failure modes.

Out of scope:

- vulnerabilities in DeepSeek Harness itself (report those upstream),
- the security of your machine, credentials, or workspace contents,
- denial of service through configuration choices you make.

## Hardening notes for operators

- The audit log and snapshots live under your DSH home (`$DSH_HOME`). Protect
  that directory with OS permissions appropriate to your threat model; the
  plugin blocks agent writes to it through policy, which is not an OS-level
  guarantee.
- Review `docs/THREAT_MODEL.md` before relying on the guard for anything the
  threat model lists as not guaranteed.
- Keep `maintain` mode time-boxed and prefer `/guard develop` for daily work.
