# Examples

- [`guard-inspect.yml`](guard-inspect.yml) — read-only default for analysis and
  CI-style profiles.
- [`guard-develop.yml`](guard-develop.yml) — the daily development defaults.
- [`guard-ci.yml`](guard-ci.yml) — a strict unattended stance.
- [`verify-install.ps1`](verify-install.ps1) — reproduces the real-install
  verification in an isolated DSH home (Windows, PowerShell).

All values in these examples are synthetic defaults. Copy the `insert` block
into `$DSH_HOME/profiles/<name>/cordis.patch.yml`, or pass the file with
`dsh --profile <name> --patch ./guard-develop.yml`.
