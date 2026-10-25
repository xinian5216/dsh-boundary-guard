# Verify a local build of the boundary guard in an isolated DSH home.
#
# This reproduces the installation checks without touching your real profile:
# it creates a throwaway DSH home, builds the bundle, installs it into a fresh
# headless profile through the official plugin manager, verifies composition,
# and removes it again.
#
# Usage (from the repository root, adjust the dsh CLI path to your install):
#   pwsh ./examples/verify-install.ps1

param(
  [string]$DshCmd = '',
  [string]$VerifyHome = ''
)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
if ($VerifyHome -eq '') { $VerifyHome = Join-Path $repo '.dsh-verify' }

# Locate the dsh CLI when not supplied explicitly.
if ($DshCmd -eq '') {
  $candidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd'),
    (Join-Path ${env:ProgramFiles} 'DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd'),
    (Join-Path ${env:ProgramFiles(x86)} 'DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd'),
    'dsh'
  )
  foreach ($candidate in $candidates) {
    if ($candidate -eq 'dsh' -or (Test-Path $candidate)) { $DshCmd = $candidate; break }
  }
}
if ($DshCmd -eq '') { throw 'Could not locate the dsh CLI; pass -DshCmd <path to dsh.cmd>' }
Write-Host "==> Using dsh CLI: $DshCmd"

Write-Host "==> Building the bundle"
pnpm --dir $repo install
pnpm --dir $repo run build

Write-Host "==> Creating an isolated DSH home at $VerifyHome"
if (Test-Path $VerifyHome) { Remove-Item $VerifyHome -Recurse -Force }
New-Item -ItemType Directory -Force -Path $VerifyHome | Out-Null
$env:DSH_HOME = $VerifyHome

Write-Host "==> Creating the guardverify profile from the headless template"
& $DshCmd --profile guardverify --from-default-profile headless --dump-config | Out-Null

Write-Host "==> Installing the bundle through the official plugin manager"
& $DshCmd plugin --profile guardverify add $repo

Write-Host "==> Verifying composition"
$config = (& $DshCmd --profile guardverify --dump-config) | Out-String
if ($config -notmatch 'boundary-guard') { throw 'boundary-guard entry missing from the composed profile' }
Write-Host 'boundary-guard entry present in the composed profile'

Write-Host "==> Verifying the plugin loads (boot stops at the model boundary)"
& $DshCmd --profile guardverify 'say hello'
if ($LASTEXITCODE -ne 1) { throw 'expected the boot to fail on the missing credential' }
if (-not (Test-Path (Join-Path $VerifyHome 'boundary-guard'))) { throw 'plugin storage was not created at load' }
Write-Host 'plugin loaded and created its storage'

Write-Host "==> Removing the bundle"
& $DshCmd plugin --profile guardverify remove dsh-boundary-guard

Write-Host '==> Verification complete'
