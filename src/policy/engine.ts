/**
 * The policy engine: a pure decision function over a classified operation.
 *
 * Priority order (first match wins):
 *   1. Non-overridable safety constraints  → DENY
 *   2. Explicit denial rules               → DENY
 *   3. Approval requirements               → ASK
 *   4. Allow rules                         → ALLOW
 *   5. Default denial                      → DENY
 *
 * The engine never performs I/O and never throws: an unexpected input shape
 * fails closed to a denial with reason `internal-error`.
 *
 * @module dsh-boundary-guard/policy/engine
 */
import { isHighValueConfig, matchProtectedPath, type ProtectedRoot } from '../boundary/protected.ts'
import { escapesRoot, isInside, type Platform } from '../boundary/paths.ts'
import { PRIVILEGED_FIR_PARTY_TOOLS } from '../tools/classify.ts'
import type { ClassifiedOperation, Decision, GuardMode, PolicyInput, PolicyResult, RiskLevel } from '../types.ts'

/** One protected-path hit with the fact that matched. */
interface ProtectedHit {
  readonly label: string
  readonly kind: string
}

function deny(reasonCode: PolicyResult['reasonCode'], reason: string, risk: RiskLevel = 'high'): PolicyResult {
  return { decision: 'deny', reasonCode, reason, risk, overridable: false }
}

function ask(reasonCode: PolicyResult['reasonCode'], reason: string, risk: RiskLevel = 'medium'): PolicyResult {
  return { decision: 'ask', reasonCode, reason, risk, overridable: true }
}

function allow(reasonCode: PolicyResult['reasonCode'], reason: string, risk: RiskLevel = 'none'): PolicyResult {
  return { decision: 'allow', reasonCode, reason, risk, overridable: true }
}

/** Whether the operation mutates the filesystem or system state. */
function isMutating(operation: ClassifiedOperation): boolean {
  return operation.operation === 'write' || operation.operation === 'delete' || operation.operation === 'execute' || operation.operation === 'admin'
}

/** Whether the operation only reads. */
function isReading(operation: ClassifiedOperation): boolean {
  return operation.operation === 'read' || operation.operation === 'search' || operation.operation === 'network'
}

/**
 * Evaluate one classified operation against the current policy.
 */
export function evaluatePolicy(input: PolicyInput, protectedRoots: readonly ProtectedRoot[], platform: Platform): PolicyResult {
  try {
    return evaluate(input, protectedRoots, platform)
  } catch (error) {
    // Fail closed: an engine fault must never open the gate.
    return deny('internal-error', `Boundary guard policy engine failed closed: ${(error as Error).message}`, 'critical')
  }
}

function evaluate(input: PolicyInput, protectedRoots: readonly ProtectedRoot[], platform: Platform): PolicyResult {
  const { mode, operation } = input
  const workspaceRoot = input.workspaceRoot
  const tags = new Set(operation.tags)

  // ---- Protected-path hits ----------------------------------------------
  const writeHits: ProtectedHit[] = []
  const readHits: ProtectedHit[] = []
  for (const target of operation.writeTargets) {
    const match = matchProtectedPath(target.absolute, protectedRoots, platform)
    if (match !== undefined) writeHits.push({ label: match.label, kind: match.kind })
  }
  for (const target of operation.readTargets) {
    const match = matchProtectedPath(target.absolute, protectedRoots, platform)
    if (match !== undefined) readHits.push({ label: match.label, kind: match.kind })
  }

  // ---- Out-of-workspace write targets ------------------------------------
  // DSH's own privileged management surfaces (plugin installation) write into
  // the DSH home by design; DSH gates those tools itself, so their storage
  // writes are not treated as workspace escapes here.
  const privileged = PRIVILEGED_FIR_PARTY_TOOLS.has(operation.toolName)
  const policyWriteTargets = privileged
    ? operation.writeTargets.filter((target) => {
      const match = matchProtectedPath(target.absolute, protectedRoots, platform)
      return match === undefined || match.kind !== 'dsh-home'
    })
    : operation.writeTargets
  const writableRoots = workspaceRoot === undefined ? [] : [workspaceRoot, ...input.additionalWritableRoots]
  // With no authorized workspace at all, every write target counts as outside.
  const outsideWriteTargets = writableRoots.length === 0
    ? policyWriteTargets
    : policyWriteTargets.filter((target) => writableRoots.every((root) => escapesRoot(root, target, platform)))
  const mutating = isMutating(operation)

  // ======================================================================
  // 1. Non-overridable safety constraints
  // ======================================================================

  // 1a. Protected paths can never be written, deleted, or administered — in
  //     any mode, including maintain. This is the permanent floor. DSH's own
  //     privileged management surfaces (plugin installation, session queries)
  //     are exempt from the DSH-home rule because DSH gates them separately.
  if (mutating && writeHits.length > 0) {
    const first = writeHits[0]
    const privileged = PRIVILEGED_FIR_PARTY_TOOLS.has(operation.toolName)
    const dshHomeOnly = writeHits.every((hit) => hit.kind === 'dsh-home')
    if (first !== undefined && !(privileged && dshHomeOnly)) {
      return deny(
        first.kind === 'dsh-home' ? 'dsh-home-write' : 'protected-path-write',
        `Boundary guard: ${operation.toolName} would modify ${first.label}, which is permanently protected. Modify it through a dedicated human administration step outside the agent.`,
        'critical',
      )
    }
  }

  // 1b. Inspect mode is strictly read-only.
  if (mode === 'inspect' && mutating) {
    const reason = operation.operation === 'execute'
      ? `Boundary guard: inspect mode forbids executing commands or code (${operation.toolName}). Switch with /guard develop for normal development.`
      : `Boundary guard: inspect mode forbids modifying files (${operation.toolName}). Switch with /guard develop for normal development.`
    return deny('inspect-mode-write', reason, 'high')
  }

  // 1c. Inspect mode also forbids reading credential material.
  if (mode === 'inspect' && readHits.length > 0) {
    const firstRead = readHits[0]
    return deny(
      'protected-path-read',
      `Boundary guard: inspect mode forbids reading ${firstRead?.label ?? 'protected material'}. Switch with /guard develop if this read is genuinely required.`,
      'high',
    )
  }

  // 1d. Reading credential material always needs a decision outside inspect.
  if (isReading(operation) && readHits.length > 0) {
    return ask(
      'credential-material',
      `Boundary guard: ${operation.toolName} would read ${readHits[0]?.label ?? 'protected material'}. Approve only if the content is genuinely required.`,
      'high',
    )
  }

  // ======================================================================
  // 2. Explicit denial rules
  // ======================================================================

  // 2a. Unknown tools.
  if (operation.toolFamily === 'unknown' || operation.operation === 'unknown') {
    if (input.unknownToolPolicy === 'deny') {
      return deny('unknown-tool', `Boundary guard: tool "${operation.toolName}" is not recognized and unknownToolPolicy is "deny".`, 'high')
    }
    return ask('unknown-tool-approval', `Boundary guard: tool "${operation.toolName}" is not recognized by the guard. Approve to run it once.`, 'high')
  }

  // 2b. Sandbox escalation attempts are policy decisions, not tool arguments.
  if (tags.has('sandbox-escalation')) {
    if (mode === 'inspect') {
      return deny('sandbox-escalation', 'Boundary guard: sandbox escalation is not available in inspect mode.', 'high')
    }
    return ask('sandbox-escalation', `Boundary guard: ${operation.toolName} requests a wider sandbox mode than the session policy grants.`, 'high')
  }

  // 2c. Out-of-workspace writes in develop mode are denied by default.
  if (mutating && outsideWriteTargets.length > 0 && mode === 'develop') {
    return deny(
      'outside-workspace-write',
      `Boundary guard: ${operation.toolName} targets a path outside the authorized workspace. Use /guard maintain for a precisely approved out-of-workspace operation.`,
      'high',
    )
  }

  // 2d. Working-directory changes that leave the workspace.
  if (operation.toolName === 'working_directory' && outsideWriteTargets.length > 0) {
    return deny(
      'working-directory-escape',
      'Boundary guard: the session working directory cannot move outside the authorized workspace.',
      'medium',
    )
  }

  // ======================================================================
  // 3. Approval requirements
  // ======================================================================

  // 3a. Deletes always need approval outside inspect mode.
  if (operation.operation === 'delete') {
    return ask('delete-requires-approval', `Boundary guard: ${operation.toolName} would delete files or directories.`, 'high')
  }

  // 3b. Out-of-workspace writes in maintain mode: precise per-operation grant.
  if (mutating && outsideWriteTargets.length > 0) {
    return ask(
      'outside-workspace-approval',
      `Boundary guard: ${operation.toolName} targets a path outside the authorized workspace. Approve this exact operation only.`,
      'high',
    )
  }

  // 3c. High-value configuration overwrite (any mutating operation, including
  //     shell commands that rewrite a config file).
  if (mutating && operation.writeTargets.some((target) => target.exists && isHighValueConfig(target.absolute))) {
    return ask('high-value-config-overwrite', `Boundary guard: ${operation.toolName} would overwrite a high-value configuration file.`, 'medium')
  }

  // 3d. Git operations.
  if (tags.has('git-global-config')) {
    return deny('protected-path-write', 'Boundary guard: global Git configuration is protected.', 'high')
  }
  if (tags.has('git-history-rewrite')) {
    return ask('git-history-rewrite', `Boundary guard: ${operation.toolName} rewrites Git history.`, 'high')
  }
  if (tags.has('git-remote-write')) {
    return ask('git-remote-write', `Boundary guard: ${operation.toolName} writes to a Git remote.`, 'high')
  }
  if (tags.has('git-state-change')) {
    return ask('git-state-change', `Boundary guard: ${operation.toolName} changes important Git state.`, 'medium')
  }

  // 3e. Dependency and system installation.
  if (tags.has('system-install')) {
    return ask('dependency-install', `Boundary guard: ${operation.toolName} installs system software.`, 'high')
  }
  if (tags.has('dependency-install')) {
    return ask('dependency-install', `Boundary guard: ${operation.toolName} installs or updates dependencies.`, 'medium')
  }
  if (tags.has('package-publish')) {
    return ask('remote-operation', `Boundary guard: ${operation.toolName} publishes to a remote registry.`, 'high')
  }

  // 3f. Remote and network side effects.
  if (tags.has('remote-session')) {
    return ask('remote-operation', `Boundary guard: ${operation.toolName} opens a remote session.`, 'high')
  }
  if (tags.has('network-upload')) {
    return ask('remote-operation', `Boundary guard: ${operation.toolName} uploads data to a remote host.`, 'high')
  }

  // 3g. Destructive commands.
  if (tags.has('mass-destructive')) {
    return ask('destructive-command', `Boundary guard: ${operation.toolName} is a mass-destructive command.`, 'critical')
  }
  if (tags.has('destructive') || tags.has('file-delete')) {
    return ask('destructive-command', `Boundary guard: ${operation.toolName} performs destructive file operations.`, 'high')
  }

  // 3h. Privilege and system configuration.
  if (tags.has('privilege-escalation')) {
    return ask('privilege-escalation', `Boundary guard: ${operation.toolName} requests elevated privileges.`, 'critical')
  }
  if (tags.has('system-config')) {
    return ask('system-config', `Boundary guard: ${operation.toolName} changes system configuration.`, 'high')
  }
  if (tags.has('process-control')) {
    return ask('process-control', `Boundary guard: ${operation.toolName} controls system processes.`, 'medium')
  }

  // 3i. Dynamic execution that cannot be fully analyzed.
  if (tags.has('dynamic-execution')) {
    return ask('dynamic-execution', `Boundary guard: ${operation.toolName} executes code the guard cannot fully analyze.`, 'high')
  }

  // 3j. Bulk operations.
  if (tags.has('bulk-operation')) {
    return ask('bulk-operation', `Boundary guard: ${operation.toolName} appears to perform a bulk operation over many files.`, 'medium')
  }

  // 3k. Working-directory changes alter how relative paths resolve.
  if (operation.toolName === 'working_directory') {
    return ask('working-directory-escape', 'Boundary guard: changing the session working directory affects how relative paths resolve.', 'low')
  }

  // 3l. Unrecognized commands inside an otherwise safe shell segment.
  if (tags.has('unknown-command')) {
    return ask('unknown-tool-approval', `Boundary guard: ${operation.toolName} runs a command the guard does not recognize.`, 'medium')
  }

  // ======================================================================
  // 4. Allow rules
  // ======================================================================
  if (isReading(operation)) {
    return allow('read-allowed', `Boundary guard: read-only operation ${operation.toolName} is permitted in ${mode} mode.`)
  }
  if (operation.operation === 'write' && workspaceRoot !== undefined && outsideWriteTargets.length === 0) {
    return allow('workspace-write-allowed', `Boundary guard: ${operation.toolName} writes inside the authorized workspace.`, 'low')
  }
  if (operation.toolFamily === 'shell' && !hasRiskyTag(tags)) {
    return allow('safe-command', `Boundary guard: ${operation.toolName} runs a command with no recognized risk pattern.`, 'low')
  }
  if (operation.operation === 'delegate') {
    return allow('first-party-tool', `Boundary guard: ${operation.toolName} delegates work; the child inherits this session's restrictions.`, 'low')
  }
  if (operation.toolFamily === 'meta' || operation.toolFamily === 'jobs' || operation.toolFamily === 'web') {
    return allow('first-party-tool', `Boundary guard: ${operation.toolName} is a first-party tool without filesystem side effects.`)
  }
  if (operation.operation === 'admin' && workspaceRoot !== undefined && outsideWriteTargets.length === 0) {
    return allow('workspace-write-allowed', `Boundary guard: ${operation.toolName} is permitted in ${mode} mode.`, 'low')
  }

  // ======================================================================
  // 5. Default denial
  // ======================================================================
  return deny('default-deny', `Boundary guard: ${operation.toolName} (${operation.operation}) matches no allow rule in ${mode} mode.`, 'medium')
}

/** Tags that keep a shell command out of the safe-command allow rule. */
const BENIGN_SHELL_TAGS = new Set(['git-read', 'git-workspace-write', 'network-read', 'background', 'file-write'])

function hasRiskyTag(tags: ReadonlySet<string>): boolean {
  for (const tag of tags) {
    if (!BENIGN_SHELL_TAGS.has(tag)) return true
  }
  return false
}

/** Re-export for tests and the approval adapter. */
export { isInside, deny, ask, allow }
export type { Decision, GuardMode }
