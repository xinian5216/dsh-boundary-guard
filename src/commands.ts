/**
 * The `/guard` command family.
 *
 * Commands are the trusted human entry point: they run directly against the
 * agent without creating a model message, so the model can never invoke them
 * and never raise its own mode. Entering maintain mode additionally requires
 * an explicit confirmation through the DSH user-questions seam and fails
 * closed when no answerer is composed.
 *
 * @module dsh-boundary-guard/commands
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { CommandDefinition, CommandInvocation } from '@deepseek-ai/dsh-commands'
import type { UserQuestionService } from '@deepseek-ai/dsh-user-questions'
import type { GuardConfig } from './config.ts'
import { parseMode } from './config.ts'
import type { AuditLogger } from './audit/logger.ts'
import type { SnapshotStore } from './snapshot/store.ts'
import type { GuardModeManager } from './mode/manager.ts'
import type { ProtectedRoot } from './boundary/protected.ts'
import { currentPlatform } from './boundary/paths.ts'
import { GUARD_MODES, type GuardMode } from './types.ts'

/** Everything the command handlers need. */
export interface GuardCommandContext {
  readonly config: GuardConfig
  readonly modes: GuardModeManager
  readonly audit: AuditLogger | undefined
  readonly snapshots: SnapshotStore | undefined
  readonly protectedRoots: readonly ProtectedRoot[]
  readonly pluginVersion: string
}

/** Build the `/guard` command definition. */
export function createGuardCommand(deps: GuardCommandContext): CommandDefinition {
  const definition = {
    definitionId: 'dsh-boundary-guard' as CommandDefinition['definitionId'],
    name: 'guard',
    description: 'Inspect or change the DSH Boundary Guard mode, and view the audit summary.',
    input: { hint: 'status | inspect | develop | maintain [minutes] | audit [count] | snapshots | rollback <id>' },
    handler: async (invocation: CommandInvocation) => handleGuardCommand(invocation.agent, invocation.rawInput.trim(), invocation.signal, deps),
  }
  return definition as CommandDefinition
}

/** Dispatch one `/guard` invocation. */
export async function handleGuardCommand(
  agent: Agent,
  rawInput: string,
  signal: AbortSignal,
  deps: GuardCommandContext,
): Promise<{ kind: 'success'; text?: string } | { kind: 'error'; text: string }> {
  const [subcommand, ...rest] = rawInput.split(/\s+/).filter((part) => part !== '')
  const session = agent.session
  switch (subcommand ?? 'status') {
    case 'status':
      return { kind: 'success', text: renderStatus(session, deps) }
    case 'inspect':
    case 'develop': {
      const mode: GuardMode | undefined = subcommand === 'inspect' ? 'inspect' : subcommand === 'develop' ? 'develop' : undefined
      if (mode === undefined) return { kind: 'error', text: `Unknown mode "${subcommand}".` }
      return applyMode(session, mode, deps)
    }
    case 'maintain':
      return applyMaintain(session, rest[0], agent, signal, deps)
    case 'audit':
      return { kind: 'success', text: await renderAudit(deps, rest[0]) }
    case 'snapshots':
      return { kind: 'success', text: await renderSnapshots(session, deps) }
    case 'rollback':
      return rollback(session, rest[0], agent, signal, deps)
    case '':
      return { kind: 'error', text: 'Usage: /guard status | inspect | develop | maintain [minutes] | audit [count] | snapshots | rollback <id>' }
    default:
      return { kind: 'error', text: `Unknown /guard subcommand "${subcommand}". Known: ${[...GUARD_MODES, 'status', 'audit', 'snapshots', 'rollback'].join(', ')}.` }
  }
}

/** Apply a non-maintain mode directly. */
function applyMode(
  session: Agent['session'],
  mode: GuardMode,
  deps: GuardCommandContext,
): { kind: 'success'; text: string } {
  const state = deps.modes.setMode(session, mode)
  const sandbox = mode === 'inspect' ? 'read-only' : mode === 'develop' ? 'workspace-write' : 'danger-full-access'
  return {
    kind: 'success',
    text: `Boundary guard mode: ${mode}. Sandbox file policy for this session: ${sandbox}.` +
      (mode === 'develop' ? ' High-risk operations will ask for approval.' : '') +
      (mode === 'inspect' ? ' All writes and executions are blocked.' : '') +
      ` (recorded ${state.source})`,
  }
}

/** Enter maintain mode with confirmation and a bounded lifetime. */
async function applyMaintain(
  session: Agent['session'],
  minutesRaw: string | undefined,
  agent: Agent,
  signal: AbortSignal,
  deps: GuardCommandContext,
): Promise<{ kind: 'success'; text: string } | { kind: 'error'; text: string }> {
  let minutes = deps.config.maintain.maxDurationMs / 60000
  if (minutesRaw !== undefined) {
    const parsed = Number(minutesRaw)
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return { kind: 'error', text: `Invalid duration "${minutesRaw}". Pass a positive number of minutes.` }
    }
    minutes = Math.min(parsed, deps.config.maintain.maxDurationMs / 60000)
  }
  if (deps.config.maintain.requireConfirmation) {
    const confirmed = await confirmMaintain(agent, minutes, signal, deps)
    if (!confirmed) {
      return { kind: 'error', text: 'Maintain mode was not confirmed; the mode is unchanged.' }
    }
  }
  const state = deps.modes.setMode(session, 'maintain', { maintainDurationMs: minutes * 60000 })
  const expires = new Date(state.maintainExpiresAt ?? Date.now())
  return {
    kind: 'success',
    text: `Boundary guard mode: maintain for ${minutes} minute(s), expiring at ${expires.toLocaleTimeString()}. ` +
      'The session sandbox is now danger-full-access; every high-risk operation still requires individual approval, ' +
      'and protected paths (credentials, other AI client configs, DSH home) remain permanently blocked. ' +
      'The mode falls back to develop automatically on expiry or session end.',
  }
}

/**
 * Ask the human to confirm entering maintain mode through the DSH
 * user-questions seam. Any failure — no answerer, abort, timeout — returns
 * false (fail closed).
 */
async function confirmMaintain(agent: Agent, minutes: number, signal: AbortSignal, deps: GuardCommandContext): Promise<boolean> {
  const ctx = (agent as unknown as { ctx?: Context }).ctx
  const questions = ctx?.get('userQuestions') as UserQuestionService | undefined
  if (questions === undefined) return false
  try {
    const answer = await questions.ask({
      agent,
      signal,
      questions: [
        {
          id: 'boundary-guard-maintain',
          header: 'Confirm',
          question: `Enable Boundary Guard maintain mode for ${minutes} minute(s)? This widens the session sandbox to danger-full-access. High-risk operations will still require individual approval, and protected paths stay blocked.`,
          options: [
            { label: 'Enable maintain mode', description: `Approve danger-full-access for ${minutes} minute(s)` },
            { label: 'Cancel', description: 'Keep the current mode' },
          ],
        },
      ],
    })
    const first = answer.answers[0]
    return first?.selected.includes('Enable maintain mode') === true
  } catch {
    return false
  }
}

/** Render the status summary. */
function renderStatus(session: Agent['session'], deps: GuardCommandContext): string {
  const effective = deps.modes.effective(session)
  const state = effective.state
  const lines = [
    `DSH Boundary Guard v${deps.pluginVersion}`,
    `Mode: ${effective.mode}${effective.expired ? ' (maintain grant expired)' : ''} (${state.source})`,
  ]
  if (state.mode === 'maintain' && state.maintainExpiresAt !== null) {
    lines.push(`Maintain grant expires: ${new Date(state.maintainExpiresAt).toLocaleString()}`)
  }
  // Report the real sandbox state: what the mode requires, what was actually
  // applied, whether that write was read back, what the policy reports now,
  // and any synchronization failure.
  const sandbox = deps.modes.sandboxStatusOf(session)
  const details: string[] = []
  if (sandbox.applied === undefined) {
    details.push('not confirmed applied')
  } else if (sandbox.applied !== sandbox.desired) {
    details.push(`last applied: ${sandbox.applied}`)
  }
  if (sandbox.applied !== undefined && !sandbox.verified) {
    details.push('written but not read back')
  }
  if (sandbox.observed !== undefined && sandbox.observed !== (sandbox.applied ?? sandbox.desired)) {
    details.push(`sandbox policy reports ${sandbox.observed}`)
  }
  if (sandbox.lastError !== undefined) details.push(sandbox.lastError)
  lines.push(`Sandbox file policy: ${sandbox.desired} (${details.length === 0 ? 'applied and verified' : details.join('; ')})`)
  lines.push(`Workspace: ${session.header.cwd ?? '(none recorded)'}`)
  lines.push(`Audit: ${deps.audit?.available === true ? 'enabled' : 'unavailable'}`)
  lines.push(`Snapshots: ${deps.snapshots === undefined ? 'disabled' : 'enabled'}`)
  lines.push(`Protected locations: ${deps.protectedRoots.length} (credentials, other AI client configs, DSH home, plugin installation)`)
  lines.push(`Platform: ${currentPlatform}`)
  return lines.join('\n')
}

/** Render a sanitized audit summary. */
async function renderAudit(deps: GuardCommandContext, countRaw: string | undefined): Promise<string> {
  if (deps.audit === undefined || !deps.audit.available) return 'Audit logging is not available in this session.'
  const count = countRaw === undefined ? 20 : Math.min(Number(countRaw) || 20, 200)
  const files = deps.audit.files()
  const records: string[] = []
  for (const file of [...files].reverse()) {
    try {
      const { readFile } = await import('node:fs/promises')
      const text = await readFile(file, 'utf8')
      const lines = text.split('\n').filter((line) => line !== '')
      for (const line of lines.reverse()) {
        records.push(line)
        if (records.length >= count) break
      }
    } catch {
      // An unreadable audit file is skipped; the summary is best-effort.
    }
    if (records.length >= count) break
  }
  if (records.length === 0) return 'No audit records yet.'
  const header = `Last ${records.length} audit record(s) (sanitized):`
  const rows = records.map((line) => {
    try {
      const record = JSON.parse(line) as Record<string, unknown>
      const time = new Date(Number(record.time)).toLocaleString()
      const targets = Array.isArray(record.targets) ? (record.targets as string[]).join(', ') : ''
      const approval = typeof record.approval === 'string' ? ` approval=${record.approval}` : ''
      return `${time} [${String(record.mode)}] ${String(record.decision).toUpperCase()} ${String(record.tool)} (${String(record.reasonCode)})${targets === '' ? '' : ` → ${targets}`}${approval}`
    } catch {
      return '(unreadable record)'
    }
  })
  return [header, ...rows].join('\n')
}

/** Render the snapshot list. */
async function renderSnapshots(session: Agent['session'], deps: GuardCommandContext): Promise<string> {
  if (deps.snapshots === undefined) return 'Snapshots are disabled in this configuration.'
  const root = session.header.cwd
  if (root === undefined) return 'This session has no recorded workspace.'
  const manifests = await deps.snapshots.list(root)
  if (manifests.length === 0) return 'No snapshots for this workspace.'
  const lines = [`${manifests.length} snapshot(s) for this workspace (newest first):`]
  for (const manifest of manifests.slice(0, 20)) {
    lines.push(`${manifest.id} — ${new Date(manifest.time).toLocaleString()} — ${manifest.trigger} — ${manifest.files.length} file(s)`)
  }
  lines.push('Restore with /guard rollback <id>. Snapshots cover only files the guard captured; they are not a universal undo.')
  return lines.join('\n')
}

/** Restore one snapshot after confirmation. */
async function rollback(
  session: Agent['session'],
  id: string | undefined,
  agent: Agent,
  signal: AbortSignal,
  deps: GuardCommandContext,
): Promise<{ kind: 'success'; text: string } | { kind: 'error'; text: string }> {
  if (deps.snapshots === undefined) return { kind: 'error', text: 'Snapshots are disabled in this configuration.' }
  const root = session.header.cwd
  if (root === undefined || id === undefined) return { kind: 'error', text: 'Usage: /guard rollback <snapshot-id>' }
  const manifests = await deps.snapshots.list(root)
  const manifest = manifests.find((candidate) => candidate.id === id)
  if (manifest === undefined) return { kind: 'error', text: `No snapshot with id "${id}" for this workspace.` }
  const confirmed = await confirmRollback(agent, manifest, signal, deps)
  if (!confirmed) return { kind: 'error', text: 'Rollback was not confirmed; nothing was restored.' }
  const result = await deps.snapshots.restore(manifest)
  return {
    kind: 'success',
    text: `Restored ${result.restored} file(s) and removed ${result.deleted} created file(s) from snapshot ${manifest.id}. ` +
      'Files the snapshot did not capture (databases, remote systems, out-of-band process effects) are not restored.',
  }
}

async function confirmRollback(agent: Agent, manifest: { id: string; files: readonly { path: string }[] }, signal: AbortSignal, deps: GuardCommandContext): Promise<boolean> {
  const ctx = (agent as unknown as { ctx?: Context }).ctx
  const questions = ctx?.get('userQuestions') as UserQuestionService | undefined
  if (questions === undefined) return false
  const fileList = manifest.files.slice(0, 10).map((file) => file.path).join(', ')
  try {
    const answer = await questions.ask({
      agent,
      signal,
      questions: [
        {
          id: 'boundary-guard-rollback',
          header: 'Confirm',
          question: `Restore snapshot ${manifest.id}? This overwrites current contents with the captured versions of: ${fileList}${manifest.files.length > 10 ? ` (and ${manifest.files.length - 10} more)` : ''}.`,
          options: [
            { label: 'Restore snapshot', description: 'Overwrite current files with the snapshot' },
            { label: 'Cancel', description: 'Keep current files' },
          ],
        },
      ],
    })
    return answer.answers[0]?.selected.includes('Restore snapshot') === true
  } catch {
    return false
  }
}

/** Parse a mode argument from an untrusted string. */
export function modeFromString(value: string): GuardMode | undefined {
  return parseMode(value)
}
