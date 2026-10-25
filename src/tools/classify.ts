/**
 * Tool classification: map a registry tool name and its arguments to a
 * normalized {@link ClassifiedOperation} the policy engine can reason about.
 *
 * Unknown tools are never guessed at: they become `unknown` operations and the
 * policy engine decides conservatively.
 *
 * @module dsh-boundary-guard/tools/classify
 */
import type { ProtectedRoot } from '../boundary/protected.ts'
import type { Platform } from '../boundary/paths.ts'
import type { ClassifiedOperation, OperationClass, PathFact, RiskLevel, ToolFamily } from '../types.ts'
import { analyzeShellCommand, type ShellRiskTag } from './shell.ts'

/** Everything the classifier needs from its environment. */
export interface ClassifierContext {
  readonly platform: Platform
  readonly protectedRoots: readonly ProtectedRoot[]
  /** Resolve one path argument to a normalized fact. */
  readonly resolveFact: (input: string) => Promise<PathFact>
}

/** Specific risk tags the classifier can attach. */
export type ClassifierTag =
  | 'sandbox-escalation'
  | 'background'
  | 'file-delete'
  | 'file-write'
  | 'git-read'
  | 'git-workspace-write'
  | 'git-state-change'
  | 'git-history-rewrite'
  | 'git-remote-write'
  | 'git-global-config'
  | 'dependency-install'
  | 'system-install'
  | 'package-publish'
  | 'destructive'
  | 'mass-destructive'
  | 'network-read'
  | 'network-upload'
  | 'remote-session'
  | 'privilege-escalation'
  | 'system-config'
  | 'process-control'
  | 'dynamic-execution'
  | 'bulk-operation'
  | 'unknown-command'
  | 'protected-mention'

/** Map shell risk tags onto classifier tags. */
function fromShellTags(tags: readonly ShellRiskTag[]): ClassifierTag[] {
  const out = new Set<ClassifierTag>()
  for (const tag of tags) {
    switch (tag) {
      case 'git-read': out.add('git-read'); break
      case 'git-network-read': out.add('git-read'); break
      case 'git-workspace-write': out.add('git-workspace-write'); break
      case 'git-state-change': out.add('git-state-change'); break
      case 'git-history-rewrite': out.add('git-history-rewrite'); break
      case 'git-remote-write': out.add('git-remote-write'); break
      case 'git-global-config': out.add('git-global-config'); break
      case 'dependency-install': out.add('dependency-install'); break
      case 'system-install': out.add('system-install'); break
      case 'package-publish': out.add('package-publish'); break
      case 'destructive': out.add('destructive'); break
      case 'mass-destructive': out.add('mass-destructive'); break
      case 'file-write': out.add('file-write'); break
      case 'file-delete': out.add('file-delete'); break
      case 'network-read': out.add('network-read'); break
      case 'network-upload': out.add('network-upload'); break
      case 'remote-session': out.add('remote-session'); break
      case 'privilege-escalation': out.add('privilege-escalation'); break
      case 'system-config': out.add('system-config'); break
      case 'process-control': out.add('process-control'); break
      case 'dynamic-execution': out.add('dynamic-execution'); break
      case 'bulk-operation': out.add('bulk-operation'); break
      case 'sandbox-escalation': out.add('sandbox-escalation'); break
      case 'unknown-command': out.add('unknown-command'); break
    }
  }
  return [...out]
}

/** Known first-party read-only tool descriptors. */
const READ_TOOLS: Record<string, ToolDescriptor> = {
  read: { family: 'fs-read', operation: 'read', risk: 'none', pathArgs: ['file_path', 'path'] },
  read_image: { family: 'fs-read', operation: 'read', risk: 'none', pathArgs: ['file_path', 'path'] },
  glob: { family: 'search', operation: 'search', risk: 'none', pathArgs: ['path', 'dir'] },
  grep: { family: 'search', operation: 'search', risk: 'none', pathArgs: ['path', 'dir'] },
  web_fetch: { family: 'web', operation: 'network', risk: 'low', pathArgs: [], tags: ['network-read'] },
  web_search: { family: 'web', operation: 'network', risk: 'low', pathArgs: [], tags: ['network-read'] },
}

/** Known first-party write tool descriptors. */
const WRITE_TOOLS: Record<string, ToolDescriptor> = {
  write: { family: 'fs-write', operation: 'write', risk: 'medium', pathArgs: ['file_path', 'path'] },
  edit: { family: 'fs-write', operation: 'write', risk: 'medium', pathArgs: ['file_path', 'path'] },
}

/** First-party tools without filesystem side effects. */
const META_TOOLS = new Set([
  'todo_write',
  'present',
  'ask_user_question',
  'load_workspace_dependencies',
  'skill',
  'job_list',
  'job_output',
  'list_subagent_models',
  'get_goal',
  'session_search',
  'session_event_read',
  'session_event_trace',
  'session_trace',
  'schedule_list',
  'team_task_list',
  'team_task_get',
])

/** Tools DSH itself gates that may touch the DSH home (management surfaces). */
export const PRIVILEGED_FIR_PARTY_TOOLS = new Set([
  'plugin_manager',
  'session_search',
  'session_event_read',
  'session_event_trace',
  'session_trace',
])

interface ToolDescriptor {
  readonly family: ToolFamily
  readonly operation: OperationClass
  readonly risk: RiskLevel
  /** Argument names that name target paths. */
  readonly pathArgs: readonly string[]
  /** Extra tags implied by the tool itself. */
  readonly tags?: readonly ClassifierTag[]
}

/** Extract a string argument defensively. */
function stringArg(args: unknown, name: string): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined
  const value = (args as Record<string, unknown>)[name]
  return typeof value === 'string' ? value : undefined
}

/** Detect a sandbox-escalation request in tool arguments. */
function hasSandboxEscalation(args: unknown): boolean {
  if (typeof args !== 'object' || args === null) return false
  const value = (args as Record<string, unknown>).sandbox_permissions
  if (typeof value !== 'string') return false
  return value !== '' && value !== 'read-only'
}

/** Detect a background execution request in tool arguments. */
function isBackground(args: unknown): boolean {
  if (typeof args !== 'object' || args === null) return false
  return (args as Record<string, unknown>).run_in_background === true
}

/**
 * The synchronous core of classification: everything except filesystem path
 * resolution. Shared by the async pre-execute path and the synchronous guard.
 */
export interface ClassifiedCore {
  readonly toolName: string
  readonly toolFamily: ToolFamily
  readonly operation: OperationClass
  readonly risk: RiskLevel
  readonly tags: readonly ClassifierTag[]
  readonly writeInputs: readonly string[]
  readonly readInputs: readonly string[]
  readonly summary: string
}

/** Classify one tool call without touching the filesystem. */
export function classifyCore(toolName: string, args: unknown, platform: Platform): ClassifiedCore {
  const tags = new Set<ClassifierTag>()
  const writeInputs: string[] = []
  const readInputs: string[] = []

  const read = READ_TOOLS[toolName]
  if (read !== undefined) {
    for (const key of read.pathArgs) {
      const value = stringArg(args, key)
      if (value !== undefined) readInputs.push(value)
    }
    for (const tag of read.tags ?? []) tags.add(tag)
    return core(toolName, read.family, read.operation, read.risk, tags, writeInputs, readInputs, `read ${toolName}`)
  }

  const write = WRITE_TOOLS[toolName]
  if (write !== undefined) {
    for (const key of write.pathArgs) {
      const value = stringArg(args, key)
      if (value !== undefined) writeInputs.push(value)
    }
    if (hasSandboxEscalation(args)) tags.add('sandbox-escalation')
    return core(toolName, write.family, write.operation, write.risk, tags, writeInputs, readInputs, `write ${toolName}`)
  }

  if (toolName === 'str_replace_editor') {
    const command = stringArg(args, 'command') ?? 'view'
    const path = stringArg(args, 'path')
    if (path !== undefined) {
      if (command === 'view') readInputs.push(path)
      else writeInputs.push(path)
    }
    if (command === 'view') {
      return core(toolName, 'fs-read', 'read', 'none', tags, writeInputs, readInputs, 'read str_replace_editor view')
    }
    if (hasSandboxEscalation(args)) tags.add('sandbox-escalation')
    return core(toolName, 'fs-write', 'write', 'medium', tags, writeInputs, readInputs, `write str_replace_editor ${command}`)
  }

  if (toolName === 'bash' || toolName === 'pwsh') {
    const command = stringArg(args, 'command') ?? ''
    const analysis = analyzeShellCommand(command, platform)
    for (const tag of fromShellTags(analysis.tags)) tags.add(tag)
    if (isBackground(args)) tags.add('background')
    if (hasSandboxEscalation(args)) tags.add('sandbox-escalation')
    // A command whose text names a protected location is flagged so the engine
    // can deny indirect access even when the write target could not be
    // resolved (variables, nested shells, encoded payloads).
    if (analysis.protectedMention) tags.add('protected-mention')
    for (const target of analysis.writeTargets) writeInputs.push(target)
    for (const target of analysis.readTargets) readInputs.push(target)
    // A provably read-only command (single segment, no substitution, no write
    // targets, read-classified) is a read, not an execution: this is what lets
    // `git status` work in inspect mode without opening the shell to anything.
    const operation: OperationClass = analysis.readOnly
      ? 'read'
      : analysis.tags.some((tag) => tag === 'file-delete' || tag === 'destructive')
        ? 'delete'
        : 'execute'
    const risk: RiskLevel = analysis.readOnly
      ? 'none'
      : analysis.tags.includes('mass-destructive') || analysis.tags.includes('privilege-escalation')
        ? 'critical'
        : analysis.tags.length > 0 ? 'high' : 'low'
    return core(toolName, 'shell', operation, risk, tags, writeInputs, readInputs, analysis.summary)
  }

  if (toolName === 'run_code') {
    tags.add('dynamic-execution')
    if (hasSandboxEscalation(args)) tags.add('sandbox-escalation')
    return core(toolName, 'code-exec', 'execute', 'high', tags, writeInputs, readInputs, 'dynamic code execution (run_code)')
  }

  if (toolName === 'workflow') {
    tags.add('dynamic-execution')
    return core(toolName, 'code-exec', 'execute', 'high', tags, writeInputs, readInputs, 'dynamic workflow script')
  }

  if (toolName === 'subagent' || toolName === 'spawn_teammate' || toolName === 'task') {
    return core(toolName, 'delegate', 'delegate', 'medium', tags, writeInputs, readInputs, `delegate via ${toolName}`)
  }

  if (toolName === 'working_directory') {
    const path = stringArg(args, 'path') ?? stringArg(args, 'directory')
    if (path !== undefined) writeInputs.push(path)
    return core(toolName, 'meta', 'admin', 'medium', tags, writeInputs, readInputs, 'change session working directory')
  }

  if (toolName === 'plugin_manager') {
    return core(toolName, 'meta', 'admin', 'high', tags, writeInputs, readInputs, 'plugin management operation')
  }

  if (META_TOOLS.has(toolName)) {
    return core(toolName, 'meta', 'read', 'none', tags, writeInputs, readInputs, `first-party tool ${toolName}`)
  }

  if (toolName === 'job_kill') {
    return core(toolName, 'jobs', 'admin', 'low', tags, writeInputs, readInputs, 'kill background job')
  }

  if (toolName === 'send_message' || toolName === 'interrupt_agent') {
    return core(toolName, 'delegate', 'admin', 'low', tags, writeInputs, readInputs, `agent control via ${toolName}`)
  }

  if (
    toolName === 'create_goal' || toolName === 'update_goal' || toolName === 'schedule_create'
    || toolName === 'schedule_update' || toolName === 'schedule_delete'
    || toolName === 'team_task_create' || toolName === 'team_task_update'
  ) {
    return core(toolName, 'meta', 'admin', 'low', tags, writeInputs, readInputs, `durable state change via ${toolName}`)
  }

  // Unknown tool: conservative classification, never guessed.
  return core(toolName, 'unknown', 'unknown', 'high', tags, writeInputs, readInputs, `unrecognized tool ${toolName}`)
}

/** Build a {@link ClassifiedCore}. */
function core(
  toolName: string,
  family: ToolFamily,
  operation: OperationClass,
  risk: RiskLevel,
  tags: Set<ClassifierTag>,
  writeInputs: readonly string[],
  readInputs: readonly string[],
  summary: string,
): ClassifiedCore {
  return {
    toolName,
    toolFamily: family,
    operation,
    risk,
    tags: [...tags],
    writeInputs,
    readInputs,
    summary,
  }
}

/** Classify one tool call and resolve its target paths. */
export async function classifyToolCall(
  toolName: string,
  args: unknown,
  ctx: ClassifierContext,
): Promise<ClassifiedOperation> {
  const base = classifyCore(toolName, args, ctx.platform)
  return attachTargets(base, ctx)
}

/** Attach resolved path facts to a classification core. */
export async function attachTargets(core: ClassifiedCore, ctx: ClassifierContext): Promise<ClassifiedOperation> {
  const resolveAll = async (inputs: readonly string[]): Promise<PathFact[]> => {
    const facts: PathFact[] = []
    const seen = new Set<string>()
    for (const input of inputs) {
      if (input === '' || seen.has(input)) continue
      seen.add(input)
      try {
        facts.push(await ctx.resolveFact(input))
      } catch {
        // A path that cannot even be resolved is treated as absent; the policy
        // engine still sees the operation class.
      }
    }
    return facts
  }
  const writeTargets = await resolveAll(core.writeInputs)
  const readTargets = await resolveAll(core.readInputs)
  const targets = [
    ...writeTargets,
    ...readTargets.filter((fact) => !writeTargets.some((write) => write.absolute === fact.absolute)),
  ]
  return {
    toolName: core.toolName,
    toolFamily: core.toolFamily,
    operation: core.operation,
    risk: core.risk,
    targets,
    writeTargets,
    readTargets,
    tags: core.tags,
    auditSummary: core.summary,
  }
}
