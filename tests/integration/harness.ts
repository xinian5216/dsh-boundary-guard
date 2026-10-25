/**
 * Integration harness: composes the REAL DeepSeek Harness tool pipeline
 * (ToolRuntime, fs tools, sandbox policy + provider, approval service,
 * session projections) together with the real boundary-guard plugin, then
 * drives real tool executions against an isolated workspace.
 *
 * @module tests/integration/harness
 */
import { existsSync, readFileSync } from 'node:fs'
import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import SessionProjectionRegistry from '@deepseek-ai/dsh-session-projection'
import SandboxPolicyService from '@deepseek-ai/dsh-sandbox-policy'
import LocalSandboxProvider from '@deepseek-ai/dsh-sandbox-local'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import LocalAttachmentStore from '@deepseek-ai/dsh-attachment-local'
import LocalFileSystem from '@deepseek-ai/dsh-fs-local'
import WorkingDirectoryService from '@deepseek-ai/dsh-working-directory'
import ApprovalService from '@deepseek-ai/dsh-user-approval'
import CommandRuntime from '@deepseek-ai/dsh-commands'
import LocalJobService from '@deepseek-ai/dsh-jobs-local'
import LocalSubprocess from '@deepseek-ai/dsh-subprocess-local'
import * as shellEnv from '@deepseek-ai/dsh-shell-env'
import SandboxPwshExecutor from '@deepseek-ai/dsh-pwsh-sandbox'
import * as toolPwsh from '@deepseek-ai/dsh-tool-pwsh'
import SandboxBashExecutor from '@deepseek-ai/dsh-bash-sandbox'
import * as toolBash from '@deepseek-ai/dsh-tool-bash'
import * as toolFs from '@deepseek-ai/dsh-tool-fs'
import { SESSION_FORMAT_VERSION, Session } from '@deepseek-ai/dsh-session'
import type { SessionId } from '@deepseek-ai/dsh-session'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { ToolCallId } from '@deepseek-ai/dsh-llm'
import type { ApprovalOutcome } from '@deepseek-ai/dsh-user-approval'
import * as boundaryGuard from '../../src/index.ts'
import { makeWorkspace, type FakeWorkspace } from '../helpers/fakes.ts'

/** One composed test environment. */
export interface GuardTestEnv {
  readonly ctx: Context
  readonly session: Session
  readonly agent: Agent
  readonly workspace: FakeWorkspace
  /** The composed confined shell tool name, or undefined when none loaded. */
  readonly shellTool: string | undefined
  /** Approval outcomes handed to upcoming requests, in order. */
  answerWith(outcomes: ApprovalOutcome[]): void
  /** Run one tool call through the real pipeline inside an open turn. */
  call(name: string, args: Record<string, unknown>): Promise<{ isError: boolean; text: string }>
  /** The file content at a workspace-relative path, or undefined. */
  read(relative: string): string | undefined
  /** Whether a workspace-relative path exists. */
  exists(relative: string): boolean
  /** Run a slash command through the real command registry. */
  command(line: string): Promise<{ kind: 'success' | 'error'; text?: string }>
  /** Create a delegated child session in the SAME composition and announce it. */
  spawnChild(): { session: Session; call: (name: string, args: Record<string, unknown>) => Promise<{ isError: boolean; text: string }> }
  /** Announce an agent through the real lifecycle event (subagent seeding). */
  announceAgent(agent: unknown): void
  /** Dispose only the guard plugin fiber (disable/unload simulation). */
  disposePlugin(): Promise<void>
  dispose(): Promise<void>
}

/** Options for composing the harness. */
export interface GuardTestEnvOptions {
  /** Guard plugin config overrides. */
  config?: Record<string, unknown>
  /** Sandbox mode the session starts in. */
  sandboxMode?: 'read-only' | 'workspace-write' | 'danger-full-access'
  /** Default approval outcome for requests without a queued answer. */
  defaultApproval?: ApprovalOutcome
  /** Workspace root; a fresh temporary workspace is created when omitted. */
  workspaceRoot?: string
  /** Session lineage metadata (for subagent inheritance tests). */
  sessionMeta?: { origin?: 'subagent'; parentSession?: string }
  /**
   * Working directory recorded on the session when it differs from the
   * workspace root (used to exercise Windows 8.3 short-name aliases).
   */
  sessionCwd?: string
}

/** Compose the real pipeline with the real plugin. */
export async function createGuardEnv(options: GuardTestEnvOptions = {}): Promise<GuardTestEnv> {
  const workspace = options.workspaceRoot === undefined
    ? makeWorkspace()
    : { root: options.workspaceRoot, cleanup: () => {} }
  const ctx = new Context()

  await ctx.plugin(SystemPrompt)
  await ctx.plugin(SessionProjectionRegistry)
  await ctx.plugin(SandboxPolicyService, {
    mode: options.sandboxMode ?? 'workspace-write',
    workspaceRoot: workspace.root,
  })
  await ctx.plugin(LocalSandboxProvider)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(LocalAttachmentStore)
  await ctx.plugin(LocalFileSystem)
  await ctx.plugin(WorkingDirectoryService, { defaultDirectory: workspace.root })
  await ctx.plugin(toolFs)
  await ctx.plugin(ApprovalService, { policy: 'ask' })
  await ctx.plugin(CommandRuntime)
  // The confined shell stack: PowerShell on Windows, Bash elsewhere.
  if (process.platform === 'win32') {
    await ctx.plugin(LocalJobService)
    await ctx.plugin(LocalSubprocess)
    await ctx.plugin(shellEnv)
    await ctx.plugin(SandboxPwshExecutor)
    await ctx.plugin(toolPwsh)
  } else {
    await ctx.plugin(LocalJobService)
    await ctx.plugin(LocalSubprocess)
    await ctx.plugin(shellEnv)
    await ctx.plugin(SandboxBashExecutor)
    await ctx.plugin(toolBash)
  }

  const sessionId = `session-${Math.random().toString(36).slice(2, 10)}` as SessionId
  const session = Session.create(sessionId, [], {
    version: SESSION_FORMAT_VERSION,
    id: sessionId,
    createdAt: Date.now(),
    isSeeded: false,
    cwd: options.sessionCwd ?? workspace.root,
    ...(options.sessionMeta?.origin === undefined ? {} : { origin: options.sessionMeta.origin }),
    ...(options.sessionMeta?.parentSession === undefined ? {} : { parentSession: options.sessionMeta.parentSession as SessionId }),
  })
  const agent = { session, options: {}, ctx: ctx.extend() } as unknown as Agent

  // Approval answers are queued per test; the default fails closed to
  // `unavailable` unless a test says otherwise.
  let queue: ApprovalOutcome[] = []
  const defaultApproval: ApprovalOutcome = options.defaultApproval ?? 'unavailable'
  ctx.on('approval/request', async () => queue.shift() ?? defaultApproval)

  const guardFiber = await ctx.plugin(boundaryGuard, {
    defaultMode: 'develop',
    additionalWritableRoots: [],
    unknownToolPolicy: 'ask',
    audit: { enabled: false },
    snapshot: { enabled: false },
    maintain: { maxDurationMs: 1800000, requireConfirmation: true },
    ...options.config,
  })

  const commands = ctx.get('commands') as import('@deepseek-ai/dsh-commands').CommandRuntime | undefined
  const shellTool = process.platform === 'win32'
    ? (ctx.tools.get('pwsh') === undefined ? undefined : 'pwsh')
    : (ctx.tools.get('bash') === undefined ? undefined : 'bash')
  let turn = 0
  const text = (content: unknown): string => {
    if (!Array.isArray(content)) return ''
    return (content as { type: string; text?: string }[])
      .map((block) => (block.type === 'text' ? block.text ?? '' : `[${block.type}]`))
      .join('\n')
  }
  return {
    ctx,
    session,
    agent,
    workspace,
    shellTool,
    answerWith(outcomes: ApprovalOutcome[]) {
      queue = [...outcomes]
    },
    async call(name, args) {
      session.append('turn/start', { turn: ++turn })
      try {
        const result = await ctx.tools.execute({
          callId: `call-${turn}` as ToolCallId,
          name,
          arguments: args,
          agent,
          signal: AbortSignal.timeout(60000),
        })
        return { isError: result.isError, text: text(result.content) }
      } finally {
        session.append('turn/end', { turn, reason: { kind: 'completed' } })
      }
    },
    read(relative) {
      try {
        return readFileSync(`${workspace.root}/${relative}`, 'utf8')
      } catch {
        return undefined
      }
    },
    exists(relative) {
      return existsSync(`${workspace.root}/${relative}`)
    },
    async command(line) {
      if (commands === undefined) throw new Error('command registry is not composed')
      const execution = await commands.execute(agent, line, [], AbortSignal.timeout(30000))
      if (execution === undefined) return { kind: 'error', text: 'command not admitted' }
      return execution.result
    },
    announceAgent(childAgent) {
      ctx.emit('agent/created', { agent: childAgent as never, source: 'subagent' as never })
    },
    spawnChild() {
      const childId = `session-${Math.random().toString(36).slice(2, 10)}` as SessionId
      const childSession = Session.create(childId, [], {
        version: SESSION_FORMAT_VERSION,
        id: childId,
        createdAt: Date.now(),
        isSeeded: false,
        cwd: workspace.root,
        origin: 'subagent',
        parentSession: session.id,
      })
      const childAgent = { session: childSession, options: {}, ctx: ctx.extend() } as unknown as Agent
      ctx.emit('agent/created', { agent: childAgent as never, source: 'subagent' as never })
      return {
        session: childSession,
        call: async (name, args) => {
          childSession.append('turn/start', { turn: ++turn })
          try {
            const result = await ctx.tools.execute({
              callId: `call-child-${turn}` as ToolCallId,
              name,
              arguments: args,
              agent: childAgent,
              signal: AbortSignal.timeout(60000),
            })
            return { isError: result.isError, text: text(result.content) }
          } finally {
            childSession.append('turn/end', { turn, reason: { kind: 'completed' } })
          }
        },
      }
    },
    async disposePlugin() {
      await guardFiber.dispose()
    },
    async dispose() {
      await guardFiber.dispose()
      workspace.cleanup()
    },
  }
}
