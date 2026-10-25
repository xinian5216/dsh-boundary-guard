/**
 * DSH Boundary Guard — plugin entry.
 *
 * A policy layer over the DeepSeek Harness tool pipeline that adds three
 * audited operating modes (inspect / develop / maintain), permanent
 * protected-path rules, human-approved high-risk operations, and a sanitized
 * local audit trail. Enforcement reuses DSH's native mechanisms: the
 * `tools/pre-execute` waterfall for approvable decisions, `ctx.tools.guard()`
 * for final denials no later listener can re-allow, the sandbox policy for
 * OS-level file confinement, and `ctx.approval` for human decisions.
 *
 * The plugin never monkey-patches DSH internals and never writes outside its
 * own storage under the DSH home.
 *
 * @module dsh-boundary-guard
 */
import type { Context } from '@deepseek-ai/cordis'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import type { Session } from '@deepseek-ai/dsh-session'
import type { ApprovalOutcome } from '@deepseek-ai/dsh-user-approval'
import { classifyCore, classifyToolCall, type ClassifierContext } from './tools/classify.ts'
import { evaluatePolicy } from './policy/engine.ts'
import { currentPlatform, lexicalPathFact, resolvePathFact } from './boundary/paths.ts'
import { currentPluginRoot, discoverProtectedRoots, discoveryFromEnvironment, type ProtectedRoot } from './boundary/protected.ts'
import { Config, normalizeConfig, type ResolvedConfig } from './config.ts'
import { GuardModeManager } from './mode/manager.ts'
import { AuditLogger, sanitizeTarget, type AuditRecord } from './audit/logger.ts'
import { SnapshotStore } from './snapshot/store.ts'
import { buildApprovalView, denialForOutcome } from './approval/adapter.ts'
import { createGuardCommand, type GuardCommandContext } from './commands.ts'
import type { ClassifiedOperation, GuardMode, PathFact, PolicyResult } from './types.ts'

export { Config }
export const name = 'boundary-guard'
export const inject: string[] = []

/** The plugin object shape the loader and `ctx.plugin` consume. */
export default { name, inject, Config, apply }

/** Plugin version, kept in sync with package.json. */
const PLUGIN_VERSION = '0.1.0'

/**
 * The plugin body. Configuration is validated before anything registers: an
 * invalid configuration fails the plugin load loudly instead of silently
 * running with a different policy.
 */
export function apply(ctx: Context, rawConfig: ResolvedConfig) {
  const config = normalizeConfig(rawConfig, homedir())
  const env = discoveryFromEnvironment(process.env)
  const platform = currentPlatform
  const protectedRoots: ProtectedRoot[] = discoverProtectedRoots({
    homedir: env.homedir,
    dshHome: env.dshHome,
    agentsHome: env.agentsHome,
    pluginRoot: currentPluginRoot(),
    platform,
  })

  const modes = new GuardModeManager(config)
  const auditDir = config.audit.dir ?? join(env.dshHome, 'boundary-guard', 'audit')
  const audit = config.audit.enabled
    ? new AuditLogger({
      dir: auditDir,
      maxFileBytes: config.audit.maxFileBytes,
      retainDays: config.audit.retainDays,
      protectedRoots,
      platform,
    })
    : undefined
  const snapshotDir = config.snapshot.dir ?? join(env.dshHome, 'boundary-guard', 'snapshots')
  const snapshots = config.snapshot.enabled
    ? new SnapshotStore({
      dir: snapshotDir,
      maxSnapshots: config.snapshot.maxSnapshots,
      maxFileBytes: config.snapshot.maxFileBytes,
    })
    : undefined

  const commandDeps: GuardCommandContext = {
    config,
    modes,
    audit,
    snapshots,
    protectedRoots,
    pluginVersion: PLUGIN_VERSION,
  }

  // ---- Optional service wiring -------------------------------------------
  ctx.inject(['sessionProjections'], (scope) => {
    modes.attach(scope.sessionProjections)
  })

  // ---- Subagent inheritance ----------------------------------------------
  // A child session can never exceed its parent's authorization: the mode is
  // seeded at creation from the parent's live state, and an unknown parent
  // fails closed to inspect.
  ctx.on('agent/created', ({ agent }) => {
    const header = agent.session.header
    if (header.origin !== 'subagent') return undefined
    const parentId = header.parentSession
    modes.inheritForSubagent(agent.session, parentId === undefined ? undefined : String(parentId))
    return undefined
  })

  ctx.on('agent/disposed', ({ agent }) => {
    modes.forget(agent.session)
  })

  // ---- Tool policy ---------------------------------------------------------
  ctx.inject(['tools'], (scope) => {
    // The synchronous backstop: evaluated after every `tools/pre-execute`
    // listener, so no later listener can turn a denial back into permission.
    scope.tools.guard((execution: ToolExecution) => guardReason(execution, scope))

    // The approvable gate.
    scope.on('tools/pre-execute', async (exec, next) => {
      const session = exec.agent?.session
      // Agentless calls have no session to authorize: fail closed to inspect.
      const mode: GuardMode = session === undefined ? 'inspect' : modes.effective(session).mode
      const workspaceRoot = session?.header.cwd
      const base = resolveWorkingDirectory(scope, session) ?? workspaceRoot
      const classifier: ClassifierContext = {
        platform,
        protectedRoots,
        resolveFact: (input) => resolvePathFact(input, base, platform),
      }
      const operation = await classifyToolCall(exec.name, exec.arguments, classifier)
      const result = evaluatePolicy(
        {
          mode,
          workspaceRoot,
          workingDirectory: base,
          operation,
          additionalWritableRoots: config.additionalWritableRoots,
          unknownToolPolicy: config.unknownToolPolicy,
        },
        protectedRoots,
        platform,
      )

      if (result.decision === 'allow') {
        record(session, mode, operation, result, undefined, exec.callId)
        return next()
      }
      if (result.decision === 'deny') {
        record(session, mode, operation, result, undefined, exec.callId)
        return {
          kind: 'deny',
          reason: result.reason,
          info: { name: 'BoundaryGuardDenial', code: result.reasonCode, reason: result.reason },
        }
      }

      // ---- ask: route through the official approval seam -------------------
      const approval = scope.get('approval') as { request(request: {
        agent: unknown
        toolName: string
        callId?: string
        reason?: string
        displayReason?: { en: string; [locale: string]: string }
        signal?: AbortSignal
      }): Promise<ApprovalOutcome> } | undefined
      if (approval === undefined || exec.agent === undefined) {
        record(session, mode, operation, result, 'unavailable', exec.callId)
        return {
          kind: 'deny',
          reason: `${exec.name} requires approval, but no approval channel is available`,
          info: { name: 'BoundaryGuardDenial', code: 'approval-unavailable' },
        }
      }
      const view = buildApprovalView({
        mode,
        operation,
        result,
        workspaceRoot,
        protectedRoots,
        platform,
        args: exec.arguments,
      })
      let outcome: ApprovalOutcome
      try {
        outcome = await approval.request({
          agent: exec.agent,
          toolName: exec.name,
          callId: exec.callId,
          reason: view.reason,
          displayReason: view.displayReason,
          signal: exec.signal,
        })
      } catch (error) {
        record(session, mode, operation, result, 'unavailable', exec.callId)
        return {
          kind: 'deny',
          reason: `${exec.name} requires approval, but the approval channel could not be reached: ${(error as Error).message}`,
          info: { name: 'BoundaryGuardDenial', code: 'approval-unavailable' },
        }
      }
      record(session, mode, operation, result, outcome, exec.callId)
      if (outcome === 'allowed-once') {
        await captureSnapshot(session, workspaceRoot, operation, result.reasonCode)
        return next()
      }
      return {
        kind: 'deny',
        reason: denialForOutcome(exec.name, outcome),
        info: { name: 'BoundaryGuardDenial', code: `approval-${outcome}` },
      }
    })
  })

  // ---- Human commands -------------------------------------------------------
  ctx.inject(['commands'], (scope) => {
    scope.commands.register(createGuardCommand(commandDeps))
  })

  // ---- Disposal --------------------------------------------------------------
  ctx.effect(() => () => {
    void audit?.close()
  }, 'boundary-guard: close audit logger')

  // ---- Helpers ----------------------------------------------------------------
  function record(
    session: Session | undefined,
    mode: GuardMode,
    operation: ClassifiedOperation,
    result: Pick<PolicyResult, 'decision' | 'reasonCode' | 'overridable' | 'risk'>,
    approval: AuditRecord['approval'],
    callId: string | undefined,
  ): void {
    if (audit === undefined || session === undefined) return
    audit.record({
      v: 1,
      time: Date.now(),
      sessionId: String(session.id),
      mode,
      tool: operation.toolName,
      family: operation.toolFamily,
      operation: operation.operation,
      risk: result.risk,
      decision: result.decision,
      reasonCode: result.reasonCode,
      overridable: result.overridable,
      targets: operation.targets.map((target) =>
        sanitizeTarget(target.absolute, session.header.cwd, protectedRoots, platform),
      ),
      tags: operation.tags,
      ...(approval === undefined ? {} : { approval }),
      ...(callId === undefined ? {} : { callId }),
    })
  }

  async function captureSnapshot(
    session: Session | undefined,
    workspaceRoot: string | undefined,
    operation: ClassifiedOperation,
    reasonCode: string,
  ): Promise<void> {
    if (snapshots === undefined || session === undefined || workspaceRoot === undefined) return
    if (operation.writeTargets.length === 0) return
    try {
      await snapshots.capture(
        workspaceRoot,
        String(session.id),
        `${operation.toolName}:${reasonCode}`,
        operation.writeTargets.map((target) => target.absolute),
      )
    } catch {
      // A failed snapshot must not block an approved operation; the approval
      // already happened and the operation is authorized.
    }
  }

  /** The synchronous backstop's denial reason, or undefined to leave the call. */
  function guardReason(execution: ToolExecution, scope: Context): string | undefined {
    const session = execution.agent?.session
    const mode: GuardMode = session === undefined ? 'inspect' : modes.effective(session).mode
    const workspaceRoot = session?.header.cwd
    const base = resolveWorkingDirectory(scope, session) ?? workspaceRoot
    let operation: ClassifiedOperation
    try {
      operation = classifyWithLexicalPaths(execution.name, execution.arguments, base)
    } catch {
      return `Boundary guard: ${execution.name} could not be classified and was denied (fail closed).`
    }
    const result = evaluatePolicy(
      {
        mode,
        workspaceRoot,
        workingDirectory: base,
        operation,
        additionalWritableRoots: config.additionalWritableRoots,
        unknownToolPolicy: config.unknownToolPolicy,
      },
      protectedRoots,
      platform,
    )
    // Only final denials act as the backstop; approvals stay with the
    // waterfall so a human decision is never second-guessed here.
    return result.decision === 'deny' ? result.reason : undefined
  }
}

/** Classify with lexical-only path resolution (no filesystem access). */
function classifyWithLexicalPaths(toolName: string, args: unknown, base: string | undefined): ClassifiedOperation {
  const core = classifyCore(toolName, args, currentPlatform)
  const resolveAll = (inputs: readonly string[]): PathFact[] => {
    const facts: PathFact[] = []
    const seen = new Set<string>()
    for (const input of inputs) {
      if (input === '' || seen.has(input)) continue
      seen.add(input)
      facts.push(lexicalPathFact(input, base, currentPlatform))
    }
    return facts
  }
  const writeTargets = resolveAll(core.writeInputs)
  const readTargets = resolveAll(core.readInputs)
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

/** Resolve the effective working directory of one session, when known. */
function resolveWorkingDirectory(scope: Context, session: Session | undefined): string | undefined {
  if (session === undefined) return undefined
  const service = scope.get('workingDirectory') as { get(session: unknown): string } | undefined
  if (service !== undefined) {
    try {
      return service.get(session)
    } catch {
      // Fall through to the immutable header cwd.
    }
  }
  return session.header.cwd
}
