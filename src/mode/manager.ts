/**
 * Guard-mode manager: per-session mode state, expiry, inheritance, and the
 * sandbox-mode synchronization that gives each mode its OS-level meaning.
 *
 * The manager is the ONLY writer of guard-mode state, and it only changes mode
 * on an explicit human command (or fail-closed inheritance). No tool, prompt,
 * or model message can raise the mode.
 *
 * @module dsh-boundary-guard/mode/manager
 */
import type { Context } from '@deepseek-ai/cordis'
import type { SandboxMode } from '@deepseek-ai/dsh-sandbox'
import { setSandboxMode } from '@deepseek-ai/dsh-sandbox-policy'
import { appendPluginRecord } from '@deepseek-ai/dsh-session'
import type { Session } from '@deepseek-ai/dsh-session'
import type { SessionProjectionRegistry } from '@deepseek-ai/dsh-session-projection'
import type { GuardMode } from '../types.ts'
import type { GuardConfig } from '../config.ts'
import { createModeProjection, MODE_RECORD_TYPE, type GuardModeState } from './projection.ts'

/** The sandbox mode each guard mode maps onto. */
export function sandboxModeFor(mode: GuardMode): SandboxMode {
  switch (mode) {
    case 'inspect': return 'read-only'
    case 'develop': return 'workspace-write'
    case 'maintain': return 'danger-full-access'
  }
}

/** Effective mode of one session after applying expiry. */
export interface EffectiveMode {
  readonly mode: GuardMode
  /** Set when a maintain grant has expired and the mode fell back. */
  readonly expired: boolean
  readonly state: GuardModeState
}

/** Options for a mode change. */
export interface SetModeOptions {
  /** Lifetime of a maintain grant; defaults to the configured maximum. */
  readonly maintainDurationMs?: number
  /** Where the change came from. */
  readonly source?: 'command' | 'inherited'
}

/** The real sandbox-sync state of one session. */
export interface SandboxSyncStatus {
  /** The sandbox mode the current guard mode requires. */
  readonly desired: SandboxMode
  /** The sandbox mode last applied successfully, if any. */
  readonly applied: SandboxMode | undefined
  /** The last synchronization failure, if any. */
  readonly lastError?: string
}

/**
 * Owns guard-mode state for every session in this process.
 */
export class GuardModeManager {
  private readonly bootId = crypto.randomUUID()
  private readonly states = new WeakMap<Session, GuardModeState>()
  /** Sessions whose sandbox mode already matches the effective guard mode. */
  private readonly sandboxSynced = new WeakMap<Session, string>()
  /** Last sandbox-sync failure per session, surfaced in status. */
  private readonly sandboxErrors = new WeakMap<Session, string>()
  /** Sessions that already received a mode record (command or inheritance). */
  private readonly recorded = new WeakSet<Session>()
  /** Live session modes by id, for subagent inheritance. */
  private readonly knownModes = new Map<string, GuardModeState>()
  private projections: SessionProjectionRegistry | undefined
  private projectionRegistered = false
  private readonly config: GuardConfig

  constructor(config: GuardConfig, projections?: SessionProjectionRegistry) {
    this.config = config
    this.projections = projections
    if (projections !== undefined) this.registerProjection()
  }

  /** Attach the projection registry when it becomes available. */
  attach(projections: SessionProjectionRegistry): void {
    this.projections = projections
    this.registerProjection()
  }

  private registerProjection(): void {
    if (this.projections === undefined || this.projectionRegistered) return
    this.projections.register(createModeProjection(this.bootId, this.config.defaultMode))
    this.projectionRegistered = true
  }

  /** Read the durable state of one session, initializing lazily. */
  stateOf(session: Session): GuardModeState {
    const cached = this.states.get(session)
    if (cached !== undefined) return cached
    let state: GuardModeState
    if (this.projections !== undefined) {
      try {
        const projected = this.projections.stateOf(session, 'boundaryGuardMode') as GuardModeState | undefined
        state = projected ?? { mode: this.config.defaultMode, maintainExpiresAt: null, source: 'default' }
      } catch {
        // A projection fault must not widen privileges: fall back to default.
        state = { mode: this.config.defaultMode, maintainExpiresAt: null, source: 'default' }
      }
    } else {
      state = { mode: this.config.defaultMode, maintainExpiresAt: null, source: 'default' }
    }
    this.states.set(session, state)
    this.knownModes.set(String(session.id), state)
    // The OS sandbox must reflect the guard mode from the first touch of a
    // session; otherwise a session that never changes mode runs with the
    // deployment default (usually workspace-write) even in inspect mode.
    this.syncSandbox(session, state.mode)
    return state
  }

  /** Effective mode after expiry. */
  effective(session: Session, now: number = Date.now()): EffectiveMode {
    const state = this.stateOf(session)
    if (state.mode === 'maintain' && state.maintainExpiresAt !== null && now >= state.maintainExpiresAt) {
      // The grant expired: lower the sandbox once and report develop.
      this.syncSandbox(session, 'develop')
      return { mode: 'develop', expired: true, state }
    }
    return { mode: state.mode, expired: false, state }
  }

  /** Change one session's mode (human command or fail-closed inheritance). */
  setMode(session: Session, mode: GuardMode, options: SetModeOptions = {}): GuardModeState {
    const now = Date.now()
    const maintainExpiresAt = mode === 'maintain'
      ? now + (options.maintainDurationMs ?? this.config.maintain.maxDurationMs)
      : null
    const state: GuardModeState = {
      mode,
      maintainExpiresAt,
      source: options.source ?? 'command',
    }
    this.states.set(session, state)
    this.knownModes.set(String(session.id), state)
    this.recorded.add(session)
    try {
      appendPluginRecord(session, MODE_RECORD_TYPE, { ...state, bootId: this.bootId })
    } catch (error) {
      // Durability failed; the in-memory state still governs this process, but
      // the failure is loud so operators can see it.
      throw new Error(`boundary-guard: failed to record mode change: ${(error as Error).message}`)
    }
    this.syncSandbox(session, mode)
    return state
  }

  /**
   * Seed a freshly created subagent session with its parent's restrictions.
   * A child can never exceed its parent: it inherits the parent's effective
   * mode verbatim (with the same maintain expiry), and an unknown parent —
   * for example a parent that lived in another process — fails closed to
   * inspect.
   */
  inheritForSubagent(session: Session, parentSessionId: string | undefined): GuardMode | undefined {
    if (this.recorded.has(session)) return undefined
    const parent = parentSessionId === undefined ? undefined : this.knownModes.get(parentSessionId)
    const mode: GuardMode = parent === undefined ? 'inspect' : parent.mode
    const maintainExpiresAt = mode === 'maintain' ? parent?.maintainExpiresAt ?? null : null
    const state: GuardModeState = { mode, maintainExpiresAt, source: 'inherited' }
    this.states.set(session, state)
    this.knownModes.set(String(session.id), state)
    this.recorded.add(session)
    try {
      appendPluginRecord(session, MODE_RECORD_TYPE, { ...state, bootId: this.bootId })
    } catch {
      // In-memory state still applies for this process.
    }
    this.syncSandbox(session, mode)
    return mode
  }

  /** Whether this session already has mode history. */
  hasHistory(session: Session): boolean {
    return this.recorded.has(session) || this.stateOf(session).source !== 'default'
  }

  /** The known live state of one session id, for inheritance lookups. */
  knownStateOf(sessionId: string): GuardModeState | undefined {
    return this.knownModes.get(sessionId)
  }

  /**
   * Lower the session sandbox to match the guard mode. Idempotent per
   * session+mode; never fights an explicit user change through the permission
   * selector (that only widens what an approved operation may execute).
   *
   * The synchronized marker is written only after `setSandboxMode` succeeds, so
   * a failure is never reported as applied and is retried on the next call.
   */
  private syncSandbox(session: Session, mode: GuardMode): void {
    const target = sandboxModeFor(mode)
    const key = `${String(session.id)}:${target}`
    if (this.sandboxSynced.get(session) === key) return
    try {
      setSandboxMode(session, target)
    } catch (error) {
      // The sandbox policy service may be absent or the append may fail. The
      // guard's own policy still applies, but OS-level confinement is weaker;
      // the failure is recorded and surfaced in status instead of being
      // silently treated as success.
      this.sandboxErrors.set(session, (error as Error).message)
      return
    }
    this.sandboxErrors.delete(session)
    this.sandboxSynced.set(session, key)
  }

  /**
   * The real sandbox-sync state of one session: what the guard mode requires,
   * what was last applied successfully, and the last failure (if any).
   */
  sandboxStatusOf(session: Session): SandboxSyncStatus {
    const state = this.stateOf(session)
    const desired = sandboxModeFor(state.mode)
    const applied = this.sandboxSynced.get(session)?.split(':').slice(1).join(':') as SandboxMode | undefined
    const lastError = this.sandboxErrors.get(session)
    return {
      desired,
      applied,
      ...(lastError === undefined ? {} : { lastError }),
    }
  }

  /** Re-attempt the sandbox sync after a failure. */
  retrySandboxSync(session: Session): void {
    this.sandboxSynced.delete(session)
    this.syncSandbox(session, this.stateOf(session).mode)
  }

  /** Drop in-memory state for a disposed session. */
  forget(session: Session): void {
    this.knownModes.delete(String(session.id))
    this.states.delete(session)
    this.sandboxSynced.delete(session)
    this.sandboxErrors.delete(session)
    this.recorded.delete(session)
  }
}

/** Install the manager as `ctx.guardModes`. */
export function registerModeManager(ctx: Context, manager: GuardModeManager): void {
  ctx.set('guardModes', manager)
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    guardModes: GuardModeManager
  }
}
