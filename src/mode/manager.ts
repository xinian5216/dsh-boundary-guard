/**
 * Guard-mode manager: per-session mode state, expiry, inheritance, and the
 * sandbox-mode synchronization that gives each mode its OS-level meaning.
 *
 * The manager is the ONLY writer of guard-mode state, and it only changes mode
 * on an explicit human command (or fail-closed inheritance). No tool, prompt,
 * or model message can raise the mode.
 *
 * The synchronization itself fails closed: a mode is "applied" only when the
 * write landed, finished inside its budget, and — when a sandbox-policy
 * service exists — was read back at least as restrictive as requested.
 * Everything else is a recorded failure that the execution path sees through
 * {@link GuardModeManager.ensureSandboxSynced}, so a session whose OS sandbox
 * cannot be confirmed never runs a mutation.
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
  /** Whether the applied mode was read back from the sandbox policy service. */
  readonly verified: boolean
  /** The mode the sandbox policy service reports right now, when it can be read. */
  readonly observed?: SandboxMode
  /** The last synchronization failure, if any. */
  readonly lastError?: string
}

/**
 * Injectable seams of the sandbox synchronization. Production uses the real
 * `setSandboxMode` write and the sandbox-policy read-back; tests inject the
 * failure they need without touching a real session log or a real sandbox.
 */
export interface GuardModeManagerOptions {
  /** Writes the session's sandbox mode. Defaults to the real write path. */
  readonly sandboxSync?: (session: Session, mode: SandboxMode) => void
  /** Reads the session's current sandbox mode back, when a policy service exists. */
  readonly verifySandbox?: (session: Session) => SandboxMode | undefined
  /** Wall-clock budget for one synchronization attempt. Defaults to 2000ms. */
  readonly syncTimeoutMs?: number
}

/** The default budget for one sandbox synchronization attempt. */
const DEFAULT_SYNC_TIMEOUT_MS = 2000

/** Every sandbox mode, least restrictive first. */
const SANDBOX_MODES: readonly SandboxMode[] = ['read-only', 'workspace-write', 'danger-full-access']

/** Whether `candidate` is at least as restrictive as `floor`. */
function isAtLeastAsRestrictive(candidate: SandboxMode, floor: SandboxMode): boolean {
  return SANDBOX_MODES.indexOf(candidate) <= SANDBOX_MODES.indexOf(floor)
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
  private readonly sandboxSync: (session: Session, mode: SandboxMode) => void
  private verifySandbox: ((session: Session) => SandboxMode | undefined) | undefined
  private readonly syncTimeoutMs: number

  constructor(
    config: GuardConfig,
    projections?: SessionProjectionRegistry,
    options: GuardModeManagerOptions = {},
  ) {
    this.config = config
    this.projections = projections
    this.sandboxSync = options.sandboxSync ?? setSandboxMode
    this.verifySandbox = options.verifySandbox
    this.syncTimeoutMs = options.syncTimeoutMs ?? DEFAULT_SYNC_TIMEOUT_MS
    if (projections !== undefined) this.registerProjection()
  }

  /**
   * Attach the read-back the sandbox policy service offers. Without it a
   * successful write is the only evidence the guard has, so status reports
   * `verified: false` and the mode still applies.
   */
  attachVerifier(verify: (session: Session) => SandboxMode | undefined): void {
    this.verifySandbox = verify
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
   * The synchronized marker is written only when the whole attempt succeeded:
   * the write did not throw, it finished inside the configured budget, and —
   * when a read-back exists — the policy reports a mode that is at least as
   * restrictive as the requested one. Anything else is a failure that is
   * recorded and surfaced, never reported as applied.
   */
  private syncSandbox(session: Session, mode: GuardMode): void {
    const target = sandboxModeFor(mode)
    const key = `${String(session.id)}:${target}`
    if (this.sandboxSynced.get(session) === key) return
    const started = performance.now()
    try {
      this.sandboxSync(session, target)
    } catch (error) {
      // The sandbox policy service may be absent or the append may fail. The
      // guard's own policy still applies, but OS-level confinement is weaker;
      // the failure is recorded and surfaced in status instead of being
      // silently treated as success.
      this.sandboxErrors.set(session, (error as Error).message)
      return
    }
    // Read the mode back before judging the attempt: the read-back is part of
    // the synchronization, so a policy service that hangs is a slow sync, not
    // a fast one that merely failed to confirm.
    const observed = this.verifySandbox === undefined ? undefined : this.readSandboxMode(session)
    const elapsed = performance.now() - started
    if (elapsed > this.syncTimeoutMs) {
      this.sandboxErrors.set(session, `sandbox synchronization timed out after ${Math.round(elapsed)}ms`)
      return
    }
    if (observed !== undefined && !isAtLeastAsRestrictive(observed, target)) {
      // The policy reports something WIDER than the mode requires. The write
      // may have landed on a different session or been overridden; treating it
      // as applied would let the guard claim confinement it does not have.
      this.sandboxErrors.set(
        session,
        `sandbox policy reports ${observed}, which is less restrictive than the required ${target}`,
      )
      return
    }
    this.sandboxErrors.delete(session)
    this.sandboxSynced.set(session, key)
  }

  /** Read the current sandbox mode back, treating a read fault as unknown. */
  private readSandboxMode(session: Session): SandboxMode | undefined {
    try {
      return this.verifySandbox?.(session)
    } catch {
      // An unreadable policy is not a confirmation.
      return undefined
    }
  }

  /**
   * The real sandbox-sync state of one session: what the guard mode requires,
   * what was last applied successfully, whether that write was read back, what
   * the policy reports now, and the last failure (if any).
   *
   * The requirement is read from the EFFECTIVE mode, never the raw one: an
   * expired maintain grant must never describe `danger-full-access` as what
   * the session requires, or a retry would re-widen a grant that already
   * ended.
   */
  sandboxStatusOf(session: Session): SandboxSyncStatus {
    const desired = sandboxModeFor(this.effective(session).mode)
    const applied = this.sandboxSynced.get(session)?.split(':').slice(1).join(':') as SandboxMode | undefined
    const lastError = this.sandboxErrors.get(session)
    const observed = this.readSandboxMode(session)
    return {
      desired,
      applied,
      verified: applied !== undefined && observed !== undefined && isAtLeastAsRestrictive(observed, applied),
      ...(observed === undefined ? {} : { observed }),
      ...(lastError === undefined ? {} : { lastError }),
    }
  }

  /**
   * The single entry point the execution path uses: report the session's real
   * sandbox state, retrying exactly once when it does not match the mode. The
   * retry is what turns a recorded failure into a recovered session without a
   * restart, and the bounded attempt count is what keeps a broken sandbox
   * policy from producing a write storm.
   */
  ensureSandboxSynced(session: Session): SandboxSyncStatus {
    const current = this.sandboxStatusOf(session)
    if (current.applied === current.desired) return current
    this.retrySandboxSync(session)
    return this.sandboxStatusOf(session)
  }

  /**
   * Re-attempt the sandbox sync after a failure.
   *
   * The attempt is keyed by mode, so a retry after a mode change re-attempts
   * the new mode while the marker of the last SUCCESSFUL sync survives as the
   * historical "applied" evidence — that is what lets `/guard status` show a
   * session running wider than its mode requires. A retry of an already
   * synchronized mode is deliberately a no-op: the guard never fights an
   * explicit user change through the permission selector.
   */
  retrySandboxSync(session: Session): void {
    this.syncSandbox(session, this.effective(session).mode)
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
