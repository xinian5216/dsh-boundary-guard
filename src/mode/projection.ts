/**
 * Durable guard-mode state for one session.
 *
 * The mode is stored as a session-log plugin record (`plugin:dsh-boundary-guard/mode`)
 * and folded through a session projection, the same pattern `dsh-sandbox-policy`
 * uses for sandbox mode. Two rules keep the fold safe:
 *
 * - `maintain` grants never survive a process restart (a stale grant must not
 *   outlive its human approval window), so records carry the boot id that
 *   wrote them and old-boot maintain records are ignored.
 * - A fold that cannot be interpreted falls back to the configured default and
 *   is reported, never silently widened.
 *
 * @module dsh-boundary-guard/mode/projection
 */
import { z } from 'zod'
import type { GuardMode } from '../types.ts'

/** The plugin record type carrying a mode change. */
export const MODE_RECORD_TYPE = 'plugin:dsh-boundary-guard/mode'

/** Payload of one mode record. */
export interface ModeRecordData {
  readonly mode: GuardMode
  /** Epoch ms when a maintain grant expires; null otherwise. */
  readonly maintainExpiresAt: number | null
  /** Where the mode came from. */
  readonly source: 'default' | 'command' | 'inherited'
  /** Boot id of the process that wrote the record. */
  readonly bootId: string
}

declare module '@deepseek-ai/dsh-session/types' {
  interface PluginRecordMap {
    'plugin:dsh-boundary-guard/mode': ModeRecordData
  }
}

declare module '@deepseek-ai/dsh-session-projection/types' {
  interface SessionProjectionStateMap {
    /** Folded guard-mode state of one session. */
    boundaryGuardMode: GuardModeState
  }
}

/** Projection state schema. */
const stateSchema = z.object({
  mode: z.enum(['inspect', 'develop', 'maintain']),
  maintainExpiresAt: z.number().nullable(),
  source: z.enum(['default', 'command', 'inherited']),
}).strict()

/** The folded guard-mode state of one session. */
export type GuardModeState = z.infer<typeof stateSchema>

/**
 * Build the projection definition. `bootId` identifies the current process;
 * `defaultMode` is the configured starting mode.
 */
export function createModeProjection(bootId: string, defaultMode: GuardMode) {
  return {
    key: 'boundaryGuardMode' as const,
    stateVersion: 1,
    stateSchema,
    init: (): GuardModeState => ({ mode: defaultMode, maintainExpiresAt: null, source: 'default' }),
    apply: (state: GuardModeState, event: { type: string; data?: unknown }): GuardModeState => {
      if (event.type !== MODE_RECORD_TYPE) return state
      const data = event.data as ModeRecordData | undefined
      if (data === undefined || typeof data.mode !== 'string') return state
      // A maintain grant from a previous process is not honored: the human
      // approval window ended with that process.
      if (data.mode === 'maintain' && data.bootId !== bootId) return state
      return {
        mode: data.mode,
        maintainExpiresAt: typeof data.maintainExpiresAt === 'number' ? data.maintainExpiresAt : null,
        source: data.source === 'command' || data.source === 'inherited' ? data.source : 'default',
      }
    },
  }
}
