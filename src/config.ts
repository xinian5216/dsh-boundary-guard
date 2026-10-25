/**
 * Plugin configuration: schema, defaults, and validation.
 *
 * Configuration failures must fail loud and closed: the plugin refuses to
 * mount rather than silently degrading to a permissive policy.
 *
 * @module dsh-boundary-guard/config
 */
import z from '@deepseek-ai/schemastery'
import { GUARD_MODES, type GuardMode } from './types.ts'

/**
 * The plugin's configuration schema.
 *
 * Schemastery object fields are optional by construction; `default()` pins the
 * value a missing field resolves to. `dir` fields stay undefined unless set, so
 * the plugin can place its storage under the DSH home at runtime.
 */
export const Config = z.object({
  /** Mode a fresh session starts in. */
  defaultMode: z.union(['inspect', 'develop', 'maintain']).default('develop'),
  /** Extra absolute directories treated as writable in develop mode. */
  additionalWritableRoots: z.array(z.string()).default([]),
  /** Decision for tools the classifier cannot identify. */
  unknownToolPolicy: z.union(['ask', 'deny']).default('ask'),
  /** Structured audit logging. */
  audit: z
    .object({
      enabled: z.boolean().default(true),
      dir: z.string(),
      maxFileBytes: z.natural().default(8 * 1024 * 1024),
      retainDays: z.natural().default(90),
    })
    .default({}),
  /** Optional workspace snapshots taken before approved mutations. */
  snapshot: z
    .object({
      enabled: z.boolean().default(false),
      dir: z.string(),
      maxSnapshots: z.natural().default(20),
      maxFileBytes: z.natural().default(4 * 1024 * 1024),
    })
    .default({}),
  /** Maintain mode behavior. */
  maintain: z
    .object({
      maxDurationMs: z.natural().default(30 * 60 * 1000),
      requireConfirmation: z.boolean().default(true),
    })
    .default({}),
})

/**
 * The validated configuration shape handed to the plugin body. Schemastery
 * fills defaults; fields without a default may be absent.
 */
export interface ResolvedConfig {
  defaultMode: GuardMode
  additionalWritableRoots: string[]
  unknownToolPolicy: 'ask' | 'deny'
  audit: { enabled: boolean; dir?: string; maxFileBytes: number; retainDays: number }
  snapshot: { enabled: boolean; dir?: string; maxSnapshots: number; maxFileBytes: number }
  maintain: { maxDurationMs: number; requireConfirmation: boolean }
}

/** Audit configuration after default resolution. */
export interface ResolvedAuditConfig {
  enabled: boolean
  dir: string | undefined
  maxFileBytes: number
  retainDays: number
}

/** Snapshot configuration after default resolution. */
export interface ResolvedSnapshotConfig {
  enabled: boolean
  dir: string | undefined
  maxSnapshots: number
  maxFileBytes: number
}

/** Fully resolved configuration view used across the plugin. */
export interface GuardConfig {
  defaultMode: GuardMode
  additionalWritableRoots: string[]
  unknownToolPolicy: 'ask' | 'deny'
  audit: ResolvedAuditConfig
  snapshot: ResolvedSnapshotConfig
  maintain: { maxDurationMs: number; requireConfirmation: boolean }
}

/** Whether a string is an absolute path on Windows or POSIX. */
function isAbsolutePath(value: string): boolean {
  return /^([a-zA-Z]:[\\/]|\\\\|\/)/.test(value)
}

/**
 * Normalize a resolved config into the internal view, expanding `~` and
 * validating absolute paths. Throws on anything unusable so the plugin fails
 * loud instead of running with a broken policy.
 */
export function normalizeConfig(raw: ResolvedConfig, home: string): GuardConfig {
  const expand = (value: string, field: string): string => {
    let out = value
    if (out === '~') out = home
    else if (out.startsWith('~/') || out.startsWith('~\\')) out = home + out.slice(1)
    if (!isAbsolutePath(out)) {
      throw new Error(`dsh-boundary-guard: config field ${field} must be an absolute path, received ${JSON.stringify(value)}`)
    }
    return out.replace(/[\\/]+$/, '') || out
  }
  return {
    defaultMode: raw.defaultMode,
    additionalWritableRoots: raw.additionalWritableRoots.map((path) => expand(path, 'additionalWritableRoots')),
    unknownToolPolicy: raw.unknownToolPolicy,
    audit: {
      enabled: raw.audit.enabled,
      dir: raw.audit.dir === undefined ? undefined : expand(raw.audit.dir, 'audit.dir'),
      maxFileBytes: raw.audit.maxFileBytes,
      retainDays: raw.audit.retainDays,
    },
    snapshot: {
      enabled: raw.snapshot.enabled,
      dir: raw.snapshot.dir === undefined ? undefined : expand(raw.snapshot.dir, 'snapshot.dir'),
      maxSnapshots: raw.snapshot.maxSnapshots,
      maxFileBytes: raw.snapshot.maxFileBytes,
    },
    maintain: {
      maxDurationMs: raw.maintain.maxDurationMs,
      requireConfirmation: raw.maintain.requireConfirmation,
    },
  }
}

/** Validate a mode string from an untrusted source (command input). */
export function parseMode(value: string): GuardMode | undefined {
  const normalized = value.trim().toLowerCase()
  return (GUARD_MODES as readonly string[]).includes(normalized) ? (normalized as GuardMode) : undefined
}
