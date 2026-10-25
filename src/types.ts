/**
 * Core vocabulary for DSH Boundary Guard.
 *
 * @module dsh-boundary-guard/types
 */

/** The three operating modes. Ordered from most to least restrictive. */
export type GuardMode = 'inspect' | 'develop' | 'maintain'

/** Every mode, most restrictive first. */
export const GUARD_MODES: readonly GuardMode[] = ['inspect', 'develop', 'maintain']

/** Whether one mode is at least as restrictive as another. */
export function isAtLeastAsRestrictive(candidate: GuardMode, floor: GuardMode): boolean {
  return GUARD_MODES.indexOf(candidate) <= GUARD_MODES.indexOf(floor)
}

/** The more restrictive of two modes. */
export function mostRestrictive(a: GuardMode, b: GuardMode): GuardMode {
  return GUARD_MODES.indexOf(a) <= GUARD_MODES.indexOf(b) ? a : b
}

/** The policy outcome of one evaluation. */
export type Decision = 'allow' | 'deny' | 'ask'

/** Risk tier attached to a classified operation. */
export type RiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

/** What an operation does, independent of the tool that performs it. */
export type OperationClass =
  | 'read'
  | 'search'
  | 'write'
  | 'delete'
  | 'execute'
  | 'network'
  | 'delegate'
  | 'admin'
  | 'unknown'

/**
 * Stable, human-readable reason codes. Every decision carries exactly one so
 * users and logs can tell why the guard acted.
 */
export type ReasonCode =
  // Non-overridable safety constraints (highest priority).
  | 'protected-path-write'
  | 'protected-path-read'
  | 'dsh-home-write'
  | 'plugin-self-write'
  | 'inspect-mode-write'
  | 'inspect-mode-execute'
  | 'sandbox-unavailable'
  | 'internal-error'
  // Explicit denials.
  | 'outside-workspace-write'
  | 'unknown-tool'
  | 'sandbox-escalation'
  | 'working-directory-escape'
  | 'credential-material'
  // Approval requirements.
  | 'delete-requires-approval'
  | 'high-value-config-overwrite'
  | 'bulk-operation'
  | 'dependency-install'
  | 'git-state-change'
  | 'git-history-rewrite'
  | 'git-remote-write'
  | 'remote-operation'
  | 'destructive-command'
  | 'dynamic-execution'
  | 'privilege-escalation'
  | 'system-config'
  | 'process-control'
  | 'outside-workspace-approval'
  | 'maintain-only-operation'
  | 'unknown-tool-approval'
  // Allowances.
  | 'read-allowed'
  | 'workspace-write-allowed'
  | 'safe-command'
  | 'first-party-tool'
  // Default denial.
  | 'default-deny'

/** One normalized target path with the facts the boundary checks proved. */
export interface PathFact {
  /** Absolute, normalized path as resolved for the check. */
  readonly absolute: string
  /** Whether the path (or its deepest existing ancestor) is a symlink/junction. */
  readonly viaLink: boolean
  /** The absolute path after resolving symlinks where they exist. */
  readonly real: string
  /** Windows alternate data stream suffix, when present. */
  readonly stream?: string
  /** Whether the path exists as a regular file. */
  readonly exists: boolean
  /** Whether the path exists as a directory. */
  readonly isDirectory: boolean
}

/** A classified tool call, ready for policy evaluation. */
export interface ClassifiedOperation {
  /** Registry tool name. */
  readonly toolName: string
  /** Coarse tool family used by rule tables. */
  readonly toolFamily: ToolFamily
  /** What the operation does. */
  readonly operation: OperationClass
  /** Risk tier of the operation itself, before mode and path rules. */
  readonly risk: RiskLevel
  /** All normalized target paths the operation touches. */
  readonly targets: readonly PathFact[]
  /** Subset of targets the operation may write, delete, or administer. */
  readonly writeTargets: readonly PathFact[]
  /** Subset of targets the operation only reads. */
  readonly readTargets: readonly PathFact[]
  /** Specific risk tags found while classifying (e.g. `git-push`). */
  readonly tags: readonly string[]
  /**
   * Sanitized one-line summary safe for audit logs. Never contains secrets or
   * full command text.
   */
  readonly auditSummary: string
}

/** Coarse tool families shared by the rule tables. */
export type ToolFamily =
  | 'fs-read'
  | 'fs-write'
  | 'search'
  | 'shell'
  | 'git'
  | 'package'
  | 'remote'
  | 'code-exec'
  | 'delegate'
  | 'web'
  | 'jobs'
  | 'meta'
  | 'unknown'

/** Everything the policy engine needs to decide one call. */
export interface PolicyInput {
  /** Effective guard mode for the calling session. */
  readonly mode: GuardMode
  /** Immutable workspace root (session cwd) when the session has one. */
  readonly workspaceRoot: string | undefined
  /** Effective mutable working directory, when known. */
  readonly workingDirectory: string | undefined
  /** The classified operation. */
  readonly operation: ClassifiedOperation
  /** Configured extra writable roots (absolute, normalized). */
  readonly additionalWritableRoots: readonly string[]
  /** Configured policy for tools the classifier does not know. */
  readonly unknownToolPolicy: 'ask' | 'deny'
  /**
   * Whether the OS sandbox was confirmed for this session. The guard lowers
   * the session sandbox to match the mode; when that write (or its read-back)
   * cannot be confirmed, every operation that depends on the sandbox is denied
   * instead of running with weaker confinement than the mode promises.
   */
  readonly sandboxConfirmed: boolean
}

/** The engine's decision with its auditable explanation. */
export interface PolicyResult {
  readonly decision: Decision
  readonly reasonCode: ReasonCode
  /** Short, model- and user-facing explanation (no secrets). */
  readonly reason: string
  /** Risk tier carried for audit and approval presentation. */
  readonly risk: RiskLevel
  /** Whether a later listener may re-allow this decision (never for denials). */
  readonly overridable: boolean
}
