/**
 * Local structured audit logging.
 *
 * Records are appended as newline-delimited JSON under the DSH home, which the
 * policy engine protects from agent writes. The log deliberately stores
 * classifications and sanitized targets — never command text, file contents,
 * or secrets.
 *
 * @module dsh-boundary-guard/audit/logger
 */
import { createWriteStream, existsSync, mkdirSync, readdirSync, rmSync, statSync, type WriteStream } from 'node:fs'
import { join } from 'node:path'
import type { Decision, GuardMode, RiskLevel } from '../types.ts'
import { matchProtectedPath, type ProtectedRoot } from '../boundary/protected.ts'
import { isInside, type Platform } from '../boundary/paths.ts'

/** One audit record. Every field is sanitized by construction. */
export interface AuditRecord {
  /** Record schema version. */
  readonly v: 1
  /** Unix epoch ms. */
  readonly time: number
  /** Session id (opaque identifier, not personal data). */
  readonly sessionId: string
  readonly mode: GuardMode
  readonly tool: string
  readonly family: string
  readonly operation: string
  readonly risk: RiskLevel
  readonly decision: Decision
  readonly reasonCode: string
  readonly overridable: boolean
  /** Sanitized targets: workspace-relative, or a protection label. */
  readonly targets: readonly string[]
  readonly tags: readonly string[]
  /** Approval outcome when the decision was an ask. */
  readonly approval?: 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable' | 'not-required'
  /** Correlation id of the tool call. */
  readonly callId?: string
}

/** Options for the audit logger. */
export interface AuditLoggerOptions {
  readonly dir: string
  readonly maxFileBytes: number
  readonly retainDays: number
  readonly protectedRoots: readonly ProtectedRoot[]
  readonly platform: Platform
  readonly now?: () => number
}

/**
 * Append-only JSONL audit log with size rotation and age retention.
 * Write failures never propagate into the tool pipeline.
 */
export class AuditLogger {
  private readonly options: AuditLoggerOptions
  private stream: WriteStream | undefined
  private currentFile: string | undefined
  private currentBytes = 0
  private failed = false

  constructor(options: AuditLoggerOptions) {
    this.options = options
    try {
      mkdirSync(options.dir, { recursive: true })
      this.pruneOldFiles()
    } catch {
      this.failed = true
    }
  }

  /** Whether the logger is usable. */
  get available(): boolean {
    return !this.failed
  }

  /** Append one record. Never throws. */
  record(entry: AuditRecord): void {
    if (this.failed) return
    try {
      const stream = this.ensureStream()
      const line = `${JSON.stringify(entry)}\n`
      if (this.currentBytes + Buffer.byteLength(line) > this.options.maxFileBytes) {
        this.rotate()
      }
      this.stream?.write(line)
      this.currentBytes += Buffer.byteLength(line)
    } catch {
      // Audit is a local record, not the enforcement boundary; a write failure
      // is logged by the caller's diagnostics and must not fail the call.
      this.failed = true
    }
  }

  /** List current audit files (oldest first). */
  files(): string[] {
    try {
      return readdirSync(this.options.dir)
        .filter((name) => name.startsWith('audit-') && name.endsWith('.jsonl'))
        .sort()
        .map((name) => join(this.options.dir, name))
    } catch {
      return []
    }
  }

  private ensureStream(): WriteStream {
    if (this.stream !== undefined && this.currentFile !== undefined) return this.stream
    const now = this.options.now?.() ?? Date.now()
    const date = new Date(now).toISOString().slice(0, 10)
    let index = 0
    let file = join(this.options.dir, `audit-${date}-${index}.jsonl`)
    while (existsSync(file) && statSync(file).size > 0 && statSync(file).size >= this.options.maxFileBytes) {
      index += 1
      file = join(this.options.dir, `audit-${date}-${index}.jsonl`)
    }
    this.currentFile = file
    this.currentBytes = existsSync(file) ? statSync(file).size : 0
    this.stream = createWriteStream(file, { flags: 'a' })
    return this.stream
  }

  private rotate(): void {
    this.stream?.end()
    this.stream = undefined
    this.currentFile = undefined
    this.currentBytes = 0
    this.ensureStream()
  }

  private pruneOldFiles(): void {
    const cutoff = (this.options.now?.() ?? Date.now()) - this.options.retainDays * 24 * 60 * 60 * 1000
    for (const file of this.files()) {
      try {
        if (statSync(file).mtimeMs < cutoff) rmSync(file)
      } catch {
        // A file that vanished or is locked is left for the next pass.
      }
    }
  }

  /** Flush and close the stream (plugin disposal). */
  async close(): Promise<void> {
    await new Promise<void>((resolve) => {
      if (this.stream === undefined) {
        resolve()
        return
      }
      this.stream.end(() => resolve())
    })
    this.stream = undefined
    this.currentFile = undefined
  }
}

/**
 * Sanitize one target path for the audit log: workspace-relative inside the
 * workspace, a protection label for protected paths, and a basename outside.
 */
export function sanitizeTarget(
  absolutePath: string,
  workspaceRoot: string | undefined,
  protectedRoots: readonly ProtectedRoot[],
  platform: Platform,
): string {
  const match = matchProtectedPath(absolutePath, protectedRoots, platform)
  if (match !== undefined) return `<protected:${match.kind}>`
  if (workspaceRoot !== undefined) {
    if (isInside(workspaceRoot, absolutePath, platform)) {
      const relative = absolutePath.slice(workspaceRoot.length).replace(/^[\\/]+/, '')
      return relative === '' ? '.' : relative
    }
  }
  const name = absolutePath.split(/[\\/]/).pop() ?? absolutePath
  return `<outside-workspace>/${name}`
}
