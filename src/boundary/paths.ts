/**
 * Path normalization and workspace-boundary checks.
 *
 * Every check here is platform-aware: Windows comparisons are
 * case-insensitive, drive letters are normalized, UNC and `\\?\` spellings are
 * folded, alternate data streams are split off, and symlinks/junctions are
 * resolved through the deepest existing ancestor so a link cannot smuggle a
 * write past the boundary.
 *
 * @module dsh-boundary-guard/boundary/paths
 */
import { realpath, stat } from 'node:fs/promises'
import { win32, posix } from 'node:path'
import type { PathFact } from '../types.ts'

/** Platform selector for the pure helpers. */
export type Platform = 'win32' | 'posix'

/** The platform the guard is running on. */
export const currentPlatform: Platform = process.platform === 'win32' ? 'win32' : 'posix'

function pathApi(platform: Platform) {
  return platform === 'win32' ? win32 : posix
}

/** Join path segments using the given platform's separator rules. */
export function joinPath(platform: Platform, ...segments: string[]): string {
  return pathApi(platform).join(...segments)
}

/** Fold a `\\?\` or `\\?\UNC\` prefix into its ordinary spelling. */
function foldDevicePrefix(input: string, platform: Platform): string {
  if (platform !== 'win32') return input
  if (input.startsWith('\\\\?\\UNC\\')) return '\\' + input.slice(7)
  if (input.startsWith('\\\\?\\')) return input.slice(4)
  return input
}

/**
 * Split a Windows alternate data stream (`C:\a\b.txt:zone`) off its base path.
 * A colon inside a drive letter or UNC prefix is not a stream marker.
 */
export function splitAds(input: string, platform: Platform): { base: string; stream?: string } {
  if (platform !== 'win32') return { base: input }
  const colon = input.lastIndexOf(':')
  if (colon <= 0) return { base: input }
  const before = input.slice(0, colon)
  const after = input.slice(colon + 1)
  // Drive letter (`C:`), extended-length, or UNC prefixes are not streams.
  if (after.includes('\\') || after.includes('/') || after === '') return { base: input }
  if (/^[a-zA-Z]$/.test(before.slice(-1)) && before.length <= 3) return { base: input }
  if (before.startsWith('\\\\')) return { base: input }
  return { base: before, stream: after }
}

/** Uppercase a Windows drive letter and unify separators for comparison. */
function comparisonKey(input: string, platform: Platform): string {
  let value = foldDevicePrefix(input, platform)
  value = pathApi(platform).normalize(value)
  if (platform === 'win32') {
    value = value.replace(/\//g, '\\')
    // `c:\ws` and `C:\WS` are the same path on Windows: normalize the drive
    // letter to upper case and the rest to lower case.
    value = value.replace(/^([a-zA-Z]):/, (_match, drive: string) => drive.toUpperCase() + ':')
    value = value.slice(0, 2) + value.slice(2).toLowerCase()
  }
  return value.replace(/[\\/]+$/, '')
}

/**
 * Resolve `input` against `base` and normalize it without touching the
 * filesystem. Relative paths resolve against `base`; `~` is not expanded here.
 */
export function normalizePath(input: string, base: string | undefined, platform: Platform = currentPlatform): string {
  const api = pathApi(platform)
  const folded = foldDevicePrefix(input.trim(), platform)
  const resolved = api.isAbsolute(folded)
    ? api.normalize(folded)
    : api.resolve(base ?? process.cwd(), folded)
  return foldDevicePrefix(resolved, platform).replace(/[\\/]+$/, '') || resolved
}

/**
 * Segment-wise containment: `candidate` is inside `root` only when every
 * segment of `root` prefixes `candidate`. String-prefix checks would accept
 * `/ws-evil` for root `/ws`.
 */
export function isInside(root: string, candidate: string, platform: Platform = currentPlatform): boolean {
  const rootKey = comparisonKey(root, platform)
  const candidateKey = comparisonKey(candidate, platform)
  if (rootKey === candidateKey) return true
  const separator = platform === 'win32' ? '\\' : '/'
  const rootWithSep = rootKey.endsWith(separator) ? rootKey : rootKey + separator
  return candidateKey.startsWith(rootWithSep)
}

/** Whether the path names a filesystem root (`C:\`, `\\server\share`, `/`). */
export function isFilesystemRoot(input: string, platform: Platform = currentPlatform): boolean {
  const api = pathApi(platform)
  const key = comparisonKey(input, platform)
  return api.parse(key).root === key
}

/**
 * Resolve one path to a {@link PathFact}: lexical normalization, ADS split,
 * symlink resolution through the deepest existing ancestor, and existence
 * flags. Filesystem failures degrade to the lexical answer (fail closed at
 * the policy layer, never throw).
 */
export async function resolvePathFact(
  input: string,
  base: string | undefined,
  platform: Platform = currentPlatform,
): Promise<PathFact> {
  const { base: withoutStream, stream } = splitAds(input.trim(), platform)
  const absolute = normalizePath(withoutStream, base, platform)
  let real = absolute
  let viaLink = false
  let exists = false
  let isDirectory = false
  try {
    real = await realpath(absolute)
    exists = true
    const stats = await stat(real)
    isDirectory = stats.isDirectory()
  } catch {
    // The final component may not exist yet (a create). Resolve the deepest
    // existing ancestor so a symlinked parent is still caught.
    const api = pathApi(platform)
    let current = absolute
    const missing: string[] = []
    for (;;) {
      try {
        const resolved = await realpath(current)
        real = missing.length > 0 ? api.join(resolved, ...missing) : resolved
        if (resolved !== current) viaLink = true
        break
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code
        if (code !== 'ENOENT') break
        const parent = api.dirname(current)
        if (parent === current) break
        missing.unshift(api.basename(current))
        current = parent
      }
    }
  }
  return {
    absolute,
    viaLink,
    real: foldDevicePrefix(real, platform).replace(/[\\/]+$/, '') || real,
    ...(stream === undefined ? {} : { stream }),
    exists,
    isDirectory,
  }
}

/**
 * Whether a path escapes `root`.
 *
 * The comparison uses the canonical (realpath-resolved) spelling, which is the
 * only spelling that survives Windows 8.3 short-name aliases, junctions, and
 * symlinks: `C:\\Users\\RUNNER~1\\...` and `C:\\Users\\runneradmin\\...` name
 * the same directory. When the path could not be resolved at all, the lexical
 * spelling is used.
 */
export function escapesRoot(root: string, fact: PathFact, platform: Platform = currentPlatform): boolean {
  return !isInside(root, fact.real, platform)
}

/**
 * Build a path fact from lexical normalization only — no filesystem access.
 * Used by the synchronous guard, which must decide without I/O; its answers
 * are a subset of the async checker's (no symlink resolution) and therefore
 * only ever backstop the async policy decision.
 */
export function lexicalPathFact(input: string, base: string | undefined, platform: Platform = currentPlatform): PathFact {
  const { base: withoutStream, stream } = splitAds(input.trim(), platform)
  const absolute = normalizePath(withoutStream, base, platform)
  return {
    absolute,
    viaLink: false,
    real: absolute,
    ...(stream === undefined ? {} : { stream }),
    exists: false,
    isDirectory: false,
  }
}

/**
 * Canonicalize a root for boundary comparison: resolve symlinks and short-name
 * aliases when the path exists, otherwise return the normalized spelling.
 */
export async function canonicalizeRoot(root: string, platform: Platform = currentPlatform): Promise<string> {
  const normalized = normalizePath(root, undefined, platform)
  try {
    const resolved = await realpath(normalized)
    return foldDevicePrefix(resolved, platform).replace(/[\\/]+$/, '') || resolved
  } catch {
    return normalized
  }
}
