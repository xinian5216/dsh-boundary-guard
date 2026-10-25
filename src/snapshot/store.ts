/**
 * Optional workspace snapshots taken before approved mutations.
 *
 * A snapshot is a local, per-workspace copy of file contents — a convenience
 * restore point for the *files this plugin saw change*, NOT a universal undo.
 * Databases, remote servers, and out-of-band process side effects are not
 * captured and cannot be restored from here.
 *
 * @module dsh-boundary-guard/snapshot/store
 */
import { copyFile, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { dirname, join, relative, resolve } from 'node:path'
import { existsSync } from 'node:fs'

/** One captured file inside a snapshot. */
export interface SnapshotFile {
  /** Path relative to the workspace root. */
  readonly path: string
  /** Whether the file existed when the snapshot was taken. */
  readonly existed: boolean
  /** Bytes captured. */
  readonly bytes: number
  /** Whether the file was truncated because it exceeded the size cap. */
  readonly truncated: boolean
}

/** One snapshot manifest. */
export interface SnapshotManifest {
  readonly id: string
  /** Unix epoch ms. */
  readonly time: number
  /** Session id that triggered the snapshot. */
  readonly sessionId: string
  /** Tool and reason code that triggered the snapshot. */
  readonly trigger: string
  readonly files: readonly SnapshotFile[]
  /** Workspace root the snapshot belongs to (stored in the protected home). */
  readonly workspaceRoot: string
}

/** Options for the snapshot store. */
export interface SnapshotStoreOptions {
  readonly dir: string
  readonly maxSnapshots: number
  readonly maxFileBytes: number
}

/** Snapshot capture and restore for one workspace root set. */
export class SnapshotStore {
  private readonly options: SnapshotStoreOptions

  constructor(options: SnapshotStoreOptions) {
    this.options = options
  }

  /** Directory holding one workspace's snapshots. */
  private workspaceDir(workspaceRoot: string): string {
    const slug = createHash('sha256').update(resolve(workspaceRoot)).digest('hex').slice(0, 16)
    return join(this.options.dir, `ws-${slug}`)
  }

  /**
   * Capture the current contents of existing files before a mutation.
   * Missing files are recorded as absent (restore deletes them).
   */
  async capture(workspaceRoot: string, sessionId: string, trigger: string, files: readonly string[]): Promise<SnapshotManifest> {
    const root = resolve(workspaceRoot)
    const id = `${Date.now().toString(36)}-${createHash('sha256').update(`${sessionId}:${trigger}:${Math.random()}`).digest('hex').slice(0, 8)}`
    const dir = join(this.workspaceDir(root), id)
    await mkdir(dir, { recursive: true })
    const captured: SnapshotFile[] = []
    for (const file of files) {
      const absolute = resolve(root, file)
      const rel = relative(root, absolute)
      if (rel.startsWith('..')) continue
      if (!existsSync(absolute)) {
        captured.push({ path: rel, existed: false, bytes: 0, truncated: false })
        continue
      }
      const stats = await stat(absolute)
      if (!stats.isFile()) continue
      const truncated = stats.size > this.options.maxFileBytes
      const content = truncated ? await readFile(absolute).then((buffer) => buffer.subarray(0, this.options.maxFileBytes)) : await readFile(absolute)
      const target = join(dir, 'files', rel)
      await mkdir(dirname(target), { recursive: true })
      await copyFile(absolute, target)
      captured.push({ path: rel, existed: true, bytes: content.length, truncated })
    }
    const manifest: SnapshotManifest = {
      id,
      time: Date.now(),
      sessionId,
      trigger,
      files: captured,
      workspaceRoot: root,
    }
    await writeFile(join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8')
    await this.prune(root)
    return manifest
  }

  /** List snapshots for one workspace, newest first. */
  async list(workspaceRoot: string): Promise<SnapshotManifest[]> {
    const dir = this.workspaceDir(resolve(workspaceRoot))
    let entries: string[]
    try {
      entries = await readdir(dir)
    } catch {
      return []
    }
    const manifests: SnapshotManifest[] = []
    for (const entry of entries) {
      try {
        manifests.push(JSON.parse(await readFile(join(dir, entry, 'manifest.json'), 'utf8')) as SnapshotManifest)
      } catch {
        // A snapshot without a readable manifest is skipped, never guessed at.
      }
    }
    return manifests.sort((a, b) => b.time - a.time)
  }

  /** Restore one snapshot into its workspace. */
  async restore(manifest: SnapshotManifest): Promise<{ restored: number; deleted: number }> {
    const root = resolve(manifest.workspaceRoot)
    const dir = join(this.workspaceDir(root), manifest.id)
    let restored = 0
    let deleted = 0
    for (const file of manifest.files) {
      const target = resolve(root, file.path)
      const source = join(dir, 'files', file.path)
      if (!file.existed) {
        if (existsSync(target)) {
          await rm(target, { force: true })
          deleted += 1
        }
        continue
      }
      await mkdir(dirname(target), { recursive: true })
      await copyFile(source, target)
      restored += 1
    }
    return { restored, deleted }
  }

  /** Remove one snapshot. */
  async remove(manifest: SnapshotManifest): Promise<void> {
    await rm(join(this.workspaceDir(resolve(manifest.workspaceRoot)), manifest.id), { recursive: true, force: true })
  }

  private async prune(root: string): Promise<void> {
    const manifests = await this.list(root)
    for (const manifest of manifests.slice(this.options.maxSnapshots)) {
      await this.remove(manifest)
    }
  }
}
