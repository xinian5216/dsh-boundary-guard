/**
 * Test helpers: synthetic sessions, workspaces, and classification inputs.
 *
 * All fixtures are synthetic: no real credentials, no real personal paths.
 *
 * @module tests/helpers/fakes
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Session, SESSION_FORMAT_VERSION } from '@deepseek-ai/dsh-session'
import type { SessionId } from '@deepseek-ai/dsh-session'
import type { ClassifiedOperation, PathFact, PolicyInput } from '../../src/types.ts'

/** Create an isolated temporary workspace. */
export interface FakeWorkspace {
  readonly root: string
  readonly cleanup: () => void
}

/** Create an isolated temporary workspace. */
export function makeWorkspace(): FakeWorkspace {
  const root = mkdtempSync(join(tmpdir(), 'boundary-guard-ws-'))
  return {
    root,
    cleanup: () => {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        // Best-effort cleanup.
      }
    },
  }
}

/** Create a file inside a workspace. */
export function writeWorkspaceFile(root: string, relative: string, content = 'x'): string {
  const target = join(root, relative)
  mkdirSync(join(target, '..'), { recursive: true })
  writeFileSync(target, content)
  return target
}

/** A detached real Session for policy and mode tests. */
export function makeSession(
  id: string,
  cwd: string | undefined,
  extra: { origin?: 'subagent'; parentSession?: string } = {},
): Session {
  const sessionId = id as SessionId
  return Session.create(sessionId, [], {
    version: SESSION_FORMAT_VERSION,
    id: sessionId,
    createdAt: Date.now(),
    isSeeded: false,
    ...(cwd === undefined ? {} : { cwd }),
    ...(extra.origin === undefined ? {} : { origin: extra.origin }),
    ...(extra.parentSession === undefined ? {} : { parentSession: extra.parentSession as SessionId }),
  })
}

/** The events appended to one session (for assertions). */
export function eventsOf(session: Session): { type: string; data: unknown }[] {
  const events: { type: string; data: unknown }[] = []
  for (let seq = 0; seq < session.seq; seq += 1) {
    const event = session.eventAt(seq as never)
    if (event !== undefined) events.push({ type: event.type, data: event.data })
  }
  return events
}

/** Build a path fact for tests without touching the filesystem. */
export function fact(absolute: string, overrides: Partial<PathFact> = {}): PathFact {
  return {
    absolute,
    viaLink: false,
    real: absolute,
    exists: false,
    isDirectory: false,
    ...overrides,
  }
}

/** Build a classified operation for engine tests. */
export function operation(overrides: Partial<ClassifiedOperation> = {}): ClassifiedOperation {
  return {
    toolName: 'write',
    toolFamily: 'fs-write',
    operation: 'write',
    risk: 'medium',
    targets: [],
    writeTargets: [],
    readTargets: [],
    tags: [],
    auditSummary: 'test operation',
    ...overrides,
  }
}

/** Build a policy input for engine tests. */
export function policyInput(overrides: Partial<PolicyInput> = {}): PolicyInput {
  return {
    mode: 'develop',
    workspaceRoot: '/ws',
    workingDirectory: '/ws',
    operation: operation(),
    additionalWritableRoots: [],
    unknownToolPolicy: 'ask',
    ...overrides,
  }
}
