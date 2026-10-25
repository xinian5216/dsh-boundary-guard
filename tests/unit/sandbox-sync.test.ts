import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Session } from '@deepseek-ai/dsh-session'
import type { SandboxMode } from '@deepseek-ai/dsh-sandbox'
import { GuardModeManager, sandboxModeFor, type GuardModeManagerOptions } from '../../src/mode/manager.ts'
import { evaluatePolicy } from '../../src/policy/engine.ts'
import { discoverProtectedRoots } from '../../src/boundary/protected.ts'
import { fact, makeSession, operation, policyInput } from '../helpers/fakes.ts'

const HOME = '/home/tester'
const roots = discoverProtectedRoots({
  homedir: HOME,
  dshHome: '/home/tester/.dsh',
  agentsHome: '/home/tester/.agents',
  pluginRoot: '/opt/profile/node_modules/dsh-boundary-guard',
  platform: 'posix',
})

function makeManager(
  defaultMode: 'inspect' | 'develop' | 'maintain' = 'develop',
  options?: GuardModeManagerOptions,
) {
  return new GuardModeManager({
    defaultMode,
    additionalWritableRoots: [],
    unknownToolPolicy: 'ask',
    audit: { enabled: false, dir: undefined, maxFileBytes: 1, retainDays: 1 },
    snapshot: { enabled: false, dir: undefined, maxSnapshots: 1, maxFileBytes: 1 },
    maintain: { maxDurationMs: 1800000, requireConfirmation: true },
  }, undefined, options)
}

function decide(overrides: Parameters<typeof policyInput>[0] = {}) {
  return evaluatePolicy(policyInput(overrides), roots, 'posix')
}

/**
 * A real session whose public `append` fails, so the sandbox-mode write path
 * (`setSandboxMode`) throws while the plugin-record write path still works.
 */
function throwingAppendSession(id: string, cwd: string): Session {
  const session = makeSession(id, cwd)
  Object.defineProperty(session, 'append', {
    value: () => {
      throw new Error('simulated append failure')
    },
    configurable: true,
  })
  return session
}

test('BUG-1a: a fresh session syncs the OS sandbox to its default guard mode', () => {
  const manager = makeManager('inspect')
  const session = makeSession('session-init', '/ws')
  // Reading the effective mode is the first touch of a session.
  assert.equal(manager.effective(session).mode, 'inspect')
  const events: string[] = []
  for (let seq = 0; seq < session.seq; seq += 1) {
    const event = session.eventAt(seq as never) as { type: string; data: { mode?: string } } | undefined
    if (event?.type === 'sandbox/mode') events.push(event.data.mode ?? '')
  }
  assert.deepEqual(events, ['read-only'], 'the OS sandbox must be lowered when the guard starts in inspect mode')
})

test('BUG-1b: a failed sandbox sync is reported and can be retried', () => {
  const manager = makeManager('inspect')
  const session = throwingAppendSession('session-throwing', '/ws')
  manager.setMode(session, 'inspect')
  const status = manager.sandboxStatusOf(session)
  assert.equal(status.applied, undefined, 'a failed sync must not be reported as applied')
  assert.notEqual(status.lastError, undefined, 'a failed sync must surface its error')
  // A retry after the failure is possible: the marker is not stuck.
  manager.retrySandboxSync(session)
  const retried = manager.sandboxStatusOf(session)
  assert.notEqual(retried.lastError, undefined, 'the retry re-attempts and reports again')
  assert.equal(retried.applied, undefined, 'the retry still has not succeeded')
})

test('BUG-1c: a successful sandbox sync reports the applied mode', () => {
  const manager = makeManager('develop')
  const session = makeSession('session-ok', '/ws')
  manager.setMode(session, 'inspect')
  const status = manager.sandboxStatusOf(session)
  assert.equal(status.desired, 'read-only')
  assert.equal(status.applied, 'read-only')
  assert.equal(status.lastError, undefined)
})

// ---- Sandbox synchronization fails closed ---------------------------------

test('a successful sync is verified when a verifier is attached, and is not repeated', () => {
  let syncs = 0
  let observed: SandboxMode | undefined
  const manager = makeManager('develop', {
    sandboxSync: () => { syncs += 1 },
    verifySandbox: () => observed,
  })
  const session = makeSession('session-verified', '/ws')
  observed = 'workspace-write'
  manager.setMode(session, 'develop')
  const status = manager.sandboxStatusOf(session)
  assert.equal(status.applied, 'workspace-write')
  assert.equal(status.verified, true)
  assert.equal(status.observed, 'workspace-write')
  assert.equal(status.lastError, undefined)
  assert.equal(syncs, 1)
  // Idempotent: a later execution must not write the mode again.
  manager.ensureSandboxSynced(session)
  assert.equal(syncs, 1)
})

test('without a verifier a sync is applied but reported as unverified', () => {
  const manager = makeManager('develop')
  const session = makeSession('session-noverify', '/ws')
  manager.setMode(session, 'develop')
  const status = manager.sandboxStatusOf(session)
  assert.equal(status.applied, 'workspace-write')
  assert.equal(status.verified, false, 'a write nobody read back is not a confirmation')
  assert.equal(status.observed, undefined)
})

test('a synchronization slower than the timeout is a failure, not an application', () => {
  const manager = makeManager('inspect', {
    sandboxSync: () => {},
    verifySandbox: () => {
      const started = performance.now()
      while (performance.now() - started < 30) {}
      return 'read-only'
    },
    syncTimeoutMs: 1,
  })
  const session = makeSession('session-slow', '/ws')
  manager.setMode(session, 'inspect')
  const status = manager.sandboxStatusOf(session)
  assert.equal(status.applied, undefined, 'a timed-out sync must not be reported as applied')
  assert.match(status.lastError ?? '', /timed out/)
  const denied = decide({
    sandboxConfirmed: false,
    operation: operation({ writeTargets: [fact('/ws/a.ts')] }),
  })
  assert.equal(denied.decision, 'deny')
  assert.equal(denied.reasonCode, 'sandbox-unavailable')
})

test('a less restrictive observation fails the sync; a more restrictive one is accepted', () => {
  const loose = makeManager('inspect', {
    sandboxSync: () => {},
    verifySandbox: () => 'danger-full-access',
  })
  const looseSession = makeSession('session-loose', '/ws')
  loose.setMode(looseSession, 'inspect')
  const looseStatus = loose.sandboxStatusOf(looseSession)
  assert.equal(looseStatus.applied, undefined, 'the sandbox must never read back wider than requested')
  assert.match(looseStatus.lastError ?? '', /less restrictive/)

  const tight = makeManager('develop', {
    sandboxSync: () => {},
    verifySandbox: () => 'read-only',
  })
  const tightSession = makeSession('session-tight', '/ws')
  tight.setMode(tightSession, 'develop')
  const tightStatus = tight.sandboxStatusOf(tightSession)
  assert.equal(tightStatus.applied, 'workspace-write', 'a human lowering the sandbox is accepted')
  assert.equal(tightStatus.observed, 'read-only', 'divergence is reported')
  assert.equal(tightStatus.lastError, undefined)
})

test('ensureSandboxSynced retries once per execution and recovers when the write path heals', () => {
  let broken = true
  let attempts = 0
  const manager = makeManager('develop', {
    sandboxSync: () => {
      attempts += 1
      if (broken) throw new Error('sandbox policy write failed')
    },
  })
  const session = makeSession('session-retry', '/ws')
  const first = manager.ensureSandboxSynced(session)
  assert.equal(first.applied, undefined)
  assert.notEqual(first.lastError, undefined)
  // Bounded: the first touch of the session performs the initial sync and
  // `ensureSandboxSynced` then retries once — two writes for one execution,
  // never a loop.
  assert.equal(attempts, 2)
  broken = false
  const second = manager.ensureSandboxSynced(session)
  assert.equal(second.applied, 'workspace-write')
  assert.equal(second.lastError, undefined)
  const third = manager.ensureSandboxSynced(session)
  assert.equal(third.applied, 'workspace-write')
  assert.equal(attempts, 3, 'a healthy sync is not attempted again')
})

test('forget clears the sandbox state of a disposed session', () => {
  let fail = true
  const manager = makeManager('inspect', {
    sandboxSync: () => {
      if (fail) throw new Error('sandbox policy write failed')
    },
  })
  const session = makeSession('session-forget', '/ws')
  manager.setMode(session, 'inspect')
  assert.notEqual(manager.sandboxStatusOf(session).lastError, undefined)
  manager.forget(session)
  fail = false
  const after = manager.sandboxStatusOf(session)
  assert.equal(after.desired, sandboxModeFor('inspect'))
  assert.equal(after.lastError, undefined, 'the recorded failure must not survive forget()')
  assert.equal(after.applied, 'read-only')
})

test('an unconfirmed sandbox denies every mutating operation', () => {
  for (const kind of ['write', 'delete', 'execute', 'admin'] as const) {
    const result = decide({ sandboxConfirmed: false, operation: operation({ operation: kind }) })
    assert.equal(result.decision, 'deny', `${kind} must be denied while the sandbox is unconfirmed`)
    assert.equal(result.reasonCode, 'sandbox-unavailable')
    assert.equal(result.overridable, false, 'the rule is non-overridable')
    assert.match(result.reason, /could not be confirmed/)
  }
})

test('an unconfirmed sandbox does not block reads, searches, network, or delegation', () => {
  const read = decide({
    sandboxConfirmed: false,
    operation: operation({ toolName: 'read', toolFamily: 'fs-read', operation: 'read', readTargets: [fact('/ws/a.ts')] }),
  })
  assert.equal(read.decision, 'allow')
  assert.notEqual(read.reasonCode, 'sandbox-unavailable')
  const search = decide({
    sandboxConfirmed: false,
    operation: operation({ toolName: 'grep', toolFamily: 'search', operation: 'search' }),
  })
  assert.equal(search.decision, 'allow')
  const network = decide({
    sandboxConfirmed: false,
    operation: operation({ toolName: 'web_fetch', toolFamily: 'web', operation: 'network' }),
  })
  assert.equal(network.decision, 'allow')
  const delegate = decide({
    sandboxConfirmed: false,
    operation: operation({ toolName: 'task', toolFamily: 'delegate', operation: 'delegate' }),
  })
  assert.equal(delegate.decision, 'allow')
  // Meta tools that only read session state (todo lists, status) stay usable.
  const meta = decide({
    sandboxConfirmed: false,
    operation: operation({ toolName: 'todo_write', toolFamily: 'meta', operation: 'read' }),
  })
  assert.equal(meta.decision, 'allow')
})

test('a confirmed sandbox leaves every other decision unchanged', () => {
  const allowed = decide({ operation: operation({ writeTargets: [fact('/ws/src/index.ts')] }) })
  assert.equal(allowed.decision, 'allow')
  assert.equal(allowed.reasonCode, 'workspace-write-allowed')
  const protectedWrite = decide({ operation: operation({ writeTargets: [fact('/home/tester/.ssh/id_ed25519')] }) })
  assert.equal(protectedWrite.reasonCode, 'protected-path-write')
})

test('the sandbox rule sits below the protected-path rules', () => {
  const result = decide({
    sandboxConfirmed: false,
    operation: operation({ writeTargets: [fact('/home/tester/.ssh/id_ed25519')] }),
  })
  assert.equal(result.reasonCode, 'protected-path-write')
})

test('an expired maintain grant never re-widens the sandbox', async () => {
  const manager = makeManager('develop')
  const session = makeSession('session-expiry', '/ws')
  manager.setMode(session, 'maintain', { maintainDurationMs: 1 })
  await new Promise((resolve) => setTimeout(resolve, 10))
  // The grant has expired by the wall clock, so the effective mode is develop.
  assert.equal(manager.effective(session).mode, 'develop')
  const status = manager.ensureSandboxSynced(session)
  assert.equal(status.desired, 'workspace-write', 'the requirement follows the effective mode')
  assert.equal(status.applied, 'workspace-write')
  assert.equal(status.lastError, undefined)
})
