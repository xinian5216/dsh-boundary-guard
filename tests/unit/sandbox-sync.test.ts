import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Session } from '@deepseek-ai/dsh-session'
import { GuardModeManager } from '../../src/mode/manager.ts'
import { makeSession } from '../helpers/fakes.ts'

function makeManager(defaultMode: 'inspect' | 'develop' | 'maintain' = 'develop') {
  return new GuardModeManager({
    defaultMode,
    additionalWritableRoots: [],
    unknownToolPolicy: 'ask',
    audit: { enabled: false, dir: undefined, maxFileBytes: 1, retainDays: 1 },
    snapshot: { enabled: false, dir: undefined, maxSnapshots: 1, maxFileBytes: 1 },
    maintain: { maxDurationMs: 1800000, requireConfirmation: true },
  })
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
