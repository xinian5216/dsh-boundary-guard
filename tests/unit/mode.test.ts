import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Config, normalizeConfig, parseMode } from '../../src/config.ts'
import { evaluatePolicy } from '../../src/policy/engine.ts'
import { discoverProtectedRoots } from '../../src/boundary/protected.ts'
import { fact, makeSession, operation, policyInput } from '../helpers/fakes.ts'
import { GuardModeManager } from '../../src/mode/manager.ts'
import { MODE_RECORD_TYPE } from '../../src/mode/projection.ts'
import z from '@deepseek-ai/schemastery'

const HOME = '/home/tester'
const roots = discoverProtectedRoots({
  homedir: HOME,
  dshHome: '/home/tester/.dsh',
  agentsHome: '/home/tester/.agents',
  pluginRoot: '/opt/profile/node_modules/dsh-boundary-guard',
  platform: 'posix',
})

test('parseMode accepts the three modes case-insensitively', () => {
  assert.equal(parseMode('Inspect'), 'inspect')
  assert.equal(parseMode(' DEVELOP '), 'develop')
  assert.equal(parseMode('maintain'), 'maintain')
  assert.equal(parseMode('root'), undefined)
})

test('normalizeConfig rejects relative paths', () => {
  assert.throws(() => normalizeConfig({
    defaultMode: 'develop',
    additionalWritableRoots: ['relative/path'],
    unknownToolPolicy: 'ask',
    audit: { enabled: true, maxFileBytes: 1, retainDays: 1 },
    snapshot: { enabled: false, maxSnapshots: 1, maxFileBytes: 1 },
    maintain: { maxDurationMs: 1, requireConfirmation: true },
  }, HOME))
})

test('normalizeConfig expands tilde paths', () => {
  const config = normalizeConfig({
    defaultMode: 'develop',
    additionalWritableRoots: ['~/shared'],
    unknownToolPolicy: 'ask',
    audit: { enabled: true, dir: '~/.dsh/boundary-guard/audit', maxFileBytes: 1, retainDays: 1 },
    snapshot: { enabled: false, maxSnapshots: 1, maxFileBytes: 1 },
    maintain: { maxDurationMs: 1, requireConfirmation: true },
  }, HOME)
  assert.deepEqual(config.additionalWritableRoots, ['/home/tester/shared'])
  assert.equal(config.audit.dir, '/home/tester/.dsh/boundary-guard/audit')
})

test('the config schema defaults are the safe documented ones', () => {
  const [value] = z.resolve({}, Config, {}) as unknown as [Record<string, unknown>]
  assert.equal(value.defaultMode, 'develop')
  assert.equal(value.unknownToolPolicy, 'ask')
  assert.deepEqual(value.additionalWritableRoots, [])
  assert.deepEqual(value.audit, { enabled: true, maxFileBytes: 8 * 1024 * 1024, retainDays: 90 })
  assert.deepEqual(value.maintain, { maxDurationMs: 1800000, requireConfirmation: true })
})

test('the config schema rejects an invalid mode', () => {
  assert.throws(() => z.resolve({ defaultMode: 'root' }, Config, {}))
})
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

test('a fresh session starts in the configured default mode', () => {
  const manager = makeManager('develop')
  const session = makeSession('session-1', '/ws')
  assert.equal(manager.effective(session).mode, 'develop')
})

test('mode changes are recorded as durable plugin records', () => {
  const manager = makeManager()
  const session = makeSession('session-1', '/ws')
  manager.setMode(session, 'inspect')
  const records: string[] = []
  for (let seq = 0; seq < session.seq; seq += 1) {
    const event = session.eventAt(seq as never)
    if (event !== undefined) records.push(event.type)
  }
  assert.ok(records.includes(MODE_RECORD_TYPE), `expected a ${MODE_RECORD_TYPE} record, saw ${records.join(', ')}`)
  assert.equal(manager.effective(session).mode, 'inspect')
})

test('an expired maintain grant falls back to develop', () => {
  const manager = makeManager()
  const session = makeSession('session-1', '/ws')
  manager.setMode(session, 'maintain', { maintainDurationMs: 1000 })
  assert.equal(manager.effective(session, Date.now() + 500).mode, 'maintain')
  const expired = manager.effective(session, Date.now() + 5000)
  assert.equal(expired.mode, 'develop')
  assert.equal(expired.expired, true)
})

test('a maintain grant is bounded by the configured maximum', () => {
  const manager = makeManager()
  const session = makeSession('session-1', '/ws')
  const state = manager.setMode(session, 'maintain', { maintainDurationMs: 10 * 60 * 1000 })
  const granted = (state.maintainExpiresAt ?? 0) - Date.now()
  assert.ok(granted <= 1800000 + 50, 'grant must not exceed the configured maximum')
})

test('subagent inheritance never exceeds the parent', () => {
  const manager = makeManager('develop')
  const parent = makeSession('session-parent', '/ws')
  manager.setMode(parent, 'inspect')
  const child = makeSession('session-child', '/ws', { origin: 'subagent', parentSession: 'session-parent' })
  const inherited = manager.inheritForSubagent(child, 'session-parent')
  assert.equal(inherited, 'inspect')
  assert.equal(manager.effective(child).mode, 'inspect')
})

test('a subagent with an unknown parent fails closed to inspect', () => {
  const manager = makeManager('develop')
  const child = makeSession('session-child', '/ws', { origin: 'subagent', parentSession: 'session-missing' })
  const inherited = manager.inheritForSubagent(child, 'session-missing')
  assert.equal(inherited, 'inspect')
})

test('a subagent of a maintain parent keeps the parent expiry window', () => {
  const manager = makeManager('develop')
  const parent = makeSession('session-parent', '/ws')
  const parentState = manager.setMode(parent, 'maintain', { maintainDurationMs: 60000 })
  const child = makeSession('session-child', '/ws', { origin: 'subagent', parentSession: 'session-parent' })
  manager.inheritForSubagent(child, 'session-parent')
  const childState = manager.stateOf(child)
  assert.equal(childState.mode, 'maintain')
  assert.equal(childState.maintainExpiresAt, parentState.maintainExpiresAt)
})

test('inheritance is applied once per session', () => {
  const manager = makeManager('develop')
  const parent = makeSession('session-parent', '/ws')
  manager.setMode(parent, 'develop')
  const child = makeSession('session-child', '/ws', { origin: 'subagent', parentSession: 'session-parent' })
  assert.equal(manager.inheritForSubagent(child, 'session-parent'), 'develop')
  assert.equal(manager.inheritForSubagent(child, 'session-parent'), undefined)
})

test('the engine denies inspect-mode writes for an inherited inspect child', () => {
  const manager = makeManager('develop')
  const parent = makeSession('session-parent', '/ws')
  manager.setMode(parent, 'inspect')
  const child = makeSession('session-child', '/ws', { origin: 'subagent', parentSession: 'session-parent' })
  manager.inheritForSubagent(child, 'session-parent')
  const result = evaluatePolicy(policyInput({
    mode: manager.effective(child).mode,
    operation: operation({ writeTargets: [fact('/ws/a.ts')] }),
  }), roots, 'posix')
  assert.equal(result.decision, 'deny')
})

test('forget drops session state', () => {
  const manager = makeManager()
  const session = makeSession('session-1', '/ws')
  manager.setMode(session, 'inspect')
  manager.forget(session)
  assert.equal(manager.effective(session).mode, 'develop')
})
