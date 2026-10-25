/**
 * Pipeline-level coverage for the fail-closed sandbox rule: when the guard
 * cannot confirm the OS sandbox for a session, mutating operations are denied
 * and nothing executes; when the write path heals, the retry wired into the
 * execution flow restores normal operation without a restart.
 *
 * The sandbox write path is broken the way a real failure looks: the session
 * log refuses the `sandbox/mode` event. Everything else the harness and the
 * plugin append (turn markers, mode records) is forwarded untouched, so the
 * only broken thing is the OS-level synchronization.
 *
 * @module tests/security/sandbox-failclosed
 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Session } from '@deepseek-ai/dsh-session'
import { createGuardEnv, type GuardTestEnv } from '../integration/harness.ts'

const envs: GuardTestEnv[] = []

async function env(options: Parameters<typeof createGuardEnv>[0] = {}): Promise<GuardTestEnv> {
  const created = await createGuardEnv(options)
  envs.push(created)
  return created
}

after(async () => {
  for (const created of envs) await created.dispose()
})

/** A session whose `sandbox/mode` write path is intercepted. */
interface BrokenSandbox {
  /** How many `sandbox/mode` writes were attempted so far. */
  attempts: () => number
  /** Forget the attempts counted so far. */
  resetCounter: () => void
  /** Let the write path succeed again. */
  heal: () => void
}

/**
 * Break only the sandbox-mode write path of one session: every other event
 * still reaches the real `append`, so the harness's own turn markers and the
 * plugin's mode records keep working.
 */
function breakSandboxWrite(session: Session): BrokenSandbox {
  const original = session.append.bind(session) as (type: string, data: unknown, ...rest: unknown[]) => unknown
  let broken = true
  let attempts = 0
  Object.defineProperty(session, 'append', {
    configurable: true,
    value: (type: string, data: unknown, ...rest: unknown[]) => {
      if (broken && type === 'sandbox/mode') {
        attempts += 1
        throw new Error('simulated sandbox-policy write failure')
      }
      return original(type, data, ...rest)
    },
  })
  return {
    attempts: () => attempts,
    resetCounter: () => { attempts = 0 },
    heal: () => { broken = false },
  }
}

/**
 * A develop session whose sandbox write path is already known to be broken.
 * The mode state is initialized first (through `/guard status`) so a later
 * attempt count measures only the per-execution retries, not the first-touch
 * synchronization a fresh session performs.
 */
async function brokenDevelopSession(): Promise<{ guard: GuardTestEnv; broken: BrokenSandbox }> {
  const guard = await env({ config: { defaultMode: 'develop' } })
  const broken = breakSandboxWrite(guard.session)
  await guard.command('/guard status')
  broken.resetCounter()
  return { guard, broken }
}

// 1. A broken sandbox write fails closed: mutations are denied, reads still work.
test('a broken sandbox write denies mutations and leaves reads working', async () => {
  const { guard, broken } = await brokenDevelopSession()
  const target = join(guard.workspace.root, 'blocked.txt')
  const denied = await guard.call('write', { file_path: target, content: 'must not exist' })
  assert.equal(denied.isError, true, 'a mutating call must be denied while the sandbox is unconfirmed')
  assert.match(denied.text, /could not be confirmed/)
  assert.equal(existsSync(target), false, 'the denied write must not have executed')
  assert.equal(broken.attempts(), 1, 'the failed write path is retried once per execution')

  // Reads do not depend on the OS sandbox and stay available.
  writeFileSync(join(guard.workspace.root, 'readable.txt'), 'hello')
  const read = await guard.call('read', { file_path: join(guard.workspace.root, 'readable.txt') })
  assert.equal(read.isError, false, read.text)
  assert.match(read.text, /hello/)
})

// 2. Recovery: the retry is wired into the execution flow, not only recorded.
test('a healed sandbox write path lets the next mutating call through', async () => {
  const guard = await env({ config: { defaultMode: 'develop' } })
  const broken = breakSandboxWrite(guard.session)
  const blocked = join(guard.workspace.root, 'blocked.txt')
  const denied = await guard.call('write', { file_path: blocked, content: 'nope' })
  assert.equal(denied.isError, true)
  assert.equal(existsSync(blocked), false)

  broken.heal()
  const allowed = join(guard.workspace.root, 'allowed.txt')
  const recovered = await guard.call('write', { file_path: allowed, content: 'yes' })
  assert.equal(recovered.isError, false, `the retry must restore normal operation: ${recovered.text}`)
  assert.equal(guard.read('allowed.txt'), 'yes')
})

// 3. Concurrency: every concurrent call is denied and the write attempts stay
//    bounded at one retry per execution.
test('concurrent calls while the sandbox is broken are all denied without a write storm', async () => {
  const { guard, broken } = await brokenDevelopSession()
  const calls = 5
  const targets = Array.from({ length: calls }, (_, index) => join(guard.workspace.root, `blocked-${index}.txt`))
  const results = await Promise.all(targets.map((target) => guard.call('write', { file_path: target, content: 'nope' })))
  for (const [index, target] of targets.entries()) {
    assert.equal(results[index]?.isError, true, `call ${index} must be denied`)
    assert.equal(existsSync(target), false, `call ${index} must not have executed`)
  }
  assert.equal(broken.attempts(), calls, 'exactly one sandbox-mode write attempt per execution')

  // The status afterwards is coherent: nothing claims to be applied.
  const status = await guard.command('/guard status')
  assert.equal(status.kind, 'success')
  assert.match(status.text ?? '', /Sandbox file policy: workspace-write/)
  assert.match(status.text ?? '', /not confirmed applied/)
})

// 4. Mode switching: a stale successful sync never authorizes the new mode.
test('a failing sync to a stricter mode leaves the stale mode and stays denied', async () => {
  const guard = await env({
    config: { defaultMode: 'develop', maintain: { maxDurationMs: 600000, requireConfirmation: false } },
  })
  // develop → maintain succeeds while the write path is healthy.
  await guard.command('/guard maintain 10')
  const broken = breakSandboxWrite(guard.session)
  // maintain → inspect cannot be applied.
  await guard.command('/guard inspect')
  const target = join(guard.workspace.root, 'stale.txt')
  const denied = await guard.call('write', { file_path: target, content: 'nope' })
  assert.equal(denied.isError, true, 'a stale wider sandbox must not authorize the stricter mode')
  assert.match(denied.text, /could not be confirmed/)
  assert.equal(existsSync(target), false)

  const status = await guard.command('/guard status')
  assert.match(status.text ?? '', /Sandbox file policy: read-only/)
  assert.match(status.text ?? '', /last applied: danger-full-access/)

  broken.heal()
  // Inspect stays read-only by policy, so the recovery is shown by returning to
  // develop: the sandbox sync now succeeds and mutations are allowed again.
  await guard.command('/guard develop')
  const recovered = await guard.call('write', { file_path: target, content: 'yes' })
  assert.equal(recovered.isError, false, recovered.text)
  assert.equal(guard.read('stale.txt'), 'yes')
  const healed = await guard.command('/guard status')
  assert.match(healed.text ?? '', /Sandbox file policy: workspace-write \(applied and verified\)/)
})

// 5. The reverse switch (inspect → develop) behaves the same way.
test('a failing sync back to develop keeps inspect confinement until it recovers', async () => {
  const guard = await env({ config: { defaultMode: 'inspect' } })
  await guard.command('/guard inspect')
  const broken = breakSandboxWrite(guard.session)
  await guard.command('/guard develop')
  const target = join(guard.workspace.root, 'reverse.txt')
  const denied = await guard.call('write', { file_path: target, content: 'nope' })
  assert.equal(denied.isError, true, 'the stale read-only sandbox must not be reported as workspace-write')
  assert.match(denied.text, /could not be confirmed/)
  assert.equal(existsSync(target), false)

  const status = await guard.command('/guard status')
  assert.match(status.text ?? '', /Sandbox file policy: workspace-write/)
  assert.match(status.text ?? '', /last applied: read-only/)

  broken.heal()
  const recovered = await guard.call('write', { file_path: target, content: 'yes' })
  assert.equal(recovered.isError, false, recovered.text)
})

// 6. No false positives: a healthy sandbox never triggers the new rule.
test('a healthy sandbox does not block ordinary develop work', async () => {
  const guard = await env({ config: { defaultMode: 'develop' } })
  const root = guard.workspace.root
  writeFileSync(join(root, 'README.md'), '# test\n')
  const cases: [string, Record<string, unknown>][] = [
    ['read', { file_path: join(root, 'README.md') }],
    ['write', { file_path: join(root, 'src/a.ts'), content: 'export const a = 1\n' }],
    ['edit', { file_path: join(root, 'src/a.ts'), old_string: 'a = 1', new_string: 'a = 2' }],
    ['glob', { pattern: '**/*.ts', path: root }],
    ['grep', { pattern: 'export', path: root }],
  ]
  for (const [name, args] of cases) {
    const result = await guard.call(name, args)
    assert.equal(result.isError, false, `${name} must not be denied by the sandbox rule: ${result.text}`)
    assert.doesNotMatch(result.text, /sandbox-unavailable/)
  }
  if (guard.shellTool !== undefined) {
    const shell = await guard.call(guard.shellTool, { command: 'echo hello', description: 'benign' })
    assert.equal(shell.isError, false, shell.text)
    assert.doesNotMatch(shell.text, /sandbox-unavailable/)
  }
})

test('a healthy inspect session still runs read-only git commands', async (t) => {
  const guard = await env({ config: { defaultMode: 'inspect' } })
  if (guard.shellTool === undefined) {
    t.skip('no confined shell tool composed on this platform')
    return
  }
  const result = await guard.call(guard.shellTool, { command: 'git status', description: 'read-only git' })
  assert.equal(result.isError, false, result.text)
  assert.doesNotMatch(result.text, /sandbox-unavailable/)
})
