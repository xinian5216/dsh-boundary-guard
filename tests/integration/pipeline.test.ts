import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { createGuardEnv, type GuardTestEnv } from './harness.ts'

const envs: GuardTestEnv[] = []

async function env(options: Parameters<typeof createGuardEnv>[0] = {}): Promise<GuardTestEnv> {
  const created = await createGuardEnv(options)
  envs.push(created)
  return created
}

after(async () => {
  for (const created of envs) await created.dispose()
})

test('the real pipeline runs the guard: a develop-mode workspace write succeeds', async () => {
  const guard = await env()
  const result = await guard.call('write', { file_path: join(guard.workspace.root, 'src/a.ts'), content: 'hello' })
  assert.equal(result.isError, false, result.text)
  assert.equal(guard.read('src/a.ts'), 'hello')
})

test('the real pipeline reads succeed in every mode', async () => {
  const guard = await env()
  await guard.call('write', { file_path: join(guard.workspace.root, 'a.ts'), content: 'content' })
  const read = await guard.call('read', { file_path: join(guard.workspace.root, 'a.ts') })
  assert.equal(read.isError, false)
  assert.match(read.text, /content/)
})

test('a denied write leaves the filesystem untouched', async () => {
  const guard = await env({ config: { defaultMode: 'inspect' } })
  const result = await guard.call('write', { file_path: join(guard.workspace.root, 'a.ts'), content: 'nope' })
  assert.equal(result.isError, true)
  assert.match(result.text, /inspect mode forbids/)
  assert.equal(guard.exists('a.ts'), false)
})

test('the guard backstop denies even when another listener prepends an allow', async () => {
  const guard = await env({ config: { defaultMode: 'inspect' } })
  // A hostile/naive plugin that tries to allow everything before the guard.
  guard.ctx.on('tools/pre-execute', async (_exec, next) => ({ kind: 'allow' }), { prepend: true })
  const result = await guard.call('write', { file_path: join(guard.workspace.root, 'a.ts'), content: 'nope' })
  assert.equal(result.isError, true, 'the monotonic guard must still deny')
  assert.equal(guard.exists('a.ts'), false)
})

test('an approved high-risk operation executes; a rejected one does not', async () => {
  const guard = await env()
  // `npm install` requires approval in develop mode.
  guard.answerWith(['allowed-once'])
  const approved = await guard.call('pwsh', { command: 'npm install --dry-run', description: 'install' })
  assert.equal(approved.isError, false, approved.text)

  guard.answerWith(['rejected'])
  const rejected = await guard.call('pwsh', { command: 'npm install --dry-run', description: 'install' })
  assert.equal(rejected.isError, true)
  assert.match(rejected.text, /rejected/)
})

test('a cancelled or unavailable approval never executes the operation', async () => {
  const guard = await env()
  guard.answerWith(['cancelled'])
  const cancelled = await guard.call('pwsh', { command: 'Remove-Item -Recurse -Force build', description: 'clean' })
  assert.equal(cancelled.isError, true)
  assert.match(cancelled.text, /cancelled/)

  guard.answerWith(['unavailable'])
  const unavailable = await guard.call('pwsh', { command: 'Remove-Item -Recurse -Force build', description: 'clean' })
  assert.equal(unavailable.isError, true)
  assert.match(unavailable.text, /approval channel/)
})

test('out-of-workspace writes are denied in develop mode', async () => {
  const guard = await env()
  const outside = join(guard.workspace.root, '..', `boundary-guard-outside-${Date.now()}.txt`)
  const result = await guard.call('write', { file_path: outside, content: 'nope' })
  assert.equal(result.isError, true)
  assert.match(result.text, /outside the authorized workspace/)
  const { existsSync } = await import('node:fs')
  assert.equal(existsSync(outside), false)
})

test('the /guard command switches modes and the pipeline follows', async () => {
  const guard = await env({ config: { defaultMode: 'develop' } })
  const inspect = await guard.command('/guard inspect')
  assert.equal(inspect.kind, 'success')
  assert.match(inspect.text ?? '', /inspect/)

  const blocked = await guard.call('write', { file_path: join(guard.workspace.root, 'a.ts'), content: 'nope' })
  assert.equal(blocked.isError, true)
  assert.equal(guard.exists('a.ts'), false)

  const develop = await guard.command('/guard develop')
  assert.equal(develop.kind, 'success')
  const allowed = await guard.call('write', { file_path: join(guard.workspace.root, 'a.ts'), content: 'yes' })
  assert.equal(allowed.isError, false, allowed.text)
  assert.equal(guard.read('a.ts'), 'yes')
})

test('/guard status reports the current mode and protection summary', async () => {
  const guard = await env()
  const status = await guard.command('/guard status')
  assert.equal(status.kind, 'success')
  assert.match(status.text ?? '', /Mode: develop/)
  assert.match(status.text ?? '', /Protected locations/)
})

test('protected paths cannot be overwritten in any mode', async () => {
  const guard = await env({ config: { defaultMode: 'maintain' } })
  const sshKey = join(process.env.USERPROFILE ?? process.env.HOME ?? '', '.ssh', 'id_ed25519')
  const result = await guard.call('write', { file_path: sshKey, content: 'overwritten' })
  assert.equal(result.isError, true)
  assert.match(result.text, /permanently protected/)
})

test('reading credential material asks for approval', async () => {
  const guard = await env()
  const envFile = join(guard.workspace.root, '.env')
  // Synthetic credential assembled at runtime: no secret-shaped literal in source.
  const syntheticToken = ['sk', '-test', '-1234567890'].join('')
  await guard.call('write', { file_path: envFile, content: `TOKEN=${syntheticToken}` })
  guard.answerWith(['rejected'])
  const result = await guard.call('read', { file_path: envFile })
  assert.equal(result.isError, true)
  assert.match(result.text, /rejected/)
})

test('maintain mode requires human confirmation and fails closed without one', async () => {
  const guard = await env({ config: { defaultMode: 'develop' } })
  // No user-questions answerer is composed in this harness: the confirmation
  // path must fail closed and leave the mode unchanged.
  const denied = await guard.command('/guard maintain 5')
  assert.equal(denied.kind, 'error')
  assert.match(denied.text ?? '', /not confirmed/)
  const status = await guard.command('/guard status')
  assert.match(status.text ?? '', /Mode: develop/)
})

test('maintain mode without confirmation applies a bounded grant that expires', async () => {
  const guard = await env({
    config: { defaultMode: 'develop', maintain: { maxDurationMs: 60000, requireConfirmation: false } },
  })
  const granted = await guard.command('/guard maintain 1')
  assert.equal(granted.kind, 'success')
  assert.match(granted.text ?? '', /maintain/)
  const status = await guard.command('/guard status')
  assert.match(status.text ?? '', /Mode: maintain/)
  // Out-of-workspace writes now require per-operation approval rather than a
  // blanket denial.
  const outside = join(tmpdir(), `boundary-guard-maint-${Date.now()}.txt`)
  try {
    guard.answerWith(['rejected'])
    const rejected = await guard.call('write', { file_path: outside, content: 'x' })
    assert.equal(rejected.isError, true)
    guard.answerWith(['allowed-once'])
    const approved = await guard.call('write', { file_path: outside, content: 'x' })
    assert.equal(approved.isError, false, approved.text)
  } finally {
    rmSync(outside, { force: true })
  }
  // Protected paths remain blocked even in maintain mode.
  const sshKey = join(process.env.USERPROFILE ?? process.env.HOME ?? '', '.ssh', 'id_ed25519')
  guard.answerWith(['allowed-once'])
  const protectedWrite = await guard.call('write', { file_path: sshKey, content: 'x' })
  assert.equal(protectedWrite.isError, true)
  assert.match(protectedWrite.text, /permanently protected/)
})
