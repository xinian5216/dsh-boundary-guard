import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { containsSecret, redactSecrets, truncate } from '../../src/audit/sanitize.ts'
import { AuditLogger, sanitizeTarget } from '../../src/audit/logger.ts'
import { discoverProtectedRoots } from '../../src/boundary/protected.ts'
import { makeWorkspace } from '../helpers/fakes.ts'

test('redactSecrets masks API keys and tokens', () => {
  assert.equal(redactSecrets('token sk-abcdef1234567890'), 'token [REDACTED KEY]')
  assert.equal(redactSecrets('AKIAIOSFODNN7EXAMPLE'), '[REDACTED AWS KEY]')
  assert.equal(redactSecrets('ghp_1234567890abcdefghijklmnop'), '[REDACTED GITHUB TOKEN]')
  assert.equal(redactSecrets('Authorization: Bearer abcdefghijklmnopqrst'), 'Authorization: Bearer [REDACTED TOKEN]')
})

test('redactSecrets masks private key blocks', () => {
  const key = '-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----'
  const redacted = redactSecrets(key)
  assert.equal(redacted.includes('MIIEabc'), false)
  assert.match(redacted, /REDACTED PRIVATE KEY/)
})

test('redactSecrets masks key=value secrets', () => {
  assert.match(redactSecrets('api_key=supersecretvalue123'), /REDACTED/)
  assert.match(redactSecrets('password: hunter2hunter2'), /REDACTED/)
})

test('containsSecret detects redactable material', () => {
  assert.equal(containsSecret('sk-abcdef1234567890'), true)
  assert.equal(containsSecret('ordinary text'), false)
})

test('truncate marks the cut', () => {
  assert.equal(truncate('abcdef', 3), 'abc…[truncated 3 chars]')
  assert.equal(truncate('abc', 10), 'abc')
})

const roots = discoverProtectedRoots({
  homedir: '/home/tester',
  dshHome: '/home/tester/.dsh',
  agentsHome: '/home/tester/.agents',
  pluginRoot: '/opt/profile/node_modules/dsh-boundary-guard',
  platform: 'posix',
})

test('sanitizeTarget shows workspace-relative paths', () => {
  assert.equal(sanitizeTarget('/ws/src/index.ts', '/ws', roots, 'posix'), 'src/index.ts')
  assert.equal(sanitizeTarget('/ws', '/ws', roots, 'posix'), '.')
})

test('sanitizeTarget labels protected paths without exposing content', () => {
  assert.equal(sanitizeTarget('/home/tester/.ssh/id_ed25519', '/ws', roots, 'posix'), '<protected:credential>')
})

test('sanitizeTarget reduces out-of-workspace paths to their name', () => {
  assert.equal(sanitizeTarget('/etc/hosts', '/ws', roots, 'posix'), '<outside-workspace>/hosts')
})

test('audit records are written as JSONL and contain no secrets', async () => {
  const workspace = makeWorkspace()
  try {
    const logger = new AuditLogger({
      dir: workspace.root,
      maxFileBytes: 1024 * 1024,
      retainDays: 1,
      protectedRoots: roots,
      platform: 'posix',
    })
    logger.record({
      v: 1,
      time: Date.now(),
      sessionId: 'session-test',
      mode: 'develop',
      tool: 'bash',
      family: 'shell',
      operation: 'execute',
      risk: 'high',
      decision: 'deny',
      reasonCode: 'remote-operation',
      overridable: false,
      targets: ['src/index.ts', '<protected:credential>'],
      tags: ['network-upload'],
    })
    await logger.close()
    const files = logger.files()
    assert.equal(files.length, 1)
    const content = readFileSync(files[0] as string, 'utf8').trim()
    const record = JSON.parse(content) as Record<string, unknown>
    assert.equal(record.tool, 'bash')
    assert.equal(record.reasonCode, 'remote-operation')
    assert.equal(content.includes('sk-'), false)
  } finally {
    workspace.cleanup()
  }
})
