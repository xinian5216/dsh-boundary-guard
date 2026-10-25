import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evaluatePolicy } from '../../src/policy/engine.ts'
import { discoverProtectedRoots } from '../../src/boundary/protected.ts'
import { fact, operation, policyInput } from '../helpers/fakes.ts'

const HOME = '/home/tester'
const roots = discoverProtectedRoots({
  homedir: HOME,
  dshHome: '/home/tester/.dsh',
  agentsHome: '/home/tester/.agents',
  pluginRoot: '/opt/profile/node_modules/dsh-boundary-guard',
  platform: 'posix',
})

const WS = '/ws'

function decide(overrides: Parameters<typeof policyInput>[0] = {}) {
  return evaluatePolicy(policyInput(overrides), roots, 'posix')
}

test('develop allows a plain workspace write', () => {
  const result = decide({ operation: operation({ writeTargets: [fact('/ws/src/index.ts')] }) })
  assert.equal(result.decision, 'allow')
  assert.equal(result.reasonCode, 'workspace-write-allowed')
})

test('develop blocks writes outside the workspace', () => {
  const result = decide({ operation: operation({ writeTargets: [fact('/etc/passwd')] }) })
  assert.equal(result.decision, 'deny')
  assert.equal(result.reasonCode, 'outside-workspace-write')
})

test('protected paths are denied in every mode, including maintain', () => {
  for (const mode of ['inspect', 'develop', 'maintain'] as const) {
    const result = decide({ mode, operation: operation({ writeTargets: [fact('/home/tester/.ssh/id_ed25519')] }) })
    assert.equal(result.decision, 'deny', `${mode} must deny protected writes`)
    assert.equal(result.reasonCode, 'protected-path-write')
    assert.equal(result.overridable, false)
  }
})

test('the DSH home is denied for generic tools but not for privileged first-party tools', () => {
  const generic = decide({ operation: operation({ toolName: 'write', writeTargets: [fact('/home/tester/.dsh/boundary-guard/audit/audit.jsonl')] }) })
  assert.equal(generic.decision, 'deny')
  assert.equal(generic.reasonCode, 'dsh-home-write')
  const privileged = decide({ operation: operation({ toolName: 'plugin_manager', toolFamily: 'meta', operation: 'admin', writeTargets: [fact('/home/tester/.dsh/profiles/desktop/package.json')] }) })
  assert.notEqual(privileged.decision, 'deny')
})

test('inspect mode blocks writes and executions', () => {
  const write = decide({ mode: 'inspect', operation: operation({ writeTargets: [fact('/ws/a.ts')] }) })
  assert.equal(write.decision, 'deny')
  assert.equal(write.reasonCode, 'inspect-mode-write')
  const shell = decide({ mode: 'inspect', operation: operation({ toolName: 'bash', toolFamily: 'shell', operation: 'execute' }) })
  assert.equal(shell.decision, 'deny')
  assert.equal(shell.reasonCode, 'inspect-mode-write')
})

test('inspect mode allows reads and searches', () => {
  const read = decide({ mode: 'inspect', operation: operation({ toolName: 'read', toolFamily: 'fs-read', operation: 'read', readTargets: [fact('/ws/a.ts')] }) })
  assert.equal(read.decision, 'allow')
  const search = decide({ mode: 'inspect', operation: operation({ toolName: 'grep', toolFamily: 'search', operation: 'search' }) })
  assert.equal(search.decision, 'allow')
})

test('inspect mode denies reading credential material', () => {
  const result = decide({ mode: 'inspect', operation: operation({ toolName: 'read', toolFamily: 'fs-read', operation: 'read', readTargets: [fact('/home/tester/.ssh/id_ed25519')] }) })
  assert.equal(result.decision, 'deny')
  assert.equal(result.reasonCode, 'protected-path-read')
})

test('develop asks before reading credential material', () => {
  const result = decide({ operation: operation({ toolName: 'read', toolFamily: 'fs-read', operation: 'read', readTargets: [fact('/home/tester/.aws/credentials')] }) })
  assert.equal(result.decision, 'ask')
  assert.equal(result.reasonCode, 'credential-material')
})

test('deletes require approval in develop and maintain', () => {
  for (const mode of ['develop', 'maintain'] as const) {
    const result = decide({ mode, operation: operation({ toolName: 'bash', toolFamily: 'shell', operation: 'delete', tags: ['file-delete'], writeTargets: [fact('/ws/a.ts')] }) })
    assert.equal(result.decision, 'ask', `${mode} must ask for deletes`)
    assert.equal(result.reasonCode, 'delete-requires-approval')
  }
})

test('maintain asks per-operation for out-of-workspace writes', () => {
  const result = decide({ mode: 'maintain', operation: operation({ writeTargets: [fact('/etc/hosts')] }) })
  assert.equal(result.decision, 'ask')
  assert.equal(result.reasonCode, 'outside-workspace-approval')
})

test('high-value configuration overwrite requires approval', () => {
  const result = decide({ operation: operation({ writeTargets: [fact('/ws/package.json', { exists: true })] }) })
  assert.equal(result.decision, 'ask')
  assert.equal(result.reasonCode, 'high-value-config-overwrite')
})

test('unknown tools ask by default and deny under a strict policy', () => {
  const askResult = decide({ operation: operation({ toolName: 'mcp__foo', toolFamily: 'unknown', operation: 'unknown' }) })
  assert.equal(askResult.decision, 'ask')
  const denyResult = decide({ unknownToolPolicy: 'deny', operation: operation({ toolName: 'mcp__foo', toolFamily: 'unknown', operation: 'unknown' }) })
  assert.equal(denyResult.decision, 'deny')
  assert.equal(denyResult.reasonCode, 'unknown-tool')
})

test('sandbox escalation asks in develop and denies in inspect', () => {
  const develop = decide({ operation: operation({ tags: ['sandbox-escalation'] }) })
  assert.equal(develop.decision, 'ask')
  const inspect = decide({ mode: 'inspect', operation: operation({ tags: ['sandbox-escalation'] }) })
  assert.equal(inspect.decision, 'deny')
})

test('git push asks, global git config is denied', () => {
  const push = decide({ operation: operation({ toolName: 'bash', toolFamily: 'shell', operation: 'execute', tags: ['git-remote-write'] }) })
  assert.equal(push.decision, 'ask')
  assert.equal(push.reasonCode, 'git-remote-write')
  const globalConfig = decide({ operation: operation({ toolName: 'bash', toolFamily: 'shell', operation: 'execute', tags: ['git-global-config'] }) })
  assert.equal(globalConfig.decision, 'deny')
})

test('dynamic execution and bulk operations ask', () => {
  const dynamic = decide({ operation: operation({ toolName: 'run_code', toolFamily: 'code-exec', operation: 'execute', tags: ['dynamic-execution'] }) })
  assert.equal(dynamic.decision, 'ask')
  const bulk = decide({ operation: operation({ toolName: 'bash', toolFamily: 'shell', operation: 'execute', tags: ['bulk-operation'] }) })
  assert.equal(bulk.decision, 'ask')
})

test('safe read-only shell commands are allowed in develop', () => {
  const result = decide({ operation: operation({ toolName: 'bash', toolFamily: 'shell', operation: 'execute', risk: 'low', tags: ['git-read'] }) })
  assert.equal(result.decision, 'allow')
  assert.equal(result.reasonCode, 'safe-command')
})

test('additional writable roots extend the workspace', () => {
  const result = decide({
    additionalWritableRoots: ['/shared/build'],
    operation: operation({ writeTargets: [fact('/shared/build/out.o')] }),
  })
  assert.equal(result.decision, 'allow')
})

test('the engine fails closed on malformed input', () => {
  const result = evaluatePolicy(policyInput({ workspaceRoot: undefined }), roots, 'posix')
  assert.notEqual(result.decision, 'allow')
  const noRootWrite = evaluatePolicy(policyInput({
    workspaceRoot: undefined,
    operation: operation({ writeTargets: [fact('/somewhere/a.ts')] }),
  }), roots, 'posix')
  assert.notEqual(noRootWrite.decision, 'allow')
})
