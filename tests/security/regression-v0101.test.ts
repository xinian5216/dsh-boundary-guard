import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { defineTool } from '@deepseek-ai/dsh-tools'
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

/**
 * Register a tool the guard cannot classify, the way an MCP server's tools
 * arrive: registered in DSH, unknown to the policy engine.
 */
function registerUnknownTool(guard: GuardTestEnv, name: string, target: string): void {
  guard.ctx.tools.register(defineTool({
    name,
    description: 'Synthetic unclassified tool used to exercise the unknown-tool policy.',
    parameters: {
      content: { type: 'string', required: true, description: 'content to write' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: String(value) }],
    },
    async execute(args: { content: string }) {
      writeFileSync(target, args.content)
      return `wrote ${target}`
    },
  }))
}

// 2. Inspect must not be able to approve an unknown tool with side effects.
test('BUG-2: inspect mode denies unknown tools even when the user approves', async () => {
  const guard = await env({ config: { defaultMode: 'inspect', unknownToolPolicy: 'ask' } })
  const target = join(guard.workspace.root, 'mcp-write.txt')
  registerUnknownTool(guard, 'mcp__synthetic__write_file', target)
  guard.answerWith(['allowed-once'])
  const result = await guard.call('mcp__synthetic__write_file', { content: 'pwned' })
  assert.equal(result.isError, true, 'an unknown tool must not be approvable in inspect mode')
  assert.equal(existsSync(target), false, 'the unknown tool must not have executed')
})

// 3. Read-only Git commands must work in inspect mode.
test('BUG-3: read-only git commands are allowed in inspect mode', async (t) => {
  const guard = await env({ config: { defaultMode: 'inspect' } })
  if (guard.shellTool === undefined) {
    t.skip('no confined shell tool composed on this platform')
    return
  }
  const root = guard.workspace.root
  // A real repository so git read commands have something to report.
  const { execFileSync } = await import('node:child_process')
  try {
    execFileSync('git', ['init', '-q'], { cwd: root })
    execFileSync('git', ['config', 'user.email', 'guard@example.invalid'], { cwd: root })
    execFileSync('git', ['config', 'user.name', 'Guard Test'], { cwd: root })
    writeFileSync(join(root, 'README.md'), '# test\n')
    execFileSync('git', ['add', '-A'], { cwd: root })
    execFileSync('git', ['commit', '-q', '-m', 'init'], { cwd: root })
  } catch {
    t.skip('git is unavailable in this environment')
    return
  }
  for (const command of ['git status', 'git log --oneline', 'git diff --stat', 'git show --stat HEAD']) {
    const result = await guard.call(guard.shellTool, { command, description: 'read-only git' })
    assert.equal(result.isError, false, `${command} must be allowed in inspect mode: ${result.text}`)
  }
})

// 4. Maintain mode must not let an approved opaque script touch protected paths.
test('BUG-4: approved opaque scripts cannot indirectly write protected paths', async (t) => {
  // The test never touches the real user profile. An isolated fake home is
  // created and exported through every variable the plugin (which derives its
  // protected roots from `os.homedir()` at load time) and the confined shell
  // child (which inherits the parent environment) read, so a regression fails
  // against a throwaway directory instead of a real one.
  const fakeHome = mkdtempSync(join(tmpdir(), 'boundary-guard-home-'))
  const previous = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    DSH_HOME: process.env.DSH_HOME,
    DSH_AGENTS_HOME: process.env.DSH_AGENTS_HOME,
  }
  try {
    process.env.HOME = fakeHome
    process.env.USERPROFILE = fakeHome
    // The plugin also reads the DSH homes from the environment; pointing them
    // inside the fake home keeps the whole composition hermetic even though
    // `scrubbedParentEnv()` strips `DSH_*` names for child processes.
    process.env.DSH_HOME = join(fakeHome, '.dsh')
    process.env.DSH_AGENTS_HOME = join(fakeHome, '.agents')
    const guard = await env({
      config: { defaultMode: 'maintain', maintain: { maxDurationMs: 600000, requireConfirmation: false } },
    })
    if (guard.shellTool === undefined) {
      t.skip('no confined shell tool composed on this platform')
      return
    }
    await guard.command('/guard maintain 10')
    const protectedTarget = join(fakeHome, '.ssh', 'boundary-guard-indirect-test.txt')
    guard.answerWith(['allowed-once'])
    // An opaque nested invocation whose write target is built at runtime.
    const result = await guard.call(guard.shellTool, {
      command: process.platform === 'win32'
        ? `cmd /c "echo indirect > %USERPROFILE%\\.ssh\\boundary-guard-indirect-test.txt"`
        : `sh -c 'echo indirect > "$HOME/.ssh/boundary-guard-indirect-test.txt"'`,
      description: 'indirect write',
    })
    assert.equal(result.isError, true, 'an approved script must not write protected paths indirectly')
    assert.equal(existsSync(protectedTarget), false, 'the protected file must not exist')
    assert.equal(existsSync(join(fakeHome, '.ssh')), false, 'the protected directory must never be created')
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
    rmSync(fakeHome, { recursive: true, force: true })
  }
})

// 5. Develop experience must stay usable on both platforms.
test('BUG-5: ordinary develop operations are not blocked on this platform', async (t) => {
  const guard = await env({ config: { defaultMode: 'develop' } })
  const root = guard.workspace.root
  mkdirSync(join(root, 'src'), { recursive: true })
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
    assert.equal(result.isError, false, `${name} should be allowed in develop mode: ${result.text}`)
  }
  if (guard.shellTool === undefined) {
    t.skip('shell assertions skipped on this platform')
    return
  }
  const shellCases = process.platform === 'win32'
    ? ['git status', 'echo hello', 'Get-ChildItem', 'Set-Content -Path notes.txt -Value hi']
    : ['git status', 'echo hello', 'ls -la', 'echo hi > notes.txt']
  for (const command of shellCases) {
    const result = await guard.call(guard.shellTool, { command, description: 'benign' })
    assert.equal(result.isError, false, `${command} should be allowed in develop mode: ${result.text}`)
  }
})
