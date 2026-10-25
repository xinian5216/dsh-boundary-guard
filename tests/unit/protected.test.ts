import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  discoverProtectedRoots,
  isHighValueConfig,
  matchProtectedPath,
} from '../../src/boundary/protected.ts'

const HOME = '/home/tester'
const DSH_HOME = '/home/tester/.dsh'
const AGENTS_HOME = '/home/tester/.agents'
const PLUGIN_ROOT = '/opt/profile/node_modules/dsh-boundary-guard'

const roots = discoverProtectedRoots({
  homedir: HOME,
  dshHome: DSH_HOME,
  agentsHome: AGENTS_HOME,
  pluginRoot: PLUGIN_ROOT,
  platform: 'posix',
})

test('SSH keys and cloud credentials are protected', () => {
  for (const path of [
    '/home/tester/.ssh/id_ed25519',
    '/home/tester/.ssh/config',
    '/home/tester/.aws/credentials',
    '/home/tester/.azure/accessTokens.json',
    '/home/tester/.kube/config',
    '/home/tester/.gnupg/secring.gpg',
  ]) {
    const match = matchProtectedPath(path, roots, 'posix')
    assert.notEqual(match, undefined, `${path} should be protected`)
    assert.equal(match?.kind, 'credential')
  }
})

test('dotenv files are protected wherever they sit', () => {
  const match = matchProtectedPath('/ws/project/.env', roots, 'posix')
  assert.notEqual(match, undefined)
  assert.equal(match?.kind, 'credential')
  assert.notEqual(matchProtectedPath('/ws/project/.env.production', roots, 'posix'), undefined)
})

test('other AI clients global configuration is protected from writes', () => {
  for (const path of [
    '/home/tester/.codex/config.toml',
    '/home/tester/.claude/settings.json',
    '/home/tester/.claude.json',
    '/home/tester/.opencode/opencode.json',
  ]) {
    const match = matchProtectedPath(path, roots, 'posix')
    assert.notEqual(match, undefined, `${path} should be protected`)
    assert.equal(match?.kind, 'ai-client-config')
  }
})

test('the DSH home and the plugin installation are protected', () => {
  assert.equal(matchProtectedPath('/home/tester/.dsh/.credentials.yaml', roots, 'posix')?.kind, 'dsh-home')
  assert.equal(matchProtectedPath('/opt/profile/node_modules/dsh-boundary-guard/lib/index.js', roots, 'posix')?.kind, 'plugin-self')
})

test('ordinary project files are not protected', () => {
  assert.equal(matchProtectedPath('/ws/src/index.ts', roots, 'posix'), undefined)
  assert.equal(matchProtectedPath('/ws/README.md', roots, 'posix'), undefined)
})

test('protected roots never depend on one machine absolute layout', () => {
  const other = discoverProtectedRoots({
    homedir: '/Users/someone',
    dshHome: '/Users/someone/.dsh',
    agentsHome: '/Users/someone/.agents',
    pluginRoot: '/Users/someone/.dsh/profiles/web/node_modules/dsh-boundary-guard',
    platform: 'posix',
  })
  // Directory-derived protection follows the discovered home.
  assert.notEqual(matchProtectedPath('/Users/someone/.codex/config.toml', other, 'posix'), undefined)
  assert.equal(matchProtectedPath('/home/tester/.codex/config.toml', other, 'posix'), undefined)
  // Name-derived protection (credential file names) applies anywhere.
  assert.notEqual(matchProtectedPath('/anywhere/id_rsa', other, 'posix'), undefined)
})

test('high-value configuration files are recognized by name', () => {
  assert.equal(isHighValueConfig('/ws/package.json'), true)
  assert.equal(isHighValueConfig('/ws/pnpm-lock.yaml'), true)
  assert.equal(isHighValueConfig('/ws/tsconfig.json'), true)
  assert.equal(isHighValueConfig('/ws/.github/workflows/ci.yml'), true)
  assert.equal(isHighValueConfig('/ws/src/index.ts'), false)
})

test('protected discovery includes the shared agent home', () => {
  assert.notEqual(matchProtectedPath('/home/tester/.agents/config.json', roots, 'posix'), undefined)
})

test('windows credential stores are protected on win32 only', () => {
  const winRoots = discoverProtectedRoots({
    homedir: 'C:\\Users\\tester',
    dshHome: 'D:\\dsh-data',
    agentsHome: 'C:\\Users\\tester\\.agents',
    pluginRoot: 'D:\\dsh-data\\profiles\\web\\node_modules\\dsh-boundary-guard',
    platform: 'win32',
  })
  const match = matchProtectedPath('C:\\Users\\tester\\AppData\\Roaming\\Microsoft\\Credentials\\abc', winRoots, 'win32')
  assert.notEqual(match, undefined)
  assert.equal(match?.kind, 'system-credential-store')
  const posixMatch = matchProtectedPath('/home/tester/AppData/Roaming/Microsoft/Credentials/abc', roots, 'posix')
  assert.equal(posixMatch, undefined)
})

test('windows protected roots use windows separators', () => {
  const winRoots = discoverProtectedRoots({
    homedir: 'C:\\Users\\tester',
    dshHome: 'D:\\dsh-data',
    agentsHome: 'C:\\Users\\tester\\.agents',
    pluginRoot: 'D:\\dsh-data\\profiles\\web\\node_modules\\dsh-boundary-guard',
    platform: 'win32',
  })
  const match = matchProtectedPath('C:\\Users\\tester\\.ssh\\id_ed25519', winRoots, 'win32')
  assert.notEqual(match, undefined)
  assert.equal(match?.kind, 'credential')
})
