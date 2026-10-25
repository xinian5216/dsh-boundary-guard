import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
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
 * Build a throwaway Git repository inside the workspace and a LOCAL bare remote
 * under the OS temp directory. Nothing here touches the real repository, the
 * real `origin`, or any network remote: the remote URL is a filesystem path.
 */
function makeGitFixture(workspaceRoot: string): { repo: string; remote: string; branch: string } {
  const repo = join(workspaceRoot, 'git-readonly-fixture')
  const remote = join(mkdtempSync(join(tmpdir(), 'boundary-guard-git-remote-')), 'remote.git')
  execFileSync('git', ['init', '--quiet', '--bare', remote])
  execFileSync('git', ['init', '--quiet', repo])
  writeFileSync(join(repo, 'README.md'), '# fixture\n')
  execFileSync('git', ['add', 'README.md'], { cwd: repo })
  execFileSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'fixture'], { cwd: repo })
  // Wire the local bare remote by hand: writing the config file keeps the test
  // independent of `git remote add` spelling and of any inherited configuration.
  writeFileSync(join(repo, '.git', 'config'), [
    '[core]',
    '\trepositoryformatversion = 0',
    '\tfilemode = false',
    '\tbare = false',
    '[user]',
    '\tname = Fixture',
    '\temail = fixture@example.invalid',
    '[remote "origin"]',
    `\turl = ${remote.replace(/\\/g, '/')}`,
    '',
  ].join('\n'))
  const branch = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: repo }).toString().trim()
  return { repo, remote, branch }
}

/** Refs that exist in a bare remote's `refs/heads`. */
function remoteHeads(remote: string): string[] {
  const heads = join(remote, 'refs', 'heads')
  if (!existsSync(heads)) return []
  return readdirSync(heads).sort()
}

/** Tags that exist in a repository (`git init` creates an empty directory). */
function localTags(repo: string): string[] {
  const tags = join(repo, '.git', 'refs', 'tags')
  if (!existsSync(tags)) return []
  return readdirSync(tags).sort()
}

test('SEC-GIT-1: inspect mode denies git commands that only look read-only', async (t) => {
  const guard = await env({ config: { defaultMode: 'inspect' } })
  if (guard.shellTool === undefined) {
    t.skip('no confined shell tool composed on this platform')
    return
  }
  let fixture: { repo: string; remote: string; branch: string }
  try {
    fixture = makeGitFixture(guard.workspace.root)
  } catch {
    t.skip('git is unavailable in this environment')
    return
  }
  const { repo, remote, branch } = fixture
  // Approval is granted for every call, so nothing but the policy can stop it.
  const denied: [string, string][] = [
    ['git -C ' + JSON.stringify(repo) + ' push origin ' + branch, 'a global -C cannot make a push read-only'],
    ['git --git-dir=' + JSON.stringify(repo + '/.git') + ' push origin ' + branch, 'a global --git-dir cannot make a push read-only'],
    ['git -c alias.x=!id x', 'a git alias can execute an arbitrary command'],
    ['git config user.email attacker@example.invalid', 'git config writes .git/config'],
    ['git branch newbranch', 'creating a branch is a workspace write'],
    ['git tag v9', 'creating a tag is a workspace write'],
    ['git diff --output=' + JSON.stringify(join(repo, 'leak.txt')), 'git diff --output writes a file'],
    ['git reflog expire --expire=now --all', 'expiring the reflog destroys history'],
    ['git symbolic-ref HEAD refs/heads/evil', 'moving HEAD changes repository state'],
    ['git worktree add ' + JSON.stringify(join(tmpdir(), 'boundary-guard-git-wt')), 'adding a worktree writes outside the repo'],
    ['git archive --output=' + JSON.stringify(join(repo, 'a.tar')) + ' HEAD', 'git archive --output writes a file'],
    ['git fsck', 'an unrecognized subcommand is not provably read-only'],
    ['git remote show origin', 'git remote show contacts the network'],
    ['git -C ' + JSON.stringify(repo) + ' commit -m "inspect escape"', 'a commit is never read-only'],
  ]
  try {
    for (const [command, why] of denied) {
      guard.answerWith(['allowed-once'])
      const result = await guard.call(guard.shellTool, { command, description: 'read-only-looking git' })
      assert.equal(result.isError, true, `${why}: ${command} was allowed in inspect mode`)
    }
    // The observable side effects must not have happened either.
    assert.deepEqual(readdirSync(join(repo, '.git', 'refs', 'heads')).sort(), [branch], 'no branch may be created')
    assert.deepEqual(localTags(repo), [], 'no tag may be created')
    assert.equal(existsSync(join(repo, 'leak.txt')), false, 'git diff --output must not write a file')
    assert.equal(existsSync(join(repo, 'a.tar')), false, 'git archive --output must not write a file')
    assert.deepEqual(remoteHeads(remote), [], 'the bare remote must not receive a ref')
    assert.equal(readFileSync(join(repo, '.git', 'HEAD'), 'utf8').trim(), `ref: refs/heads/${branch}`, 'HEAD must not move')
    const config = readFileSync(join(repo, '.git', 'config'), 'utf8')
    assert.equal(config.includes('attacker@example.invalid'), false, 'git config must not write user.email')
    // The reflog still holds the fixture commit, so it was not expired.
    const reflog = execFileSync('git', ['reflog'], { cwd: repo }).toString()
    assert.match(reflog, /fixture/, 'the reflog must survive')
  } finally {
    rmSync(join(tmpdir(), 'boundary-guard-git-wt'), { recursive: true, force: true })
    rmSync(repo, { recursive: true, force: true })
    rmSync(remote, { recursive: true, force: true })
  }
})

test('SEC-GIT-2: inspect mode still allows provably read-only git', async (t) => {
  const guard = await env({ config: { defaultMode: 'inspect' } })
  if (guard.shellTool === undefined) {
    t.skip('no confined shell tool composed on this platform')
    return
  }
  let fixture: { repo: string; remote: string; branch: string }
  try {
    fixture = makeGitFixture(guard.workspace.root)
  } catch {
    t.skip('git is unavailable in this environment')
    return
  }
  const { repo, remote, branch } = fixture
  try {
    for (const command of [
      'git status',
      'git log --oneline',
      'git diff --stat',
      'git -C ' + JSON.stringify(repo) + ' status',
      'git --git-dir=' + JSON.stringify(repo + '/.git') + ' status',
      'git config user.name',
      'git branch -a',
      'git reflog',
      'git worktree list',
      'git remote -v',
    ]) {
      const result = await guard.call(guard.shellTool, { command, description: 'read-only git' })
      assert.equal(result.isError, false, `${command} must be allowed in inspect mode: ${result.text}`)
    }
  } finally {
    rmSync(repo, { recursive: true, force: true })
    rmSync(remote, { recursive: true, force: true })
  }
})

test('SEC-GIT-3: maintain mode still performs an approved push to a local bare remote', async (t) => {
  const guard = await env({
    config: { defaultMode: 'maintain', maintain: { maxDurationMs: 600000, requireConfirmation: false } },
  })
  if (guard.shellTool === undefined) {
    t.skip('no confined shell tool composed on this platform')
    return
  }
  let fixture: { repo: string; remote: string; branch: string }
  try {
    fixture = makeGitFixture(guard.workspace.root)
  } catch {
    t.skip('git is unavailable in this environment')
    return
  }
  const { repo, remote, branch } = fixture
  try {
    await guard.command('/guard maintain 10')
    guard.answerWith(['allowed-once'])
    const result = await guard.call(guard.shellTool, {
      command: `git -C ${JSON.stringify(repo)} push origin ${branch}`,
      description: 'push to the local bare remote',
    })
    assert.equal(result.isError, false, `an approved push to a local remote must work: ${result.text}`)
    assert.deepEqual(remoteHeads(remote), [branch], 'the bare remote must now hold the branch')
  } finally {
    rmSync(repo, { recursive: true, force: true })
    rmSync(remote, { recursive: true, force: true })
  }
})

test('SEC-GIT-4: develop mode requires approval for a remote write', async (t) => {
  const guard = await env({ config: { defaultMode: 'develop' } })
  if (guard.shellTool === undefined) {
    t.skip('no confined shell tool composed on this platform')
    return
  }
  let fixture: { repo: string; remote: string; branch: string }
  try {
    fixture = makeGitFixture(guard.workspace.root)
  } catch {
    t.skip('git is unavailable in this environment')
    return
  }
  const { repo, remote, branch } = fixture
  try {
    // Without an approval channel the push must not run.
    guard.answerWith(['unavailable'])
    const unavailable = await guard.call(guard.shellTool, {
      command: `git -C ${JSON.stringify(repo)} push origin ${branch}`,
      description: 'push without approval',
    })
    assert.equal(unavailable.isError, true, 'a push must require approval in develop mode')
    assert.deepEqual(remoteHeads(remote), [], 'no ref may reach the remote without approval')
    // And an explicit rejection is honored too.
    guard.answerWith(['rejected'])
    const rejected = await guard.call(guard.shellTool, {
      command: `git -C ${JSON.stringify(repo)} push origin ${branch}`,
      description: 'rejected push',
    })
    assert.equal(rejected.isError, true, 'a rejected push must not run')
    assert.deepEqual(remoteHeads(remote), [], 'no ref may reach the remote after a rejection')
  } finally {
    rmSync(repo, { recursive: true, force: true })
    rmSync(remote, { recursive: true, force: true })
  }
})
