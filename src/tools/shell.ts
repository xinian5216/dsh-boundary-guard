/**
 * Shell command analysis for `bash` and `pwsh` tool calls.
 *
 * This is a heuristic layer, NOT a sandbox: it classifies what a command
 * *appears* to do so the policy engine can require approval or deny. The real
 * confinement comes from the DSH sandbox and the OS. Anything the analyzer
 * cannot parse conservatively becomes "dynamic execution", which the policy
 * engine treats as requiring approval (or denial in inspect mode).
 *
 * @module dsh-boundary-guard/tools/shell
 */

/** Risk tags the analyzer can attach to a command. */
export type ShellRiskTag =
  | 'git-read'
  | 'git-workspace-write'
  | 'git-state-change'
  | 'git-history-rewrite'
  | 'git-remote-write'
  | 'git-global-config'
  | 'dependency-install'
  | 'package-publish'
  | 'system-install'
  | 'destructive'
  | 'mass-destructive'
  | 'file-write'
  | 'file-delete'
  | 'network-read'
  | 'network-upload'
  | 'remote-session'
  | 'privilege-escalation'
  | 'system-config'
  | 'process-control'
  | 'dynamic-execution'
  | 'bulk-operation'
  | 'sandbox-escalation'
  | 'unknown-command'

/** One analyzed command segment. */
export interface ShellSegment {
  readonly words: readonly string[]
  readonly command: string
  readonly redirectTargets: readonly string[]
  readonly tags: readonly ShellRiskTag[]
}

/** The full analysis of one command string. */
export interface ShellAnalysis {
  readonly segments: readonly ShellSegment[]
  /** All tags across segments, deduplicated. */
  readonly tags: readonly ShellRiskTag[]
  /** Path-like tokens that may be written (redirections, write cmdlets). */
  readonly writeTargets: readonly string[]
  /** Path-like tokens that may be read or deleted. */
  readonly readTargets: readonly string[]
  /** The command uses eval/dynamic execution that cannot be fully analyzed. */
  readonly dynamic: boolean
  /** The command appears to operate in bulk over many files. */
  readonly bulk: boolean
  /** Sanitized one-line summary safe for audit logs (never the raw command). */
  readonly summary: string
}

const WRITE_CMDLETS = new Set([
  'set-content',
  'add-content',
  'out-file',
  'new-item',
  'tee-object',
  'export-csv',
  'export-clixml',
  'out-string',
])

const DESTRUCTIVE_COMMANDS = new Set([
  'remove-item',
  'ri',
  'rm',
  'rmdir',
  'del',
  'erase',
  'rd',
  'clear-content',
  'format',
  'diskpart',
  'mkfs',
  'mkfs.ext4',
  'dd',
  'shred',
])

/** Split a command string into segments on unquoted control operators. */
export function splitSegments(command: string): string[] {
  const segments: string[] = []
  let current = ''
  let quote: '"' | "'" | '`' | null = null
  let depth = 0
  for (let i = 0; i < command.length; i += 1) {
    const char = command[i]
    if (char === undefined) break
    if (quote) {
      current += char
      if (char === quote) quote = null
      continue
    }
    if (char === '"' || char === "'" || char === '`') {
      quote = char
      current += char
      continue
    }
    if (char === '(') depth += 1
    if (char === ')') depth = Math.max(0, depth - 1)
    if (depth === 0) {
      const two = command.slice(i, i + 2)
      if (two === '&&' || two === '||' || two === '>>') {
        if (two === '>>') {
          current += two
          i += 1
          continue
        }
        segments.push(current)
        current = ''
        i += 1
        continue
      }
      if (char === ';' || char === '|' || char === '\n' || char === '&') {
        segments.push(current)
        current = ''
        continue
      }
    }
    current += char
  }
  if (current.trim() !== '') segments.push(current)
  return segments.map((segment) => segment.trim()).filter((segment) => segment !== '')
}

/** Tokenize one segment respecting quotes and escapes. */
export function tokenize(segment: string, platform: 'win32' | 'posix' = 'posix'): string[] {
  const tokens: string[] = []
  let current = ''
  let quote: '"' | "'" | null = null
  let started = false
  for (let i = 0; i < segment.length; i += 1) {
    const char = segment[i]
    if (char === undefined) break
    if (quote) {
      if (char === quote) {
        quote = null
        continue
      }
      if (quote === '"' && char === '\\' && platform === 'posix' && i + 1 < segment.length) {
        current += segment[i + 1]
        i += 1
        continue
      }
      current += char
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      started = true
      continue
    }
    // PowerShell (win32) treats the backslash literally; POSIX shells use it
    // as an escape. Keeping it literal on Windows preserves path separators.
    if (char === '\\' && platform === 'posix' && i + 1 < segment.length) {
      current += segment[i + 1]
      i += 1
      started = true
      continue
    }
    if (/\s/.test(char)) {
      if (started) {
        tokens.push(current)
        current = ''
        started = false
      }
      continue
    }
    current += char
    started = true
  }
  if (started) tokens.push(current)
  return tokens
}

/** Extract redirection targets from a token list. */
function redirectTargets(tokens: readonly string[]): string[] {
  const targets: string[] = []
  const redirectPattern = /^(?:\d|&)?(?:>>?|<)$/
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i]
    if (token === undefined) continue
    const glued = /^(?:\d|&)?>>?\s*(.+)$/.exec(token)
    if (glued !== null && glued[1] !== undefined && !redirectPattern.test(token)) {
      targets.push(glued[1])
      continue
    }
    if (redirectPattern.test(token)) {
      const next = tokens[i + 1]
      if (next !== undefined && !next.startsWith('-')) targets.push(next)
    }
  }
  return targets
}

/** Resolve a command word to its base name, ignoring paths and extensions. */
function baseCommand(word: string): string {
  const withoutPath = word.split(/[\\/]/).pop() ?? word
  return withoutPath.replace(/\.(exe|cmd|bat|ps1|com)$/i, '').toLowerCase()
}

/** Path-like token heuristic. */
function looksLikePath(token: string): boolean {
  if (token.startsWith('-')) return false
  if (/^[a-zA-Z]:[\\/]/.test(token)) return true
  if (token.startsWith('\\\\') || token.startsWith('//')) return true
  if (token.startsWith('~/') || token === '~') return true
  if (token.startsWith('/')) return true
  if (token.startsWith('./') || token.startsWith('../')) return true
  return false
}

const GIT_READ_SUBCOMMANDS = new Set([
  'status', 'diff', 'log', 'show', 'blame', 'shortlog', 'describe', 'rev-parse',
  'ls-files', 'ls-tree', 'branch', 'tag', 'remote', 'config', 'whatchanged',
  'reflog', 'grep', 'diff-tree', 'merge-base', 'name-rev', 'symbolic-ref',
  'check-ignore', 'var', 'version', 'help', 'fetch',
])
const GIT_WORKSPACE_SUBCOMMANDS = new Set(['add', 'mv', 'checkout', 'switch', 'restore', 'init', 'clone', 'stash', 'commit'])
const GIT_STATE_SUBCOMMANDS = new Set(['reset', 'rebase', 'clean', 'update-ref', 'notes', 'gc', 'prune', 'replace', 'merge', 'pull', 'cherry-pick', 'revert', 'filter-branch', 'filter-repo'])
const GIT_REMOTE_SUBCOMMANDS = new Set(['push', 'submodule'])

function gitTags(words: readonly string[]): ShellRiskTag[] {
  const sub = words[1]?.toLowerCase() ?? ''
  const subSub = words[2]?.toLowerCase() ?? ''
  const flags = words.slice(2).map((word) => word.toLowerCase())
  const joined = flags.join(' ')
  const tags: ShellRiskTag[] = []
  if (GIT_READ_SUBCOMMANDS.has(sub)) tags.push('git-read')
  if (GIT_WORKSPACE_SUBCOMMANDS.has(sub)) tags.push('git-workspace-write')
  if (GIT_STATE_SUBCOMMANDS.has(sub)) {
    tags.push('git-state-change')
    if (sub === 'rebase' || sub === 'filter-branch' || sub === 'filter-repo') tags.push('git-history-rewrite')
    if (sub === 'reset' && (flags.includes('--hard') || flags.includes('--merge'))) tags.push('git-history-rewrite')
  }
  if (sub === 'stash' && (subSub === 'drop' || subSub === 'clear')) {
    tags.length = 0
    tags.push('git-state-change')
  }
  if (sub === 'commit' && flags.includes('--amend')) {
    tags.length = 0
    tags.push('git-history-rewrite')
  }
  if (sub === 'branch' && (flags.includes('-d') || flags.includes('-m') || flags.includes('-c') || flags.includes('--delete') || flags.includes('--move') || flags.includes('--copy'))) {
    tags.push('git-state-change')
  }
  if (sub === 'tag' && (flags.includes('-d') || flags.includes('--delete'))) tags.push('git-state-change')
  if (sub === 'remote' && ['add', 'remove', 'rm', 'set-url', 'rename', 'prune'].includes(subSub)) tags.push('git-remote-write')
  if (GIT_REMOTE_SUBCOMMANDS.has(sub)) tags.push('git-remote-write')
  if (sub === 'push') {
    const force = flags.includes('--force') || flags.includes('-f') || flags.includes('--force-with-lease') || joined.includes('+refs')
    if (force) tags.push('git-history-rewrite')
  }
  if (sub === 'config' && (flags.includes('--global') || flags.includes('--system'))) tags.push('git-global-config')
  if (sub === 'clean' && joined.includes('-f')) tags.push('destructive')
  if (sub === 'gc' && joined.includes('prune=now')) tags.push('git-history-rewrite')
  if (sub === 'submodule' && ['update', 'sync', 'init'].includes(subSub)) tags.push('git-state-change')
  return tags
}

const PACKAGE_INSTALLERS = new Set(['npm', 'pnpm', 'yarn', 'bun', 'npx', 'pip', 'pip3', 'python', 'python3', 'gem', 'cargo', 'go', 'apt', 'apt-get', 'winget', 'choco', 'scoop', 'brew', 'dnf', 'yum', 'pacman'])
const NETWORK_TOOLS = new Set(['ssh', 'scp', 'sftp', 'rsync', 'ftp', 'smbclient', 'nc', 'ncat', 'netcat', 'telnet'])
const DOWNLOAD_TOOLS = new Set(['curl', 'wget', 'iwr', 'invoke-webrequest', 'irm', 'invoke-restmethod'])
const PRIVILEGE_TOOLS = new Set(['sudo', 'doas', 'runas', 'su'])
const SYSTEM_CONFIG_TOOLS = new Set(['setx', 'reg', 'regedit', 'netsh', 'sc', 'systemctl', 'service', 'schtasks', 'launchctl', 'defaults'])
const PROCESS_TOOLS = new Set(['taskkill', 'kill', 'stop-process', 'start-process', 'pkill'])
const DYNAMIC_TOOLS = new Set(['eval', 'iex', 'invoke-expression', 'exec'])

function segmentTags(words: readonly string[], raw: string): ShellRiskTag[] {
  const first = words[0]
  if (first === undefined) return []
  const command = baseCommand(first)
  const tags = new Set<ShellRiskTag>()
  const lower = raw.toLowerCase()

  if (command === 'git') for (const tag of gitTags(words)) tags.add(tag)

  if (PACKAGE_INSTALLERS.has(command)) {
    const sub = (words[1] ?? '').toLowerCase()
    if (['install', 'i', 'add', 'update', 'upgrade', 'ci', 'link', 'sync'].includes(sub)) tags.add('dependency-install')
    if (['publish', 'unpublish'].includes(sub)) tags.add('package-publish')
    if (['apt', 'apt-get', 'dnf', 'yum', 'pacman', 'brew', 'winget', 'choco', 'scoop'].includes(command)) tags.add('system-install')
    if (command === 'npx' || command === 'bunx') tags.add('dynamic-execution')
  }

  // Language runtimes executing inline code: the payload is opaque.
  if (['node', 'nodejs', 'deno', 'ts-node', 'tsx', 'python', 'python3', 'ruby', 'perl', 'php'].includes(command)) {
    const flags = words.slice(1).map((word) => word.toLowerCase())
    if (flags.includes('-e') || flags.includes('--eval') || flags.includes('-c') || flags.includes('--command') || flags.includes('--input-type')) {
      tags.add('dynamic-execution')
    }
  }

  if (NETWORK_TOOLS.has(command)) {
    tags.add(lower.includes('scp') || command === 'scp' || command === 'rsync' ? 'network-upload' : 'network-read')
    if (['ssh', 'sftp', 'ftp', 'telnet'].includes(command)) tags.add('remote-session')
  }

  if (DOWNLOAD_TOOLS.has(command)) {
    const flags = words.slice(1)
    const upload = flags.some((flag) => /^(-o|-O|--output|-d|--data|--data-raw|-T|--upload-file|-F|--form|-X|--request|-Method|-OutFile|-Body)$/i.test(flag))
    const methodIndex = flags.findIndex((flag) => /^(-X|--request|-Method)$/i.test(flag))
    const method = methodIndex >= 0 ? (flags[methodIndex + 1] ?? '').toUpperCase() : ''
    if (upload || ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) tags.add('network-upload')
    else tags.add('network-read')
  }

  if (PRIVILEGE_TOOLS.has(command)) tags.add('privilege-escalation')

  if (SYSTEM_CONFIG_TOOLS.has(command)) {
    tags.add('system-config')
    const sub = (words[1] ?? '').toLowerCase()
    if (command === 'reg' && ['add', 'delete', 'import'].includes(sub)) tags.add('system-config')
    if (command === 'setx') tags.add('system-config')
  }

  if (PROCESS_TOOLS.has(command)) tags.add('process-control')

  if (DESTRUCTIVE_COMMANDS.has(command)) {
    tags.add('destructive')
    if (command === 'format' || command === 'diskpart' || command === 'mkfs' || command === 'dd') tags.add('mass-destructive')
    // `rm -rf /`, `rm -rf ~`, and friends aim at a whole filesystem or home.
    const targets = words.slice(1).filter((word) => !word.startsWith('-'))
    if (['rm', 'remove-item', 'ri', 'rmdir', 'del', 'erase', 'rd'].includes(command)) {
      if (targets.some((target) => /^(\/|\*|~\/?\*?|%USERPROFILE%|\$HOME|\$env:USERPROFILE|[a-zA-Z]:\\?\*?)$/.test(target))) {
        tags.add('mass-destructive')
      }
    }
    const flags = words.slice(1).join(' ')
    if (/-\w*[rf]\w*/i.test(flags) && ['rm', 'remove-item', 'ri', 'rmdir', 'del', 'erase', 'rd'].includes(command)) tags.add('file-delete')
    if (command === 'remove-item' && /-recurse/i.test(flags) && /-force/i.test(flags)) tags.add('file-delete')
  }

  if (WRITE_CMDLETS.has(command)) tags.add('file-write')

  if (DYNAMIC_TOOLS.has(command)) tags.add('dynamic-execution')

  if (command === 'pwsh' || command === 'powershell') {
    const flags = words.slice(1).map((flag) => flag.toLowerCase())
    if (flags.includes('-enc') || flags.includes('-encodedcommand') || flags.some((flag) => flag.startsWith('-e'))) tags.add('dynamic-execution')
    if (flags.includes('-command') || flags.includes('-c')) tags.add('dynamic-execution')
  }
  if (command === 'bash' || command === 'sh' || command === 'zsh' || command === 'cmd') {
    if (words.some((word) => /^-c$/i.test(word))) tags.add('dynamic-execution')
  }

  if (/\bfor(each)?\b|\bwhile\b|\bforeach\b/i.test(raw) && /(set-content|add-content|out-file|remove-item|>|>>)/i.test(raw)) tags.add('bulk-operation')
  if (/-recurse/i.test(raw) && /(set-content|add-content|out-file|remove-item|copy-item|move-item)/i.test(raw)) tags.add('bulk-operation')
  if (/\bsed\s+-i/i.test(raw) || /\bxargs\b/i.test(raw)) tags.add('bulk-operation')

  if (/sandbox_permissions|sandbox-permissions/i.test(raw)) tags.add('sandbox-escalation')

  return [...tags]
}

/** Commands whose positional (non-flag) arguments are paths they act on. */
const PATH_TAKING_COMMANDS = new Set([
  ...WRITE_CMDLETS,
  'copy-item',
  'move-item',
  'remove-item',
  'ri',
  'rm',
  'rmdir',
  'del',
  'erase',
  'rd',
  'test-path',
  'get-content',
  'cat',
  'type',
  'ls',
  'dir',
  'get-childitem',
  'gci',
])

/** Flags whose following token is a path. */
const PATH_FLAGS = new Set(['-path', '-literalpath', '-filepath', '-outfile', '-destination', '-file', '-filter'])

/** Collect path arguments of path-taking commands from one segment. */
function positionalTargets(segment: ShellSegment): { writes: string[]; reads: string[] } {
  const writes: string[] = []
  const reads: string[] = []
  if (!PATH_TAKING_COMMANDS.has(segment.command)) return { writes, reads }
  const isWrite = WRITE_CMDLETS.has(segment.command)
    || ['copy-item', 'move-item', 'remove-item', 'ri', 'rm', 'rmdir', 'del', 'erase', 'rd'].includes(segment.command)
  for (let i = 1; i < segment.words.length; i += 1) {
    const word = segment.words[i]
    if (word === undefined) continue
    const lower = word.toLowerCase()
    if (PATH_FLAGS.has(lower)) {
      const next = segment.words[i + 1]
      if (next !== undefined) {
        if (isWrite) writes.push(next)
        else reads.push(next)
        i += 1
      }
      continue
    }
    if (word.startsWith('-')) continue
    if (looksLikePath(word) || /\.[a-z0-9]{1,8}$/i.test(word)) {
      if (isWrite) writes.push(word)
      else reads.push(word)
    }
  }
  return { writes, reads }
}

/** Analyze one shell command string. */
export function analyzeShellCommand(command: string, platform: 'win32' | 'posix' = 'posix'): ShellAnalysis {
  const segments = splitSegments(command).map((raw) => {
    const words = tokenize(raw, platform)
    const command0 = words[0] === undefined ? '' : baseCommand(words[0])
    return {
      words,
      command: command0,
      redirectTargets: redirectTargets(words),
      tags: segmentTags(words, raw),
    }
  })
  const tags = new Set<ShellRiskTag>()
  const writeTargets = new Set<string>()
  const readTargets = new Set<string>()
  let dynamic = false
  let bulk = false
  for (const segment of segments) {
    for (const tag of segment.tags) {
      tags.add(tag)
      if (tag === 'dynamic-execution') dynamic = true
      if (tag === 'bulk-operation') bulk = true
    }
    for (const target of segment.redirectTargets) writeTargets.add(target)
    const positional = positionalTargets(segment)
    for (const target of positional.writes) writeTargets.add(target)
    for (const target of positional.reads) readTargets.add(target)
    for (const word of segment.words) {
      if (!looksLikePath(word)) continue
      const destructive = segment.tags.some((tag) => tag === 'destructive' || tag === 'file-delete' || tag === 'mass-destructive')
      if (destructive || segment.tags.includes('file-write') || segment.redirectTargets.includes(word)) writeTargets.add(word)
      else readTargets.add(word)
    }
  }
  // Whole-command bulk heuristics: a pipeline like
  // `Get-ChildItem -Recurse | Remove-Item` splits the evidence across
  // segments, so the bulk check also runs on the complete command.
  if (
    /\bfor(each)?\b|\bwhile\b|\bforeach\b/i.test(command)
    && /(set-content|add-content|out-file|remove-item|>|>>)/i.test(command)
  ) {
    tags.add('bulk-operation')
    bulk = true
  }
  if (/-recurse/i.test(command) && /(set-content|add-content|out-file|remove-item|copy-item|move-item)/i.test(command)) {
    tags.add('bulk-operation')
    bulk = true
  }
  if (/\bsed\s+-i/i.test(command) || /\bxargs\b/i.test(command)) {
    tags.add('bulk-operation')
    bulk = true
  }
  const summary = (() => {
    const all = [...tags]
    return all.length > 0
      ? `shell command classified: ${all.join(', ')}`
      : 'shell command classified: no recognized risk pattern'
  })()
  return {
    segments,
    tags: [...tags],
    writeTargets: [...writeTargets],
    readTargets: [...readTargets],
    dynamic,
    bulk,
    summary,
  }
}
