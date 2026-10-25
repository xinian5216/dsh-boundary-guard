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
import { mentionsProtectedLocation } from '../boundary/protected.ts'

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
  | 'git-network-read'

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
  /**
   * Whether the command is provably read-only: a single segment, no shell
   * substitution constructs, and either only read-classified Git tags or a
   * command from the explicit read-only allowlist. This is what allows
   * `git status` style commands in inspect mode without opening the shell.
   */
  readonly readOnly: boolean
  /**
   * Whether the command's text names a protected location (`.ssh`, `.env`,
   * credentials, ...). A heuristic backstop for indirect access, used only to
   * deny mutating commands; read-only commands are handled by the read rules.
   */
  readonly protectedMention: boolean
  /** Sanitized one-line summary safe for audit logs (never the raw command). */
  readonly summary: string
}

/**
 * Commands that are read-only when they appear alone, without redirection,
 * pipeline, or substitution. Everything else stays unclassified and is
 * treated as a potential execution.
 *
 * `git` is deliberately absent: read-only Git comes only from the explicit
 * subcommand+argument allowlist below, never from the command name.
 */
const READ_ONLY_COMMANDS = new Set([
  'ls',
  'dir',
  'pwd',
  'cat',
  'type',
  'echo',
  'get-childitem',
  'gci',
  'get-content',
  'gc',
  'get-location',
  'where',
  'which',
  'whoami',
  'hostname',
  'date',
  'findstr',
  'select-string',
])

/**
 * Allowlist entries that are read-only only with specific arguments. `date -s`
 * changes the system clock (and a bare Windows `date` opens a prompt), so a
 * flagless or UTC-flagged `date` is the only provably read-only spelling.
 */
const READ_ONLY_ARGUMENT_RULES = new Map<string, (args: readonly string[]) => boolean>([
  ['date', (args) => args.every((arg) => DATE_OUTPUT_FLAGS.has(arg.toLowerCase()))],
])

/** Output-format flags that cannot change the clock. */
const DATE_OUTPUT_FLAGS = new Set(['-u', '--utc', '--universal'])

/** Shell substitution constructs that make a command opaque. */
const SUBSTITUTION_PATTERN = /\$\(|`|\$\{|<\(|>\(|\$\(|\beval\b|\biex\b|\binvoke-expression\b/i

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

/**
 * Git global options accepted before the subcommand, with how each consumes a
 * value. `attached` means Git only accepts `--opt=<value>`; `value` means both
 * `--opt=<value>` and `--opt <value>` are accepted. A token that is not listed
 * here is not a global option, so the scan stops and that token is taken as
 * the subcommand — which then fails the read allowlist.
 */
const GIT_GLOBAL_OPTIONS = new Map<string, 'none' | 'attached' | 'value'>([
  ['-C', 'value'],
  ['-c', 'value'],
  ['--config', 'value'],
  ['--config-env', 'attached'],
  ['--exec-path', 'attached'],
  ['--git-dir', 'value'],
  ['--work-tree', 'value'],
  ['--namespace', 'value'],
  ['--super-prefix', 'value'],
  ['--literal-pathspecs', 'none'],
  ['--no-literal-pathspecs', 'none'],
  ['--glob-pathspecs', 'none'],
  ['--noglob-pathspecs', 'none'],
  ['--no-optional-locks', 'none'],
  ['--no-replace-objects', 'none'],
  ['--bare', 'none'],
  ['-p', 'none'],
  ['--paginate', 'none'],
  ['--no-pager', 'none'],
  ['--help', 'none'],
])

/**
 * Global options that make Git run a program the guard cannot analyze:
 * `alias.*`, `core.pager`, `credential.helper`, `diff.external`, an editor.
 * They disqualify provable read-only and are tagged dynamic execution.
 */
const GIT_EXECUTING_GLOBAL_OPTIONS = new Set([
  '-c',
  '--config',
  '--config-env',
  '--exec-path',
  '--namespace',
  '--super-prefix',
  // `-p`/`--paginate` force the pager to run even when stdout is not a TTY.
  '-p',
  '--paginate',
])

/** Global options whose value names a path the command acts on. */
const GIT_PATH_GLOBAL_OPTIONS = new Set(['-C', '--git-dir', '--work-tree'])

/** Subcommands whose read-only verdict depends on their arguments. */
const GIT_CONDITIONAL_SUBCOMMANDS = new Set([
  'config',
  'branch',
  'tag',
  'reflog',
  'symbolic-ref',
  'worktree',
  'stash',
  'notes',
  'remote',
  'diff',
  'show',
  'format-patch',
])

/** Subcommands that only ever read repository state. */
const GIT_READ_SUBCOMMANDS = new Set([
  'status', 'log', 'blame', 'shortlog', 'describe', 'rev-parse', 'ls-files',
  'ls-tree', 'whatchanged', 'grep', 'diff-tree', 'merge-base', 'name-rev',
  'check-ignore', 'var', 'version',
])
// `git fetch` talks to the network and writes refs/objects into .git, so it is
// deliberately NOT a read-classified subcommand: it stays an execution.
const GIT_NETWORK_SUBCOMMANDS = new Set(['fetch', 'ls-remote'])
const GIT_WORKSPACE_SUBCOMMANDS = new Set(['add', 'mv', 'checkout', 'switch', 'restore', 'init', 'clone', 'commit'])
const GIT_STATE_SUBCOMMANDS = new Set(['reset', 'rebase', 'clean', 'update-ref', 'gc', 'prune', 'replace', 'merge', 'pull', 'cherry-pick', 'revert', 'filter-branch', 'filter-repo'])
const GIT_REMOTE_SUBCOMMANDS = new Set(['push', 'submodule'])

/**
 * Options whose following token is a value rather than a positional argument,
 * for the subcommands that decide read-only by counting positionals. Without
 * this, a genuine read such as `git tag --contains HEAD` would look like a ref
 * creation.
 */
const GIT_VALUED_OPTIONS = new Map<string, readonly string[]>([
  ['branch', ['--contains', '--no-contains', '--merged', '--no-merged', '--points-at', '--sort', '--format']],
  ['tag', ['-n', '--contains', '--no-contains', '--merged', '--no-merged', '--points-at', '--sort', '--format']],
])

/** What one Git invocation does to the repository. */
type GitVerdict = 'read' | 'network' | 'workspace' | 'state' | 'remote' | 'unknown'

/** One parsed Git invocation: the real subcommand plus its arguments. */
interface GitInvocation {
  /** The subcommand Git will run, lowercased, or undefined when absent. */
  readonly subcommand: string | undefined
  /** Tokens after the subcommand. */
  readonly args: readonly string[]
  /** Values of `-C`, `--git-dir`, `--work-tree`: paths the command acts on. */
  readonly pathOptions: readonly string[]
  /** Whether a global option can execute a program the guard cannot analyze. */
  readonly executesProgram: boolean
}

/** Outcome of validating one subcommand's arguments. */
interface GitVerdictResult {
  readonly verdict: GitVerdict
  /** The invocation runs a program the guard cannot analyze. */
  readonly dynamic: boolean
  /** Files the invocation writes through `--output`-style options. */
  readonly outputs: readonly string[]
}

/** Everything the analyzer concluded about one `git ...` segment. */
interface GitConclusion {
  readonly tags: readonly ShellRiskTag[]
  /** Path inputs the command reads. */
  readonly reads: readonly string[]
  /** Path inputs the command writes. */
  readonly writes: readonly string[]
  /** Tokens already accounted for as path inputs. */
  readonly handled: readonly string[]
}

/** Split `--opt=value` into its name and attached value. */
function splitOptionValue(word: string): [string, string | undefined] {
  if (!word.startsWith('--')) return [word, undefined]
  const eq = word.indexOf('=')
  return eq === -1 ? [word, undefined] : [word.slice(0, eq), word.slice(eq + 1)]
}

/**
 * Find the real subcommand of a Git invocation by consuming the global options
 * that precede it. An unparseable spelling stops the scan early, which leaves
 * the subcommand unrecognized rather than guessed at.
 */
function parseGitInvocation(words: readonly string[]): GitInvocation {
  const pathOptions: string[] = []
  let executesProgram = false
  let index = 1
  while (index < words.length) {
    const word = words[index]
    if (word === undefined) break
    // Everything after `--` belongs to the subcommand.
    if (word === '--') {
      index += 1
      break
    }
    const [name, attached] = splitOptionValue(word)
    const arity = GIT_GLOBAL_OPTIONS.get(name)
    if (arity === undefined) break
    if (GIT_EXECUTING_GLOBAL_OPTIONS.has(name)) executesProgram = true
    if (GIT_PATH_GLOBAL_OPTIONS.has(name)) {
      const separate = arity === 'value' && attached === undefined ? words[index + 1] : undefined
      const value = attached ?? separate
      if (value !== undefined) pathOptions.push(value)
    }
    index += attached !== undefined || arity === 'none' ? 1 : 2
  }
  const subcommand = words[index]?.toLowerCase()
  return { subcommand, args: words.slice(index + 1), pathOptions, executesProgram }
}

/** Flag names in one argument list, lowercased and without `=value`. */
function gitFlagNames(args: readonly string[]): Set<string> {
  const names = new Set<string>()
  for (const arg of args) {
    if (!arg.startsWith('-')) continue
    const [name] = splitOptionValue(arg)
    names.add((name ?? arg).toLowerCase())
  }
  return names
}

/** Positional arguments, skipping flags and the values of valued options. */
function gitPositionals(args: readonly string[], valued: readonly string[]): string[] {
  const positionals: string[] = []
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]
    if (arg === undefined || arg === '--') continue
    if (arg.startsWith('-')) {
      // A valued option written separately swallows the next token.
      const [name] = splitOptionValue(arg)
      if (!arg.includes('=') && valued.includes((name ?? arg).toLowerCase()) && args[i + 1] !== undefined) i += 1
      continue
    }
    positionals.push(arg)
  }
  return positionals
}

/** Collect the values of value-taking options, in both spellings. */
function gitOptionValues(args: readonly string[], names: readonly string[]): string[] {
  const values: string[] = []
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]
    if (arg === undefined) continue
    const [name, attached] = splitOptionValue(arg)
    if (!names.includes((name ?? arg).toLowerCase())) continue
    const next = args[i + 1]
    const separate = attached === undefined && next !== undefined && !next.startsWith('-') ? next : undefined
    const value = attached ?? separate
    if (value !== undefined && value !== '') values.push(value)
    if (attached === undefined && separate !== undefined) i += 1
  }
  return values
}

/**
 * Decide what one Git subcommand does from its arguments.
 *
 * Every rule is deliberately conservative: a write side effect is never
 * read-only, and a subcommand the rules cannot prove safe becomes `workspace`,
 * `state`, or `unknown` so the policy engine asks instead of silently allowing.
 */
function gitVerdictOf(invocation: GitInvocation): GitVerdictResult {
  const sub = invocation.subcommand
  const args = invocation.args
  if (sub === undefined) return { verdict: 'unknown', dynamic: false, outputs: [] }
  const flags = gitFlagNames(args)
  const has = (...names: string[]): boolean => names.some((name) => flags.has(name))
  const positionals = gitPositionals(args, GIT_VALUED_OPTIONS.get(sub) ?? [])
  const nested = positionals[0]?.toLowerCase()
  const plain = (verdict: GitVerdict): GitVerdictResult => ({ verdict, dynamic: false, outputs: [] })

  if (GIT_CONDITIONAL_SUBCOMMANDS.has(sub)) {
    // diff / show / format-patch: `--output[=file]` writes a file and
    // `--ext-diff`/`--textconv` run an external driver, so neither is a read.
    if (sub === 'diff' || sub === 'show' || sub === 'format-patch') {
      if (has('--ext-diff', '--textconv')) return { verdict: 'read', dynamic: true, outputs: [] }
      const outputs = gitOptionValues(args, sub === 'format-patch'
        ? ['--output', '-o', '--output-directory']
        : ['--output'])
      if (outputs.length > 0) return { verdict: 'workspace', dynamic: false, outputs }
      // `format-patch` writes `.patch` files unless it is told to use stdout.
      if (sub === 'format-patch' && !has('--stdout')) return { verdict: 'workspace', dynamic: false, outputs }
      return plain('read')
    }

    // config: a read needs an explicit read flag or at most one positional,
    // and never a write flag.
    if (sub === 'config') {
      if (has('--add', '--unset', '--unset-all', '--replace-all', '--rename-section', '--remove-section', '--edit', '-e')) {
        return plain('workspace')
      }
      const readFlag = has('--list', '-l', '--get', '--get-all', '--get-regexp', '--get-urlmatch', '--null', '-z', '--name-only', '--show-origin', '--show-scope')
      if (!readFlag && positionals.length > 1) return plain('workspace')
      return plain('read')
    }

    // branch: listing is a read; naming or mutating a branch is not.
    if (sub === 'branch') {
      if (has('-d', '-D', '-m', '-M', '-c', '-C', '--delete', '--move', '--copy', '--edit-description', '--set-upstream-to', '--unset-upstream')) {
        return plain('state')
      }
      if (positionals.length > 0) return plain('workspace')
      return plain('read')
    }

    // tag: listing is a read; creating, signing, or deleting one is not.
    if (sub === 'tag') {
      const annotating = has('-a', '--annotate', '-s', '--sign')
      const messaged = has('-m', '--message', '-F', '--file')
      if (has('-d', '--delete')) return plain('state')
      if (annotating || has('-m', '--message', '-F', '--file', '-f', '--force', '-u', '--local-user')) {
        // An annotated tag without a message opens an editor.
        return { verdict: 'workspace', dynamic: annotating && !messaged, outputs: [] }
      }
      if (positionals.length > 0) return plain('workspace')
      return plain('read')
    }

    // reflog: showing is a read; expiring or deleting entries is not.
    if (sub === 'reflog') {
      if (nested === undefined || nested === 'show') return plain('read')
      return plain('state')
    }

    // symbolic-ref: reading one ref is a read; moving or deleting it is not.
    if (sub === 'symbolic-ref') {
      if (has('-d', '--delete')) return plain('state')
      if (positionals.length > 1) return plain('state')
      return plain('read')
    }

    // worktree: listing is a read; adding or moving one writes the workspace.
    if (sub === 'worktree') {
      if (nested === 'list') return plain('read')
      if (nested === 'remove' || nested === 'prune') return plain('state')
      return plain('workspace')
    }

    // stash: listing is a read; dropping or clearing destroys state.
    if (sub === 'stash') {
      if (nested === 'list' || nested === 'show') return plain('read')
      if (nested === 'drop' || nested === 'clear') return plain('state')
      return plain('workspace')
    }

    // notes: listing is a read; anything else rewrites the notes ref.
    if (sub === 'notes') {
      if (nested === 'list' || nested === 'show') return plain('read')
      return plain('state')
    }

    // remote: `show` contacts the network; the rest either read or write.
    if (sub === 'remote') {
      if (nested === 'show') return plain('network')
      if (['add', 'remove', 'rm', 'set-url', 'rename', 'prune', 'update', 'set-head', 'set-branches'].includes(nested ?? '')) {
        return plain('remote')
      }
      return plain('read')
    }
  }

  if (GIT_READ_SUBCOMMANDS.has(sub)) return plain('read')
  if (GIT_NETWORK_SUBCOMMANDS.has(sub)) return plain('network')
  if (GIT_REMOTE_SUBCOMMANDS.has(sub)) return plain('remote')
  if (GIT_WORKSPACE_SUBCOMMANDS.has(sub)) return plain('workspace')
  if (GIT_STATE_SUBCOMMANDS.has(sub)) return plain('state')
  // Not on any known list: the engine must ask instead of silently allowing.
  return plain('unknown')
}

/**
 * Classify one `git ...` segment.
 *
 * Read-only comes only from {@link gitVerdictOf}: a subcommand on the explicit
 * read allowlist whose arguments the per-subcommand rules proved tame, with no
 * behavior-changing global option.
 */
function classifyGit(words: readonly string[]): GitConclusion {
  const invocation = parseGitInvocation(words)
  const result = gitVerdictOf(invocation)
  const args = invocation.args
  const joined = args.map((word) => word.toLowerCase()).join(' ')
  const flags = gitFlagNames(args)
  const sub = invocation.subcommand
  const tags = new Set<ShellRiskTag>()

  switch (result.verdict) {
    case 'read': tags.add('git-read'); break
    case 'network': tags.add('git-network-read'); break
    case 'workspace': tags.add('git-workspace-write'); break
    case 'state': tags.add('git-state-change'); break
    case 'remote': tags.add('git-remote-write'); break
    case 'unknown': tags.add('unknown-command'); break
  }
  if (result.dynamic || invocation.executesProgram) tags.add('dynamic-execution')

  // Refinements that survive the verdict. Each one only ADDS a stronger tag, so
  // no classification that was already correct is weakened.
  if (sub === 'push' && (flags.has('--force') || flags.has('-f') || flags.has('--force-with-lease') || joined.includes('+refs'))) {
    tags.add('git-history-rewrite')
  }
  if (sub === 'commit' && flags.has('--amend')) {
    tags.delete('git-workspace-write')
    tags.add('git-history-rewrite')
  }
  if (sub === 'reset' && (flags.has('--hard') || flags.has('--merge'))) tags.add('git-history-rewrite')
  if (sub === 'rebase' || sub === 'filter-branch' || sub === 'filter-repo') tags.add('git-history-rewrite')
  if (sub === 'config' && (flags.has('--global') || flags.has('--system'))) tags.add('git-global-config')
  if (sub === 'clean' && joined.includes('-f')) tags.add('destructive')
  if (sub === 'gc' && joined.includes('prune=now')) tags.add('git-history-rewrite')
  if (sub === 'submodule' && ['update', 'sync', 'init'].includes(args[0]?.toLowerCase() ?? '')) tags.add('git-state-change')

  // Global path options are inputs of the command: reads for a read-classified
  // subcommand, writes for a mutating one, so the engine's protected-path and
  // out-of-workspace rules still see them.
  const touching = result.verdict === 'read' || result.verdict === 'network'
  const reads: string[] = []
  const writes: string[] = [...result.outputs]
  for (const path of invocation.pathOptions) (touching ? reads : writes).push(path)

  return { tags: [...tags], reads, writes, handled: [...reads, ...writes] }
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

  if (command === 'git') for (const tag of classifyGit(words).tags) tags.add(tag)

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
    // Windows `cmd.exe` spells its switches with slashes, which a `-c`-only test
    // never matches: `cmd /c "git push"` would otherwise look unanalyzable-free.
    const opaque = command === 'cmd' ? /^[-/][ckr]$/i : /^-c$/i
    if (words.some((word) => opaque.test(word))) tags.add('dynamic-execution')
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
  const segmentWrites: string[][] = []
  let dynamic = false
  let bulk = false
  for (const segment of segments) {
    for (const tag of segment.tags) {
      tags.add(tag)
      if (tag === 'dynamic-execution') dynamic = true
      if (tag === 'bulk-operation') bulk = true
    }
    // A Git segment contributes its own path inputs (`-C`, `--git-dir`,
    // `--work-tree`, `--output`), classified as reads or writes by its
    // subcommand; the generic scan below must not re-classify them.
    const git = segment.command === 'git' ? classifyGit(segment.words) : undefined
    const writes = new Set<string>(segment.redirectTargets)
    if (git !== undefined) for (const target of git.writes) writes.add(target)
    const positional = positionalTargets(segment)
    for (const target of positional.writes) writes.add(target)
    segmentWrites.push([...writes])
    for (const target of writes) writeTargets.add(target)
    for (const target of positional.reads) readTargets.add(target)
    if (git !== undefined) for (const target of git.reads) readTargets.add(target)
    for (const word of segment.words) {
      if (!looksLikePath(word)) continue
      if (git !== undefined && git.handled.includes(word)) continue
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

  // ---- Provably read-only determination ----------------------------------
  // Only a single segment without substitution constructs, redirection, or
  // write targets can be proven read-only, and only when its classification
  // says so: either the segment carries exactly the read-classified Git tag, or
  // its command is on the explicit read-only allowlist with no other tags and
  // tame arguments. Anything with a pipeline, redirection, loop, or
  // substitution stays an execution.
  const readOnly = (() => {
    if (segments.length !== 1) return false
    if (SUBSTITUTION_PATTERN.test(command)) return false
    const segment = segments[0]
    if (segment === undefined) return false
    if (segment.redirectTargets.length > 0) return false
    if ((segmentWrites[0] ?? []).length > 0) return false
    if (segment.tags.length === 1 && segment.tags[0] === 'git-read') return true
    if (segment.tags.length === 0 && READ_ONLY_COMMANDS.has(segment.command)) {
      const tame = READ_ONLY_ARGUMENT_RULES.get(segment.command)
      if (tame !== undefined && !tame(segment.words.slice(1))) return false
      return true
    }
    return false
  })()

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
    readOnly,
    protectedMention: mentionsProtectedLocation(command),
    summary,
  }
}
