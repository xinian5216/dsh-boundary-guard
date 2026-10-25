/**
 * Protected-path discovery and matching.
 *
 * Protection is derived from cross-platform locations (home directory, DSH
 * home, shared agent home, the plugin's own install root) — never from one
 * developer machine's absolute paths. Sensitive *content* is never read to
 * decide sensitivity; only paths are matched.
 *
 * @module dsh-boundary-guard/boundary/protected
 */
import { homedir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { isInside, joinPath, normalizePath, type Platform } from './paths.ts'

/** Why a path is protected; drives the reason code and UI text. */
export type ProtectionKind =
  | 'credential'
  | 'ai-client-config'
  | 'dsh-home'
  | 'plugin-self'
  | 'system-credential-store'

/** One protected root with its kind. */
export interface ProtectedRoot {
  readonly kind: ProtectionKind
  readonly root: string
  /** Short, non-identifying label for approval prompts. */
  readonly label: string
}

/** File-name patterns whose content is credential material wherever they sit. */
const CREDENTIAL_FILE_PATTERNS: readonly RegExp[] = [
  /^\.env$/i,
  /^\.env\..+$/i,
  /^id_rsa$/i,
  /^id_dsa$/i,
  /^id_ecdsa$/i,
  /^id_ed25519$/i,
  /^identity$/i,
  /^.*\.pem$/i,
  /^.*\.key$/i,
  /^.*\.p12$/i,
  /^.*\.pfx$/i,
  /^.*\.jks$/i,
  /^credentials$/i,
  /^credentials\.json$/i,
  /^credentials\.db$/i,
  /^access_tokens$/i,
  /^\.netrc$/i,
  /^\.pgpass$/i,
  /^\.npmrc$/i,
  /^\.pypirc$/i,
  /^\.git-credentials$/i,
]

/** Directory roots whose contents are credential material. */
const CREDENTIAL_DIRS: readonly { suffix: string; kind: ProtectionKind; label: string }[] = [
  { suffix: '.ssh', kind: 'credential', label: 'SSH directory' },
  { suffix: '.aws', kind: 'credential', label: 'AWS credentials' },
  { suffix: '.azure', kind: 'credential', label: 'Azure credentials' },
  { suffix: '.config/gcloud', kind: 'credential', label: 'Google Cloud credentials' },
  { suffix: '.kube', kind: 'credential', label: 'Kubernetes credentials' },
  { suffix: '.docker', kind: 'credential', label: 'Docker credentials' },
  { suffix: '.gnupg', kind: 'credential', label: 'GnuPG keyring' },
  { suffix: '.cargo/credentials', kind: 'credential', label: 'Cargo credentials' },
  { suffix: '.gem/credentials', kind: 'credential', label: 'RubyGems credentials' },
  { suffix: '.config/gh', kind: 'credential', label: 'GitHub CLI credentials' },
  { suffix: '.dsh', kind: 'dsh-home', label: 'DeepSeek Harness home' },
  { suffix: '.agents', kind: 'dsh-home', label: 'Shared agent configuration home' },
]

/** Other AI clients' global configuration trees, protected from writes. */
const AI_CLIENT_DIRS: readonly { suffix: string; label: string }[] = [
  { suffix: '.codex', label: 'Codex configuration' },
  { suffix: '.claude', label: 'Claude Code configuration' },
  { suffix: '.cursor', label: 'Cursor configuration' },
  { suffix: '.opencode', label: 'OpenCode configuration' },
  { suffix: '.config/opencode', label: 'OpenCode configuration' },
  { suffix: '.aider', label: 'Aider configuration' },
]

/** Windows credential stores and other host secret locations. */
const WINDOWS_SECRET_DIRS: readonly { suffix: string; label: string }[] = [
  { suffix: 'AppData/Roaming/Microsoft/Credentials', label: 'Windows Credential Manager' },
  { suffix: 'AppData/Local/Microsoft/Credentials', label: 'Windows Credential Manager' },
  { suffix: 'AppData/Roaming/Microsoft/Protect', label: 'Windows DPAPI protection' },
]

/** Home-root credential files. */
const HOME_CREDENTIAL_FILES: readonly string[] = ['.netrc', '.pgpass', '.npmrc', '.pypirc', '.git-credentials']

/** Home-root configuration files of other AI clients (protected from writes). */
const HOME_AI_CLIENT_FILES: readonly string[] = ['.claude.json', '.codex.json', '.cursor.json', '.aider.conf.yml']

/** Inputs for {@link discoverProtectedRoots}. */
export interface ProtectedDiscoveryInput {
  readonly homedir: string
  /** DSH home (DSH_HOME or ~/.dsh). */
  readonly dshHome: string
  /** Shared agent configuration home (DSH_AGENTS_HOME or ~/.agents). */
  readonly agentsHome: string
  /** This plugin's install root. */
  readonly pluginRoot: string
  readonly platform: Platform
}

/**
 * Discover the protected roots for this machine. Pure and synchronous so the
 * guard can rebuild it after configuration changes without I/O.
 */
export function discoverProtectedRoots(input: ProtectedDiscoveryInput): ProtectedRoot[] {
  const { homedir: home, platform } = input
  const roots: ProtectedRoot[] = []
  const seen = new Set<string>()
  const add = (kind: ProtectionKind, root: string, label: string) => {
    const normalized = normalizePath(root, undefined, platform).toLowerCase()
    if (seen.has(normalized)) return
    seen.add(normalized)
    roots.push({ kind, root: normalizePath(root, undefined, platform), label })
  }
  for (const dir of CREDENTIAL_DIRS) {
    const base = dir.kind === 'dsh-home' ? undefined : home
    if (base === undefined) continue
    add(dir.kind, joinPath(platform, base, dir.suffix), dir.label)
  }
  add('dsh-home', input.dshHome, 'DeepSeek Harness home')
  add('dsh-home', input.agentsHome, 'Shared agent configuration home')
  for (const dir of AI_CLIENT_DIRS) {
    add('ai-client-config', joinPath(platform, home, dir.suffix), dir.label)
  }
  for (const dir of WINDOWS_SECRET_DIRS) {
    if (platform !== 'win32') continue
    add('system-credential-store', joinPath(platform, home, dir.suffix), dir.label)
  }
  add('plugin-self', input.pluginRoot, 'DSH Boundary Guard installation')
  for (const file of HOME_CREDENTIAL_FILES) {
    add('credential', joinPath(platform, home, file), `${file} credential file`)
  }
  for (const file of HOME_AI_CLIENT_FILES) {
    add('ai-client-config', joinPath(platform, home, file), `${file} AI client configuration`)
  }
  return roots
}

/** Resolve this plugin's own install root from its module location. */
export function currentPluginRoot(moduleUrl: string = import.meta.url): string {
  // src/boundary/protected.ts or lib/index.js → package root is two levels up.
  const here = fileURLToPath(moduleUrl)
  const trimmed = here.replace(/[\\/](src|lib)[\\/][^\\/]*$/, '')
  return trimmed || here
}

/** The classification of one path against the protected set. */
export interface ProtectionMatch {
  readonly kind: ProtectionKind
  readonly label: string
  /** The protected root that matched. */
  readonly root: string
}

/**
 * Match a path against the protected roots. Directory roots match their whole
 * subtree; file patterns match by name anywhere in the tree.
 */
export function matchProtectedPath(
  absolutePath: string,
  roots: readonly ProtectedRoot[],
  platform: Platform,
): ProtectionMatch | undefined {
  for (const root of roots) {
    if (isInside(root.root, absolutePath, platform)) {
      return { kind: root.kind, label: root.label, root: root.root }
    }
  }
  const name = absolutePath.split(/[\\/]/).pop() ?? ''
  for (const pattern of CREDENTIAL_FILE_PATTERNS) {
    if (pattern.test(name)) {
      return { kind: 'credential', label: `${name} credential file`, root: absolutePath }
    }
  }
  return undefined
}

/** High-value configuration files whose overwrite needs approval. */
const HIGH_VALUE_CONFIG_PATTERNS: readonly RegExp[] = [
  /^package\.json$/i,
  /^package-lock\.json$/i,
  /^pnpm-lock\.yaml$/i,
  /^yarn\.lock$/i,
  /^bun\.lockb$/i,
  /^tsconfig.*\.json$/i,
  /^jsconfig.*\.json$/i,
  /^dockerfile$/i,
  /^docker-compose.*\.ya?ml$/i,
  /^makefile$/i,
  /^\.gitconfig$/i,
  /^\.gitattributes$/i,
  /^\.editorconfig$/i,
  /^\.npmrc$/i,
  /^\.nvmrc$/i,
  /^\.node-version$/i,
  /^\.tool-versions$/i,
  /^cargo\.toml$/i,
  /^pyproject\.toml$/i,
  /^go\.mod$/i,
  /^go\.sum$/i,
  /^gemfile$/i,
  /^gemfile\.lock$/i,
  /^requirements.*\.txt$/i,
  /^pom\.xml$/i,
  /^build\.gradle.*$/i,
  /^\.github[\\/]workflows[\\/].+\.ya?ml$/i,
  /^\.gitlab-ci\.yml$/i,
  /^azure-pipelines.*\.ya?ml$/i,
  /^vite\.config\..+$/i,
  /^webpack\.config\..+$/i,
  /^rollup\.config\..+$/i,
  /^esbuild\..+$/i,
  /^eslint\.config\..+$/i,
  /^\.eslintrc.*$/i,
  /^prettier\.config\..+$/i,
  /^\.prettierrc.*$/i,
  /^biome\.json.*$/i,
  /^renovate\.json.*$/i,
  /^dependabot\.ya?ml$/i,
]

/** Whether a path names a high-value configuration file. */
export function isHighValueConfig(absolutePath: string): boolean {
  const segments = absolutePath.split(/[\\/]/)
  const name = segments.pop() ?? ''
  const parent = segments.pop() ?? ''
  const grandparent = segments.pop() ?? ''
  for (const pattern of HIGH_VALUE_CONFIG_PATTERNS) {
    if (pattern.test(name)) return true
    // `.github/workflows/ci.yml` style paths: match the directory tail too.
    if (pattern.test(`${parent}/${name}`)) return true
    if (pattern.test(`${parent}\\${name}`)) return true
    if (pattern.test(`${grandparent}/${parent}/${name}`)) return true
    if (pattern.test(`${grandparent}\\${parent}\\${name}`)) return true
  }
  return false
}

/** Environment-derived discovery input using the current process. */
export function discoveryFromEnvironment(env: NodeJS.ProcessEnv = process.env): {
  homedir: string
  dshHome: string
  agentsHome: string
} {
  const home = homedir()
  const expand = (value: string | undefined, fallback: string): string => {
    if (value === undefined || value === '') return fallback
    if (value === '~') return home
    if (value.startsWith('~/') || value.startsWith('~\\')) return home + value.slice(1)
    return value
  }
  return {
    homedir: home,
    dshHome: expand(env.DSH_HOME, joinPath('posix', home, '.dsh')),
    agentsHome: expand(env.DSH_AGENTS_HOME, joinPath('posix', home, '.agents')),
  }
}
