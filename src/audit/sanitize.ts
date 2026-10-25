/**
 * Redaction helpers shared by the audit log and approval presentation.
 *
 * The audit log NEVER stores raw command text, file contents, or secrets: it
 * stores classifications, sanitized targets, and decisions. Approval prompts
 * DO show the user the real (redacted) command — the human must see what they
 * approve — but that text lives only in the approval channel, never in the
 * audit record.
 *
 * @module dsh-boundary-guard/audit/sanitize
 */

const SECRET_PATTERNS: readonly { pattern: RegExp; replacement: string }[] = [
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: '[REDACTED PRIVATE KEY]' },
  { pattern: /\b(sk|pk|rk|ak)-[A-Za-z0-9_\-]{8,}/g, replacement: '[REDACTED KEY]' },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/g, replacement: '[REDACTED AWS KEY]' },
  { pattern: /\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}/g, replacement: '[REDACTED GITHUB TOKEN]' },
  { pattern: /\bxox[baprs]-[A-Za-z0-9\-]{10,}/g, replacement: '[REDACTED SLACK TOKEN]' },
  { pattern: /\bAIza[0-9A-Za-z_\-]{35}\b/g, replacement: '[REDACTED GOOGLE KEY]' },
  { pattern: /\bya29\.[0-9A-Za-z_\-]{20,}/g, replacement: '[REDACTED OAUTH TOKEN]' },
  { pattern: /\bBearer\s+[A-Za-z0-9._\-]{16,}/gi, replacement: 'Bearer [REDACTED TOKEN]' },
  { pattern: /(?<=((?i:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential)s?)\s*[=:]\s*)(["']?)[^"'\s]{6,}\2/gi, replacement: '[REDACTED]' },
  { pattern: /--(password|token|api-key|secret)[= ][^\s"']+/gi, replacement: '--$1=[REDACTED]' },
  { pattern: /\b[0-9a-fA-F]{40,}\b/g, replacement: '[REDACTED HEX TOKEN]' },
]

/** Redact secret-looking material from text intended for a human. */
export function redactSecrets(text: string): string {
  let out = text
  for (const { pattern, replacement } of SECRET_PATTERNS) {
    out = out.replace(pattern, replacement)
  }
  return out
}

/** Whether text contains anything that looks like secret material. */
export function containsSecret(text: string): boolean {
  return redactSecrets(text) !== text
}

/** Truncate text for logs, marking the cut. */
export function truncate(text: string, maxBytes: number): string {
  if (text.length <= maxBytes) return text
  return `${text.slice(0, maxBytes)}…[truncated ${text.length - maxBytes} chars]`
}
