/**
 * Approval adapter: turns a policy `ask` into a DSH approval request through
 * the official `ctx.approval` seam, and maps the outcome back to a decision.
 *
 * The audited `reason` is sanitized by construction (classification and
 * labels only). The `displayReason` shows the human the specific command,
 * target paths, risk, and consequences — with secrets redacted — because a
 * meaningful approval requires seeing the real operation.
 *
 * @module dsh-boundary-guard/approval/adapter
 */
import type { ApprovalOutcome } from '@deepseek-ai/dsh-user-approval'
import { matchProtectedPath, type ProtectedRoot } from '../boundary/protected.ts'
import { isInside, type Platform } from '../boundary/paths.ts'
import type { ClassifiedOperation, GuardMode, PolicyResult } from '../types.ts'
import { redactSecrets, truncate } from '../audit/sanitize.ts'

/** The approval request view for one ask decision. */
export interface ApprovalView {
  /** Sanitized reason stored in the session approval audit. */
  readonly reason: string
  /** Localized presentation text shown in the approval UI. */
  readonly displayReason: { readonly en: string; readonly [locale: string]: string }
}

/** Inputs for building an approval view. */
export interface ApprovalViewInput {
  readonly mode: GuardMode
  readonly operation: ClassifiedOperation
  readonly result: PolicyResult
  readonly workspaceRoot: string | undefined
  readonly protectedRoots: readonly ProtectedRoot[]
  readonly platform: Platform
  /** Raw arguments, used ONLY to build the redacted display text. */
  readonly args: unknown
}

/** Display one target path: workspace-relative, protected label, or basename. */
function displayTarget(
  absolutePath: string,
  workspaceRoot: string | undefined,
  protectedRoots: readonly ProtectedRoot[],
  platform: Platform,
): string {
  const match = matchProtectedPath(absolutePath, protectedRoots, platform)
  if (match !== undefined) return `${match.label} (protected)`
  if (workspaceRoot !== undefined && isInside(workspaceRoot, absolutePath, platform)) {
    const relative = absolutePath.slice(workspaceRoot.length).replace(/^[\\/]+/, '')
    return relative === '' ? '.' : relative
  }
  const name = absolutePath.split(/[\\/]/).pop() ?? absolutePath
  return `<outside workspace>/${name}`
}

/** Extract the raw command text from tool arguments, when present. */
function rawCommand(args: unknown): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined
  const value = (args as Record<string, unknown>).command
  return typeof value === 'string' ? value : undefined
}

/** Extract raw code text from tool arguments, when present. */
function rawCode(args: unknown): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined
  const value = (args as Record<string, unknown>).code
  return typeof value === 'string' ? value : undefined
}

/** Human consequence text per reason code. */
function consequenceOf(reasonCode: string, tool: string): { en: string; zh: string } {
  switch (reasonCode) {
    case 'delete-requires-approval':
      return { en: 'Files or directories will be permanently deleted.', zh: '文件或目录将被永久删除。' }
    case 'dependency-install':
      return { en: 'Dependencies will be installed or updated; lockfiles may change and build scripts may run.', zh: '将安装或更新依赖；锁文件可能变化，并可能执行构建脚本。' }
    case 'git-remote-write':
      return { en: 'Changes will be pushed to a remote repository.', zh: '更改将被推送到远程仓库。' }
    case 'git-history-rewrite':
      return { en: 'Git history will be rewritten; previous commits may become unreachable.', zh: '将重写 Git 历史；此前的提交可能无法找回。' }
    case 'git-state-change':
      return { en: 'Important Git state (branches, index, or refs) will change.', zh: '重要的 Git 状态（分支、索引或引用）将发生变化。' }
    case 'remote-operation':
      return { en: 'Data will be sent to or a session opened with a remote host.', zh: '数据将发送到远程主机，或与远程主机建立会话。' }
    case 'dynamic-execution':
      return { en: 'Code that the guard cannot fully analyze will execute with the session\'s permissions.', zh: '将执行守卫无法完全分析的代码，并使用当前会话的权限。' }
    case 'destructive-command':
      return { en: 'A destructive command will run and may remove data irreversibly.', zh: '将执行破坏性命令，可能不可逆地删除数据。' }
    case 'privilege-escalation':
      return { en: 'Elevated privileges will be requested.', zh: '将请求提升权限。' }
    case 'system-config':
      return { en: 'System configuration will be modified.', zh: '将修改系统配置。' }
    case 'bulk-operation':
      return { en: 'A bulk operation over many files will run.', zh: '将对大量文件执行批量操作。' }
    case 'outside-workspace-approval':
      return { en: 'A path outside the authorized workspace will be modified.', zh: '将修改授权工作区之外的路径。' }
    case 'high-value-config-overwrite':
      return { en: 'A high-value configuration file will be overwritten.', zh: '将覆盖高价值配置文件。' }
    case 'sandbox-escalation':
      return { en: 'The command requests a wider sandbox mode than the session grants.', zh: '该命令请求比当前会话更宽的沙箱模式。' }
    case 'credential-material':
      return { en: 'Credential material will be read into the conversation.', zh: '凭据材料将被读入对话。' }
    case 'unknown-tool-approval':
      return { en: `Tool "${tool}" is not recognized by the guard; its effects cannot be predicted.`, zh: `守卫无法识别工具“${tool}”；其效果无法预测。` }
    default:
      return { en: 'The operation will run once if approved.', zh: '批准后该操作将执行一次。' }
  }
}

/** Build the approval view for one ask decision. */
export function buildApprovalView(input: ApprovalViewInput): ApprovalView {
  const { mode, operation, result, workspaceRoot, protectedRoots, platform } = input
  const targets = operation.targets.map((target) =>
    displayTarget(target.absolute, workspaceRoot, protectedRoots, platform),
  )
  const command = rawCommand(input.args) ?? rawCode(input.args)
  const redactedCommand = command === undefined ? undefined : truncate(redactSecrets(command), 600)

  const reason = `boundary-guard[${mode}/${result.reasonCode}]: ${operation.toolName} ${operation.operation}` +
    (targets.length > 0 ? ` targets=${targets.join(', ')}` : '') +
    (operation.tags.length > 0 ? ` tags=${operation.tags.join(',')}` : '')

  const en = [
    `[DSH Boundary Guard] Approval required (${mode} mode)`,
    `Tool: ${operation.toolName} — ${operation.operation} (risk: ${result.risk})`,
    ...(targets.length > 0 ? [`Targets: ${targets.join(', ')}`] : []),
    ...(operation.tags.length > 0 ? [`Detected: ${operation.tags.join(', ')}`] : []),
    `Reason: ${result.reasonCode} — ${result.reason}`,
    `Consequence: ${consequenceOf(result.reasonCode, operation.toolName).en}`,
    ...(redactedCommand === undefined ? [] : [`Command (redacted): ${redactedCommand}`]),
    'Approving runs this exact operation once. It is not remembered for similar operations.',
  ].join('\n')

  const zh = [
    `[DSH 边界守卫] 需要审批（${mode} 模式）`,
    `工具：${operation.toolName} — ${operation.operation}（风险：${result.risk}）`,
    ...(targets.length > 0 ? [`目标：${targets.join(', ')}`] : []),
    ...(operation.tags.length > 0 ? [`检测到：${operation.tags.join(', ')}`] : []),
    `原因：${result.reasonCode} — ${result.reason}`,
    `后果：${consequenceOf(result.reasonCode, operation.toolName).zh}`,
    ...(redactedCommand === undefined ? [] : [`命令（已脱敏）：${redactedCommand}`]),
    '批准后仅执行这一次该操作，类似操作不会自动获得信任。',
  ].join('\n')

  return { reason, displayReason: { en, 'zh-CN': zh } }
}

/** Map an approval outcome to the model-facing denial reason. */
export function denialForOutcome(toolName: string, outcome: ApprovalOutcome): string {
  switch (outcome) {
    case 'rejected':
      return `the user rejected ${toolName}`
    case 'cancelled':
      return `approval for ${toolName} was cancelled`
    case 'unavailable':
      return `${toolName} requires approval, but no approval channel is available`
    default:
      return `${toolName} was not approved`
  }
}
