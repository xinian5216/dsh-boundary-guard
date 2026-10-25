# DSH 边界守卫（DSH Boundary Guard）

一个为 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
设计的基于模式的操作边界插件：三种可审计的运行模式、需人工审批的高风险操作、
永久受保护的凭据与配置位置，以及脱敏的本地审计轨迹。

本插件是构建在 DSH 原生机制之上的**策略层**——`tools/pre-execute` 瀑布流、
单调的 `ctx.tools.guard()` 兜底、沙箱策略服务、审批接口以及人类命令注册表。
它不修改 DSH 内部实现，也不承诺阻止所有可能的副作用。确切的保证与边界见
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)（英文）。

> 它不是沙箱的替代品，也不是"绝对安全"的保证。它提高事故与误用的成本，
> 并让高风险操作可见、可审批、可审计。

## 三种模式

| 模式 | 沙箱文件策略 | 用途 |
|---|---|---|
| `inspect`（排查） | `read-only` | 分析与排查：读取、搜索、只读 Git（`status`、`log`、`diff`、`show`）与只读 shell 命令（`ls`、`cat`、`echo`）。禁止一切写入、执行与无法分类的工具——审批也不能解除。 |
| `develop`（开发） | `workspace-write` | 日常开发：工作区内写入；高风险操作需审批。 |
| `maintain`（维护） | `danger-full-access` | 限时维护：每个高风险操作单独审批；受保护位置仍然禁止。 |

模式只能通过 `/guard` 命令（人类命令平面）切换。任何工具、提示词或模型消息
都不能提升模式。`maintain` 授权受 `maintain.maxDurationMs` 限制，不会在进程
重启后保留，过期后自动回落到 `develop`。子 Agent 原样继承父级模式；父级未知时
以 fail-closed 方式落入 `inspect`。

## 安装

要求：DeepSeek Harness `0.2.1-rc.3` 或任何 `0.2.x` 运行时
（`engines.dsh: ">=0.2.1-rc.3 <0.3.0"`），Node.js 24。

从 [v0.1.0 Release](https://github.com/xinian5216/dsh-boundary-guard/releases/tag/v0.1.0)
下载打包好的 bundle（`dsh-boundary-guard-0.1.0.tgz`，SHA-256 见随附的
`SHA256SUMS`），然后通过官方插件管理器安装：

```sh
# 从 release 压缩包安装
dsh plugin --profile <profile> add ./dsh-boundary-guard-0.1.0.tgz

# 或从本地构建安装
git clone https://github.com/xinian5216/dsh-boundary-guard.git
cd dsh-boundary-guard
pnpm install && pnpm run build && pnpm pack
dsh plugin --profile <profile> add ./dsh-boundary-guard-0.1.0.tgz
```

在 Web 客户端中也可以通过 **Plugins → Install** 选择该 `.tgz` 安装。profile 必须
已包含 DSH 基础组合（所有官方 profile 均如此）；插件依赖它提供
`@deepseek-ai/cordis` 与工具流水线。上架插件市场是后续工作，release 压缩包是
当前经过验证的分发渠道。

可用 [`examples/verify-install.ps1`](examples/verify-install.ps1) 在隔离的 DSH
主目录中完整复现安装 / 组合 / 加载 / 移除验证。

## 卸载

```sh
dsh plugin --profile <profile> remove dsh-boundary-guard
```

移除会取消选择该 bundle 并卸载其监听器。`$DSH_HOME/boundary-guard` 下的审计
日志与快照会保留，如需删除请手动处理。

只想禁用（不删除）：在 Web 客户端的 **Plugins** 页面切换该 bundle 的启用状态
（它会修改 profile 的 bundle 选择），或从
`$DSH_HOME/profiles/<profile>/package.json` 的 `dsh.profile.bundles` 列表中移除
对应条目。

## 命令

命令运行在可信的人类命令平面上，模型无法调用。

| 命令 | 作用 |
|---|---|
| `/guard status` | 当前模式、沙箱策略、工作区、审计与快照状态、受保护位置数量 |
| `/guard inspect` | 进入排查模式（沙箱 `read-only`） |
| `/guard develop` | 进入开发模式（沙箱 `workspace-write`） |
| `/guard maintain [分钟]` | 经确认后进入维护模式，授权有上限（默认与最大值 30 分钟） |
| `/guard audit [条数]` | 最近审计记录的脱敏摘要（默认 20 条） |
| `/guard snapshots` | 列出工作区快照 |
| `/guard rollback <id>` | 经确认后恢复某个快照 |

## 默认保护范围

- SSH 密钥与云凭据（`~/.ssh`、`~/.aws`、`~/.azure`、gcloud、Kubernetes、
  Docker、GnuPG、cargo/gem/GitHub CLI 凭据）
- 任意位置的 API Key 与令牌文件：`.env`、`.env.*`、`*.pem`、`*.key`、
  `*.p12`、`*.pfx`、`.netrc`、`.npmrc`、`.pypirc`、`.git-credentials`、
  `credentials`、`access_tokens`
- 其他 AI 客户端的全局配置（`~/.codex`、`~/.claude`、`~/.claude.json`、
  `~/.cursor`、`~/.opencode`、`~/.aider`）
- DSH 主目录、共享 agent 主目录（`~/.agents`）以及本插件自身的安装目录
- Windows 凭据存储（`%USERPROFILE%\AppData\*\Microsoft\Credentials`、
  `Microsoft\Protect`）

受保护位置在任何模式下（包括 maintain）都不可写入、删除或管理。在 develop 与
maintain 模式下读取凭据材料需要审批，在 inspect 模式下直接拒绝。

## 需要审批的操作

在 develop 与 maintain 模式下，以下操作会通过 DSH 审批界面请求批准：删除文件、
覆盖高价值配置（`package.json`、锁文件、`tsconfig`、CI 工作流、Dockerfile 等）、
批量操作、依赖与系统安装、Git 状态变更、历史重写与远程写入、远程会话与上传、
破坏性命令、提权、系统配置变更、守卫无法完全分析的动态执行、沙箱升级参数、
工作区外写入（仅 maintain）、以及无法识别的工具。

审批是针对当次调用的一次性授权。拒绝、取消以及审批通道不可用都会导致操作被
拒绝——绝不会静默重试。

## 审计

每次决策都以 JSONL 形式追加到 `$DSH_HOME/boundary-guard/audit/`，包含：时间、
会话标识、模式、工具族、操作类型、风险级别、决策结果、原因代码、脱敏目标、
标签以及审批结果。日志绝不包含命令原文、文件内容或密钥。`/guard audit` 可查看
脱敏摘要。

## 开发

```sh
pnpm install
pnpm run typecheck
pnpm test          # 单元 + 集成 + 安全回归
pnpm run build     # 产出 bundle 所需的 lib/
```

- `tests/unit` —— 纯函数测试（路径、受保护集合、策略引擎、shell 分析、脱敏、
  模式管理）。
- `tests/integration` —— 真实 DSH 流水线：ToolRuntime、fs 与 pwsh 工具、
  Windows ACL 沙箱提供者、审批服务与命令注册表。
- `tests/security` —— 15 项验收回归（模式隔离、受保护路径、审批结果、符号链接
  逃逸、子 Agent 继承、配置 fail-closed、审计保密、多会话隔离、卸载）。

## 文档

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)（英文）—— 保证与边界
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md)（英文）—— 全部配置项与存储路径
- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)（英文）—— 已验证版本、扩展点、
  平台说明
- [SECURITY.md](SECURITY.md) —— 漏洞报告
- [CONTRIBUTING.md](CONTRIBUTING.md) —— 开发规则
- [CHANGELOG.md](CHANGELOG.md)

## 许可证

MIT，见 [LICENSE](LICENSE)。
