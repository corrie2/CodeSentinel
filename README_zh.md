**[English](README.md)** | 中文

# CodeSentinel — PR 风险顾问 & 生态审计官

PR 风险顾问 & 生态审计官。

输入一个 PR，输出一份结构化的风险评估报告。不是找 bug 的工具，而是告诉你**这个 PR 会不会炸、什么时候能合并**。

## 快速开始

```bash
# Install
pip install -e .
# or
uv sync

# 审查 GitHub PR
export GITHUB_TOKEN=***
export MIMO_API_KEY=***
codesentinel review https://github.com/owner/repo/pull/123

# 审查 GitLab MR（支持嵌套命名空间）
export GITLAB_TOKEN=***
codesentinel review https://gitlab.com/group/subgroup/project/-/merge_requests/456

# Output to file
codesentinel review <pr_url> --output report.md

# Skip LLM deep review (faster, no API key needed)
codesentinel review <pr_url> --skip-llm

# With local repo (enables git history + CODEOWNERS)
codesentinel review <pr_url> --repo-path ./my-repo
```

## 架构

三级漏斗模型：

```
PR → [Level 1: 风险评分] → 低风险: 仅记录
                           → 中风险: +供应链审计 +工程影响
                           → 高风险: +LLM深度审查 (问题+证据+测试骨架)
```

### Level 1 — 风险评分（秒级）

确定性规则引擎，不依赖 LLM。19 条内置规则覆盖：

- 变更规模（文件数、行数、hunk 数）
- 敏感路径（payment/、auth/、security/）
- 依赖变更（新增、升级、删除）
- 作者经验（首次贡献、模块熟悉度）
- 项目关键路径（.codesentinel/rules.toml 自定义）

输出：风险等级（低/中/高）+ 贡献来源明细：
```
Risk Level: ⚠️ Medium
Risk Points: 8
  +5 sensitive path (payment/)
  +3 large PR (25 files)
```

### Level 2 — 供应链审计 + 工程影响（分钟级）

- **供应链审计**：查询 OSV 数据库，检测依赖 CVE、许可证风险
- **工程影响评估**：预估构建时间变化、测试覆盖影响、模块耦合度
- **依赖扫描**：三层架构（detect → patch parse → full diff），支持 8 种包管理格式

### Level 3 — LLM 深度审查（按需）

仅高风险 PR 触发。使用 risk-aware 文件选择：

- 敏感路径：+50
- 配置/依赖文件：+40
- 项目关键路径：+weight
- 高缺陷模块：+30
- 无对应测试：+20
- 生产路径：+15
- 删除代码：+15
- 权限逻辑：+25
- 错误处理：+15

输出：问题描述 + 证据 + 可执行测试骨架。

## 项目规则

```bash
# Generate project-specific rules
codesentinel init
codesentinel init --minimal   # Only rules.toml
codesentinel init --force     # Overwrite existing
```

生成 `.codesentinel/` 目录：

```
.codesentinel/
  rules.toml            # 风险规则 + 关键路径
  project_profile.md    # 项目背景（注入 LLM prompt）
  review_policy.md      # 审查原则（注入 LLM prompt）
```

### rules.toml

```toml
[settings]
low_risk_max = 3
medium_risk_max = 6

[[rules]]
name = "payment_change"
description = "Changes to payment module"
condition = "touches('payment/')"
score_delta = 5
tag = "security"

[project]
critical_paths = [
    {path = "src/core/", weight = 50, reason = "Core engine"},
    {path = "payment/", weight = 40, reason = "Payment flow"},
]
```

### 安全机制

`.codesentinel/` 配置永远从 **base branch** 读取，不读 PR head。

如果 PR 修改了 `.codesentinel/`，报告会显示：
> ⚠️ 审查策略被本次PR修改 — 本次审查使用 base branch 配置，新策略将在合并后生效。

防止恶意 PR 通过修改配置注入 prompt。

## 流水线状态

每步都有状态追踪，报告里可见：

```
| Step              | Status | Detail                          |
|-------------------|--------|---------------------------------|
| PR Data           | ✅ ok   | PR data collected               |
| Dependency Scan   | ⚠️ partial | patch-only, 2 deps found    |
| Risk Scoring      | ✅ ok   | Risk: HIGH (score=12)           |
| OSV Audit         | ✅ ok   | 0 vulnerabilities found         |
| Impact Assessment | ✅ ok   | Build impact: +90s              |
| LLM Deep Review   | ✅ ok   | 3 findings                      |
| Project Context   | ✅ ok   | Loaded 2 file(s)                |
```

## Python API

CodeSentinel 可以作为 Python 库使用，无需 CLI。

### 异步（推荐）

```python
import asyncio
from code_sentinel import review, ReviewOptions

async def main():
    # GitHub PR
    result = await review(
        "https://github.com/owner/repo/pull/123",
        options=ReviewOptions(provider="mimo"),
    )
    print(f"Risk: {result.risk.level} ({result.risk.score} points)")

    # GitLab MR（支持嵌套命名空间）
    result = await review(
        "https://gitlab.com/group/subgroup/project/-/merge_requests/456",
        options=ReviewOptions(provider="mimo"),
    )
    print(f"Risk: {result.risk.level} ({result.risk.score} points)")

asyncio.run(main())
```

### 同步

```python
from code_sentinel import review_sync, ReviewOptions

result = review_sync(
    "https://github.com/owner/repo/pull/123",
    options=ReviewOptions(skip_llm=True),
)
print(result.summary)
```

### ReviewOptions

所有字段都是可选的 — 留空为 `None` 时从配置文件和环境变量解析。

```python
ReviewOptions(
    provider="mimo",          # LLM provider (mimo, deepseek)
    model="mimo-v2.5-pro",   # Model name
    api_key="...",            # LLM API key
    github_token="...",       # GitHub API token
    rules_path="rules.toml", # Custom rules file
    repo_path=".",            # Local repo path (enables git history)
    skip_llm=False,           # Skip LLM deep review
    timeout_seconds=120,      # Pipeline timeout
    strict=False,             # Raise on any pipeline error
    auditors=[],              # Custom auditor plugins
    reporters=[],             # Custom reporter plugins
)
```

### ReviewResult

```python
result.risk.level              # "low" / "medium" / "high"
result.risk.score              # int
result.risk.contributions      # list[RiskContribution]
result.llm_review.findings     # list[Finding]
result.dependencies            # DependencySummary
result.supply_chain            # SupplyChainSummary
result.impact                  # ImpactSummary
result.attention               # list[AttentionFile]
result.pipeline.steps          # list[PipelineStep]
result.reports                 # dict[str, str] (markdown, json, pr-comment)
result.summary                 # one-line human-readable string
result.is_high_risk            # bool
result.has_findings            # bool
result.to_dict()               # serialize to plain dict
```

## 插件系统

CodeSentinel 支持 auditor 和 reporter 插件扩展。

### AuditorPlugin

向流水线添加自定义分析步骤。继承 `AuditorPlugin` 并实现 `audit()`：

```python
from code_sentinel.plugins import AuditorPlugin, AuditContext, AuditResult

class MyAuditor(AuditorPlugin):
    name = "my_auditor"

    async def audit(self, context: AuditContext) -> AuditResult:
        result = AuditResult(name=self.name)
        # Access: context.changeset, context.raw_diff, context.dep_changes, ...
        result.status = "ok"
        result.findings.append({"type": "custom", "severity": "medium", "message": "..."})
        return result
```

通过 `ReviewOptions(auditors=[MyAuditor()])` 传入。

### ReporterPlugin

添加自定义输出格式。继承 `ReporterPlugin` 并实现 `render()`：

```python
from code_sentinel.plugins import ReporterPlugin
from code_sentinel.result import ReviewResult

class SlackReporter(ReporterPlugin):
    name = "slack"

    def render(self, result: ReviewResult) -> str:
        return f"Risk: {result.risk.level} ({result.risk.score})"
```

通过 `ReviewOptions(reporters=[SlackReporter()])` 传入。渲染后的输出在 `result.reports["slack"]` 中。

### 内置插件

| 插件 | 类型 | 名称 | 描述 |
|------|------|------|------|
| `MarkdownReporter` | Reporter | `markdown` | 完整 Markdown 报告 |
| `JsonReporter` | Reporter | `json` | JSON 序列化 |
| `PrCommentReporter` | Reporter | `pr-comment` | GitHub PR 评论格式 |
| `SupplyChainAuditor` | Auditor | `supply_chain` | OSV 漏洞扫描 |
| `ImpactAuditor` | Auditor | `impact` | 构建/测试影响评估 |
| `DeepReviewAuditor` | Auditor | `deep_review` | LLM 深度审查（仅高风险） |

## 示例

查看 `examples/` 目录：

| 文件 | 描述 |
|------|------|
| `examples/basic.py` | 一行代码异步审查 |
| `examples/basic_sync.py` | 同步用法 |
| `examples/custom_rules.py` | 项目自定义 rules.toml |
| `examples/custom_reporter.py` | 自定义 Slack reporter 插件 |
| `examples/custom_auditor.py` | 自定义 SQL 注入 & 凭证 auditor |
| `examples/ci_pipeline.py` | CI/CD 集成与退出码 |

运行示例：

```bash
python examples/basic.py
```

## Harness 架构

CodeSentinel 采用三级漏斗 + 插件 harness 模式：

```
PR URL
  │
  ├─ Collect PR Data (GitHub API)
  ├─ Parse Diff → ChangeSet
  ├─ Dependency Scan (3-layer: detect → patch → full diff)
  ├─ Load Project Context (.codesentinel/)
  │
  ├─ Level 1: Risk Scoring (deterministic rules)
  │   └─ 19 built-in rules + custom rules.toml
  │
  ├─ Level 2: Auditors (plugin harness)
  │   ├─ SupplyChainAuditor → OSV vulnerabilities
  │   ├─ ImpactAuditor → build/test impact
  │   └─ [Custom AuditorPlugins]
  │
  ├─ Level 3: LLM Deep Review (high-risk only)
  │   └─ risk-aware file selection → findings + test skeletons
  │
  ├─ Reporters (plugin harness)
  │   ├─ MarkdownReporter
  │   ├─ JsonReporter
  │   ├─ PrCommentReporter
  │   └─ [Custom ReporterPlugins]
  │
  └─ ReviewResult (unified output)
```

Harness 模式：

1. **AuditorPlugin.audit(context) → AuditResult** — 每个 auditor 获取包含所有 PR 数据的 `AuditContext`，返回带有 findings/warnings 的 `AuditResult`。
2. **ReporterPlugin.render(result) → str** — 每个 reporter 将 `ReviewResult` 转换为格式化字符串。
3. **流水线编排器**按顺序运行 auditors，收集结果，然后运行 reporters。部分失败会被容忍，除非设置 `strict=True`。

## GitHub Action

```yaml
# .github/workflows/audit.yml
name: CodeSentinel
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv python install 3.11
      - run: uv tool install git+https://github.com/corrie2/CodeSentinel.git@main
      - run: codesentinel review "${{ github.event.pull_request.html_url }}" --output report.md
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          MIMO_API_KEY: ${{ secrets.MIMO_API_KEY }}
```

## Webhook 服务

```bash
# Start webhook server
codesentinel serve --port 8080

# GitHub webhook: POST /webhook/github
# GitLab webhook: POST /webhook/gitlab
```

Webhook 服务执行完整流水线：
1. 接收来自 GitHub 或 GitLab 的 PR/MR 事件
2. 运行风险评分、依赖审计和 LLM 深度审查
3. **将审查结果回写为 PR/MR 评论**

要回写评论，Token 需要写权限：
- GitHub: `GITHUB_TOKEN` 需要 `issues:write` 权限
- GitLab: `GITLAB_TOKEN` 需要 `api` scope

## 配置

环境变量（优先级：`CODESENTINEL_` 前缀 > 无前缀）：

| 变量 | 说明 |
|------|------|
| `GITHUB_TOKEN` | GitHub API Token |
| `MIMO_API_KEY` | MiMo LLM API Key（默认） |
| `DEEPSEEK_API_KEY` | DeepSeek API Key（备选） |
| `GITLAB_TOKEN` | GitLab API Token（可选） |

## CLI 命令

```
codesentinel review <pr_url>     # 审查 PR/MR（GitHub 或 GitLab）
codesentinel serve               # Start webhook server
codesentinel init                # Generate .codesentinel/ template
codesentinel config show         # Show current config
codesentinel config set <k> <v>  # Set config value
```

支持的 URL 格式：
- GitHub: `https://github.com/{owner}/{repo}/pull/{number}`
- GitLab: `https://{host}/{project_path}/-/merge_requests/{number}`
  - 支持嵌套命名空间：`group/subgroup/project`

## 项目结构

```
src/code_sentinel/
  cli.py                 # CLI entry point
  config.py              # Configuration management
  server.py              # FastAPI webhook server
  git_provider/          # GitHub + GitLab API
  collector/             # diff_parser, dep_scanner, codeowners, git_history
  risk/                  # scorer, rules, file_ranker, memory
  auditor/               # supply_chain, impact, deep_review
  reporter/              # formatter (Markdown/JSON/PR comment)
  llm/                   # LLM client + prompts
rules/                   # Default risk rules
templates/               # Report templates
```

## License

MIT
