# CodeSentinel — Risk Advisor & Ecosystem Auditor

PR 风险顾问 & 生态审计官。

输入一个 PR，输出一份结构化的风险评估报告。不是找 bug 的工具，而是告诉你"这个 PR 会不会炸、什么时候能合并"。

## Quick Start

```bash
# Install
pip install -e .
# or
uv sync

# Review a PR
export GITHUB_TOKEN=your_token
export MIMO_API_KEY=your_key
codesentinel review https://github.com/owner/repo/pull/123

# Output to file
codesentinel review <pr_url> --output report.md

# Skip LLM deep review (faster, no API key needed)
codesentinel review <pr_url> --skip-llm

# With local repo (enables git history + CODEOWNERS)
codesentinel review <pr_url> --repo-path ./my-repo
```

## Architecture

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

- 敏感路径 +50
- 配置/依赖文件 +40
- 项目关键路径 +weight
- 高缺陷模块 +30
- 无对应测试 +20
- 生产路径 +15
- 删除代码 +15
- 权限逻辑 +25
- 错误处理 +15

输出：问题描述 + 证据 + 可执行测试骨架。

## Project Rules

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

## Pipeline Status

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

## Webhook Server

```bash
# Start webhook server
codesentinel serve --port 8080

# GitHub webhook: POST /webhook/github
# GitLab webhook: POST /webhook/gitlab
```

## Configuration

环境变量（优先级：`CODESENTINEL_` 前缀 > 无前缀）：

| 变量 | 说明 |
|------|------|
| `GITHUB_TOKEN` | GitHub API Token |
| `MIMO_API_KEY` | MiMo LLM API Key（默认） |
| `DEEPSEEK_API_KEY` | DeepSeek API Key（备选） |
| `GITLAB_TOKEN` | GitLab API Token（可选） |

## CLI Commands

```
codesentinel review <pr_url>     # Review a PR
codesentinel serve               # Start webhook server
codesentinel init                # Generate .codesentinel/ template
codesentinel config show         # Show current config
codesentinel config set <k> <v>  # Set config value
```

## Project Structure

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

## Python API

CodeSentinel can be used as a Python library — no CLI required.

### Async (recommended)

```python
import asyncio
from code_sentinel import review, ReviewOptions

async def main():
    result = await review(
        "https://github.com/owner/repo/pull/123",
        options=ReviewOptions(provider="mimo"),
    )
    print(f"Risk: {result.risk.level} ({result.risk.score} points)")
    print(f"Findings: {len(result.llm_review.findings)}")
    print(result.reports.get("markdown", ""))

asyncio.run(main())
```

### Synchronous

```python
from code_sentinel import review_sync, ReviewOptions

result = review_sync(
    "https://github.com/owner/repo/pull/123",
    options=ReviewOptions(skip_llm=True),
)
print(result.summary)
```

### ReviewOptions

All fields are optional — anything left as `None` is resolved from config file and environment variables.

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

## Plugins

CodeSentinel has a plugin system for auditors and reporters.

### AuditorPlugin

Add custom analysis steps to the pipeline. Subclass `AuditorPlugin` and implement `audit()`:

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

Pass it via `ReviewOptions(auditors=[MyAuditor()])`.

### ReporterPlugin

Add custom output formats. Subclass `ReporterPlugin` and implement `render()`:

```python
from code_sentinel.plugins import ReporterPlugin
from code_sentinel.result import ReviewResult

class SlackReporter(ReporterPlugin):
    name = "slack"

    def render(self, result: ReviewResult) -> str:
        return f"Risk: {result.risk.level} ({result.risk.score})"
```

Pass it via `ReviewOptions(reporters=[SlackReporter()])`. The rendered output is available in `result.reports["slack"]`.

### Built-in Plugins

| Plugin | Type | Name | Description |
|--------|------|------|-------------|
| `MarkdownReporter` | Reporter | `markdown` | Full Markdown report |
| `JsonReporter` | Reporter | `json` | JSON serialization |
| `PrCommentReporter` | Reporter | `pr-comment` | GitHub PR comment format |
| `SupplyChainAuditor` | Auditor | `supply_chain` | OSV vulnerability scan |
| `ImpactAuditor` | Auditor | `impact` | Build/test impact assessment |
| `DeepReviewAuditor` | Auditor | `deep_review` | LLM deep review (high-risk only) |

## Examples

See the `examples/` directory:

| File | Description |
|------|-------------|
| `examples/basic.py` | Async review with one line |
| `examples/basic_sync.py` | Synchronous usage |
| `examples/custom_rules.py` | Project-specific rules.toml |
| `examples/custom_reporter.py` | Custom Slack reporter plugin |
| `examples/custom_auditor.py` | Custom SQL injection & credential auditor |
| `examples/ci_pipeline.py` | CI/CD integration with exit codes |

Run any example:

```bash
python examples/basic.py
```

## Harness Architecture

CodeSentinel uses a three-level funnel with a plugin harness:

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

The harness pattern:

1. **AuditorPlugin.audit(context) → AuditResult** — each auditor gets an `AuditContext` with all PR data and returns an `AuditResult` with findings/warnings.
2. **ReporterPlugin.render(result) → str** — each reporter converts a `ReviewResult` into a formatted string.
3. **Pipeline orchestrator** runs auditors in order, collects results, then runs reporters. Partial failures are tolerated unless `strict=True`.

## License

MIT
