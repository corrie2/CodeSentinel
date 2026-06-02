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

## License

MIT
