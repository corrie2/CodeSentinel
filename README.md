**English** | [中文](README_zh.md)

# CodeSentinel — Risk Advisor & Ecosystem Auditor

PR risk advisor and ecosystem auditor.

Feed it a PR, get back a structured risk assessment report. Not a bug finder — it tells you **whether this PR will blow up and when it can be merged**.

## Quick Start

```bash
# Install
pip install -e .
# or
uv sync

# Review a GitHub PR
export GITHUB_TOKEN=***
export MIMO_API_KEY=***
codesentinel review https://github.com/owner/repo/pull/123

# Review a GitLab MR (supports nested namespaces)
export GITLAB_TOKEN=***
codesentinel review https://gitlab.com/group/subgroup/project/-/merge_requests/456

# Output to file
codesentinel review <pr_url> --output report.md

# Skip LLM deep review (faster, no API key needed)
codesentinel review <pr_url> --skip-llm

# With local repo (enables git history + CODEOWNERS)
codesentinel review <pr_url> --repo-path ./my-repo
```

## Architecture

Three-level funnel model:

```
PR → [Level 1: Risk Scoring] → Low risk: log only
                               → Medium risk: +supply chain audit +engineering impact
                               → High risk: +LLM deep review (issues + evidence + test skeletons)
```

### Level 1 — Risk Scoring (seconds)

Deterministic rule engine, no LLM dependency. 19 built-in rules covering:

- Change scale (file count, line count, hunk count)
- Sensitive paths (payment/, auth/, security/)
- Dependency changes (additions, upgrades, removals)
- Author experience (first-time contributor, module familiarity)
- Project critical paths (customizable via .codesentinel/rules.toml)

Output: risk level (low/medium/high) + contribution breakdown:
```
Risk Level: ⚠️ Medium
Risk Points: 8
  +5 sensitive path (payment/)
  +3 large PR (25 files)
```

### Level 2 — Supply Chain Audit + Engineering Impact (minutes)

- **Supply Chain Audit**: Queries OSV database for dependency CVEs and license risks
- **Engineering Impact Assessment**: Estimates build time changes, test coverage impact, module coupling
- **Dependency Scan**: Three-layer architecture (detect → patch parse → full diff), supports 8 package manager formats

### Level 3 — LLM Deep Review (on-demand)

Only triggered for high-risk PRs. Uses risk-aware file selection:

- Sensitive paths: +50
- Config/dependency files: +40
- Project critical paths: +weight
- High-defect modules: +30
- No corresponding tests: +20
- Production paths: +15
- Deleted code: +15
- Permission logic: +25
- Error handling: +15

Output: issue description + evidence + executable test skeleton.

## Project Rules

```bash
# Generate project-specific rules
codesentinel init
codesentinel init --minimal   # Only rules.toml
codesentinel init --force     # Overwrite existing
```

Generates a `.codesentinel/` directory:

```
.codesentinel/
  rules.toml            # Risk rules + critical paths
  project_profile.md    # Project context (injected into LLM prompt)
  review_policy.md      # Review principles (injected into LLM prompt)
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

### Security Mechanism

`.codesentinel/` configuration is always read from the **base branch**, not the PR head.

If a PR modifies `.codesentinel/`, the report will show:
> ⚠️ Review policy was modified by this PR — this review uses the base branch config; the new policy takes effect after merge.

This prevents malicious PRs from injecting prompts via config changes.

## Pipeline Status

Every step has status tracking, visible in the report:

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

CodeSentinel can be used as a Python library — no CLI required.

### Async (recommended)

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

    # GitLab MR (supports nested namespaces)
    result = await review(
        "https://gitlab.com/group/subgroup/project/-/merge_requests/456",
        options=ReviewOptions(provider="mimo"),
    )
    print(f"Risk: {result.risk.level} ({result.risk.score} points)")

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

The webhook server runs the full pipeline:
1. Receives PR/MR events from GitHub or GitLab
2. Runs risk scoring, dependency audit, and LLM deep review
3. **Posts review results back as a PR/MR comment**

For the comment to be posted, the token needs write access:
- GitHub: `GITHUB_TOKEN` with `issues:write` permission
- GitLab: `GITLAB_TOKEN` with `api` scope

## Configuration

Environment variables (priority: `CODESENTINEL_` prefix > no prefix):

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub API Token |
| `MIMO_API_KEY` | MiMo LLM API Key (default) |
| `DEEPSEEK_API_KEY` | DeepSeek API Key (alternative) |
| `GITLAB_TOKEN` | GitLab API Token (optional) |

## CLI Commands

```
codesentinel review <pr_url>     # Review a PR/MR (GitHub or GitLab)
codesentinel serve               # Start webhook server
codesentinel init                # Generate .codesentinel/ template
codesentinel config show         # Show current config
codesentinel config set <k> <v>  # Set config value
```

Supported URL formats:
- GitHub: `https://github.com/{owner}/{repo}/pull/{number}`
- GitLab: `https://{host}/{project_path}/-/merge_requests/{number}`
  - Supports nested namespaces: `group/subgroup/project`

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
