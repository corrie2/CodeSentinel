# CodeSentinel — 变更生态审计官

不是"代码审查Bot"，而是"变更风险顾问"。

输入一个 PR，输出一份结构化的"变更影响评估报告"。

## Quick Start

```bash
pip install -e .
codesentinel review https://github.com/owner/repo/pull/123
```

## Architecture

三级漏斗模型：

1. **风险评分器**（秒级）— 确定性规则，输出风险标签（低/中/高）
2. **影响评估引擎**（分钟级）— 供应链审计 + 工程影响预测
3. **深度审查**（按需）— 仅高风险 PR 触发 LLM 审查，输出问题+证据+测试骨架

## Configuration

```bash
export MIMO_API_KEY=your_key
export GITHUB_TOKEN=your_token
codesentinel review <pr_url>
```
