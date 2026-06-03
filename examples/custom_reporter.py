"""Custom reporter — generate a Slack-formatted message."""

import asyncio

from code_sentinel import review, ReviewOptions
from code_sentinel.plugins import ReporterPlugin
from code_sentinel.result import ReviewResult


class SlackReporter(ReporterPlugin):
    name = "slack"

    def render(self, result: ReviewResult) -> str:
        emoji = {"low": "\U0001f7e2", "medium": "\U0001f7e1", "high": "\U0001f534"}.get(
            result.risk.level, "\u26aa"
        )
        lines = [
            f"{emoji} *CodeSentinel Review*",
            f"*PR:* {result.pr_title}",
            f"*Risk:* {result.risk.level.upper()} ({result.risk.score} points)",
        ]
        if result.llm_review.findings:
            lines.append(f"*Findings:* {len(result.llm_review.findings)}")
            for f in result.llm_review.findings[:3]:
                lines.append(f"  \u2022 {f.issue_type}: {f.description[:80]}")
        return "\n".join(lines)


async def main():
    result = await review(
        "https://github.com/owner/repo/pull/123",
        options=ReviewOptions(
            reporters=[SlackReporter()],
            skip_llm=True,
        ),
    )
    print(result.reports.get("slack", "No slack report"))


asyncio.run(main())
