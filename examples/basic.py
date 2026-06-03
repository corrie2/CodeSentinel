"""Basic usage — review a PR with one line."""

import asyncio

from code_sentinel import review, ReviewOptions


async def main():
    result = await review(
        "https://github.com/owner/repo/pull/123",
        options=ReviewOptions(provider="mimo"),
    )
    print(f"Risk: {result.risk.level}")
    print(f"Score: {result.risk.score}")
    print(f"Findings: {len(result.llm_review.findings)}")
    print(result.reports.get("markdown", ""))


asyncio.run(main())
