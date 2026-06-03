"""Custom rules — use project-specific .codesentinel/rules.toml."""

import asyncio

from code_sentinel import review, ReviewOptions


async def main():
    result = await review(
        "https://github.com/owner/repo/pull/123",
        options=ReviewOptions(
            rules_path=".codesentinel/rules.toml",
            repo_path=".",
        ),
    )
    for c in result.risk.contributions:
        print(f"  +{c.score_delta} {c.reason}")


asyncio.run(main())
