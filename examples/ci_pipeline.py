"""CI pipeline — use in any CI/CD system."""

import asyncio
import sys

from code_sentinel import review, ReviewOptions


async def main():
    pr_url = sys.argv[1] if len(sys.argv) > 1 else None
    if not pr_url:
        print("Usage: python ci_pipeline.py <pr_url>")
        sys.exit(1)

    result = await review(
        pr_url,
        options=ReviewOptions(
            strict=False,
            skip_llm=False,
        ),
    )

    # Print report
    print(result.reports.get("markdown", ""))

    # Exit code based on risk
    if result.risk.level == "high":
        print("\n\u274c HIGH RISK \u2014 review required before merge")
        sys.exit(1)
    elif result.risk.level == "medium":
        print("\n\u26a0\ufe0f MEDIUM RISK \u2014 consider addressing findings")
        sys.exit(0)
    else:
        print("\n\u2705 LOW RISK \u2014 safe to merge")
        sys.exit(0)


asyncio.run(main())
