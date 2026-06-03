"""CodeSentinel – Risk Advisor & Ecosystem Auditor.

Public API:
    from code_sentinel import review, review_sync, ReviewOptions, ReviewResult

    result = await review("https://github.com/owner/repo/pull/123")
    result = review_sync("https://github.com/owner/repo/pull/123")
    result = review_sync("https://...", options=ReviewOptions(provider="mimo"))
"""

from code_sentinel.config import Config
from code_sentinel.result import ReviewResult
from code_sentinel.review import ReviewOptions, review, review_sync

__all__ = [
    "Config",
    "ReviewResult",
    "ReviewOptions",
    "review",
    "review_sync",
]
__version__ = "0.1.0"
