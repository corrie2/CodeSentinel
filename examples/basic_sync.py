"""Synchronous usage."""

from code_sentinel import review_sync, ReviewOptions

result = review_sync(
    "https://github.com/owner/repo/pull/123",
    options=ReviewOptions(skip_llm=True),
)
print(result.summary)
