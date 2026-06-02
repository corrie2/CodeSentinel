"""LLM integration layer."""

from code_sentinel.llm.client import LLMClient, LLMClientError
from code_sentinel.llm.prompts import DEEP_REVIEW_PROMPT, IMPACT_SUMMARY_PROMPT

__all__ = ["LLMClient", "LLMClientError", "DEEP_REVIEW_PROMPT", "IMPACT_SUMMARY_PROMPT"]
