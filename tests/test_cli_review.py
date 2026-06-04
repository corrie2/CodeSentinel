"""Tests for the CodeSentinel CLI entry-point (codesentinel review ...).

Covers format selection, file output, and correct use of result.reports
from the review() pipeline.

Every test mocks the review() function so no real API calls are made.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from unittest.mock import AsyncMock, patch

from code_sentinel.result import ReviewResult, RiskSummary
from code_sentinel.plugins.reporters import MarkdownReporter, JsonReporter, PrCommentReporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_result_with_reports(
    risk_level: str = "low",
    risk_score: int = 0,
    pr_url: str = "https://github.com/owner/repo/pull/1",
    pr_title: str = "Test PR",
) -> ReviewResult:
    """Build a ReviewResult and run the default reporters to populate .reports."""
    result = ReviewResult(
        pr_url=pr_url,
        pr_title=pr_title,
        pr_author="testuser",
        repo="owner/repo",
        risk=RiskSummary(level=risk_level, score=risk_score),
    )
    # Run the three default reporters so result.reports is realistic
    for reporter_cls in (MarkdownReporter, JsonReporter, PrCommentReporter):
        reporter = reporter_cls()
        result.reports[reporter.name] = reporter.render(result)
    return result


_MOCK_REVIEW = "code_sentinel.review.review"


# ---------------------------------------------------------------------------
# 1. test_cli_review_skip_llm_format_json
# ---------------------------------------------------------------------------

def test_cli_review_skip_llm_format_json(capsys):
    """CLI review --skip-llm --format json produces valid JSON on stdout."""
    fake_result = _build_result_with_reports()

    async def _mock_review(pr_url, options=None):
        assert options.skip_llm is True, "Expected --skip-llm to be set"
        return fake_result

    with patch(_MOCK_REVIEW, side_effect=_mock_review):
        from code_sentinel.cli import main
        exit_code = main([
            "review",
            "https://github.com/owner/repo/pull/1",
            "--skip-llm",
            "--format", "json",
        ])

    assert exit_code == 0, f"CLI exited with code {exit_code}"

    captured = capsys.readouterr()
    output = captured.out.strip()
    assert output, "Expected JSON output on stdout"

    # Output must be valid JSON
    parsed = json.loads(output)
    assert isinstance(parsed, dict)
    # The JSON report should contain the risk level
    assert "risk" in parsed


# ---------------------------------------------------------------------------
# 2. test_cli_review_output_to_file
# ---------------------------------------------------------------------------

def test_cli_review_output_to_file(tmp_path):
    """CLI review --output <file> writes the report to disk."""
    fake_result = _build_result_with_reports()
    output_file = str(tmp_path / "test_report.md")

    async def _mock_review(pr_url, options=None):
        return fake_result

    with patch(_MOCK_REVIEW, side_effect=_mock_review):
        from code_sentinel.cli import main
        exit_code = main([
            "review",
            "https://github.com/owner/repo/pull/1",
            "--skip-llm",
            "--output", output_file,
        ])

    assert exit_code == 0, f"CLI exited with code {exit_code}"

    # File should exist and contain risk-related content
    assert Path(output_file).exists(), f"Expected output file {output_file} to exist"

    content = Path(output_file).read_text(encoding="utf-8")
    assert "Risk Level" in content, (
        f"Expected 'Risk Level' in output file, got: {content[:300]}"
    )


# ---------------------------------------------------------------------------
# 3. test_cli_uses_result_reports
# ---------------------------------------------------------------------------

def test_cli_uses_result_reports(capsys):
    """CLI outputs the report from result.reports, not a fallback render."""
    fake_result = _build_result_with_reports()

    # Inject a custom report to verify the CLI uses it verbatim
    fake_result.reports["markdown"] = "CUSTOM_MARKDOWN_SENTINEL_42"

    async def _mock_review(pr_url, options=None):
        return fake_result

    with patch(_MOCK_REVIEW, side_effect=_mock_review):
        from code_sentinel.cli import main
        exit_code = main([
            "review",
            "https://github.com/owner/repo/pull/1",
            "--skip-llm",
            # default format is markdown
        ])

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "CUSTOM_MARKDOWN_SENTINEL_42" in captured.out, (
        f"Expected custom sentinel in stdout, got: {captured.out[:300]}"
    )
