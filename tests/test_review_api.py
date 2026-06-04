"""Tests for the CodeSentinel Python review API.

Covers review(), review_sync(), ReviewOptions, custom auditors,
custom reporters, report format content, and strict-mode behaviour.

Every test is self-contained, uses fast mocks, and requires no real API keys.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from code_sentinel.plugins import AuditContext, AuditResult, AuditorPlugin, ReporterPlugin
from code_sentinel.result import ReviewResult
from code_sentinel.review import ReviewOptions, review, review_sync


# ---------------------------------------------------------------------------
# Helpers (mirrors test_harness.py patterns)
# ---------------------------------------------------------------------------

_FAKE_DIFF = (
    "--- a/foo.py\n"
    "+++ b/foo.py\n"
    "@@ -1,3 +1,5 @@\n"
    " hello\n"
    "+world\n"
    "+added\n"
    " end\n"
)


def _fake_pr_data():
    """Return a minimal but valid PR data dict for the pipeline."""
    return {
        "pr": {
            "title": "Test PR #42",
            "author": "testuser",
            "url": "https://github.com/owner/repo/pull/42",
            "number": 42,
            "repo": "owner/repo",
            "base_sha": "abc123",
            "head_sha": "def456",
        },
        "diff": _FAKE_DIFF,
        "changed_files": [
            {"filename": "foo.py", "status": "modified", "additions": 2, "deletions": 0},
        ],
    }


def _make_risk_score(level="low", score=0, triggered=None, details=None):
    """Build a mock RiskScore with the given level/score."""
    from code_sentinel.risk.scorer import RiskLevel

    rs = MagicMock()
    rs.level = getattr(RiskLevel, level.upper()) if isinstance(level, str) else level
    rs.score = score
    rs.triggered_rules = triggered or []
    rs.tags = []
    rs.rule_details = details or []
    return rs


# Patch targets (same as test_harness.py)
_COLLECT = "code_sentinel.review._collect_pr_data"
_ASSESS = "code_sentinel.risk.scorer.assess_risk"
_LOAD_RULES = "code_sentinel.risk.scorer.load_rules"


def _base_patches(**kwargs):
    """Return a list of patch context managers needed for every test."""
    collect = kwargs.get("collect", AsyncMock(return_value=_fake_pr_data()))
    risk_score = kwargs.get("risk_score", _make_risk_score())

    return [
        patch(_COLLECT, collect),
        patch(_ASSESS, return_value=risk_score),
        patch(_LOAD_RULES, return_value=MagicMock(rules=[], critical_paths=[])),
    ]


# Concrete mock auditor
class _RecordingAuditor(AuditorPlugin):
    """Auditor that records whether audit() was called."""

    name = "test_auditor"

    def __init__(self):
        self.called = False
        self.received_ctx: AuditContext | None = None

    async def audit(self, context: AuditContext) -> AuditResult:
        self.called = True
        self.received_ctx = context
        return AuditResult(name=self.name, status="ok", findings=["api-finding"])


class _FailingAuditor(AuditorPlugin):
    """Auditor that always raises an exception."""

    name = "failing_auditor"

    async def audit(self, context: AuditContext) -> AuditResult:
        raise RuntimeError("auditor exploded in strict mode test")


class _RecordingReporter(ReporterPlugin):
    """Reporter that records whether render() was called."""

    name = "custom_reporter"

    def __init__(self):
        self.called = False

    def render(self, result: ReviewResult) -> str:
        self.called = True
        return "custom-report-output-12345"


# ---------------------------------------------------------------------------
# 1. test_review_returns_review_result
# ---------------------------------------------------------------------------

def test_review_returns_review_result():
    """review() returns a ReviewResult with expected report keys."""
    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(
            review("https://github.com/owner/repo/pull/42",
                   ReviewOptions(skip_llm=True, github_token="fake"))
        )

    assert isinstance(result, ReviewResult)
    assert "markdown" in result.reports
    assert "json" in result.reports
    assert "pr-comment" in result.reports


# ---------------------------------------------------------------------------
# 2. test_review_reports_contain_all_formats
# ---------------------------------------------------------------------------

def test_review_reports_contain_all_formats():
    """Report content for each built-in format is valid and contains key strings."""
    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(
            review("https://github.com/owner/repo/pull/42",
                   ReviewOptions(skip_llm=True, github_token="fake"))
        )

    # Markdown report contains "Risk Level"
    assert "Risk Level" in result.reports["markdown"], (
        f"Expected 'Risk Level' in markdown report, got: {result.reports['markdown'][:200]}"
    )

    # JSON report is valid JSON
    parsed = json.loads(result.reports["json"])
    assert isinstance(parsed, dict), "JSON report should deserialize to a dict"

    # PR comment report contains "CodeSentinel Review"
    assert "CodeSentinel Review" in result.reports["pr-comment"], (
        f"Expected 'CodeSentinel Review' in pr-comment report, got: {result.reports['pr-comment'][:200]}"
    )


# ---------------------------------------------------------------------------
# 3. test_custom_auditor_called
# ---------------------------------------------------------------------------

def test_custom_auditor_called():
    """A custom AuditorPlugin passed via ReviewOptions.auditors is invoked,
    and its result appears in result.agent_results."""
    auditor = _RecordingAuditor()
    opts = ReviewOptions(
        skip_llm=True,
        github_token="fake",
        auditors=[auditor],
    )

    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(review("https://github.com/owner/repo/pull/42", opts))

    assert auditor.called is True, "Custom auditor's audit() was never invoked"
    assert auditor.received_ctx is not None, "AuditContext was not passed"
    assert auditor.received_ctx.pr_url == "https://github.com/owner/repo/pull/42"

    names = [ar.name for ar in result.agent_results]
    assert "test_auditor" in names, (
        f"Expected 'test_auditor' in agent_results, got {names}"
    )

    test_result = next(ar for ar in result.agent_results if ar.name == "test_auditor")
    assert test_result.status == "ok"
    assert test_result.findings == ["api-finding"]


# ---------------------------------------------------------------------------
# 4. test_custom_reporter_called
# ---------------------------------------------------------------------------

def test_custom_reporter_called():
    """A custom ReporterPlugin passed via ReviewOptions.reporters is invoked,
    and its output appears in result.reports."""
    reporter = _RecordingReporter()
    opts = ReviewOptions(
        skip_llm=True,
        github_token="fake",
        reporters=[reporter],
    )

    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(review("https://github.com/owner/repo/pull/42", opts))

    assert reporter.called is True, "Custom reporter's render() was never invoked"
    assert "custom_reporter" in result.reports, (
        f"Expected 'custom_reporter' key in reports, got {list(result.reports.keys())}"
    )
    assert result.reports["custom_reporter"] == "custom-report-output-12345"


# ---------------------------------------------------------------------------
# 5. test_review_sync_returns_result
# ---------------------------------------------------------------------------

def test_review_sync_returns_result():
    """review_sync() returns a ReviewResult (not a coroutine)."""
    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        result = review_sync(
            "https://github.com/owner/repo/pull/42",
            ReviewOptions(skip_llm=True, github_token="fake"),
        )

    assert isinstance(result, ReviewResult)
    assert not asyncio.iscoroutine(result), "review_sync should not return a coroutine"
    assert result.pr_url == "https://github.com/owner/repo/pull/42"


# ---------------------------------------------------------------------------
# 6. test_strict_mode_raises_on_failure
# ---------------------------------------------------------------------------

def test_strict_mode_raises_on_failure():
    """strict=True causes a RuntimeError when an auditor raises."""
    auditor = _FailingAuditor()
    opts = ReviewOptions(
        skip_llm=True,
        github_token="fake",
        strict=True,
        auditors=[auditor],
    )

    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        with pytest.raises(RuntimeError, match="failed"):
            asyncio.run(review("https://github.com/owner/repo/pull/42", opts))
