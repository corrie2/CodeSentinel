"""Tests for the CodeSentinel review harness — plugin execution, pipeline
orchestration, strict/non-strict modes, and reporter integration.

Every test is self-contained, uses fast mocks, and requires no real API keys.
"""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from code_sentinel.plugins import AuditContext, AuditResult, AuditorPlugin, ReporterPlugin
from code_sentinel.result import ReviewResult, RiskSummary, RiskContribution
from code_sentinel.review import ReviewOptions, review, review_sync


# ---------------------------------------------------------------------------
# Helpers
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


# Concrete mock auditor for reuse across tests
class _RecordingAuditor(AuditorPlugin):
    """Auditor that records whether audit() was called."""

    name = "recording"

    def __init__(self):
        self.called = False
        self.received_ctx: AuditContext | None = None

    async def audit(self, context: AuditContext) -> AuditResult:
        self.called = True
        self.received_ctx = context
        return AuditResult(name=self.name, status="ok", findings=["finding-a", "finding-b"])


class _FailingAuditor(AuditorPlugin):
    """Auditor that always raises an exception."""

    name = "failing"

    async def audit(self, context: AuditContext) -> AuditResult:
        raise RuntimeError("auditor exploded")


class _DummyReporter(ReporterPlugin):
    """Reporter that returns a fixed string."""

    name = "dummy_reporter"

    def render(self, result: ReviewResult) -> str:
        return "<dummy>report output</dummy>"


# ---------------------------------------------------------------------------
# Common patches — reused across tests to avoid real I/O
# ---------------------------------------------------------------------------

_COLLECT = "code_sentinel.review._collect_pr_data"
_ASSESS = "code_sentinel.risk.scorer.assess_risk"
_LOAD_RULES = "code_sentinel.risk.scorer.load_rules"


def _base_patches(**kwargs):
    """Return a list of patch decorators needed for every test.

    Callers can override individual mock values via kwargs.
    """
    collect = kwargs.get("collect", AsyncMock(return_value=_fake_pr_data()))
    risk_score = kwargs.get("risk_score", _make_risk_score())

    return [
        patch(_COLLECT, collect),
        patch(_ASSESS, return_value=risk_score),
        patch(_LOAD_RULES, return_value=MagicMock(rules=[], critical_paths=[])),
    ]


# ---------------------------------------------------------------------------
# 1. test_custom_auditor_is_executed
# ---------------------------------------------------------------------------

def test_custom_auditor_is_executed():
    """A custom AuditorPlugin passed via ReviewOptions.auditors is called."""
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


# ---------------------------------------------------------------------------
# 2. test_custom_auditor_result_is_preserved
# ---------------------------------------------------------------------------

def test_custom_auditor_result_is_preserved():
    """AuditResult from a custom auditor appears in result.agent_results."""
    auditor = _RecordingAuditor()
    opts = ReviewOptions(
        skip_llm=True,
        github_token="fake",
        auditors=[auditor],
    )

    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(review("https://github.com/owner/repo/pull/42", opts))

    names = [ar.name for ar in result.agent_results]
    assert "recording" in names, (
        f"Expected 'recording' in agent_results, got {names}"
    )

    recording_result = next(ar for ar in result.agent_results if ar.name == "recording")
    assert recording_result.status == "ok"
    assert recording_result.findings == ["finding-a", "finding-b"]


# ---------------------------------------------------------------------------
# 3. test_custom_reporter_populates_reports
# ---------------------------------------------------------------------------

def test_custom_reporter_populates_reports():
    """A custom ReporterPlugin's output appears in result.reports."""
    reporter = _DummyReporter()
    opts = ReviewOptions(
        skip_llm=True,
        github_token="fake",
        reporters=[reporter],
    )

    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(review("https://github.com/owner/repo/pull/42", opts))

    assert "dummy_reporter" in result.reports, (
        f"Expected 'dummy_reporter' key in reports, got {list(result.reports.keys())}"
    )
    assert result.reports["dummy_reporter"] == "<dummy>report output</dummy>"


# ---------------------------------------------------------------------------
# 4. test_strict_mode_raises_on_auditor_failure
# ---------------------------------------------------------------------------

def test_strict_mode_raises_on_auditor_failure():
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
        with pytest.raises(RuntimeError, match="failing failed"):
            asyncio.run(review("https://github.com/owner/repo/pull/42", opts))


# ---------------------------------------------------------------------------
# 5. test_non_strict_mode_records_failed_step
# ---------------------------------------------------------------------------

def test_non_strict_mode_records_failed_step():
    """strict=False continues after an auditor failure and records the failure."""
    auditor = _FailingAuditor()
    opts = ReviewOptions(
        skip_llm=True,
        github_token="fake",
        strict=False,
        auditors=[auditor],
    )

    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(review("https://github.com/owner/repo/pull/42", opts))

    # Pipeline should have completed and returned a result
    assert isinstance(result, ReviewResult)

    # The failed step should be recorded in the pipeline trace
    failed_steps = [s for s in result.pipeline.steps if s.status == "failed"]
    assert len(failed_steps) > 0, (
        f"Expected at least one failed step, got steps: "
        f"{[(s.name, s.status) for s in result.pipeline.steps]}"
    )

    # The failing auditor should also appear in agent_results with status "failed"
    failing_ar = next(
        (ar for ar in result.agent_results if ar.name == "failing"), None
    )
    assert failing_ar is not None, "Failing auditor missing from agent_results"
    assert failing_ar.status == "failed"
    assert "exploded" in (failing_ar.error or "")


# ---------------------------------------------------------------------------
# 6. test_review_sync_returns_review_result
# ---------------------------------------------------------------------------

def test_review_sync_returns_review_result():
    """review_sync() returns a ReviewResult instance."""
    patches = _base_patches(risk_score=_make_risk_score("low", 0))
    with patches[0], patches[1], patches[2]:
        result = review_sync(
            "https://github.com/owner/repo/pull/42",
            ReviewOptions(skip_llm=True, github_token="fake"),
        )

    assert isinstance(result, ReviewResult)
    assert result.pr_url == "https://github.com/owner/repo/pull/42"


# ---------------------------------------------------------------------------
# 7. test_risk_contributions_populated
# ---------------------------------------------------------------------------

def test_risk_contributions_populated():
    """result.risk.contributions is populated when risk rules trigger."""
    details = [
        {"description": "Touches auth module", "score_delta": 5, "tag": "security"},
        {"description": "Large PR", "score_delta": 3, "tag": "size"},
    ]
    risk_score = _make_risk_score("high", 8, triggered=["auth", "big"], details=details)

    patches = _base_patches(risk_score=risk_score)
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(review(
            "https://github.com/owner/repo/pull/42",
            ReviewOptions(skip_llm=True, github_token="fake"),
        ))

    assert result.risk.level == "high"
    assert result.risk.score == 8
    assert len(result.risk.contributions) == 2

    contrib_rules = [c.rule for c in result.risk.contributions]
    assert "Touches auth module" in contrib_rules
    assert "Large PR" in contrib_rules

    # Verify score_delta and evidence fields
    auth_contrib = next(c for c in result.risk.contributions if c.rule == "Touches auth module")
    assert auth_contrib.score_delta == 5
    assert auth_contrib.evidence == "security"


# ---------------------------------------------------------------------------
# 8. test_agent_results_contains_all_auditors
# ---------------------------------------------------------------------------

def test_agent_results_contains_all_auditors():
    """When risk is high, built-in auditors + custom auditors all appear
    in result.agent_results.
    """
    custom_auditor = _RecordingAuditor()
    opts = ReviewOptions(
        skip_llm=True,  # skip_llm=True prevents DeepReviewAuditor from needing LLM
        github_token="fake",
        auditors=[custom_auditor],
    )

    # High risk triggers SupplyChainAuditor + ImpactAuditor (but not DeepReviewAuditor
    # because skip_llm=True).  Our custom _RecordingAuditor is always appended.
    risk_score = _make_risk_score("high", 10)
    patches = _base_patches(risk_score=risk_score)
    with patches[0], patches[1], patches[2]:
        result = asyncio.run(review("https://github.com/owner/repo/pull/42", opts))

    agent_names = [ar.name for ar in result.agent_results]

    # Built-in auditors that run at HIGH risk with skip_llm=True
    assert "supply_chain" in agent_names, (
        f"supply_chain auditor missing; got {agent_names}"
    )
    assert "impact" in agent_names, (
        f"impact auditor missing; got {agent_names}"
    )
    # Our custom auditor
    assert "recording" in agent_names, (
        f"custom 'recording' auditor missing; got {agent_names}"
    )
