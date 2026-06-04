"""Concrete reporter plugins for CodeSentinel.

Each reporter converts a ReviewResult into a specific output format
(markdown, JSON, PR comment, etc.).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from code_sentinel.plugins import ReporterPlugin
from code_sentinel.reporter.formatter import (
    PRMetadata,
    ReportContext,
    ReviewResults,
    build_report_context,
    render_json,
    render_markdown,
    render_pr_comment,
)
from code_sentinel.result import ReviewResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _review_result_to_context(result: ReviewResult) -> ReportContext:
    """Build a ReportContext from a ReviewResult.

    Maps the new ReviewResult dataclasses to the older ReportContext
    format expected by the existing formatter functions.
    """
    # Build PRMetadata from ReviewResult
    pr_meta = PRMetadata(
        title=result.pr_title,
        author=result.pr_author,
        url=result.pr_url,
        number=_extract_pr_number(result.pr_url),
        repo=result.repo,
        base_branch=result.base_branch,
        head_branch=result.head_branch,
    )

    # Risk breakdown from contributions
    risk_breakdown: list[str] = []
    for contrib in result.risk.contributions:
        evidence = f" ({contrib.evidence})" if contrib.evidence else ""
        risk_breakdown.append(
            f"{contrib.rule}: {contrib.reason}{evidence} (+{contrib.score_delta})"
        )

    # Build supply chain report wrapper for build_report_context
    _sc = result.supply_chain

    # Build impact report wrapper
    _impact = result.impact

    # Deep review
    deep_review = None
    if result.llm_review.findings or result.llm_review.status != "skipped":
        deep_review = ReviewResults(
            findings=[
                {
                    "issue_type": f.issue_type,
                    "severity": f.severity,
                    "file": f.file,
                    "line": f.line,
                    "description": f.description,
                    "evidence": f.evidence,
                    "test_suggestion": f.test_suggestion,
                }
                for f in result.llm_review.findings
            ],
            summary=result.llm_review.error or "",
            suggestions=[],
        )

    # Attention files
    needs_attention = [
        {
            "path": af.path,
            "score": af.score,
            "reasons": af.reasons,
            "needs_attention": True,
        }
        for af in result.attention
    ]

    # Pipeline steps
    pipeline_steps = result.pipeline.steps

    # Build the context
    ctx = ReportContext(
        pr=pr_meta,
        risk_score=result.risk.score,
        risk_level=result.risk.level,
        risk_details={},
        risk_breakdown=risk_breakdown,
        codesentinel_modified=result.metadata.codesentinel_modified,
    )

    # Supply chain
    ctx.total_deps = _sc.total_deps
    ctx.vulnerable_deps = [
        {
            "package": v.package,
            "version": "",  # Vulnerability in result.py doesn't have version
            "ecosystem": "",
            "vuln_id": v.id,
            "summary": v.summary,
            "severity": v.severity,
            "fixed_version": v.fixed_version,
        }
        for v in _sc.vulnerabilities
    ]
    ctx.deprecated_deps = []
    ctx.license_issues = []

    # Impact
    ctx.total_files_changed = len(_impact.affected_modules)  # approximate
    ctx.estimated_build_seconds = _impact.estimated_build_seconds
    ctx.build_risk = _impact.build_risk
    ctx.test_coverage_risk = _impact.test_coverage_risk
    ctx.affected_modules = [
        {"module": m, "files_changed": 0, "change_types": [], "severity": "low"}
        for m in _impact.affected_modules
    ]

    ctx.deep_review = deep_review
    ctx.needs_attention = needs_attention
    ctx.pipeline_steps = pipeline_steps

    return ctx


def _extract_pr_number(pr_url: str) -> int:
    """Extract PR number from a GitHub PR URL."""
    import re
    match = re.search(r"/pull/(\d+)", pr_url)
    return int(match.group(1)) if match else 0


# ---------------------------------------------------------------------------
# Markdown Reporter
# ---------------------------------------------------------------------------

class MarkdownReporter(ReporterPlugin):
    """Renders a ReviewResult as a Markdown report."""

    name = "markdown"

    def render(self, result: ReviewResult) -> str:
        """Convert ReviewResult to markdown via the existing formatter."""
        ctx = _review_result_to_context(result)
        return render_markdown(ctx)


# ---------------------------------------------------------------------------
# JSON Reporter
# ---------------------------------------------------------------------------

class JsonReporter(ReporterPlugin):
    """Renders a ReviewResult as a JSON string."""

    name = "json"

    def render(self, result: ReviewResult) -> str:
        """Convert ReviewResult to JSON."""
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# PR Comment Reporter
# ---------------------------------------------------------------------------

class PrCommentReporter(ReporterPlugin):
    """Renders a ReviewResult as a GitHub PR comment (markdown with collapsible sections)."""

    name = "pr-comment"

    def render(self, result: ReviewResult) -> str:
        """Convert ReviewResult to a PR comment format."""
        ctx = _review_result_to_context(result)
        return render_pr_comment(ctx)
