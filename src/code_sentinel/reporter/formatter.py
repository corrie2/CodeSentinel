"""Report formatter — generates markdown reports from audit results."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


@dataclass
class PRMetadata:
    """Pull request metadata."""

    title: str = ""
    author: str = ""
    url: str = ""
    number: int = 0
    repo: str = ""
    created_at: str = ""
    base_branch: str = "main"
    head_branch: str = ""


@dataclass
class ReviewResults:
    """LLM deep review findings (optional)."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    suggestions: list[str] = field(default_factory=list)


@dataclass
class ReportContext:
    """All data needed to render the report."""

    pr: PRMetadata = field(default_factory=PRMetadata)
    risk_score: int = 0
    risk_level: str = "low"  # low, medium, high
    risk_details: dict[str, Any] = field(default_factory=dict)

    # Supply chain
    total_deps: int = 0
    vulnerable_deps: list[dict[str, Any]] = field(default_factory=list)
    deprecated_deps: list[dict[str, Any]] = field(default_factory=list)
    license_issues: list[dict[str, Any]] = field(default_factory=list)

    # Impact
    total_files_changed: int = 0
    files_added: int = 0
    files_modified: int = 0
    files_deleted: int = 0
    estimated_build_seconds: int = 0
    build_risk: str = "low"
    test_files_changed: int = 0
    estimated_new_tests_needed: int = 0
    test_coverage_risk: str = "low"
    affected_modules: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    config_changes: list[str] = field(default_factory=list)
    ci_changes: list[str] = field(default_factory=list)
    dependency_changes: list[str] = field(default_factory=list)

    # Deep review
    deep_review: ReviewResults | None = None

    # Recommendations
    recommendations: list[str] = field(default_factory=list)

    # Metadata
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )


_RISK_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}
_RISK_LABEL = {"low": "Low Risk", "medium": "Medium Risk", "high": "High Risk"}


def _default_template_dir() -> Path:
    """Find the templates directory relative to this package."""
    # Walk up to find templates/
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "templates"
        if candidate.is_dir():
            return candidate
    # Fallback: look in project root
    return here.parent.parent.parent.parent / "templates"


def build_report_context(
    *,
    pr: PRMetadata | None = None,
    risk_score: int = 0,
    risk_level: str = "low",
    risk_details: dict[str, Any] | None = None,
    supply_chain_report: Any = None,
    impact_report: Any = None,
    deep_review: ReviewResults | None = None,
) -> ReportContext:
    """Build a ReportContext from individual audit results."""
    ctx = ReportContext(
        pr=pr or PRMetadata(),
        risk_score=risk_score,
        risk_level=risk_level,
        risk_details=risk_details or {},
    )

    # Map supply chain report
    if supply_chain_report is not None:
        ctx.total_deps = supply_chain_report.total_deps
        ctx.vulnerable_deps = [
            {
                "package": v.package,
                "version": v.version,
                "ecosystem": v.ecosystem,
                "vuln_id": v.vuln_id,
                "summary": v.summary,
                "severity": v.display_severity,
                "fixed_version": v.fixed_version,
            }
            for v in supply_chain_report.vulnerable_deps
        ]
        ctx.deprecated_deps = [
            {"package": d.package, "ecosystem": d.ecosystem, "reason": d.reason}
            for d in supply_chain_report.deprecated_deps
        ]
        ctx.license_issues = [
            {"package": l.package, "ecosystem": l.ecosystem, "license": l.license, "risk": l.risk}
            for l in supply_chain_report.license_issues
        ]

    # Map impact report
    if impact_report is not None:
        ctx.total_files_changed = impact_report.total_files_changed
        ctx.files_added = impact_report.files_added
        ctx.files_modified = impact_report.files_modified
        ctx.files_deleted = impact_report.files_deleted
        ctx.estimated_build_seconds = impact_report.estimated_build_seconds
        ctx.build_risk = impact_report.build_risk
        ctx.test_files_changed = impact_report.test_files_changed
        ctx.estimated_new_tests_needed = impact_report.estimated_new_tests_needed
        ctx.test_coverage_risk = impact_report.test_coverage_risk
        ctx.affected_modules = [
            {
                "module": m.module,
                "files_changed": m.files_changed,
                "change_types": m.change_types,
                "severity": m.severity,
            }
            for m in impact_report.affected_modules
        ]
        ctx.warnings = list(impact_report.warnings)
        ctx.config_changes = list(impact_report.config_changes)
        ctx.ci_changes = list(impact_report.ci_changes)
        ctx.dependency_changes = list(impact_report.dependency_changes)

    ctx.deep_review = deep_review

    # Generate recommendations
    ctx.recommendations = _generate_recommendations(ctx)

    return ctx


def _generate_recommendations(ctx: ReportContext) -> list[str]:
    """Auto-generate recommendations based on audit results."""
    recs: list[str] = []

    if ctx.vulnerable_deps:
        recs.append(
            f"Fix {len(ctx.vulnerable_deps)} vulnerable dependencies before merging."
        )

    if ctx.test_coverage_risk == "high":
        recs.append(
            "Add missing test coverage — high test coverage risk detected."
        )
    elif ctx.test_coverage_risk == "medium":
        recs.append("Consider adding tests for newly modified modules.")

    if ctx.build_risk == "high":
        recs.append("Large build impact — consider splitting this PR into smaller changes.")

    if ctx.ci_changes:
        recs.append("CI/CD pipeline changes detected — verify pipeline runs correctly before merge.")

    if ctx.files_deleted > 5:
        recs.append(
            "Significant file deletions — ensure no external references are broken."
        )

    if ctx.risk_level == "high":
        recs.append("This PR has HIGH risk — require at least 2 reviewers before merge.")

    if not recs:
        recs.append("No critical issues found — this PR looks safe to merge.")

    return recs


def render_markdown(ctx: ReportContext, template_dir: Path | None = None) -> str:
    """Render the report as markdown using the Jinja2 template."""
    tmpl_dir = template_dir or _default_template_dir()
    env = Environment(
        loader=FileSystemLoader(str(tmpl_dir)),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Add custom filters
    env.filters["risk_emoji"] = lambda level: _RISK_EMOJI.get(level, "⚪")
    env.filters["risk_label"] = lambda level: _RISK_LABEL.get(level, "Unknown")

    try:
        template = env.get_template("report.md.j2")
    except Exception:
        # Fallback to inline template
        return _render_inline(ctx)

    return template.render(
        pr=ctx.pr,
        risk_score=ctx.risk_score,
        risk_level=ctx.risk_level,
        risk_details=ctx.risk_details,
        total_deps=ctx.total_deps,
        vulnerable_deps=ctx.vulnerable_deps,
        deprecated_deps=ctx.deprecated_deps,
        license_issues=ctx.license_issues,
        total_files_changed=ctx.total_files_changed,
        files_added=ctx.files_added,
        files_modified=ctx.files_modified,
        files_deleted=ctx.files_deleted,
        estimated_build_seconds=ctx.estimated_build_seconds,
        build_risk=ctx.build_risk,
        test_files_changed=ctx.test_files_changed,
        estimated_new_tests_needed=ctx.estimated_new_tests_needed,
        test_coverage_risk=ctx.test_coverage_risk,
        affected_modules=ctx.affected_modules,
        warnings=ctx.warnings,
        config_changes=ctx.config_changes,
        ci_changes=ctx.ci_changes,
        dependency_changes=ctx.dependency_changes,
        deep_review=ctx.deep_review,
        recommendations=ctx.recommendations,
        generated_at=ctx.generated_at,
    )


def render_pr_comment(ctx: ReportContext, template_dir: Path | None = None) -> str:
    """Render as a GitHub PR comment format (adds collapsible sections)."""
    markdown = render_markdown(ctx, template_dir)

    # Wrap in PR comment style with collapsible details
    header = f"## {_RISK_EMOJI.get(ctx.risk_level, '⚪')} CodeSentinel Review\n\n"
    risk_badge = f"**Risk Score: {ctx.risk_score}/100** — {_RISK_LABEL.get(ctx.risk_level, 'Unknown')}\n\n"

    body = header + risk_badge + markdown

    # Add collapsible raw details
    if ctx.deep_review and ctx.deep_review.findings:
        body += "\n\n<details>\n<summary>Raw Deep Review Findings</summary>\n\n"
        body += "```json\n"
        body += json.dumps(ctx.deep_review.findings, indent=2, ensure_ascii=False)
        body += "\n```\n\n</details>"

    return body


def render_json(ctx: ReportContext) -> str:
    """Render the report as JSON."""
    data = {
        "pr": asdict(ctx.pr),
        "risk": {
            "score": ctx.risk_score,
            "level": ctx.risk_level,
            "details": ctx.risk_details,
        },
        "supply_chain": {
            "total_deps": ctx.total_deps,
            "vulnerable_deps": ctx.vulnerable_deps,
            "deprecated_deps": ctx.deprecated_deps,
            "license_issues": ctx.license_issues,
        },
        "impact": {
            "total_files_changed": ctx.total_files_changed,
            "files_added": ctx.files_added,
            "files_modified": ctx.files_modified,
            "files_deleted": ctx.files_deleted,
            "estimated_build_seconds": ctx.estimated_build_seconds,
            "build_risk": ctx.build_risk,
            "test_files_changed": ctx.test_files_changed,
            "estimated_new_tests_needed": ctx.estimated_new_tests_needed,
            "test_coverage_risk": ctx.test_coverage_risk,
            "affected_modules": ctx.affected_modules,
            "warnings": ctx.warnings,
        },
        "recommendations": ctx.recommendations,
        "generated_at": ctx.generated_at,
    }
    if ctx.deep_review:
        data["deep_review"] = asdict(ctx.deep_review)
    return json.dumps(data, indent=2, ensure_ascii=False)


def _render_inline(ctx: ReportContext) -> str:
    """Fallback inline template if Jinja2 template file not found."""
    lines: list[str] = []
    emoji = _RISK_EMOJI.get(ctx.risk_level, "⚪")
    label = _RISK_LABEL.get(ctx.risk_level, "Unknown")

    lines.append(f"# {emoji} CodeSentinel — Change Impact Report")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append(f"- **Risk Level:** {emoji} {label} ({ctx.risk_score}/100)")
    if ctx.pr.title:
        lines.append(f"- **PR:** [{ctx.pr.title}]({ctx.pr.url})")
    if ctx.pr.author:
        lines.append(f"- **Author:** {ctx.pr.author}")
    lines.append(f"- **Generated:** {ctx.generated_at}")
    lines.append("")

    # Supply chain
    lines.append("## Supply Chain Risk")
    if ctx.vulnerable_deps:
        lines.append(f"Found **{len(ctx.vulnerable_deps)}** vulnerable dependencies:\n")
        for v in ctx.vulnerable_deps:
            lines.append(f"- `{v['package']}@{v['version']}` — {v['vuln_id']}: {v['summary']}")
            if v.get("fixed_version"):
                lines.append(f"  - Fixed in: `{v['fixed_version']}`")
    else:
        lines.append("No known vulnerabilities found.")
    lines.append("")

    # Impact
    lines.append("## Engineering Impact")
    lines.append(f"- **Files changed:** {ctx.total_files_changed} (added: {ctx.files_added}, modified: {ctx.files_modified}, deleted: {ctx.files_deleted})")
    lines.append(f"- **Estimated build time:** ~{ctx.estimated_build_seconds}s ({_RISK_EMOJI.get(ctx.build_risk, '')} {ctx.build_risk})")
    lines.append(f"- **Test files changed:** {ctx.test_files_changed}")
    if ctx.estimated_new_tests_needed > 0:
        lines.append(f"- **New tests recommended:** ~{ctx.estimated_new_tests_needed}")
    if ctx.affected_modules:
        lines.append("\n**Affected Modules:**")
        for m in ctx.affected_modules:
            lines.append(f"- `{m['module']}` — {m['files_changed']} file(s), severity: {m['severity']}")
    lines.append("")

    # Warnings
    if ctx.warnings:
        lines.append("## Warnings")
        for w in ctx.warnings:
            lines.append(f"- {w}")
        lines.append("")

    # Deep review
    if ctx.deep_review:
        lines.append("## Deep Review Findings")
        if ctx.deep_review.summary:
            lines.append(ctx.deep_review.summary)
            lines.append("")
        for finding in ctx.deep_review.findings:
            lines.append(f"- **{finding.get('severity', 'info')}**: {finding.get('description', '')}")
        lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    for rec in ctx.recommendations:
        lines.append(f"- {rec}")
    lines.append("")

    return "\n".join(lines)
