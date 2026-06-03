"""Concrete auditor plugins for CodeSentinel.

Each auditor wraps an existing analysis function and returns an AuditResult
compatible with the plugin orchestrator.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from code_sentinel.plugins import AuditContext, AuditResult, AuditorPlugin

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Supply Chain Auditor
# ---------------------------------------------------------------------------

class SupplyChainAuditor(AuditorPlugin):
    """Audits dependencies for known vulnerabilities via OSV API."""

    name = "supply_chain"

    async def audit(self, context: AuditContext) -> AuditResult:
        """Run supply chain audit on dependency changes.

        Queries the OSV API for known vulnerabilities in the
        dependencies changed by this PR.
        """
        from code_sentinel.auditor.supply_chain import run_supply_chain_audit

        t0 = time.monotonic()
        result = AuditResult(name=self.name)

        try:
            # Build package list from dep_changes
            from code_sentinel.auditor.supply_chain import PackageQuery

            packages: list[PackageQuery] = []
            for dc in context.dep_changes:
                if hasattr(dc, "package") and hasattr(dc, "version") and hasattr(dc, "ecosystem"):
                    packages.append(PackageQuery(
                        name=dc.package,
                        version=dc.version or "",
                        ecosystem=dc.ecosystem or "",
                    ))

            report = await run_supply_chain_audit(packages=packages)

            result.status = "ok"
            result.artifacts["total_deps"] = report.total_deps
            result.artifacts["vulnerable_deps"] = [
                {
                    "package": v.package,
                    "version": v.version,
                    "ecosystem": v.ecosystem,
                    "vuln_id": v.vuln_id,
                    "summary": v.summary,
                    "severity": v.display_severity,
                    "fixed_version": v.fixed_version,
                }
                for v in report.vulnerable_deps
            ]
            result.artifacts["deprecated_deps"] = [
                {"package": d.package, "ecosystem": d.ecosystem, "reason": d.reason}
                for d in report.deprecated_deps
            ]
            result.artifacts["license_issues"] = [
                {"package": l.package, "ecosystem": l.ecosystem, "license": l.license, "risk": l.risk}
                for l in report.license_issues
            ]

            # Convert vulnerable deps to findings
            for v in report.vulnerable_deps:
                result.findings.append({
                    "type": "vulnerability",
                    "severity": v.display_severity.lower() or "medium",
                    "package": v.package,
                    "vuln_id": v.vuln_id,
                    "summary": v.summary,
                    "fixed_version": v.fixed_version,
                })

            if report.errors:
                result.warnings.extend(report.errors)
                if not report.vulnerable_deps:
                    result.status = "partial"

        except Exception as exc:
            logger.error("Supply chain audit failed: %s", exc)
            result.status = "failed"
            result.error = str(exc)

        result.duration_seconds = time.monotonic() - t0
        return result


# ---------------------------------------------------------------------------
# Impact Auditor
# ---------------------------------------------------------------------------

class ImpactAuditor(AuditorPlugin):
    """Assesses engineering impact of the PR (build time, test coverage, modules)."""

    name = "impact"

    async def audit(self, context: AuditContext) -> AuditResult:
        """Run engineering impact assessment.

        Analyzes changed files to estimate build impact, test coverage
        risk, and affected modules.
        """
        from code_sentinel.auditor.impact import assess_impact

        t0 = time.monotonic()
        result = AuditResult(name=self.name)

        try:
            # Build changed_files list from context
            changed_files: list[dict[str, Any]] = []

            # Try to get files from the changeset
            if context.changeset and hasattr(context.changeset, "files"):
                for f in context.changeset.files:
                    changed_files.append({
                        "filename": f.path if hasattr(f, "path") else str(f),
                        "status": f.change_type.value if hasattr(f, "change_type") else "modified",
                    })

            # Fallback: try step_results for changed_files
            if not changed_files:
                for step in context.step_results:
                    if hasattr(step, "details") and "changed_files" in step.details:
                        changed_files = step.details["changed_files"]
                        break

            report = assess_impact(changed_files)

            result.status = "ok"
            result.artifacts = {
                "total_files_changed": report.total_files_changed,
                "files_added": report.files_added,
                "files_modified": report.files_modified,
                "files_deleted": report.files_deleted,
                "estimated_build_seconds": report.estimated_build_seconds,
                "build_risk": report.build_risk,
                "test_files_changed": report.test_files_changed,
                "estimated_new_tests_needed": report.estimated_new_tests_needed,
                "test_coverage_risk": report.test_coverage_risk,
                "affected_modules": [
                    {
                        "module": m.module,
                        "files_changed": m.files_changed,
                        "change_types": m.change_types,
                        "severity": m.severity,
                    }
                    for m in report.affected_modules
                ],
                "config_changes": report.config_changes,
                "ci_changes": report.ci_changes,
                "dependency_changes": report.dependency_changes,
            }

            # Add warnings as findings
            for w in report.warnings:
                result.warnings.append(w)

        except Exception as exc:
            logger.error("Impact assessment failed: %s", exc)
            result.status = "failed"
            result.error = str(exc)

        result.duration_seconds = time.monotonic() - t0
        return result


# ---------------------------------------------------------------------------
# Deep Review Auditor
# ---------------------------------------------------------------------------

class DeepReviewAuditor(AuditorPlugin):
    """LLM-powered deep code review for high-risk PRs.

    Only runs when the risk level is HIGH.
    """

    name = "deep_review"

    async def audit(self, context: AuditContext) -> AuditResult:
        """Run LLM deep review on high-risk files.

        Skipped unless the risk level is 'high'.
        """
        from code_sentinel.auditor.deep_review import run_deep_review

        t0 = time.monotonic()
        result = AuditResult(name=self.name)

        # Only run for high risk
        # Check if risk level is available in the context
        risk_level = "low"
        if context.options and hasattr(context.options, "risk_level"):
            risk_level = context.options.risk_level
        # Also check step_results for risk info
        for step in context.step_results:
            if hasattr(step, "name") and step.name == "Risk Scoring":
                if hasattr(step, "message") and "HIGH" in step.message.upper():
                    risk_level = "high"
                elif hasattr(step, "details") and step.details.get("level") == "high":
                    risk_level = "high"

        if risk_level != "high":
            result.status = "skipped"
            result.duration_seconds = time.monotonic() - t0
            return result

        try:
            # We need a Config and RiskScore for run_deep_review
            from code_sentinel.config import Config
            from code_sentinel.risk.scorer import RiskScore, RiskLevel

            # Build Config from context
            llm_config = context.llm_config or {}
            config = Config(
                provider=llm_config.get("provider", "mimo"),
                api_key=llm_config.get("api_key"),
                github_token=context.github_token,
            )

            # Build a minimal RiskScore
            risk_score = RiskScore(
                level=RiskLevel.HIGH,
                score=0,
                contributions=[],
                triggered_rules=[],
                tags=[],
            )

            findings = await run_deep_review(
                changeset=context.changeset,
                risk_score=risk_score,
                config=config,
                raw_diff=context.raw_diff,
                project_context=context.project_context,
            )

            result.status = "ok"
            for f in findings:
                result.findings.append({
                    "issue_type": f.issue_type,
                    "severity": f.severity,
                    "file": f.file,
                    "line": f.line,
                    "description": f.description,
                    "evidence": f.evidence,
                    "test_suggestion": f.test_suggestion,
                })

        except Exception as exc:
            logger.error("Deep review failed: %s", exc)
            result.status = "failed"
            result.error = str(exc)

        result.duration_seconds = time.monotonic() - t0
        return result
