"""Unified result types for the CodeSentinel review pipeline.

These dataclasses represent the serializable output of every pipeline stage
and are consumed by reporters, the server, and CLI output formatters.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------

@dataclass
class RiskContribution:
    """A single rule's contribution to the overall risk score."""

    rule: str
    score_delta: int
    reason: str
    evidence: str | None = None


@dataclass
class RiskSummary:
    """Aggregated risk assessment result."""

    level: str  # "low" / "medium" / "high"
    score: int
    contributions: list[RiskContribution] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

@dataclass
class DependencySummary:
    """Summary of dependency changes detected in the PR."""

    changes: list[dict]  # serialized DepChange dicts
    scan_mode: str  # "full" / "patch-only" / "skipped"
    manifest_count: int = 0


# ---------------------------------------------------------------------------
# Supply chain
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    """A known vulnerability affecting a dependency."""

    id: str
    summary: str
    severity: str
    package: str
    fixed_version: str | None = None


@dataclass
class SupplyChainSummary:
    """Aggregated supply-chain audit result."""

    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    total_deps: int = 0
    status: str = "skipped"  # "ok" / "partial" / "failed" / "skipped"
    error: str | None = None


# ---------------------------------------------------------------------------
# Impact
# ---------------------------------------------------------------------------

@dataclass
class ImpactSummary:
    """Engineering impact assessment summary."""

    estimated_build_seconds: int = 0
    affected_modules: list[str] = field(default_factory=list)
    build_risk: str = "low"
    test_coverage_risk: str = "low"
    status: str = "skipped"


# ---------------------------------------------------------------------------
# LLM deep review
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single issue discovered by the deep-review LLM."""

    issue_type: str
    severity: str
    file: str
    line: int
    description: str
    evidence: str
    test_suggestion: str


@dataclass
class LLMReviewSummary:
    """Aggregated LLM deep-review result."""

    findings: list[Finding] = field(default_factory=list)
    status: str = "skipped"  # "ok" / "partial" / "failed" / "skipped"
    error: str | None = None


# ---------------------------------------------------------------------------
# Attention / file ranking
# ---------------------------------------------------------------------------

@dataclass
class AttentionFile:
    """A file flagged as needing human attention."""

    path: str
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pipeline trace
# ---------------------------------------------------------------------------

@dataclass
class PipelineStep:
    """A single step in the review pipeline."""

    name: str
    status: str  # "ok" / "partial" / "skipped" / "failed"
    message: str = ""


@dataclass
class PipelineTrace:
    """Ordered list of pipeline steps executed during the review."""

    steps: list[PipelineStep] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

@dataclass
class ReviewMetadata:
    """Metadata about the review run itself."""

    duration_seconds: float = 0.0
    provider: str = ""
    model: str = ""
    codesentinel_modified: bool = False
    project_rules_loaded: bool = False


# ---------------------------------------------------------------------------
# Top-level result
# ---------------------------------------------------------------------------

@dataclass
class ReviewResult:
    """The complete, serializable result of a CodeSentinel review."""

    pr_url: str = ""
    pr_title: str = ""
    pr_author: str = ""
    repo: str = ""
    base_branch: str = ""
    head_branch: str = ""

    risk: RiskSummary = field(
        default_factory=lambda: RiskSummary(level="low", score=0)
    )
    dependencies: DependencySummary = field(
        default_factory=lambda: DependencySummary(changes=[], scan_mode="skipped")
    )
    supply_chain: SupplyChainSummary = field(default_factory=SupplyChainSummary)
    impact: ImpactSummary = field(default_factory=ImpactSummary)
    llm_review: LLMReviewSummary = field(default_factory=LLMReviewSummary)
    attention: list[AttentionFile] = field(default_factory=list)
    pipeline: PipelineTrace = field(default_factory=PipelineTrace)
    reports: dict[str, str] = field(default_factory=dict)
    agent_results: list = field(default_factory=list)  # list[AuditResult]
    metadata: ReviewMetadata = field(default_factory=ReviewMetadata)

    # -- convenience properties ------------------------------------------------

    @property
    def is_high_risk(self) -> bool:
        """True when the risk level is 'high'."""
        return self.risk.level == "high"

    @property
    def has_findings(self) -> bool:
        """True when the LLM review produced at least one finding."""
        return len(self.llm_review.findings) > 0

    @property
    def summary(self) -> str:
        """One-line human-readable summary of the review."""
        parts: list[str] = []
        parts.append(f"[{self.risk.level.upper()}] score={self.risk.score}")
        if self.llm_review.findings:
            parts.append(f"findings={len(self.llm_review.findings)}")
        if self.supply_chain.vulnerabilities:
            parts.append(f"vulns={len(self.supply_chain.vulnerabilities)}")
        if self.pr_title:
            parts.append(f"pr={self.pr_title[:60]}")
        return " | ".join(parts)

    # -- serialization ---------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize the entire result to a plain dict."""
        return asdict(self)
