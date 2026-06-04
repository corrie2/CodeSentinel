"""Plugin interfaces for CodeSentinel.

Defines the base classes and shared data structures that every auditor
and reporter plugin must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Shared context / result objects
# ---------------------------------------------------------------------------

@dataclass
class AuditContext:
    """All data a plugin needs to perform its audit.

    Passed into ``AuditorPlugin.audit()`` by the pipeline orchestrator.
    """

    pr_url: str = ""
    pr_info: dict = field(default_factory=dict)
    # title, author, url, number, repo, base_sha, head_sha

    changeset: Any = None  # ChangeSet or None
    raw_diff: str = ""
    base_ref: str = ""
    head_ref: str = ""
    repo_path: str | None = None
    ruleset: Any = None  # RuleSet
    project_context: str | None = None
    dep_changes: list = field(default_factory=list)
    github_token: str | None = None
    gitlab_token: str | None = None
    llm_config: dict | None = None
    risk_summary: Any = None  # RiskSummary (risk level + score)
    options: Any = None  # ReviewOptions
    step_results: list = field(default_factory=list)  # collected StepResults


@dataclass
class AuditResult:
    """Output produced by a single auditor plugin."""

    name: str = ""
    status: str = "skipped"  # "ok" / "partial" / "failed" / "skipped"
    findings: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    error: str | None = None
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Plugin base classes
# ---------------------------------------------------------------------------

class AuditorPlugin(ABC):
    """Base class for all auditor plugins.

    Subclass this and implement ``audit()`` to add a new analysis step
    to the CodeSentinel pipeline.
    """

    name: str = "base"

    @abstractmethod
    async def audit(self, context: AuditContext) -> AuditResult:
        """Run the audit and return an AuditResult."""
        raise NotImplementedError


class ReporterPlugin(ABC):
    """Base class for all reporter plugins.

    Subclass this and implement ``render()`` to add a new output format
    (JSON, SARIF, HTML, etc.).
    """

    name: str = "base"

    @abstractmethod
    def render(self, result: Any) -> str:
        """Render a ReviewResult (or similar) into a string."""
        raise NotImplementedError


class RulePlugin(ABC):
    """Base class for rule-loading plugins.

    Subclass this and implement ``load_rules()`` to add custom rule
    sources (remote API, database, etc.).
    """

    name: str = "base"

    @abstractmethod
    def load_rules(self) -> Any:
        """Load and return a RuleSet (or compatible object)."""
        raise NotImplementedError
