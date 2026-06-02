"""Risk scoring engine — combines data collectors and rule evaluation into a RiskScore."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    import toml
except ImportError:
    toml = None  # type: ignore

from code_sentinel.collector.diff_parser import ChangeSet
from code_sentinel.collector.dep_scanner import DependencyChange
from code_sentinel.collector.codeowners import CodeOwnersFile
from code_sentinel.risk.rules import (
    RuleSet,
    evaluate_rules,
    load_rules_from_toml,
)


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RiskScore:
    """Final risk assessment output."""
    level: RiskLevel
    score: int
    triggered_rules: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    rule_details: List[Dict[str, Any]] = field(default_factory=list)

    def summary(self) -> str:
        """Human-readable summary of the risk score."""
        lines = [
            f"Risk Level: {self.level.value.upper()}",
            f"Score: {self.score}",
            f"Tags: {', '.join(self.tags) if self.tags else 'none'}",
        ]
        if self.triggered_rules:
            lines.append("Triggered rules:")
            for rule in self.triggered_rules:
                lines.append(f"  - {rule}")
        return "\n".join(lines)

    @property
    def breakdown_lines(self) -> List[str]:
        """Formatted breakdown lines showing each rule's contribution.

        Returns strings like '+5 sensitive path (payment/)'.
        """
        lines: List[str] = []
        for detail in self.rule_details:
            delta = detail.get("score_delta", 0)
            desc = detail.get("description", "")
            tag = detail.get("tag", "")
            line = f"+{delta} {desc}"
            if tag:
                line += f" [{tag}]"
            lines.append(line)
        return lines


def _build_context(
    changeset: Optional[ChangeSet] = None,
    dep_changes: Optional[List[DependencyChange]] = None,
    codeowners: Optional[CodeOwnersFile] = None,
    author: Optional[str] = None,
    author_history: Optional[Dict[str, Any]] = None,
    module_defect_density: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """Build the context dictionary for rule evaluation.

    Args:
        changeset: Parsed diff changeset.
        dep_changes: List of dependency changes.
        codeowners: Parsed CODEOWNERS file.
        author: PR author username.
        author_history: Dict with author history info (modules touched, etc.).
        module_defect_density: Dict mapping module paths to defect densities.

    Returns:
        Context dictionary for rule evaluation.
    """
    ctx: Dict[str, Any] = {
        "modified_files": 0,
        "lines_added": 0,
        "lines_deleted": 0,
        "total_changes": 0,
        "added_files": 0,
        "deleted_files": 0,
        "renamed_files": 0,
        "unique_functions_changed": 0,
        "unique_classes_changed": 0,
        "new_deps_count": 0,
        "removed_deps_count": 0,
        "upgraded_deps_count": 0,
        "adds_new_dependency": False,
        "removes_dependency": False,
        "author_first_time_in_module": False,
        "module_defect_density": 0.0,
        "hunks": 0,
        # Internal data for function-based rules
        "_file_paths": [],
        "_dep_changes": dep_changes or [],
        "_author_owned_paths": [],
    }

    # Changeset data
    if changeset:
        ctx["modified_files"] = changeset.total_files
        ctx["lines_added"] = changeset.total_additions
        ctx["lines_deleted"] = changeset.total_deletions
        ctx["total_changes"] = changeset.total_changes

        all_funcs: set = set()
        all_classes: set = set()
        total_hunks = 0
        added_count = 0
        deleted_count = 0
        renamed_count = 0

        for f in changeset.files:
            from code_sentinel.collector.diff_parser import ChangeType
            if f.change_type == ChangeType.ADD:
                added_count += 1
            elif f.change_type == ChangeType.DELETE:
                deleted_count += 1
            elif f.change_type == ChangeType.RENAME:
                renamed_count += 1

            all_funcs.update(f.changed_functions)
            all_classes.update(f.changed_classes)
            total_hunks += f.hunks

        ctx["added_files"] = added_count
        ctx["deleted_files"] = deleted_count
        ctx["renamed_files"] = renamed_count
        ctx["unique_functions_changed"] = len(all_funcs)
        ctx["unique_classes_changed"] = len(all_classes)
        ctx["hunks"] = total_hunks
        ctx["_file_paths"] = changeset.paths()

    # Dependency changes (supports both old DependencyChange and new DepChange)
    if dep_changes:
        for dc in dep_changes:
            if hasattr(dc, 'change_type'):
                # New DepChange format
                if dc.change_type == 'added':
                    ctx["new_deps_count"] += 1
                elif dc.change_type == 'removed':
                    ctx["removed_deps_count"] += 1
                elif dc.change_type == 'version_changed':
                    ctx["upgraded_deps_count"] += 1
            else:
                # Old DependencyChange format
                ctx["new_deps_count"] += len(dc.added)
                ctx["removed_deps_count"] += len(dc.removed)
                ctx["upgraded_deps_count"] += len(dc.upgraded)
        ctx["adds_new_dependency"] = ctx["new_deps_count"] > 0
        ctx["removes_dependency"] = ctx["removed_deps_count"] > 0

    # Author history
    if author_history:
        ctx["author_first_time_in_module"] = author_history.get(
            "first_time_in_module", False
        )
        ctx["author_total_prs"] = author_history.get("total_prs", 0)
        ctx["author_merged_prs"] = author_history.get("merged_prs", 0)

    # Module defect density
    if module_defect_density and changeset:
        max_density = 0.0
        for path in changeset.paths():
            # Check if any module in the path has high defect density
            for module, density in module_defect_density.items():
                if module in path:
                    max_density = max(max_density, density)
        ctx["module_defect_density"] = max_density

    # Codeowners: find what the author owns
    if codeowners and author:
        owned_paths = []
        for rule in codeowners.rules:
            if author in rule.owners:
                owned_paths.append(rule.pattern)
        ctx["_author_owned_paths"] = owned_paths

    return ctx


def load_rules(rules_path: Optional[str] = None) -> RuleSet:
    """Load rules from a TOML file.

    Args:
        rules_path: Path to the rules TOML file. If None, uses the default location.

    Returns:
        A RuleSet instance.
    """
    if rules_path is None:
        # Default: look for rules/default.toml relative to the package
        rules_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
            "rules",
            "default.toml",
        )

    if toml is None:
        raise ImportError(
            "The 'toml' package is required to load rules. "
            "Install it with: pip install toml"
        )

    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            data = toml.load(f)
    except FileNotFoundError:
        # Return default ruleset if file not found
        return RuleSet()
    except Exception as e:
        raise RuntimeError(f"Failed to load rules from {rules_path}: {e}")

    return load_rules_from_toml(data)


def assess_risk(
    changeset: Optional[ChangeSet] = None,
    dep_changes: Optional[List[DependencyChange]] = None,
    codeowners: Optional[CodeOwnersFile] = None,
    author: Optional[str] = None,
    author_history: Optional[Dict[str, Any]] = None,
    module_defect_density: Optional[Dict[str, float]] = None,
    rules_path: Optional[str] = None,
    ruleset: Optional[RuleSet] = None,
) -> RiskScore:
    """Perform a full risk assessment.

    Args:
        changeset: Parsed diff changeset.
        dep_changes: List of dependency changes.
        codeowners: Parsed CODEOWNERS file.
        author: PR author username.
        author_history: Dict with author history info.
        module_defect_density: Dict mapping module paths to defect densities.
        rules_path: Path to the rules TOML file (optional).
        ruleset: Pre-loaded RuleSet (optional, takes precedence over rules_path).

    Returns:
        A RiskScore with level, score, triggered rules, and tags.
    """
    # Load rules
    if ruleset is None:
        ruleset = load_rules(rules_path)

    # Build evaluation context
    context = _build_context(
        changeset=changeset,
        dep_changes=dep_changes,
        codeowners=codeowners,
        author=author,
        author_history=author_history,
        module_defect_density=module_defect_density,
    )

    # Evaluate
    score, triggered, tags = evaluate_rules(ruleset, context)

    # Determine risk level
    if score <= ruleset.low_risk_max:
        level = RiskLevel.LOW
    elif score <= ruleset.medium_risk_max:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH

    # Build rule details with score_delta for breakdown display
    triggered_set = set(triggered)
    rule_details: List[Dict[str, Any]] = []
    for rule in ruleset.rules:
        if rule.enabled and rule.description in triggered_set:
            rule_details.append({
                "description": rule.description,
                "score_delta": rule.score_delta,
                "tag": rule.tag,
            })

    return RiskScore(
        level=level,
        score=score,
        triggered_rules=triggered,
        tags=tags,
        rule_details=rule_details,
    )
