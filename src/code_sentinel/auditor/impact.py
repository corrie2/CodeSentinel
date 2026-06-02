"""Engineering impact assessment — heuristic-based MVP."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ModuleImpact:
    """Impact on a single module/directory."""

    module: str
    files_changed: int
    change_types: list[str]  # "added", "modified", "deleted"
    severity: str  # "low", "medium", "high"


@dataclass
class ImpactReport:
    """Aggregated engineering impact report."""

    total_files_changed: int = 0
    files_added: int = 0
    files_modified: int = 0
    files_deleted: int = 0

    # Build impact
    estimated_build_seconds: int = 0
    build_risk: str = "low"  # low, medium, high

    # Test impact
    test_files_changed: int = 0
    estimated_new_tests_needed: int = 0
    test_coverage_risk: str = "low"

    # Module breakdown
    affected_modules: list[ModuleImpact] = field(default_factory=list)

    # Infrastructure / config changes
    config_changes: list[str] = field(default_factory=list)
    ci_changes: list[str] = field(default_factory=list)
    dependency_changes: list[str] = field(default_factory=list)

    # Warnings
    warnings: list[str] = field(default_factory=list)

    @property
    def has_risk(self) -> bool:
        return self.build_risk in ("medium", "high") or self.test_coverage_risk in ("medium", "high")


# ── Heuristic constants ──────────────────────────────────────────

# Seconds per file by type (very rough)
_BUILD_TIME_PER_FILE: dict[str, float] = {
    ".py": 2,
    ".js": 3,
    ".ts": 5,
    ".jsx": 4,
    ".tsx": 6,
    ".go": 8,
    ".rs": 30,
    ".java": 10,
    ".c": 15,
    ".cpp": 20,
    ".css": 1,
    ".html": 1,
    ".md": 0,
    ".json": 0.5,
    ".yaml": 0.5,
    ".yml": 0.5,
    ".toml": 0.5,
}

_TEST_FILE_PATTERNS = (
    "test_", "_test.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js",
    ".test.tsx", ".test.jsx", ".spec.tsx", ".spec.jsx", "_test.go",
)

_CONFIG_PATTERNS = (
    ".env", "config", "settings", "docker-compose", "Dockerfile",
    ".github/", ".gitlab-ci", "Makefile", "pyproject.toml", "package.json",
    "tsconfig", "webpack", "vite", "rollup", "babel",
)

_CI_PATTERNS = (".github/workflows/", ".gitlab-ci", ".circleci/", "Jenkinsfile", "bitbucket-pipelines")

_DEP_FILES = (
    "requirements.txt", "Pipfile", "pyproject.toml", "package.json",
    "package-lock.json", "yarn.lock", "go.mod", "go.sum", "Cargo.toml",
    "Cargo.lock", "Gemfile", "pom.xml", "build.gradle",
)


def _ext(filename: str) -> str:
    """Get file extension (with dot)."""
    _, ext = os.path.splitext(filename)
    return ext.lower()


def _is_test_file(filename: str) -> bool:
    name = filename.lower()
    return any(pat in name for pat in _TEST_FILE_PATTERNS)


def _is_config_file(filename: str) -> bool:
    name = filename.lower()
    return any(pat in name for pat in _CONFIG_PATTERNS)


def _is_ci_file(filename: str) -> bool:
    name = filename.lower()
    return any(pat in name for pat in _CI_PATTERNS)


def _is_dep_file(filename: str) -> bool:
    basename = os.path.basename(filename).lower()
    return basename in _DEP_FILES


def _extract_module(filename: str, max_depth: int = 2) -> str:
    """Extract top-level module from filepath."""
    parts = Path(filename).parts
    if len(parts) <= 1:
        return "(root)"
    depth = min(max_depth, len(parts) - 1)
    return os.path.join(*parts[:depth])


def _estimate_build_risk(seconds: int) -> str:
    if seconds > 300:
        return "high"
    if seconds > 60:
        return "medium"
    return "low"


def _estimate_test_risk(test_changed: int, total_changed: int, new_tests_needed: int) -> str:
    if total_changed == 0:
        return "low"
    ratio = test_changed / total_changed if total_changed else 0
    if ratio < 0.1 or new_tests_needed > 10:
        return "high"
    if ratio < 0.3 or new_tests_needed > 5:
        return "medium"
    return "low"


def assess_impact(changed_files: list[dict[str, Any]]) -> ImpactReport:
    """
    Assess engineering impact from a list of changed files.

    Each dict should have at minimum:
        - filename: str
        - status: str (added/modified/removed)  [optional, defaults to modified]

    Returns an ImpactReport with heuristic-based estimates.
    """
    report = ImpactReport()

    if not changed_files:
        return report

    report.total_files_changed = len(changed_files)

    # ── Count by change type ──────────────────────────────
    for f in changed_files:
        status = f.get("status", "modified").lower()
        if status in ("added", "add"):
            report.files_added += 1
        elif status in ("removed", "deleted", "remove"):
            report.files_deleted += 1
        else:
            report.files_modified += 1

    # ── Build time estimate ───────────────────────────────
    total_build_seconds = 0.0
    for f in changed_files:
        ext = _ext(f.get("filename", ""))
        total_build_seconds += _BUILD_TIME_PER_FILE.get(ext, 2)
    report.estimated_build_seconds = int(total_build_seconds)
    report.build_risk = _estimate_build_risk(report.estimated_build_seconds)

    # ── Test impact ───────────────────────────────────────
    test_files = [f for f in changed_files if _is_test_file(f.get("filename", ""))]
    report.test_files_changed = len(test_files)

    # Heuristic: each non-test source file likely needs 1 new test
    non_test_source = [
        f for f in changed_files
        if not _is_test_file(f.get("filename", ""))
        and _ext(f.get("filename", "")) in (".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".java", ".rs")
    ]
    # Only count files that were added or significantly modified
    report.estimated_new_tests_needed = max(0, len(non_test_source) - report.test_files_changed)
    report.test_coverage_risk = _estimate_test_risk(
        report.test_files_changed, report.total_files_changed, report.estimated_new_tests_needed
    )

    # ── Module breakdown ──────────────────────────────────
    module_map: dict[str, ModuleImpact] = {}
    for f in changed_files:
        module = _extract_module(f.get("filename", ""))
        status = f.get("status", "modified").lower()
        if module not in module_map:
            module_map[module] = ModuleImpact(
                module=module, files_changed=0, change_types=[], severity="low"
            )
        mi = module_map[module]
        mi.files_changed += 1
        if status not in mi.change_types:
            mi.change_types.append(status)

    for mi in module_map.values():
        if mi.files_changed > 10 or "deleted" in mi.change_types:
            mi.severity = "high"
        elif mi.files_changed > 3:
            mi.severity = "medium"
        else:
            mi.severity = "low"

    report.affected_modules = sorted(module_map.values(), key=lambda m: m.files_changed, reverse=True)

    # ── Config / CI / Dep changes ─────────────────────────
    for f in changed_files:
        fname = f.get("filename", "")
        if _is_ci_file(fname):
            report.ci_changes.append(fname)
        elif _is_config_file(fname):
            report.config_changes.append(fname)
        if _is_dep_file(fname):
            report.dependency_changes.append(fname)

    # ── Warnings ──────────────────────────────────────────
    if report.files_deleted > 0:
        report.warnings.append(f"{report.files_deleted} file(s) deleted — verify no breaking references.")
    if report.ci_changes:
        report.warnings.append(f"CI/CD config changed ({len(report.ci_changes)} file(s)) — review pipeline carefully.")
    if report.dependency_changes:
        report.warnings.append(f"Dependency manifests changed ({len(report.dependency_changes)} file(s)) — run supply chain audit.")
    if report.test_files_changed == 0 and report.total_files_changed > 5:
        report.warnings.append("No test files changed with >5 source files modified — consider adding tests.")

    return report
