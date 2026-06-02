"""Rank individual files by risk for LLM review and human attention.

This module scores each changed file in a ChangeSet independently,
producing a prioritized list of files that deserve the most scrutiny.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from code_sentinel.collector.diff_parser import ChangeSet


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS = (
    "payment/",
    "auth/",
    "security/",
    ".github/workflows/",
    "deploy/",
)

_CONFIG_DEP_PATTERNS = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    ".env",
    ".env.",
    "docker-compose",
    "Dockerfile",
    "k8s/",
    "kubernetes/",
    "helm/",
    ".gitlab-ci.yml",
    ".travis.yml",
    "Jenkinsfile",
    "Makefile",
    "Terraformfile",
    ".tf",
)

_PROD_EXCLUDE_PATTERNS = (
    "test/",
    "tests/",
    "spec/",
    "specs/",
    "__tests__/",
    "doc/",
    "docs/",
    "example/",
    "examples/",
    "demo/",
    "fixture/",
    "fixtures/",
    "mock/",
    "mocks/",
    "testdata/",
    ".md",
    ".txt",
    ".rst",
)

_TEST_PREFIXES = ("test_", "test.", "_test.", "_test_")
_TEST_DIR_SEGMENTS = ("test/", "tests/", "spec/", "specs/", "__tests__/")

_AUTH_KEYWORDS_RE = re.compile(
    r"\b(?:permission|auth|role|access|token|secret|credential)\b",
    re.IGNORECASE,
)

_ERROR_KEYWORDS_RE = re.compile(
    r"\b(?:catch|except|error|throw|rescue|finally)\b",
    re.IGNORECASE,
)

ATTENTION_THRESHOLD = 40.0


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RankedFile:
    """A single file ranked by risk score."""
    path: str
    score: float
    reasons: List[str] = field(default_factory=list)
    needs_attention: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _base_score(lines_added: int, lines_deleted: int) -> float:
    """Log-scaled base score from change size."""
    return math.log2(lines_added + lines_deleted + 1) * 2


def _is_sensitive_path(path: str) -> bool:
    lower = path.lower()
    return any(pat in lower for pat in _SENSITIVE_PATHS)


def _is_config_or_dep(path: str) -> bool:
    lower = path.lower()
    basename = os.path.basename(lower)
    return any(pat in lower or basename == pat for pat in _CONFIG_DEP_PATTERNS)


def _is_production_path(path: str) -> bool:
    """True if the path is NOT a test/doc/example/fixture file."""
    lower = path.lower()
    return not any(pat in lower for pat in _PROD_EXCLUDE_PATTERNS)


def _has_no_test_file(path: str, all_paths: List[str]) -> bool:
    """Check if a source file has no corresponding test file in the changeset.

    Heuristic: if path contains src/ and does not itself look like a test,
    look for a matching test_* or *_test file.
    """
    normalized = path.replace("\\", "/")
    basename = os.path.basename(normalized)
    name_no_ext, ext = os.path.splitext(basename)

    # Skip if the file itself is a test
    if any(basename.startswith(p) for p in _TEST_PREFIXES):
        return False
    if any(seg in normalized for seg in _TEST_DIR_SEGMENTS):
        return False

    # Only apply to source files (skip configs, assets, etc.)
    source_exts = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java",
        ".rb", ".rs", ".c", ".cpp", ".cs", ".kt", ".swift",
        ".scala", ".ex", ".exs", ".lua", ".php",
    }
    if ext.lower() not in source_exts:
        return False

    # Build candidate test file names
    candidates = set()
    for prefix in ("test_",):
        candidates.add(prefix + name_no_ext + ext)
    for suffix in ("_test",):
        candidates.add(name_no_ext + suffix + ext)

    all_basenames = {os.path.basename(p.replace("\\", "/")) for p in all_paths}
    return not (candidates & all_basenames)


def _has_auth_keywords(path: str) -> bool:
    """Check if the path itself suggests auth/permission logic."""
    return bool(_AUTH_KEYWORDS_RE.search(path))


def _matches_critical_path(
    path: str, critical_paths: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Return the matching critical path entry, or None."""
    for entry in critical_paths:
        cp = entry.get("path", "")
        if cp and cp in path:
            return entry
    return None


def _is_high_defect_module(
    path: str, high_defect_modules: List[str]
) -> bool:
    return any(mod in path for mod in high_defect_modules)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def rank_files(
    changeset: ChangeSet,
    risk_context: Optional[Dict[str, Any]] = None,
) -> List[RankedFile]:
    """Rank every file in *changeset* by risk score.

    Parameters
    ----------
    changeset:
        A parsed diff ChangeSet (from ``diff_parser.parse_diff``).
    risk_context:
        Optional dict with project-specific risk signals:

        - ``critical_paths``: list of ``{path, weight, reason}``
        - ``high_defect_modules``: list of module path strings
        - ``codeowners``: dict mapping path patterns to owners

    Returns
    -------
    list[RankedFile]
        Files sorted by score descending. Each file's ``needs_attention``
        flag is set when score >= ATTENTION_THRESHOLD.
    """
    ctx = risk_context or {}
    critical_paths = ctx.get("critical_paths", [])
    high_defect_modules = ctx.get("high_defect_modules", [])
    all_paths = changeset.paths()

    results: List[RankedFile] = []

    for f in changeset.files:
        score = 0.0
        reasons: List[str] = []

        # --- Base: log-scaled change size ---
        base = _base_score(f.lines_added, f.lines_deleted)
        score += base
        if base > 4:
            reasons.append(
                f"Large change: {f.lines_added} added, {f.lines_deleted} deleted"
            )

        # --- Sensitive path ---
        if _is_sensitive_path(f.path):
            score += 50
            reasons.append("Sensitive path (payment/auth/security/deploy)")

        # --- Config / dependency file ---
        if _is_config_or_dep(f.path):
            score += 40
            reasons.append("Config or dependency file")

        # --- Critical path from project rules ---
        cp_match = _matches_critical_path(f.path, critical_paths)
        if cp_match:
            weight = cp_match.get("weight", 0)
            reason = cp_match.get("reason", "Critical path in project rules")
            score += weight
            reasons.append(f"Critical path: {reason} (+{weight})")

        # --- High-defect module from memory ---
        if _is_high_defect_module(f.path, high_defect_modules):
            score += 30
            reasons.append("High-defect module (project memory)")

        # --- No corresponding test file ---
        if _has_no_test_file(f.path, all_paths):
            score += 20
            reasons.append("No corresponding test file in changeset")

        # --- Production path (not test/doc/example) ---
        if _is_production_path(f.path):
            score += 15
            reasons.append("Production source file")

        # --- Deletion-heavy ---
        if f.lines_deleted > f.lines_added and f.lines_deleted > 0:
            score += 15
            reasons.append(
                f"Deletion-heavy ({f.lines_deleted} deleted > {f.lines_added} added)"
            )

        # --- Permission / auth logic in path ---
        if _has_auth_keywords(f.path):
            score += 25
            reasons.append("Auth/permission-related path")

        # --- Error handling keywords in path (rare but catches error_handlers etc.) ---
        if _ERROR_KEYWORDS_RE.search(f.path):
            score += 15
            reasons.append("Error-handling related path")

        # --- Finalize ---
        needs_attention = score >= ATTENTION_THRESHOLD
        results.append(
            RankedFile(
                path=f.path,
                score=round(score, 2),
                reasons=reasons,
                needs_attention=needs_attention,
            )
        )

    results.sort(key=lambda r: r.score, reverse=True)
    return results


def get_top_files(
    changeset: ChangeSet,
    n: int = 3,
    risk_context: Optional[Dict[str, Any]] = None,
) -> List[RankedFile]:
    """Return the top *n* highest-risk files for LLM deep review.

    Convenience wrapper around :func:`rank_files`.
    """
    return rank_files(changeset, risk_context)[:n]
