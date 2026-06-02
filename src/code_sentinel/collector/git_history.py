"""Git history analysis for project memory.

Uses subprocess to call ``git log`` commands (no git library dependency)
to compute per-module defect density, author experience, and incident history.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, List

logger = logging.getLogger(__name__)

# Keywords that indicate a bug-fix commit (case-insensitive match)
_BUG_FIX_PATTERNS = re.compile(
    r"\b(?:fix|bug|patch|hotfix|issue|resolve[ds]?)\b", re.IGNORECASE
)


def _run_git(repo_path: str, args: list[str], timeout: int = 30) -> str:
    """Run a git command and return stdout.

    Args:
        repo_path: Path to the git repository root.
        args: Git sub-command arguments (e.g., ["log", "--oneline"]).
        timeout: Subprocess timeout in seconds.

    Returns:
        Decoded stdout string.

    Raises:
        FileNotFoundError: If the repo_path does not exist.
        subprocess.CalledProcessError: If git exits non-zero.
        subprocess.TimeoutExpired: If the command exceeds *timeout* seconds.
    """
    cmd = ["git"] + args
    result = subprocess.run(
        cmd,
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, cmd, result.stdout, result.stderr
        )
    return result.stdout


def _since_date(months: int) -> str:
    """Return an ISO date string ``months`` months ago."""
    dt = datetime.now(timezone.utc) - timedelta(days=months * 30)
    return dt.strftime("%Y-%m-%d")


def _extract_module(file_path: str, max_depth: int = 2) -> str:
    """Extract the top-2 directory levels as a module name.

    Examples:
        ``src/payment/billing.py`` -> ``src/payment/``
        ``lib/util.js``           -> ``lib/``
        ``README.md``             -> ``(root)``
    """
    parts = file_path.replace("\\", "/").split("/")
    if len(parts) <= 1:
        return "(root)"
    depth = min(max_depth, len(parts) - 1)
    return "/".join(parts[:depth]) + "/"


def _is_bug_fix(message: str) -> bool:
    """Check whether a commit message indicates a bug fix."""
    return bool(_BUG_FIX_PATTERNS.search(message))


def get_module_commit_counts(
    repo_path: str, months: int = 6
) -> Dict[str, int]:
    """Compute commit count per module (top-2 directory levels).

    Args:
        repo_path: Path to the git repository root.
        months: Look-back window in months.

    Returns:
        Mapping of module path -> number of commits that touched it.
    """
    since = _since_date(months)
    try:
        output = _run_git(repo_path, [
            "log", f"--since={since}", "--name-only", "--pretty=format:",
        ])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.warning("Failed to get commit counts: %s", exc)
        return {}

    counts: Dict[str, int] = {}
    for line in output.splitlines():
        path = line.strip()
        if not path:
            continue
        module = _extract_module(path)
        counts[module] = counts.get(module, 0) + 1
    return counts


def get_module_bug_fix_ratio(
    repo_path: str, months: int = 6
) -> Dict[str, float]:
    """Compute the ratio of bug-fix commits per module.

    A commit is considered a bug-fix if its message contains common
    bug-fix keywords (fix, bug, patch, hotfix, issue, resolve).

    Args:
        repo_path: Path to the git repository root.
        months: Look-back window in months.

    Returns:
        Mapping of module path -> bug-fix ratio (0.0 to 1.0).
    """
    since = _since_date(months)

    # Get all commits with their messages and changed files
    try:
        output = _run_git(repo_path, [
            "log", f"--since={since}",
            "--pretty=format:COMMIT_MSG:%s", "--name-only",
        ])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.warning("Failed to get bug-fix ratio: %s", exc)
        return {}

    # Parse: lines starting with COMMIT_MSG: are messages, others are files
    module_total: Dict[str, int] = {}
    module_bugfix: Dict[str, int] = {}
    current_is_bugfix = False

    for line in output.splitlines():
        if line.startswith("COMMIT_MSG:"):
            current_is_bugfix = _is_bug_fix(line[len("COMMIT_MSG:"):])
            continue
        path = line.strip()
        if not path:
            continue
        module = _extract_module(path)
        module_total[module] = module_total.get(module, 0) + 1
        if current_is_bugfix:
            module_bugfix[module] = module_bugfix.get(module, 0) + 1

    result: Dict[str, float] = {}
    for module, total in module_total.items():
        bugfix = module_bugfix.get(module, 0)
        result[module] = bugfix / total if total > 0 else 0.0
    return result


def get_author_module_experience(
    repo_path: str, author_email: str
) -> Dict[str, int]:
    """Count commits per module by a specific author.

    Args:
        repo_path: Path to the git repository root.
        author_email: The git author email to filter by.

    Returns:
        Mapping of module path -> number of commits by this author.
    """
    try:
        output = _run_git(repo_path, [
            "log", f"--author={author_email}", "--name-only",
            "--pretty=format:",
        ])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.warning("Failed to get author experience: %s", exc)
        return {}

    counts: Dict[str, int] = {}
    for line in output.splitlines():
        path = line.strip()
        if not path:
            continue
        module = _extract_module(path)
        counts[module] = counts.get(module, 0) + 1
    return counts


def get_recent_incidents(
    repo_path: str, months: int = 3
) -> Dict[str, int]:
    """Count bug-fix commits per module in recent history.

    Args:
        repo_path: Path to the git repository root.
        months: Look-back window in months.

    Returns:
        Mapping of module path -> number of bug-fix commits.
    """
    since = _since_date(months)
    try:
        output = _run_git(repo_path, [
            "log", f"--since={since}",
            "--pretty=format:COMMIT_MSG:%s", "--name-only",
        ])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.warning("Failed to get recent incidents: %s", exc)
        return {}

    module_bugfix: Dict[str, int] = {}
    current_is_bugfix = False

    for line in output.splitlines():
        if line.startswith("COMMIT_MSG:"):
            current_is_bugfix = _is_bug_fix(line[len("COMMIT_MSG:"):])
            continue
        path = line.strip()
        if not path:
            continue
        if current_is_bugfix:
            module = _extract_module(path)
            module_bugfix[module] = module_bugfix.get(module, 0) + 1

    return module_bugfix
