"""Tests for .codesentinel/ security logic: modified-by-PR blocks local fallback,
base branch priority, and API failure fallback behavior.

Every test is self-contained, uses fast mocks, and requires no real API keys.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from code_sentinel.review import ReviewOptions, review
from code_sentinel.result import ReviewResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_DIFF_WITH_CODESENTINEL = (
    "--- a/.codesentinel/project_profile.md\n"
    "+++ b/.codesentinel/project_profile.md\n"
    "@@ -1,2 +1,3 @@\n"
    " # Project\n"
    "+updated\n"
    "--- a/foo.py\n"
    "+++ b/foo.py\n"
    "@@ -1,3 +1,4 @@\n"
    " hello\n"
    "+world\n"
    " end\n"
)

_FAKE_DIFF_NORMAL = (
    "--- a/foo.py\n"
    "+++ b/foo.py\n"
    "@@ -1,3 +1,4 @@\n"
    " hello\n"
    "+world\n"
    " end\n"
)


def _fake_pr_data_normal():
    """PR data that does NOT touch .codesentinel/ files."""
    return {
        "pr": {
            "title": "Normal PR",
            "author": "dev",
            "url": "https://github.com/owner/repo/pull/10",
            "number": 10,
            "repo": "owner/repo",
            "base_sha": "abc123",
            "head_sha": "def456",
        },
        "diff": _FAKE_DIFF_NORMAL,
        "changed_files": [
            {"filename": "foo.py", "status": "modified", "additions": 1, "deletions": 0},
        ],
    }


def _fake_pr_data_with_codesentinel():
    """PR data that DOES touch .codesentinel/ files."""
    return {
        "pr": {
            "title": "Modify config PR",
            "author": "admin",
            "url": "https://github.com/owner/repo/pull/11",
            "number": 11,
            "repo": "owner/repo",
            "base_sha": "abc123",
            "head_sha": "def456",
        },
        "diff": _FAKE_DIFF_WITH_CODESENTINEL,
        "changed_files": [
            {
                "filename": ".codesentinel/project_profile.md",
                "status": "modified",
                "additions": 1,
                "deletions": 0,
            },
            {"filename": "foo.py", "status": "modified", "additions": 1, "deletions": 0},
        ],
    }


def _make_risk_score(level="low", score=0, triggered=None, details=None):
    """Build a mock RiskScore."""
    from code_sentinel.risk.scorer import RiskLevel

    rs = MagicMock()
    rs.level = getattr(RiskLevel, level.upper()) if isinstance(level, str) else level
    rs.score = score
    rs.triggered_rules = triggered or []
    rs.tags = []
    rs.rule_details = details or []
    return rs


_COLLECT = "code_sentinel.review._collect_pr_data"
_ASSESS = "code_sentinel.risk.scorer.assess_risk"
_LOAD_RULES = "code_sentinel.risk.scorer.load_rules"
_GITHUB_PROVIDER = "code_sentinel.git_provider.github.GitHubProvider"


def _base_patches(**kwargs):
    """Return a list of patch decorators for every test."""
    collect = kwargs.get("collect", AsyncMock(return_value=_fake_pr_data_normal()))
    risk_score = kwargs.get("risk_score", _make_risk_score())

    return [
        patch(_COLLECT, collect),
        patch(_ASSESS, return_value=risk_score),
        patch(_LOAD_RULES, return_value=MagicMock(rules=[], critical_paths=[])),
    ]


def _mock_github_provider(return_content=""):
    """Create a mock GitHubProvider that works as an async context manager.

    Parameters
    ----------
    return_content : str or Exception
        If str, get_file_content returns this value.
        If Exception subclass instance, get_file_content raises it.
    """
    mock_provider = AsyncMock()
    mock_provider.__aenter__ = AsyncMock(return_value=mock_provider)
    mock_provider.__aexit__ = AsyncMock(return_value=False)
    if isinstance(return_content, Exception):
        mock_provider.get_file_content = AsyncMock(side_effect=return_content)
    else:
        mock_provider.get_file_content = AsyncMock(return_value=return_content)
    return patch(_GITHUB_PROVIDER, return_value=mock_provider)


# ---------------------------------------------------------------------------
# 1. test_codesentinel_modified_blocks_local_fallback
# ---------------------------------------------------------------------------


def test_codesentinel_modified_blocks_local_fallback():
    """When a PR modifies .codesentinel/ files, local fallback must be blocked.

    Even if repo_path points to a directory with .codesentinel/project_profile.md,
    the local file must NOT be read when codesentinel_modified=True.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        codesentinel_dir = Path(tmpdir) / ".codesentinel"
        codesentinel_dir.mkdir()
        profile = codesentinel_dir / "project_profile.md"
        profile.write_text("# Local Project Profile\nThis should NOT be read.\n")

        opts = ReviewOptions(
            skip_llm=True,
            github_token="fake",
            repo_path=tmpdir,
        )

        patches = _base_patches(
            collect=AsyncMock(return_value=_fake_pr_data_with_codesentinel()),
            risk_score=_make_risk_score("low", 0),
        )

        # API returns empty — local fallback is also blocked
        with patches[0], patches[1], patches[2], _mock_github_provider(""):
            result = asyncio.run(
                review("https://github.com/owner/repo/pull/11", opts)
            )

        # project_context must be empty — local fallback is blocked
        # and API returned nothing
        ctx_steps = [
            s for s in result.pipeline.steps if s.name == "Project Context"
        ]
        assert len(ctx_steps) > 0
        assert ctx_steps[0].status == "partial"
        assert "base branch" in ctx_steps[0].message.lower() or "modified" in ctx_steps[0].message.lower()


# ---------------------------------------------------------------------------
# 2. test_base_branch_rules_priority
# ---------------------------------------------------------------------------


def test_base_branch_rules_priority():
    """When the GitHub API returns rules.toml from the base branch, those rules
    take priority over any local rules.toml.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create local rules.toml — should NOT be used
        codesentinel_dir = Path(tmpdir) / ".codesentinel"
        codesentinel_dir.mkdir()
        local_rules = codesentinel_dir / "rules.toml"
        local_rules.write_text('[rules]\ncritical_paths = ["local_secret"]\n')

        opts = ReviewOptions(
            skip_llm=True,
            github_token="fake",
            repo_path=tmpdir,
        )

        # Mock GitHub provider to return base-branch rules
        base_rules_content = '[rules]\ncritical_paths = ["base_branch_path"]\n'

        patches = _base_patches(risk_score=_make_risk_score("low", 0))

        with patches[0], patches[1], patches[2], \
             _mock_github_provider(base_rules_content):
            result = asyncio.run(
                review("https://github.com/owner/repo/pull/10", opts)
            )

        # load_rules should have been called with the temp file from base branch
        # (not the local path).  Check that a "Project Rules" trace was recorded
        # for the base branch.
        rules_steps = [
            s for s in result.pipeline.steps if s.name == "Project Rules"
        ]
        assert len(rules_steps) > 0
        assert "base branch" in rules_steps[0].message.lower()


# ---------------------------------------------------------------------------
# 3. test_base_api_failure_with_modified_blocks_local
# ---------------------------------------------------------------------------


def test_base_api_failure_with_modified_blocks_local():
    """When PR modifies .codesentinel/ and the API fails, local fallback is
    still blocked.  rules_path should stay None (uses defaults).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        codesentinel_dir = Path(tmpdir) / ".codesentinel"
        codesentinel_dir.mkdir()
        profile = codesentinel_dir / "project_profile.md"
        profile.write_text("# Local Profile\nThis must NOT be read.\n")
        local_rules = codesentinel_dir / "rules.toml"
        local_rules.write_text('[rules]\ncritical_paths = ["local_only"]\n')

        opts = ReviewOptions(
            skip_llm=True,
            github_token="fake",
            repo_path=tmpdir,
        )

        patches = _base_patches(
            collect=AsyncMock(return_value=_fake_pr_data_with_codesentinel()),
            risk_score=_make_risk_score("low", 0),
        )

        # API raises an exception
        with patches[0], patches[1], patches[2], \
             _mock_github_provider(Exception("API error")):
            result = asyncio.run(
                review("https://github.com/owner/repo/pull/11", opts)
            )

        # risk score should still be computed (defaults)
        assert result.risk is not None

        # Check that no "loaded from local repo" trace exists
        rules_steps = [
            s for s in result.pipeline.steps if s.name == "Project Rules"
        ]
        for step in rules_steps:
            assert "local repo" not in step.message.lower(), (
                f"Local fallback should be blocked when .codesentinel/ is modified. "
                f"Got: {step.message}"
            )


# ---------------------------------------------------------------------------
# 4. test_base_api_failure_without_modified_uses_local
# ---------------------------------------------------------------------------


def test_base_api_failure_without_modified_uses_local():
    """When the PR does NOT modify .codesentinel/ and the API fails, local
    rules.toml should be loaded as a fallback.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        codesentinel_dir = Path(tmpdir) / ".codesentinel"
        codesentinel_dir.mkdir()
        local_rules = codesentinel_dir / "rules.toml"
        local_rules.write_text('[rules]\ncritical_paths = ["local_fallback"]\n')

        opts = ReviewOptions(
            skip_llm=True,
            github_token="fake",
            repo_path=tmpdir,
        )

        patches = _base_patches(risk_score=_make_risk_score("low", 0))

        # API raises an exception — no .codesentinel/ in PR diff so local is OK
        with patches[0], patches[1], patches[2], \
             _mock_github_provider(Exception("API error")):
            result = asyncio.run(
                review("https://github.com/owner/repo/pull/10", opts)
            )

        # Verify local rules were loaded
        rules_steps = [
            s for s in result.pipeline.steps if s.name == "Project Rules"
        ]
        assert len(rules_steps) > 0
        assert any(
            "local repo" in s.message.lower() for s in rules_steps
        ), (
            f"Expected local rules to be loaded as fallback. "
            f"Got steps: {[s.message for s in rules_steps]}"
        )
