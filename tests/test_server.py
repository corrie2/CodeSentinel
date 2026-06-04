"""Tests for CodeSentinel webhook server.

Covers app creation, config injection, health endpoint, audit pipeline,
and comment posting (GitHub + GitLab).

Every test is self-contained, uses fast mocks, and requires no real API keys.
"""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from code_sentinel.config import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_review_result(
    reports: dict | None = None,
    risk_level: str = "low",
    risk_score: int = 0,
    findings: list | None = None,
):
    """Create a mock ReviewResult with configurable reports."""
    result = MagicMock()
    result.risk.level = risk_level
    result.risk.score = risk_score
    result.llm_review.findings = findings or []
    result.reports = reports or {}
    result.pr_url = "https://github.com/owner/repo/pull/42"
    result.pr_title = "Test PR"
    result.pr_author = "testuser"
    result.repo = "owner/repo"
    result.base_branch = "main"
    result.head_branch = "feature"
    result.needs_attention = []
    result.recommendations = []
    result.risk.contributions = []
    return result


# ---------------------------------------------------------------------------
# 1. App creation
# ---------------------------------------------------------------------------


def test_create_app_with_config():
    """create_app(config=Config(provider='deepseek')) populates _app_state."""
    from code_sentinel.server import create_app, _app_state

    cfg = Config(provider="deepseek")
    app = create_app(config=cfg)

    assert _app_state["config"] is cfg
    assert _app_state["config"].provider == "deepseek"


# ---------------------------------------------------------------------------
# 2. Health endpoint
# ---------------------------------------------------------------------------


def test_health_endpoint():
    """GET /health returns status 'healthy'."""
    from code_sentinel.server import create_app

    try:
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("httpx not installed — needed for TestClient")

    app = create_app(config=Config(provider="mimo"))
    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "codesentinel"


# ---------------------------------------------------------------------------
# 3. Audit pipeline — config passthrough
# ---------------------------------------------------------------------------


def test_run_audit_passes_config():
    """_run_audit passes the provider from _app_state['config'] to ReviewOptions."""
    from code_sentinel.server import create_app, _app_state, _run_audit

    cfg = Config(provider="deepseek", github_token="gh_test_token")
    create_app(config=cfg)

    captured = {}

    async def fake_review(pr_url, options=None):
        captured["options"] = options
        return _make_review_result()

    with patch("code_sentinel.server._app_state", _app_state), \
         patch("code_sentinel.review.review", side_effect=fake_review):
        asyncio.run(_run_audit("github", "owner", "repo", 42))

    assert captured["options"].provider == "deepseek"
    assert captured["options"].github_token == "gh_test_token"


# ---------------------------------------------------------------------------
# 4. Comment posting — GitHub
# ---------------------------------------------------------------------------


def test_run_audit_posts_github_comment():
    """_run_audit posts review comment on GitHub PR using pr-comment report."""
    from code_sentinel.server import create_app, _app_state, _run_audit

    cfg = Config(github_token="gh_token")
    create_app(config=cfg)

    review_result = _make_review_result(
        reports={"pr-comment": "## CodeSentinel Review\n\nRisk: LOW"}
    )

    mock_provider = AsyncMock()
    mock_provider.__aenter__ = AsyncMock(return_value=mock_provider)
    mock_provider.__aexit__ = AsyncMock(return_value=False)
    mock_provider.post_comment = AsyncMock(return_value=True)

    async def fake_review(pr_url, options=None):
        return review_result

    with patch("code_sentinel.server._app_state", _app_state), \
         patch("code_sentinel.review.review", side_effect=fake_review), \
         patch("code_sentinel.git_provider.github.GitHubProvider", return_value=mock_provider):
        asyncio.run(_run_audit("github", "owner", "repo", 42))

    mock_provider.post_comment.assert_called_once()
    call_args = mock_provider.post_comment.call_args
    assert call_args[0][0] == "owner"  # owner
    assert call_args[0][1] == "repo"   # repo
    assert call_args[0][2] == 42       # number
    assert "CodeSentinel Review" in call_args[0][3]  # body


def test_run_audit_github_uses_fallback_comment():
    """_run_audit generates fallback comment when pr-comment report missing."""
    from code_sentinel.server import create_app, _app_state, _run_audit

    cfg = Config(github_token="gh_token")
    create_app(config=cfg)

    # No pr-comment key in reports
    review_result = _make_review_result(reports={"markdown": "# Report"})

    mock_provider = AsyncMock()
    mock_provider.__aenter__ = AsyncMock(return_value=mock_provider)
    mock_provider.__aexit__ = AsyncMock(return_value=False)
    mock_provider.post_comment = AsyncMock(return_value=True)

    async def fake_review(pr_url, options=None):
        return review_result

    with patch("code_sentinel.server._app_state", _app_state), \
         patch("code_sentinel.review.review", side_effect=fake_review), \
         patch("code_sentinel.git_provider.github.GitHubProvider", return_value=mock_provider):
        asyncio.run(_run_audit("github", "owner", "repo", 42))

    mock_provider.post_comment.assert_called_once()
    body = mock_provider.post_comment.call_args[0][3]
    assert "CodeSentinel Review" in body


def test_run_audit_github_comment_failure_logged():
    """_run_audit logs error when comment posting fails."""
    from code_sentinel.server import create_app, _app_state, _run_audit

    cfg = Config(github_token="gh_token")
    create_app(config=cfg)

    review_result = _make_review_result(
        reports={"pr-comment": "comment"}
    )

    mock_provider = AsyncMock()
    mock_provider.__aenter__ = AsyncMock(return_value=mock_provider)
    mock_provider.__aexit__ = AsyncMock(return_value=False)
    mock_provider.post_comment = AsyncMock(return_value=False)

    async def fake_review(pr_url, options=None):
        return review_result

    with patch("code_sentinel.server._app_state", _app_state), \
         patch("code_sentinel.review.review", side_effect=fake_review), \
         patch("code_sentinel.git_provider.github.GitHubProvider", return_value=mock_provider):
        # Should not raise, just log
        asyncio.run(_run_audit("github", "owner", "repo", 42))

    mock_provider.post_comment.assert_called_once()


# ---------------------------------------------------------------------------
# 5. Comment posting — GitLab
# ---------------------------------------------------------------------------


def test_run_audit_posts_gitlab_comment():
    """_run_audit posts review note on GitLab MR using correct provider."""
    from code_sentinel.server import create_app, _app_state, _run_audit

    cfg = Config(gitlab_token="gl_token")
    create_app(config=cfg)

    review_result = _make_review_result(
        reports={"pr-comment": "## CodeSentinel Review\n\nRisk: LOW"}
    )

    mock_provider = AsyncMock()
    mock_provider.__aenter__ = AsyncMock(return_value=mock_provider)
    mock_provider.__aexit__ = AsyncMock(return_value=False)
    mock_provider.post_comment = AsyncMock(return_value=True)

    async def fake_review(pr_url, options=None):
        return review_result

    with patch("code_sentinel.server._app_state", _app_state), \
         patch("code_sentinel.review.review", side_effect=fake_review), \
         patch("code_sentinel.git_provider.gitlab.GitLabProvider", return_value=mock_provider):
        asyncio.run(_run_audit("gitlab", "mygroup", "myproject", 42))

    mock_provider.post_comment.assert_called_once()
    call_args = mock_provider.post_comment.call_args
    # GitLab uses owner/repo as full path
    assert call_args[0][0] == "mygroup/myproject"
    assert call_args[0][1] == ""
    assert call_args[0][2] == 42


def test_run_audit_gitlab_nested_namespace():
    """_run_audit handles GitLab nested namespaces correctly."""
    from code_sentinel.server import create_app, _app_state, _run_audit

    cfg = Config(gitlab_token="gl_token")
    create_app(config=cfg)

    review_result = _make_review_result(
        reports={"pr-comment": "comment"}
    )

    mock_provider = AsyncMock()
    mock_provider.__aenter__ = AsyncMock(return_value=mock_provider)
    mock_provider.__aexit__ = AsyncMock(return_value=False)
    mock_provider.post_comment = AsyncMock(return_value=True)

    async def fake_review(pr_url, options=None):
        return review_result

    with patch("code_sentinel.server._app_state", _app_state), \
         patch("code_sentinel.review.review", side_effect=fake_review), \
         patch("code_sentinel.git_provider.gitlab.GitLabProvider", return_value=mock_provider):
        asyncio.run(_run_audit("gitlab", "org/team/backend", "service", 7))

    call_args = mock_provider.post_comment.call_args
    assert call_args[0][0] == "org/team/backend/service"
    assert call_args[0][2] == 7


# ---------------------------------------------------------------------------
# 6. Review failure — no comment posted
# ---------------------------------------------------------------------------


def test_run_audit_review_failure_no_comment():
    """_run_audit does not attempt to post comment when review() raises."""
    from code_sentinel.server import create_app, _app_state, _run_audit

    cfg = Config(github_token="gh_token")
    create_app(config=cfg)

    async def failing_review(pr_url, options=None):
        raise RuntimeError("API failure")

    mock_provider = AsyncMock()

    with patch("code_sentinel.server._app_state", _app_state), \
         patch("code_sentinel.review.review", side_effect=failing_review), \
         patch("code_sentinel.git_provider.github.GitHubProvider", return_value=mock_provider):
        # Should not raise, just log
        asyncio.run(_run_audit("github", "owner", "repo", 42))

    mock_provider.post_comment.assert_not_called()
