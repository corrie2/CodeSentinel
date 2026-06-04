"""Tests for the CodeSentinel webhook server: app creation, config injection,
health endpoint, and audit pipeline invocation.

Every test is self-contained, uses fast mocks, and requires no real API keys.
"""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from code_sentinel.config import Config


# ---------------------------------------------------------------------------
# 1. test_create_app_with_config
# ---------------------------------------------------------------------------


def test_create_app_with_config():
    """create_app(config=Config(provider='deepseek')) populates _app_state."""
    from code_sentinel.server import create_app, _app_state

    cfg = Config(provider="deepseek")
    app = create_app(config=cfg)

    assert _app_state["config"] is cfg
    assert _app_state["config"].provider == "deepseek"


# ---------------------------------------------------------------------------
# 2. test_run_github_audit_uses_config
# ---------------------------------------------------------------------------


def test_run_github_audit_uses_config():
    """_run_github_audit passes the provider from _app_state['config'] to
    ReviewOptions.
    """
    from code_sentinel.server import create_app, _app_state, _run_github_audit

    cfg = Config(provider="deepseek", github_token="gh_test_token")
    create_app(config=cfg)

    # Capture the ReviewOptions passed to review()
    captured = {}

    async def fake_review(pr_url, options=None):
        captured["options"] = options
        result = MagicMock()
        result.risk.level = "low"
        result.risk.score = 0
        result.llm_review.findings = []
        return result

    with patch("code_sentinel.server._app_state", _app_state), \
         patch("code_sentinel.review.review", side_effect=fake_review):
        asyncio.run(_run_github_audit("owner", "repo", 42))

    assert captured["options"].provider == "deepseek"
    assert captured["options"].github_token == "gh_test_token"


# ---------------------------------------------------------------------------
# 3. test_health_endpoint
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
