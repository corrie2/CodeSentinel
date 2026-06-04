"""Tests for GitLab provider integration.

Covers nested namespace URL parsing, MR diff fetching, GitLab token
handling, base/head refs extraction, and rules.toml loading.

Every test uses mocks — no real GitLab API calls.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from code_sentinel.config import Config
from code_sentinel.git_provider.gitlab import GitLabProvider
from code_sentinel.git_provider.base import PRInfo, ProviderError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(status_code: int = 200, json_data: dict | list | None = None, text: str = "") -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text
    resp.is_closed = False
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.return_value = {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp
        )
    return resp


def _mr_data(
    iid: int = 42,
    title: str = "Test MR",
    author: str = "testuser",
    source_branch: str = "feature/test",
    target_branch: str = "main",
    base_sha: str = "abc123",
    head_sha: str = "def456",
    state: str = "opened",
) -> dict:
    """Return minimal GitLab MR API response."""
    return {
        "iid": iid,
        "title": title,
        "author": {"username": author},
        "source_branch": source_branch,
        "target_branch": target_branch,
        "diff_refs": {
            "base_sha": base_sha,
            "head_sha": head_sha,
            "start_sha": "000000",
        },
        "state": state,
        "labels": [],
        "description": "Test description",
    }


def _mr_diff_data() -> list[dict]:
    """Return minimal GitLab MR changes API response."""
    return [
        {
            "old_path": "src/main.py",
            "new_path": "src/main.py",
            "diff": "@@ -1,3 +1,5 @@\n hello\n+world\n end\n",
            "new_file": False,
            "renamed_file": False,
            "deleted_file": False,
        },
        {
            "old_path": "src/utils.py",
            "new_path": "src/helpers.py",
            "diff": "@@ -1,2 +1,2 @@\n-old\n+new\n",
            "new_file": False,
            "renamed_file": True,
            "deleted_file": False,
        },
    ]


# ---------------------------------------------------------------------------
# Nested namespace URL parsing
# ---------------------------------------------------------------------------


class TestNestedNamespaceParsing:
    """Test that _parse_pr_url handles GitLab nested namespaces."""

    def test_simple_namespace(self):
        from code_sentinel.review import _parse_pr_url
        owner, repo, num, provider = _parse_pr_url(
            "https://gitlab.com/mygroup/myproject/-/merge_requests/42"
        )
        assert owner == "mygroup/myproject"
        assert repo == ""
        assert num == 42
        assert provider == "gitlab"

    def test_nested_namespace(self):
        from code_sentinel.review import _parse_pr_url
        owner, repo, num, provider = _parse_pr_url(
            "https://gitlab.com/org/team/backend/service/-/merge_requests/100"
        )
        assert owner == "org/team/backend/service"
        assert repo == ""
        assert num == 100
        assert provider == "gitlab"

    def test_self_hosted_gitlab(self):
        from code_sentinel.review import _parse_pr_url
        owner, repo, num, provider = _parse_pr_url(
            "https://gitlab.example.com/mygroup/subgroup/project/-/merge_requests/7"
        )
        assert owner == "mygroup/subgroup/project"
        assert repo == ""
        assert num == 7
        assert provider == "gitlab"

    def test_github_url_unchanged(self):
        from code_sentinel.review import _parse_pr_url
        owner, repo, num, provider = _parse_pr_url(
            "https://github.com/owner/repo/pull/123"
        )
        assert owner == "owner"
        assert repo == "repo"
        assert num == 123
        assert provider == "github"


# ---------------------------------------------------------------------------
# GitLabProvider construction
# ---------------------------------------------------------------------------


class TestGitLabProviderConstruction:
    """Test GitLabProvider accepts Config, str, or None."""

    def test_config_object(self):
        cfg = Config(gitlab_token="test_token_123")
        provider = GitLabProvider(cfg)
        assert provider._token == "test_token_123"

    def test_config_no_token_falls_back_to_env(self):
        cfg = Config()
        cfg.gitlab_token = None
        with patch.dict("os.environ", {"GITLAB_TOKEN": "env_token"}):
            provider = GitLabProvider(cfg)
            assert provider._token == "env_token"

    def test_raw_token_string(self):
        provider = GitLabProvider("raw_token")
        assert provider._token == "raw_token"

    def test_none_falls_back_to_env(self):
        with patch.dict("os.environ", {"GITLAB_TOKEN": "env_token"}):
            provider = GitLabProvider(None)
            assert provider._token == "env_token"

    def test_no_args_falls_back_to_env(self):
        with patch.dict("os.environ", {"GITLAB_TOKEN": "env_token"}):
            provider = GitLabProvider()
            assert provider._token == "env_token"

    def test_custom_base_url(self):
        provider = GitLabProvider("token", base_url="https://custom.gitlab.com/api/v4")
        assert provider._base_url == "https://custom.gitlab.com/api/v4"


# ---------------------------------------------------------------------------
# MR diff fetching
# ---------------------------------------------------------------------------


class TestGitLabMrDiff:
    """Test GitLab MR diff fetching and formatting."""

    def test_get_diff_formats_unified_diff(self):
        provider = GitLabProvider("token")
        provider._resolve_project_id = AsyncMock(return_value=123)

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.is_closed = False
        mock_client.get.return_value = _mock_response(
            json_data={"changes": _mr_diff_data()}
        )
        provider._client = mock_client

        diff = asyncio.run(provider.get_diff("mygroup/myproject", "", 42))

        assert "--- src/main.py" in diff
        assert "+++ src/main.py" in diff
        assert "+world" in diff
        assert "--- src/utils.py" in diff
        assert "+++ src/helpers.py" in diff

    def test_get_files_maps_statuses(self):
        provider = GitLabProvider("token")
        provider._resolve_project_id = AsyncMock(return_value=123)

        changes = _mr_diff_data()
        changes.append({
            "old_path": "old.py",
            "new_path": "old.py",
            "diff": "",
            "new_file": False,
            "renamed_file": False,
            "deleted_file": True,
        })
        changes.append({
            "old_path": "",
            "new_path": "new.py",
            "diff": "@@ -0,0 +1 @@\n+new\n",
            "new_file": True,
            "renamed_file": False,
            "deleted_file": False,
        })

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.get.return_value = _mock_response(json_data={"changes": changes})
        provider._client = mock_client

        files = asyncio.run(provider.get_files("mygroup/myproject", "", 42))

        assert len(files) == 4
        statuses = {f.filename: f.status.value for f in files}
        assert statuses["src/main.py"] == "modified"
        assert statuses["src/helpers.py"] == "renamed"
        assert statuses["old.py"] == "removed"
        assert statuses["new.py"] == "added"


# ---------------------------------------------------------------------------
# Base/head refs extraction
# ---------------------------------------------------------------------------


class TestGitLabBaseHeadRefs:
    """Test that base_sha/head_sha are extracted from diff_refs."""

    def test_get_pr_extracts_diff_refs(self):
        provider = GitLabProvider("token")
        provider._resolve_project_id = AsyncMock(return_value=123)

        mr = _mr_data(base_sha="base_sha_123", head_sha="head_sha_456")
        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.get.return_value = _mock_response(json_data=mr)
        provider._client = mock_client

        pr_info = asyncio.run(provider.get_pr("mygroup/myproject", "", 42))

        assert pr_info.base_sha == "base_sha_123"
        assert pr_info.head_sha == "head_sha_456"
        assert pr_info.base_branch == "main"
        assert pr_info.head_branch == "feature/test"

    def test_get_pr_handles_missing_diff_refs(self):
        provider = GitLabProvider("token")
        provider._resolve_project_id = AsyncMock(return_value=123)

        mr = _mr_data()
        del mr["diff_refs"]
        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.get.return_value = _mock_response(json_data=mr)
        provider._client = mock_client

        pr_info = asyncio.run(provider.get_pr("mygroup/myproject", "", 42))

        assert pr_info.base_sha == ""
        assert pr_info.head_sha == ""


# ---------------------------------------------------------------------------
# Rules.toml loading via get_file_content
# ---------------------------------------------------------------------------


class TestGitLabFileContent:
    """Test GitLab get_file_content for rules.toml loading."""

    def test_get_file_content_returns_raw(self):
        provider = GitLabProvider("token")
        provider._resolve_project_id = AsyncMock(return_value=123)

        rules_content = '[rules]\n[[rules]]\nname = "test"\ncondition = "true"\n'
        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.get.return_value = _mock_response(text=rules_content)
        provider._client = mock_client

        result = asyncio.run(
            provider.get_file_content("mygroup/myproject", "", ".codesentinel/rules.toml", ref="abc123")
        )

        assert result == rules_content
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        params = call_args.kwargs.get("params", {})
        assert params.get("ref") == "abc123"

    def test_get_file_content_returns_empty_on_404(self):
        provider = GitLabProvider("token")
        provider._resolve_project_id = AsyncMock(return_value=123)

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.get.return_value = _mock_response(status_code=404)
        provider._client = mock_client

        result = asyncio.run(
            provider.get_file_content("mygroup/myproject", "", ".codesentinel/rules.toml")
        )

        assert result == ""

    def test_get_file_content_encodes_path(self):
        provider = GitLabProvider("token")
        provider._resolve_project_id = AsyncMock(return_value=123)

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.get.return_value = _mock_response(text="content")
        provider._client = mock_client

        asyncio.run(
            provider.get_file_content("mygroup/myproject", "", "path/with spaces/file.toml")
        )

        call_args = mock_client.get.call_args
        url = call_args[0][0] if call_args[0] else ""
        # urllib.parse.quote(safe="") encodes "/" as %2F and spaces as %20
        assert "path%2Fwith%20spaces%2Ffile.toml" in url


# ---------------------------------------------------------------------------
# post_comment
# ---------------------------------------------------------------------------


class TestGitLabPostComment:
    """Test GitLab post_comment for MR notes."""

    def test_post_comment_success(self):
        provider = GitLabProvider("token")
        provider._resolve_project_id = AsyncMock(return_value=123)

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.post.return_value = _mock_response(status_code=201)
        provider._client = mock_client

        result = asyncio.run(
            provider.post_comment("mygroup/myproject", "", 42, "## Review\nAll good")
        )

        assert result is True
        mock_client.post.assert_called_once()

    def test_post_comment_handles_404(self):
        provider = GitLabProvider("token")
        provider._resolve_project_id = AsyncMock(return_value=123)

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.post.return_value = _mock_response(status_code=404)
        provider._client = mock_client

        result = asyncio.run(
            provider.post_comment("mygroup/myproject", "", 42, "comment")
        )

        assert result is False


# ---------------------------------------------------------------------------
# Token handling
# ---------------------------------------------------------------------------


class TestGitLabTokenHandling:
    """Test GitLab token is passed correctly in headers."""

    def test_token_in_headers(self):
        provider = GitLabProvider("my_secret_token")

        asyncio.run(provider._get_client())

        assert provider._client is not None
        headers = provider._client.headers
        assert headers.get("PRIVATE-TOKEN") == "my_secret_token"

    def test_no_token_no_header(self):
        provider = GitLabProvider("")

        asyncio.run(provider._get_client())

        assert provider._client is not None
        headers = provider._client.headers
        assert "PRIVATE-TOKEN" not in headers
