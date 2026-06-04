"""
GitLab REST API v4 Provider.

Implements :class:`BaseGitProvider` using the GitLab REST API with
``httpx``.  Handles authentication, pagination, rate-limit retries,
and project ID resolution (numeric or URL-encoded path).
"""

from __future__ import annotations

import asyncio
import logging
import os
import urllib.parse
from typing import Any, Optional

import httpx

from code_sentinel.git_provider.base import (
    BaseGitProvider,
    FileInfo,
    FileStatus,
    PRInfo,
    ProviderError,
    RepoInfo,
)

logger = logging.getLogger(__name__)

_API = "https://gitlab.com/api/v4"

# Map GitLab MR states to our canonical states
_STATE_MAP: dict[str, str] = {
    "opened": "open",
    "closed": "closed",
    "merged": "merged",
    "locked": "closed",
}

# Map GitLab file change statuses to our FileStatus enum
_STATUS_MAP: dict[str, FileStatus] = {
    "added": FileStatus.ADDED,
    "modified": FileStatus.MODIFIED,
    "deleted": FileStatus.REMOVED,
    "renamed": FileStatus.RENAMED,
    "copied": FileStatus.MODIFIED,
    "changed": FileStatus.MODIFIED,
}


class GitLabProvider(BaseGitProvider):
    """Concrete git provider backed by the GitLab REST API v4.

    Parameters
    ----------
    token : str | None
        GitLab personal access token.  Falls back to the ``GITLAB_TOKEN``
        environment variable.
    base_url : str
        GitLab API base URL (default ``https://gitlab.com/api/v4``).
    timeout : float
        Per-request HTTP timeout in seconds (default 30).
    max_retries : int
        Maximum retry attempts on rate-limit / server errors (default 3).
    """

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: str = _API,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self._token = token or os.environ.get("GITLAB_TOKEN", "")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None
        # Cache project_id lookups: "owner/repo" -> numeric id
        self._project_id_cache: dict[str, int] = {}

    # ── Lifecycle ────────────────────────────────────────────────────

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazily create the shared HTTP client."""
        if self._client is None or self._client.is_closed:
            headers: dict[str, str] = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            if self._token:
                headers["PRIVATE-TOKEN"] = self._token

            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers,
                timeout=httpx.Timeout(self._timeout, connect=10.0),
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Shut down the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "GitLabProvider":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # ── Project ID resolution ────────────────────────────────────────

    def _encode_project_path(self, owner: str, repo: str) -> str:
        """URL-encode the project path for use in API URLs.

        Supports nested namespaces (e.g. "group/subgroup/project").
        """
        path = f"{owner}/{repo}" if repo else owner
        return urllib.parse.quote(path, safe="")

    async def _resolve_project_id(self, owner: str, repo: str) -> int:
        """Resolve the numeric project ID for *owner/repo*.

        Supports nested namespaces: pass full path as owner with repo="",
        or owner="group/subgroup" and repo="project".

        Results are cached so that repeated calls for the same project
        do not trigger additional API requests.

        Raises
        ------
        ProviderError
            If the project cannot be found.
        """
        path = f"{owner}/{repo}" if repo else owner
        key = path
        if key in self._project_id_cache:
            return self._project_id_cache[key]

        # If owner is purely numeric, treat it as a project ID directly
        if owner.isdigit():
            pid = int(owner)
            self._project_id_cache[key] = pid
            return pid

        encoded = self._encode_project_path(owner, repo)
        data = await self._get(f"/projects/{encoded}")
        pid = data.get("id")
        if not pid:
            raise ProviderError(
                f"Could not resolve project ID for {path}",
                status_code=404,
            )
        self._project_id_cache[key] = int(pid)
        return int(pid)

    # ── Abstract method implementations ──────────────────────────────

    async def get_pr(self, owner: str, repo: str, number: int) -> PRInfo:
        """Fetch merge-request metadata from GitLab.

        Parameters
        ----------
        owner : str
            GitLab namespace (user or group).
        repo : str
            Repository (project) name.
        number : int
            Merge-request IID (internal to the project).

        Returns
        -------
        PRInfo
            Populated merge-request metadata mapped to our PRInfo model.
        """
        project_id = await self._resolve_project_id(owner, repo)
        data = await self._get(f"/projects/{project_id}/merge_requests/{number}")

        state = _STATE_MAP.get(data.get("state", ""), data.get("state", ""))

        return PRInfo(
            title=data.get("title", ""),
            body=data.get("description", "") or "",
            author=data.get("author", {}).get("username", ""),
            base_branch=data.get("target_branch", ""),
            head_branch=data.get("source_branch", ""),
            state=state,
            labels=data.get("labels", []),
        )

    async def get_diff(self, owner: str, repo: str, number: int) -> str:
        """Retrieve the full unified diff for a merge request.

        GitLab's ``/changes`` endpoint returns a JSON payload with per-file
        diffs.  We reconstruct a unified diff text from that payload.

        Parameters
        ----------
        owner : str
            GitLab namespace.
        repo : str
            Repository name.
        number : int
            Merge-request IID.

        Returns
        -------
        str
            Reconstructed unified diff text.
        """
        project_id = await self._resolve_project_id(owner, repo)
        data = await self._get(
            f"/projects/{project_id}/merge_requests/{number}/changes"
        )

        changes = data.get("changes", [])
        if not changes:
            return ""

        diff_parts: list[str] = []
        for change in changes:
            old_path = change.get("old_path", "")
            new_path = change.get("new_path", "")
            diff_text = change.get("diff", "")

            header = f"--- {old_path}\n+++ {new_path}"
            diff_parts.append(f"{header}\n{diff_text}")

        return "\n".join(diff_parts)

    async def get_files(
        self, owner: str, repo: str, number: int
    ) -> list[FileInfo]:
        """List all files changed in a merge request.

        Parameters
        ----------
        owner : str
            GitLab namespace.
        repo : str
            Repository name.
        number : int
            Merge-request IID.

        Returns
        -------
        list[FileInfo]
            One entry per changed file with diff hunks attached.
        """
        project_id = await self._resolve_project_id(owner, repo)
        data = await self._get(
            f"/projects/{project_id}/merge_requests/{number}/changes"
        )

        changes = data.get("changes", [])
        files: list[FileInfo] = []

        for change in changes:
            new_path = change.get("new_path", "")
            old_path = change.get("old_path", "")
            diff_text = change.get("diff", "")

            # Determine status
            new_file = change.get("new_file", False)
            deleted_file = change.get("deleted_file", False)
            renamed_file = change.get("renamed_file", False)

            if new_file:
                status = FileStatus.ADDED
            elif deleted_file:
                status = FileStatus.REMOVED
            elif renamed_file:
                status = FileStatus.RENAMED
            else:
                status = FileStatus.MODIFIED

            # Parse additions/deletions from diff text
            additions, deletions = _count_diff_lines(diff_text)

            filename = new_path if not deleted_file else old_path

            files.append(
                FileInfo(
                    filename=filename,
                    status=status,
                    additions=additions,
                    deletions=deletions,
                    patch=diff_text,
                )
            )

        return files

    async def get_repo_info(self, owner: str, repo: str) -> RepoInfo:
        """Fetch repository metadata from GitLab.

        Parameters
        ----------
        owner : str
            GitLab namespace.
        repo : str
            Repository name.

        Returns
        -------
        RepoInfo
            Default branch, primary language, description.
        """
        project_id = await self._resolve_project_id(owner, repo)
        data = await self._get(f"/projects/{project_id}")

        # GitLab returns the default branch at top level
        default_branch = data.get("default_branch", "main")

        # Language info may be under 'languages' (a dict of lang -> percentage)
        languages = data.get("languages", {})
        language: Optional[str] = None
        if languages:
            # Pick the language with the highest percentage
            language = max(languages, key=languages.get)  # type: ignore[arg-type]

        return RepoInfo(
            default_branch=default_branch or "main",
            language=language,
            description=data.get("description"),
        )

    # ── Internal HTTP helpers ────────────────────────────────────────

    async def _get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """GET request with rate-limit aware retry.

        Returns the parsed JSON body.

        Raises
        ------
        ProviderError
            On non-retryable HTTP errors or after exhausting retries.
        """
        client = await self._get_client()

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = await client.get(path, params=params)

                # Rate-limit handling (GitLab uses 429)
                if resp.status_code == 429:
                    await self._wait_rate_limit(resp, attempt)
                    continue

                resp.raise_for_status()
                return resp.json()

            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in (429, 500, 502, 503):
                    wait = 2 ** attempt
                    logger.warning(
                        "GitLab GET %s attempt %d/%d got %d, retrying in %ds",
                        path, attempt, self._max_retries, status, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise ProviderError(
                    f"GitLab API error ({status}) on GET {path}: {exc.response.text}",
                    status_code=status,
                ) from exc

            except httpx.RequestError as exc:
                if attempt < self._max_retries:
                    wait = 2 ** attempt
                    logger.warning(
                        "GitLab GET %s attempt %d/%d network error, retrying in %ds",
                        path, attempt, self._max_retries, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise ProviderError(
                    f"Network error on GET {path}: {exc}"
                ) from exc

        raise ProviderError(
            f"All {self._max_retries} attempts failed for GET {path}"
        )

    async def _get_paginated(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> list[Any]:
        """GET request with pagination support using the ``X-Next-Page``
        header that GitLab returns.

        Returns a flat list of all items across pages.
        """
        client = await self._get_client()
        all_items: list[Any] = []
        current_params = dict(params or {})

        while True:
            for attempt in range(1, self._max_retries + 1):
                try:
                    resp = await client.get(path, params=current_params)

                    if resp.status_code == 429:
                        await self._wait_rate_limit(resp, attempt)
                        continue

                    resp.raise_for_status()
                    break

                except httpx.HTTPStatusError as exc:
                    status = exc.response.status_code
                    if status in (429, 500, 502, 503) and attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    raise ProviderError(
                        f"GitLab API error ({status}) on GET {path}",
                        status_code=status,
                    ) from exc
                except httpx.RequestError as exc:
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    raise ProviderError(
                        f"Network error on GET {path}: {exc}"
                    ) from exc
            else:
                raise ProviderError(
                    f"All {self._max_retries} attempts failed for GET {path}"
                )

            page_data = resp.json()
            if isinstance(page_data, list):
                all_items.extend(page_data)
            else:
                all_items.append(page_data)

            # Check for next page
            next_page = resp.headers.get("X-Next-Page", "")
            if not next_page:
                break

            current_params["page"] = next_page

        return all_items

    @staticmethod
    async def _wait_rate_limit(resp: httpx.Response, attempt: int) -> None:
        """Sleep until the rate limit resets (or use exponential backoff)."""
        # GitLab uses RateLimit-Reset or Retry-After headers
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                wait = max(1, int(retry_after))
            except ValueError:
                wait = 2 ** attempt
        else:
            reset_ts = resp.headers.get("RateLimit-Reset")
            if reset_ts:
                import time
                try:
                    wait = max(1, int(reset_ts) - int(time.time())) + 1
                except ValueError:
                    wait = 2 ** attempt
            else:
                wait = 2 ** attempt

        wait = min(wait, 120)  # cap at 2 minutes
        logger.warning("Rate limited by GitLab. Waiting %ds (attempt %d)", wait, attempt)
        await asyncio.sleep(wait)


def _count_diff_lines(diff_text: str) -> tuple[int, int]:
    """Count addition and deletion lines from a unified diff hunk.

    Parameters
    ----------
    diff_text : str
        The raw diff text for a single file.

    Returns
    -------
    tuple[int, int]
        (additions, deletions)
    """
    additions = 0
    deletions = 0
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            additions += 1
        elif line.startswith("-") and not line.startswith("---"):
            deletions += 1
    return additions, deletions
