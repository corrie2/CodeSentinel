"""
GitHub REST API v3 Provider.

Implements :class:`BaseGitProvider` using the GitHub REST API with
``httpx``.  Handles authentication, pagination, and rate-limit retries.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx

from code_sentinel.config import Config
from code_sentinel.git_provider.base import (
    BaseGitProvider,
    FileInfo,
    FileStatus,
    PRInfo,
    ProviderError,
    RepoInfo,
)

logger = logging.getLogger(__name__)

_API = "https://api.github.com"


class GitHubProvider(BaseGitProvider):
    """Concrete git provider backed by the GitHub REST API v3.

    Parameters
    ----------
    config : Config
        Application config (uses ``github_token`` and ``github_headers``).
    timeout : float
        Per-request HTTP timeout in seconds (default 30).
    max_retries : int
        Maximum retry attempts on rate-limit / server errors (default 3).
    """

    def __init__(
        self,
        config: Config,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self._config = config
        self._timeout = timeout
        self._max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None

    # ── Lifecycle ────────────────────────────────────────────────────

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazily create the shared HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=_API,
                headers=self._config.github_headers,
                timeout=httpx.Timeout(self._timeout, connect=10.0),
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Shut down the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "GitHubProvider":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # ── Abstract method implementations ──────────────────────────────

    async def get_pr(self, owner: str, repo: str, number: int) -> PRInfo:
        """Fetch pull-request metadata from GitHub."""
        data = await self._get(f"/repos/{owner}/{repo}/pulls/{number}")
        return PRInfo(
            title=data.get("title", ""),
            body=data.get("body", "") or "",
            author=data.get("user", {}).get("login", ""),
            base_branch=data.get("base", {}).get("ref", ""),
            head_branch=data.get("head", {}).get("ref", ""),
            state=data.get("state", ""),
            labels=[lbl["name"] for lbl in data.get("labels", [])],
        )

    async def get_diff(self, owner: str, repo: str, number: int) -> str:
        """Retrieve the raw unified diff for a PR.

        GitHub returns the diff when the ``Accept`` header is set to
        ``application/vnd.github.v3.diff``.
        """
        client = await self._get_client()
        headers = {**self._config.github_headers, "Accept": "application/vnd.github.v3.diff"}
        url = f"/repos/{owner}/{repo}/pulls/{number}"

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 403 and self._is_rate_limited(resp):
                    await self._wait_rate_limit(resp, attempt)
                    continue
                resp.raise_for_status()
                return resp.text
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (429, 500, 502, 503):
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise ProviderError(
                    f"Failed to fetch diff for #{number}: {exc}",
                    status_code=exc.response.status_code,
                ) from exc
            except httpx.RequestError as exc:
                if attempt < self._max_retries:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise ProviderError(f"Network error fetching diff: {exc}") from exc

        raise ProviderError(f"All {self._max_retries} attempts failed for diff of #{number}")

    async def get_files(
        self, owner: str, repo: str, number: int
    ) -> list[FileInfo]:
        """List all files in a PR with pagination support."""
        files: list[FileInfo] = []
        page = 1
        per_page = 100

        while True:
            data = await self._get(
                f"/repos/{owner}/{repo}/pulls/{number}/files",
                params={"page": page, "per_page": per_page},
            )
            if not isinstance(data, list):
                break

            for item in data:
                status_str = item.get("status", "modified")
                try:
                    status = FileStatus(status_str)
                except ValueError:
                    # GitHub can return "changed" etc.; fall back to MODIFIED
                    status = FileStatus.MODIFIED

                files.append(
                    FileInfo(
                        filename=item.get("filename", ""),
                        status=status,
                        additions=item.get("additions", 0),
                        deletions=item.get("deletions", 0),
                        patch=item.get("patch", ""),
                    )
                )

            if len(data) < per_page:
                break
            page += 1

        return files

    async def get_repo_info(self, owner: str, repo: str) -> RepoInfo:
        """Fetch repository metadata."""
        data = await self._get(f"/repos/{owner}/{repo}")
        return RepoInfo(
            default_branch=data.get("default_branch", "main"),
            language=data.get("language"),
            description=data.get("description"),
        )

    async def get_file_content(
        self, owner: str, repo: str, path: str, ref: str = "main"
    ) -> str:
        """Get raw file content from GitHub at a specific ref.

        Returns an empty string if the file does not exist (404).
        """
        client = await self._get_client()
        headers = {
            **self._config.github_headers,
            "Accept": "application/vnd.github.raw+json",
        }
        url = f"/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref}

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = await client.get(url, params=params, headers=headers)

                if resp.status_code == 404:
                    return ""

                # Rate-limit handling
                if resp.status_code == 403 and self._is_rate_limited(resp):
                    await self._wait_rate_limit(resp, attempt)
                    continue

                resp.raise_for_status()
                return resp.text

            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    return ""
                status = exc.response.status_code
                if status in (429, 500, 502, 503):
                    wait = 2 ** attempt
                    logger.warning(
                        "GitHub GET %s attempt %d/%d got %d, retrying in %ds",
                        url, attempt, self._max_retries, status, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise ProviderError(
                    f"GitHub API error ({status}) on GET {url}: {exc.response.text}",
                    status_code=status,
                ) from exc

            except httpx.RequestError as exc:
                if attempt < self._max_retries:
                    wait = 2 ** attempt
                    logger.warning(
                        "GitHub GET %s attempt %d/%d network error, retrying in %ds",
                        url, attempt, self._max_retries, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise ProviderError(
                    f"Network error on GET {url}: {exc}"
                ) from exc

        raise ProviderError(
            f"All {self._max_retries} attempts failed for GET {url}"
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

                # Rate-limit handling
                if resp.status_code == 403 and self._is_rate_limited(resp):
                    await self._wait_rate_limit(resp, attempt)
                    continue

                resp.raise_for_status()
                return resp.json()

            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in (429, 500, 502, 503):
                    wait = 2 ** attempt
                    logger.warning(
                        "GitHub GET %s attempt %d/%d got %d, retrying in %ds",
                        path, attempt, self._max_retries, status, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise ProviderError(
                    f"GitHub API error ({status}) on GET {path}: {exc.response.text}",
                    status_code=status,
                ) from exc

            except httpx.RequestError as exc:
                if attempt < self._max_retries:
                    wait = 2 ** attempt
                    logger.warning(
                        "GitHub GET %s attempt %d/%d network error, retrying in %ds",
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

    @staticmethod
    def _is_rate_limited(resp: httpx.Response) -> bool:
        """Check if a 403 is due to GitHub rate limiting."""
        return "X-RateLimit-Remaining" in resp.headers and (
            resp.headers.get("X-RateLimit-Remaining", "1") == "0"
        )

    @staticmethod
    async def _wait_rate_limit(resp: httpx.Response, attempt: int) -> None:
        """Sleep until the rate limit resets (or use exponential backoff)."""
        import time

        reset_ts = resp.headers.get("X-RateLimit-Reset")
        if reset_ts:
            try:
                wait = max(1, int(reset_ts) - int(time.time())) + 1
            except ValueError:
                wait = 2 ** attempt
        else:
            wait = 2 ** attempt

        wait = min(wait, 120)  # cap at 2 minutes
        logger.warning("Rate limited by GitHub. Waiting %ds (attempt %d)", wait, attempt)
        await asyncio.sleep(wait)
