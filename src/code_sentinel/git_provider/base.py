"""
Abstract Git Provider Interface.

Defines the data models and abstract base class that every git-hosting
backend must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Data Models ──────────────────────────────────────────────────────


class FileStatus(str, Enum):
    """Possible states for a file in a pull request."""

    ADDED = "added"
    MODIFIED = "modified"
    REMOVED = "removed"
    RENAMED = "renamed"


@dataclass(frozen=True)
class PRInfo:
    """Core metadata for a pull request."""

    title: str
    body: str
    author: str
    base_branch: str
    head_branch: str
    state: str  # "open", "closed", "merged"
    labels: list[str] = field(default_factory=list)
    base_sha: str = ""
    head_sha: str = ""


@dataclass(frozen=True)
class FileInfo:
    """Metadata for a single file changed in a PR."""

    filename: str
    status: FileStatus
    additions: int
    deletions: int
    patch: str = ""  # unified diff hunks for this file


@dataclass(frozen=True)
class RepoInfo:
    """High-level repository metadata."""

    default_branch: str
    language: Optional[str] = None
    description: Optional[str] = None


# ── Abstract Provider ────────────────────────────────────────────────


class BaseGitProvider(ABC):
    """Abstract base for git-hosting platform integrations.

    Subclasses must implement every ``@abstractmethod`` below.
    """

    @abstractmethod
    async def get_pr(
        self, owner: str, repo: str, number: int
    ) -> PRInfo:
        """Fetch metadata for a single pull request.

        Parameters
        ----------
        owner : str
            Repository owner (user or organisation).
        repo : str
            Repository name.
        number : int
            Pull-request number.

        Returns
        -------
        PRInfo
            Populated pull-request metadata.

        Raises
        ------
        ProviderError
            If the request fails or the PR does not exist.
        """
        ...

    @abstractmethod
    async def get_diff(
        self, owner: str, repo: str, number: int
    ) -> str:
        """Retrieve the full unified diff for a pull request.

        Parameters
        ----------
        owner : str
            Repository owner.
        repo : str
            Repository name.
        number : int
            Pull-request number.

        Returns
        -------
        str
            The complete diff text.
        """
        ...

    @abstractmethod
    async def get_files(
        self, owner: str, repo: str, number: int
    ) -> list[FileInfo]:
        """List all files changed in a pull request.

        Must handle pagination transparently for large PRs.

        Parameters
        ----------
        owner : str
            Repository owner.
        repo : str
            Repository name.
        number : int
            Pull-request number.

        Returns
        -------
        list[FileInfo]
            One entry per changed file with diff hunks attached.
        """
        ...

    @abstractmethod
    async def get_repo_info(
        self, owner: str, repo: str
    ) -> RepoInfo:
        """Fetch high-level repository metadata.

        Parameters
        ----------
        owner : str
            Repository owner.
        repo : str
            Repository name.

        Returns
        -------
        RepoInfo
            Default branch, primary language, description.
        """
        ...

    @abstractmethod
    async def get_file_content(
        self, owner: str, repo: str, path: str, ref: str = "main"
    ) -> str:
        """Get raw file content at a specific ref.

        Parameters
        ----------
        owner : str
            Repository owner (user or organisation).
        repo : str
            Repository name.
        path : str
            File path within the repository.
        ref : str
            Git ref (branch, tag, or commit SHA). Defaults to ``"main"``.

        Returns
        -------
        str
            The raw file content, or an empty string if the file does not exist.
        """
        ...

    @abstractmethod
    async def post_comment(
        self, owner: str, repo: str, number: int, body: str
    ) -> bool:
        """Post a comment on a pull request / merge request.

        Parameters
        ----------
        owner : str
            Repository owner (user or organisation).
        repo : str
            Repository name.
        number : int
            Pull-request / merge-request number.
        body : str
            Comment body (Markdown).

        Returns
        -------
        bool
            True if the comment was posted successfully.
        """
        raise NotImplementedError


class ProviderError(Exception):
    """Raised when a git-provider API call fails irrecoverably."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
