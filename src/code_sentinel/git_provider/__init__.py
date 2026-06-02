"""Git-hosting provider integrations."""

from code_sentinel.git_provider.base import (
    BaseGitProvider,
    FileInfo,
    FileStatus,
    PRInfo,
    ProviderError,
    RepoInfo,
)
from code_sentinel.git_provider.github import GitHubProvider
from code_sentinel.git_provider.gitlab import GitLabProvider

__all__ = [
    "BaseGitProvider",
    "FileInfo",
    "FileStatus",
    "PRInfo",
    "ProviderError",
    "RepoInfo",
    "GitHubProvider",
    "GitLabProvider",
]
