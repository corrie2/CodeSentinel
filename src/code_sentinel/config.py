"""
CodeSentinel Configuration Management.

Resolves settings from environment variables with sensible defaults.
Supports multiple LLM providers: mimo, deepseek, openai.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Canonical provider → default base_url mapping
PROVIDER_URLS: dict[str, str] = {
    "mimo": "https://token-plan-cn.xiaomimimo.com/v1",
    "deepseek": "https://api.deepseek.com",
    "openai": "https://api.openai.com/v1",
}


@dataclass
class Config:
    """Application configuration resolved from environment variables.

    Environment variable resolution rules:
        - ``api_key``  → ``{PROVIDER}_API_KEY``  (e.g. ``MIMO_API_KEY``)
        - ``base_url`` → ``{PROVIDER}_BASE_URL`` (e.g. ``MIMO_BASE_URL``)
        - ``github_token`` → ``GITHUB_TOKEN``

    Any field can also be set explicitly at construction time to override
    the automatic resolution.
    """

    # ── LLM settings ────────────────────────────────────────────────
    provider: str = "mimo"
    api_key: Optional[str] = field(default=None)
    base_url: Optional[str] = field(default=None)
    model: str = ""

    # ── GitHub settings ─────────────────────────────────────────────
    github_token: Optional[str] = field(default=None)

    # ── GitLab settings ─────────────────────────────────────────────
    gitlab_token: Optional[str] = field(default=None)

    # ── Paths ───────────────────────────────────────────────────────
    rules_path: str = "rules/"
    memory_db_path: str = "memory.db"

    # ── Runtime ─────────────────────────────────────────────────────
    max_retries: int = 3
    timeout: float = 120.0

    def __post_init__(self) -> None:
        """Auto-resolve fields left as None from environment variables."""
        # Normalise provider name
        self.provider = self.provider.lower().strip()

        # ── api_key ─────────────────────────────────────────────────
        if self.api_key is None:
            env_key = f"{self.provider.upper()}_API_KEY"
            self.api_key = os.environ.get(env_key)

        # ── base_url ────────────────────────────────────────────────
        if self.base_url is None:
            env_url = f"{self.provider.upper()}_BASE_URL"
            self.base_url = os.environ.get(
                env_url, PROVIDER_URLS.get(self.provider, "")
            )

        # ── github_token ────────────────────────────────────────────
        if self.github_token is None:
            self.github_token = os.environ.get("GITHUB_TOKEN")

        # ── gitlab_token ────────────────────────────────────────────
        if self.gitlab_token is None:
            self.gitlab_token = os.environ.get("GITLAB_TOKEN")

    # ── Convenience helpers ─────────────────────────────────────────

    @property
    def headers(self) -> dict[str, str]:
        """Default HTTP headers for LLM API calls."""
        h: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    @property
    def github_headers(self) -> dict[str, str]:
        """Default HTTP headers for GitHub API calls."""
        h: dict[str, str] = {
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        }
        if self.github_token:
            h["Authorization"] = f"token {self.github_token}"
        return h

    def resolve_path(self, path_str: str) -> Path:
        """Resolve a config path string to an absolute ``Path``."""
        p = Path(path_str).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        return p

    def validate(self) -> list[str]:
        """Return a list of validation warnings/errors (empty = OK)."""
        issues: list[str] = []
        if not self.api_key:
            issues.append(
                f"No API key found. Set {self.provider.upper()}_API_KEY env var."
            )
        if self.provider not in PROVIDER_URLS:
            issues.append(
                f"Unknown provider '{self.provider}'. "
                f"Known providers: {', '.join(PROVIDER_URLS)}"
            )
        if not self.base_url:
            issues.append("base_url could not be resolved.")
        return issues

    def __repr__(self) -> str:
        masked_key = (self.api_key[:8] + "...") if self.api_key else None
        return (
            f"Config(provider={self.provider!r}, api_key={masked_key!r}, "
            f"base_url={self.base_url!r}, model={self.model!r})"
        )
