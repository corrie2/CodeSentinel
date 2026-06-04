"""Core review pipeline for CodeSentinel.

Provides a clean async/sync API for running the full three-level
funnel pipeline without depending on argparse.

Usage::

    from code_sentinel.review import review, ReviewOptions

    result = await review(
        "https://github.com/owner/repo/pull/123",
        ReviewOptions(skip_llm=True),
    )
    print(result.risk.level, result.risk.score)

Or synchronously::

    from code_sentinel.review import review_sync
    result = review_sync("https://github.com/owner/repo/pull/123")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from code_sentinel.config import Config
from code_sentinel.result import (
    AttentionFile,
    DependencySummary,
    Finding,
    ImpactSummary,
    LLMReviewSummary,
    PipelineStep,
    PipelineTrace,
    ReviewMetadata,
    ReviewResult,
    RiskSummary,
    SupplyChainSummary,
    Vulnerability,
)

logger = logging.getLogger(__name__)


# ── Public API ──────────────────────────────────────────────────


# Regex for detecting sensitive words in project context files
_SENSITIVE_WORDS_RE = re.compile(
    r"\b(?:key|token|secret|password|credential)\b|"
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)


@dataclass
class ReviewOptions:
    """Options for :func:`review`.

    Any field left as *None* will be resolved from the config file
    and environment variables (in that priority order).
    """

    provider: str | None = None
    model: str | None = None
    api_key: str | None = None
    github_token: str | None = None
    gitlab_token: str | None = None
    rules_path: str | None = None
    repo_path: str | None = None
    skip_llm: bool = False
    timeout_seconds: int = 120
    strict: bool = False
    auditors: list[str] | None = None
    reporters: list[str] | None = None
    memory_db: str | None = None


async def review(
    pr_url: str,
    options: ReviewOptions | None = None,
) -> ReviewResult:
    """Run the full CodeSentinel review pipeline.

    Args:
        pr_url: GitHub PR URL (``https://github.com/owner/repo/pull/123``).
        options: Optional pipeline configuration.  Anything left as *None*
            is resolved from the config file and environment variables.

    Returns:
        A :class:`ReviewResult` with all collected data.

    Raises:
        RuntimeError: If ``strict=True`` and any pipeline step fails.
    """
    opts = options or ReviewOptions()
    config_dict = _load_config()
    merged = _merge_options(opts, config_dict)

    # Enforce overall timeout
    try:
        async with asyncio.timeout(merged.timeout_seconds):
            return await _run_pipeline_internal(pr_url, merged, opts)
    except TimeoutError:
        # Return partial result on timeout
        result = ReviewResult(pr_url=pr_url)
        result.pipeline.steps.append(PipelineStep(
            name="pipeline", status="failed",
            message=f"Pipeline timed out after {merged.timeout_seconds}s",
        ))
        result.metadata.duration_seconds = float(merged.timeout_seconds)
        return result


def review_sync(
    pr_url: str,
    options: ReviewOptions | None = None,
) -> ReviewResult:
    """Synchronous wrapper for :func:`review`.

    Args:
        pr_url: GitHub PR URL.
        options: Optional pipeline configuration.

    Returns:
        A :class:`ReviewResult`.
    """
    return asyncio.run(review(pr_url, options))


# ── Merged options (internal) ───────────────────────────────────


@dataclass
class _MergedOptions:
    """Resolved settings after merging options, config, and env vars."""

    provider: str = "mimo"
    model: str = ""
    api_key: str = ""
    github_token: str = ""
    gitlab_token: str = ""
    rules_path: str = ""
    repo_path: str = ""
    skip_llm: bool = False
    timeout_seconds: int = 120
    strict: bool = False
    memory_db: str = ""
    auditors: list[str] | None = None
    reporters: list[str] | None = None


# ── Config helpers ──────────────────────────────────────────────

_ENV_PREFIX = "CODESENTINEL_"
_DEFAULT_CONFIG = {
    "github_token": "",
    "gitlab_token": "",
    "mimo_api_key": "",
    "default_format": "markdown",
    "skip_llm": "false",
    "rules_file": "",
    "memory_db_path": "",
    "provider": "",
}

_CONFIG_DIR = Path.home() / ".config" / "codesentinel"
_CONFIG_FILE = _CONFIG_DIR / "config.json"

_PR_PATTERN = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)"
)
_GITLAB_MR_PATTERN = re.compile(
    r"https?://(?P<host>[^/]+)/(?P<project_path>.+?)/-/merge_requests/(?P<number>\d+)"
)


def _load_config() -> dict[str, str]:
    """Load config from file + env vars (env takes precedence)."""
    config = dict(_DEFAULT_CONFIG)

    if _CONFIG_FILE.exists():
        try:
            with open(_CONFIG_FILE) as f:
                file_config = json.load(f)
            config.update({k: str(v) for k, v in file_config.items()})
        except Exception:
            pass

    for key in _DEFAULT_CONFIG:
        prefixed_key = _ENV_PREFIX + key.upper()
        val = os.environ.get(prefixed_key)
        if val is None:
            val = os.environ.get(key.upper())
        if val is not None:
            config[key] = val

    return config


def _merge_options(opts: ReviewOptions, cfg: dict[str, str]) -> _MergedOptions:
    """Merge ReviewOptions with config-file + env values."""
    provider = opts.provider or cfg.get("provider") or "mimo"

    api_key = opts.api_key or ""
    if not api_key:
        api_key = cfg.get(f"{provider}_api_key") or cfg.get("api_key") or ""

    github_token = opts.github_token or cfg.get("github_token") or ""
    gitlab_token = opts.gitlab_token or cfg.get("gitlab_token") or ""

    skip_llm = opts.skip_llm
    if not skip_llm:
        skip_llm = cfg.get("skip_llm", "").lower() == "true"

    rules_path = opts.rules_path or cfg.get("rules_file") or ""
    repo_path = opts.repo_path or ""
    memory_db = opts.memory_db or cfg.get("memory_db_path") or ""

    return _MergedOptions(
        provider=provider,
        model=opts.model or "",
        api_key=api_key,
        github_token=github_token,
        gitlab_token=gitlab_token,
        rules_path=rules_path,
        repo_path=repo_path,
        skip_llm=skip_llm,
        timeout_seconds=opts.timeout_seconds,
        strict=opts.strict,
        memory_db=memory_db,
        auditors=opts.auditors,
        reporters=opts.reporters,
    )


def _parse_pr_url(url: str) -> tuple[str, str, int, str]:
    """Parse a PR/MR URL into (owner, repo, pr_number, provider_type).

    Supports GitHub PRs and GitLab MRs (including nested namespaces).
    For GitLab, owner=full_project_path, repo="" (use _full_project_path() helper).
    """
    url = url.strip()
    match = _PR_PATTERN.match(url)
    if match:
        return match.group("owner"), match.group("repo"), int(match.group("number")), "github"
    match = _GITLAB_MR_PATTERN.match(url)
    if match:
        # For GitLab, return full project path as owner (e.g. "group/subgroup/project")
        project_path = match.group("project_path")
        return project_path, "", int(match.group("number")), "gitlab"
    raise ValueError(
        f"Invalid PR URL: {url}\nExpected: https://github.com/owner/repo/pull/123 or https://gitlab.com/owner/repo/-/merge_requests/123"
    )


def _full_project_path(owner: str, repo: str) -> str:
    """Reconstruct the full project path for GitLab (handles nested namespaces)."""
    if repo:
        return f"{owner}/{repo}"
    return owner


def _create_provider(provider_type: str, config_obj: Any):
    """Create the appropriate git provider based on provider_type."""
    if provider_type == "gitlab":
        from code_sentinel.git_provider.gitlab import GitLabProvider
        return GitLabProvider(config_obj)
    else:
        from code_sentinel.git_provider.github import GitHubProvider
        return GitHubProvider(config_obj)


def _provider_owner_repo(owner: str, repo: str, provider_type: str) -> tuple[str, str]:
    """Return (owner, repo) args appropriate for the provider.

    For GitLab, returns (full_project_path, ""). For GitHub, returns (owner, repo).
    """
    if provider_type == "gitlab":
        return _full_project_path(owner, repo), ""
    return owner, repo


def _record(trace: PipelineTrace, name: str, status: str, message: str) -> None:
    """Append a step to the pipeline trace."""
    trace.steps.append(PipelineStep(name=name, status=status, message=message))


# ── Internal pipeline ───────────────────────────────────────────


async def _collect_pr_data(
    owner: str, repo: str, pr_number: int, config_obj: Any, provider_type: str = "github"
) -> dict[str, Any]:
    """Collect PR data from GitHub or GitLab."""
    if provider_type == "gitlab":
        from code_sentinel.git_provider.gitlab import GitLabProvider
        provider_cls = GitLabProvider
        project_path = _full_project_path(owner, repo)
        url_prefix = f"https://gitlab.com/{project_path}/-/merge_requests/{pr_number}"
    else:
        from code_sentinel.git_provider.github import GitHubProvider
        provider_cls = GitHubProvider
        url_prefix = f"https://github.com/{owner}/{repo}/pull/{pr_number}"

    result: dict[str, Any] = {
        "pr": {
            "title": f"PR #{pr_number}",
            "author": "",
            "url": url_prefix,
            "number": pr_number,
            "repo": f"{owner}/{repo}" if repo else owner,
            "base_sha": "",
            "head_sha": "",
            "base_branch": "",
            "head_branch": "",
        },
        "diff": "",
        "changed_files": [],
    }

    try:
        async with provider_cls(config_obj) as provider:
            # For GitLab, pass full project path; for GitHub, pass owner/repo separately
            if provider_type == "gitlab":
                pr_info = await provider.get_pr(project_path, "", pr_number)
            else:
                pr_info = await provider.get_pr(owner, repo, pr_number)
            result["pr"]["title"] = pr_info.title
            result["pr"]["author"] = pr_info.author
            result["pr"]["base_sha"] = pr_info.base_sha
            result["pr"]["head_sha"] = pr_info.head_sha
            result["pr"]["base_branch"] = pr_info.base_branch
            result["pr"]["head_branch"] = pr_info.head_branch

            if provider_type == "gitlab":
                result["diff"] = await provider.get_diff(project_path, "", pr_number)
                files = await provider.get_files(project_path, "", pr_number)
            else:
                result["diff"] = await provider.get_diff(owner, repo, pr_number)
                files = await provider.get_files(owner, repo, pr_number)
            result["changed_files"] = [
                {
                    "filename": f.filename,
                    "status": f.status.value,
                    "additions": f.additions,
                    "deletions": f.deletions,
                }
                for f in files
            ]

    except Exception as exc:
        logger.warning("Git provider API error: %s — continuing with partial data", exc)

    return result


async def _run_pipeline_internal(
    pr_url: str,
    merged: _MergedOptions,
    opts: ReviewOptions,
) -> ReviewResult:
    """Execute the full three-level review pipeline.

    Each step is wrapped in try/except so partial results are always returned
    (unless ``strict=True``, in which case a ``RuntimeError`` is raised on
    the first failure).
    """
    from code_sentinel.collector.diff_parser import parse_diff
    from code_sentinel.risk.scorer import RiskLevel, assess_risk

    t0 = time.monotonic()
    trace = PipelineTrace()

    result = ReviewResult(pipeline=trace, metadata=ReviewMetadata(
        provider=merged.provider,
        model=merged.model,
    ))

    # Build Config object for providers
    config_obj = Config(
        provider=merged.provider,
        api_key=merged.api_key or None,
        github_token=merged.github_token or None,
        gitlab_token=merged.gitlab_token or None,
    )

    # Parse PR URL
    try:
        owner, repo, pr_number, provider_type = _parse_pr_url(pr_url)
    except ValueError as exc:
        if merged.strict:
            raise RuntimeError(str(exc)) from exc
        _record(trace, "PR URL Parse", "failed", str(exc))
        result.metadata.duration_seconds = time.monotonic() - t0
        return result

    result.pr_url = pr_url
    logger.info("Reviewing %s/%s#%s [%s] ...", owner, repo, pr_number, provider_type)

    # ── Step 1: Collect PR data ──────────────────────────────────
    pr_data: dict[str, Any] = {}
    raw_diff = ""
    changed_files: list[dict] = []

    try:
        pr_data = await _collect_pr_data(owner, repo, pr_number, config_obj, provider_type)
        raw_diff = pr_data.get("diff", "")
        changed_files = pr_data.get("changed_files", [])

        if not raw_diff and not changed_files:
            token_hint = "GITLAB_TOKEN" if provider_type == "gitlab" else "GITHUB_TOKEN"
            msg = f"Could not fetch PR diff. Check your {token_hint}."
            _record(trace, "PR Data", "failed", msg)
            if merged.strict:
                raise RuntimeError(msg)
            result.metadata.duration_seconds = time.monotonic() - t0
            return result

        result.pr_title = pr_data.get("pr", {}).get("title", "")
        result.pr_author = pr_data.get("pr", {}).get("author", "")
        result.repo = f"{owner}/{repo}"
        result.base_branch = pr_data.get("pr", {}).get("base_branch", "")
        result.head_branch = pr_data.get("pr", {}).get("head_branch", "")
        _record(trace, "PR Data", "ok", "PR data collected")
    except RuntimeError:
        raise
    except Exception as exc:
        msg = f"Failed to collect PR data: {exc}"
        _record(trace, "PR Data", "failed", msg)
        if merged.strict:
            raise RuntimeError(msg) from exc
        result.metadata.duration_seconds = time.monotonic() - t0
        return result

    # ── Step 2: Parse diff -> ChangeSet ──────────────────────────
    changeset = None
    try:
        changeset = parse_diff(raw_diff) if raw_diff else None
        _record(trace, "Diff Parse", "ok", "Diff parsed successfully")
    except Exception as exc:
        msg = f"Diff parsing failed: {exc}"
        _record(trace, "Diff Parse", "failed", msg)
        if merged.strict:
            raise RuntimeError(msg) from exc

    # ── Step 3: Dependency scanning (3-layer pipeline) ───────────
    dep_changes: list = []
    dep_scan_mode = "skipped"
    dep_manifest_count = 0

    try:
        if changeset:
            from code_sentinel.collector.dep_scanner import (
                scan_diff_for_dep_files,
                parse_dep_changes_from_patch,
                compute_dep_diff,
                detect_ecosystem,
            )

            dep_filenames = scan_diff_for_dep_files(changeset.files)
            dep_manifest_count = len(dep_filenames) if dep_filenames else 0

            if dep_filenames:
                # Build filename -> patch map from raw diff
                file_patch_map: dict[str, str] = {}
                _current_file = None
                _current_lines: list[str] = []
                for _line in raw_diff.splitlines():
                    if _line.startswith("+++ b/"):
                        if _current_file:
                            file_patch_map[_current_file] = "\n".join(_current_lines)
                        _current_file = _line[len("+++ b/"):]
                        _current_lines = [_line]
                    elif _current_file is not None:
                        _current_lines.append(_line)
                if _current_file:
                    file_patch_map[_current_file] = "\n".join(_current_lines)

                # Layer 2: Parse patches for each dep file
                for dep_file in dep_filenames:
                    patch = file_patch_map.get(dep_file, "")
                    changes = parse_dep_changes_from_patch(dep_file, patch)
                    dep_changes.extend(changes)

                # Layer 3: Resolve low-confidence changes with full file content
                low_conf_files = set()
                for dc in dep_changes:
                    if dc.confidence == "low":
                        low_conf_files.add(dc.package)

                used_layer3 = False
                if low_conf_files:
                    base_sha = pr_data.get("pr", {}).get("base_sha", "")
                    head_sha = pr_data.get("pr", {}).get("head_sha", "")
                    if base_sha and head_sha:
                        prov_owner, prov_repo = _provider_owner_repo(owner, repo, provider_type)
                        async with _create_provider(provider_type, config_obj) as layer3_provider:
                            for dep_file in dep_filenames:
                                try:
                                    old_content = await layer3_provider.get_file_content(
                                        prov_owner, prov_repo, dep_file, ref=base_sha
                                    )
                                    new_content = await layer3_provider.get_file_content(
                                        prov_owner, prov_repo, dep_file, ref=head_sha
                                    )
                                    if old_content or new_content:
                                        layer3_changes = compute_dep_diff(
                                            dep_file, old_content, new_content
                                        )
                                        _ecosystem = detect_ecosystem(dep_file)
                                        dep_changes = [
                                            c
                                            for c in dep_changes
                                            if not (
                                                c.confidence == "low"
                                                and c.ecosystem == _ecosystem
                                            )
                                        ]
                                        dep_changes.extend(layer3_changes)
                                        used_layer3 = True
                                except Exception as exc:
                                    logger.warning(
                                        "Layer 3 dep scan failed for %s: %s",
                                        dep_file,
                                        exc,
                                    )

                dep_scan_mode = "full" if used_layer3 else "patch-only"
                dep_msg = f"{len(dep_changes)} deps found, {dep_scan_mode}"
                _record(trace, "Dependency Scan", "ok" if used_layer3 else "partial", dep_msg)
            else:
                _record(trace, "Dependency Scan", "skipped", "No dependency files in changeset")
        else:
            _record(trace, "Dependency Scan", "skipped", "No changeset available")
    except Exception as exc:
        msg = f"Dependency scan failed: {exc}"
        _record(trace, "Dependency Scan", "failed", msg)
        if merged.strict:
            raise RuntimeError(msg) from exc

    result.dependencies = DependencySummary(
        changes=[_dep_to_dict(c) for c in dep_changes],
        scan_mode=dep_scan_mode,
        manifest_count=dep_manifest_count,
    )

    # ── Step 4: Project context (.codesentinel/) ─────────────────
    # If changeset is None, we can't verify .codesentinel/ is untouched — block fallback
    codesentinel_modified = True if changeset is None else any(
        f.path.startswith(".codesentinel/") for f in changeset.files
    )

    if codesentinel_modified:
        _record(
            trace,
            "Project Context",
            "partial",
            "Review policy modified by PR, using base branch config",
        )

    project_context = ""
    _ctx_count = 0
    base_sha = pr_data.get("pr", {}).get("base_sha", "")
    project_context_loaded = False

    try:
        if base_sha and owner and repo:
            prov_owner, prov_repo = _provider_owner_repo(owner, repo, provider_type)
            async with _create_provider(provider_type, config_obj) as ctx_provider:
                for ctx_file in ("project_profile.md", "review_policy.md"):
                    try:
                        raw = await ctx_provider.get_file_content(
                            prov_owner, prov_repo, f".codesentinel/{ctx_file}", ref=base_sha
                        )
                        if raw:
                            sanitized = "\n".join(
                                line
                                for line in raw.splitlines()
                                if not _SENSITIVE_WORDS_RE.search(line)
                            )
                            project_context += f"\n\n## {ctx_file}\n\n{sanitized}"
                            _ctx_count += 1
                    except Exception as exc:
                        logger.debug("Failed to fetch .codesentinel/%s from base branch: %s", ctx_file, exc)

        # Fallback: try local file (BLOCKED if PR modifies .codesentinel/)
        if not project_context and merged.repo_path and not codesentinel_modified:
            repo_root = Path(merged.repo_path).resolve()
            for ctx_file in ("project_profile.md", "review_policy.md"):
                ctx_path = repo_root / ".codesentinel" / ctx_file
                if ctx_path.exists():
                    try:
                        raw = ctx_path.read_text(encoding="utf-8")
                        sanitized = "\n".join(
                            line
                            for line in raw.splitlines()
                            if not _SENSITIVE_WORDS_RE.search(line)
                        )
                        project_context += f"\n\n## {ctx_file}\n\n{sanitized}"
                        _ctx_count += 1
                    except Exception as exc:
                        logger.warning("Failed to read %s: %s", ctx_path, exc)

        if project_context and not codesentinel_modified:
            file_names = []
            if "project_profile.md" in project_context:
                file_names.append("project_profile.md")
            if "review_policy.md" in project_context:
                file_names.append("review_policy.md")
            status = "ok" if len(file_names) == 2 else "partial"
            project_context_loaded = len(file_names) > 0
            _record(trace, "Project Context", status, f"Loaded {' + '.join(file_names)}")
        elif not codesentinel_modified:
            _record(trace, "Project Context", "skipped", "No .codesentinel/ directory")
    except Exception as exc:
        msg = f"Project context loading failed: {exc}"
        _record(trace, "Project Context", "failed", msg)
        if merged.strict:
            raise RuntimeError(msg) from exc

    # ── Step 5: Parse CODEOWNERS ─────────────────────────────────
    codeowners = None
    if merged.repo_path:
        try:
            from code_sentinel.collector.codeowners import load_codeowners

            codeowners = load_codeowners(merged.repo_path)
            _record(trace, "CODEOWNERS", "ok", "Loaded CODEOWNERS")
        except Exception as exc:
            _record(trace, "CODEOWNERS", "skipped", f"Not available: {exc}")

    # ── Step 6: Project memory ───────────────────────────────────
    module_densities: dict[str, float] = {}
    memory = None

    if merged.memory_db:
        try:
            from code_sentinel.risk.memory import ProjectMemory

            memory = ProjectMemory(merged.memory_db)
            module_densities = memory.get_all_module_densities()
            _record(trace, "Project Memory", "ok", f"Loaded {len(module_densities)} modules")
        except Exception as exc:
            _record(trace, "Project Memory", "skipped", f"Failed: {exc}")
    else:
        _record(trace, "Project Memory", "skipped", "No memory DB configured")

    if memory and merged.repo_path:
        try:
            memory.update_from_git(merged.repo_path)
            module_densities = memory.get_all_module_densities()
        except Exception as exc:
            logger.warning("Failed to update memory from git: %s", exc)

    # ── Step 7: Risk scoring ─────────────────────────────────────
    risk_score = None
    loaded_ruleset = None
    project_rules_loaded = bool(merged.rules_path)  # True if explicitly provided

    try:
        from code_sentinel.risk.scorer import load_rules

        rules_path = merged.rules_path

        # Auto-load .codesentinel/rules.toml if not explicitly set
        if not rules_path:
            _rules_loaded = False
            if base_sha and owner and repo:
                try:
                    prov_owner, prov_repo = _provider_owner_repo(owner, repo, provider_type)
                    async with _create_provider(provider_type, config_obj) as rules_provider:
                        rules_content = await rules_provider.get_file_content(
                            prov_owner, prov_repo, ".codesentinel/rules.toml", ref=base_sha
                        )
                        if rules_content:
                            tmp = tempfile.NamedTemporaryFile(
                                mode="w", suffix=".toml", delete=False
                            )
                            tmp.write(rules_content)
                            tmp.close()
                            rules_path = tmp.name
                            _rules_loaded = True
                            _record(
                                trace, "Project Rules", "ok",
                                "Loaded .codesentinel/rules.toml from base branch",
                            )
                except Exception:
                    pass

            if not _rules_loaded and merged.repo_path and not codesentinel_modified:
                local_rules = (
                    Path(merged.repo_path).resolve() / ".codesentinel" / "rules.toml"
                )
                if local_rules.exists():
                    rules_path = str(local_rules)
                    _rules_loaded = True
                    _record(
                        trace, "Project Rules", "ok",
                        "Loaded .codesentinel/rules.toml from local repo",
                    )

        loaded_ruleset = load_rules(rules_path or None)
        risk_score = assess_risk(
            changeset=changeset,
            dep_changes=dep_changes,
            codeowners=codeowners,
            author=pr_data.get("pr", {}).get("author", ""),
            module_defect_density=module_densities if module_densities else None,
            ruleset=loaded_ruleset,
        )

        # Map rule_details to RiskContribution
        from code_sentinel.result import RiskContribution
        contributions = [
            RiskContribution(
                rule=d.get("description", ""),
                score_delta=d.get("score_delta", 0),
                reason=d.get("description", ""),
                evidence=d.get("tag", ""),
            )
            for d in getattr(risk_score, "rule_details", [])
        ]
        result.risk = RiskSummary(
            level=risk_score.level.value,
            score=risk_score.score,
            contributions=contributions,
        )
        result.metadata.project_context_loaded = project_context_loaded
        result.metadata.project_rules_loaded = project_rules_loaded or _rules_loaded

        _record(
            trace, "Risk Scoring", "ok",
            f"Risk: {risk_score.level.value.upper()} (score={risk_score.score})",
        )
    except Exception as exc:
        msg = f"Risk scoring failed: {exc}"
        _record(trace, "Risk Scoring", "failed", msg)
        if merged.strict:
            raise RuntimeError(msg) from exc
        result.risk = RiskSummary(level="low", score=0)

    # ── Level 2 & 3: Plugin-based audits ─────────────────────────
    from code_sentinel.plugins import AuditContext, AuditResult
    from code_sentinel.plugins.auditors import (
        SupplyChainAuditor,
        ImpactAuditor,
        DeepReviewAuditor,
    )

    needs_attention: list[AttentionFile] = []

    # Construct AuditContext from collected pipeline state
    ctx = AuditContext(
        pr_url=pr_url,
        pr_info=pr_data.get("pr", {}),
        changeset=changeset,
        raw_diff=raw_diff,
        base_ref=pr_data.get("pr", {}).get("base_sha", ""),
        head_ref=pr_data.get("pr", {}).get("head_sha", ""),
        repo_path=merged.repo_path,
        ruleset=loaded_ruleset,
        project_context=project_context,
        dep_changes=dep_changes,
        github_token=merged.github_token,
        gitlab_token=merged.gitlab_token,
        llm_config={"provider": merged.provider, "api_key": merged.api_key},
        risk_summary=result.risk,
        options=merged,
        step_results=trace.steps,
    )

    # Build default auditors based on risk level
    default_auditors: list = []
    if risk_score and risk_score.level in (RiskLevel.MEDIUM, RiskLevel.HIGH):
        default_auditors.append(SupplyChainAuditor())
        default_auditors.append(ImpactAuditor())
        if risk_score.level == RiskLevel.HIGH and not merged.skip_llm:
            default_auditors.append(DeepReviewAuditor())

    # Merge with user-provided auditors
    all_auditors = default_auditors + (merged.auditors or [])

    # Trace name mapping for backward compatibility with existing traces
    _AUDITOR_TRACE_NAMES = {
        "supply_chain": "OSV Audit",
        "impact": "Impact Assessment",
        "deep_review": "LLM Deep Review",
    }

    # Always record skipped traces for built-in auditors when risk is low
    if not (risk_score and risk_score.level in (RiskLevel.MEDIUM, RiskLevel.HIGH)):
        _record(trace, "OSV Audit", "skipped", "risk=low, not triggered")
        _record(trace, "Impact Assessment", "skipped", "risk=low, not triggered")
        _record(trace, "LLM Deep Review", "skipped", "risk=low, not triggered")

    # Run all auditors
    audit_results: list[AuditResult] = []
    if all_auditors:
        for auditor in all_auditors:
            trace_name = _AUDITOR_TRACE_NAMES.get(auditor.name, auditor.name)
            try:
                ar = await auditor.audit(ctx)
                audit_results.append(ar)
                _record(
                    trace, trace_name, ar.status,
                    f"{len(ar.findings)} findings, {len(ar.warnings)} warnings",
                )
            except Exception as exc:
                ar = AuditResult(name=auditor.name, status="failed", error=str(exc))
                audit_results.append(ar)
                _record(trace, trace_name, "failed", str(exc))
                if merged.strict:
                    raise RuntimeError(f"{trace_name} failed: {exc}") from exc


    # Store all audit results (built-in + custom)
    result.agent_results = audit_results

    # Map built-in auditors to ReviewResult fields
    for ar in audit_results:
        if ar.name == "supply_chain":
            result.supply_chain = _map_supply_chain(ar)
        elif ar.name == "impact":
            result.impact = _map_impact(ar)
        elif ar.name == "deep_review":
            result.llm_review = _map_llm_review(ar)

    # ── Record in memory ─────────────────────────────────────────
    if memory:
        try:
            findings_list = result.llm_review.findings if result.llm_review.findings else []
            memory.record_review(
                pr_url=pr_data.get("pr", {}).get("url", ""),
                risk_level=result.risk.level,
                findings=[f.__dict__ if hasattr(f, "__dict__") else f for f in findings_list],
            )
        except Exception as exc:
            logger.warning("Failed to record in memory: %s", exc)

    # ── File ranking for human attention ──────────────────────────
    try:
        if changeset:
            from code_sentinel.risk.file_ranker import get_top_files

            _high_defect = (
                [m for m, d in module_densities.items() if d >= 0.1]
                if module_densities else []
            )
            risk_ctx = {
                "high_defect_modules": _high_defect,
                "critical_paths": getattr(loaded_ruleset, "critical_paths", []),
            }
            ranked_files = get_top_files(changeset, n=10, risk_context=risk_ctx)
            needs_attention = [
                AttentionFile(
                    path=getattr(rf, "path", ""),
                    score=getattr(rf, "score", 0.0),
                    reasons=getattr(rf, "reasons", []),
                )
                if hasattr(rf, "path") else rf
                for rf in ranked_files
            ]
            _record(trace, "File Ranking", "ok", f"{len(needs_attention)} files ranked")
    except Exception as exc:
        _record(trace, "File Ranking", "failed", f"Failed: {exc}")
        if merged.strict:
            raise RuntimeError(f"File ranking failed: {exc}") from exc

    result.attention = needs_attention
    result.metadata.duration_seconds = time.monotonic() - t0
    result.metadata.codesentinel_modified = codesentinel_modified

    # ── Run reporters ────────────────────────────────────────────
    from code_sentinel.plugins.reporters import (
        MarkdownReporter,
        JsonReporter,
        PrCommentReporter,
    )

    default_reporters = [MarkdownReporter(), JsonReporter(), PrCommentReporter()]
    all_reporters = default_reporters + (merged.reporters or [])

    for reporter in all_reporters:
        try:
            output = reporter.render(result)
            result.reports[reporter.name] = output
            _record(trace, f"Reporter: {reporter.name}", "ok", f"rendered {len(output)} chars")
        except Exception as exc:
            result.reports[reporter.name] = f"Error: {exc}"
            _record(trace, f"Reporter: {reporter.name}", "failed", str(exc))
            logger.warning("Reporter %s failed: %s", reporter.name, exc)
            if merged.strict:
                raise RuntimeError(f"Reporter {reporter.name} failed: {exc}") from exc

    # ── Final check: strict mode ─────────────────────────────────
    if merged.strict and trace_has_failures(trace):
        failed_names = ", ".join(s.name for s in trace.steps if s.status == "failed")
        raise RuntimeError(f"Pipeline steps failed: {failed_names}")

    return result


# ── Utility helpers ─────────────────────────────────────────────


def trace_has_failures(trace: PipelineTrace) -> bool:
    """Check if any step in the trace has status 'failed'."""
    return any(s.status == "failed" for s in trace.steps)


def _dep_to_dict(dep: Any) -> dict[str, Any]:
    """Convert a DepChange to a plain dict for serialization."""
    if hasattr(dep, "as_dict"):
        return dep.as_dict()
    if hasattr(dep, "__dict__"):
        return dep.__dict__
    return {"raw": str(dep)}


# ── Plugin result mappers ───────────────────────────────────────


def _map_supply_chain(ar: "AuditResult") -> SupplyChainSummary:
    """Map a supply_chain AuditResult to a SupplyChainSummary."""
    vulns = []
    for v in ar.artifacts.get("vulnerable_deps", []):
        vulns.append(Vulnerability(
            id=v.get("vuln_id", ""),
            summary=v.get("summary", ""),
            severity=v.get("severity", ""),
            package=v.get("package", ""),
            fixed_version=v.get("fixed_version"),
        ))
    return SupplyChainSummary(
        vulnerabilities=vulns,
        total_deps=ar.artifacts.get("total_deps", 0),
        status=ar.status,
        error=ar.error,
    )


def _map_impact(ar: "AuditResult") -> ImpactSummary:
    """Map an impact AuditResult to an ImpactSummary."""
    return ImpactSummary(
        estimated_build_seconds=ar.artifacts.get("estimated_build_seconds", 0),
        affected_modules=[
            m.get("module", "") if isinstance(m, dict) else str(m)
            for m in ar.artifacts.get("affected_modules", [])
        ],
        build_risk=ar.artifacts.get("build_risk", "low"),
        test_coverage_risk=ar.artifacts.get("test_coverage_risk", "low"),
        status=ar.status,
    )


def _map_llm_review(ar: "AuditResult") -> LLMReviewSummary:
    """Map a deep_review AuditResult to an LLMReviewSummary."""
    findings = []
    for f in ar.findings:
        findings.append(Finding(
            issue_type=f.get("issue_type", ""),
            severity=f.get("severity", "info"),
            file=f.get("file", ""),
            line=f.get("line", 0),
            description=f.get("description", ""),
            evidence=f.get("evidence", ""),
            test_suggestion=f.get("test_suggestion", ""),
        ))
    return LLMReviewSummary(
        findings=findings,
        status=ar.status,
        error=ar.error,
    )
