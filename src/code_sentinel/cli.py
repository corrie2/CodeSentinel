"""CLI entry point for CodeSentinel.

Wires the full three-level funnel pipeline:
  Level 1: Risk scoring (always)
  Level 2: Supply chain + impact assessment (medium/high risk)
  Level 3: LLM deep review (high risk only)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from code_sentinel.reporter.formatter import (
    PRMetadata,
    ReportContext,
    ReviewResults,
    build_report_context,
    render_json,
    render_markdown,
    render_pr_comment,
)

logger = logging.getLogger(__name__)


@dataclass
class StepResult:
    """Track status of a pipeline step."""

    name: str           # "Dependency Scan", "OSV Audit", etc.
    status: str         # "ok", "partial", "skipped", "failed"
    message: str        # Human-readable summary
    details: dict = field(default_factory=dict)

    @property
    def emoji(self) -> str:
        return {"ok": "✅", "partial": "⚠️", "skipped": "⏭️", "failed": "❌"}.get(
            self.status, "❓"
        )


# ── Config ───────────────────────────────────────────────────────

_ENV_PREFIX = "CODESENTINEL_"
_DEFAULT_CONFIG = {
    "github_token": "",
    "mimo_api_key": "",
    "default_format": "markdown",
    "skip_llm": "false",
    "rules_file": "",
}

_CONFIG_DIR = Path.home() / ".config" / "codesentinel"
_CONFIG_FILE = _CONFIG_DIR / "config.json"


def _load_config() -> dict[str, str]:
    """Load config from file + env vars (env takes precedence)."""
    config = dict(_DEFAULT_CONFIG)

    # Load from file
    if _CONFIG_FILE.exists():
        try:
            with open(_CONFIG_FILE) as f:
                file_config = json.load(f)
            config.update({k: str(v) for k, v in file_config.items()})
        except Exception:
            pass

    # Override with env vars (try prefixed first, then non-prefixed)
    for key in _DEFAULT_CONFIG:
        prefixed_key = _ENV_PREFIX + key.upper()
        val = os.environ.get(prefixed_key)
        if val is None:
            # Fallback: try non-prefixed (e.g. GITHUB_TOKEN, MIMO_API_KEY)
            val = os.environ.get(key.upper())
        if val is not None:
            config[key] = val

    return config


def _save_config(config: dict[str, str]) -> None:
    """Save config to file."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2, sort_keys=True)
    print(f"Config saved to {_CONFIG_FILE}")


# ── PR URL Parsing ───────────────────────────────────────────────

_PR_PATTERN = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)"
)


def parse_pr_url(url: str) -> tuple[str, str, int]:
    """Parse a GitHub PR URL into (owner, repo, pr_number)."""
    match = _PR_PATTERN.match(url.strip())
    if not match:
        raise ValueError(
            f"Invalid PR URL: {url}\nExpected format: https://github.com/owner/repo/pull/123"
        )
    return match.group("owner"), match.group("repo"), int(match.group("number"))


# ── Pipeline ─────────────────────────────────────────────────────


async def _collect_pr_data(
    owner: str, repo: str, pr_number: int, config_obj: Any
) -> dict[str, Any]:
    """Collect PR data from GitHub using the GitHubProvider.

    Args:
        owner: Repository owner.
        repo: Repository name.
        pr_number: PR number.
        config_obj: A :class:`Config` instance.

    Returns:
        Dict with ``pr`` metadata, ``diff``, ``changed_files`` (from GitHub API),
        and ``codeowners_content``.
    """
    from code_sentinel.git_provider.github import GitHubProvider

    result: dict[str, Any] = {
        "pr": {
            "title": f"PR #{pr_number}",
            "author": "",
            "url": f"https://github.com/{owner}/{repo}/pull/{pr_number}",
            "number": pr_number,
            "repo": f"{owner}/{repo}",
            "base_sha": "",
            "head_sha": "",
        },
        "diff": "",
        "changed_files": [],
    }

    try:
        async with GitHubProvider(config_obj) as gh:
            # PR metadata
            pr_info = await gh.get_pr(owner, repo, pr_number)
            result["pr"]["title"] = pr_info.title
            result["pr"]["author"] = pr_info.author

            # Extract actual commit SHAs for get_file_content (Layer 3 dep scan)
            try:
                raw_pr = await gh._get(f"/repos/{owner}/{repo}/pulls/{pr_number}")
                result["pr"]["base_sha"] = raw_pr.get("base", {}).get("sha", "")
                result["pr"]["head_sha"] = raw_pr.get("head", {}).get("sha", "")
            except Exception:
                result["pr"]["base_sha"] = ""
                result["pr"]["head_sha"] = ""

            # Diff
            result["diff"] = await gh.get_diff(owner, repo, pr_number)

            # Files (for impact assessment)
            files = await gh.get_files(owner, repo, pr_number)
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
        logger.warning("GitHub API error: %s — continuing with partial data", exc)

    return result


async def _run_pipeline(
    args: argparse.Namespace,
    config_dict: dict[str, str],
) -> int:
    """Execute the full three-level review pipeline.

    Level 1: Parse diff -> Risk score
    Level 2: Supply chain + Impact (medium/high)
    Level 3: LLM deep review (high only)

    Args:
        args: Parsed CLI arguments.
        config_dict: The loaded config dictionary.

    Returns:
        Exit code (0 = success).
    """
    from code_sentinel.config import Config
    from code_sentinel.collector.diff_parser import parse_diff
    from code_sentinel.risk.scorer import RiskLevel, assess_risk

    # Build Config object for providers
    _provider = args.provider or config_dict.get("provider", "mimo")
    config_obj = Config(
        provider=_provider,
        api_key=config_dict.get(f"{_provider}_api_key") or config_dict.get("api_key"),
        github_token=config_dict.get("github_token"),
    )

    # Pipeline step tracking
    steps: list[StepResult] = []

    # Parse PR URL
    try:
        owner, repo, pr_number = parse_pr_url(args.pr_url)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Reviewing {owner}/{repo}#{pr_number}...", file=sys.stderr)

    # ── Step 1: Collect PR data ──────────────────────────────────
    print("  [1/6] Collecting PR data from GitHub...", file=sys.stderr)
    pr_data = await _collect_pr_data(owner, repo, pr_number, config_obj)
    raw_diff = pr_data.get("diff", "")
    changed_files = pr_data.get("changed_files", [])

    if not raw_diff and not changed_files:
        steps.append(StepResult("PR Data", "failed", "Could not fetch PR diff"))
        print("Error: Could not fetch PR diff. Check your GITHUB_TOKEN.", file=sys.stderr)
        return 1
    steps.append(StepResult("PR Data", "ok", "PR data collected"))

    # ── Step 2: Parse diff -> ChangeSet ──────────────────────────
    print("  [2/6] Parsing diff...", file=sys.stderr)
    changeset = parse_diff(raw_diff) if raw_diff else None

    # ── Step 3: Dependency scanning (3-layer pipeline) ───────────
    print("  [3/6] Scanning dependency changes...", file=sys.stderr)
    dep_changes: list = []
    if changeset:
        from code_sentinel.collector.dep_scanner import (
            scan_diff_for_dep_files,
            parse_dep_changes_from_patch,
            compute_dep_diff,
        )

        dep_filenames = scan_diff_for_dep_files(changeset.files)
        if dep_filenames:
            print(f"         Detected {len(dep_filenames)} dependency manifest(s): {', '.join(dep_filenames)}", file=sys.stderr)

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
            low_conf_files = {
                dep_file for dep_file in dep_filenames
                if any(c.confidence == "low" for c in dep_changes
                       if dep_file.rsplit("/", 1)[-1] in dep_file)
            }
            # More precise: check which dep_files produced low-confidence changes
            _dep_basenames = {f.rsplit("/", 1)[-1] for f in dep_filenames}
            low_conf_files = set()
            for dc in dep_changes:
                if dc.confidence == "low":
                    low_conf_files.add(dc.package)

            if low_conf_files:
                base_sha = pr_data.get("pr", {}).get("base_sha", "")
                head_sha = pr_data.get("pr", {}).get("head_sha", "")
                if base_sha and head_sha:
                    from code_sentinel.git_provider.github import GitHubProvider
                    async with GitHubProvider(config_obj) as gh_layer3:
                        for dep_file in dep_filenames:
                            try:
                                old_content = await gh_layer3.get_file_content(owner, repo, dep_file, ref=base_sha)
                                new_content = await gh_layer3.get_file_content(owner, repo, dep_file, ref=head_sha)
                                if old_content or new_content:
                                    layer3_changes = compute_dep_diff(dep_file, old_content, new_content)
                                    # Replace low-confidence entries for this file's ecosystem
                                    dep_changes = [c for c in dep_changes if c.confidence != "low"]
                                    dep_changes.extend(layer3_changes)
                            except Exception as exc:
                                logger.warning("Layer 3 dep scan failed for %s: %s", dep_file, exc)

            print(f"         Found {len(dep_changes)} dependency change(s)", file=sys.stderr)
            # Determine if Layer 3 (full file content) was used
            used_layer3 = bool(low_conf_files and base_sha and head_sha)
            dep_status = "ok" if used_layer3 else "partial"
            dep_msg = f"{len(dep_changes)} deps found, {'full scan' if used_layer3 else 'patch-only'}"
            steps.append(StepResult("Dependency Scan", dep_status, dep_msg))
        else:
            print("         No dependency files in changeset", file=sys.stderr)
            steps.append(StepResult("Dependency Scan", "skipped", "No dependency files in changeset"))
    else:
        steps.append(StepResult("Dependency Scan", "skipped", "No changeset available"))

    # ── Step 4: Project context (project_profile.md + review_policy.md) ──
    # SECURITY: Always load from BASE branch to prevent a malicious PR from
    # injecting instructions via .codesentinel/ config files.
    _SENSITIVE_WORDS = re.compile(
        r"\b(?:key|token|secret|password|credential)\b|"
        r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
        r"private[_-]?key|client[_-]?secret)",
        re.IGNORECASE,
    )

    # Check if PR modifies .codesentinel/
    codesentinel_modified = any(
        f.path.startswith(".codesentinel/") for f in (changeset.files if changeset else [])
    )
    if codesentinel_modified:
        steps.append(StepResult(
            "Project Context", "partial",
            "审查策略被本次PR修改，使用base branch配置",
        ))

    # Load from base branch via GitHub API
    project_context = ""
    _ctx_count = 0
    base_sha = pr_data.get("pr", {}).get("base_sha", "")
    if base_sha and owner and repo:
        from code_sentinel.git_provider.github import GitHubProvider
        async with GitHubProvider(config_obj) as gh_ctx:
            for ctx_file in ("project_profile.md", "review_policy.md"):
                try:
                    raw = await gh_ctx.get_file_content(
                        owner, repo, f".codesentinel/{ctx_file}", ref=base_sha
                    )
                    if raw:
                        sanitized = "\n".join(
                            line for line in raw.splitlines()
                            if not _SENSITIVE_WORDS.search(line)
                        )
                        project_context += f"\n\n## {ctx_file}\n\n{sanitized}"
                        _ctx_count += 1
                except Exception:
                    pass

    # Fallback: try local file if API failed or base_sha unavailable
    if not project_context and args.repo_path:
        repo_root = Path(args.repo_path).resolve()
        for ctx_file in ("project_profile.md", "review_policy.md"):
            ctx_path = repo_root / ".codesentinel" / ctx_file
            if ctx_path.exists():
                try:
                    raw = ctx_path.read_text(encoding="utf-8")
                    sanitized = "\n".join(
                        line for line in raw.splitlines()
                        if not _SENSITIVE_WORDS.search(line)
                    )
                    project_context += f"\n\n## {ctx_file}\n\n{sanitized}"
                    _ctx_count += 1
                except Exception as exc:
                    logger.warning("Failed to read %s: %s", ctx_path, exc)

    if project_context:
        print(f"         Loaded project context from .codesentinel/", file=sys.stderr)

    # Only add step if we didn't already add one for codesentinel_modified
    if not codesentinel_modified:
        if _ctx_count > 0:
            _file_names = []
            if "project_profile.md" in project_context:
                _file_names.append("project_profile.md")
            if "review_policy.md" in project_context:
                _file_names.append("review_policy.md")
            status = "ok" if len(_file_names) == 2 else "partial"
            steps.append(StepResult("Project Context", status,
                                    f"Loaded {' + '.join(_file_names)}"))
        else:
            steps.append(StepResult("Project Context", "skipped", "No .codesentinel/ directory"))

    # ── Step 5: Parse CODEOWNERS ─────────────────────────────────
    codeowners = None
    if args.repo_path:
        from code_sentinel.collector.codeowners import load_codeowners
        codeowners = load_codeowners(args.repo_path)

    # ── Step 6: Project memory ───────────────────────────────────
    module_densities: Dict[str, float] = {}
    memory = None
    memory_db_path = args.memory_db or config_dict.get("memory_db_path", "")

    if memory_db_path:
        try:
            from code_sentinel.risk.memory import ProjectMemory
            memory = ProjectMemory(memory_db_path)
            module_densities = memory.get_all_module_densities()
            print(f"  [3/6] Loaded project memory ({len(module_densities)} modules)", file=sys.stderr)
        except Exception as exc:
            logger.warning("Failed to load project memory: %s", exc)
    else:
        print("  [3/6] No project memory (use --memory-db to enable)", file=sys.stderr)

    # If repo_path provided, update memory from git history
    if memory and args.repo_path:
        try:
            memory.update_from_git(args.repo_path)
            module_densities = memory.get_all_module_densities()
        except Exception as exc:
            logger.warning("Failed to update memory from git: %s", exc)

    # ── Step 7: Risk scoring ─────────────────────────────────────
    print("  [4/6] Computing risk score...", file=sys.stderr)
    rules_path = args.rules or config_dict.get("rules_file") or None

    # Auto-load .codesentinel/rules.toml from base branch if not explicitly set
    if not rules_path and base_sha and owner and repo:
        try:
            from code_sentinel.git_provider.github import GitHubProvider
            async with GitHubProvider(config_obj) as gh_rules:
                rules_content = await gh_rules.get_file_content(
                    owner, repo, ".codesentinel/rules.toml", ref=base_sha
                )
                if rules_content:
                    # Write to temp file for load_rules to read
                    import tempfile
                    tmp = tempfile.NamedTemporaryFile(
                        mode="w", suffix=".toml", delete=False
                    )
                    tmp.write(rules_content)
                    tmp.close()
                    rules_path = tmp.name
                    print(f"         Loaded .codesentinel/rules.toml from base branch", file=sys.stderr)
                    steps.append(StepResult(
                        name="Project Rules",
                        status="ok",
                        message="Loaded .codesentinel/rules.toml from base branch",
                    ))
        except Exception:
            pass  # No .codesentinel/rules.toml in repo, use defaults

    # Load rules once — used for risk scoring AND critical_paths for file ranker
    from code_sentinel.risk.scorer import load_rules
    loaded_ruleset = load_rules(rules_path)
    risk_score = assess_risk(
        changeset=changeset,
        dep_changes=dep_changes,
        codeowners=codeowners,
        author=pr_data.get("pr", {}).get("author", ""),
        module_defect_density=module_densities if module_densities else None,
        ruleset=loaded_ruleset,
    )

    print(
        f"         Risk: {risk_score.level.value.upper()} (score={risk_score.score})",
        file=sys.stderr,
    )
    steps.append(StepResult(
        "Risk Scoring", "ok",
        f"Risk: {risk_score.level.value.upper()} (score={risk_score.score})"
    ))

    # ── Level 2 & 3: Conditional audits ──────────────────────────
    supply_chain_report = None
    impact_report = None
    deep_review_findings = None

    if risk_score.level in (RiskLevel.MEDIUM, RiskLevel.HIGH):
        # Level 2: Supply chain + Impact
        print("  [5/6] Running supply chain + impact assessment...", file=sys.stderr)
        from code_sentinel.auditor.supply_chain import run_supply_chain_audit
        from code_sentinel.auditor.impact import assess_impact

        # Build PackageQuery objects from dep_changes for supply chain audit
        supply_chain_packages = None
        if dep_changes:
            from code_sentinel.auditor.supply_chain import (
                PackageQuery as SC_PackageQuery,
            )
            _OSV_ECOSYSTEM_MAP = {
                "npm": "npm", "pypi": "PyPI", "go": "Go",
                "cargo": "crates.io", "maven": "Maven", "gradle": "Maven",
            }
            supply_chain_packages = [
                SC_PackageQuery(
                    name=c.package,
                    version=c.new_spec or c.old_spec or "",
                    ecosystem=_OSV_ECOSYSTEM_MAP.get(c.ecosystem, c.ecosystem),
                )
                for c in dep_changes
                if c.change_type in ("added", "version_changed") and (c.new_spec or c.old_spec)
            ]
        supply_chain_report = await run_supply_chain_audit(
            changed_files=changed_files,
            packages=supply_chain_packages or None,
        )
        # Track supply chain audit result
        _vuln_count = len(getattr(supply_chain_report, 'vulnerable_deps', []))
        _query_failed = len(getattr(supply_chain_report, 'errors', []))
        if _query_failed > 0:
            steps.append(StepResult("OSV Audit", "partial",
                                    f"OSV query failed for {_query_failed} packages"))
        else:
            steps.append(StepResult("OSV Audit", "ok",
                                    f"{_vuln_count} vulnerabilities found"))

        impact_report = assess_impact(changed_files)
        steps.append(StepResult("Impact Assessment", "ok",
                                f"Build impact: +{getattr(impact_report, 'estimated_build_seconds', 0)}s"))

        if risk_score.level == RiskLevel.HIGH:
            # Level 3: Deep LLM review
            skip_llm = args.skip_llm or config_dict.get("skip_llm", "").lower() == "true"
            if not skip_llm:
                print("  [6/6] Running LLM deep review (high risk)...", file=sys.stderr)
                from code_sentinel.auditor.deep_review import run_deep_review

                try:
                    findings = await run_deep_review(
                        changeset=changeset,
                        risk_score=risk_score,
                        config=config_obj,
                        raw_diff=raw_diff,
                        module_densities=module_densities or None,
                        project_context=project_context or None,
                        critical_paths=getattr(loaded_ruleset, 'critical_paths', None),
                    )
                    if findings:
                        deep_review_findings = ReviewResults(
                            findings=[f.as_dict() for f in findings],
                            summary=f"Deep review found {len(findings)} issue(s).",
                            suggestions=[
                                f.test_suggestion
                                for f in findings
                                if f.test_suggestion
                            ],
                        )
                        steps.append(StepResult("LLM Deep Review", "ok",
                                                f"{len(findings)} findings"))
                    else:
                        steps.append(StepResult("LLM Deep Review", "ok", "0 findings"))
                except Exception as exc:
                    logger.error("Deep review failed: %s", exc)
                    print(f"  [6/6] Deep review failed: {exc}", file=sys.stderr)
                    if "timeout" in str(exc).lower():
                        steps.append(StepResult("LLM Deep Review", "failed", "LLM timeout"))
                    else:
                        steps.append(StepResult("LLM Deep Review", "failed",
                                                f"LLM error: {exc}"))
            else:
                print("  [6/6] Skipping deep review (--skip-llm)", file=sys.stderr)
                steps.append(StepResult("LLM Deep Review", "skipped", "--skip-llm"))
        else:
            print("  [6/6] Skipping deep review (medium risk)", file=sys.stderr)
            steps.append(StepResult("LLM Deep Review", "skipped", "risk=medium, not triggered"))
    else:
        print("  [5/6] Skipping audits (low risk)", file=sys.stderr)
        print("  [6/6] Skipping deep review (low risk)", file=sys.stderr)
        steps.append(StepResult("OSV Audit", "skipped", "risk=low, not triggered"))
        steps.append(StepResult("Impact Assessment", "skipped", "risk=low, not triggered"))
        steps.append(StepResult("LLM Deep Review", "skipped", "risk=low, not triggered"))

    # ── Record in memory ─────────────────────────────────────────
    if memory:
        findings_list = (
            deep_review_findings.findings if deep_review_findings else []
        )
        memory.record_review(
            pr_url=pr_data.get("pr", {}).get("url", ""),
            risk_level=risk_score.level.value,
            findings=findings_list,
        )

    # ── File ranking for human attention ──────────────────────────
    needs_attention: list = []
    if changeset:
        from code_sentinel.risk.file_ranker import get_top_files
        _high_defect = (
            [m for m, d in module_densities.items() if d >= 0.1]
            if module_densities else []
        )
        risk_ctx = {
            "high_defect_modules": _high_defect,
            "critical_paths": loaded_ruleset.critical_paths,
        }
        needs_attention = get_top_files(changeset, n=10, risk_context=risk_ctx)

    # ── Build report ─────────────────────────────────────────────
    _pr_valid_keys = set(PRMetadata.__dataclass_fields__)
    pr_meta = PRMetadata(**{k: v for k, v in pr_data.get("pr", {}).items() if k in _pr_valid_keys})
    ctx = build_report_context(
        pr=pr_meta,
        risk_score=risk_score.score,
        risk_level=risk_score.level.value,
        risk_details={
            "triggered_rules": risk_score.triggered_rules,
            "tags": risk_score.tags,
        },
        risk_breakdown=risk_score.breakdown_lines,
        supply_chain_report=supply_chain_report,
        impact_report=impact_report,
        deep_review=deep_review_findings,
        needs_attention=needs_attention,
        pipeline_steps=steps,
        codesentinel_modified=codesentinel_modified,
    )

    # ── Render output ────────────────────────────────────────────
    fmt = args.format or config_dict.get("default_format", "markdown")
    if fmt == "json":
        output_text = render_json(ctx)
    elif fmt == "pr-comment":
        output_text = render_pr_comment(ctx)
    else:
        output_text = render_markdown(ctx)

    # Write to file or stdout
    output_path = getattr(args, "output", None)
    if output_path:
        Path(output_path).write_text(output_text, encoding="utf-8")
        print(f"Report written to {output_path}", file=sys.stderr)
    else:
        print(output_text)

    return 0


# ── Commands ─────────────────────────────────────────────────────


async def cmd_review(args: argparse.Namespace) -> int:
    """Run the full review pipeline."""
    config_dict = _load_config()
    return await _run_pipeline(args, config_dict)


def cmd_config_show(args: argparse.Namespace) -> int:
    """Show current config."""
    config = _load_config()
    print(f"Config file: {_CONFIG_FILE}")
    print()
    for key, val in sorted(config.items()):
        env_key = _ENV_PREFIX + key.upper()
        env_val = os.environ.get(env_key)
        source = "env" if env_val else "file" if _CONFIG_FILE.exists() else "default"
        # Mask sensitive values
        display_val = val
        if "key" in key.lower() or "token" in key.lower() or "secret" in key.lower():
            if val:
                display_val = val[:4] + "..." + val[-4:] if len(val) > 8 else "****"
            else:
                display_val = "(not set)"
        print(f"  {key} = {display_val}  [{source}]")
    return 0


def cmd_config_set(args: argparse.Namespace) -> int:
    """Set a config value."""
    config = _load_config()
    key = args.key.lower().replace("-", "_")

    if key not in _DEFAULT_CONFIG:
        print(f"Error: Unknown config key '{key}'", file=sys.stderr)
        print(f"Valid keys: {', '.join(sorted(_DEFAULT_CONFIG.keys()))}", file=sys.stderr)
        return 1

    config[key] = args.value
    _save_config(config)
    return 0


# ── Init Command ───────────────────────────────────────────────


_ECOSYSTEM_MARKERS = {
    "npm": "package.json",
    "go": "go.mod",
    "python": "requirements.txt",
    "rust": "Cargo.toml",
}

_ECOSYSTEM_CRITICAL_PATHS: dict[str, list[tuple[str, str, int, str]]] = {
    "npm": [
        ("touches_package_json", "PR modifies package.json", 2, "sensitive-module"),
        ("touches_lockfile", "PR modifies package-lock.json or yarn.lock", 1, "dependency"),
        ("touches_node_modules", "PR modifies node_modules/", 3, "sensitive-module"),
    ],
    "go": [
        ("touches_go_mod", "PR modifies go.mod or go.sum", 2, "dependency"),
        ("touches_vendor", "PR modifies vendor/ directory", 2, "sensitive-module"),
    ],
    "python": [
        ("touches_setup", "PR modifies setup.py, setup.cfg, or pyproject.toml", 2, "sensitive-module"),
        ("touches_requirements", "PR modifies requirements*.txt", 2, "dependency"),
        ("touches_venv", "PR modifies virtualenv or venv directory", 3, "sensitive-module"),
    ],
    "rust": [
        ("touches_cargo_toml", "PR modifies Cargo.toml or Cargo.lock", 2, "dependency"),
        ("touches_target", "PR modifies target/ directory", 3, "sensitive-module"),
    ],
}

_ECOSYSTEM_EXTRA_RULES: dict[str, str] = {
    "npm": """
# ---- Ecosystem: npm ----

[[rules]]
name = "touches_package_json"
description = "PR modifies package.json"
condition = "touches('package.json')"
score_delta = 2
tag = "sensitive-module"

[[rules]]
name = "touches_lockfile"
description = "PR modifies package-lock.json or yarn.lock"
condition = "touches('package-lock.json') or touches('yarn.lock')"
score_delta = 1
tag = "dependency"

[[rules]]
name = "touches_node_modules"
description = "PR modifies node_modules/ directory"
condition = "touches('node_modules/')"
score_delta = 3
tag = "sensitive-module"
""",
    "go": """
# ---- Ecosystem: Go ----

[[rules]]
name = "touches_go_mod"
description = "PR modifies go.mod or go.sum"
condition = "touches('go.mod') or touches('go.sum')"
score_delta = 2
tag = "dependency"

[[rules]]
name = "touches_vendor"
description = "PR modifies vendor/ directory"
condition = "touches('vendor/')"
score_delta = 2
tag = "sensitive-module"
""",
    "python": """
# ---- Ecosystem: Python ----

[[rules]]
name = "touches_setup"
description = "PR modifies setup.py, setup.cfg, or pyproject.toml"
condition = "touches('setup.py') or touches('setup.cfg') or touches('pyproject.toml')"
score_delta = 2
tag = "sensitive-module"

[[rules]]
name = "touches_requirements"
description = "PR modifies requirements*.txt"
condition = "touches('requirements')"
score_delta = 2
tag = "dependency"

[[rules]]
name = "touches_venv"
description = "PR modifies virtualenv or venv directory"
condition = "touches('.venv/') or touches('venv/')"
score_delta = 3
tag = "sensitive-module"
""",
    "rust": """
# ---- Ecosystem: Rust ----

[[rules]]
name = "touches_cargo_toml"
description = "PR modifies Cargo.toml or Cargo.lock"
condition = "touches('Cargo.toml') or touches('Cargo.lock')"
score_delta = 2
tag = "dependency"

[[rules]]
name = "touches_target"
description = "PR modifies target/ directory"
condition = "touches('target/')"
score_delta = 3
tag = "sensitive-module"
""",
}


def _detect_ecosystem() -> str | None:
    """Auto-detect the project ecosystem from marker files in cwd."""
    cwd = Path.cwd()
    for ecosystem, marker in _ECOSYSTEM_MARKERS.items():
        # python checks two files
        if ecosystem == "python":
            if (cwd / "requirements.txt").exists() or (cwd / "pyproject.toml").exists():
                return "python"
        elif (cwd / marker).exists():
            return ecosystem
    return None


def _build_rules_toml(ecosystem: str | None, critical_paths: list[str] | None) -> str:
    """Build the rules.toml content from the default template + ecosystem rules."""
    # Try to read the packaged default rules
    default_rules_path = Path(__file__).resolve().parent.parent.parent.parent / "rules" / "default.toml"
    if not default_rules_path.exists():
        # Fallback: try relative to package dir
        default_rules_path = Path(__file__).resolve().parent.parent / "rules" / "default.toml"

    if default_rules_path.exists():
        with open(default_rules_path) as f:
            content = f.read()
    else:
        # Hardcoded fallback
        content = _HARDCODED_DEFAULT_RULES

    # Append project.critical_paths section (dict format matching load_rules_from_toml)
    content += "\n# ---- Project-Specific Critical Paths (customise these) ----\n\n[project]\ncritical_paths = [\n"
    if critical_paths:
        for p in critical_paths:
            escaped = p.replace("\\", "\\\\").replace('"', '\\"')
            content += f'    {{path = "{escaped}", weight = 30, reason = "Project source"}},\n'
    else:
        content += '    {path = "src/", weight = 30, reason = "Project source"},\n'
    content += "]\n"

    # Append ecosystem-specific rules
    if ecosystem and ecosystem in _ECOSYSTEM_EXTRA_RULES:
        content += _ECOSYSTEM_EXTRA_RULES[ecosystem]

    return content


_HARDCODED_DEFAULT_RULES = """\
# CodeSentinel Default Risk Rules
# Each [[rules]] entry defines a rule that contributes to the overall risk score.

[settings]
low_risk_max = 3      # score <= this is LOW risk
medium_risk_max = 6    # score <= this is MEDIUM risk, above is HIGH

# ---- Change Size Rules ----

[[rules]]
name = "large_pr"
description = "PR modifies more than 10 files"
condition = "modified_files > 10"
score_delta = 2
tag = "size"

[[rules]]
name = "very_large_pr"
description = "PR modifies more than 30 files"
condition = "modified_files > 30"
score_delta = 3
tag = "size"

[[rules]]
name = "high_churn"
description = "PR has more than 500 lines of changes"
condition = "total_changes > 500"
score_delta = 2
tag = "size"

[[rules]]
name = "massive_churn"
description = "PR has more than 2000 lines of changes"
condition = "total_changes > 2000"
score_delta = 3
tag = "size"

# ---- Module Risk Rules (sensitive directories) ----

[[rules]]
name = "touches_payment"
description = "PR touches payment-related code"
condition = "touches('payment/')"
score_delta = 3
tag = "sensitive-module"

[[rules]]
name = "touches_auth"
description = "PR touches authentication/authorization code"
condition = "touches('auth/')"
score_delta = 3
tag = "sensitive-module"

[[rules]]
name = "touches_core"
description = "PR touches core platform code"
condition = "touches('core/')"
score_delta = 2
tag = "sensitive-module"

[[rules]]
name = "touches_security"
description = "PR touches security-sensitive code"
condition = "touches('security/')"
score_delta = 3
tag = "sensitive-module"

[[rules]]
name = "touches_infra"
description = "PR touches infrastructure or deployment code"
condition = "touches('infra/')"
score_delta = 2
tag = "sensitive-module"

[[rules]]
name = "touches_config"
description = "PR modifies configuration files"
condition = "touches('config/')"
score_delta = 1
tag = "sensitive-module"

# ---- Author Experience Rules ----

[[rules]]
name = "new_contributor_module"
description = "Author is contributing to this module for the first time"
condition = "author_first_time_in_module"
score_delta = 2
tag = "author-experience"

# ---- Dependency Change Rules ----

[[rules]]
name = "new_dependency_added"
description = "PR adds a new dependency"
condition = "adds_new_dependency"
score_delta = 2
tag = "dependency"

[[rules]]
name = "multiple_new_deps"
description = "PR adds more than 3 new dependencies"
condition = "new_deps_count > 3"
score_delta = 2
tag = "dependency"

[[rules]]
name = "dependency_removed"
description = "PR removes a dependency"
condition = "removes_dependency"
score_delta = 1
tag = "dependency"

[[rules]]
name = "many_dep_upgrades"
description = "PR upgrades more than 5 dependencies"
condition = "upgraded_deps_count > 5"
score_delta = 1
tag = "dependency"

# ---- High-Defect Module Rules ----

[[rules]]
name = "high_defect_module"
description = "PR modifies a module with high defect density (>0.1)"
condition = "module_defect_density > 0.1"
score_delta = 3
tag = "defect-prone"

# ---- Code Structure Rules ----

[[rules]]
name = "many_functions_changed"
description = "PR modifies more than 15 functions"
condition = "unique_functions_changed > 15"
score_delta = 2
tag = "complexity"

[[rules]]
name = "many_classes_changed"
description = "PR modifies more than 5 classes"
condition = "unique_classes_changed > 5"
score_delta = 2
tag = "complexity"

[[rules]]
name = "many_hunks"
description = "PR contains more than 20 diff hunks"
condition = "hunks > 20"
score_delta = 1
tag = "complexity"
"""


_PROJECT_PROFILE_TEMPLATE = """\
# Project Profile

> Fill in this template to give CodeSentinel context about your project.
> The more detail you provide, the better the risk assessments will be.

## Overview

<!-- What does this project do? Who are the users? -->
<!-- e.g. "A REST API for managing user accounts in a SaaS platform." -->


## Architecture

<!-- Describe the high-level architecture: monolith, microservices, event-driven, etc. -->
<!-- e.g. "Monolithic Django app with PostgreSQL, Redis cache, and Celery workers." -->


## Key Modules

<!-- List the most important modules/packages and what they do. -->
<!-- e.g. -->
<!-- - `src/auth/` — Authentication and session management -->
<!-- - `src/payments/` — Stripe integration and billing logic -->
<!-- - `src/api/` — REST API endpoints -->


## Tech Stack

<!-- Languages, frameworks, databases, infrastructure. -->
<!-- e.g. Python 3.11, Django 4.2, PostgreSQL 15, Redis 7, Docker, AWS ECS -->


## Known Issues

<!-- Document any known technical debt, fragile areas, or workarounds. -->
<!-- e.g. "The payments module has no tests — changes there require manual QA." -->

"""


_REVIEW_POLICY_TEMPLATE = """\
# Review Policy

> Customise this policy to control how CodeSentinel evaluates pull requests.

## Block Conditions

<!-- Conditions that should ALWAYS block a PR from merging. -->
<!-- e.g. -->
<!-- - Any change touching `src/auth/` without a security review label -->
<!-- - PRs that modify more than 50 files -->
<!-- - PRs that remove test files without adding replacements -->

- (add your block conditions here)

## Required Tests

<!-- What tests must pass before a PR can be approved? -->
<!-- e.g. -->
<!-- - All unit tests pass (`pytest`) -->
<!-- - Integration tests for payment module pass -->
<!-- - No decrease in code coverage for `src/auth/` -->

- (add your required tests here)

## Historical Pitfalls

<!-- Problems that have occurred in the past — CodeSentinel will watch for similar patterns. -->
<!-- e.g. -->
<!-- - "2024-01: ORM migration broke production — always run migration tests" -->
<!-- - "2024-03: New dependency introduced license incompatibility — check licenses" -->

- (add historical pitfalls here)

## Performance Budgets

<!-- Performance constraints that changes must respect. -->
<!-- e.g. -->
<!-- - API p99 latency must stay under 200ms -->
<!-- - Database queries must not exceed 50ms -->
<!-- - Bundle size must not increase by more than 10KB -->

- (add performance budgets here)
"""


def cmd_init(args: argparse.Namespace) -> int:
    """Initialise a .codesentinel/ directory in the current project."""
    sentinel_dir = Path(".codesentinel")
    force = getattr(args, "force", False)
    minimal = getattr(args, "minimal", False)

    # Check if .codesentinel/ already exists
    if sentinel_dir.exists() and not force:
        existing = [f.name for f in sentinel_dir.iterdir()]
        if existing:
            print(
                f"Error: .codesentinel/ already exists ({', '.join(existing)}). "
                "Use --force to overwrite.",
                file=sys.stderr,
            )
            return 1

    sentinel_dir.mkdir(parents=True, exist_ok=True)

    # Auto-detect ecosystem
    ecosystem = _detect_ecosystem()

    # Determine critical paths based on ecosystem
    critical_paths: list[str] = ["src/"]
    if ecosystem == "npm":
        critical_paths = ["src/", "package.json"]
    elif ecosystem == "go":
        critical_paths = ["cmd/", "internal/", "pkg/"]
    elif ecosystem == "python":
        critical_paths = ["src/", "setup.py", "pyproject.toml"]
    elif ecosystem == "rust":
        critical_paths = ["src/", "Cargo.toml"]

    # Generate rules.toml
    rules_content = _build_rules_toml(ecosystem, critical_paths)
    rules_path = sentinel_dir / "rules.toml"
    with open(rules_path, "w") as f:
        f.write(rules_content)
    print(f"  Created {rules_path}" + (f" (ecosystem: {ecosystem})" if ecosystem else ""))

    if minimal:
        print(f"\nInitialized .codesentinel/ (minimal mode)")
        print(f"  Edit {rules_path} to customise risk rules.")
        return 0

    # Generate project_profile.md
    profile_path = sentinel_dir / "project_profile.md"
    with open(profile_path, "w") as f:
        f.write(_PROJECT_PROFILE_TEMPLATE)
    print(f"  Created {profile_path}")

    # Generate review_policy.md
    policy_path = sentinel_dir / "review_policy.md"
    with open(policy_path, "w") as f:
        f.write(_REVIEW_POLICY_TEMPLATE)
    print(f"  Created {policy_path}")

    print(f"\nInitialized .codesentinel/ in {Path.cwd()}")
    if ecosystem:
        print(f"  Detected ecosystem: {ecosystem}")
    print(f"  Next steps:")
    print(f"    1. Edit {rules_path} to tune risk rules")
    print(f"    2. Fill in {profile_path} with project context")
    print(f"    3. Define review policies in {policy_path}")
    return 0


# ── Argument Parser ──────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codesentinel",
        description="CodeSentinel — Risk Advisor & Ecosystem Auditor: PR risk assessment and impact analysis",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Review command
    review_parser = subparsers.add_parser(
        "review",
        help="Review a GitHub pull request",
    )
    review_parser.add_argument("pr_url", help="GitHub PR URL (https://github.com/owner/repo/pull/123)")
    review_parser.add_argument(
        "--format",
        choices=["markdown", "json", "pr-comment"],
        default=None,
        help="Output format (default: markdown)",
    )
    review_parser.add_argument(
        "--rules",
        default=None,
        help="Path to custom rules TOML file",
    )
    review_parser.add_argument(
        "--skip-llm",
        action="store_true",
        default=False,
        help="Skip LLM-based deep review",
    )
    review_parser.add_argument(
        "--repo-path",
        default=None,
        help="Path to a local git repository (enables git history analysis and CODEOWNERS)",
    )
    review_parser.add_argument(
        "--memory-db",
        default=None,
        help="Path to project memory SQLite database",
    )
    review_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write report to file instead of stdout",
    )
    review_parser.add_argument(
        "--provider",
        default=None,
        choices=["mimo", "deepseek", "openai"],
        help="LLM provider (default: from config or mimo)",
    )

    # Config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")

    # serve
    serve_parser = subparsers.add_parser("serve", help="Start webhook server")
    serve_parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    serve_parser.add_argument("--webhook-secret", default="", help="Webhook secret for signature verification")

    # init
    init_parser = subparsers.add_parser(
        "init",
        help="Initialise .codesentinel/ directory in the current project",
    )
    init_parser.add_argument(
        "--minimal",
        action="store_true",
        default=False,
        help="Only generate rules.toml (skip project_profile.md and review_policy.md)",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Overwrite existing files if .codesentinel/ already exists",
    )

    config_sub = config_parser.add_subparsers(dest="config_command")

    config_sub.add_parser("show", help="Show current configuration")

    set_parser = config_sub.add_parser("set", help="Set a config value")
    set_parser.add_argument("key", help="Config key (e.g. github_token)")
    set_parser.add_argument("value", help="Config value")

    return parser


def cmd_serve(args) -> int:
    """Start webhook server."""
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn not installed. Run: pip install uvicorn fastapi", file=sys.stderr)
        return 1

    from code_sentinel.server import create_app

    app = create_app()
    print(f"Starting CodeSentinel webhook server on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "review":
        return asyncio.run(cmd_review(args))

    if args.command == "serve":
        return cmd_serve(args)

    if args.command == "init":
        return cmd_init(args)

    if args.command == "config":
        if args.config_command == "show":
            return cmd_config_show(args)
        elif args.config_command == "set":
            return cmd_config_set(args)
        else:
            # Show config help
            parser.parse_args(["config", "--help"])
            return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
