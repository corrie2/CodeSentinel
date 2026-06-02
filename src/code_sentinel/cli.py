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

    # Override with env vars
    for key in _DEFAULT_CONFIG:
        env_key = _ENV_PREFIX + key.upper()
        val = os.environ.get(env_key)
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
    config_obj = Config(
        provider=config_dict.get("provider", "mimo"),
        api_key=config_dict.get("mimo_api_key") or config_dict.get("api_key"),
        github_token=config_dict.get("github_token"),
    )

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
        print("Error: Could not fetch PR diff. Check your GITHUB_TOKEN.", file=sys.stderr)
        return 1

    # ── Step 2: Parse diff -> ChangeSet ──────────────────────────
    print("  [2/6] Parsing diff...", file=sys.stderr)
    changeset = parse_diff(raw_diff) if raw_diff else None

    # ── Step 3: Dependency changes (from diff) ───────────────────
    # For MVP we scan the diff for dependency file changes.
    # A full implementation would compare old/new file content via the API.
    dep_changes: list = []

    # ── Step 4: Parse CODEOWNERS ─────────────────────────────────
    codeowners = None
    if args.repo_path:
        from code_sentinel.collector.codeowners import load_codeowners
        codeowners = load_codeowners(args.repo_path)

    # ── Step 5: Project memory ───────────────────────────────────
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

    # ── Step 6: Risk scoring ─────────────────────────────────────
    print("  [4/6] Computing risk score...", file=sys.stderr)
    rules_path = args.rules or config_dict.get("rules_file") or None
    risk_score = assess_risk(
        changeset=changeset,
        dep_changes=dep_changes,
        codeowners=codeowners,
        author=pr_data.get("pr", {}).get("author", ""),
        module_defect_density=module_densities if module_densities else None,
        rules_path=rules_path,
    )

    print(
        f"         Risk: {risk_score.level.value.upper()} (score={risk_score.score})",
        file=sys.stderr,
    )

    # ── Level 2 & 3: Conditional audits ──────────────────────────
    supply_chain_report = None
    impact_report = None
    deep_review_findings = None

    if risk_score.level in (RiskLevel.MEDIUM, RiskLevel.HIGH):
        # Level 2: Supply chain + Impact
        print("  [5/6] Running supply chain + impact assessment...", file=sys.stderr)
        from code_sentinel.auditor.supply_chain import run_supply_chain_audit
        from code_sentinel.auditor.impact import assess_impact

        supply_chain_report = await run_supply_chain_audit(changed_files=changed_files)
        impact_report = assess_impact(changed_files)

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
                except Exception as exc:
                    logger.error("Deep review failed: %s", exc)
                    print(f"  [6/6] Deep review failed: {exc}", file=sys.stderr)
            else:
                print("  [6/6] Skipping deep review (--skip-llm)", file=sys.stderr)
        else:
            print("  [6/6] Skipping deep review (medium risk)", file=sys.stderr)
    else:
        print("  [5/6] Skipping audits (low risk)", file=sys.stderr)
        print("  [6/6] Skipping deep review (low risk)", file=sys.stderr)

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

    # ── Build report ─────────────────────────────────────────────
    pr_meta = PRMetadata(**pr_data.get("pr", {}))
    ctx = build_report_context(
        pr=pr_meta,
        risk_score=risk_score.score,
        risk_level=risk_score.level.value,
        risk_details={
            "triggered_rules": risk_score.triggered_rules,
            "tags": risk_score.tags,
        },
        supply_chain_report=supply_chain_report,
        impact_report=impact_report,
        deep_review=deep_review_findings,
    )

    # ── Render output ────────────────────────────────────────────
    fmt = args.format or config_dict.get("default_format", "markdown")
    if fmt == "json":
        print(render_json(ctx))
    elif fmt == "pr-comment":
        print(render_pr_comment(ctx))
    else:
        print(render_markdown(ctx))

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

    # Config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")

    # serve
    serve_parser = subparsers.add_parser("serve", help="Start webhook server")
    serve_parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    serve_parser.add_argument("--webhook-secret", default="", help="Webhook secret for signature verification")
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
