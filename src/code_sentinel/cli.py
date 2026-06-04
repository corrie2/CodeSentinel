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
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


# ── Pipeline ─────────────────────────────────────────────────────



async def cmd_review(args: argparse.Namespace) -> int:
    """Run the full review pipeline using review()."""
    from code_sentinel.review import review, ReviewOptions

    options = ReviewOptions(
        provider=args.provider,
        rules_path=args.rules,
        repo_path=args.repo_path,
        skip_llm=args.skip_llm,
        memory_db=getattr(args, "memory_db", None),
    )

    result = await review(args.pr_url, options=options)

    # Reports are populated by reporter plugins in review()
    fmt = args.format or "markdown"
    report_key = fmt if fmt in result.reports else "markdown"
    output_text = result.reports.get(report_key, "")

    if not output_text:
        print("Error: no report generated", file=sys.stderr)
        return 1

    # Write to file or stdout
    output_path = getattr(args, "output", None)
    if output_path:
        Path(output_path).write_text(output_text, encoding="utf-8")
        print(f"Report written to {output_path}", file=sys.stderr)
    else:
        print(output_text)

    return 0


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

    app = create_app(webhook_secret=getattr(args, "webhook_secret", None))
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
