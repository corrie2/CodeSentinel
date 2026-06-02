"""LLM-powered deep review for high-risk PRs.

Only triggered when the risk score is ``HIGH``.  Sends the diff of the
most dangerous files to the LLM and parses structured findings.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from code_sentinel.config import Config
from code_sentinel.llm.client import LLMClient
from code_sentinel.llm.prompts import DEEP_REVIEW_PROMPT
from code_sentinel.risk.scorer import RiskScore

logger = logging.getLogger(__name__)

# Maximum high-risk files to send to the LLM (cost control)
_MAX_HIGH_RISK_FILES = 3


@dataclass
class DeepFinding:
    """A single issue discovered by the deep-review LLM.

    Attributes:
        issue_type:  One of ``security``, ``concurrency``,
                     ``resource_leak``, ``logic_error``.
        severity:    One of ``critical``, ``high``, ``medium``, ``low``, ``info``.
        file:        The file path where the issue occurs.
        line:        Approximate line number (0 if unknown).
        description: Concise explanation of the problem.
        evidence:    Code snippet or reasoning that proves the issue.
        test_suggestion: A pytest-style test or snippet that could expose
                         the bug.
    """

    issue_type: str = "logic_error"
    severity: str = "medium"
    file: str = ""
    line: int = 0
    description: str = ""
    evidence: str = ""
    test_suggestion: str = ""

    def as_dict(self) -> Dict[str, Any]:
        """Serialise to a dict suitable for the report formatter."""
        return {
            "issue_type": self.issue_type,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "evidence": self.evidence,
            "test_suggestion": self.test_suggestion,
        }


def _build_user_prompt(
    changeset: Any,
    risk_score: RiskScore,
    module_densities: Optional[Dict[str, float]] = None,
    ranked_files: Optional[list] = None,
) -> str:
    """Build the user-facing prompt containing the diff and context.

    Args:
        changeset: A :class:`ChangeSet` from ``diff_parser``.
        risk_score: The computed :class:`RiskScore`.
        module_densities: Optional module defect densities from project memory.

    Returns:
        A prompt string ready to send to the LLM.
    """
    parts: list[str] = []

    # Context section
    parts.append("## Context")
    parts.append(f"- Risk level: **{risk_score.level.value.upper()}** (score {risk_score.score})")
    parts.append(f"- Triggered rules: {', '.join(risk_score.triggered_rules) or 'none'}")
    parts.append(f"- Tags: {', '.join(risk_score.tags) or 'none'}")

    if module_densities:
        high_modules = [m for m, d in module_densities.items() if d >= 0.1]
        if high_modules:
            parts.append(f"- High-defect modules: {', '.join(high_modules)}")

    parts.append("")

    # Diff section — top N high-risk files (ranked by file_ranker)
    # Use ranked files if available, otherwise fall back to size-based sort
    if ranked_files:
        ranked_paths = [rf.path for rf in ranked_files]
        sorted_files = [
            f for f in changeset.files if f.path in ranked_paths
        ][:_MAX_HIGH_RISK_FILES]
    else:
        sorted_files = sorted(
            changeset.files,
            key=lambda f: f.lines_added + f.lines_deleted,
            reverse=True,
        )[:_MAX_HIGH_RISK_FILES]

    parts.append("## Changed Files (high-risk subset)")
    for f in sorted_files:
        parts.append(f"- `{f.path}` (+{f.lines_added}/-{f.lines_deleted})")
    parts.append("")

    parts.append("## Diffs")
    # We include the raw diff text that was parsed into the changeset.
    # The caller stores the raw diff; here we reconstruct a summary.
    for f in sorted_files:
        parts.append(f"### {f.path}")
        parts.append(f"Change type: {f.change_type.value}, "
                      f"+{f.lines_added}/-{f.lines_deleted}, "
                      f"hunks: {f.hunks}")
        if f.changed_functions:
            parts.append(f"Functions: {', '.join(f.changed_functions)}")
        if f.changed_classes:
            parts.append(f"Classes: {', '.join(f.changed_classes)}")
        parts.append("")

    return "\n".join(parts)


def _extract_json_array(text: str) -> list[dict]:
    """Best-effort extraction of a JSON array from LLM output.

    Handles cases where the LLM wraps the array in markdown fences
    or includes explanatory text around it.

    Args:
        text: Raw LLM response text.

    Returns:
        Parsed list of dicts (empty list on failure).
    """
    # Try direct parse first
    text = text.strip()
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
        return []
    except json.JSONDecodeError:
        pass

    # Try to find a JSON array in markdown code fences
    fence_match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
    if fence_match:
        try:
            result = json.loads(fence_match.group(1))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    # Try to find a bare JSON array in the text
    bracket_match = re.search(r"\[.*\]", text, re.DOTALL)
    if bracket_match:
        try:
            result = json.loads(bracket_match.group(0))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    logger.warning("Failed to extract JSON array from LLM response (len=%d)", len(text))
    return []


def _parse_location(location: str) -> tuple[str, int]:
    """Split a ``filepath:line_number`` string.

    Args:
        location: e.g. ``src/auth/login.py:42``

    Returns:
        Tuple of (file_path, line_number).  Line defaults to 0 if missing.
    """
    if ":" in location:
        parts = location.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return location, 0
    return location, 0


def _finding_from_dict(raw: dict) -> DeepFinding:
    """Convert a raw dict from the LLM response into a DeepFinding."""
    location = raw.get("location", "")
    file_path, line = _parse_location(str(location))
    return DeepFinding(
        issue_type=raw.get("issue_type", "logic_error"),
        severity=raw.get("severity", "medium"),
        file=file_path,
        line=line,
        description=raw.get("description", ""),
        evidence=raw.get("evidence", ""),
        test_suggestion=raw.get("test_suggestion", ""),
    )


async def run_deep_review(
    changeset: Any,
    risk_score: RiskScore,
    config: Config,
    raw_diff: str = "",
    module_densities: Optional[Dict[str, float]] = None,
    project_context: Optional[str] = None,
) -> List[DeepFinding]:
    """Perform an LLM-powered deep code review of high-risk files.

    Only files with the most changes are sent to the LLM to control cost.
    The LLM returns a JSON array of structured findings.

    Args:
        changeset: A :class:`ChangeSet` from the diff parser.
        risk_score: The computed :class:`RiskScore`.
        config: Application :class:`Config` (provides LLM credentials).
        raw_diff: The original raw diff text (optional, for richer context).
        module_densities: Module defect densities from project memory.
        project_context: Optional project profile and review policy context
            from .codesentinel/ config files (already sanitized).

    Returns:
        A list of :class:`DeepFinding` objects.
    """
    if not changeset or not changeset.files:
        logger.info("No files in changeset, skipping deep review")
        return []

    # Rank files using file_ranker for smarter file selection
    from code_sentinel.risk.file_ranker import get_top_files
    _high_defect = (
        [m for m, d in module_densities.items() if d >= 0.1]
        if module_densities else []
    )
    risk_ctx = {
        "high_defect_modules": _high_defect,
        "critical_paths": [],
    }
    ranked_files = get_top_files(
        changeset, n=_MAX_HIGH_RISK_FILES, risk_context=risk_ctx
    )
    ranked_paths = {rf.path for rf in ranked_files}

    # Build user prompt (uses ranked files)
    user_prompt = _build_user_prompt(
        changeset, risk_score, module_densities, ranked_files=ranked_files
    )

    # If we have the raw diff, extract relevant sections for ranked files
    diff_section = ""
    if raw_diff:
        diff_sections = _extract_diff_sections(raw_diff, ranked_paths)
        if diff_sections:
            diff_section = "\n\n## Actual Diff Content\n" + diff_sections

    # Build system prompt (optionally prepend project context)
    system_prompt = DEEP_REVIEW_PROMPT
    if project_context:
        system_prompt = (
            "## Project Context\n\n"
            + project_context.strip()
            + "\n\n---\n\n"
            + DEEP_REVIEW_PROMPT
        )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt + diff_section},
    ]

    # Call LLM
    client = LLMClient(config)
    try:
        response_text = await client.chat(
            messages=messages,
            temperature=0.2,
            max_tokens=4096,
        )
    except Exception as exc:
        logger.error("Deep review LLM call failed: %s", exc)
        return []
    finally:
        await client.close()

    # Parse response
    raw_findings = _extract_json_array(response_text)
    findings = [_finding_from_dict(d) for d in raw_findings]

    logger.info("Deep review produced %d findings", len(findings))
    return findings


def _extract_diff_sections(raw_diff: str, target_paths: set[str]) -> str:
    """Extract diff sections for specific file paths.

    Args:
        raw_diff: The full unified diff.
        target_paths: Set of file paths to extract.

    Returns:
        Concatenated diff sections for the target files.
    """
    sections: list[str] = []
    current_path: Optional[str] = None
    current_lines: list[str] = []

    for line in raw_diff.splitlines():
        if line.startswith("+++ b/"):
            # Save previous section if it matches
            if current_path and current_path in target_paths and current_lines:
                sections.append("\n".join(current_lines))
            # Start new section
            current_path = line[len("+++ b/"):]
            current_lines = [line]
        elif current_path is not None:
            current_lines.append(line)

    # Don't forget the last section
    if current_path and current_path in target_paths and current_lines:
        sections.append("\n".join(current_lines))

    return "\n\n".join(sections)
