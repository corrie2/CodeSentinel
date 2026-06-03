"""Rule evaluation engine for risk scoring.

Supports evaluating simple expressions against a context dictionary, and
loading rule definitions from TOML files.
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Rule:
    """A single risk rule."""
    name: str
    description: str
    condition: str
    score_delta: int = 1
    tag: str = ""
    enabled: bool = True


@dataclass
class RuleSet:
    """A collection of rules with evaluation context."""
    rules: List[Rule] = field(default_factory=list)
    low_risk_max: int = 3
    medium_risk_max: int = 6
    critical_paths: List[Dict[str, Any]] = field(default_factory=list)


# ---- Built-in functions available in rule expressions ----


def _fn_touches(context: Dict[str, Any], pattern: str) -> bool:
    """Check if any modified file path contains the pattern."""
    paths = context.get("_file_paths", [])
    return any(pattern in p for p in paths)


def _fn_authors_path(context: Dict[str, Any], pattern: str) -> bool:
    """Check if the author owns files in the given path (from CODEOWNERS)."""
    author_ownerships = context.get("_author_owned_paths", [])
    return any(pattern in p for p in author_ownerships)


def _fn_any_dep_type(context: Dict[str, Any], dep_type: str) -> bool:
    """Check if there are dependency changes of the given type."""
    dep_changes = context.get("_dep_changes", [])
    for dc in dep_changes:
        if hasattr(dc, 'change_type'):
            # New DepChange format
            if dc.change_type == dep_type:
                return True
        else:
            # Old DependencyChange format
            if dep_type == 'added' and dc.added:
                return True
            if dep_type == 'removed' and dc.removed:
                return True
            if dep_type in ('upgraded', 'version_changed') and dc.upgraded:
                return True
    return False


# Comparison operators
_OPS: Dict[str, Callable[[Any, Any], bool]] = {
    ">": operator.gt,
    "<": operator.lt,
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
}

# Pattern for binary comparisons: field op value
_COMPARE_RE = re.compile(
    r"^(\w+)\s*(>=|<=|!=|==|>|<)\s*(.+)$"
)

# Pattern for touches('pattern')
_TOUCHES_RE = re.compile(r"^touches\(\s*['\"](.+?)['\"]\s*\)$")

# Pattern for any function call: func_name('arg')
_FUNC_CALL_RE = re.compile(r"^(\w+)\(\s*['\"](.+?)['\"]\s*\)$")

# Pattern for bare boolean fields
_BOOL_FIELD_RE = re.compile(r"^(\w+)$")


# Registry of built-in functions
_BUILTIN_FUNCS: Dict[str, Callable] = {
    "touches": _fn_touches,
    "authors_path": _fn_authors_path,
    "any_dep_type": _fn_any_dep_type,
}


def evaluate_condition(condition: str, context: Dict[str, Any]) -> bool:
    """Evaluate a rule condition string against a context.

    Supported condition formats:
        - field > value / field < value / field >= value etc.
        - touches('pattern')
        - func_name('arg')  (for registered built-in functions)
        - bare_field_name   (truthy check)

    Args:
        condition: The condition expression string.
        context: Dictionary of variables for evaluation.

    Returns:
        True if the condition is met.

    Raises:
        ValueError: If the condition cannot be parsed.
    """
    condition = condition.strip()

    # Try function call: touches('payment/') or any_dep_type('added')
    m = _TOUCHES_RE.match(condition)
    if m:
        pattern = m.group(1)
        return _fn_touches(context, pattern)

    m = _FUNC_CALL_RE.match(condition)
    if m:
        func_name = m.group(1)
        arg = m.group(2)
        func = _BUILTIN_FUNCS.get(func_name)
        if func:
            return func(context, arg)
        raise ValueError(f"Unknown function in condition: {func_name}")

    # Try binary comparison: field op value
    m = _COMPARE_RE.match(condition)
    if m:
        field_name = m.group(1)
        op_str = m.group(2)
        value_str = m.group(3).strip()

        field_val = context.get(field_name)
        if field_val is None:
            return False

        # Parse the comparison value
        cmp_val = _parse_value(value_str, field_val)

        op_func = _OPS.get(op_str)
        if op_func is None:
            raise ValueError(f"Unknown operator: {op_str}")

        try:
            return op_func(field_val, cmp_val)
        except TypeError:
            return False

    # Try bare boolean field
    m = _BOOL_FIELD_RE.match(condition)
    if m:
        field_name = m.group(1)
        val = context.get(field_name)
        return bool(val) if val is not None else False

    raise ValueError(f"Cannot parse condition: {condition}")


def _parse_value(value_str: str, ref_value: Any) -> Any:
    """Parse a value string, inferring type from the reference value."""
    value_str = value_str.strip()

    # String literal
    if (value_str.startswith("'") and value_str.endswith("'")) or \
       (value_str.startswith('"') and value_str.endswith('"')):
        return value_str[1:-1]

    # Try int
    try:
        return int(value_str)
    except ValueError:
        pass

    # Try float
    try:
        return float(value_str)
    except ValueError:
        pass

    # Bool
    if value_str.lower() == "true":
        return True
    if value_str.lower() == "false":
        return False

    # Fallback to string
    return value_str


def load_rules_from_toml(toml_data: dict) -> RuleSet:
    """Load a RuleSet from parsed TOML data.

    Expected format:
        [settings]
        low_risk_max = 3
        medium_risk_max = 6

        [[rules]]
        name = "large_pr"
        description = "PR modifies more than 10 files"
        condition = "modified_files > 10"
        score_delta = 2
        tag = "size"

    Args:
        toml_data: Parsed TOML dictionary.

    Returns:
        A RuleSet instance.
    """
    ruleset = RuleSet()

    # Load settings
    settings = toml_data.get("settings", {})
    ruleset.low_risk_max = settings.get("low_risk_max", 3)
    ruleset.medium_risk_max = settings.get("medium_risk_max", 6)

    # Load rules
    rules_list = toml_data.get("rules", [])
    if not isinstance(rules_list, list):
        rules_list = []

    for r in rules_list:
        if not isinstance(r, dict):
            continue
        rule = Rule(
            name=r.get("name", "unnamed"),
            description=r.get("description", ""),
            condition=r.get("condition", "false"),
            score_delta=r.get("score_delta", 1),
            tag=r.get("tag", ""),
            enabled=r.get("enabled", True),
        )
        ruleset.rules.append(rule)

    # Load project critical paths
    project = toml_data.get("project", {})
    critical_paths = project.get("critical_paths", [])
    if isinstance(critical_paths, list):
        ruleset.critical_paths = [
            cp for cp in critical_paths if isinstance(cp, dict) and "path" in cp
        ]

    return ruleset


def evaluate_rules(
    ruleset: RuleSet,
    context: Dict[str, Any],
) -> tuple[int, List[str], List[str]]:
    """Evaluate all enabled rules against the context.

    Args:
        ruleset: The RuleSet to evaluate.
        context: Context dictionary with evaluation variables.

    Returns:
        Tuple of (total_score, list_of_triggered_rule_descriptions, list_of_tags).
    """
    total_score = 0
    triggered: List[str] = []
    tags: List[str] = []

    for rule in ruleset.rules:
        if not rule.enabled:
            continue
        try:
            if evaluate_condition(rule.condition, context):
                total_score += rule.score_delta
                triggered.append(rule.description)
                if rule.tag and rule.tag not in tags:
                    tags.append(rule.tag)
        except (ValueError, TypeError) as e:
            # Skip rules that fail to evaluate
            continue

    return total_score, triggered, tags
