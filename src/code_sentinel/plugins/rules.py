"""Concrete rule-loading plugin for CodeSentinel.

Wraps the default TOML-based rule loading from the risk scorer.
"""

from __future__ import annotations

import logging
from typing import Any

from code_sentinel.plugins import RulePlugin

logger = logging.getLogger(__name__)


class DefaultRulePlugin(RulePlugin):
    """Loads rules from a TOML file (or built-in defaults).

    Delegates to ``code_sentinel.risk.scorer.load_rules`` which reads
    from a TOML file path or falls back to the built-in default rules.
    """

    name = "default"

    def __init__(self, rules_path: str | None = None) -> None:
        self.rules_path = rules_path

    def load_rules(self) -> Any:
        """Load and return a RuleSet.

        Args:
            None — the rules_path is set at construction time.

        Returns:
            A ``RuleSet`` object from the risk scorer.
        """
        from code_sentinel.risk.scorer import load_rules

        return load_rules(self.rules_path)
