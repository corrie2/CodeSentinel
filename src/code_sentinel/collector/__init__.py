"""Data collection layer for CodeSentinel."""

from code_sentinel.collector.diff_parser import (
    ChangeSet,
    ChangedFile,
    ChangeType,
    parse_diff,
)
from code_sentinel.collector.dep_scanner import (
    DepInfo,
    DepDiff,
    DependencyChange,
    parse_deps,
    compare_deps,
    scan_dependency_changes,
    DEP_FILES,
)
from code_sentinel.collector.codeowners import (
    CodeOwnerRule,
    CodeOwnersFile,
    parse_codeowners,
    find_codeowners_file,
    load_codeowners,
    match_files_to_owners,
)

__all__ = [
    "ChangeSet", "ChangedFile", "ChangeType", "parse_diff",
    "DepInfo", "DepDiff", "DependencyChange", "parse_deps",
    "compare_deps", "scan_dependency_changes", "DEP_FILES",
    "CodeOwnerRule", "CodeOwnersFile", "parse_codeowners",
    "find_codeowners_file", "load_codeowners", "match_files_to_owners",
]
