"""Parse unified diff format from GitHub API into structured ChangeSet objects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ChangeType(str, Enum):
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"


@dataclass
class ChangedFile:
    """A single file that was changed in a diff."""
    path: str
    old_path: Optional[str] = None  # set on rename
    change_type: ChangeType = ChangeType.MODIFY
    lines_added: int = 0
    lines_deleted: int = 0
    changed_functions: List[str] = field(default_factory=list)
    changed_classes: List[str] = field(default_factory=list)
    hunks: int = 0


@dataclass
class ChangeSet:
    """Structured representation of a full PR diff."""
    files: List[ChangedFile] = field(default_factory=list)
    total_additions: int = 0
    total_deletions: int = 0
    total_files: int = 0

    @property
    def total_changes(self) -> int:
        return self.total_additions + self.total_deletions

    def paths(self) -> List[str]:
        return [f.path for f in self.files]

    def touches(self, pattern: str) -> bool:
        """Check if any changed file path contains the given pattern."""
        return any(pattern in f.path for f in self.files)


# --- regex patterns ---
# Matches: @@ -old_start[,old_count] +new_start[,new_count] @@ optional context
_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$"
)

# Common function/class header patterns for various languages
_FUNC_PATTERNS = [
    # Python: def func_name(
    re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("),
    # JavaScript/TypeScript: function name(, const name = (... =>, export function name(
    re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\("
    ),
    re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\("
    ),
    # Go: func name(
    re.compile(r"^func\s+(\w+)\s*\("),
    # Java/C/C++/C#/Rust: type name(...) or visibility type name(
    re.compile(
        r"^\s*(?:public|private|protected|static|final|abstract|virtual|override|"
        r"async|extern|inline|fn|pub\s+fn)?\s*"
        r"(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*(?:\{|->|throws|:)"
    ),
    # Ruby: def name
    re.compile(r"^\s*def\s+(\w+)"),
]

_CLASS_PATTERNS = [
    re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+(\w+)"),
    re.compile(r"^\s*(?:public|private|protected)?\s*(?:abstract\s+)?class\s+(\w+)"),
    re.compile(r"^type\s+(\w+)\s+struct"),
    re.compile(r"^struct\s+(\w+)"),
    re.compile(r"^class\s+(\w+)"),
]

# Diff line prefixes
_ADD_PREFIX = "+"
_DEL_PREFIX = "-"
_FILE_HEADER_NEW = "+++ b/"
_FILE_HEADER_OLD = "--- a/"
_DEV_NULL = "/dev/null"
_RENAME_FROM = "rename from "
_RENAME_TO = "rename to "
_NEW_FILE = "new file"
_DELETED_FILE = "deleted file"


def _detect_function(line: str) -> Optional[str]:
    """Try to extract a function name from a source line."""
    for pat in _FUNC_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(1)
    return None


def _detect_class(line: str) -> Optional[str]:
    """Try to extract a class name from a source line."""
    for pat in _CLASS_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(1)
    return None


def _detect_change_type(
    lines: List[str], idx: int, new_path: str
) -> tuple[ChangeType, Optional[str]]:
    """Look at diff headers to determine the change type."""
    # scan backwards from idx for file mode headers
    for lookback in range(max(0, idx - 10), idx):
        line = lines[lookback]
        if line.startswith(_NEW_FILE):
            return ChangeType.ADD, None
        if line.startswith(_DELETED_FILE):
            return ChangeType.DELETE, None
        if line.startswith(_RENAME_FROM):
            old_path = line[len(_RENAME_FROM) :].strip()
            return ChangeType.RENAME, old_path
    return ChangeType.MODIFY, None


def parse_diff(raw_diff: str) -> ChangeSet:
    """Parse a unified diff string into a ChangeSet.

    Args:
        raw_diff: The raw unified diff text (as returned by GitHub API).

    Returns:
        A ChangeSet with structured file-level and overall stats.
    """
    lines = raw_diff.splitlines()
    changeset = ChangeSet()
    current: Optional[ChangedFile] = None
    current_function: Optional[str] = None
    current_class: Optional[str] = None

    i = 0
    while i < len(lines):
        line = lines[i]

        # Detect new file header: +++ b/path
        if line.startswith(_FILE_HEADER_NEW):
            path = line[len(_FILE_HEADER_NEW) :].strip()
            # Skip /dev/null entries
            if path == _DEV_NULL:
                i += 1
                continue

            change_type, old_path = _detect_change_type(lines, i, path)

            current = ChangedFile(
                path=path,
                old_path=old_path,
                change_type=change_type,
            )
            changeset.files.append(current)

        # Detect deleted file: --- b/path (when +++ was /dev/null)
        elif line.startswith(_FILE_HEADER_OLD):
            path = line[len(_FILE_HEADER_OLD) :].strip()
            if path == _DEV_NULL:
                i += 1
                continue

            # Check if next line is +++ /dev/null (deletion)
            is_delete = False
            for look in range(i + 1, min(i + 3, len(lines))):
                nxt = lines[look]
                if nxt.startswith("+++") and "/dev/null" in nxt:
                    is_delete = True
                    break
                if nxt.startswith("@@") or nxt.startswith(_FILE_HEADER_NEW):
                    break

            if is_delete:
                # Check we haven't already created a file for this path
                already_exists = any(f.path == path for f in changeset.files)
                if not already_exists:
                    current = ChangedFile(
                        path=path,
                        change_type=ChangeType.DELETE,
                    )
                    changeset.files.append(current)

        # Parse hunk headers
        elif line.startswith("@@") and current is not None:
            m = _HUNK_HEADER_RE.match(line)
            if m:
                current.hunks += 1
                # Try to extract function/class context from the hunk header
                context = m.group(5).strip()
                if context:
                    # Strip surrounding markers like "func_name()" -> keep name
                    func = _detect_function(context)
                    if func and func not in current.changed_functions:
                        current.changed_functions.append(func)
                    cls = _detect_class(context)
                    if cls and cls not in current.changed_classes:
                        current.changed_classes.append(cls)

        # Count additions/deletions
        elif current is not None:
            if line.startswith(_ADD_PREFIX) and not line.startswith("+++"):
                current.lines_added += 1
                # Try to detect function/class definitions in added lines
                src = line[1:]  # strip the +
                func = _detect_function(src)
                if func and func not in current.changed_functions:
                    current.changed_functions.append(func)
                cls = _detect_class(src)
                if cls and cls not in current.changed_classes:
                    current.changed_classes.append(cls)
            elif line.startswith(_DEL_PREFIX) and not line.startswith("---"):
                current.lines_deleted += 1

        i += 1

    # Compute totals
    for f in changeset.files:
        changeset.total_additions += f.lines_added
        changeset.total_deletions += f.lines_deleted
    changeset.total_files = len(changeset.files)

    return changeset
