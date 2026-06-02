"""Parse CODEOWNERS file (GitHub format) and match file paths against patterns."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class CodeOwnerRule:
    """A single CODEOWNERS rule: pattern + owners."""
    pattern: str
    owners: List[str]
    line_number: int = 0

    # Pre-compiled regex (lazily built)
    _regex: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def _build_regex(self) -> re.Pattern:
        """Convert a CODEOWNERS glob pattern to a regex."""
        if self._regex is not None:
            return self._regex

        pat = self.pattern

        # Normalize: remove leading /
        if pat.startswith("/"):
            pat = pat[1:]

        # Escape special regex chars (except * ? and **)
        result = []
        i = 0
        while i < len(pat):
            c = pat[i]
            if c == "*" and i + 1 < len(pat) and pat[i + 1] == "*":
                # ** matches everything including /
                result.append(".*")
                i += 2
                # consume optional trailing /*
                if i < len(pat) and pat[i] == "/":
                    i += 1
            elif c == "*":
                # * matches anything except /
                result.append("[^/]*")
                i += 1
            elif c == "?":
                result.append("[^/]")
                i += 1
            elif c == "[":
                # character class — pass through until ]
                j = pat.index("]", i)
                result.append(pat[i : j + 1])
                i = j + 1
            elif c == "#":
                break  # comment
            else:
                result.append(re.escape(c))
                i += 1

        regex_str = "".join(result)

        # If pattern doesn't end with /, it should match both files and directories
        # For directory patterns (ending with /), match anything under that dir
        if self.pattern.endswith("/"):
            regex_str = regex_str.rstrip("/")
            regex_str = f"(?:^|/)\\/?{regex_str}(?:/.*)?$"
        elif "*" not in self.pattern and "?" not in self.pattern:
            # Exact file match (no wildcards)
            regex_str = f"(?:^|/)\\/?{regex_str}$"
        else:
            regex_str = f"(?:^|/)\\/?{regex_str}$"

        self._regex = re.compile(regex_str)
        return self._regex

    def matches(self, file_path: str) -> bool:
        """Check if a file path matches this CODEOWNERS pattern.

        Args:
            file_path: The file path to match (relative to repo root, no leading /).

        Returns:
            True if the path matches this pattern.
        """
        regex = self._build_regex()
        return regex.search(file_path) is not None


@dataclass
class CodeOwnersFile:
    """Parsed CODEOWNERS file."""
    rules: List[CodeOwnerRule] = field(default_factory=list)
    raw_content: str = ""

    def find_owners(self, file_path: str) -> List[str]:
        """Find the owners for a given file path.

        Per GitHub docs, the LAST matching pattern wins.

        Args:
            file_path: The relative file path (e.g., "src/auth/login.py").

        Returns:
            List of owner strings (usernames/team names).
        """
        owners: List[str] = []
        for rule in self.rules:
            if rule.matches(file_path):
                owners = rule.owners
        return owners

    def get_all_owners(self) -> List[str]:
        """Get a deduplicated list of all owners in the file."""
        seen = set()
        result: List[str] = []
        for rule in self.rules:
            for owner in rule.owners:
                if owner not in seen:
                    seen.add(owner)
                    result.append(owner)
        return result


def parse_codeowners(content: str) -> CodeOwnersFile:
    """Parse a CODEOWNERS file content.

    Args:
        content: Raw content of the CODEOWNERS file.

    Returns:
        A CodeOwnersFile with parsed rules.
    """
    co_file = CodeOwnersFile(raw_content=content)

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        parts = stripped.split()
        if len(parts) < 2:
            continue

        pattern = parts[0]
        owners = [p for p in parts[1:] if not p.startswith("#")]

        if owners:
            co_file.rules.append(CodeOwnerRule(
                pattern=pattern,
                owners=owners,
                line_number=line_num,
            ))

    return co_file


def find_codeowners_file(repo_root: str) -> Optional[str]:
    """Locate the CODEOWNERS file in a repository.

    Searches in order:
    1. Root: CODEOWNERS
    2. .github/CODEOWNERS
    3. docs/CODEOWNERS

    Args:
        repo_root: Path to the repository root.

    Returns:
        Path to the CODEOWNERS file, or None if not found.
    """
    candidates = [
        os.path.join(repo_root, "CODEOWNERS"),
        os.path.join(repo_root, ".github", "CODEOWNERS"),
        os.path.join(repo_root, "docs", "CODEOWNERS"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def load_codeowners(repo_root: str) -> CodeOwnersFile:
    """Load and parse the CODEOWNERS file from a repository.

    Args:
        repo_root: Path to the repository root.

    Returns:
        Parsed CodeOwnersFile, or an empty one if no CODEOWNERS file exists.
    """
    path = find_codeowners_file(repo_root)
    if path is None:
        return CodeOwnersFile()

    try:
        with open(path, "r", encoding="utf-8") as f:
            return parse_codeowners(f.read())
    except OSError:
        return CodeOwnersFile()


def match_files_to_owners(
    codeowners: CodeOwnersFile,
    file_paths: List[str],
) -> List[Tuple[str, List[str]]]:
    """Match a list of file paths to their owners.

    Args:
        codeowners: Parsed CODEOWNERS file.
        file_paths: List of relative file paths.

    Returns:
        List of (file_path, owners) tuples.
    """
    results: List[Tuple[str, List[str]]] = []
    for path in file_paths:
        owners = codeowners.find_owners(path)
        results.append((path, owners))
    return results
