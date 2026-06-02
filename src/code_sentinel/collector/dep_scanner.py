"""Scan dependency files and detect dependency changes between old and new versions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Supported dependency file names
DEP_FILES = [
    "package.json",
    "go.mod",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
]


@dataclass
class DepInfo:
    """A single dependency with name and version."""
    name: str
    version: Optional[str] = None


@dataclass
class DepDiff:
    """A single dependency change."""
    name: str
    change_type: str  # "added", "removed", "upgraded", "downgraded"
    old_version: Optional[str] = None
    new_version: Optional[str] = None


@dataclass
class DependencyChange:
    """Aggregated dependency changes across all detected files."""
    file_path: str
    file_type: str  # e.g. "package.json", "go.mod"
    added: List[DepDiff] = field(default_factory=list)
    removed: List[DepDiff] = field(default_factory=list)
    upgraded: List[DepDiff] = field(default_factory=list)
    downgraded: List[DepDiff] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.upgraded) + len(self.downgraded)

    @property
    def has_new_deps(self) -> bool:
        return len(self.added) > 0


def _compare_versions(v1: Optional[str], v2: Optional[str]) -> int:
    """Compare two semver-like version strings.

    Returns:
        -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
        Falls back to lexicographic comparison for non-semver.
    """
    if v1 is None:
        return -1
    if v2 is None:
        return 1

    # Strip common prefixes
    v1_clean = v1.lstrip("~^>=<! ")
    v2_clean = v2.lstrip("~^>=<! ")

    def _parse_ver(v: str) -> list[int]:
        parts = []
        for p in v.split("."):
            # Extract leading digits
            m = re.match(r"(\d+)", p)
            if m:
                parts.append(int(m.group(1)))
            else:
                parts.append(0)
        return parts

    parts1 = _parse_ver(v1_clean)
    parts2 = _parse_ver(v2_clean)

    # Pad to same length
    maxlen = max(len(parts1), len(parts2))
    parts1.extend([0] * (maxlen - len(parts1)))
    parts2.extend([0] * (maxlen - len(parts2)))

    for a, b in zip(parts1, parts2):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


def _detect_file_type(filename: str) -> Optional[str]:
    """Detect the dependency file type from a filename."""
    name = filename.rsplit("/", 1)[-1]
    if name in DEP_FILES:
        return name
    return None


# ---- Parsers for each format ----


def _parse_package_json(content: str) -> List[DepInfo]:
    """Parse package.json dependencies + devDependencies."""
    deps: List[DepInfo] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        section_deps = data.get(section, {})
        if isinstance(section_deps, dict):
            for name, ver in section_deps.items():
                deps.append(DepInfo(name=name, version=str(ver)))
    return deps


def _parse_go_mod(content: str) -> List[DepInfo]:
    """Parse go.mod require block."""
    deps: List[DepInfo] = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require"):
            if "(" in stripped:
                in_require = True
            else:
                # Single-line require: require golang.org/x/text v1.3.0
                parts = stripped.split()
                if len(parts) >= 3:
                    deps.append(DepInfo(name=parts[1], version=parts[2]))
            continue
        if in_require:
            if stripped == ")":
                in_require = False
                continue
            if stripped and not stripped.startswith("//"):
                parts = stripped.split()
                if len(parts) >= 2:
                    deps.append(DepInfo(name=parts[0], version=parts[1]))
    return deps


def _parse_requirements_txt(content: str) -> List[DepInfo]:
    """Parse requirements.txt format."""
    deps: List[DepInfo] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: package==1.0, package>=1.0, package~=1.0, package
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)?$", line)
        if m:
            name = m.group(1)
            version = m.group(2).strip() if m.group(2) else None
            # Clean extras like [security]
            name = re.sub(r"\[.*\]", "", name)
            deps.append(DepInfo(name=name, version=version))
    return deps


def _parse_pipfile(content: str) -> List[DepInfo]:
    """Parse Pipfile [packages] and [dev-packages] sections (TOML-like)."""
    deps: List[DepInfo] = []
    in_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            in_section = section in ("packages", "dev-packages")
            continue
        if in_section and "=" in stripped:
            parts = stripped.split("=", 1)
            name = parts[0].strip().strip('"').strip("'")
            ver_raw = parts[1].strip().strip('"').strip("'")
            if ver_raw == "*":
                ver_raw = None
            deps.append(DepInfo(name=name, version=ver_raw))
    return deps


def _parse_pyproject_toml(content: str) -> List[DepInfo]:
    """Parse pyproject.toml dependencies (regex-based, no toml dep required)."""
    deps: List[DepInfo] = []
    # Look for [project] dependencies = [...] or [tool.poetry.dependencies]
    # Simple approach: find dependency arrays
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = False
            continue
        if re.match(r'dependencies\s*=\s*\[', stripped):
            in_deps = True
            # Check single-line case
            items = re.findall(r'"([^"]+)"', stripped)
            for item in items:
                m = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)?$", item)
                if m:
                    deps.append(DepInfo(name=m.group(1), version=m.group(2).strip() or None))
            if "]" in stripped:
                in_deps = False
            continue
        if in_deps:
            if "]" in stripped:
                in_deps = False
                continue
            items = re.findall(r'"([^"]+)"', stripped)
            for item in items:
                m = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)?$", item)
                if m:
                    deps.append(DepInfo(name=m.group(1), version=m.group(2).strip() or None))
    return deps


def _parse_cargo_toml(content: str) -> List[DepInfo]:
    """Parse Cargo.toml [dependencies] and [dev-dependencies]."""
    deps: List[DepInfo] = []
    in_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped[1:-1].strip().lower()
            in_section = section in ("dependencies", "dev-dependencies")
            continue
        if in_section and "=" in stripped:
            parts = stripped.split("=", 1)
            name = parts[0].strip()
            val = parts[1].strip()
            if val.startswith('"'):
                ver = val.strip('"')
            elif val.startswith("{"):
                m = re.search(r'version\s*=\s*"([^"]+)"', val)
                ver = m.group(1) if m else None
            else:
                ver = val.strip('"').strip("'") or None
            deps.append(DepInfo(name=name, version=ver))
    return deps


def _parse_pom_xml(content: str) -> List[DepInfo]:
    """Parse pom.xml <dependency> blocks."""
    deps: List[DepInfo] = []
    # Find each <dependency>...</dependency>
    dep_blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
    for block in dep_blocks:
        group = re.search(r"<groupId>([^<]+)</groupId>", block)
        artifact = re.search(r"<artifactId>([^<]+)</artifactId>", block)
        version = re.search(r"<version>([^<]+)</version>", block)
        if artifact:
            name = f"{group.group(1)}:{artifact.group(1)}" if group else artifact.group(1)
            deps.append(DepInfo(name=name, version=version.group(1) if version else None))
    return deps


def _parse_build_gradle(content: str) -> List[DepInfo]:
    """Parse build.gradle dependency declarations."""
    deps: List[DepInfo] = []
    # Match patterns like: implementation 'group:artifact:version'
    for m in re.finditer(
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"
        r"implementation|compile|testCompile)\s+['\"]([^'\"]+)['\"]",
        content,
    ):
        coord = m.group(1)
        parts = coord.split(":")
        if len(parts) >= 2:
            name = f"{parts[0]}:{parts[1]}"
            version = parts[2] if len(parts) >= 3 else None
            deps.append(DepInfo(name=name, version=version))
    return deps


_PARSERS = {
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "requirements.txt": _parse_requirements_txt,
    "Pipfile": _parse_pipfile,
    "pyproject.toml": _parse_pyproject_toml,
    "Cargo.toml": _parse_cargo_toml,
    "pom.xml": _parse_pom_xml,
    "build.gradle": _parse_build_gradle,
}


def parse_deps(file_type: str, content: str) -> List[DepInfo]:
    """Parse dependency content for the given file type.

    Args:
        file_type: One of the supported dependency file names.
        content: Raw file content string.

    Returns:
        List of DepInfo objects.
    """
    parser = _PARSERS.get(file_type)
    if parser is None:
        return []
    return parser(content)


def compare_deps(
    old_deps: List[DepInfo],
    new_deps: List[DepInfo],
) -> Tuple[List[DepDiff], List[DepDiff], List[DepDiff], List[DepDiff]]:
    """Compare old and new dependency lists.

    Returns:
        Tuple of (added, removed, upgraded, downgraded) DepDiff lists.
    """
    old_map: Dict[str, Optional[str]] = {d.name: d.version for d in old_deps}
    new_map: Dict[str, Optional[str]] = {d.name: d.version for d in new_deps}

    added: List[DepDiff] = []
    removed: List[DepDiff] = []
    upgraded: List[DepDiff] = []
    downgraded: List[DepDiff] = []

    # Check new deps
    for name, new_ver in new_map.items():
        if name not in old_map:
            added.append(DepDiff(
                name=name, change_type="added",
                old_version=None, new_version=new_ver,
            ))
        else:
            old_ver = old_map[name]
            cmp = _compare_versions(old_ver, new_ver)
            if cmp < 0:
                upgraded.append(DepDiff(
                    name=name, change_type="upgraded",
                    old_version=old_ver, new_version=new_ver,
                ))
            elif cmp > 0:
                downgraded.append(DepDiff(
                    name=name, change_type="downgraded",
                    old_version=old_ver, new_version=new_ver,
                ))

    # Check removed deps
    for name, old_ver in old_map.items():
        if name not in new_map:
            removed.append(DepDiff(
                name=name, change_type="removed",
                old_version=old_ver, new_version=None,
            ))

    return added, removed, upgraded, downgraded


def scan_dependency_changes(
    file_path: str,
    old_content: str,
    new_content: str,
) -> Optional[DependencyChange]:
    """Scan a dependency file for changes between old and new content.

    Args:
        file_path: Path of the dependency file.
        old_content: Old file content (empty string if new file).
        new_content: New file content (empty string if deleted file).

    Returns:
        DependencyChange or None if file is not a known dependency file.
    """
    file_type = _detect_file_type(file_path)
    if file_type is None:
        return None

    old_deps = parse_deps(file_type, old_content) if old_content else []
    new_deps = parse_deps(file_type, new_content) if new_content else []

    added, removed, upgraded, downgraded = compare_deps(old_deps, new_deps)

    change = DependencyChange(
        file_path=file_path,
        file_type=file_type,
        added=added,
        removed=removed,
        upgraded=upgraded,
        downgraded=downgraded,
    )

    return change if change.total_changes > 0 else None
