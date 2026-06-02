"""Scan dependency files and detect dependency changes between old and new versions.

3-layer architecture:
  Layer 1 (detect): scan_diff_for_dep_files - identify dependency manifest files
  Layer 2 (parse patch): parse_dep_changes_from_patch - extract changes from unified diff
  Layer 3 (full diff): compute_dep_diff - precise comparison with full file content
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEP_FILE_NAMES: set[str] = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "poetry.lock",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
}

# Maps manifest filename -> ecosystem
_ECOSYSTEM_MAP: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "go.mod": "go",
    "go.sum": "go",
    "requirements.txt": "pypi",
    "Pipfile": "pypi",
    "pyproject.toml": "pypi",
    "poetry.lock": "pypi",
    "Cargo.toml": "cargo",
    "pom.xml": "maven",
    "build.gradle": "gradle",
}

ChangeType = Literal['added', 'removed', 'version_changed', 'metadata_changed', 'unknown_changed']
Direction = Literal['upgraded', 'downgraded', 'unknown', 'not_applicable']
Confidence = Literal['high', 'medium', 'low']

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class DepChange:
    """A single dependency change detected between two versions."""
    package: str
    ecosystem: str        # npm, pypi, go, cargo, maven, gradle
    change_type: ChangeType
    direction: Direction
    old_spec: str | None
    new_spec: str | None
    confidence: Confidence


@dataclass
class PackageQuery:
    """Package reference for supply-chain integration."""
    name: str
    version: str | None
    ecosystem: str


# ---------------------------------------------------------------------------
# Semver helpers
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[.\-]([a-zA-Z0-9.]+))?")

def _parse_semver(v: str | None) -> tuple[int, ...] | None:
    """Parse a semver-like string into a tuple of ints for comparison."""
    if not v:
        return None
    clean = v.lstrip("~^>=<! *@")
    m = _SEMVER_RE.search(clean)
    if not m:
        return None
    parts = [int(m.group(i) or 0) for i in range(1, 5)]
    # pre-release gets a penalty so 1.0.0-alpha < 1.0.0
    has_prerelease = parts[3] > 0 or bool(m.group(4) and not m.group(4).isdigit())
    return (parts[0], parts[1], parts[2], 0 if has_prerelease else 1)

def _compare_versions(v1: str | None, v2: str | None) -> int:
    """Compare two semver-like version strings.
    Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
    Falls back to lexicographic comparison for non-semver.
    """
    if v1 is None:
        return -1
    if v2 is None:
        return 1
    p1 = _parse_semver(v1)
    p2 = _parse_semver(v2)
    if p1 is not None and p2 is not None:
        maxlen = max(len(p1), len(p2))
        a = p1 + (0,) * (maxlen - len(p1))
        b = p2 + (0,) * (maxlen - len(p2))
        for x, y in zip(a, b):
            if x < y:
                return -1
            if x > y:
                return 1
        return 0
    # Fallback: strip prefix, lexicographic
    c1 = v1.lstrip("~^>=<! ")
    c2 = v2.lstrip("~^>=<! ")
    return -1 if c1 < c2 else (1 if c1 > c2 else 0)

def _determine_direction(old_spec: str | None, new_spec: str | None) -> Direction:
    """Determine upgrade/downgrade direction from two version specs."""
    if old_spec is None and new_spec is not None:
        return "not_applicable"
    if old_spec is not None and new_spec is None:
        return "not_applicable"
    if old_spec is None and new_spec is None:
        return "unknown"
    cmp = _compare_versions(old_spec, new_spec)
    if cmp < 0:
        return "upgraded"
    if cmp > 0:
        return "downgraded"
    return "unknown"


# ---------------------------------------------------------------------------
# Layer 1: Detect dependency manifest files from diff file list
# ---------------------------------------------------------------------------

def detect_ecosystem(filename: str) -> str:
    """Return the ecosystem string for a known dependency manifest filename.
    Returns 'unknown' if the file is not a recognized manifest.
    """
    basename = filename.rsplit("/", 1)[-1]
    return _ECOSYSTEM_MAP.get(basename, "unknown")


def scan_diff_for_dep_files(file_changes: list) -> list[str]:
    """Layer 1: Pure detection of dependency manifest files.

    Args:
        file_changes: List of FileInfo objects (or anything with a .filename attribute)
                      from diff_parser.

    Returns:
        List of filenames that are recognized dependency manifests.
    """
    result: list[str] = []
    for fc in file_changes:
        fname = getattr(fc, "filename", None) or getattr(fc, "path", None) or str(fc)
        basename = fname.rsplit("/", 1)[-1]
        if basename in DEP_FILE_NAMES:
            result.append(fname)
    return result


# ---------------------------------------------------------------------------
# Unified-diff line helpers
# ---------------------------------------------------------------------------

def _split_patch_lines(patch_text: str) -> tuple[list[str], list[str]]:
    """Split a unified diff patch into added and removed lines.

    Returns (added_lines, removed_lines) where each line has the +/- prefix stripped.
    Comment lines (--- / +++) file headers are excluded.
    """
    added: list[str] = []
    removed: list[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    return added, removed


# ---------------------------------------------------------------------------
# Layer 2: Parse dependency changes from a patch (unified diff text)
# ---------------------------------------------------------------------------

def parse_dep_changes_from_patch(filename: str, patch_text: str) -> list[DepChange]:
    """Layer 2: Extract dependency changes from a unified diff patch.

    Args:
        filename: The file path (used to determine ecosystem/format).
        patch_text: The raw unified diff text from GitHub.

    Returns:
        List of DepChange with confidence='high' for simple adds/removes,
        'medium' for version changes, 'low' when ambiguous.
    """
    basename = filename.rsplit("/", 1)[-1]
    added, removed = _split_patch_lines(patch_text)
    if not added and not removed:
        return []

    if basename == "package.json":
        return _patch_package_json(added, removed)
    elif basename in ("requirements.txt",):
        return _patch_requirements_txt(added, removed)
    elif basename == "go.mod":
        return _patch_go_mod(added, removed)
    elif basename == "Cargo.toml":
        return _patch_cargo_toml(added, removed)
    elif basename in ("Pipfile",):
        return _patch_pipfile(added, removed)
    elif basename == "pyproject.toml":
        return _patch_pyproject_toml(added, removed)
    elif basename == "pom.xml":
        return _patch_pom_xml(added, removed)
    elif basename == "build.gradle":
        return _patch_build_gradle(added, removed)
    else:
        # Lock files / unknown: treat as metadata, low confidence
        ecosystem = detect_ecosystem(filename)
        changes: list[DepChange] = []
        for line in added:
            changes.append(DepChange(
                package=line.strip()[:60],
                ecosystem=ecosystem,
                change_type="metadata_changed",
                direction="not_applicable",
                old_spec=None,
                new_spec=None,
                confidence="low",
            ))
        return changes


def _patch_package_json(added: list[str], removed: list[str]) -> list[DepChange]:
    """Parse package.json patch: look for JSON key-value additions/removals."""
    changes: list[DepChange] = []
    dep_re = re.compile(r'"([^"]+)"\s*:\s*"([^"]*)"')
    added_deps: dict[str, str] = {}
    removed_deps: dict[str, str] = {}
    for line in added:
        m = dep_re.search(line)
        if m:
            added_deps[m.group(1)] = m.group(2)
    for line in removed:
        m = dep_re.search(line)
        if m:
            removed_deps[m.group(1)] = m.group(2)
    all_names = set(added_deps) | set(removed_deps)
    for name in all_names:
        new_v = added_deps.get(name)
        old_v = removed_deps.get(name)
        if old_v is None and new_v is not None:
            changes.append(DepChange(
                package=name, ecosystem="npm", change_type="added",
                direction="not_applicable", old_spec=None, new_spec=new_v,
                confidence="high",
            ))
        elif old_v is not None and new_v is None:
            changes.append(DepChange(
                package=name, ecosystem="npm", change_type="removed",
                direction="not_applicable", old_spec=old_v, new_spec=None,
                confidence="high",
            ))
        elif old_v is not None and new_v is not None and old_v != new_v:
            d = _determine_direction(old_v, new_v)
            changes.append(DepChange(
                package=name, ecosystem="npm", change_type="version_changed",
                direction=d, old_spec=old_v, new_spec=new_v,
                confidence="medium",
            ))
    return changes


def _patch_requirements_txt(added: list[str], removed: list[str]) -> list[DepChange]:
    """Parse requirements.txt patch lines."""
    pkg_re = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(.*)?$")
    added_pkgs: dict[str, str | None] = {}
    removed_pkgs: dict[str, str | None] = {}
    for line in added:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = pkg_re.match(line)
        if m:
            added_pkgs[m.group(1)] = m.group(2).strip() if m.group(2) else None
    for line in removed:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = pkg_re.match(line)
        if m:
            removed_pkgs[m.group(1)] = m.group(2).strip() if m.group(2) else None
    changes: list[DepChange] = []
    all_names = set(added_pkgs) | set(removed_pkgs)
    for name in all_names:
        new_v = added_pkgs.get(name)
        old_v = removed_pkgs.get(name)
        if old_v is None and new_v is not None:
            changes.append(DepChange(
                package=name, ecosystem="pypi", change_type="added",
                direction="not_applicable", old_spec=None, new_spec=new_v,
                confidence="high",
            ))
        elif old_v is not None and new_v is None:
            changes.append(DepChange(
                package=name, ecosystem="pypi", change_type="removed",
                direction="not_applicable", old_spec=old_v, new_spec=None,
                confidence="high",
            ))
        elif old_v is not None and new_v is not None and old_v != new_v:
            d = _determine_direction(old_v, new_v)
            changes.append(DepChange(
                package=name, ecosystem="pypi", change_type="version_changed",
                direction=d, old_spec=old_v, new_spec=new_v,
                confidence="medium",
            ))
    return changes


_go_mod_line_re = re.compile(r"^\s*(\S+)\s+(v[\w.+\-]+)")

def _patch_go_mod(added: list[str], removed: list[str]) -> list[DepChange]:
    """Parse go.mod require block patch lines."""
    added_deps: dict[str, str] = {}
    removed_deps: dict[str, str] = {}
    for line in added:
        m = _go_mod_line_re.match(line)
        if m:
            added_deps[m.group(1)] = m.group(2)
    for line in removed:
        m = _go_mod_line_re.match(line)
        if m:
            removed_deps[m.group(1)] = m.group(2)
    changes: list[DepChange] = []
    all_names = set(added_deps) | set(removed_deps)
    for name in all_names:
        new_v = added_deps.get(name)
        old_v = removed_deps.get(name)
        if old_v is None and new_v is not None:
            changes.append(DepChange(
                package=name, ecosystem="go", change_type="added",
                direction="not_applicable", old_spec=None, new_spec=new_v,
                confidence="high",
            ))
        elif old_v is not None and new_v is None:
            changes.append(DepChange(
                package=name, ecosystem="go", change_type="removed",
                direction="not_applicable", old_spec=old_v, new_spec=None,
                confidence="high",
            ))
        elif old_v is not None and new_v is not None and old_v != new_v:
            d = _determine_direction(old_v, new_v)
            changes.append(DepChange(
                package=name, ecosystem="go", change_type="version_changed",
                direction=d, old_spec=old_v, new_spec=new_v,
                confidence="medium",
            ))
    return changes


_cargo_line_re = re.compile(r'^([A-Za-z0-9_\-]+)\s*=\s*(?:"([^"]*)"|.*version\s*=\s*"([^"]*)")')

def _patch_cargo_toml(added: list[str], removed: list[str]) -> list[DepChange]:
    """Parse Cargo.toml patch lines."""
    added_deps: dict[str, str | None] = {}
    removed_deps: dict[str, str | None] = {}
    for line in added:
        m = _cargo_line_re.search(line)
        if m:
            added_deps[m.group(1)] = m.group(2) or m.group(3)
    for line in removed:
        m = _cargo_line_re.search(line)
        if m:
            removed_deps[m.group(1)] = m.group(2) or m.group(3)
    changes: list[DepChange] = []
    all_names = set(added_deps) | set(removed_deps)
    for name in all_names:
        new_v = added_deps.get(name)
        old_v = removed_deps.get(name)
        if old_v is None and new_v is not None:
            changes.append(DepChange(
                package=name, ecosystem="cargo", change_type="added",
                direction="not_applicable", old_spec=None, new_spec=new_v,
                confidence="high",
            ))
        elif old_v is not None and new_v is None:
            changes.append(DepChange(
                package=name, ecosystem="cargo", change_type="removed",
                direction="not_applicable", old_spec=old_v, new_spec=None,
                confidence="high",
            ))
        elif old_v is not None and new_v is not None and old_v != new_v:
            d = _determine_direction(old_v, new_v)
            changes.append(DepChange(
                package=name, ecosystem="cargo", change_type="version_changed",
                direction=d, old_spec=old_v, new_spec=new_v,
                confidence="medium",
            ))
    return changes


def _patch_pipfile(added: list[str], removed: list[str]) -> list[DepChange]:
    """Parse Pipfile patch lines."""
    eq_re = re.compile(r'^"?([A-Za-z0-9_.\-]+)"?\s*=\s*"?([^"]*)"?')
    added_deps: dict[str, str | None] = {}
    removed_deps: dict[str, str | None] = {}
    for line in added:
        m = eq_re.search(line)
        if m:
            ver = m.group(2).strip()
            added_deps[m.group(1)] = ver if ver and ver != "*" else None
    for line in removed:
        m = eq_re.search(line)
        if m:
            ver = m.group(2).strip()
            removed_deps[m.group(1)] = ver if ver and ver != "*" else None
    changes: list[DepChange] = []
    all_names = set(added_deps) | set(removed_deps)
    for name in all_names:
        new_v = added_deps.get(name)
        old_v = removed_deps.get(name)
        if old_v is None and new_v is not None:
            changes.append(DepChange(
                package=name, ecosystem="pypi", change_type="added",
                direction="not_applicable", old_spec=None, new_spec=new_v,
                confidence="high",
            ))
        elif old_v is not None and new_v is None:
            changes.append(DepChange(
                package=name, ecosystem="pypi", change_type="removed",
                direction="not_applicable", old_spec=old_v, new_spec=None,
                confidence="high",
            ))
        elif old_v is not None and new_v is not None and old_v != new_v:
            d = _determine_direction(old_v, new_v)
            changes.append(DepChange(
                package=name, ecosystem="pypi", change_type="version_changed",
                direction=d, old_spec=old_v, new_spec=new_v,
                confidence="medium",
            ))
    return changes


_pyproject_dep_re = re.compile(r'"([A-Za-z0-9_.\-]+)\s*([^"]*)"')

def _patch_pyproject_toml(added: list[str], removed: list[str]) -> list[DepChange]:
    """Parse pyproject.toml patch lines."""
    def _extract(line: str) -> tuple[str, str | None] | None:
        m = _pyproject_dep_re.search(line)
        if m:
            ver = m.group(2).strip()
            return (m.group(1), ver or None)
        return None

    added_deps: dict[str, str | None] = {}
    removed_deps: dict[str, str | None] = {}
    for line in added:
        r = _extract(line)
        if r:
            added_deps[r[0]] = r[1]
    for line in removed:
        r = _extract(line)
        if r:
            removed_deps[r[0]] = r[1]
    changes: list[DepChange] = []
    all_names = set(added_deps) | set(removed_deps)
    for name in all_names:
        new_v = added_deps.get(name)
        old_v = removed_deps.get(name)
        if old_v is None and new_v is not None:
            changes.append(DepChange(
                package=name, ecosystem="pypi", change_type="added",
                direction="not_applicable", old_spec=None, new_spec=new_v,
                confidence="high",
            ))
        elif old_v is not None and new_v is None:
            changes.append(DepChange(
                package=name, ecosystem="pypi", change_type="removed",
                direction="not_applicable", old_spec=old_v, new_spec=None,
                confidence="high",
            ))
        elif old_v is not None and new_v is not None and old_v != new_v:
            d = _determine_direction(old_v, new_v)
            changes.append(DepChange(
                package=name, ecosystem="pypi", change_type="version_changed",
                direction=d, old_spec=old_v, new_spec=new_v,
                confidence="medium",
            ))
    return changes


_pom_ver_re = re.compile(r"<version>([^<]+)</version>")
_pom_artifact_re = re.compile(r"<artifactId>([^<]+)</artifactId>")
_pom_group_re = re.compile(r"<groupId>([^<]+)</groupId>")

def _patch_pom_xml(added: list[str], removed: list[str]) -> list[DepChange]:
    """Parse pom.xml patch lines. Simplified: extract version/artifact from diff lines."""
    # This is a simplified heuristic since pom.xml dependency blocks span multiple lines.
    # We look for version changes on removed/added lines near <dependency> blocks.
    added_versions: dict[str, str] = {}
    removed_versions: dict[str, str] = {}
    for line in added:
        m = _pom_ver_re.search(line)
        if m:
            added_versions["__pending__"] = m.group(1)
    for line in removed:
        m = _pom_ver_re.search(line)
        if m:
            removed_versions["__pending__"] = m.group(1)
    # For pom.xml, patch-level parsing is inherently low-confidence
    changes: list[DepChange] = []
    for line in added:
        m = _pom_artifact_re.search(line)
        if m:
            changes.append(DepChange(
                package=m.group(1), ecosystem="maven", change_type="added",
                direction="not_applicable", old_spec=None, new_spec=None,
                confidence="low",
            ))
    for line in removed:
        m = _pom_artifact_re.search(line)
        if m:
            changes.append(DepChange(
                package=m.group(1), ecosystem="maven", change_type="removed",
                direction="not_applicable", old_spec=None, new_spec=None,
                confidence="low",
            ))
    return changes


_gradle_dep_re = re.compile(r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|compile|testCompile)\s+['"]([^'"]+)['"]""")

def _patch_build_gradle(added: list[str], removed: list[str]) -> list[DepChange]:
    """Parse build.gradle patch lines."""
    added_deps: dict[str, str | None] = {}
    removed_deps: dict[str, str | None] = {}
    for line in added:
        m = _gradle_dep_re.search(line)
        if m:
            coord = m.group(1)
            parts = coord.split(":")
            name = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else parts[0]
            version = parts[2] if len(parts) >= 3 else None
            added_deps[name] = version
    for line in removed:
        m = _gradle_dep_re.search(line)
        if m:
            coord = m.group(1)
            parts = coord.split(":")
            name = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else parts[0]
            version = parts[2] if len(parts) >= 3 else None
            removed_deps[name] = version
    changes: list[DepChange] = []
    all_names = set(added_deps) | set(removed_deps)
    for name in all_names:
        new_v = added_deps.get(name)
        old_v = removed_deps.get(name)
        if old_v is None and new_v is not None:
            changes.append(DepChange(
                package=name, ecosystem="gradle", change_type="added",
                direction="not_applicable", old_spec=None, new_spec=new_v,
                confidence="high",
            ))
        elif old_v is not None and new_v is None:
            changes.append(DepChange(
                package=name, ecosystem="gradle", change_type="removed",
                direction="not_applicable", old_spec=old_v, new_spec=None,
                confidence="high",
            ))
        elif old_v is not None and new_v is not None and old_v != new_v:
            d = _determine_direction(old_v, new_v)
            changes.append(DepChange(
                package=name, ecosystem="gradle", change_type="version_changed",
                direction=d, old_spec=old_v, new_spec=new_v,
                confidence="medium",
            ))
    return changes


# ---------------------------------------------------------------------------
# Layer 3: Full-content diff (precise comparison with semver parsing)
# ---------------------------------------------------------------------------

def _parse_package_json_full(content: str) -> dict[str, str]:
    """Parse package.json dependencies + devDependencies + peerDependencies."""
    deps: dict[str, str] = {}
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        section_deps = data.get(section, {})
        if isinstance(section_deps, dict):
            for name, ver in section_deps.items():
                deps[name] = str(ver)
    return deps


def _parse_go_mod_full(content: str) -> dict[str, str]:
    """Parse go.mod require block."""
    deps: dict[str, str] = {}
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require"):
            if "(" in stripped:
                in_require = True
            else:
                parts = stripped.split()
                if len(parts) >= 3:
                    deps[parts[1]] = parts[2]
            continue
        if in_require:
            if stripped == ")":
                in_require = False
                continue
            if stripped and not stripped.startswith("//"):
                parts = stripped.split()
                if len(parts) >= 2:
                    deps[parts[0]] = parts[1]
    return deps


def _parse_requirements_txt_full(content: str) -> dict[str, str]:
    """Parse requirements.txt format."""
    deps: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)?$", line)
        if m:
            name = re.sub(r"\[.*\]", "", m.group(1))
            version = m.group(2).strip() if m.group(2) else ""
            deps[name] = version
    return deps


def _parse_pipfile_full(content: str) -> dict[str, str]:
    """Parse Pipfile [packages] and [dev-packages] sections."""
    deps: dict[str, str] = {}
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
            deps[name] = ver_raw if ver_raw != "*" else ""
    return deps


def _parse_pyproject_toml_full(content: str) -> dict[str, str]:
    """Parse pyproject.toml dependencies (regex-based, no toml dep required)."""
    deps: dict[str, str] = {}
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = False
            continue
        if re.match(r'dependencies\s*=\s*\[', stripped):
            in_deps = True
            items = re.findall(r'"([^"]+)"', stripped)
            for item in items:
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)?$", item)
                if m:
                    deps[m.group(1)] = m.group(2).strip()
            if "]" in stripped:
                in_deps = False
            continue
        if in_deps:
            if "]" in stripped:
                in_deps = False
                continue
            items = re.findall(r'"([^"]+)"', stripped)
            for item in items:
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)?$", item)
                if m:
                    deps[m.group(1)] = m.group(2).strip()
    return deps


def _parse_cargo_toml_full(content: str) -> dict[str, str]:
    """Parse Cargo.toml [dependencies] and [dev-dependencies]."""
    deps: dict[str, str] = {}
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
                ver = m.group(1) if m else ""
            else:
                ver = val.strip('"').strip("'")
            deps[name] = ver
    return deps


def _parse_pom_xml_full(content: str) -> dict[str, str]:
    """Parse pom.xml <dependency> blocks."""
    deps: dict[str, str] = {}
    dep_blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
    for block in dep_blocks:
        group = re.search(r"<groupId>([^<]+)</groupId>", block)
        artifact = re.search(r"<artifactId>([^<]+)</artifactId>", block)
        version = re.search(r"<version>([^<]+)</version>", block)
        if artifact:
            name = f"{group.group(1)}:{artifact.group(1)}" if group else artifact.group(1)
            deps[name] = version.group(1) if version else ""
    return deps


def _parse_build_gradle_full(content: str) -> dict[str, str]:
    """Parse build.gradle dependency declarations."""
    deps: dict[str, str] = {}
    for m in re.finditer(
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"
        r"compile|testCompile)\s+['\"]([^'\"]+)['\"]",
        content,
    ):
        coord = m.group(1)
        parts = coord.split(":")
        if len(parts) >= 2:
            name = f"{parts[0]}:{parts[1]}"
            version = parts[2] if len(parts) >= 3 else ""
            deps[name] = version
    return deps


_FULL_PARSERS = {
    "package.json": _parse_package_json_full,
    "go.mod": _parse_go_mod_full,
    "requirements.txt": _parse_requirements_txt_full,
    "Pipfile": _parse_pipfile_full,
    "pyproject.toml": _parse_pyproject_toml_full,
    "Cargo.toml": _parse_cargo_toml_full,
    "pom.xml": _parse_pom_xml_full,
    "build.gradle": _parse_build_gradle_full,
}


def compute_dep_diff(
    filename: str,
    old_content: str,
    new_content: str,
) -> list[DepChange]:
    """Layer 3: Precise dependency diff using full file content with semver parsing.

    Only called when Layer 2 confidence is 'low' or caller explicitly requests it.
    Returns DepChange items with confidence='high'.
    """
    basename = filename.rsplit("/", 1)[-1]
    parser = _FULL_PARSERS.get(basename)
    if parser is None:
        return []

    old_deps = parser(old_content) if old_content else {}
    new_deps = parser(new_content) if new_content else {}
    ecosystem = detect_ecosystem(filename)

    changes: list[DepChange] = []
    all_names = set(old_deps) | set(new_deps)

    for name in sorted(all_names):
        old_v = old_deps.get(name)
        new_v = new_deps.get(name)

        if old_v is None and new_v is not None:
            changes.append(DepChange(
                package=name, ecosystem=ecosystem, change_type="added",
                direction="not_applicable", old_spec=None, new_spec=new_v,
                confidence="high",
            ))
        elif old_v is not None and new_v is None:
            changes.append(DepChange(
                package=name, ecosystem=ecosystem, change_type="removed",
                direction="not_applicable", old_spec=old_v, new_spec=None,
                confidence="high",
            ))
        elif old_v is not None and new_v is not None and old_v != new_v:
            d = _determine_direction(old_v, new_v)
            changes.append(DepChange(
                package=name, ecosystem=ecosystem, change_type="version_changed",
                direction=d, old_spec=old_v, new_spec=new_v,
                confidence="high",
            ))

    return changes


# ---------------------------------------------------------------------------
# Manifest parsing for supply-chain integration
# ---------------------------------------------------------------------------

_MANIFEST_PARSERS = {
    "package.json": _parse_package_json_full,
    "go.mod": _parse_go_mod_full,
    "requirements.txt": _parse_requirements_txt_full,
    "Pipfile": _parse_pipfile_full,
    "pyproject.toml": _parse_pyproject_toml_full,
    "Cargo.toml": _parse_cargo_toml_full,
    "pom.xml": _parse_pom_xml_full,
    "build.gradle": _parse_build_gradle_full,
}


def parse_manifest(filename: str, content: str) -> list[PackageQuery]:
    """Parse a dependency manifest file into PackageQuery objects.

    Used by supply_chain integration.
    """
    basename = filename.rsplit("/", 1)[-1]
    ecosystem = detect_ecosystem(filename)
    parser = _MANIFEST_PARSERS.get(basename)
    if parser is None:
        return []
    deps = parser(content)
    return [
        PackageQuery(name=name, version=ver or None, ecosystem=ecosystem)
        for name, ver in deps.items()
    ]


# ---------------------------------------------------------------------------
# Backward-compatible aliases (DO NOT REMOVE - used by __init__.py and other modules)
# ---------------------------------------------------------------------------

from dataclasses import dataclass as _dc, field as _field  # noqa: E402
from typing import Optional as _Opt, Tuple as _Tuple  # noqa: E402

DEP_FILES: list[str] = sorted(DEP_FILE_NAMES)


@_dc
class DepInfo:
    """A single dependency with name and version (backward-compat)."""
    name: str
    version: _Opt[str] = None


@_dc
class DepDiff:
    """A single dependency change (backward-compat)."""
    name: str
    change_type: str  # "added", "removed", "upgraded", "downgraded"
    old_version: _Opt[str] = None
    new_version: _Opt[str] = None


@_dc
class DependencyChange:
    """Aggregated dependency changes across all detected files (backward-compat)."""
    file_path: str
    file_type: str
    added: list[DepDiff] = _field(default_factory=list)
    removed: list[DepDiff] = _field(default_factory=list)
    upgraded: list[DepDiff] = _field(default_factory=list)
    downgraded: list[DepDiff] = _field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.upgraded) + len(self.downgraded)

    @property
    def has_new_deps(self) -> bool:
        return len(self.added) > 0


_COMPAT_PARSERS = {
    "package.json": _parse_package_json_full,
    "go.mod": _parse_go_mod_full,
    "requirements.txt": _parse_requirements_txt_full,
    "Pipfile": _parse_pipfile_full,
    "pyproject.toml": _parse_pyproject_toml_full,
    "Cargo.toml": _parse_cargo_toml_full,
    "pom.xml": _parse_pom_xml_full,
    "build.gradle": _parse_build_gradle_full,
}


def parse_deps(file_type: str, content: str) -> list[DepInfo]:
    """Parse dependency content for the given file type (backward-compat)."""
    parser = _COMPAT_PARSERS.get(file_type)
    if parser is None:
        return []
    deps = parser(content)
    return [DepInfo(name=n, version=v or None) for n, v in deps.items()]


def compare_deps(
    old_deps: list[DepInfo],
    new_deps: list[DepInfo],
) -> _Tuple[list[DepDiff], list[DepDiff], list[DepDiff], list[DepDiff]]:
    """Compare old and new dependency lists (backward-compat)."""
    old_map: dict[str, _Opt[str]] = {d.name: d.version for d in old_deps}
    new_map: dict[str, _Opt[str]] = {d.name: d.version for d in new_deps}

    added: list[DepDiff] = []
    removed: list[DepDiff] = []
    upgraded: list[DepDiff] = []
    downgraded: list[DepDiff] = []

    for name, new_ver in new_map.items():
        if name not in old_map:
            added.append(DepDiff(name=name, change_type="added", old_version=None, new_version=new_ver))
        else:
            old_ver = old_map[name]
            cmp = _compare_versions(old_ver, new_ver)
            if cmp < 0:
                upgraded.append(DepDiff(name=name, change_type="upgraded", old_version=old_ver, new_version=new_ver))
            elif cmp > 0:
                downgraded.append(DepDiff(name=name, change_type="downgraded", old_version=old_ver, new_version=new_ver))

    for name, old_ver in old_map.items():
        if name not in new_map:
            removed.append(DepDiff(name=name, change_type="removed", old_version=old_ver, new_version=None))

    return added, removed, upgraded, downgraded


def scan_dependency_changes(
    file_path: str,
    old_content: str,
    new_content: str,
) -> _Opt[DependencyChange]:
    """Scan a dependency file for changes between old and new content (backward-compat)."""
    basename = file_path.rsplit("/", 1)[-1]
    if basename not in DEP_FILE_NAMES:
        return None

    file_type = basename
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
