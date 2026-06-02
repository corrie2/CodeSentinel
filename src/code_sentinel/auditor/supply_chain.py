"""Supply chain audit — CVE scanning via OSV API."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
ECOSYSTEMS = {"npm", "PyPI", "Go", "crates.io", "Maven", "NuGet", "RubyGems", "Packagist"}


@dataclass
class VulnerableDep:
    """A dependency with known vulnerabilities."""

    package: str
    version: str
    ecosystem: str
    vuln_id: str
    summary: str
    severity: str
    fixed_version: str | None

    @property
    def display_severity(self) -> str:
        return self.severity or "UNKNOWN"


@dataclass
class DeprecatedDep:
    """A dependency that is deprecated or unmaintained."""

    package: str
    ecosystem: str
    reason: str


@dataclass
class LicenseIssue:
    """A dependency with a problematic license."""

    package: str
    ecosystem: str
    license: str
    risk: str  # e.g. "copyleft", "unknown", "restrictive"


@dataclass
class SupplyChainReport:
    """Aggregated supply chain audit result."""

    total_deps: int = 0
    vulnerable_deps: list[VulnerableDep] = field(default_factory=list)
    deprecated_deps: list[DeprecatedDep] = field(default_factory=list)
    license_issues: list[LicenseIssue] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def vulnerable_count(self) -> int:
        return len(self.vulnerable_deps)

    @property
    def has_issues(self) -> bool:
        return bool(self.vulnerable_deps or self.deprecated_deps or self.license_issues)


@dataclass
class PackageQuery:
    """A package to query for vulnerabilities."""

    name: str
    version: str
    ecosystem: str


def _parse_vuln(vuln: dict[str, Any]) -> tuple[str, str, str, str | None]:
    """Extract vuln_id, summary, severity, fixed_version from an OSV response entry."""
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = vuln.get("summary", vuln.get("details", "")[:200])
    severity = ""
    fixed_version = None

    # Extract severity from database_specific or severity array
    severity_list = vuln.get("severity", [])
    if severity_list:
        severity = severity_list[0].get("score", "")
    db_specific = vuln.get("database_specific", {})
    if not severity and "severity" in db_specific:
        severity = db_specific["severity"]

    # Extract fixed version from affected ranges
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed_version = event["fixed"]
                    break

    return vuln_id, summary, severity, fixed_version


async def _query_single(
    client: httpx.AsyncClient,
    pkg: PackageQuery,
    semaphore: asyncio.Semaphore,
) -> list[VulnerableDep]:
    """Query OSV for a single package and return vulnerable deps."""
    payload: dict[str, Any] = {
        "package": {
            "name": pkg.name,
            "ecosystem": pkg.ecosystem,
        },
        "version": pkg.version,
    }

    async with semaphore:
        try:
            resp = await client.post(OSV_QUERY_URL, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            return []  # skip packages that 404 or error
        except Exception:
            return []

    results: list[VulnerableDep] = []
    for vuln in data.get("vulns", []):
        vuln_id, summary, severity, fixed_version = _parse_vuln(vuln)
        results.append(
            VulnerableDep(
                package=pkg.name,
                version=pkg.version,
                ecosystem=pkg.ecosystem,
                vuln_id=vuln_id,
                summary=summary,
                severity=severity,
                fixed_version=fixed_version,
            )
        )
    return results


async def query_osv_batch(packages: list[PackageQuery]) -> list[VulnerableDep]:
    """Query OSV for multiple packages in parallel (max 10 concurrent)."""
    semaphore = asyncio.Semaphore(10)
    async with httpx.AsyncClient() as client:
        tasks = [_query_single(client, pkg, semaphore) for pkg in packages]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_vulns: list[VulnerableDep] = []
    for result in results:
        if isinstance(result, list):
            all_vulns.extend(result)
    return all_vulns


def _detect_ecosystem(filename: str) -> str | None:
    """Guess ecosystem from a manifest/lockfile name."""
    mapping = {
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "pnpm-lock.yaml": "npm",
        "package.json": "npm",
        "requirements.txt": "PyPI",
        "Pipfile.lock": "PyPI",
        "pyproject.toml": "PyPI",
        "setup.py": "PyPI",
        "go.sum": "Go",
        "go.mod": "Go",
        "Cargo.lock": "crates.io",
        "Cargo.toml": "crates.io",
        "Gemfile.lock": "RubyGems",
        "pom.xml": "Maven",
        "build.gradle": "Maven",
        "*.csproj": "NuGet",
    }
    for pattern, ecosystem in mapping.items():
        if pattern.startswith("*"):
            if filename.endswith(pattern[1:]):
                return ecosystem
        elif filename == pattern:
            return ecosystem
    return None


def _parse_requirements(content: str, ecosystem: str) -> list[PackageQuery]:
    """Parse dependency lines into PackageQuery objects (MVP: supports PyPI requirements.txt)."""
    packages: list[PackageQuery] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle "name==version" or "name>=version"
        for sep in ("==", ">="):
            if sep in line:
                name, version = line.split(sep, 1)
                packages.append(PackageQuery(
                    name=name.strip(),
                    version=version.split(";")[0].strip().strip('"').strip("'"),
                    ecosystem=ecosystem,
                ))
                break
    return packages


def _parse_package_json(content: str) -> list[PackageQuery]:
    """Parse package.json deps into PackageQuery objects."""
    import json

    packages: list[PackageQuery] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            # Strip leading ^ or ~
            clean_version = version.lstrip("^~>=<")
            packages.append(PackageQuery(
                name=name,
                version=clean_version,
                ecosystem="npm",
            ))
    return packages


def parse_manifest(filename: str, content: str) -> list[PackageQuery]:
    """Parse a manifest/lockfile into PackageQuery objects."""
    if filename == "package.json":
        return _parse_package_json(content)
    ecosystem = _detect_ecosystem(filename)
    if ecosystem and ecosystem == "PyPI":
        return _parse_requirements(content, ecosystem)
    # For other ecosystems, return empty (MVP)
    return []


async def run_supply_chain_audit(
    changed_files: list[dict[str, Any]] | None = None,
    packages: list[PackageQuery] | None = None,
) -> SupplyChainReport:
    """
    Run a supply chain audit.

    Either provide explicit packages or changed_files with manifest content.
    changed_files: list of dicts with 'filename' and 'content' keys.
    """
    if packages is None:
        packages = []

    if changed_files:
        for f in changed_files:
            filename = f.get("filename", "")
            content = f.get("content", "")
            if content:
                packages.extend(parse_manifest(filename, content))

    report = SupplyChainReport(total_deps=len(packages))

    if not packages:
        return report

    try:
        vulns = await query_osv_batch(packages)
        report.vulnerable_deps = vulns
    except Exception as exc:
        report.errors.append(f"OSV query failed: {exc}")

    return report
