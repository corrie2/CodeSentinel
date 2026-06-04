"""Custom auditor — write your own AuditorPlugin.

This example shows how to create a custom auditor that checks
for specific patterns in the codebase (e.g., SQL injection risks,
hardcoded credentials, deprecated API usage).

Usage:
    python examples/custom_auditor.py
"""

import asyncio
import time
import re
from code_sentinel import review, ReviewOptions
from code_sentinel.plugins import AuditContext, AuditResult, AuditorPlugin


class SQLInjectionAuditor(AuditorPlugin):
    """Detect potential SQL injection patterns in changed files."""

    name = "sql_injection"

    # Common SQL injection patterns
    PATTERNS = [
        (r'(?:"|\')\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\%s', "String formatting in SQL"),
        (r'(?:"|\')\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+', "String concatenation in SQL"),
        (r'f"(?:SELECT|INSERT|UPDATE|DELETE)', "F-string in SQL"),
        (r"f'(?:SELECT|INSERT|UPDATE|DELETE)", "F-string in SQL"),
        (r'\.execute\([^)]*%', "execute() with formatting"),
        (r'\.execute\([^)]*\+', "execute() with concatenation"),
    ]

    async def audit(self, context: AuditContext) -> AuditResult:
        t0 = time.monotonic()
        result = AuditResult(name=self.name)

        if not context.changeset:
            result.status = "skipped"
            result.duration_seconds = time.monotonic() - t0
            return result

        for f in context.changeset.files:
            if not hasattr(f, "patch") or not f.patch:
                continue
            for pattern, description in self.PATTERNS:
                matches = re.findall(pattern, f.patch, re.IGNORECASE)
                if matches:
                    result.findings.append({
                        "type": "sql_injection",
                        "severity": "high",
                        "file": f.path,
                        "description": f"{description} found in {f.path}",
                        "evidence": matches[0][:100],
                        "test_suggestion": f"Write a test that verifies {f.path} uses parameterized queries",
                    })

        result.status = "ok"
        result.duration_seconds = time.monotonic() - t0
        return result


class HardcodedCredentialAuditor(AuditorPlugin):
    """Detect hardcoded credentials, API keys, and secrets."""

    name = "hardcoded_credentials"

    PATTERNS = [
        (r'(?i)(?:api[_-]?key|secret|password|token)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded credential"),
        (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}', "Hardcoded bearer token"),
        (r'(?i)(?:sk|pk|ghp|gho|glpat)-[a-zA-Z0-9]{20,}', "Known API key prefix"),
    ]

    async def audit(self, context: AuditContext) -> AuditResult:
        t0 = time.monotonic()
        result = AuditResult(name=self.name)

        if not context.changeset:
            result.status = "skipped"
            result.duration_seconds = time.monotonic() - t0
            return result

        for f in context.changeset.files:
            if not hasattr(f, "patch") or not f.patch:
                continue
            # Skip test files and examples
            if "test" in f.path.lower() or "example" in f.path.lower():
                continue
            for pattern, description in self.PATTERNS:
                matches = re.findall(pattern, f.patch)
                if matches:
                    result.findings.append({
                        "type": "hardcoded_credential",
                        "severity": "critical",
                        "file": f.path,
                        "description": f"{description} in {f.path}",
                        "evidence": "***REDACTED***",
                        "test_suggestion": f"Verify {f.path} reads credentials from environment variables",
                    })

        result.status = "ok"
        result.duration_seconds = time.monotonic() - t0
        return result


async def main():
    # Use custom auditors alongside built-in ones
    result = await review(
        "https://github.com/owner/repo/pull/123",
        options=ReviewOptions(
            auditors=[
                SQLInjectionAuditor(),
                HardcodedCredentialAuditor(),
            ],
            skip_llm=True,  # Skip LLM for faster demo
        ),
    )

    print(f"Risk: {result.risk.level} ({result.risk.score} points)")
    print(f"\nAll auditor results:")
    for ar in result.agent_results:
        print(f"  {ar.name}: {ar.status} — {len(ar.findings)} findings")
        for f in ar.findings:
            print(f"    [{f.get('severity')}] {f.get('description', '')[:80]}")


if __name__ == "__main__":
    asyncio.run(main())
