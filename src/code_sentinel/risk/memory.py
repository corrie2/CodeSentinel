"""Project memory store backed by SQLite.

Maintains per-module defect density, author experience, and review history
so that risk scoring can incorporate long-term project context.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from code_sentinel.collector.git_history import (
    get_author_module_experience,
    get_module_bug_fix_ratio,
    get_module_commit_counts,
    get_recent_incidents,
)

logger = logging.getLogger(__name__)


class ProjectMemory:
    """SQLite-backed project memory for CodeSentinel.

    Stores per-module statistics derived from git history and review outcomes
    so that the risk scorer can incorporate historical defect patterns.

    Parameters
    ----------
    db_path : str
        Path to the SQLite database file.  Created automatically if absent.
    """

    def __init__(self, db_path: str = "memory.db") -> None:
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_schema()

    # ── Connection helpers ────────────────────────────────────────

    @property
    def _db(self) -> sqlite3.Connection:
        """Lazily open the SQLite connection."""
        if self._conn is None:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _ensure_schema(self) -> None:
        """Create tables if they do not exist."""
        cur = self._db.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS module_stats (
                module_path    TEXT PRIMARY KEY,
                total_commits  INTEGER NOT NULL DEFAULT 0,
                bug_fix_count  INTEGER NOT NULL DEFAULT 0,
                defect_density REAL    NOT NULL DEFAULT 0.0,
                last_updated   TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS author_stats (
                author_email TEXT NOT NULL,
                module_path  TEXT NOT NULL,
                commit_count INTEGER NOT NULL DEFAULT 0,
                last_updated TEXT    NOT NULL,
                PRIMARY KEY (author_email, module_path)
            );

            CREATE TABLE IF NOT EXISTS review_history (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                pr_url         TEXT    NOT NULL,
                risk_level     TEXT    NOT NULL,
                triggered_rules TEXT   NOT NULL DEFAULT '',
                findings_count INTEGER NOT NULL DEFAULT 0,
                timestamp      TEXT    NOT NULL
            );
        """)
        self._db.commit()

    # ── Git history integration ───────────────────────────────────

    def update_from_git(self, repo_path: str) -> None:
        """Refresh module and author statistics from git history.

        Args:
            repo_path: Path to a local git repository.
        """
        now = datetime.now(timezone.utc).isoformat()
        cur = self._db.cursor()

        # Gather data
        commit_counts = get_module_commit_counts(repo_path, months=6)
        bug_fix_ratios = get_module_bug_fix_ratio(repo_path, months=6)

        # Upsert module_stats
        for module, total_commits in commit_counts.items():
            ratio = bug_fix_ratios.get(module, 0.0)
            bug_fix_count = int(total_commits * ratio)
            cur.execute(
                """
                INSERT INTO module_stats
                    (module_path, total_commits, bug_fix_count, defect_density, last_updated)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(module_path) DO UPDATE SET
                    total_commits  = excluded.total_commits,
                    bug_fix_count  = excluded.bug_fix_count,
                    defect_density = excluded.defect_density,
                    last_updated   = excluded.last_updated
                """,
                (module, total_commits, bug_fix_count, ratio, now),
            )

        self._db.commit()
        logger.info(
            "Updated module_stats for %d modules from %s", len(commit_counts), repo_path
        )

    # ── Query helpers ─────────────────────────────────────────────

    def get_module_defect_density(self, module_path: str) -> float:
        """Return the stored defect density for *module_path*.

        Args:
            module_path: The module directory path (e.g. ``src/payment/``).

        Returns:
            Defect density as a float (0.0 if not found).
        """
        cur = self._db.execute(
            "SELECT defect_density FROM module_stats WHERE module_path = ?",
            (module_path,),
        )
        row = cur.fetchone()
        return float(row["defect_density"]) if row else 0.0

    def get_author_experience(self, author_email: str, module_path: str) -> int:
        """Return the number of commits an author has in a specific module.

        If the author has no recorded history, returns 0.

        Args:
            author_email: The author's git email address.
            module_path: The module directory path.

        Returns:
            Commit count for this author in the module.
        """
        cur = self._db.execute(
            """
            SELECT commit_count FROM author_stats
            WHERE author_email = ? AND module_path = ?
            """,
            (author_email, module_path),
        )
        row = cur.fetchone()
        return int(row["commit_count"]) if row else 0

    def record_review(
        self,
        pr_url: str,
        risk_level: str,
        findings: Optional[List[dict]] = None,
    ) -> None:
        """Store a review result in the history.

        Args:
            pr_url: The pull-request URL.
            risk_level: One of ``low``, ``medium``, ``high``.
            findings: List of finding dicts (counted for storage).
        """
        now = datetime.now(timezone.utc).isoformat()
        findings_count = len(findings) if findings else 0
        # Extract triggered rules if provided in findings metadata
        triggered = ""
        if findings:
            rules_set: set = set()
            for f in findings:
                if "triggered_rule" in f:
                    rules_set.add(f["triggered_rule"])
            triggered = ",".join(sorted(rules_set))

        self._db.execute(
            """
            INSERT INTO review_history
                (pr_url, risk_level, triggered_rules, findings_count, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (pr_url, risk_level, triggered, findings_count, now),
        )
        self._db.commit()
        logger.debug("Recorded review for %s (level=%s)", pr_url, risk_level)

    def get_high_defect_modules(self, threshold: float = 0.1) -> List[str]:
        """Return modules whose defect density exceeds *threshold*.

        Args:
            threshold: Minimum defect density to be considered "high".

        Returns:
            List of module path strings.
        """
        cur = self._db.execute(
            "SELECT module_path FROM module_stats WHERE defect_density >= ? "
            "ORDER BY defect_density DESC",
            (threshold,),
        )
        return [row["module_path"] for row in cur.fetchall()]

    def get_all_module_densities(self) -> Dict[str, float]:
        """Return a dict of all module defect densities.

        Returns:
            Mapping of module_path -> defect_density.
        """
        cur = self._db.execute(
            "SELECT module_path, defect_density FROM module_stats"
        )
        return {row["module_path"]: float(row["defect_density"]) for row in cur.fetchall()}

    # ── Context manager support ───────────────────────────────────

    def __enter__(self) -> "ProjectMemory":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
