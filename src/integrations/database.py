"""
WhiteHatHacker AI — Database Integration

SQLite/PostgreSQL veritabanı yönetimi. Tarama sonuçları,
bulgular, oturumlar ve konfigürasyonların kalıcı depolanması.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Models
# ============================================================

class ScanSession(BaseModel):
    session_id: str = ""
    target: str = ""
    mode: str = "semi-autonomous"
    profile: str = "balanced"
    status: str = "running"
    started_at: float = Field(default_factory=time.time)
    completed_at: float = 0.0
    findings_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingRecord(BaseModel):
    finding_id: str = ""
    session_id: str = ""
    vuln_type: str = ""
    severity: str = ""
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    tool: str = ""
    confidence: int = 50
    cvss_score: float = 0.0
    status: str = "open"  # open, verified, false_positive, reported
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class ToolRunRecord(BaseModel):
    run_id: str = ""
    session_id: str = ""
    tool_name: str = ""
    target: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    status: str = ""
    findings_count: int = 0
    raw_output_path: str = ""
    error: str = ""


# ============================================================
# Database Manager
# ============================================================

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    mode TEXT DEFAULT 'semi-autonomous',
    profile TEXT DEFAULT 'balanced',
    status TEXT DEFAULT 'running',
    started_at REAL,
    completed_at REAL,
    findings_count INTEGER DEFAULT 0,
    metadata TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    target TEXT NOT NULL,
    endpoint TEXT DEFAULT '',
    parameter TEXT DEFAULT '',
    tool TEXT DEFAULT '',
    confidence INTEGER DEFAULT 50,
    cvss_score REAL DEFAULT 0.0,
    status TEXT DEFAULT 'open',
    evidence TEXT DEFAULT '{}',
    created_at REAL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

CREATE TABLE IF NOT EXISTS tool_runs (
    run_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL,
    started_at REAL,
    completed_at REAL,
    status TEXT DEFAULT '',
    findings_count INTEGER DEFAULT 0,
    raw_output_path TEXT DEFAULT '',
    error TEXT DEFAULT '',
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

CREATE TABLE IF NOT EXISTS config_store (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_tool_runs_session ON tool_runs(session_id);
"""


class DatabaseManager:
    """
    Merkezi veritabanı yöneticisi.

    Usage:
        db = DatabaseManager("output/whai.db")

        # Oturum kaydet
        db.save_session(ScanSession(session_id="sess-001", target="example.com"))

        # Bulgu kaydet
        db.save_finding(FindingRecord(
            finding_id="f-001", session_id="sess-001",
            vuln_type="xss_reflected", severity="medium",
            target="example.com",
        ))

        # Sorgu
        findings = db.get_session_findings("sess-001")
    """

    def __init__(self, db_path: str | Path = "output/whai.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Veritabanı ve tabloları oluştur."""
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA_SQL)
        logger.debug(f"Database initialized: {self.db_path}")

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Thread-safe connection context manager."""
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as _exc:
            conn.rollback()
            raise
        finally:
            conn.close()

    # --------- Sessions ---------

    def save_session(self, session: ScanSession) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scan_sessions
                   (session_id, target, mode, profile, status, started_at,
                    completed_at, findings_count, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session.session_id, session.target, session.mode,
                    session.profile, session.status, session.started_at,
                    session.completed_at, session.findings_count,
                    json.dumps(session.metadata, ensure_ascii=False),
                ),
            )

    def get_session(self, session_id: str) -> ScanSession | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scan_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row:
                return ScanSession(
                    **{**dict(row), "metadata": json.loads(row["metadata"])}
                )
        return None

    def update_session_status(
        self, session_id: str, status: str, findings_count: int = 0,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """UPDATE scan_sessions SET status = ?, findings_count = ?,
                   completed_at = ? WHERE session_id = ?""",
                (status, findings_count, time.time(), session_id),
            )

    def list_sessions(self, limit: int = 50) -> list[ScanSession]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                ScanSession(**{**dict(r), "metadata": json.loads(r["metadata"])})
                for r in rows
            ]

    # --------- Findings ---------

    def save_finding(self, finding: FindingRecord) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO findings
                   (finding_id, session_id, vuln_type, severity, target,
                    endpoint, parameter, tool, confidence, cvss_score,
                    status, evidence, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.finding_id, finding.session_id,
                    finding.vuln_type, finding.severity, finding.target,
                    finding.endpoint, finding.parameter, finding.tool,
                    finding.confidence, finding.cvss_score, finding.status,
                    json.dumps(finding.evidence, ensure_ascii=False),
                    finding.created_at,
                ),
            )

    def save_findings_batch(self, findings: list[FindingRecord]) -> None:
        with self._conn() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO findings
                   (finding_id, session_id, vuln_type, severity, target,
                    endpoint, parameter, tool, confidence, cvss_score,
                    status, evidence, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        f.finding_id, f.session_id, f.vuln_type, f.severity,
                        f.target, f.endpoint, f.parameter, f.tool,
                        f.confidence, f.cvss_score, f.status,
                        json.dumps(f.evidence, ensure_ascii=False),
                        f.created_at,
                    )
                    for f in findings
                ],
            )

    def get_finding(self, finding_id: str) -> FindingRecord | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if row:
                return FindingRecord(
                    **{**dict(row), "evidence": json.loads(row["evidence"])}
                )
        return None

    def get_session_findings(
        self, session_id: str, severity: str = "",
    ) -> list[FindingRecord]:
        with self._conn() as conn:
            if severity:
                rows = conn.execute(
                    """SELECT * FROM findings
                       WHERE session_id = ? AND severity = ?
                       ORDER BY cvss_score DESC""",
                    (session_id, severity),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM findings
                       WHERE session_id = ?
                       ORDER BY cvss_score DESC""",
                    (session_id,),
                ).fetchall()
            return [
                FindingRecord(**{**dict(r), "evidence": json.loads(r["evidence"])})
                for r in rows
            ]

    def update_finding_status(self, finding_id: str, status: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE findings SET status = ? WHERE finding_id = ?",
                (status, finding_id),
            )

    def get_findings_stats(self, session_id: str = "") -> dict[str, Any]:
        with self._conn() as conn:
            where = "WHERE session_id = ?" if session_id else ""
            params = (session_id,) if session_id else ()

            total = conn.execute(
                f"SELECT COUNT(*) FROM findings {where}", params
            ).fetchone()[0]

            severity_counts = {}
            rows = conn.execute(
                f"SELECT severity, COUNT(*) as cnt FROM findings {where} GROUP BY severity",
                params,
            ).fetchall()
            for r in rows:
                severity_counts[r["severity"]] = r["cnt"]

            status_counts = {}
            rows = conn.execute(
                f"SELECT status, COUNT(*) as cnt FROM findings {where} GROUP BY status",
                params,
            ).fetchall()
            for r in rows:
                status_counts[r["status"]] = r["cnt"]

            return {
                "total": total,
                "by_severity": severity_counts,
                "by_status": status_counts,
            }

    # --------- Tool Runs ---------

    def save_tool_run(self, run: ToolRunRecord) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO tool_runs
                   (run_id, session_id, tool_name, target, started_at,
                    completed_at, status, findings_count, raw_output_path, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run.run_id, run.session_id, run.tool_name, run.target,
                    run.started_at, run.completed_at, run.status,
                    run.findings_count, run.raw_output_path, run.error,
                ),
            )

    def get_session_tool_runs(self, session_id: str) -> list[ToolRunRecord]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM tool_runs WHERE session_id = ? ORDER BY started_at",
                (session_id,),
            ).fetchall()
            return [ToolRunRecord(**dict(r)) for r in rows]

    # --------- Config Store ---------

    def set_config(self, key: str, value: Any) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO config_store (key, value, updated_at)
                   VALUES (?, ?, ?)""",
                (key, json.dumps(value, ensure_ascii=False), time.time()),
            )

    def get_config(self, key: str, default: Any = None) -> Any:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM config_store WHERE key = ?", (key,),
            ).fetchone()
            if row:
                return json.loads(row["value"])
        return default


__all__ = [
    "DatabaseManager",
    "ScanSession",
    "FindingRecord",
    "ToolRunRecord",
]
