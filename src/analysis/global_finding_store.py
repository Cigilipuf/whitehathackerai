"""
WhiteHatHacker AI — Global Finding Store (P6-3)

Centralized, cross-scan finding deduplication with SQLite persistence.
Provides:
- Canonical finding_hash() for consistent dedup across all pipeline stages
- Cross-scan "seen before" detection with first_seen tracking
- Regression detection (resolved→reappeared)
- Bulk lookup and batch insertion for pipeline efficiency

Schema: global_findings table with (finding_hash, program, target, vuln_type,
endpoint, parameter, severity, title, first_seen_scan, last_seen_scan,
times_seen, status, created_at, updated_at)
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs

from loguru import logger
from pydantic import BaseModel


# ── Canonical Normalisation ──────────────────────────────────────

# 60+ vuln-type aliases → canonical name (superset of all pipeline mappings)
_VULN_SYNONYMS: dict[str, str] = {
    # XSS family
    "xss_reflected": "xss", "reflected_xss": "xss", "xss_stored": "xss",
    "stored_xss": "xss", "xss_dom": "xss", "dom_xss": "xss",
    "dom-based_xss": "xss", "cross-site_scripting": "xss",
    "cross_site_scripting": "xss", "cross-site scripting": "xss",
    # SQLi family
    "sqli_error": "sqli", "sqli_blind": "sqli", "sqli_time": "sqli",
    "sqli_union": "sqli", "sql_injection": "sqli",
    "sql-injection": "sqli", "blind_sqli": "sqli",
    "error-based_sqli": "sqli", "time-based_sqli": "sqli",
    "boolean_sqli": "sqli",
    # SSRF
    "ssrf_blind": "ssrf", "blind_ssrf": "ssrf",
    "server-side_request_forgery": "ssrf",
    # SSTI
    "server_side_template_injection": "ssti",
    "template_injection": "ssti",
    # Command injection
    "command_injection": "rce", "cmd_injection": "rce",
    "os_command_injection": "rce", "remote_code_execution": "rce",
    # Open redirect
    "open_redirect": "redirect", "openredirect": "redirect",
    "url_redirect": "redirect",
    # CORS
    "cors_misconfiguration": "cors", "cors_misconfig": "cors",
    # CRLF
    "crlf_injection": "crlf", "header_injection": "crlf",
    # XXE
    "xml_external_entity": "xxe",
    # IDOR
    "insecure_direct_object_reference": "idor",
    # CSRF
    "cross-site_request_forgery": "csrf",
    # Info disclosure
    "information_disclosure": "info_disclosure",
    "sensitive_data_exposure": "info_disclosure",
    "information_exposure": "info_disclosure",
    # LFI/RFI
    "local_file_inclusion": "lfi", "path_traversal": "lfi",
    "directory_traversal": "lfi",
    "remote_file_inclusion": "rfi",
    # NoSQLi
    "nosql_injection": "nosqli",
    # JWT
    "jwt_vulnerability": "jwt", "jwt_misconfiguration": "jwt",
    # Deserialization
    "insecure_deserialization": "deserialization",
    # Prototype pollution
    "prototype_pollution": "prototype_pollution",
    # HTTP smuggling
    "http_request_smuggling": "http_smuggling",
    "request_smuggling": "http_smuggling",
    # Subdomain takeover
    "subdomain_takeover": "subdomain_takeover",
    "sub_takeover": "subdomain_takeover",
}


def _coerce_str(raw: Any) -> str:
    """Safely coerce heterogeneous finding values to strings."""
    if raw is None:
        return ""
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    return raw if isinstance(raw, str) else str(raw)


def _canonical_vuln_type(raw: Any) -> str:
    """Normalise a vulnerability type string to its canonical form."""
    v = _coerce_str(raw).strip().lower().replace(" ", "_").replace("-", "_")
    return _VULN_SYNONYMS.get(v, v)


def _normalise_url(raw: Any) -> str:
    """
    Normalise a URL for dedup:
    - lowercase scheme + host
    - strip trailing slash on path
    - sort query parameters
    - strip fragment
    """
    if not raw:
        return ""
    try:
        raw_s = _coerce_str(raw).strip()
        p = urlparse(raw_s)
        scheme = (p.scheme or "https").lower()
        host = (p.netloc or "").lower()
        path = p.path.rstrip("/") or "/"
        # Sort query params for stability
        qs = parse_qs(p.query, keep_blank_values=True)
        sorted_qs = urlencode(sorted(qs.items()), doseq=True) if qs else ""
        if sorted_qs:
            return f"{scheme}://{host}{path}?{sorted_qs}"
        return f"{scheme}://{host}{path}"
    except Exception:
        return _coerce_str(raw).strip().lower()


def finding_hash(finding: dict[str, Any]) -> str:
    """
    Compute a canonical, deterministic hash for a finding dict.

    Key fields (in order):
    1. vuln_type  — canonical normalised
    2. url        — normalised (scheme://host/path?sorted_params)
    3. parameter  — lowered, stripped
    4. cve_id     — if present, adds specificity

    Returns a 16-char hex digest (sha256 prefix).
    """
    vtype = _canonical_vuln_type(
        finding.get("vulnerability_type")
        or finding.get("vuln_type")
        or finding.get("type")
        or "unknown"
    )
    url = _normalise_url(
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("target")
        or ""
    )
    param = _coerce_str(finding.get("parameter") or "").strip().lower()
    cve = _coerce_str(finding.get("cve_id") or "").strip().upper()

    raw = f"{vtype}||{url}||{param}||{cve}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ── Models ──────────────────────────────────────────────────────

class FindingStatus(StrEnum):
    NEW = "new"
    RECURRING = "recurring"
    REGRESSION = "regression"  # was resolved, reappeared
    RESOLVED = "resolved"


class GlobalFinding(BaseModel):
    """A persisted finding record across all scans."""
    hash: str
    program: str
    target: str
    vuln_type: str
    endpoint: str
    parameter: str
    severity: str
    title: str
    first_seen_scan: str
    last_seen_scan: str
    times_seen: int = 1
    status: FindingStatus = FindingStatus.NEW
    created_at: str = ""
    updated_at: str = ""


class DeduplicationResult(BaseModel):
    """Result of dedup lookup for a single finding."""
    hash: str
    is_new: bool
    is_regression: bool  # was resolved, came back
    times_seen: int
    first_seen_scan: str
    status: FindingStatus


# ── Store ──────────────────────────────────────────────────────

_SQL_CREATE = """
CREATE TABLE IF NOT EXISTS global_findings (
    hash           TEXT PRIMARY KEY,
    program        TEXT NOT NULL DEFAULT '',
    target         TEXT NOT NULL DEFAULT '',
    vuln_type      TEXT NOT NULL DEFAULT '',
    endpoint       TEXT NOT NULL DEFAULT '',
    parameter      TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL DEFAULT 'info',
    title          TEXT NOT NULL DEFAULT '',
    first_seen_scan TEXT NOT NULL DEFAULT '',
    last_seen_scan TEXT NOT NULL DEFAULT '',
    times_seen     INTEGER NOT NULL DEFAULT 1,
    status         TEXT NOT NULL DEFAULT 'new',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gf_program ON global_findings(program);
CREATE INDEX IF NOT EXISTS idx_gf_target  ON global_findings(target);
CREATE INDEX IF NOT EXISTS idx_gf_status  ON global_findings(status);
CREATE INDEX IF NOT EXISTS idx_gf_vuln    ON global_findings(vuln_type);
"""


class GlobalFindingStore:
    """
    SQLite-backed cross-scan finding deduplication store.

    Thread-safe via per-thread connections.
    """

    def __init__(self, db_path: str | Path = "output/global_findings.db"):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    # ── Connection management ────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self._db_path), timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SQL_CREATE)
        conn.commit()

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # ── Core operations ──────────────────────────────────────

    def lookup(self, finding: dict[str, Any]) -> DeduplicationResult:
        """
        Check if a finding has been seen before.
        Returns dedup metadata without modifying the store.
        """
        h = finding_hash(finding)
        conn = self._get_conn()
        row = conn.execute(
            "SELECT hash, times_seen, first_seen_scan, status FROM global_findings WHERE hash = ?",
            (h,),
        ).fetchone()

        if row is None:
            return DeduplicationResult(
                hash=h,
                is_new=True,
                is_regression=False,
                times_seen=0,
                first_seen_scan="",
                status=FindingStatus.NEW,
            )

        return DeduplicationResult(
            hash=h,
            is_new=False,
            is_regression=(row["status"] == FindingStatus.RESOLVED),
            times_seen=row["times_seen"],
            first_seen_scan=row["first_seen_scan"],
            status=FindingStatus(row["status"]),
        )

    def record(
        self,
        finding: dict[str, Any],
        scan_id: str,
        program: str = "",
    ) -> DeduplicationResult:
        """
        Record a finding in the store. Returns dedup result.
        - Existing active → UPDATE times_seen, last_seen_scan, status=recurring
        - Previously resolved → UPDATE status=regression
        """
        h = finding_hash(finding)
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_conn()

        row = conn.execute(
            "SELECT hash, times_seen, first_seen_scan, status FROM global_findings WHERE hash = ?",
            (h,),
        ).fetchone()

        vuln_type = _canonical_vuln_type(
            finding.get("vulnerability_type")
            or finding.get("vuln_type")
            or finding.get("type")
            or "unknown"
        )
        url = _normalise_url(
            finding.get("url") or finding.get("endpoint") or finding.get("target") or ""
        )
        param = _coerce_str(finding.get("parameter") or "").strip().lower()
        severity = _coerce_str(finding.get("severity") or "info").strip().lower()
        title = (finding.get("title") or "")[:200]
        target = _coerce_str(finding.get("target") or finding.get("url") or "").strip()

        if row is None:
            # New finding
            conn.execute(
                """INSERT INTO global_findings
                   (hash, program, target, vuln_type, endpoint, parameter,
                    severity, title, first_seen_scan, last_seen_scan,
                    times_seen, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'new', ?, ?)""",
                (h, program, target, vuln_type, url, param,
                 severity, title, scan_id, scan_id, now, now),
            )
            conn.commit()
            return DeduplicationResult(
                hash=h, is_new=True, is_regression=False,
                times_seen=1, first_seen_scan=scan_id,
                status=FindingStatus.NEW,
            )

        # Existing finding
        old_status = row["status"]
        new_times = row["times_seen"] + 1
        is_regression = (old_status == FindingStatus.RESOLVED)
        new_status = FindingStatus.REGRESSION if is_regression else FindingStatus.RECURRING

        conn.execute(
            """UPDATE global_findings
               SET last_seen_scan = ?, times_seen = ?, status = ?,
                   updated_at = ?, severity = ?
               WHERE hash = ?""",
            (scan_id, new_times, new_status.value, now, severity, h),
        )
        conn.commit()
        return DeduplicationResult(
            hash=h, is_new=False, is_regression=is_regression,
            times_seen=new_times, first_seen_scan=row["first_seen_scan"],
            status=new_status,
        )

    def record_batch(
        self,
        findings: list[dict[str, Any]],
        scan_id: str,
        program: str = "",
    ) -> list[DeduplicationResult]:
        """Record multiple findings efficiently. Returns results in same order."""
        results = []
        for f in findings:
            results.append(self.record(f, scan_id, program))
        return results

    def mark_resolved(self, finding_hash_value: str) -> None:
        """Mark a finding as resolved (no longer detected)."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_conn()
        conn.execute(
            "UPDATE global_findings SET status = ?, updated_at = ? WHERE hash = ?",
            (FindingStatus.RESOLVED.value, now, finding_hash_value),
        )
        conn.commit()

    def mark_resolved_not_in_scan(
        self,
        scan_id: str,
        program: str = "",
        target: str = "",
    ) -> int:
        """
        Mark all findings NOT seen in this scan as resolved.
        Only affects findings for the given program/target.
        Returns count of resolved findings.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        conditions = ["last_seen_scan != ?", "status != 'resolved'"]
        params: list[Any] = [scan_id]
        if program:
            conditions.append("program = ?")
            params.append(program)
        if target:
            conditions.append("target = ?")
            params.append(target)

        where = " AND ".join(conditions)
        cursor = conn.execute(
            f"UPDATE global_findings SET status = 'resolved', updated_at = ? WHERE {where}",
            [now] + params,
        )
        conn.commit()
        return cursor.rowcount

    # ── Query operations ────────────────────────────────────

    def get_finding(self, hash_value: str) -> GlobalFinding | None:
        """Get a specific finding by hash."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM global_findings WHERE hash = ?", (hash_value,)
        ).fetchone()
        if row is None:
            return None
        return GlobalFinding(**dict(row))

    def get_findings_for_program(self, program: str) -> list[GlobalFinding]:
        """Get all findings for a program."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM global_findings WHERE program = ? ORDER BY updated_at DESC",
            (program,),
        ).fetchall()
        return [GlobalFinding(**dict(r)) for r in rows]

    def get_findings_for_target(self, target: str) -> list[GlobalFinding]:
        """Get all findings for a target."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM global_findings WHERE target = ? ORDER BY updated_at DESC",
            (target,),
        ).fetchall()
        return [GlobalFinding(**dict(r)) for r in rows]

    def get_new_findings(self, scan_id: str) -> list[GlobalFinding]:
        """Get findings first seen in a specific scan."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM global_findings WHERE first_seen_scan = ? ORDER BY severity",
            (scan_id,),
        ).fetchall()
        return [GlobalFinding(**dict(r)) for r in rows]

    def get_regressions(self, scan_id: str) -> list[GlobalFinding]:
        """Get findings that regressed in a specific scan."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM global_findings WHERE last_seen_scan = ? AND status = 'regression'",
            (scan_id,),
        ).fetchall()
        return [GlobalFinding(**dict(r)) for r in rows]

    def get_stats(self, program: str = "") -> dict[str, Any]:
        """Get summary statistics."""
        conn = self._get_conn()
        where = "WHERE program = ?" if program else ""
        params = (program,) if program else ()

        total = conn.execute(
            f"SELECT COUNT(*) FROM global_findings {where}", params
        ).fetchone()[0]

        by_status = {}
        for row in conn.execute(
            f"SELECT status, COUNT(*) as cnt FROM global_findings {where} GROUP BY status",
            params,
        ):
            by_status[row["status"]] = row["cnt"]

        by_severity = {}
        for row in conn.execute(
            f"SELECT severity, COUNT(*) as cnt FROM global_findings {where} GROUP BY severity",
            params,
        ):
            by_severity[row["severity"]] = row["cnt"]

        by_vuln = {}
        for row in conn.execute(
            f"SELECT vuln_type, COUNT(*) as cnt FROM global_findings {where} GROUP BY vuln_type ORDER BY cnt DESC LIMIT 20",
            params,
        ):
            by_vuln[row["vuln_type"]] = row["cnt"]

        return {
            "total": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "by_vuln_type": by_vuln,
        }

    def count(self, program: str = "") -> int:
        """Quick count of all findings."""
        conn = self._get_conn()
        if program:
            return conn.execute(
                "SELECT COUNT(*) FROM global_findings WHERE program = ?", (program,)
            ).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM global_findings").fetchone()[0]
