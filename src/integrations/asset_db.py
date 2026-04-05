"""
WhiteHatHacker AI — Asset Database (V7-T0-2)

Program bazlı asset veritabanı. Keşfedilen subdomain, IP, endpoint,
teknoloji ve port bilgilerini kalıcı olarak depolar. Scan'lar arası
asset tracking ve diff analizi sağlar.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from loguru import logger
from pydantic import BaseModel, Field, field_validator


def _coerce_timestamp(v: Any) -> str:
    """Convert float/int epoch timestamps to ISO-8601 strings."""
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
    return v if isinstance(v, str) else str(v) if v is not None else ""


# ============================================================
# Models
# ============================================================


class Asset(BaseModel):
    """Keşfedilen bir varlık (subdomain, IP, endpoint, vb.)."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    program_id: str = ""
    asset_type: str = ""  # subdomain / ip / endpoint / technology / port / url
    value: str = ""
    first_seen: str = ""
    last_seen: str = ""
    scan_id: str = ""
    is_alive: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> str:
        return _coerce_timestamp(v)


class AssetDiff(BaseModel):
    """İki scan arasındaki asset farkları."""

    program_id: str = ""
    old_scan_id: str = ""
    new_scan_id: str = ""

    new_assets: list[Asset] = Field(default_factory=list)
    disappeared_assets: list[Asset] = Field(default_factory=list)
    changed_assets: list[dict[str, Any]] = Field(default_factory=list)

    new_asset_count: int = 0
    disappeared_count: int = 0
    changed_count: int = 0


class FindingDiff(BaseModel):
    """İki scan arasındaki finding farkları."""

    new_findings: list[dict[str, Any]] = Field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = Field(default_factory=list)
    new_count: int = 0
    resolved_count: int = 0


# ============================================================
# Schema
# ============================================================

_ASSET_SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT DEFAULT '',
    scope_config TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id),
    asset_type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_id TEXT DEFAULT '',
    is_alive INTEGER DEFAULT 1,
    metadata TEXT DEFAULT '{}',
    UNIQUE(program_id, asset_type, value)
);

CREATE TABLE IF NOT EXISTS finding_history (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id),
    scan_id TEXT NOT NULL,
    asset_value TEXT DEFAULT '',
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL DEFAULT 50.0,
    title TEXT DEFAULT '',
    status TEXT DEFAULT 'new',
    first_found TEXT NOT NULL,
    last_found TEXT DEFAULT '',
    details TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id),
    started_at TEXT,
    finished_at TEXT,
    profile TEXT DEFAULT 'balanced',
    status TEXT DEFAULT 'running',
    stats TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_alive ON assets(is_alive);
CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);
CREATE INDEX IF NOT EXISTS idx_fh_program ON finding_history(program_id);
CREATE INDEX IF NOT EXISTS idx_fh_scan ON finding_history(scan_id);
CREATE INDEX IF NOT EXISTS idx_fh_severity ON finding_history(severity);
CREATE INDEX IF NOT EXISTS idx_fh_status ON finding_history(status);
CREATE INDEX IF NOT EXISTS idx_sr_program ON scan_runs(program_id);

CREATE TABLE IF NOT EXISTS asset_scan_map (
    asset_id TEXT NOT NULL REFERENCES assets(id),
    scan_id TEXT NOT NULL,
    program_id TEXT NOT NULL,
    PRIMARY KEY (asset_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_asm_scan ON asset_scan_map(scan_id);
CREATE INDEX IF NOT EXISTS idx_asm_program ON asset_scan_map(program_id);
"""


# ============================================================
# Asset Database
# ============================================================


class AssetDB:
    """
    Program bazlı asset veritabanı.

    Usage:
        db = AssetDB("output/assets.db")
        db.ensure_program("prog-001", "example.com", "hackerone")
        db.upsert_assets("prog-001", "scan-001", [
            Asset(asset_type="subdomain", value="api.example.com"),
            Asset(asset_type="subdomain", value="staging.example.com"),
        ])
        new = db.get_new_assets("prog-001", since="2026-03-01T00:00:00Z")
    """

    def __init__(self, db_path: str | Path = "output/assets.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript(_ASSET_SCHEMA)
        logger.debug(f"Asset DB initialized: {self.db_path}")

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # --------- Programs ---------

    def ensure_program(
        self, program_id: str, name: str = "", platform: str = "",
    ) -> None:
        """Program oluştur veya güncelle."""
        now = _now_iso()
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM programs WHERE id = ?", (program_id,),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE programs SET name=?, platform=?, updated_at=? WHERE id=?",
                    (name, platform, now, program_id),
                )
            else:
                conn.execute(
                    "INSERT INTO programs (id, name, platform, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (program_id, name, platform, now, now),
                )

    # --------- Assets ---------

    def upsert_assets(
        self,
        program_id: str,
        scan_id: str,
        assets: list[Asset],
    ) -> tuple[int, int]:
        """
        Asset'leri ekle veya güncelle.

        Returns:
            (inserted_count, updated_count)
        """
        now = _now_iso()
        inserted = 0
        updated = 0

        with self._conn() as conn:
            for asset in assets:
                existing = conn.execute(
                    "SELECT id FROM assets WHERE program_id=? AND asset_type=? AND value=?",
                    (program_id, asset.asset_type, asset.value),
                ).fetchone()

                meta_json = json.dumps(asset.metadata, ensure_ascii=False)

                if existing:
                    conn.execute(
                        "UPDATE assets SET last_seen=?, scan_id=?, is_alive=1, metadata=? "
                        "WHERE id=?",
                        (now, scan_id, meta_json, existing["id"]),
                    )
                    # Record this scan saw this asset
                    conn.execute(
                        "INSERT OR IGNORE INTO asset_scan_map (asset_id, scan_id, program_id) "
                        "VALUES (?, ?, ?)",
                        (existing["id"], scan_id, program_id),
                    )
                    updated += 1
                else:
                    aid = asset.id or uuid.uuid4().hex[:16]
                    conn.execute(
                        "INSERT INTO assets (id, program_id, asset_type, value, "
                        "first_seen, last_seen, scan_id, is_alive, metadata) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
                        (aid, program_id, asset.asset_type, asset.value,
                         now, now, scan_id, meta_json),
                    )
                    # Record this scan saw this asset
                    conn.execute(
                        "INSERT OR IGNORE INTO asset_scan_map (asset_id, scan_id, program_id) "
                        "VALUES (?, ?, ?)",
                        (aid, scan_id, program_id),
                    )
                    inserted += 1

        logger.info(
            f"Asset upsert: {inserted} new, {updated} updated "
            f"(program={program_id}, scan={scan_id})"
        )
        return inserted, updated

    def mark_dead(self, program_id: str, scan_id: str, alive_values: set[str]) -> int:
        """
        Bu scan'da görülmeyen asset'leri is_alive=0 olarak işaretle.

        Args:
            alive_values: Bu scan'da tespit edilen asset değerleri seti

        Returns:
            Dead olarak işaretlenen asset sayısı
        """
        marked = 0
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, value FROM assets WHERE program_id=? AND is_alive=1",
                (program_id,),
            ).fetchall()
            for row in rows:
                if row["value"] not in alive_values:
                    conn.execute(
                        "UPDATE assets SET is_alive=0 WHERE id=?",
                        (row["id"],),
                    )
                    marked += 1
        if marked:
            logger.info(f"Marked {marked} assets as dead (program={program_id})")
        return marked

    def get_assets(
        self,
        program_id: str,
        asset_type: str | None = None,
        alive_only: bool = True,
    ) -> list[Asset]:
        """Asset listesi getir."""
        with self._conn() as conn:
            query = "SELECT * FROM assets WHERE program_id=?"
            params: list[Any] = [program_id]

            if asset_type:
                query += " AND asset_type=?"
                params.append(asset_type)

            if alive_only:
                query += " AND is_alive=1"

            query += " ORDER BY first_seen DESC"
            rows = conn.execute(query, params).fetchall()

        return [_row_to_asset(r) for r in rows]

    def get_new_assets(
        self,
        program_id: str,
        since: str,
    ) -> list[Asset]:
        """Belirli bir tarihten sonra ilk kez görülen asset'ler."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM assets WHERE program_id=? AND first_seen > ? "
                "ORDER BY first_seen DESC",
                (program_id, since),
            ).fetchall()
        return [_row_to_asset(r) for r in rows]

    def get_disappeared_assets(self, program_id: str) -> list[Asset]:
        """Artık alive olmayan asset'ler."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM assets WHERE program_id=? AND is_alive=0 "
                "ORDER BY last_seen DESC",
                (program_id,),
            ).fetchall()
        return [_row_to_asset(r) for r in rows]

    def count_assets(self, program_id: str) -> dict[str, int]:
        """Asset türüne göre sayılar."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT asset_type, COUNT(*) as cnt FROM assets "
                "WHERE program_id=? AND is_alive=1 GROUP BY asset_type",
                (program_id,),
            ).fetchall()
        return {r["asset_type"]: r["cnt"] for r in rows}

    # --------- Findings History ---------

    def save_finding(
        self,
        program_id: str,
        scan_id: str,
        vuln_type: str,
        severity: str,
        title: str = "",
        asset_value: str = "",
        confidence: float = 50.0,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Finding kaydet. Eğer aynı vuln_type+asset_value zaten varsa last_found güncelle."""
        now = _now_iso()
        details_json = json.dumps(details or {}, ensure_ascii=False)

        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM finding_history "
                "WHERE program_id=? AND vuln_type=? AND asset_value=? AND status != 'fixed'",
                (program_id, vuln_type, asset_value),
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE finding_history SET last_found=?, scan_id=?, confidence=? "
                    "WHERE id=?",
                    (now, scan_id, confidence, existing["id"]),
                )
                return existing["id"]

            fid = uuid.uuid4().hex[:16]
            conn.execute(
                "INSERT INTO finding_history "
                "(id, program_id, scan_id, asset_value, vuln_type, severity, "
                "confidence, title, status, first_found, last_found, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?)",
                (fid, program_id, scan_id, asset_value, vuln_type,
                 severity, confidence, title, now, now, details_json),
            )
            return fid

    def get_findings(
        self,
        program_id: str,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """Finding history sorgula."""
        with self._conn() as conn:
            query = "SELECT * FROM finding_history WHERE program_id=?"
            params: list[Any] = [program_id]
            if severity:
                query += " AND severity=?"
                params.append(severity)
            if status:
                query += " AND status=?"
                params.append(status)
            query += " ORDER BY first_found DESC"
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # --------- Scan Runs ---------

    def record_scan_start(
        self,
        scan_id: str,
        program_id: str,
        profile: str = "balanced",
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_runs "
                "(id, program_id, started_at, profile, status) "
                "VALUES (?, ?, ?, ?, 'running')",
                (scan_id, program_id, _now_iso(), profile),
            )

    def record_scan_finish(
        self,
        scan_id: str,
        status: str = "completed",
        stats: dict[str, Any] | None = None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE scan_runs SET finished_at=?, status=?, stats=? WHERE id=?",
                (_now_iso(), status, json.dumps(stats or {}), scan_id),
            )

    def get_scan_runs(
        self,
        program_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_runs WHERE program_id=? ORDER BY started_at DESC LIMIT ?",
                (program_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # --------- Diff ---------

    def diff_assets(
        self,
        program_id: str,
        old_scan_id: str,
        new_scan_id: str,
    ) -> AssetDiff:
        """İki scan arasındaki asset farklarını hesapla.

        Uses the asset_scan_map junction table to determine which assets
        were observed in each scan, so an UPDATE to assets.scan_id does
        not destroy the historical record.
        """
        with self._conn() as conn:
            old_rows = conn.execute(
                "SELECT DISTINCT a.value, a.asset_type FROM assets a "
                "JOIN asset_scan_map m ON a.id = m.asset_id "
                "WHERE m.program_id=? AND m.scan_id=?",
                (program_id, old_scan_id),
            ).fetchall()

            new_rows = conn.execute(
                "SELECT DISTINCT a.value, a.asset_type FROM assets a "
                "JOIN asset_scan_map m ON a.id = m.asset_id "
                "WHERE m.program_id=? AND m.scan_id=?",
                (program_id, new_scan_id),
            ).fetchall()

        old_set = {(r["value"], r["asset_type"]) for r in old_rows}
        new_set = {(r["value"], r["asset_type"]) for r in new_rows}

        added = new_set - old_set
        removed = old_set - new_set

        new_assets = [
            Asset(asset_type=at, value=val) for val, at in added
        ]
        disappeared = [
            Asset(asset_type=at, value=val) for val, at in removed
        ]

        return AssetDiff(
            program_id=program_id,
            old_scan_id=old_scan_id,
            new_scan_id=new_scan_id,
            new_assets=new_assets,
            disappeared_assets=disappeared,
            new_asset_count=len(new_assets),
            disappeared_count=len(disappeared),
        )


# ============================================================
# Helpers
# ============================================================


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _row_to_asset(row: sqlite3.Row) -> Asset:
    d = dict(row)
    d["is_alive"] = bool(d.get("is_alive", 1))
    meta = d.pop("metadata", "{}")
    try:
        d["metadata"] = json.loads(meta) if isinstance(meta, str) else meta
    except (json.JSONDecodeError, TypeError):
        d["metadata"] = {}
    return Asset(**d)
