"""
Regression tests for the Diff Engine system.

Covers:
1. AssetDB asset_scan_map junction table creation
2. upsert_assets populates asset_scan_map
3. diff_assets uses junction table for correct per-scan asset sets
4. DiffEngine._find_new_findings uses first_found timestamp
5. DiffEngine._find_resolved_findings uses last_found timestamp
6. DiffEngine._get_scan_start helper
7. get_scan_runs returns 'id' column (not 'scan_id')
8. End-to-end diff: scan A → scan B → correct asset/finding diff
9. send_diff_alerts fires correct notification count
10. full_scan.py uses _adb._program_name and correct dict key
"""

import inspect
import importlib
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.integrations.asset_db import AssetDB, Asset, AssetDiff
from src.analysis.diff_engine import DiffEngine, ScanDiffReport


# ──────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary AssetDB instance."""
    db_path = tmp_path / "test_assets.db"
    return AssetDB(db_path=str(db_path))


@pytest.fixture
def seeded_db(tmp_db):
    """
    AssetDB with two scans worth of data.

    Scan A: finds sub1.example.com, sub2.example.com, endpoint /api/v1
    Scan B: finds sub2.example.com, sub3.example.com, endpoint /api/v1, /api/v2
    
    Expected diff:
      New assets: sub3.example.com, /api/v2
      Disappeared: sub1.example.com
    """
    db = tmp_db
    program = "example.com"
    db.ensure_program(program, name=program)

    # Record scan A
    db.record_scan_start("scan-A", program, "balanced")
    db.upsert_assets(program, "scan-A", [
        Asset(asset_type="subdomain", value="sub1.example.com"),
        Asset(asset_type="subdomain", value="sub2.example.com"),
        Asset(asset_type="endpoint", value="/api/v1"),
    ])
    db.record_scan_finish("scan-A", status="completed")

    # Small delay to ensure timestamps differ
    time.sleep(0.05)

    # Record scan B
    db.record_scan_start("scan-B", program, "balanced")
    db.upsert_assets(program, "scan-B", [
        Asset(asset_type="subdomain", value="sub2.example.com"),
        Asset(asset_type="subdomain", value="sub3.example.com"),
        Asset(asset_type="endpoint", value="/api/v1"),
        Asset(asset_type="endpoint", value="/api/v2"),
    ])
    db.record_scan_finish("scan-B", status="completed")

    return db


# ──────────────────────────────────────────────────────────────
# 1. Schema: asset_scan_map table exists
# ──────────────────────────────────────────────────────────────

class TestAssetScanMapSchema:
    def test_junction_table_created(self, tmp_db):
        """asset_scan_map table must exist in the DB."""
        conn = sqlite3.connect(str(tmp_db.db_path))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='asset_scan_map'"
        ).fetchall()
        conn.close()
        assert len(tables) == 1

    def test_junction_table_has_correct_columns(self, tmp_db):
        conn = sqlite3.connect(str(tmp_db.db_path))
        cols = conn.execute("PRAGMA table_info(asset_scan_map)").fetchall()
        conn.close()
        col_names = {c[1] for c in cols}
        assert {"asset_id", "scan_id", "program_id"} <= col_names


# ──────────────────────────────────────────────────────────────
# 2. upsert_assets populates junction table
# ──────────────────────────────────────────────────────────────

class TestUpsertPopulatesJunction:
    def test_new_asset_creates_mapping(self, tmp_db):
        db = tmp_db
        db.ensure_program("p1", name="p1")
        db.upsert_assets("p1", "scan-1", [
            Asset(asset_type="subdomain", value="a.example.com"),
        ])
        conn = sqlite3.connect(str(db.db_path))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM asset_scan_map WHERE scan_id='scan-1'"
        ).fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0]["program_id"] == "p1"

    def test_repeated_upsert_creates_second_mapping(self, tmp_db):
        """Same asset seen in two scans → two junction rows."""
        db = tmp_db
        db.ensure_program("p1", name="p1")
        db.upsert_assets("p1", "scan-1", [
            Asset(asset_type="subdomain", value="a.example.com"),
        ])
        db.upsert_assets("p1", "scan-2", [
            Asset(asset_type="subdomain", value="a.example.com"),
        ])
        conn = sqlite3.connect(str(db.db_path))
        rows = conn.execute("SELECT * FROM asset_scan_map").fetchall()
        conn.close()
        assert len(rows) == 2

    def test_idempotent_upsert_same_scan(self, tmp_db):
        """Upserting same asset in same scan twice → only one junction row."""
        db = tmp_db
        db.ensure_program("p1", name="p1")
        db.upsert_assets("p1", "scan-1", [
            Asset(asset_type="subdomain", value="a.example.com"),
        ])
        db.upsert_assets("p1", "scan-1", [
            Asset(asset_type="subdomain", value="a.example.com"),
        ])
        conn = sqlite3.connect(str(db.db_path))
        rows = conn.execute("SELECT * FROM asset_scan_map WHERE scan_id='scan-1'").fetchall()
        conn.close()
        assert len(rows) == 1


# ──────────────────────────────────────────────────────────────
# 3. diff_assets uses junction table correctly
# ──────────────────────────────────────────────────────────────

class TestDiffAssetsCorrectness:
    def test_new_assets_detected(self, seeded_db):
        diff = seeded_db.diff_assets("example.com", "scan-A", "scan-B")
        new_values = {a.value for a in diff.new_assets}
        assert "sub3.example.com" in new_values
        assert "/api/v2" in new_values

    def test_disappeared_assets_detected(self, seeded_db):
        diff = seeded_db.diff_assets("example.com", "scan-A", "scan-B")
        gone_values = {a.value for a in diff.disappeared_assets}
        assert "sub1.example.com" in gone_values

    def test_common_assets_not_in_diff(self, seeded_db):
        diff = seeded_db.diff_assets("example.com", "scan-A", "scan-B")
        new_values = {a.value for a in diff.new_assets}
        gone_values = {a.value for a in diff.disappeared_assets}
        # sub2 and /api/v1 are in BOTH scans — should not appear in diff
        assert "sub2.example.com" not in new_values
        assert "sub2.example.com" not in gone_values
        assert "/api/v1" not in new_values
        assert "/api/v1" not in gone_values

    def test_empty_old_scan(self, tmp_db):
        """If old scan has no assets, all new scan assets are 'new'."""
        db = tmp_db
        db.ensure_program("p1", name="p1")
        db.record_scan_start("s1", "p1")
        db.record_scan_finish("s1")
        db.record_scan_start("s2", "p1")
        db.upsert_assets("p1", "s2", [
            Asset(asset_type="subdomain", value="x.example.com"),
        ])
        db.record_scan_finish("s2")
        diff = db.diff_assets("p1", "s1", "s2")
        assert len(diff.new_assets) == 1
        assert diff.new_assets[0].value == "x.example.com"
        assert len(diff.disappeared_assets) == 0


# ──────────────────────────────────────────────────────────────
# 4-6. DiffEngine finding diff + helpers
# ──────────────────────────────────────────────────────────────

class TestDiffEngineFindingDiff:
    def test_new_findings_only_from_new_scan(self, tmp_db):
        """XSS saved during scan-A should NOT appear as new; SQLi in scan-B should."""
        db = tmp_db
        program = "example.com"
        db.ensure_program(program, name=program)

        # --- Scan A: save XSS finding DURING the scan ---
        db.record_scan_start("scan-A", program, "balanced")
        db.save_finding(program, "scan-A", "xss", "HIGH",
                        title="XSS in /search", asset_value="/search")
        db.record_scan_finish("scan-A", status="completed")

        time.sleep(0.05)

        # --- Scan B: save NEW SQLi + re-confirm XSS ---
        db.record_scan_start("scan-B", program, "balanced")
        db.save_finding(program, "scan-B", "sqli", "CRITICAL",
                        title="SQLi in /login", asset_value="/login")
        db.save_finding(program, "scan-B", "xss", "HIGH",
                        title="XSS in /search", asset_value="/search")
        db.record_scan_finish("scan-B", status="completed")

        engine = DiffEngine(db)
        report = engine.diff(program, "scan-A", "scan-B")

        new_types = [f.get("vuln_type") for f in report.new_findings]
        assert "sqli" in new_types
        assert "xss" not in new_types

    def test_resolved_findings_not_reseen(self, tmp_db):
        """LFI saved during scan-A but NOT re-confirmed in scan-B → resolved."""
        db = tmp_db
        program = "example.com"
        db.ensure_program(program, name=program)

        # --- Scan A: save LFI finding DURING the scan ---
        db.record_scan_start("scan-A", program, "balanced")
        db.save_finding(program, "scan-A", "lfi", "MEDIUM",
                        title="LFI in /include", asset_value="/include")
        db.record_scan_finish("scan-A", status="completed")

        time.sleep(0.05)

        # --- Scan B: does NOT re-confirm LFI ---
        db.record_scan_start("scan-B", program, "balanced")
        db.record_scan_finish("scan-B", status="completed")

        engine = DiffEngine(db)
        report = engine.diff(program, "scan-A", "scan-B")

        resolved_types = [f.get("vuln_type") for f in report.resolved_findings]
        assert "lfi" in resolved_types

    def test_get_scan_start_helper(self, seeded_db):
        engine = DiffEngine(seeded_db)
        start = engine._get_scan_start("example.com", "scan-A")
        assert start != "", "Should return a non-empty ISO timestamp"
        assert "T" in start  # ISO format check


# ──────────────────────────────────────────────────────────────
# 7. get_scan_runs returns 'id' column
# ──────────────────────────────────────────────────────────────

class TestScanRunsKeyName:
    def test_scan_runs_use_id_key(self, seeded_db):
        runs = seeded_db.get_scan_runs("example.com")
        assert len(runs) >= 2
        for r in runs:
            assert "id" in r, f"scan_runs row should have 'id' key, got: {list(r.keys())}"
            # Verify there is NO 'scan_id' key (that was the bug)
            # scan_id is not a column in scan_runs table

    def test_runs_ordered_by_started_at_desc(self, seeded_db):
        runs = seeded_db.get_scan_runs("example.com")
        # First result should be the most recent (scan-B)
        assert runs[0]["id"] == "scan-B"
        assert runs[1]["id"] == "scan-A"


# ──────────────────────────────────────────────────────────────
# 8. End-to-end diff
# ──────────────────────────────────────────────────────────────

class TestEndToEndDiff:
    def test_full_diff_report(self, seeded_db):
        db = seeded_db
        db.save_finding("example.com", "scan-A", "xss", "HIGH",
                        title="XSS", asset_value="/search")
        time.sleep(0.05)
        db.save_finding("example.com", "scan-B", "sqli", "CRITICAL",
                        title="SQLi", asset_value="/login")

        engine = DiffEngine(db)
        report = engine.diff("example.com", "scan-A", "scan-B")

        # Asset checks
        new_values = {a.value for a in report.asset_diff.new_assets}
        gone_values = {a.value for a in report.asset_diff.disappeared_assets}
        assert "sub3.example.com" in new_values
        assert "sub1.example.com" in gone_values

        # Finding checks
        assert any(f["vuln_type"] == "sqli" for f in report.new_findings)

        # Markdown generation
        md = engine.generate_markdown(report)
        assert "New Assets" in md
        assert "Disappeared Assets" in md
        assert "sub3.example.com" in md
        assert "sub1.example.com" in md


# ──────────────────────────────────────────────────────────────
# 9. send_diff_alerts
# ──────────────────────────────────────────────────────────────

class TestDiffAlerts:
    def test_alerts_count_with_findings(self):
        """send_diff_alerts should fire at least scan-summary alert."""
        import asyncio
        from src.integrations.diff_alerts import send_diff_alerts

        report = ScanDiffReport(
            program_id="test.com",
            old_scan_id="s1",
            new_scan_id="s2",
            new_findings=[
                {"severity": "CRITICAL", "title": "SQLi", "asset_value": "/api"},
            ],
        )
        mock_notify = AsyncMock()
        sent = asyncio.run(send_diff_alerts(report, notify_fn=mock_notify))
        # Should send: critical alert + scan summary = at least 2
        assert sent >= 2
        assert mock_notify.call_count >= 2

    def test_alerts_without_notify_fn(self):
        import asyncio
        from src.integrations.diff_alerts import send_diff_alerts
        report = ScanDiffReport(program_id="t", old_scan_id="a", new_scan_id="b")
        sent = asyncio.run(send_diff_alerts(report, notify_fn=None))
        assert sent == 0


# ──────────────────────────────────────────────────────────────
# 10. full_scan.py wiring correctness
# ──────────────────────────────────────────────────────────────

class TestFullScanDiffWiring:
    def test_uses_program_name_not_state_target(self):
        """Diff section must use _adb._program_name() for consistency."""
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        # Must use _adb._program_name(state) not state.target for DiffEngine
        assert "_adb._program_name(state)" in src or \
               "_program_name(state)" in src

    def test_uses_id_key_not_scan_id(self):
        """Must access scan_runs dict via 'id' not 'scan_id'."""
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        # Find the DiffEngine section
        idx = src.find("DiffEngine + Alerts")
        assert idx > 0
        section = src[idx:idx + 1500]
        # Should use .get("id") not .get("scan_id") for prior scan lookup
        assert '.get("id"' in section or ".get('id'" in section
        # Must NOT use .get("scan_id") for scan_runs
        assert '.get("scan_id")' not in section

    def test_prior_scans_first_not_last(self):
        """get_scan_runs returns DESC order, so [0] is most recent."""
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        idx = src.find("DiffEngine + Alerts")
        section = src[idx:idx + 1500]
        assert "_prior_scans[0]" in section
        assert "_prior_scans[-1]" not in section
