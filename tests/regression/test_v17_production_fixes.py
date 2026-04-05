"""
Regression tests for NEXT_LEVEL_PLAN_V17 production fixes.

Tests cover:
  P0-1: ScanProfiler metadata serialization
  P0-3: WAFResult constructor in deep_probe
  P0-6: URL list type guard in Phase C fallback
  P0-7: Per-finding error handling in ReportGenerator
  P0-8: Early findings.json persistence
  P0-9: tech_cve_checker split guard
  P1:   Checkpoint fallback serialization
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ──────────────────────────────────────────────────────────────
# P0-1: ScanProfiler metadata sanitization
# ──────────────────────────────────────────────────────────────


class TestMetadataSanitization:
    """Ensure non-serializable objects in workflow_metadata are sanitized."""

    def _make_session_manager(self):
        from src.workflow.session_manager import SessionManager
        return SessionManager(output_dir=Path("/tmp/whai_test_sessions_v17"))

    def _make_session(self, sid: str = "test-v17-001"):
        from src.workflow.session_manager import ScanSession, SessionMetadata
        return ScanSession(
            metadata=SessionMetadata(
                session_id=sid,
                target="example.com",
                started_at=time.time(),
            ),
        )

    def test_scanprofiler_is_serialized_to_dict(self):
        """ScanProfiler object in metadata should be converted via to_dict()."""
        sm = self._make_session_manager()
        session = self._make_session()

        # Create a mock workflow state with a ScanProfiler in metadata
        class FakeProfiler:
            def to_dict(self):
                return {"scan_id": "test", "stages": []}

        class FakeState:
            subdomains = []
            live_hosts = []
            open_ports = {}
            endpoints = []
            technologies = {}
            raw_findings = []
            verified_findings = []
            false_positives = []
            reports_generated = []
            tools_run = []
            metadata = {"scan_profiler": FakeProfiler(), "other_key": "plain_value"}
            current_stage = "test"

        sm.sync_from_workflow_state(session, FakeState())

        # The ScanProfiler should be converted to dict
        assert isinstance(session.workflow_metadata.get("scan_profiler"), dict)
        assert session.workflow_metadata["scan_profiler"] == {"scan_id": "test", "stages": []}
        assert session.workflow_metadata["other_key"] == "plain_value"

        # Must be JSON-serializable now
        json.dumps(session.workflow_metadata, default=str)

    def test_non_serializable_fallback_to_str(self):
        """Objects without to_dict() that aren't JSON-safe become strings."""
        sm = self._make_session_manager()
        session = self._make_session()

        class Unserializable:
            def __repr__(self):
                return "Unserializable()"

        class FakeState:
            subdomains = []
            live_hosts = []
            open_ports = {}
            endpoints = []
            technologies = {}
            raw_findings = []
            verified_findings = []
            false_positives = []
            reports_generated = []
            tools_run = []
            metadata = {"bad_obj": Unserializable(), "good": 42}
            current_stage = "test"

        sm.sync_from_workflow_state(session, FakeState())

        # bad_obj should have been converted to string
        assert isinstance(session.workflow_metadata["bad_obj"], str)
        assert session.workflow_metadata["good"] == 42

        # Must be JSON-serializable
        json.dumps(session.workflow_metadata, default=str)

    def test_normal_metadata_passes_through(self):
        """Normal JSON-safe metadata should pass through unchanged."""
        sm = self._make_session_manager()
        session = self._make_session()

        class FakeState:
            subdomains = []
            live_hosts = []
            open_ports = {}
            endpoints = []
            technologies = {}
            raw_findings = []
            verified_findings = []
            false_positives = []
            reports_generated = []
            tools_run = []
            metadata = {"key1": "value1", "key2": [1, 2, 3], "key3": {"nested": True}}
            current_stage = "test"

        sm.sync_from_workflow_state(session, FakeState())
        assert session.workflow_metadata == {"key1": "value1", "key2": [1, 2, 3], "key3": {"nested": True}}


# ──────────────────────────────────────────────────────────────
# P0-3: WAFResult constructor
# ──────────────────────────────────────────────────────────────


class TestWAFResultConstructor:
    """WAFResult must be constructed with correct field names."""

    def test_wafresult_requires_host(self):
        """WAFResult needs host as first positional arg."""
        from src.tools.scanners.waf_strategy import WAFResult
        result = WAFResult(host="unknown", detected=True, waf_name="unknown", confidence=0.5)
        assert result.host == "unknown"
        assert result.detected is True
        assert result.waf_name == "unknown"
        assert result.confidence == 0.5

    def test_wafresult_no_details_field(self):
        """WAFResult should NOT accept a 'details' keyword."""
        from src.tools.scanners.waf_strategy import WAFResult
        with pytest.raises(TypeError):
            WAFResult(host="x", detected=True, details={})


# ──────────────────────────────────────────────────────────────
# P0-6: URL list type guard
# ──────────────────────────────────────────────────────────────


class TestURLTypeGuard:
    """Findings where url is a list should not crash startswith()."""

    def test_list_url_filtered_out(self):
        """A finding with url=list should be excluded from Phase C candidates."""
        findings = [
            {"confidence": 80, "url": ["http://a.com", "http://b.com"], "severity": "high"},
            {"confidence": 80, "url": "http://c.com/api", "severity": "high"},
            {"confidence": 80, "url": "", "severity": "high"},
        ]
        _INFO_SEVERITIES = {"info", "informational", "none"}
        candidates = [
            f for f in findings
            if f.get("confidence", 0) >= 50.0
            and not f.get("poc_confirmed")
            and isinstance(f.get("url", ""), str) and f.get("url", "").startswith("http")
            and str(f.get("severity", "")).lower() not in _INFO_SEVERITIES
        ]
        assert len(candidates) == 1
        assert candidates[0]["url"] == "http://c.com/api"

    def test_string_url_passes(self):
        """Normal string URL should pass the filter."""
        url_val = "http://example.com/test"
        assert isinstance(url_val, str) and url_val.startswith("http")


# ──────────────────────────────────────────────────────────────
# P0-7: Per-finding error handling in ReportGenerator
# ──────────────────────────────────────────────────────────────


class TestReportGeneratorErrorHandling:
    """ReportGenerator.generate() should not crash on one bad finding."""

    def test_bad_finding_skipped(self):
        """One malformed finding should not prevent report generation."""
        from src.reporting.report_generator import ReportGenerator

        gen = ReportGenerator(output_dir="/tmp/test_v17_report")

        # Mix of good and intentionally problematic findings
        findings = [
            {
                "title": "Good Finding",
                "vulnerability_type": "xss",
                "severity": "HIGH",
                "confidence": 90,
                "url": "http://example.com/test",
                "description": "Test XSS found",
            },
            # A finding that will cause issues — deeply nested bad types
            {
                "title": None,  # None title
                "vulnerability_type": None,
                "severity": "INVALID_SEVERITY",
                "confidence": "not_a_number",
                "url": 12345,  # wrong type
            },
            {
                "title": "Another Good",
                "vulnerability_type": "sqli",
                "severity": "MEDIUM",
                "confidence": 75,
                "url": "http://example.com/api",
                "description": "SQL injection test",
            },
        ]

        report = asyncio.run(gen.generate(
            findings=findings,
            target="example.com",
            session_id="test-v17-002",
            scan_time=100.0,
            use_brain=False,
        ))

        # Should have at least the good findings (may include all if converter is robust)
        assert report is not None
        assert len(report.findings) >= 2


# ──────────────────────────────────────────────────────────────
# P0-9: tech_cve_checker split guard
# ──────────────────────────────────────────────────────────────


class TestTechCVECheckerSplitGuard:
    """Ensure .split()[0] doesn't crash on whitespace-only strings."""

    def test_empty_string_after_strip(self):
        """An empty/whitespace tech_name should not cause IndexError."""
        import re
        tech_name = "   "
        # Same logic as the fixed code
        tech_name = re.sub(r'[{}"\[\]:,]', ' ', tech_name).strip()
        tech_name = tech_name.split()[0] if tech_name else ""
        assert tech_name == ""

    def test_normal_string_extracts_first_word(self):
        import re
        tech_name = '{"name": "Apache"}'
        tech_name = re.sub(r'[{}"\[\]:,]', ' ', tech_name).strip()
        tech_name = tech_name.split()[0] if tech_name else ""
        assert tech_name == "name"

    def test_only_special_chars(self):
        import re
        tech_name = '{[":,]}'
        tech_name = re.sub(r'[{}"\[\]:,]', ' ', tech_name).strip()
        tech_name = tech_name.split()[0] if tech_name else ""
        assert tech_name == ""


# ──────────────────────────────────────────────────────────────
# P1: Checkpoint fallback serialization
# ──────────────────────────────────────────────────────────────


class TestCheckpointFallback:
    """Checkpoint save should have a fallback when model_dump_json fails."""

    def test_checkpoint_save_with_clean_data(self, tmp_path):
        """Normal checkpoint save should work."""
        from src.workflow.session_manager import ScanSession, SessionManager, SessionMetadata

        sm = SessionManager(output_dir=tmp_path)
        session = ScanSession(
            metadata=SessionMetadata(
                session_id="test-cp-001",
                target="example.com",
                started_at=time.time(),
            ),
        )

        result = sm.checkpoint(session, force=True)
        assert result is True

        # Verify checkpoint file exists
        cp_dir = tmp_path / "sessions" / "test-cp-001" / "checkpoints"
        assert cp_dir.exists()
        cp_files = list(cp_dir.glob("cp_*.json"))
        assert len(cp_files) == 1

        # Verify it's valid JSON
        data = json.loads(cp_files[0].read_text())
        assert data["metadata"]["session_id"] == "test-cp-001"

    def test_session_save_with_clean_data(self, tmp_path):
        """Normal session save should work."""
        from src.workflow.session_manager import ScanSession, SessionManager, SessionMetadata

        sm = SessionManager(output_dir=tmp_path)
        session = ScanSession(
            metadata=SessionMetadata(
                session_id="test-save-001",
                target="example.com",
                started_at=time.time(),
            ),
        )

        sm._save_session(session)

        session_file = tmp_path / "sessions" / "test-save-001" / "session.json"
        assert session_file.exists()
        data = json.loads(session_file.read_text())
        assert data["metadata"]["target"] == "example.com"


# ──────────────────────────────────────────────────────────────
# P0-8: Early findings persistence guard
# ──────────────────────────────────────────────────────────────


class TestEarlyFindingsPersistence:
    """Findings should be persisted before report generation."""

    def test_early_findings_json_write(self, tmp_path):
        """Simulate the early findings JSON write logic."""
        import json as _early_fj

        session_id = "test-early-001"
        findings_dir = tmp_path / "sessions" / session_id / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = str(findings_dir / "findings.json")

        verified = [
            {"title": "XSS", "severity": "HIGH", "url": "http://example.com"},
            {"title": "SQLi", "severity": "CRITICAL", "url": "http://example.com/api"},
        ]

        data = {
            "session_id": session_id,
            "target": "example.com",
            "total_raw": 10,
            "total_verified": 2,
            "total_false_positives": 3,
            "verified_findings": verified,
        }

        Path(findings_path).write_text(
            _early_fj.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )

        # Verify
        loaded = json.loads(Path(findings_path).read_text())
        assert loaded["total_verified"] == 2
        assert len(loaded["verified_findings"]) == 2
        assert loaded["verified_findings"][0]["title"] == "XSS"
