"""
Tests for Phase 6 modules — Continuous Operation Infrastructure.

Covers:
- P6-3: GlobalFindingStore (finding_hash, dedup, lifecycle)
- P6-5: ScanProfiler (timing, bottleneck detection, report)
- P6-1: ContinuousMonitor (init, iteration logic)
- P6-4: AutoDraftGenerator (qualification, rendering)
- P6-2: CampaignManager (from_file, scope matching, signal)
- Pipeline wiring (GlobalFindingStore + ScanProfiler + AutoDraft in full_scan)
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ============================================================
# P6-3: GlobalFindingStore Tests
# ============================================================


class TestFindingHash:
    """Test canonical finding_hash() function."""

    def test_basic_hash(self):
        from src.analysis.global_finding_store import finding_hash

        h = finding_hash({
            "vulnerability_type": "XSS",
            "url": "https://example.com/search?q=test",
        })
        assert isinstance(h, str)
        assert len(h) == 16

    def test_hash_stability(self):
        """Same finding should always produce the same hash."""
        from src.analysis.global_finding_store import finding_hash

        f = {
            "vulnerability_type": "SQL Injection",
            "url": "https://example.com/api/user?id=1",
            "parameter": "id",
        }
        h1 = finding_hash(f)
        h2 = finding_hash(f)
        assert h1 == h2

    def test_hash_ignores_extra_fields(self):
        """Hash should be based only on canonical fields."""
        from src.analysis.global_finding_store import finding_hash

        base = {
            "vulnerability_type": "XSS",
            "url": "https://example.com/page",
        }
        extended = {
            **base,
            "tool": "nuclei",
            "confidence": 85,
            "severity": "HIGH",
        }
        assert finding_hash(base) == finding_hash(extended)

    def test_hash_parameter_sensitivity(self):
        """Different parameters should produce different hashes."""
        from src.analysis.global_finding_store import finding_hash

        h1 = finding_hash({
            "vulnerability_type": "SQLi",
            "url": "https://example.com/api",
            "parameter": "id",
        })
        h2 = finding_hash({
            "vulnerability_type": "SQLi",
            "url": "https://example.com/api",
            "parameter": "name",
        })
        assert h1 != h2

    def test_hash_url_normalisation(self):
        """URL trailing slash and query param order shouldn't change hash."""
        from src.analysis.global_finding_store import finding_hash

        h1 = finding_hash({
            "vulnerability_type": "XSS",
            "url": "https://example.com/path?b=2&a=1",
        })
        h2 = finding_hash({
            "vulnerability_type": "XSS",
            "url": "https://example.com/path/?a=1&b=2",
        })
        assert h1 == h2

    def test_hash_vuln_type_synonyms(self):
        """Synonym vuln types should hash to the same canonical type."""
        from src.analysis.global_finding_store import finding_hash

        h1 = finding_hash({
            "vulnerability_type": "xss_reflected",
            "url": "https://example.com/search",
        })
        h2 = finding_hash({
            "vulnerability_type": "reflected_xss",
            "url": "https://example.com/search",
        })
        assert h1 == h2

    def test_hash_different_vuln_types(self):
        """Different vuln types should produce different hashes."""
        from src.analysis.global_finding_store import finding_hash

        h1 = finding_hash({
            "vulnerability_type": "XSS",
            "url": "https://example.com/page",
        })
        h2 = finding_hash({
            "vulnerability_type": "SQLi",
            "url": "https://example.com/page",
        })
        assert h1 != h2

    def test_hash_cve_sensitivity(self):
        """Different CVEs should produce different hashes."""
        from src.analysis.global_finding_store import finding_hash

        h1 = finding_hash({
            "vulnerability_type": "RCE",
            "url": "https://example.com",
            "cve_id": "CVE-2024-1234",
        })
        h2 = finding_hash({
            "vulnerability_type": "RCE",
            "url": "https://example.com",
            "cve_id": "CVE-2024-5678",
        })
        assert h1 != h2


class TestCanonicalVulnType:
    """Test _canonical_vuln_type normalisation."""

    def test_known_synonyms(self):
        from src.analysis.global_finding_store import _canonical_vuln_type

        assert _canonical_vuln_type("xss_reflected") == "xss"
        assert _canonical_vuln_type("SQL Injection") == "sqli"
        assert _canonical_vuln_type("command-injection") == "rce"
        assert _canonical_vuln_type("Open Redirect") == "redirect"

    def test_passthrough(self):
        from src.analysis.global_finding_store import _canonical_vuln_type

        assert _canonical_vuln_type("unknown_type") == "unknown_type"


class TestNormaliseUrl:
    """Test _normalise_url function."""

    def test_strip_trailing_slash(self):
        from src.analysis.global_finding_store import _normalise_url

        assert _normalise_url("https://example.com/path/") == "https://example.com/path"

    def test_sort_query_params(self):
        from src.analysis.global_finding_store import _normalise_url

        result = _normalise_url("https://example.com/page?z=1&a=2")
        assert "a=2" in result
        assert result.index("a=2") < result.index("z=1")

    def test_strip_fragment(self):
        from src.analysis.global_finding_store import _normalise_url

        result = _normalise_url("https://example.com/page#section")
        assert "#" not in result

    def test_lowercase_scheme_host(self):
        from src.analysis.global_finding_store import _normalise_url

        result = _normalise_url("HTTPS://EXAMPLE.COM/Path")
        assert result.startswith("https://example.com/")


class TestGlobalFindingStore:
    """Test GlobalFindingStore SQLite operations."""

    def _make_store(self, tmp_path: Path):
        from src.analysis.global_finding_store import GlobalFindingStore

        return GlobalFindingStore(db_path=str(tmp_path / "test_gfs.db"))

    def test_lookup_new(self, tmp_path):
        store = self._make_store(tmp_path)
        finding = {"vulnerability_type": "XSS", "url": "https://example.com/a"}
        result = store.lookup(finding)
        assert result.is_new
        assert not result.is_regression
        assert result.times_seen == 0

    def test_record_and_lookup(self, tmp_path):
        store = self._make_store(tmp_path)
        finding = {"vulnerability_type": "XSS", "url": "https://example.com/a"}
        store.record(finding, scan_id="scan1", program="prog1")

        result = store.lookup(finding)
        assert not result.is_new
        assert result.times_seen >= 1

    def test_lifecycle_new_recurring_resolved_regression(self, tmp_path):
        """Full lifecycle: new → recurring → resolved → regression."""
        from src.analysis.global_finding_store import FindingStatus

        store = self._make_store(tmp_path)
        f = {"vulnerability_type": "SQLi", "url": "https://example.com/api"}

        from src.analysis.global_finding_store import finding_hash
        h = finding_hash(f)

        # Scan 1: new
        d1 = store.record(f, scan_id="s1", program="p1")
        assert d1.is_new
        gf1 = store.get_finding(h)
        assert gf1 is not None
        assert gf1.status == FindingStatus.NEW

        # Scan 2: recurring
        d2 = store.record(f, scan_id="s2", program="p1")
        assert not d2.is_new
        assert not d2.is_regression
        gf2 = store.get_finding(h)
        assert gf2.status == FindingStatus.RECURRING

        # Resolve
        store.mark_resolved_not_in_scan(scan_id="s3", program="p1")
        gf3 = store.get_finding(h)
        assert gf3.status == FindingStatus.RESOLVED

        # Scan 4: regression
        d4 = store.record(f, scan_id="s4", program="p1")
        assert d4.is_regression
        gf4 = store.get_finding(h)
        assert gf4.status == FindingStatus.REGRESSION

    def test_record_batch(self, tmp_path):
        store = self._make_store(tmp_path)
        findings = [
            {"vulnerability_type": "XSS", "url": "https://example.com/a"},
            {"vulnerability_type": "SQLi", "url": "https://example.com/b"},
            {"vulnerability_type": "SSRF", "url": "https://example.com/c"},
        ]
        results = store.record_batch(findings, scan_id="s1", program="p1")
        assert len(results) == 3
        assert all(r.is_new for r in results)

    def test_get_new_findings(self, tmp_path):
        store = self._make_store(tmp_path)
        f1 = {"vulnerability_type": "XSS", "url": "https://a.com"}
        f2 = {"vulnerability_type": "SQLi", "url": "https://b.com"}
        store.record(f1, scan_id="s1", program="p")
        store.record(f2, scan_id="s1", program="p")

        new_findings = store.get_new_findings("s1")
        assert len(new_findings) == 2

    def test_get_stats(self, tmp_path):
        store = self._make_store(tmp_path)
        store.record({"vulnerability_type": "XSS", "url": "https://a.com"}, "s1", "p")
        store.record({"vulnerability_type": "SQLi", "url": "https://b.com"}, "s1", "p")

        stats = store.get_stats("p")
        assert stats["total"] == 2

    def test_count(self, tmp_path):
        store = self._make_store(tmp_path)
        assert store.count() == 0
        store.record({"vulnerability_type": "XSS", "url": "https://a.com"}, "s1", "p")
        assert store.count() == 1
        assert store.count(program="p") == 1
        assert store.count(program="other") == 0

    def test_record_handles_list_typed_fields(self, tmp_path):
        store = self._make_store(tmp_path)
        finding = {
            "vulnerability_type": ["XSS"],
            "url": ["https://example.com/a"],
            "parameter": ["q"],
            "severity": ["HIGH"],
            "target": ["example.com"],
        }

        result = store.record(finding, scan_id="s1", program="p1")

        assert result.is_new is True
        stored = store.get_new_findings("s1")
        assert stored[0].endpoint == "https://example.com/a"
        assert stored[0].parameter == "q"
        assert stored[0].severity == "high"


# ============================================================
# P6-5: ScanProfiler Tests
# ============================================================


class TestScanProfiler:
    """Test ScanProfiler timing and bottleneck detection."""

    def test_stage_recording(self):
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        p.record_stage("recon", duration_s=10.0, findings_count=3)
        p.record_stage("vuln_scan", duration_s=50.0, findings_count=5)
        p.end_scan()

        report = p.generate_report()
        assert len(report.stage_timings) == 2
        assert report.total_duration_s > 0

    def test_tool_recording(self):
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        p.record_tool("nmap", 5.0, True, findings_count=2)
        p.record_tool("subfinder", 3.0, True, findings_count=0)
        p.end_scan()

        report = p.generate_report()
        assert "nmap" in report.tool_effectiveness
        assert report.tool_effectiveness["nmap"]["findings"] == 2

    def test_bottleneck_detection_slow_stage(self):
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        p.record_stage("fast_stage", duration_s=10.0, findings_count=5)
        p.record_stage("slow_stage", duration_s=200.0, findings_count=0)
        p.end_scan()

        report = p.generate_report()
        # slow_stage is >30% of total and >60s → should be flagged
        stage_bottlenecks = [b for b in report.bottlenecks if b.category == "stage"]
        assert len(stage_bottlenecks) >= 1
        assert any("slow_stage" in b.name for b in stage_bottlenecks)

    def test_bottleneck_detection_dead_tool(self):
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        p.record_tool("slow_tool", 150.0, True, findings_count=0)
        p.record_tool("fast_tool", 5.0, True, findings_count=3)
        p.end_scan()

        report = p.generate_report()
        tool_bottlenecks = [b for b in report.bottlenecks if b.category == "tool"]
        # slow_tool: >120s with 0 findings → should be flagged
        assert any("slow_tool" in b.name for b in tool_bottlenecks)

    def test_stage_context_manager(self):
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        with p.stage("test_stage"):
            time.sleep(0.01)  # minimal sleep
        p.end_scan()

        report = p.generate_report()
        assert len(report.stage_timings) == 1
        assert report.stage_timings[0].stage_name == "test_stage"
        assert report.stage_timings[0].duration_s >= 0.01

    def test_markdown_report(self):
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        p.record_stage("recon", duration_s=10.0, findings_count=2)
        p.end_scan()

        report = p.generate_report()
        md = report.to_markdown()
        assert "# Scan Performance Report" in md
        assert "recon" in md

    def test_to_dict(self):
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        p.record_stage("a", duration_s=5.0, findings_count=1)
        p.end_scan()

        d = p.to_dict()
        assert "stages" in d
        assert "total_duration_s" in d

    def test_recommendations(self):
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        p.record_tool("tool_a", 200.0, True, findings_count=0)
        p.record_tool("tool_b", 10.0, True, findings_count=10)
        p.end_scan()

        report = p.generate_report()
        assert any("tool_a" in r.lower() or "dead weight" in r.lower() for r in report.recommendations)


# ============================================================
# P6-4: AutoDraftGenerator Tests
# ============================================================


class TestAutoDraftGenerator:
    """Test auto-draft report generation."""

    def test_should_draft_high(self):
        from src.reporting.auto_draft import AutoDraftGenerator

        gen = AutoDraftGenerator()
        assert gen.should_draft({"severity": "HIGH", "confidence": 50})
        assert gen.should_draft({"severity": "CRITICAL", "confidence": 30})

    def test_should_draft_medium_high_confidence(self):
        from src.reporting.auto_draft import AutoDraftGenerator

        gen = AutoDraftGenerator()
        assert gen.should_draft({"severity": "MEDIUM", "confidence_score": 85})
        assert not gen.should_draft({"severity": "MEDIUM", "confidence_score": 60})

    def test_should_not_draft_low(self):
        from src.reporting.auto_draft import AutoDraftGenerator

        gen = AutoDraftGenerator()
        assert not gen.should_draft({"severity": "LOW", "confidence": 90})
        assert not gen.should_draft({"severity": "INFO"})

    def test_generate_draft_hackerone(self, tmp_path):
        from src.reporting.auto_draft import AutoDraftGenerator

        gen = AutoDraftGenerator(output_dir=str(tmp_path), platform="hackerone", target="example.com")
        finding = {
            "title": "Reflected XSS in search parameter",
            "vulnerability_type": "xss",
            "severity": "HIGH",
            "url": "https://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "confidence_score": 85,
            "description": "User input is reflected without encoding.",
        }
        path = gen.generate_draft(finding, scan_id="test_scan")
        assert path is not None
        assert path.exists()
        content = path.read_text()
        assert "example.com" in content
        assert "HackerOne" in content
        assert "DRAFT" in content
        assert "CWE-79" in content

    def test_generate_draft_bugcrowd(self, tmp_path):
        from src.reporting.auto_draft import AutoDraftGenerator

        gen = AutoDraftGenerator(output_dir=str(tmp_path), platform="bugcrowd", target="test.com")
        finding = {
            "title": "SQL Injection",
            "vulnerability_type": "sqli",
            "severity": "CRITICAL",
            "url": "https://test.com/api",
            "confidence_score": 95,
        }
        path = gen.generate_draft(finding)
        assert path is not None
        content = path.read_text()
        assert "Bugcrowd" in content
        assert "P1" in content

    def test_generate_batch(self, tmp_path):
        from src.reporting.auto_draft import AutoDraftGenerator

        gen = AutoDraftGenerator(output_dir=str(tmp_path), target="t.com")
        findings = [
            {"title": "XSS", "severity": "HIGH", "vulnerability_type": "xss", "url": "https://t.com/a", "confidence_score": 80},
            {"title": "Info", "severity": "INFO", "vulnerability_type": "info", "url": "https://t.com/b"},
            {"title": "SQLi", "severity": "CRITICAL", "vulnerability_type": "sqli", "url": "https://t.com/c", "confidence_score": 90},
        ]
        paths = gen.generate_batch(findings)
        # Should only generate for HIGH and CRITICAL
        assert len(paths) == 2

    def test_skip_low_confidence(self, tmp_path):
        from src.reporting.auto_draft import AutoDraftGenerator

        gen = AutoDraftGenerator(output_dir=str(tmp_path))
        finding = {"title": "Maybe XSS", "severity": "MEDIUM", "confidence_score": 40}
        path = gen.generate_draft(finding)
        assert path is None

    def test_drafts_generated_property(self, tmp_path):
        from src.reporting.auto_draft import AutoDraftGenerator

        gen = AutoDraftGenerator(output_dir=str(tmp_path))
        assert gen.drafts_generated == []
        gen.generate_draft({"title": "X", "severity": "HIGH", "vulnerability_type": "xss", "url": "https://x.com", "confidence": 80})
        assert len(gen.drafts_generated) == 1


# ============================================================
# P6-2: CampaignManager Tests
# ============================================================


class TestCampaignManager:
    """Test CampaignManager multi-target orchestration."""

    def test_from_file(self, tmp_path):
        from src.workflow.campaign_manager import CampaignManager

        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("example.com\ntest.com\n# comment\n\nanother.com\n")

        cm = CampaignManager.from_file(str(targets_file))
        assert len(cm.targets) == 3
        assert "example.com" in cm.targets
        assert "# comment" not in cm.targets

    def test_from_file_not_found(self):
        from src.workflow.campaign_manager import CampaignManager

        with pytest.raises(FileNotFoundError):
            CampaignManager.from_file("/nonexistent/targets.txt")

    def test_from_file_empty(self, tmp_path):
        from src.workflow.campaign_manager import CampaignManager

        targets_file = tmp_path / "empty.txt"
        targets_file.write_text("# only comments\n\n")

        with pytest.raises(ValueError, match="No targets found"):
            CampaignManager.from_file(str(targets_file))

    def test_find_scope_file(self, tmp_path):
        from src.workflow.campaign_manager import CampaignManager

        scope_dir = tmp_path / "scopes"
        scope_dir.mkdir()
        (scope_dir / "example_com.yaml").write_text("target: example.com")

        cm = CampaignManager(
            targets=["example.com"],
            scope_dir=str(scope_dir),
        )
        found = cm._find_scope_file("example.com")
        assert found is not None
        assert found.name == "example_com.yaml"

    def test_find_scope_file_no_match(self, tmp_path):
        from src.workflow.campaign_manager import CampaignManager

        scope_dir = tmp_path / "scopes"
        scope_dir.mkdir()

        cm = CampaignManager(targets=["unknown.com"], scope_dir=str(scope_dir))
        assert cm._find_scope_file("unknown.com") is None

    def test_campaign_id_format(self):
        from src.workflow.campaign_manager import CampaignManager

        cm = CampaignManager(targets=["a.com"])
        assert cm.campaign_id.startswith("campaign_")

    def test_campaign_report_to_markdown(self):
        from src.workflow.campaign_manager import CampaignReport, TargetResult

        report = CampaignReport(
            campaign_id="test_campaign",
            started_at="2025-01-01T00:00:00Z",
            finished_at="2025-01-01T01:00:00Z",
            duration_s=3600,
            targets_total=2,
            targets_completed=1,
            targets_failed=1,
            total_findings=5,
            total_high_crit=2,
            results=[
                TargetResult(target="a.com", status="completed", findings_total=5, findings_high_crit=2),
                TargetResult(target="b.com", status="failed", error="Connection refused"),
            ],
        )
        md = report.to_markdown()
        assert "Campaign Report" in md
        assert "a.com" in md
        assert "completed" in md
        assert "failed" in md

    def test_signal_handler_sets_event(self):
        from src.workflow.campaign_manager import CampaignManager

        cm = CampaignManager(targets=["a.com", "b.com"])
        assert not cm._stop_event.is_set()
        cm._signal_handler()
        assert cm._stop_event.is_set()


# ============================================================
# P6-1: ContinuousMonitor Tests
# ============================================================


class TestContinuousMonitor:
    """Test ContinuousMonitor init and helper logic."""

    def test_init(self):
        from src.workflow.continuous_monitor import ContinuousMonitor

        cm = ContinuousMonitor(
            target="example.com",
            scope_file=None,
            profile="stealth",
            mode="autonomous",
        )
        assert cm.target == "example.com"
        assert cm.profile == "stealth"

    def test_stop(self):
        from src.workflow.continuous_monitor import ContinuousMonitor

        cm = ContinuousMonitor(target="test.com")
        assert not cm._stop_event.is_set()
        cm.stop()
        assert cm._stop_event.is_set()

    def test_run_single_iteration(self):
        """Test that monitor runs one iteration and stops with max_iterations=1."""
        from src.workflow.continuous_monitor import ContinuousMonitor

        cm = ContinuousMonitor(target="test.com")

        # Mock _run_one_iteration
        mock_result = {
            "scan_id": "test_scan",
            "iteration": 1,
            "new_findings": 0,
            "regressions": 0,
            "resolved": 0,
        }
        cm._run_one_iteration = AsyncMock(return_value=mock_result)
        cm._execute_scan = AsyncMock(return_value=MagicMock(
            raw_findings=[], verified_findings=[], false_positives=[],
            target="test.com", session_id="s1",
            metadata={}, tools_run=[],
        ))

        import asyncio
        result = asyncio.run(cm.run(interval_minutes=1, max_iterations=1))
        assert isinstance(result, dict)
        assert result["iterations"] >= 1


# ============================================================
# Pipeline Wiring Tests
# ============================================================


class TestPipelineWiring:
    """Verify Phase 6 modules are wired into full_scan.py."""

    def test_global_finding_store_import_in_pipeline(self):
        """GlobalFindingStore should be importable from the pipeline."""
        import importlib
        mod = importlib.import_module("src.analysis.global_finding_store")
        assert hasattr(mod, "GlobalFindingStore")
        assert hasattr(mod, "finding_hash")

    def test_scan_profiler_import(self):
        import importlib
        mod = importlib.import_module("src.analysis.scan_profiler")
        assert hasattr(mod, "ScanProfiler")
        assert hasattr(mod, "PerformanceReport")

    def test_auto_draft_import(self):
        import importlib
        mod = importlib.import_module("src.reporting.auto_draft")
        assert hasattr(mod, "AutoDraftGenerator")

    def test_continuous_monitor_import(self):
        import importlib
        mod = importlib.import_module("src.workflow.continuous_monitor")
        assert hasattr(mod, "ContinuousMonitor")

    def test_campaign_manager_import(self):
        import importlib
        mod = importlib.import_module("src.workflow.campaign_manager")
        assert hasattr(mod, "CampaignManager")
        assert hasattr(mod, "CampaignReport")

    def test_full_scan_references_global_finding_store(self):
        """Verify the pipeline source mentions GlobalFindingStore."""
        src = Path("src/workflow/pipelines/full_scan.py").read_text(encoding="utf-8")
        assert "GlobalFindingStore" in src

    def test_full_scan_references_scan_profiler(self):
        src = Path("src/workflow/pipelines/full_scan.py").read_text(encoding="utf-8")
        assert "ScanProfiler" in src

    def test_full_scan_references_auto_draft(self):
        src = Path("src/workflow/pipelines/full_scan.py").read_text(encoding="utf-8")
        assert "AutoDraftGenerator" in src

    def test_cli_has_monitor_command(self):
        src = Path("src/cli.py").read_text(encoding="utf-8")
        assert "def monitor(" in src

    def test_cli_has_campaign_command(self):
        src = Path("src/cli.py").read_text(encoding="utf-8")
        assert "def campaign(" in src


# ============================================================
# Edge Case Tests
# ============================================================


class TestEdgeCases:
    """Edge cases for GlobalFindingStore."""

    def test_empty_url(self):
        from src.analysis.global_finding_store import finding_hash

        h = finding_hash({"vulnerability_type": "xss", "url": ""})
        assert isinstance(h, str) and len(h) == 16

    def test_no_vuln_type(self):
        from src.analysis.global_finding_store import finding_hash

        h = finding_hash({"url": "https://a.com"})
        assert isinstance(h, str) and len(h) == 16

    def test_type_field_alias(self):
        """Finding with 'type' instead of 'vulnerability_type'."""
        from src.analysis.global_finding_store import finding_hash

        h1 = finding_hash({"vulnerability_type": "xss", "url": "https://a.com"})
        h2 = finding_hash({"type": "xss", "url": "https://a.com"})
        assert h1 == h2

    def test_endpoint_field_alias(self):
        """Finding with 'endpoint' instead of 'url'."""
        from src.analysis.global_finding_store import finding_hash

        h1 = finding_hash({"vulnerability_type": "xss", "url": "https://a.com/page"})
        h2 = finding_hash({"vulnerability_type": "xss", "endpoint": "https://a.com/page"})
        assert h1 == h2

    def test_concurrent_writes(self, tmp_path):
        """Multiple records in quick succession shouldn't fail."""
        from src.analysis.global_finding_store import GlobalFindingStore

        store = GlobalFindingStore(db_path=str(tmp_path / "concurrent.db"))
        for i in range(50):
            store.record(
                {"vulnerability_type": f"xss_{i}", "url": f"https://a.com/{i}"},
                scan_id="s1", program="p1",
            )
        assert store.count() == 50

    def test_auto_draft_missing_fields(self, tmp_path):
        """AutoDraft should handle findings with minimal fields."""
        from src.reporting.auto_draft import AutoDraftGenerator

        gen = AutoDraftGenerator(output_dir=str(tmp_path))
        # Minimal HIGH finding
        path = gen.generate_draft({"severity": "HIGH", "title": "Test"})
        assert path is not None
        assert path.exists()

    def test_profiler_empty_scan(self):
        """Profiler should handle a scan with no stages."""
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        p.end_scan()
        report = p.generate_report()
        assert report.total_duration_s >= 0
        assert len(report.stage_timings) == 0
        assert len(report.bottlenecks) == 0
