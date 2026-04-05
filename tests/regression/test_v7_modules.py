"""Tests for V7 new modules: benchmark, asset_db, gf_patterns, and new tools."""

from __future__ import annotations

import sqlite3
import time

import pytest


# ============================================================
# Benchmark Tests (V7-T0-1)
# ============================================================


class TestBenchmark:
    """src/analysis/benchmark.py tests."""

    def _make_benchmark(self, scan_id="test-001", **overrides):
        from src.analysis.benchmark import ScanBenchmark

        defaults = dict(
            scan_id=scan_id,
            target="example.com",
            timestamp="2025-01-01T00:00:00Z",
            duration_seconds=100.0,
            total_endpoints_tested=50,
            total_tools_run=3,
            raw_findings=20,
            confirmed_findings=8,
            fp_rate=60.0,
        )
        defaults.update(overrides)
        return ScanBenchmark(**defaults)

    def test_scan_benchmark_dataclass(self):
        b = self._make_benchmark()
        assert b.scan_id == "test-001"
        assert b.fp_rate == pytest.approx(60.0)
        assert b.tool_execution_counts == {}
        assert b.stage_finding_counts == {}
        assert b.module_impact == {}

    def test_scan_benchmark_zero_findings(self):
        b = self._make_benchmark(scan_id="z", raw_findings=0, confirmed_findings=0, fp_rate=0.0)
        assert b.fp_rate == 0.0

    def test_benchmark_store_save_and_get(self, tmp_path):
        from src.analysis.benchmark import BenchmarkStore

        db_path = tmp_path / "bench.db"
        store = BenchmarkStore(str(db_path))
        b = self._make_benchmark()
        store.save(b)

        loaded = store.get("test-001")
        assert loaded is not None
        assert loaded.target == "example.com"
        assert loaded.confirmed_findings == 8

    def test_benchmark_store_roundtrips_extended_json_fields(self, tmp_path):
        from src.analysis.benchmark import BenchmarkStore

        db_path = tmp_path / "bench_ext.db"
        store = BenchmarkStore(str(db_path))
        b = self._make_benchmark(
            tool_finding_counts={"jwt_checker": 2},
            tool_execution_counts={"jwt_checker": 1, "graphql_deep_scanner": 1},
            stage_finding_counts={"vulnerability_scan": 4},
            module_impact={"jwt_checker": 2, "graphql_deep_scanner": 0},
        )
        store.save(b)

        loaded = store.get("test-001")
        assert loaded is not None
        assert loaded.tool_finding_counts == {"jwt_checker": 2}
        assert loaded.tool_execution_counts["graphql_deep_scanner"] == 1
        assert loaded.stage_finding_counts["vulnerability_scan"] == 4
        assert loaded.module_impact["graphql_deep_scanner"] == 0

    def test_module_impact_includes_executed_tracked_tools_with_zero_findings(self):
        from src.analysis.benchmark import build_module_impact

        impact = build_module_impact(
            {"jwt_checker": 2},
            ["jwt_checker", "graphql_deep_scanner", "nuclei"],
        )

        assert impact["jwt_checker"] == 2
        assert impact["graphql_deep_scanner"] == 0

    def test_stage_finding_counts_builder(self):
        from types import SimpleNamespace
        from src.analysis.benchmark import build_stage_finding_counts

        counts = build_stage_finding_counts({
            "passive_recon": SimpleNamespace(findings_count=3),
            "enumeration": SimpleNamespace(findings_count=7),
        })

        assert counts == {"passive_recon": 3, "enumeration": 7}

    def test_benchmark_store_list(self, tmp_path):
        from src.analysis.benchmark import BenchmarkStore

        db_path = tmp_path / "bench2.db"
        store = BenchmarkStore(str(db_path))

        for i in range(3):
            store.save(self._make_benchmark(scan_id=f"s{i}"))
        items = store.list_all(target="example.com")
        assert len(items) == 3

    def test_benchmark_compare(self, tmp_path):
        from src.analysis.benchmark import BenchmarkStore

        db_path = tmp_path / "bench3.db"
        store = BenchmarkStore(str(db_path))
        store.save(self._make_benchmark(scan_id="a", confirmed_findings=8))
        store.save(self._make_benchmark(scan_id="b", confirmed_findings=15))

        diff = store.compare("a", "b")
        assert diff is not None
        assert diff.confirmed_change == 7


# ============================================================
# Asset DB Tests (V7-T0-2)
# ============================================================


class TestAssetDB:
    """src/integrations/asset_db.py tests."""

    def test_ensure_program(self, tmp_path):
        from src.integrations.asset_db import AssetDB

        db = AssetDB(str(tmp_path / "asset.db"))
        db.ensure_program("test-prog", "Test Program")
        # calling again should not raise
        db.ensure_program("test-prog", "Test Program")

    def test_upsert_and_get_assets(self, tmp_path):
        from src.integrations.asset_db import Asset, AssetDB

        db = AssetDB(str(tmp_path / "asset2.db"))
        db.ensure_program("prog1", "Program 1")

        assets = [
            Asset(asset_type="subdomain", value="sub1.example.com"),
            Asset(asset_type="subdomain", value="sub2.example.com"),
        ]
        inserted, updated = db.upsert_assets("prog1", "scan-001", assets)
        assert inserted == 2

        all_assets = db.get_assets("prog1")
        assert len(all_assets) >= 2

    def test_upsert_dedup(self, tmp_path):
        from src.integrations.asset_db import Asset, AssetDB

        db = AssetDB(str(tmp_path / "asset3.db"))
        db.ensure_program("p", "P")

        a = Asset(asset_type="subdomain", value="x.com")
        db.upsert_assets("p", "s1", [a])
        db.upsert_assets("p", "s2", [a])  # duplicate → update
        all_a = db.get_assets("p", asset_type="subdomain")
        assert len(all_a) == 1

    def test_diff_assets(self, tmp_path):
        from src.integrations.asset_db import Asset, AssetDB

        db = AssetDB(str(tmp_path / "asset4.db"))
        db.ensure_program("p", "P")

        # Scan 1: only a.com
        db.upsert_assets("p", "scan-old", [
            Asset(asset_type="subdomain", value="a.com"),
        ])
        # Scan 2: only c.com
        db.upsert_assets("p", "scan-new", [
            Asset(asset_type="subdomain", value="c.com"),
        ])

        diff = db.diff_assets("p", "scan-old", "scan-new")
        assert "c.com" in [a.value for a in diff.new_assets]
        assert "a.com" in [a.value for a in diff.disappeared_assets]

    def test_scan_run_lifecycle(self, tmp_path):
        from src.integrations.asset_db import AssetDB

        db = AssetDB(str(tmp_path / "asset5.db"))
        db.ensure_program("p", "P")

        db.record_scan_start("scan-001", "p")
        db.record_scan_finish("scan-001")
        runs = db.get_scan_runs("p")
        assert len(runs) == 1
        assert runs[0]["status"] == "completed"


# ============================================================
# GF Pattern Engine Tests (V7-T2-6)
# ============================================================


class TestGFPatterns:
    """src/tools/recon/web_discovery/gf_patterns.py tests."""

    def test_classify_xss(self):
        from src.tools.recon.web_discovery.gf_patterns import GFPatternEngine

        engine = GFPatternEngine()
        urls = [
            "https://example.com/search?q=test",
            "https://example.com/static/style.css",
        ]
        result = engine.classify(urls)
        assert len(result["xss"]) >= 1
        assert "https://example.com/search?q=test" in result["xss"]

    def test_classify_sqli(self):
        from src.tools.recon.web_discovery.gf_patterns import GFPatternEngine

        engine = GFPatternEngine()
        urls = ["https://example.com/product?id=123"]
        result = engine.classify(urls)
        assert "https://example.com/product?id=123" in result["sqli"]

    def test_filter(self):
        from src.tools.recon.web_discovery.gf_patterns import GFPatternEngine

        engine = GFPatternEngine()
        urls = [
            "https://example.com/redirect?url=http://evil.com",
            "https://example.com/about",
        ]
        redirects = engine.filter(urls, "redirect")
        assert len(redirects) == 1

    def test_filter_interesting(self):
        from src.tools.recon.web_discovery.gf_patterns import GFPatternEngine

        engine = GFPatternEngine()
        urls = [
            "https://example.com/search?q=x",
            "https://example.com/about",
            "https://example.com/api?cmd=ls",
        ]
        interesting = engine.filter_interesting(urls)
        assert len(interesting) >= 2  # search?q, ?cmd

    def test_unmatched(self):
        from src.tools.recon.web_discovery.gf_patterns import GFPatternEngine

        engine = GFPatternEngine()
        result = engine.classify(["https://example.com/about"])
        assert "https://example.com/about" in result["unmatched"]

    def test_add_pattern(self):
        from src.tools.recon.web_discovery.gf_patterns import GFPatternEngine

        engine = GFPatternEngine()
        engine.add_pattern("custom", r"custom_param=", "Test")
        urls = ["https://x.com/?custom_param=1"]
        assert len(engine.filter(urls, "custom")) == 1

    def test_categories(self):
        from src.tools.recon.web_discovery.gf_patterns import GFPatternEngine

        engine = GFPatternEngine()
        cats = engine.categories()
        assert "xss" in cats
        assert "sqli" in cats


# ============================================================
# GitHub Secret Scanner Tests (V7-T1-1)
# ============================================================


class TestGitHubSecretScanner:
    """src/tools/recon/osint/github_secret_scanner.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.osint.github_secret_scanner import GitHubSecretScanner

        scanner = GitHubSecretScanner()
        assert scanner.name == "github_secret_scanner"

    def test_is_available_without_token(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        from src.tools.recon.osint.github_secret_scanner import GitHubSecretScanner

        scanner = GitHubSecretScanner()
        assert scanner.is_available() is False

    def test_build_search_queries(self):
        from src.tools.recon.osint.github_secret_scanner import GitHubSecretScanner

        scanner = GitHubSecretScanner()
        queries = scanner._build_search_queries("example.com", {})
        assert len(queries) > 10
        assert any("example.com" in q for q in queries)

    def test_build_queries_with_org(self):
        from src.tools.recon.osint.github_secret_scanner import GitHubSecretScanner

        scanner = GitHubSecretScanner()
        queries = scanner._build_search_queries("example.com", {"org_name": "testorg"})
        assert any("org:testorg" in q for q in queries)

    def test_secret_patterns_compile(self):
        from src.tools.recon.osint.github_secret_scanner import _COMPILED_PATTERNS

        assert len(_COMPILED_PATTERNS) > 20
        # Check one pattern actually matches
        assert _COMPILED_PATTERNS["aws_access_key"].search("AKIAIOSFODNN7EXAMPLE")


# ============================================================
# Cloud Storage Enumerator Tests (V7-T1-2)
# ============================================================


class TestCloudStorageEnumerator:
    """src/tools/recon/osint/cloud_enum.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.osint.cloud_enum import CloudStorageEnumerator

        enum = CloudStorageEnumerator()
        assert enum.name == "cloud_storage_enum"
        assert enum.is_available() is True

    def test_derive_names(self):
        from src.tools.recon.osint.cloud_enum import CloudStorageEnumerator

        enum = CloudStorageEnumerator()
        names = enum._derive_names("sub.example.com", {})
        assert "example" in names
        assert "sub" in names

    def test_generate_bucket_names(self):
        from src.tools.recon.osint.cloud_enum import CloudStorageEnumerator

        enum = CloudStorageEnumerator()
        buckets = enum._generate_bucket_names(["example"])
        assert "example" in buckets
        assert "example-dev" in buckets
        assert "example-backup" in buckets
        assert len(buckets) > 20


# ============================================================
# Email Security Checker Tests (V7-T1-3)
# ============================================================


class TestEmailSecurityChecker:
    """src/tools/recon/dns/mail_security.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.dns.mail_security import EmailSecurityChecker

        checker = EmailSecurityChecker()
        assert checker.name == "email_security_checker"
        assert checker.is_available() is True


# ============================================================
# 403/401 Bypass Tests (V7-T2-4)
# ============================================================


class TestFourXXBypass:
    """src/tools/scanners/custom_checks/fourxx_bypass.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.scanners.custom_checks.fourxx_bypass import FourXXBypassChecker

        checker = FourXXBypassChecker()
        assert checker.name == "fourxx_bypass"
        assert checker.is_available() is True

    def test_path_mutations(self):
        from src.tools.scanners.custom_checks.fourxx_bypass import _path_mutations

        mutations = _path_mutations("/admin/dashboard")
        techniques = [m["technique"] for m in mutations]
        assert "trailing_slash" in techniques
        assert "spring_bypass" in techniques
        assert "encoded_slash" in techniques
        assert len(mutations) > 15

    def test_header_bypasses(self):
        from src.tools.scanners.custom_checks.fourxx_bypass import _header_bypasses

        bypasses = _header_bypasses()
        assert len(bypasses) > 20
        techniques = [b["technique"] for b in bypasses]
        assert any("X-Forwarded-For" in t for t in techniques)

    def test_method_overrides(self):
        from src.tools.scanners.custom_checks.fourxx_bypass import _method_overrides

        overrides = _method_overrides()
        assert len(overrides) >= 6


# ============================================================
# Asset DB Hooks Tests (V7-T0-3)
# ============================================================


class TestAssetDBHooks:
    """src/workflow/pipelines/asset_db_hooks.py tests."""

    def test_import(self):
        from src.workflow.pipelines import asset_db_hooks as hooks

        assert hasattr(hooks, "record_scan_start")
        assert hasattr(hooks, "save_subdomains")
        assert hasattr(hooks, "save_live_hosts")
        assert hasattr(hooks, "save_endpoints")
        assert hasattr(hooks, "save_verified_findings")
        assert hasattr(hooks, "record_scan_finish")

    def test_program_name_fallback(self):
        from src.workflow.pipelines.asset_db_hooks import _program_name

        class FakeState:
            scope_config = {}
            target = "example.com"

        assert _program_name(FakeState()) == "example.com"
