"""Tests for V7 modules batch 2: T1-4 through T4-4."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ============================================================
# Reverse IP Lookup Tests (V7-T1-4)
# ============================================================


class TestReverseIPLookup:
    """src/tools/recon/dns/reverse_ip.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.dns.reverse_ip import ReverseIPLookup

        tool = ReverseIPLookup()
        assert tool.name == "reverse_ip_lookup"
        assert tool.is_available() is True

    def test_parse_output_with_domains(self):
        from src.tools.recon.dns.reverse_ip import ReverseIPLookup

        tool = ReverseIPLookup()
        raw = "example.com\ntest.com\nfoo.bar.org"
        findings = tool.parse_output(raw, target="1.2.3.4")
        assert len(findings) == 1
        assert "3 domains" in findings[0].title

    def test_parse_output_empty(self):
        from src.tools.recon.dns.reverse_ip import ReverseIPLookup

        tool = ReverseIPLookup()
        findings = tool.parse_output("", target="1.2.3.4")
        assert findings == []

    def test_build_command_is_empty(self):
        from src.tools.recon.dns.reverse_ip import ReverseIPLookup

        tool = ReverseIPLookup()
        assert tool.build_command("example.com") == []


# ============================================================
# Metadata Extractor Tests (V7-T1-5)
# ============================================================


class TestMetadataExtractor:
    """src/tools/recon/osint/metadata_extractor.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.osint.metadata_extractor import MetadataExtractor

        tool = MetadataExtractor()
        assert tool.name == "metadata_extractor"
        assert tool.binary_name == "exiftool"

    def test_interesting_tags(self):
        from src.tools.recon.osint.metadata_extractor import _INTERESTING_TAGS

        assert "Author" in _INTERESTING_TAGS
        assert "Creator" in _INTERESTING_TAGS
        assert "Software" in _INTERESTING_TAGS

    def test_email_regex(self):
        from src.tools.recon.osint.metadata_extractor import _EMAIL_RE

        text = "contact is admin@example.com and info@test.org"
        matches = _EMAIL_RE.findall(text)
        assert "admin@example.com" in matches
        assert "info@test.org" in matches

    def test_internal_path_regex(self):
        from src.tools.recon.osint.metadata_extractor import _INTERNAL_PATH_RE

        assert _INTERNAL_PATH_RE.search("C:\\Users\\John\\Desktop\\report.pdf")
        assert _INTERNAL_PATH_RE.search("/home/john/documents/secret.txt")
        assert _INTERNAL_PATH_RE.search("/Users/admin/project/main.py")

    def test_build_command(self):
        from src.tools.recon.osint.metadata_extractor import MetadataExtractor

        tool = MetadataExtractor()
        cmd = tool.build_command("example.com")
        assert cmd == []  # Pure async Python, no single command


# ============================================================
# CDN Detector Tests (V7-T2-1)
# ============================================================


class TestCDNDetector:
    """src/tools/recon/tech_detect/cdn_detector.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.tech_detect.cdn_detector import CDNDetector

        tool = CDNDetector()
        assert tool.name == "cdn_detector"
        assert tool.is_available() is True

    def test_cdn_signatures_structure(self):
        from src.tools.recon.tech_detect.cdn_detector import _CDN_SIGNATURES

        assert "cloudflare" in _CDN_SIGNATURES
        assert "akamai" in _CDN_SIGNATURES
        assert "cloudfront" in _CDN_SIGNATURES
        # Each entry should have header+pattern keys
        for provider, sigs in _CDN_SIGNATURES.items():
            for sig in sigs:
                assert "header" in sig, f"Missing 'header' in {provider}"
                assert "pattern" in sig, f"Missing 'pattern' in {provider}"

    def test_cname_patterns(self):
        import re

        from src.tools.recon.tech_detect.cdn_detector import _CDN_CNAME_PATTERNS

        assert len(_CDN_CNAME_PATTERNS) >= 9
        # Verify patterns compile
        for pattern in _CDN_CNAME_PATTERNS:
            re.compile(pattern)

    def test_build_command(self):
        from src.tools.recon.tech_detect.cdn_detector import CDNDetector

        tool = CDNDetector()
        assert tool.build_command("example.com") == []


# ============================================================
# CSP Subdomain Discovery Tests (V7-T2-2)
# ============================================================


class TestCSPSubdomainDiscovery:
    """src/tools/recon/web_discovery/csp_discovery.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.web_discovery.csp_discovery import CSPSubdomainDiscovery

        tool = CSPSubdomainDiscovery()
        assert tool.name == "csp_subdomain_discovery"
        assert tool.is_available() is True

    def test_extract_domains(self):
        from src.tools.recon.web_discovery.csp_discovery import CSPSubdomainDiscovery

        tool = CSPSubdomainDiscovery()
        csp = "default-src 'self'; script-src cdn.example.com *.google.com; img-src images.test.org"
        domains = tool._extract_domains(csp)
        assert "cdn.example.com" in domains
        assert "google.com" in domains
        assert "images.test.org" in domains

    def test_extract_domains_skips_keywords(self):
        from src.tools.recon.web_discovery.csp_discovery import CSPSubdomainDiscovery

        tool = CSPSubdomainDiscovery()
        csp = "default-src 'self' 'unsafe-inline' 'unsafe-eval' 'none'"
        domains = tool._extract_domains(csp)
        assert "self" not in domains
        assert "none" not in domains

    def test_base_domain_helper(self):
        from src.tools.recon.web_discovery.csp_discovery import _base_domain

        assert _base_domain("https://sub.example.com/path") == "example.com"
        assert _base_domain("example.com") == "example.com"
        assert _base_domain("deep.sub.example.com") == "example.com"

    def test_parse_output(self):
        from src.tools.recon.web_discovery.csp_discovery import CSPSubdomainDiscovery

        tool = CSPSubdomainDiscovery()
        csp = "script-src cdn.example.com api.example.com third.party.com"
        findings = tool.parse_output(csp, target="example.com")
        assert len(findings) == 1
        assert "3" in findings[0].title or "domains" in findings[0].title


# ============================================================
# VHost Fuzzer Tests (V7-T2-3)
# ============================================================


class TestVHostFuzzer:
    """src/tools/recon/web_discovery/vhost_fuzzer.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.web_discovery.vhost_fuzzer import VHostFuzzer

        tool = VHostFuzzer()
        assert tool.name == "vhost_fuzzer"
        assert tool.is_available() is True  # has Python fallback

    def test_builtin_prefixes(self):
        from src.tools.recon.web_discovery.vhost_fuzzer import _BUILTIN_PREFIXES

        assert "admin" in _BUILTIN_PREFIXES
        assert "api" in _BUILTIN_PREFIXES
        assert "staging" in _BUILTIN_PREFIXES
        assert len(_BUILTIN_PREFIXES) >= 30

    def test_build_command_ffuf(self):
        from src.tools.recon.web_discovery.vhost_fuzzer import VHostFuzzer

        tool = VHostFuzzer()
        cmd = tool.build_command("example.com", options={"ip": "1.2.3.4"})
        # Should return ffuf command when options have ip
        assert isinstance(cmd, list)


# ============================================================
# Source Map Extractor Tests (V7-T2-5)
# ============================================================


class TestSourceMapExtractor:
    """src/tools/recon/web_discovery/sourcemap_extractor.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.web_discovery.sourcemap_extractor import SourceMapExtractor

        tool = SourceMapExtractor()
        assert tool.name == "sourcemap_extractor"
        assert tool.is_available() is True

    def test_secret_patterns_compile(self):
        from src.tools.recon.web_discovery.sourcemap_extractor import _SECRET_PATTERNS

        assert len(_SECRET_PATTERNS) >= 7
        # Verify all patterns match known test inputs
        assert _SECRET_PATTERNS["aws_key"].search("AKIAIOSFODNN7EXAMPLE")
        assert _SECRET_PATTERNS["jwt_token"].search("eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY3ODkw")
        assert _SECRET_PATTERNS["private_key"].search("-----BEGIN RSA PRIVATE KEY-----")
        assert _SECRET_PATTERNS["internal_url"].search("http://localhost:3000/api")

    def test_sourcemap_comment_regex(self):
        from src.tools.recon.web_discovery.sourcemap_extractor import _SOURCEMAP_COMMENT_RE

        js_code = "// some code\n//# sourceMappingURL=app.js.map\n"
        match = _SOURCEMAP_COMMENT_RE.search(js_code)
        assert match is not None
        assert match.group(1) == "app.js.map"

    def test_build_command(self):
        from src.tools.recon.web_discovery.sourcemap_extractor import SourceMapExtractor

        tool = SourceMapExtractor()
        assert tool.build_command("example.com") == []


# ============================================================
# Diff Engine Tests (V7-T3-1)
# ============================================================


class TestDiffEngine:
    """src/analysis/diff_engine.py tests."""

    def test_scan_diff_report_init(self):
        from src.analysis.diff_engine import ScanDiffReport

        report = ScanDiffReport(
            program_id="p1",
            old_scan_id="s-old",
            new_scan_id="s-new",
        )
        assert report.program_id == "p1"
        assert report.new_findings == []
        assert report.resolved_findings == []

    def test_diff_engine_with_db(self, tmp_path):
        from src.analysis.diff_engine import DiffEngine
        from src.integrations.asset_db import Asset, AssetDB

        db = AssetDB(str(tmp_path / "diff.db"))
        db.ensure_program("p", "Program")
        db.upsert_assets("p", "scan-old", [
            Asset(asset_type="subdomain", value="old.example.com"),
        ])
        db.upsert_assets("p", "scan-new", [
            Asset(asset_type="subdomain", value="new.example.com"),
        ])

        engine = DiffEngine(db)
        report = engine.diff("p", "scan-old", "scan-new")
        assert report.asset_diff is not None
        # new.example.com appears only in scan-new
        new_values = [a.value for a in report.asset_diff.new_assets]
        assert "new.example.com" in new_values

    def test_generate_markdown(self, tmp_path):
        from src.analysis.diff_engine import DiffEngine, ScanDiffReport
        from src.integrations.asset_db import Asset, AssetDB

        db = AssetDB(str(tmp_path / "diff2.db"))
        db.ensure_program("p", "Program")
        db.upsert_assets("p", "s1", [Asset(asset_type="subdomain", value="a.com")])
        db.upsert_assets("p", "s2", [Asset(asset_type="subdomain", value="b.com")])

        engine = DiffEngine(db)
        report = engine.diff("p", "s1", "s2")
        md = engine.generate_markdown(report)
        assert "Scan Diff Report" in md
        assert "s1" in md
        assert "s2" in md


# ============================================================
# Incremental Scan Tests (V7-T3-2)
# ============================================================


class TestIncrementalScan:
    """src/workflow/pipelines/incremental.py tests."""

    def test_compute_incremental_targets(self, tmp_path):
        from src.integrations.asset_db import Asset, AssetDB
        from src.workflow.pipelines.incremental import compute_incremental_targets

        db = AssetDB(str(tmp_path / "incr.db"))
        db.ensure_program("p", "Program")
        # Already known
        db.upsert_assets("p", "s1", [
            Asset(asset_type="subdomain", value="known.example.com"),
        ])

        result = compute_incremental_targets(
            db, "p",
            current_subdomains=["known.example.com", "new.example.com"],
            current_endpoints=["/api/v1", "/api/v2"],
        )
        assert "new.example.com" in result["new_subdomains"]
        assert "known.example.com" not in result["new_subdomains"]
        assert len(result["new_endpoints"]) == 2  # both new since no endpoints stored

    def test_get_last_scan_id_empty(self, tmp_path):
        from src.integrations.asset_db import AssetDB
        from src.workflow.pipelines.incremental import get_last_scan_id

        db = AssetDB(str(tmp_path / "incr2.db"))
        db.ensure_program("p", "Program")
        assert get_last_scan_id(db, "p") is None

    def test_get_last_scan_id_with_completed(self, tmp_path):
        from src.integrations.asset_db import AssetDB
        from src.workflow.pipelines.incremental import get_last_scan_id

        db = AssetDB(str(tmp_path / "incr3.db"))
        db.ensure_program("p", "Program")
        db.record_scan_start("scan-001", "p")
        db.record_scan_finish("scan-001")

        result = get_last_scan_id(db, "p")
        assert result == "scan-001"

    def test_should_rescan_endpoint(self):
        from src.workflow.pipelines.incremental import should_rescan_endpoint

        findings = [
            {"asset_value": "/api/v1", "status": "new"},
            {"asset_value": "/api/v2", "status": "fixed"},
        ]
        assert should_rescan_endpoint("/api/v1", findings) is True
        assert should_rescan_endpoint("/api/v2", findings) is False
        assert should_rescan_endpoint("/api/v3", findings) is False


# ============================================================
# Diff Alerts Tests (V7-T3-3)
# ============================================================


class TestDiffAlerts:
    """src/integrations/diff_alerts.py tests."""

    def test_no_notify_fn_returns_zero(self):
        from src.analysis.diff_engine import ScanDiffReport
        from src.integrations.diff_alerts import send_diff_alerts

        report = ScanDiffReport("p", "s1", "s2")
        result = asyncio.run(send_diff_alerts(report, notify_fn=None))
        assert result == 0

    def test_critical_finding_triggers_alert(self):
        from src.analysis.diff_engine import ScanDiffReport
        from src.integrations.diff_alerts import send_diff_alerts

        report = ScanDiffReport(
            "p", "s1", "s2",
            new_findings=[{"severity": "CRITICAL", "title": "SQLi found", "asset_value": "/api"}],
        )

        notified = []

        async def mock_notify(title, body, level):
            notified.append({"title": title, "level": level})

        asyncio.run(send_diff_alerts(report, notify_fn=mock_notify))
        # Should have at least the critical alert + possibly summary
        assert any(n["level"] == "critical" for n in notified)

    def test_new_assets_trigger_alert(self):
        from src.analysis.diff_engine import ScanDiffReport
        from src.integrations.diff_alerts import send_diff_alerts
        from src.integrations.asset_db import Asset, AssetDiff

        diff = AssetDiff(
            new_assets=[Asset(asset_type="subdomain", value="new.example.com")],
            disappeared_assets=[],
            changed_assets=[],
        )
        report = ScanDiffReport("p", "s1", "s2", asset_diff=diff)

        notified = []

        async def mock_notify(title, body, level):
            notified.append({"title": title, "level": level})

        asyncio.run(send_diff_alerts(report, notify_fn=mock_notify))
        assert any("new assets" in n["title"].lower() or "📡" in n["title"] for n in notified)


# ============================================================
# Dynamic Wordlist Generator Tests (V7-T4-1)
# ============================================================


class TestDynamicWordlistGenerator:
    """src/tools/fuzzing/dynamic_wordlist.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.fuzzing.dynamic_wordlist import DynamicWordlistGenerator

        gen = DynamicWordlistGenerator()
        assert gen is not None

    def test_technology_augmentation(self):
        from src.tools.fuzzing.dynamic_wordlist import DynamicWordlistGenerator

        gen = DynamicWordlistGenerator()
        words = gen.generate("example.com", technologies=["WordPress"])
        assert "wp-admin" in words
        assert "wp-content" in words
        assert "wp-login.php" in words

    def test_spring_augmentation(self):
        from src.tools.fuzzing.dynamic_wordlist import DynamicWordlistGenerator

        gen = DynamicWordlistGenerator()
        words = gen.generate("example.com", technologies=["Spring Boot"])
        assert "actuator" in words
        assert "actuator/health" in words

    def test_subdomain_pattern_extraction(self):
        from src.tools.fuzzing.dynamic_wordlist import DynamicWordlistGenerator

        gen = DynamicWordlistGenerator()
        words = gen.generate(
            "example.com",
            subdomains=["api-v1.example.com", "dev.example.com"],
        )
        # Should generate version expansions from api-v1
        assert "api-v1" in words
        assert "api-v2" in words or "api-v3" in words

    def test_endpoint_pattern_extraction(self):
        from src.tools.fuzzing.dynamic_wordlist import DynamicWordlistGenerator

        gen = DynamicWordlistGenerator()
        words = gen.generate(
            "example.com",
            endpoints=["/api/v1/users", "/api/v1/products"],
        )
        assert "api" in words
        assert "users" in words
        assert "products" in words

    def test_save_wordlist(self, tmp_path):
        from src.tools.fuzzing.dynamic_wordlist import DynamicWordlistGenerator

        gen = DynamicWordlistGenerator()
        words = gen.generate("example.com", technologies=["Django"])
        out = str(tmp_path / "wordlist.txt")
        count = gen.save(words, out)
        assert count == len(words)
        assert (tmp_path / "wordlist.txt").exists()

    def test_empty_generation(self):
        from src.tools.fuzzing.dynamic_wordlist import DynamicWordlistGenerator

        gen = DynamicWordlistGenerator()
        words = gen.generate("example.com")
        assert isinstance(words, list)


# ============================================================
# Favicon Hasher Tests (V7-T4-2)
# ============================================================


class TestFaviconHasher:
    """src/tools/recon/tech_detect/favicon_hasher.py tests."""

    def test_import_and_instantiate(self):
        from src.tools.recon.tech_detect.favicon_hasher import FaviconHasher

        tool = FaviconHasher()
        assert tool.name == "favicon_hasher"
        assert tool.is_available() is True

    def test_mmh3_hash32_deterministic(self):
        from src.tools.recon.tech_detect.favicon_hasher import mmh3_hash32

        data = b"test favicon data"
        h1 = mmh3_hash32(data)
        h2 = mmh3_hash32(data)
        assert h1 == h2  # Same input → same hash

    def test_mmh3_hash32_different_inputs(self):
        from src.tools.recon.tech_detect.favicon_hasher import mmh3_hash32

        h1 = mmh3_hash32(b"data1")
        h2 = mmh3_hash32(b"data2")
        assert h1 != h2

    def test_mmh3_hash32_returns_signed_int(self):
        from src.tools.recon.tech_detect.favicon_hasher import mmh3_hash32

        h = mmh3_hash32(b"test")
        assert isinstance(h, int)
        # Signed 32-bit int range
        assert -2147483648 <= h <= 2147483647

    def test_known_hashes_populated(self):
        from src.tools.recon.tech_detect.favicon_hasher import _KNOWN_HASHES

        assert len(_KNOWN_HASHES) >= 20
        # Check known entries
        assert -1137812357 in _KNOWN_HASHES  # Spring Boot
        assert 116323821 in _KNOWN_HASHES  # Jenkins

    def test_build_command(self):
        from src.tools.recon.tech_detect.favicon_hasher import FaviconHasher

        tool = FaviconHasher()
        assert tool.build_command("example.com") == []


# ============================================================
# GF Router Tests (V7-T4-3)
# ============================================================


class TestGFRouter:
    """src/tools/scanners/gf_router.py tests."""

    def test_route_xss_urls(self):
        from src.tools.scanners.gf_router import route_urls

        classified = {
            "xss": ["https://example.com/search?q=test"],
            "unmatched": ["https://example.com/about"],
        }
        tasks = route_urls(classified)
        xss_tasks = [t for t in tasks if t["category"] == "xss"]
        assert len(xss_tasks) >= 1
        assert xss_tasks[0]["tool"] in ("dalfox", "xsstrike")

    def test_route_sqli_urls(self):
        from src.tools.scanners.gf_router import route_urls

        classified = {"sqli": ["https://example.com/product?id=1"]}
        tasks = route_urls(classified)
        assert any(t["tool"] == "sqlmap" for t in tasks)

    def test_route_empty_urls(self):
        from src.tools.scanners.gf_router import route_urls

        tasks = route_urls({"xss": [], "unmatched": []})
        assert tasks == []

    def test_max_urls_per_tool(self):
        from src.tools.scanners.gf_router import route_urls

        urls = [f"https://example.com/?p={i}" for i in range(100)]
        tasks = route_urls({"xss": urls}, max_urls_per_tool=10)
        for t in tasks:
            assert len(t["urls"]) <= 10

    def test_routing_table_completeness(self):
        from src.tools.scanners.gf_router import get_routing_table

        table = get_routing_table()
        assert "xss" in table
        assert "sqli" in table
        assert "ssrf" in table
        assert "lfi" in table
        assert "rce" in table
        assert len(table) >= 10

    def test_tasks_sorted_by_priority(self):
        from src.tools.scanners.gf_router import route_urls

        classified = {
            "xss": ["https://a.com/?q=1"],
            "sqli": ["https://a.com/?id=1"],
            "ssrf": ["https://a.com/?url=x"],
        }
        tasks = route_urls(classified)
        priorities = [t["priority"] for t in tasks]
        assert priorities == sorted(priorities)


# ============================================================
# Dry-Run Mode Tests (V7-T4-4)
# ============================================================


class TestDryRun:
    """src/workflow/pipelines/dry_run.py tests."""

    def test_dry_run_plan_structure(self):
        from src.workflow.pipelines.dry_run import dry_run_plan

        plan = dry_run_plan("example.com", "balanced", {})
        assert "target" in plan
        assert "profile" in plan
        assert "stages" in plan
        assert plan["target"] == "example.com"
        assert len(plan["stages"]) >= 7

    def test_dry_run_format(self):
        from src.workflow.pipelines.dry_run import dry_run_plan, format_dry_run

        plan = dry_run_plan("example.com", "balanced", {})
        text = format_dry_run(plan)
        assert "example.com" in text
        assert "balanced" in text.lower() or "Balanced" in text

    def test_dry_run_profiles(self):
        from src.workflow.pipelines.dry_run import dry_run_plan

        for profile in ("stealth", "balanced", "aggressive"):
            plan = dry_run_plan("test.com", profile, {})
            assert plan["profile"] == profile

    def test_pipeline_stages_have_tools(self):
        from src.workflow.pipelines.dry_run import _PIPELINE_STAGES

        for stage in _PIPELINE_STAGES:
            assert "stage" in stage
            assert "tools" in stage
            assert len(stage["tools"]) > 0
            for tool in stage["tools"]:
                assert "name" in tool
                assert "desc" in tool
                assert "risk" in tool
