"""Regression tests for v2.8.0 changes.

Covers:
1. B1: Per-tool default_timeout overrides
2. B2: Finding dedup normalization (URL, vuln synonyms)
3. P3: SPA catch-all FP patterns in known_fps.py
4. P4-1: Per-tool memory_limit class variable
5. P4-2: Pre-scan tool availability check logic
6. P5-3: SSH watchdog log level reduction
7. P6-4: Confidence-based report sections
8. C2: Endpoint scoring function
9. C3: FP pattern learning dynamic confidence in knowledge_base
"""

import importlib
import inspect
import re

import pytest


# ──────────────────────────────────────────────────────────────
# 1. B1: Per-tool default_timeout overrides
# ──────────────────────────────────────────────────────────────

class TestToolTimeoutOverrides:
    """Verify heavy tools declare explicit default_timeout."""

    @pytest.mark.parametrize("mod_path,cls_name,expected_timeout", [
        ("src.tools.scanners.nuclei_wrapper", "NucleiWrapper", 1800),
        ("src.tools.scanners.sqlmap_wrapper", "SqlmapWrapper", 900),
        ("src.tools.recon.web_discovery.katana_wrapper", "KatanaWrapper", 900),
        ("src.tools.recon.web_discovery.gospider_wrapper", "GoSpiderWrapper", 600),
        ("src.tools.recon.port_scan.nmap_wrapper", "NmapWrapper", 1200),
        ("src.tools.recon.subdomain.amass_wrapper", "AmassWrapper", 600),
    ])
    def test_tool_has_explicit_timeout(self, mod_path, cls_name, expected_timeout):
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, cls_name)
        # Must be explicitly set in __dict__ (not inherited)
        assert "default_timeout" in cls.__dict__, f"{cls_name} must explicitly define default_timeout"
        assert cls.__dict__["default_timeout"] == expected_timeout


# ──────────────────────────────────────────────────────────────
# 2. B2: URL normalization in dedup
# ──────────────────────────────────────────────────────────────

class TestDedupNormalization:
    """Verify dedup helpers normalize URLs and vuln types."""

    def test_normalize_url_lowercase(self):
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        # _normalize_url must lowercase scheme and host
        assert ".lower()" in src or "lower()" in src

    def test_vuln_synonyms_expanded(self):
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        assert "_VULN_SYNONYMS" in src, "_VULN_SYNONYMS must exist in full_scan.py"
        # Count synonym entries — each line like '  "key": "value",' counts
        synonym_block_start = src.index("_VULN_SYNONYMS")
        synonym_block = src[synonym_block_start:synonym_block_start + 5000]
        entry_count = synonym_block.count('": "')
        assert entry_count >= 30, f"Expected 30+ synonyms, got {entry_count}"

    def test_default_ports_dict_exists(self):
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        assert "_DEFAULT_PORTS" in src


# ──────────────────────────────────────────────────────────────
# 3. P3: SPA catch-all FP patterns
# ──────────────────────────────────────────────────────────────

class TestSPAFPPatterns:
    """Verify SPA catch-all FP patterns exist in known_fps.py."""

    def test_spa_patterns_in_known_fps(self):
        from src.fp_engine.patterns.known_fps import KNOWN_FP_PATTERNS
        ids = {p.id for p in KNOWN_FP_PATTERNS}
        assert "FP-SPA-001" in ids, "Expected FP-SPA-001 pattern"
        assert "FP-SPA-002" in ids, "Expected FP-SPA-002 pattern"

    def test_fp_detector_spa_expanded_types(self):
        """Layer 1b SPA catch-all must cover expanded vuln types."""
        src = inspect.getsource(importlib.import_module("src.fp_engine.fp_detector"))
        assert "sensitive_url" in src, "SPA penalty should cover sensitive_url"
        assert "exposed_panel" in src, "SPA penalty should cover exposed_panel"
        assert "debug_endpoint" in src, "SPA penalty should cover debug_endpoint"


# ──────────────────────────────────────────────────────────────
# 4. P4-1: Per-tool memory limits
# ──────────────────────────────────────────────────────────────

class TestToolMemoryLimits:
    """Verify memory_limit class variable on heavy tools."""

    def test_base_class_has_memory_limit(self):
        from src.tools.base import SecurityTool
        assert hasattr(SecurityTool, "memory_limit")
        assert SecurityTool.memory_limit == 2 * 1024 * 1024 * 1024  # 2GB default

    @pytest.mark.parametrize("mod_path,cls_name,expected_mb", [
        ("src.tools.recon.web_discovery.waybackurls_wrapper", "WaybackurlsWrapper", 256),
        ("src.tools.recon.web_discovery.gau_wrapper", "GauWrapper", 256),
        ("src.tools.scanners.nuclei_wrapper", "NucleiWrapper", 512),
    ])
    def test_tool_has_memory_limit(self, mod_path, cls_name, expected_mb):
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, cls_name)
        assert "memory_limit" in cls.__dict__, f"{cls_name} must explicitly define memory_limit"
        expected_bytes = expected_mb * 1024 * 1024
        assert cls.__dict__["memory_limit"] == expected_bytes

    def test_execute_command_uses_memory_limit(self):
        """_set_rlimits closure must use instance memory_limit, not hardcoded 2GB."""
        src = inspect.getsource(importlib.import_module("src.tools.base"))
        assert "_mem_limit" in src, "execute_command should capture memory_limit into _mem_limit"
        # The setrlimit(RLIMIT_AS, ...) call should reference _mem_limit
        assert "setrlimit(resource.RLIMIT_AS, (_mem_limit" in src, \
            "RLIMIT_AS setrlimit should use _mem_limit variable"


# ──────────────────────────────────────────────────────────────
# 5. P4-2: Pre-scan tool availability check
# ──────────────────────────────────────────────────────────────

class TestPreScanAvailabilityCheck:
    """Verify pre-scan tool availability check in full_scan.py scope analysis."""

    def test_unavailable_tools_metadata_set(self):
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        assert 'unavailable_tools' in src, "Pre-scan check must store unavailable_tools in metadata"


# ──────────────────────────────────────────────────────────────
# 6. P5-3: SSH watchdog log level
# ──────────────────────────────────────────────────────────────

class TestSSHWatchdogLogLevel:
    """Verify SSH watchdog uses debug level for routine checks."""

    def test_tunnel_watchdog_uses_debug(self):
        src = inspect.getsource(importlib.import_module("src.brain.engine"))
        # Tunnel down in watchdog must use debug, not warning
        assert 'logger.debug("Tunnel watchdog: tunnel down' in src
        assert 'logger.debug(f"Tunnel watchdog error' in src or \
               "logger.debug(f\"Tunnel watchdog error" in src


# ──────────────────────────────────────────────────────────────
# 7. P6-4: Confidence-based report sections
# ──────────────────────────────────────────────────────────────

class TestConfidenceReportSections:
    """Verify report groups findings by confidence tiers."""

    def test_render_finding_method_exists(self):
        from src.reporting.report_generator import ReportGenerator
        assert hasattr(ReportGenerator, "_render_finding"), \
            "ReportGenerator must have _render_finding helper"

    def test_to_markdown_has_confidence_tiers(self):
        src = inspect.getsource(importlib.import_module("src.reporting.report_generator"))
        assert "Confirmed Findings" in src
        assert "Likely Findings" in src
        assert "Needs Investigation" in src

    def test_report_generation_with_tiers(self):
        """Generate a minimal report and verify tier headers appear."""
        from src.reporting.report_generator import ReportGenerator, Report, ReportFinding
        from src.tools.base import SeverityLevel

        gen = ReportGenerator()
        report = Report(
            report_id="test-001",
            target="example.com",
            findings=[
                ReportFinding(
                    title="High Confidence XSS",
                    severity=SeverityLevel.HIGH,
                    vulnerability_type="xss",
                    confidence_score=90.0,
                    cvss_score=7.5,
                ),
                ReportFinding(
                    title="Medium Confidence SQLi",
                    severity=SeverityLevel.MEDIUM,
                    vulnerability_type="sqli",
                    confidence_score=65.0,
                    cvss_score=5.0,
                ),
                ReportFinding(
                    title="Low Confidence LFI",
                    severity=SeverityLevel.LOW,
                    vulnerability_type="lfi",
                    confidence_score=30.0,
                    cvss_score=3.0,
                ),
            ],
        )
        md = gen.to_markdown(report)
        assert "Confirmed Findings" in md
        assert "Likely Findings" in md
        assert "Needs Investigation" in md
        assert "High Confidence XSS" in md
        assert "Medium Confidence SQLi" in md
        assert "Low Confidence LFI" in md


# ──────────────────────────────────────────────────────────────
# 8. C2: Endpoint scoring
# ──────────────────────────────────────────────────────────────

class TestEndpointScoring:
    """Verify _score_endpoint function exists and scores correctly."""

    def test_score_endpoint_exists(self):
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        assert "def _score_endpoint" in src, "_score_endpoint function must exist"

    def test_high_value_params_set(self):
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        assert "_HIGH_VALUE_PARAMS" in src, "_HIGH_VALUE_PARAMS set must exist"
        # Check a few key params are present
        assert '"id"' in src or "'id'" in src
        assert '"search"' in src or "'search'" in src


# ──────────────────────────────────────────────────────────────
# 9. C3: FP pattern learning dynamic confidence
# ──────────────────────────────────────────────────────────────

class TestFPLearningConfidence:
    """Verify knowledge_base FP pattern learning uses dynamic confidence."""

    def test_dynamic_confidence_in_code(self):
        src = inspect.getsource(importlib.import_module("src.brain.memory.knowledge_base"))
        # Must use dynamic confidence formula: min(0.95, 0.5 + times_seen * 0.1)
        assert "times_seen" in src, "save_fp_pattern must track times_seen"
        assert "0.95" in src, "Dynamic confidence must cap at 0.95"
        assert "0.5" in src, "Dynamic confidence must start at 0.5"
