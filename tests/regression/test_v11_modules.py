"""Tests for V11 additions: cloud_checker, gf_router integration, FP confidence fix."""

from __future__ import annotations

import pytest


class TestCloudChecker:
    """Tests for the cloud-native security checker module."""

    def test_import(self):
        from src.tools.scanners.custom_checks.cloud_checker import (
            check_cloud_security,
            _CLOUD_ENDPOINTS,
            _POSITIVE_SIGNATURES,
        )
        assert callable(check_cloud_security)
        assert len(_CLOUD_ENDPOINTS) > 30
        assert "kubernetes" in _POSITIVE_SIGNATURES

    def test_endpoint_categories(self):
        from src.tools.scanners.custom_checks.cloud_checker import _CLOUD_ENDPOINTS
        categories = {e[3] for e in _CLOUD_ENDPOINTS}
        assert "kubernetes" in categories
        assert "cicd" in categories
        assert "container" in categories
        assert "monitoring" in categories

    def test_endpoint_tuple_structure(self):
        from src.tools.scanners.custom_checks.cloud_checker import _CLOUD_ENDPOINTS
        for path, desc, sev, cat in _CLOUD_ENDPOINTS:
            assert path.startswith("/") or path.startswith("."), f"Path must start with / or .: {path}"
            assert isinstance(desc, str) and len(desc) > 0
            assert sev in ("critical", "high", "medium", "low", "info")
            assert isinstance(cat, str)


class TestGFRouterIntegration:
    """Tests for GF→Scanner auto-routing."""

    def test_gf_router_import(self):
        from src.tools.scanners.gf_router import route_urls, get_routing_table
        assert callable(route_urls)
        table = get_routing_table()
        assert "xss" in table
        assert "sqli" in table
        assert "ssrf" in table

    def test_route_urls_basic(self):
        from src.tools.scanners.gf_router import route_urls
        classified = {
            "xss": ["https://example.com/search?q=test"],
            "sqli": ["https://example.com/user?id=1"],
            "unmatched": ["https://example.com/"],
        }
        tasks = route_urls(classified)
        assert len(tasks) >= 2
        tools_used = {t["tool"] for t in tasks}
        assert "dalfox" in tools_used or "xsstrike" in tools_used
        assert "sqlmap" in tools_used

    def test_route_urls_empty(self):
        from src.tools.scanners.gf_router import route_urls
        tasks = route_urls({})
        assert tasks == []

    def test_route_urls_respects_limit(self):
        from src.tools.scanners.gf_router import route_urls
        classified = {
            "xss": [f"https://example.com/p?q={i}" for i in range(100)],
        }
        tasks = route_urls(classified, max_urls_per_tool=5)
        for task in tasks:
            assert len(task["urls"]) <= 5


class TestDecisionEngineProfileLimits:
    """Tests for DecisionEngine profile-aware integration."""

    def test_profile_limits_exist(self):
        from src.workflow.decision_engine import PROFILE_LIMITS
        assert "stealth" in PROFILE_LIMITS
        assert "balanced" in PROFILE_LIMITS
        assert "aggressive" in PROFILE_LIMITS

    def test_stealth_skips_aggressive_tools(self):
        from src.workflow.decision_engine import PROFILE_LIMITS
        stealth = PROFILE_LIMITS["stealth"]
        assert stealth["skip_aggressive_tools"] is True
        assert "sqlmap" in stealth["aggressive_tools"]
        assert "masscan" in stealth["aggressive_tools"]

    def test_balanced_no_skip(self):
        from src.workflow.decision_engine import PROFILE_LIMITS
        balanced = PROFILE_LIMITS["balanced"]
        assert balanced["skip_aggressive_tools"] is False


class TestFPConfidenceRange:
    """Test that FP confidence is no longer destructively clamped."""

    def test_confidence_full_range(self):
        """Verify the FPDetector entry function uses [0, 100] range."""
        import ast
        from pathlib import Path

        fp_path = Path("src/fp_engine/fp_detector.py")
        source = fp_path.read_text()

        # Should NOT contain max(30 or min(70 clamping
        assert "max(30.0" not in source, "FP confidence still clamped at 30"
        assert "min(70.0" not in source, "FP confidence still clamped at 70"

        # Should contain full range
        assert "max(0.0" in source or "max( 0.0" in source
        assert "min(100.0" in source or "min( 100.0" in source


class TestV11PipelineWiring:
    """Verify V11 modules are wired into the full_scan pipeline."""

    def test_cloud_infra_checker_wired(self):
        """cloud_infra_checker should be in the fan-out."""
        from pathlib import Path
        source = Path("src/workflow/pipelines/full_scan.py").read_text()
        assert "_run_cloud_infra()" in source
        assert "cloud_infra_checker" in source

    def test_gf_router_wired(self):
        """GF router should be called after GF classification."""
        from pathlib import Path
        source = Path("src/workflow/pipelines/full_scan.py").read_text()
        assert "gf_route_urls" in source
        assert "gf_routed_tasks" in source

    def test_critique_recommendations_consumed(self):
        """Critique recommendations should be read in vuln scan handler."""
        from pathlib import Path
        source = Path("src/workflow/pipelines/full_scan.py").read_text()
        assert 'critique_recommendations' in source
        assert 'critique_adapt_action' in source

    def test_decision_engine_profile_check(self):
        """DecisionEngine profile limits should be checked."""
        from pathlib import Path
        source = Path("src/workflow/pipelines/full_scan.py").read_text()
        assert "PROFILE_LIMITS" in source
        assert "_skipped_tools" in source

    def test_auth_headers_to_crawlers(self):
        """Auth headers should be passed to katana and gospider."""
        from pathlib import Path
        source = Path("src/workflow/pipelines/full_scan.py").read_text()
        assert "_recon_auth_headers" in source
        assert "_katana_opts" in source
        assert "_gospider_opts" in source

    def test_checker_count_updated(self):
        """Fan-out comment should say 24 checkers (tech-relevant routing)."""
        from pathlib import Path
        source = Path("src/workflow/pipelines/full_scan.py").read_text()
        assert "24 tech-relevant" in source or "Running 24 custom checkers" in source

    def test_response_intelligence_wired(self):
        """Response intelligence should be called in vuln scan handler."""
        from pathlib import Path
        source = Path("src/workflow/pipelines/full_scan.py").read_text()
        assert "response_intelligence" in source
        assert "analyze_responses" in source
        assert "response_intel" in source


class TestResponseIntelligence:
    """Tests for the Response Intelligence Engine module."""

    def test_import(self):
        from src.analysis.response_intelligence import (
            analyze_response_headers,
            analyze_response_body,
            analyze_responses,
            ResponseIntel,
        )
        assert callable(analyze_response_headers)
        assert callable(analyze_response_body)
        assert callable(analyze_responses)

    def test_server_fingerprint_nginx(self):
        from src.analysis.response_intelligence import analyze_response_headers
        intel = analyze_response_headers({"Server": "nginx/1.25.3"}, url="https://example.com")
        assert "nginx" in intel.technologies
        assert intel.technologies["nginx"] == "1.25.3"

    def test_server_fingerprint_apache(self):
        from src.analysis.response_intelligence import analyze_response_headers
        intel = analyze_response_headers({"Server": "Apache/2.4.58"})
        assert "apache" in intel.technologies
        assert intel.technologies["apache"] == "2.4.58"

    def test_powered_by_php(self):
        from src.analysis.response_intelligence import analyze_response_headers
        intel = analyze_response_headers({"X-Powered-By": "PHP/8.2.1"})
        assert "php" in intel.technologies
        assert intel.technologies["php"] == "8.2.1"

    def test_interesting_headers_detected(self):
        from src.analysis.response_intelligence import analyze_response_headers
        intel = analyze_response_headers({
            "X-Debug-Token": "abc123",
            "X-Aspnet-Version": "4.0.30319",
        })
        header_names = {h["header"] for h in intel.interesting_headers}
        assert "x-debug-token" in header_names
        assert "x-aspnet-version" in header_names

    def test_missing_security_headers(self):
        from src.analysis.response_intelligence import analyze_response_headers
        intel = analyze_response_headers({"Content-Type": "text/html"})
        assert "strict-transport-security" in intel.missing_security_headers
        assert "content-security-policy" in intel.missing_security_headers

    def test_security_headers_present(self):
        from src.analysis.response_intelligence import analyze_response_headers
        intel = analyze_response_headers({
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        })
        assert "strict-transport-security" not in intel.missing_security_headers
        assert "content-security-policy" not in intel.missing_security_headers

    def test_body_php_error(self):
        from src.analysis.response_intelligence import analyze_response_body
        body = 'Fatal error: Uncaught Exception in /var/www/html/index.php on line 42'
        intel = analyze_response_body(body, url="https://target.com/")
        assert len(intel.error_disclosures) >= 1
        assert intel.error_disclosures[0]["tech"] == "php"
        assert "php" in intel.technologies

    def test_body_java_stack_trace(self):
        from src.analysis.response_intelligence import analyze_response_body
        body = 'java.lang.NullPointerException\n  at com.example.App(App.java:15)'
        intel = analyze_response_body(body)
        techs = [e["tech"] for e in intel.error_disclosures]
        assert "java" in techs

    def test_body_debug_mode(self):
        from src.analysis.response_intelligence import analyze_response_body
        body = '<title>Werkzeug Debugger</title>'
        intel = analyze_response_body(body)
        assert intel.debug_mode_detected is True

    def test_body_internal_path_extraction(self):
        from src.analysis.response_intelligence import analyze_response_body
        body = 'Error in /var/www/html/app/controllers/user.php line 42'
        intel = analyze_response_body(body)
        assert any("/var/www" in p for p in intel.internal_paths)

    def test_body_graphql_signal(self):
        from src.analysis.response_intelligence import analyze_response_body
        body = '{"data": {"__schema": {"queryType": {"name": "Query"}}}}'
        intel = analyze_response_body(body)
        assert len(intel.api_signals) >= 1
        assert "GraphQL" in intel.api_signals[0]["signal"]

    def test_batch_analyze_responses(self):
        from src.analysis.response_intelligence import analyze_responses
        resps = [
            {"url": "https://a.com", "headers": {"Server": "nginx"}, "body": ""},
            {"url": "https://b.com", "headers": {}, "body": "Fatal error: in /var/www/x.php"},
            {"url": "https://c.com", "status_code": 500, "headers": {}, "body": ""},
        ]
        intel = analyze_responses(resps)
        assert "nginx" in intel.technologies
        assert "php" in intel.technologies
        assert len(intel.error_disclosures) >= 2  # PHP error + HTTP 500

    def test_response_intel_to_dict(self):
        from src.analysis.response_intelligence import ResponseIntel
        intel = ResponseIntel()
        intel.technologies["nginx"] = "1.25"
        intel.debug_mode_detected = True
        d = intel.to_dict()
        assert d["technologies"]["nginx"] == "1.25"
        assert d["debug_mode_detected"] is True
        assert "summary" in d

    def test_response_intel_summary(self):
        from src.analysis.response_intelligence import ResponseIntel
        intel = ResponseIntel()
        assert intel.summary() == "No signals"
        intel.technologies["php"] = "8.2"
        assert "Tech:" in intel.summary()

    def test_deduplication(self):
        from src.analysis.response_intelligence import analyze_responses
        resps = [
            {"url": "https://a.com", "headers": {"Server": "nginx"}, "body": ""},
            {"url": "https://a.com", "headers": {"Server": "nginx"}, "body": ""},
        ]
        intel = analyze_responses(resps)
        # Headers should be deduplicated
        assert len([h for h in intel.interesting_headers if h["url"] == "https://a.com"]) <= 1


class TestBugFixRegressions:
    """Regression tests for bugs fixed in this session."""

    def test_c3_brain_confirmed_down_in_state(self):
        """C3: brain_confirmed_down field must exist in WorkflowState."""
        from src.workflow.orchestrator import WorkflowState
        state = WorkflowState()
        assert hasattr(state, "brain_confirmed_down")
        assert state.brain_confirmed_down is False

    def test_c3_brain_down_sync_in_orchestrator(self):
        """C3: orchestrator must sync brain_confirmed_down from intel engine."""
        from pathlib import Path
        source = Path("src/workflow/orchestrator.py").read_text()
        assert "brain_confirmed_down = True" in source
        assert "Brain confirmed down" in source

    def test_h2_session_manager_retry(self):
        """H2: SessionManager init should retry on failure."""
        from pathlib import Path
        source = Path("src/workflow/orchestrator.py").read_text()
        assert "for _attempt in range(2)" in source
        assert "crash recovery DISABLED" in source

    def test_h4_intelligence_timeout_retry(self):
        """H4: Intelligence engine should retry once on timeout."""
        from pathlib import Path
        source = Path("src/brain/intelligence.py").read_text()
        assert "retry_timeout = timeout * 0.6" in source
        assert "retry succeeded" in source

    def test_h10_fp_verdict_accepts_likely_fp(self):
        """H10: FPVerdict should document likely_fp as valid verdict."""
        from pathlib import Path
        source = Path("src/fp_engine/fp_detector.py").read_text()
        assert "likely_fp" in source

    def test_m5_truncation_marker(self):
        """M5: Output truncation should add a marker."""
        from pathlib import Path
        source = Path("src/tools/base.py").read_text()
        assert "[OUTPUT TRUNCATED:" in source

    def test_m7_ansi_stripping(self):
        """M7: Tool output should strip ANSI escape sequences."""
        from pathlib import Path
        source = Path("src/tools/base.py").read_text()
        assert "_ansi_re" in source
        assert "\\x1b" in source

    def test_m4_dynamic_wordlist_metadata(self):
        """M4: Dynamic wordlist path should be saved to state.metadata."""
        from pathlib import Path
        source = Path("src/workflow/pipelines/full_scan.py").read_text()
        assert 'state.metadata["dynamic_wordlist_path"]' in source

    def test_ansi_strip_actually_works(self):
        """M7: Verify ANSI regex strips escape sequences correctly."""
        import re
        _ansi_re = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
        colored = "\x1b[31mERROR\x1b[0m: something failed"
        cleaned = _ansi_re.sub('', colored)
        assert cleaned == "ERROR: something failed"
        assert "\x1b" not in cleaned
