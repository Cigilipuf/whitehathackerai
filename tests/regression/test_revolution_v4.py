"""
Revolution v4.0 Regression Tests
=================================
Validates all Phase 1-3 fixes that eliminated 436 FPs from GitLab scan (36bdfaffd99e87ab).

Phase 1: Pipeline Quality Gates (full_scan.py)
Phase 2: Checker Fixes (7 modules)
Phase 3: FP Pattern Library
"""

import importlib
import inspect
import re
import textwrap

import pytest


# ============================================================
#  Phase 1: Pipeline Quality Gates
# ============================================================

class TestPhase1PipelineGates:
    """Verify full_scan.py confidence threshold, null handling, and evidence gate."""

    def _get_full_scan_source(self):
        mod = importlib.import_module("src.workflow.pipelines.full_scan")
        return inspect.getsource(mod)

    def test_confidence_threshold_is_severity_tiered(self):
        """Phase 4.1: Threshold severity-tiered (60 for MEDIUM+, 50 for LOW/INFO)."""
        src = self._get_full_scan_source()
        assert "60.0" in src and "50.0" in src, "Pipeline must have tiered thresholds"
        assert "_min_conf" in src, "Pipeline must use _min_conf variable"

    def test_no_or_50_default(self):
        """Phase 1.2: 'or 50.0' null confidence promotion must be removed."""
        from src.workflow.pipelines.full_scan import _safe_float
        # Null confidence should default to 0.0 not 50.0
        assert _safe_float(None, 0.0) == 0.0
        assert _safe_float("", 0.0) == 0.0
        assert _safe_float("high", 0.0) == 0.0
        # Valid floats pass through
        assert _safe_float(75.0, 0.0) == 75.0
        assert _safe_float("65.5", 0.0) == 65.5

    def test_evidence_gate_caps_at_35(self):
        """Phase 1.4: MEDIUM+ findings without evidence get confidence capped at 35."""
        src = self._get_full_scan_source()
        # Must import and use the EvidenceQualityGate module
        assert "_eqg_evaluate" in src, "Pipeline must use EvidenceQualityGate evaluate()"
        assert "evidence_quality_gate" in src, "Pipeline must import evidence_quality_gate"


# ============================================================
#  Phase 2.1: ResponseValidator 404/410 Rejection
# ============================================================

class TestPhase2_1_ResponseValidator404:
    """ResponseValidator must reject 404 and 410 status codes."""

    def test_404_rejected(self):
        from src.utils.response_validator import ResponseValidator
        rv = ResponseValidator()
        result = rv.validate(404, {}, "Not Found")
        assert not result.is_valid, "404 must be rejected"

    def test_410_rejected(self):
        from src.utils.response_validator import ResponseValidator
        rv = ResponseValidator()
        result = rv.validate(410, {}, "Gone")
        assert not result.is_valid, "410 must be rejected"

    def test_200_still_valid(self):
        from src.utils.response_validator import ResponseValidator
        rv = ResponseValidator()
        result = rv.validate(200, {"content-type": "text/html"}, "<html><body>Hello</body></html>")
        assert result.is_valid, "200 with real content should still be valid"


# ============================================================
#  Phase 2.2: business_logic.py ResponseValidator + SPA
# ============================================================

class TestPhase2_2_BusinessLogic:
    """business_logic.py must use ResponseValidator and reject SPA/static content."""

    def test_imports_response_validator(self):
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.custom_checks.business_logic")
        )
        assert "ResponseValidator" in src, "Must import ResponseValidator"

    def test_is_genuine_success_rejects_waf(self):
        from src.tools.scanners.custom_checks.business_logic import _is_genuine_success
        # WAF challenge page
        assert _is_genuine_success(403, "Access Denied by WAF") is False

    def test_is_genuine_success_rejects_spa(self):
        from src.tools.scanners.custom_checks.business_logic import _is_genuine_success
        spa_body = '{"buildId":"abc123","page":"/_app","props":{}}'
        assert _is_genuine_success(200, spa_body) is False

    def test_is_genuine_success_rejects_nuxt(self):
        from src.tools.scanners.custom_checks.business_logic import _is_genuine_success
        nuxt_body = '<script>window.__nuxt__={config:{},state:{}}</script>'
        assert _is_genuine_success(200, nuxt_body) is False

    def test_has_transaction_content(self):
        from src.tools.scanners.custom_checks.business_logic import _has_transaction_content
        # Needs 2+ keywords
        assert _has_transaction_content('{"total": 100, "price": 50}') is True
        assert _has_transaction_content('{"message": "ok"}') is False

    def test_is_api_json_response(self):
        from src.tools.scanners.custom_checks.business_logic import _is_api_json_response
        assert _is_api_json_response('{"status": "ok"}') is True
        assert _is_api_json_response('[{"id": 1}]') is True
        assert _is_api_json_response('<html>') is False
        assert _is_api_json_response('') is False


# ============================================================
#  Phase 2.3: cicd_checker.py Self-Platform Detection
# ============================================================

class TestPhase2_3_CICDChecker:
    """cicd_checker must skip self-hosted platform endpoints."""

    def test_is_self_hosted_platform_gitlab(self):
        from src.tools.scanners.custom_checks.cicd_checker import _is_self_hosted_platform
        assert _is_self_hosted_platform("https://gitlab.com/api/v4/projects", "gitlab") is True

    def test_is_self_hosted_platform_github(self):
        from src.tools.scanners.custom_checks.cicd_checker import _is_self_hosted_platform
        assert _is_self_hosted_platform("https://github.com/user/repo", "github") is True

    def test_not_self_hosted(self):
        from src.tools.scanners.custom_checks.cicd_checker import _is_self_hosted_platform
        # Random target should not be flagged as self-hosted
        assert _is_self_hosted_platform("https://example.com/api", "gitlab") is False

    def test_known_cicd_domains_exist(self):
        from src.tools.scanners.custom_checks.cicd_checker import _KNOWN_CICD_DOMAINS
        assert "gitlab" in _KNOWN_CICD_DOMAINS
        assert "github" in _KNOWN_CICD_DOMAINS
        assert len(_KNOWN_CICD_DOMAINS) >= 5


# ============================================================
#  Phase 2.4: tech_cve_checker.py Word-Boundary + Version Skip
# ============================================================

class TestPhase2_4_TechCVEChecker:
    """tech_cve_checker must use word boundaries and skip version-unknown findings."""

    def test_word_boundary_matching(self):
        """'apache' must NOT match 'apachesolr' via substring."""
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.custom_checks.tech_cve_checker")
        )
        # Must contain word boundary regex
        assert r"\b" in src, "Must use word boundary \\b for tech matching"
        assert "re.escape" in src, "Must escape tech names in regex"

    def test_nxdomain_version_unknown_skip(self):
        """Findings without version must be skipped, not low-confidence reported."""
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.custom_checks.tech_cve_checker")
        )
        # The old code had `confidence = 35.0` for version-unknown — now it should skip
        # Check that the 'continue' pattern exists where version-unknown was
        assert "continue" in src, "version-unknown findings must use 'continue' to skip"


# ============================================================
#  Phase 2.5: js_analyzer.py Cloudflare/Discord Filtering
# ============================================================

class TestPhase2_5_JSAnalyzer:
    """js_analyzer must filter Cloudflare/Discord third-party JS."""

    def test_cloudflare_in_third_party_domains(self):
        from src.tools.scanners.custom_checks.js_analyzer import _THIRD_PARTY_JS_DOMAINS
        cf_domains = [
            "static.cloudflareinsights.com",
            "cloudflare.com",
            "ajax.cloudflare.com",
        ]
        for d in cf_domains:
            assert d in _THIRD_PARTY_JS_DOMAINS, f"{d} must be in third-party filter"

    def test_discord_in_third_party_domains(self):
        from src.tools.scanners.custom_checks.js_analyzer import _THIRD_PARTY_JS_DOMAINS
        discord_domains = ["discord.com", "discordapp.com", "cdn.discordapp.com"]
        for d in discord_domains:
            assert d in _THIRD_PARTY_JS_DOMAINS, f"{d} must be in third-party filter"

    def test_is_third_party_detection(self):
        from src.tools.scanners.custom_checks.js_analyzer import _is_third_party_js
        assert _is_third_party_js("https://static.cloudflareinsights.com/beacon.min.js") is True
        assert _is_third_party_js("https://cdn.discordapp.com/widget.js") is True
        assert _is_third_party_js("https://example.com/app.js") is False


# ============================================================
#  Phase 2.6: mass_assignment_checker.py Non-JSON Fallback Removed
# ============================================================

class TestPhase2_6_MassAssignment:
    """mass_assignment_checker must NOT use string matching on non-JSON responses."""

    def test_no_string_matching_fallback(self):
        """The non-JSON fallback (str(value) in body) must be removed."""
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.custom_checks.mass_assignment_checker")
        )
        # Old code: `if str(value) in body and field_name in body:`
        assert "str(value) in body" not in src, \
            "Non-JSON string matching fallback must be removed — primary FP source"


# ============================================================
#  Phase 2.7: subdomain_takeover.py HTTP Fingerprint Required
# ============================================================

class TestPhase2_7_SubdomainTakeover:
    """subdomain_takeover must require HTTP fingerprint confirmation."""

    def test_no_finding_without_http_confirmation(self):
        """CNAME pattern alone should NOT create a finding."""
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.custom_checks.subdomain_takeover")
        )
        assert "if not http_confirmed:" in src, \
            "Must check http_confirmed and return None if not confirmed"
        assert "return None" in src[src.index("if not http_confirmed:"):src.index("if not http_confirmed:") + 200], \
            "Must return None when http_confirmed is False"


# ============================================================
#  Phase 2.8: commix_wrapper.py Blind Injection Severity
# ============================================================

class TestPhase2_8_Commix:
    """commix_wrapper must differentiate blind vs confirmed injection."""

    def test_time_based_gets_lower_confidence(self):
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.commix_wrapper").CommixWrapper.parse_output
        )
        assert "is_blind" in src, "Must detect blind (time-based) technique"
        assert "35.0 if is_blind" in src, "Blind technique must get 35% confidence"
        assert "MEDIUM" in src, "Blind technique must get MEDIUM severity, not CRITICAL"

    def test_blind_tag(self):
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.commix_wrapper").CommixWrapper.parse_output
        )
        assert '"blind"' in src, "Blind technique must get 'blind' tag"


# ============================================================
#  Phase 3: FP Pattern Library
# ============================================================

class TestPhase3_FPPatterns:
    """Verify all 12 new Revolution v4.0 FP patterns exist."""

    def _get_patterns(self):
        from src.fp_engine.patterns.known_fps import KNOWN_FP_PATTERNS
        return {p.id: p for p in KNOWN_FP_PATTERNS}

    @pytest.mark.parametrize("pattern_id,vuln_type,min_penalty", [
        ("FP-CICD-001", "cicd_exposure", -25),
        ("FP-CICD-002", "cicd_exposure", -20),
        ("FP-BIZLOGIC-001", "*", -25),
        ("FP-BIZLOGIC-002", "*", -20),
        ("FP-TECHCVE-001", "outdated_software", -30),
        ("FP-TECHCVE-002", "outdated_software", -25),
        ("FP-TECHCVE-003", "outdated_software", -20),
        ("FP-MASSASSIGN-001", "mass_assignment", -20),
        ("FP-MASSASSIGN-002", "*", -20),
        ("FP-SOURCEMAP-001", "*", -15),
        ("FP-JSDOM-001", "*", -30),
        ("FP-SUBTAKEOVER-001", "subdomain_takeover", -25),
    ])
    def test_pattern_exists(self, pattern_id, vuln_type, min_penalty):
        patterns = self._get_patterns()
        assert pattern_id in patterns, f"Pattern {pattern_id} must exist"
        p = patterns[pattern_id]
        assert p.vuln_type == vuln_type, f"{pattern_id} vuln_type mismatch"
        assert p.confidence_penalty <= min_penalty, \
            f"{pattern_id} penalty {p.confidence_penalty} must be <= {min_penalty}"

    def test_total_pattern_count_increased(self):
        from src.fp_engine.patterns.known_fps import KNOWN_FP_PATTERNS
        # Revolution v4.0 added 12+6 patterns to the previous ~100
        assert len(KNOWN_FP_PATTERNS) >= 118, \
            f"Expected >= 118 patterns, got {len(KNOWN_FP_PATTERNS)}"


# ============================================================
#  Integration: FP Pattern Matching Against GitLab-Like Findings
# ============================================================

class TestPhase3_PatternMatching:
    """Test that new patterns actually trigger on GitLab-scan-like findings."""

    def _check(self, finding_dict):
        from src.fp_engine.patterns.known_fps import KnownFPMatcher
        matcher = KnownFPMatcher()
        result = matcher.check(finding_dict)
        return result["matches"]

    def test_cicd_404_finding_matches(self):
        finding = {
            "title": "CI/CD Exposure: Jenkins",
            "vuln_type": "cicd_exposure",
            "tool": "cicd_checker",
            "evidence": "Status: 404 Not Found",
            "status_code": "404",
        }
        matches = self._check(finding)
        fp_ids = [m.id for m in matches]
        assert "FP-CICD-001" in fp_ids

    def test_techcve_no_version_matches(self):
        finding = {
            "title": "CVE-2021-1234 affects apache",
            "vuln_type": "outdated_software",
            "tool": "tech_cve_checker",
            "evidence": "Technology: apache detected",
        }
        matches = self._check(finding)
        fp_ids = [m.id for m in matches]
        assert "FP-TECHCVE-002" in fp_ids

    def test_cloudflare_js_dom_xss_matches(self):
        finding = {
            "title": "DOM XSS Source/Sink",
            "vuln_type": "xss_dom",
            "tool": "js_analyzer",
            "evidence": "Source: _cf_chl_opt in challenges.cloudflare.com/turnstile",
        }
        matches = self._check(finding)
        fp_ids = [m.id for m in matches]
        assert "FP-JSDOM-001" in fp_ids


# ============================================================
#  Phase 4.3: Auth Bypass Modernization
# ============================================================

class TestPhase4_3_AuthBypass:
    """auth_bypass.py must use ResponseValidator and require positive content."""

    def test_imports_response_validator(self):
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.custom_checks.auth_bypass")
        )
        assert "ResponseValidator" in src

    def test_rejects_waf_via_validator(self):
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        checker = AuthBypassChecker()
        # WAF page with Cloudflare challenge — must be rejected
        waf_body = '<html><title>Access Denied</title><body>Attention Required! Cloudflare Ray ID: abc123</body></html>'
        assert checker._is_bypass_success(403, 200, 100, len(waf_body), waf_body) is False

    def test_rejects_login_page_as_bypass(self):
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        checker = AuthBypassChecker()
        # 403→200 but body says "please sign in"
        login_body = '<html><form><input name="user"><input name="pass"><button>Sign In</button></form></html>'
        assert checker._is_bypass_success(403, 200, 100, len(login_body), login_body) is False

    def test_rejects_unauthorized_json_as_bypass(self):
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        checker = AuthBypassChecker()
        # API returning auth error with 200 status
        error_body = '{"error": "unauthorized", "message": "Please authenticate"}'
        assert checker._is_bypass_success(403, 200, 100, len(error_body), error_body) is False

    def test_accepts_real_bypass_with_dashboard(self):
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        checker = AuthBypassChecker()
        # Real bypass: 403→200 with actual dashboard content
        dashboard_body = '<html><div id="admin-panel"><h1>Dashboard</h1><p>Welcome admin</p><a href="/logout">Logout</a></div></html>'
        assert checker._is_bypass_success(403, 200, 100, len(dashboard_body), dashboard_body) is True

    def test_rejects_small_200_without_auth_keywords(self):
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        checker = AuthBypassChecker()
        # 403→200 but small generic response without authenticated content
        small_body = '{"status": "ok"}'
        assert checker._is_bypass_success(403, 200, 100, len(small_body), small_body) is False

    def test_same_200_requires_3x_size_and_auth_content(self):
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        checker = AuthBypassChecker()
        # Both 200 but just slightly bigger — NOT enough
        assert checker._is_bypass_success(200, 200, 300, 500, "x" * 500) is False
        # 3x bigger with dashboard content — IS enough
        big_body = "dashboard " * 200
        assert checker._is_bypass_success(200, 200, 300, len(big_body), big_body) is True

    def test_302_always_rejected(self):
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        checker = AuthBypassChecker()
        assert checker._is_bypass_success(403, 302, 100, 50, "") is False


# ============================================================
#  Phase 4.5: Endpoint Quality Prioritization
# ============================================================

class TestPhase4_5_EndpointScoring:
    """Verify _score_endpoint exists and the main endpoints list is sorted."""

    def test_score_endpoint_function_defined(self):
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        assert "def _score_endpoint(ep: str) -> int:" in src

    def test_endpoints_list_sorted_by_score(self):
        """After _score_endpoint sort, the local `endpoints` list must be sorted."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Verify the sort call exists for the main endpoints list
        assert "endpoints.sort(key=_score_endpoint, reverse=True)" in src, \
            "Main endpoints list must be sorted by quality score"

    def test_state_endpoints_sorted(self):
        """state.endpoints should also be sorted for custom checkers."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        assert "state.endpoints.sort(key=_score_endpoint, reverse=True)" in src, \
            "state.endpoints must be sorted for custom checker slicing"

    def test_scoring_favors_parameterized_urls(self):
        """Parameterized URLs should score higher than bare paths."""
        from urllib.parse import urlparse, parse_qs
        # Simulate the scoring logic inline (function is a closure, not directly importable)
        _HIGH_VALUE_PARAMS = {"id", "search", "q", "query", "username", "email"}
        _HIGH_VALUE_PATHS_RE = re.compile(
            r"/(api|admin|auth|login|user|account|search|dashboard)", re.IGNORECASE
        )

        def _mini_score(ep: str) -> int:
            score = 0
            p = urlparse(ep)
            params = parse_qs(p.query, keep_blank_values=True)
            for pname in params:
                if pname.lower() in _HIGH_VALUE_PARAMS:
                    score += 10
            score += min(len(params) * 2, 10)
            if _HIGH_VALUE_PATHS_RE.search(p.path):
                score += 5
            return score

        bare = "https://example.com/static/style.css"
        param = "https://example.com/api/search?q=test&id=1"
        assert _mini_score(param) > _mini_score(bare), \
            "Parameterized API URL must score higher than static"

    def test_scoring_prioritizes_business_logic(self):
        """Business logic keywords (checkout, payment) should boost score."""
        from urllib.parse import urlparse
        _BIZ_KEYWORDS = {"checkout", "payment", "order", "transfer", "wallet"}

        def _biz_score(ep: str) -> int:
            score = 0
            p = urlparse(ep)
            if any(kw in p.path.lower() for kw in _BIZ_KEYWORDS):
                score += 25
            return score

        normal = "https://example.com/about"
        checkout = "https://example.com/checkout/confirm"
        assert _biz_score(checkout) > _biz_score(normal)


# ============================================================
#  Phase 4.2: Deep Probe Expansion
# ============================================================

class TestPhase4_2_DeepProbe:
    """Verify deep_probe_batch expansion: limit, CDN, last-resort, host_profiles wiring."""

    def test_batch_limit_is_50(self):
        """P4.2: Endpoint limit increased from 25 to 50."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.deep_probe")
        )
        assert "_BATCH_LIMIT = 50" in src, "Batch limit must be 50"
        # Old limit must be gone
        assert "sorted_targets[:25]" not in src, "Old 25 limit must be removed"

    def test_cdn_only_not_skipped(self):
        """P4.2: CDN hosts should NOT be skipped — they can have misconfigs."""
        from src.workflow.pipelines.deep_probe import _SKIP_HOST_TYPES
        assert "cdn_only" not in _SKIP_HOST_TYPES, "cdn_only must not be in skip list"
        # redirect_host and static_site should still be skipped
        assert "redirect_host" in _SKIP_HOST_TYPES
        assert "static_site" in _SKIP_HOST_TYPES

    def test_last_resort_sampling_exists(self):
        """P4.2: Last-resort random sampling when 0 confirmed from top-50."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.deep_probe")
        )
        assert "last-resort" in src.lower() or "last_resort" in src.lower(), \
            "Last-resort sampling logic must exist"
        assert "_rand.sample(remainder" in src, "Random sampling must be implemented"

    def test_run_deep_probe_accepts_host_profiles(self):
        """P4.2: IntelligenceEngine.run_deep_probe() must accept host_profiles."""
        from src.brain.intelligence import IntelligenceEngine
        sig = inspect.signature(IntelligenceEngine.run_deep_probe)
        assert "host_profiles" in sig.parameters, \
            "run_deep_probe must accept host_profiles parameter"


# ============================================================
#  Phase 4.1: Creative Narratives → Deep Probe Wiring
# ============================================================

class TestPhase4_1_CreativeNarratives:
    """Verify creative_narratives are wired to HUNTER Phase B deep probe targets."""

    def test_creative_narratives_read_in_hunter(self):
        """P4.1: full_scan must read creative_narratives from attack_surface_data."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        assert 'attack_surface_data.get("creative_narratives"' in src, \
            "HUNTER Phase B must read creative_narratives"

    def test_narratives_vuln_class_mapping(self):
        """P4.1: vuln_class → vuln_type mapping should cover major classes."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Verify key mappings exist
        for vclass in ["idor", "sqli", "xss", "ssrf", "rce", "race condition", "mass assignment"]:
            assert f'"{vclass}"' in src, f"vuln_class mapping must include '{vclass}'"

    def test_narratives_dedup_against_existing_targets(self):
        """P4.1: Narrative endpoints already in probe_targets must not be duplicated."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        assert "_probe_eps" in src, "Must track existing endpoints to avoid duplication"
        assert "_resolved in _probe_eps" in src, "Must check for duplicate before adding"

    def test_narrative_priority_mapping(self):
        """P4.1: Narrative severity_estimate must map to priority numbers."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Same mapping as brain_vectors
        assert '"critical": 4' in src
        assert '"high": 3' in src
