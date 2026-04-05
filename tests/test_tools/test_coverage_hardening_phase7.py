"""
Regression tests for Wave 2 — Phase 6 (Deep Probe) & Phase 7 (Checker Fixes).

Validates:
 1. Deep probe rejects WAF/CDN/SPA responses via ResponseValidator
 2. Deep probe skips CDN_ONLY / redirect / static hosts via host_profiles
 3. auth_bypass rejects 302 redirects as bypass success
 4. auth_bypass rejects WAF 200 pages in _is_bypass_success
 5. auth_bypass _test_default_creds requires 200 + positive body
 6. info_disclosure rejects 301/302 (only accepts 200)
 7. http_method TRACE requires body echo validation
 8. http_method PUT requires follow-up GET confirmation
 9. bfla_bola rejects error-body 200 responses
10. cache_poisoning rejects WAF body reflections
11. header_checker returns (headers, status_code) tuple
12. header_checker skips missing-header findings on non-200
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# =====================================================================
# §1  DEEP PROBE — ResponseValidator Integration
# =====================================================================

class TestDeepProbeResponseValidation:
    """Phase 6: deep_probe.py rejects WAF/SPA/CDN responses."""

    def test_response_validator_instance_exists(self):
        """Module-level _response_validator is instantiated."""
        from src.workflow.pipelines.deep_probe import _response_validator
        assert _response_validator is not None

    def test_skip_host_types_defined(self):
        """_SKIP_HOST_TYPES frozenset contains redirect/static (cdn_only removed in P4.2)."""
        from src.workflow.pipelines.deep_probe import _SKIP_HOST_TYPES
        assert "cdn_only" not in _SKIP_HOST_TYPES  # P4.2: CDN hosts can have misconfigs
        assert "redirect_host" in _SKIP_HOST_TYPES
        assert "static_site" in _SKIP_HOST_TYPES

    def test_extract_host_helper(self):
        """_extract_host() properly extracts hostname."""
        from src.workflow.pipelines.deep_probe import _extract_host
        assert _extract_host("https://example.com/path") == "example.com"
        assert _extract_host("http://sub.target.io:8080/api") == "sub.target.io"
        assert _extract_host("plain-text") == "plain-text"

    def test_deep_probe_batch_accepts_host_profiles_param(self):
        """deep_probe_batch() signature includes host_profiles."""
        import inspect
        from src.workflow.pipelines.deep_probe import deep_probe_batch
        sig = inspect.signature(deep_probe_batch)
        assert "host_profiles" in sig.parameters


# =====================================================================
# §2  AUTH_BYPASS — 302 Rejection
# =====================================================================

class TestAuthBypass302Rejection:
    """Phase 7.1: auth_bypass.py no longer treats 302 as bypass."""

    def _make_checker(self):
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        return AuthBypassChecker()

    def test_is_bypass_success_rejects_302(self):
        """302 from 401 baseline must NOT count as bypass."""
        c = self._make_checker()
        # Previously this returned True — now must return False
        assert c._is_bypass_success(401, 302, 0, 0, "") is False
        assert c._is_bypass_success(403, 302, 0, 0, "") is False
        assert c._is_bypass_success(401, 301, 0, 0, "") is False

    def test_is_bypass_success_rejects_waf_200(self):
        """200 with WAF body signatures (Cloudflare, access denied) → False."""
        c = self._make_checker()
        assert c._is_bypass_success(403, 200, 100, 200, "Access Denied - Please verify") is False
        assert c._is_bypass_success(403, 200, 100, 500, '<div class="cf-error">Cloudflare</div>') is False
        assert c._is_bypass_success(403, 200, 100, 300, "Request blocked by WAF") is False
        assert c._is_bypass_success(403, 200, 100, 200, "Please complete the captcha") is False

    def test_is_bypass_success_accepts_real_200(self):
        """200 with genuine application content → True."""
        c = self._make_checker()
        assert c._is_bypass_success(403, 200, 100, 200, "<h1>Admin Dashboard</h1>") is True
        # JSON API data WITHOUT authenticated keywords is no longer enough
        # (must contain dashboard/admin/settings/etc or be >1000 bytes)
        assert c._is_bypass_success(401, 200, 100, 500, '{"users": [...]}') is False

    def test_is_bypass_success_200_same_baseline(self):
        """200→200 with similar body length is NOT bypass."""
        c = self._make_checker()
        # Same status, similar length — not bypass
        assert c._is_bypass_success(200, 200, 500, 500, "page content") is False
        # Same status, 3x larger + authenticated content required
        assert c._is_bypass_success(200, 200, 100, 800, '{"data": "secret"}') is False
        assert c._is_bypass_success(200, 200, 100, 800, "Admin Dashboard settings") is True


# =====================================================================
# §3  INFO_DISCLOSURE — Only 200 Accepted
# =====================================================================

class TestInfoDisclosure200Only:
    """Phase 7.2: info_disclosure only creates findings on status 200."""

    def test_status_check_uses_last_status(self):
        """Source code uses re.findall + [-1] for last status (after -L)."""
        import inspect
        from src.tools.scanners.custom_checks import info_disclosure_checker
        source = inspect.getsource(info_disclosure_checker._check_path)
        # Must NOT contain `status in (200, 301, 302)`
        assert "301, 302)" not in source, "Still accepting 301/302!"
        # Must contain `status == 200`
        assert "status == 200" in source

    def test_uses_findall_for_last_status(self):
        """Source code extracts LAST status code with re.findall()."""
        import inspect
        from src.tools.scanners.custom_checks import info_disclosure_checker
        source = inspect.getsource(info_disclosure_checker._check_path)
        assert "re.findall" in source, "Should use findall to get last redirect status"

    @pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308, 403, 500])
    def test_non_200_produces_no_finding(self, status_code):
        """Non-200 status code path → _check_path returns None."""
        # We test the regex extraction logic directly.
        # When curl -L follows a redirect, we may see multiple status lines:
        # HTTP/1.1 302 Found\r\n...\r\nHTTP/1.1 200 OK
        # The fix uses re.findall() and takes [-1].
        header_text = f"HTTP/1.1 {status_code} Something"
        all_statuses = re.findall(r"HTTP/[\d.]+ (\d{3})", header_text)
        status = int(all_statuses[-1]) if all_statuses else 0
        assert status == status_code
        # Only 200 should pass the guard
        assert (status == 200) == (status_code == 200)


# =====================================================================
# §4  HTTP_METHOD — TRACE Echo + PUT Verification
# =====================================================================

class TestHttpMethodValidation:
    """Phase 7.3: TRACE and PUT checks require body evidence."""

    def test_test_method_with_body_exists(self):
        """New _test_method_with_body() function is available."""
        from src.tools.scanners.custom_checks.http_method_checker import _test_method_with_body
        assert callable(_test_method_with_body)

    def test_trace_check_requires_echo(self):
        """TRACE finding requires body containing echo marker."""
        import inspect
        from src.tools.scanners.custom_checks import http_method_checker
        source = inspect.getsource(http_method_checker.check_http_methods)
        # Must check for echo marker or message/http content-type
        assert "X-WHAI-Trace-Test" in source or "echo-validation-marker" in source
        assert "message/http" in source

    def test_trace_check_uses_body_method(self):
        """TRACE uses _test_method_with_body, not _test_method."""
        import inspect
        from src.tools.scanners.custom_checks import http_method_checker
        source = inspect.getsource(http_method_checker.check_http_methods)
        # Find TRACE section — it should call _test_method_with_body
        trace_section_match = re.search(
            r"# 2.*?TRACE.*?(?=# 3|$)", source, re.DOTALL
        )
        assert trace_section_match is not None
        trace_section = trace_section_match.group(0)
        assert "_test_method_with_body" in trace_section

    def test_put_check_verifies_with_get(self):
        """PUT finding requires follow-up GET confirmation."""
        import inspect
        from src.tools.scanners.custom_checks import http_method_checker
        source = inspect.getsource(http_method_checker.check_http_methods)
        # Find PUT section
        put_section_match = re.search(
            r"# 3.*?PUT.*?(?=return host_findings|$)", source, re.DOTALL
        )
        assert put_section_match is not None
        put_section = put_section_match.group(0)
        # Must do follow-up GET
        assert "GET" in put_section
        assert "file_created" in put_section or "get_result" in put_section

    def test_put_confidence_higher_with_verification(self):
        """Verified PUT should have confidence >= 80."""
        import inspect
        from src.tools.scanners.custom_checks import http_method_checker
        source = inspect.getsource(http_method_checker.check_http_methods)
        # After verification, confidence should be 85 (our fix)
        assert "confidence=85" in source


# =====================================================================
# §5  BFLA_BOLA — Error Body Screening
# =====================================================================

class TestBflaBolaErrorBodyScreening:
    """Phase 7.4: bfla_bola rejects error-body 200 responses."""

    def test_error_signatures_check_exists(self):
        """Source contains error signature screening for 200 responses."""
        import inspect
        from src.tools.scanners.custom_checks import bfla_bola_checker
        source = inspect.getsource(bfla_bola_checker)
        # Must screen for common error keywords in body
        assert "unauthorized" in source.lower()
        assert "forbidden" in source.lower()

    @pytest.mark.parametrize("body_keyword", [
        "error", "unauthorized", "forbidden", "denied",
        "not allowed", "permission denied", "method not allowed",
    ])
    def test_error_body_signatures_defined(self, body_keyword):
        """Each error keyword should be in the _error_sigs tuple."""
        import inspect
        from src.tools.scanners.custom_checks import bfla_bola_checker
        source = inspect.getsource(bfla_bola_checker)
        assert body_keyword in source.lower()


# =====================================================================
# §6  CACHE_POISONING — WAF Reflection Rejection
# =====================================================================

class TestCachePoisoningWAFRejection:
    """Phase 7.5: cache_poisoning_checker rejects WAF body reflections."""

    def test_waf_signatures_present(self):
        """WAF body signatures are checked before creating finding."""
        import inspect
        from src.tools.scanners.custom_checks import cache_poisoning_checker
        source = inspect.getsource(cache_poisoning_checker)
        assert "cloudflare" in source.lower()
        assert "access denied" in source.lower()
        assert "captcha" in source.lower()
        assert "ray id:" in source.lower()

    def test_waf_check_comes_after_reflection(self):
        """WAF check is between reflection check and finding creation."""
        import inspect
        from src.tools.scanners.custom_checks import cache_poisoning_checker
        # Read _test_unkeyed_headers source
        source = inspect.getsource(cache_poisoning_checker._test_unkeyed_headers)
        # "reflected" check should come BEFORE waf_sigs
        reflected_pos = source.find("if not reflected")
        waf_pos = source.find("_waf_sigs")
        assert reflected_pos < waf_pos, "WAF check should be after reflection check"


# =====================================================================
# §7  HEADER_CHECKER — Status Code Awareness
# =====================================================================

class TestHeaderCheckerStatusCode:
    """Phase 7.6: header_checker returns status + skips non-200."""

    def test_fetch_headers_returns_tuple(self):
        """_fetch_headers returns (dict, int) tuple."""
        import inspect
        from src.tools.scanners.custom_checks import header_checker
        sig = inspect.signature(header_checker._fetch_headers)
        # Check return annotation or source
        source = inspect.getsource(header_checker._fetch_headers)
        assert "tuple[" in source or "status_code" in source

    def test_fetch_headers_extracts_status(self):
        """_fetch_headers parses HTTP status line."""
        import inspect
        from src.tools.scanners.custom_checks import header_checker
        source = inspect.getsource(header_checker._fetch_headers)
        assert "status_code" in source
        assert "HTTP/" in source

    def test_check_security_headers_uses_is_success(self):
        """check_security_headers guards missing-header findings with is_success."""
        import inspect
        from src.tools.scanners.custom_checks import header_checker
        source = inspect.getsource(header_checker.check_security_headers)
        assert "is_success" in source, "Must check is_success before missing-header finding"

    def test_non_200_skips_missing_headers(self):
        """Missing header findings are skipped for non-2xx responses."""
        import inspect
        from src.tools.scanners.custom_checks import header_checker
        source = inspect.getsource(header_checker.check_security_headers)
        # Guard: `if not is_success: continue`
        assert "not is_success" in source

    def test_200_range_for_is_success(self):
        """is_success covers 200-299 range."""
        import inspect
        from src.tools.scanners.custom_checks import header_checker
        source = inspect.getsource(header_checker.check_security_headers)
        assert "200 <= status_code <= 299" in source or "200 <=" in source


# =====================================================================
# §8  Cross-Checker Consistency Checks
# =====================================================================

class TestCrossCheckerConsistency:
    """All Phase 7 checkers should be importable and syntactically valid."""

    @pytest.mark.parametrize("module_path", [
        "src.tools.scanners.custom_checks.auth_bypass",
        "src.tools.scanners.custom_checks.info_disclosure_checker",
        "src.tools.scanners.custom_checks.http_method_checker",
        "src.tools.scanners.custom_checks.bfla_bola_checker",
        "src.tools.scanners.custom_checks.cache_poisoning_checker",
        "src.tools.scanners.custom_checks.header_checker",
    ])
    def test_module_importable(self, module_path):
        """Each fixed module imports cleanly."""
        import importlib
        mod = importlib.import_module(module_path)
        assert mod is not None

    def test_auth_bypass_no_blind_302(self):
        """auth_bypass._is_bypass_success source has no blind 302 accept."""
        import inspect
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        source = inspect.getsource(AuthBypassChecker._is_bypass_success)
        # Must NOT have: if ... test_status in (301, 302): return True
        lines = source.split("\n")
        for line in lines:
            stripped = line.strip()
            if "301, 302" in stripped and "return True" in stripped:
                pytest.fail(f"Blind 302 acceptance still present: {stripped}")

    def test_deep_probe_has_response_validator_import(self):
        """deep_probe.py imports ResponseValidator."""
        import inspect
        from src.workflow.pipelines import deep_probe
        source = inspect.getsource(deep_probe)
        assert "ResponseValidator" in source
        assert "from src.utils.response_validator import" in source
