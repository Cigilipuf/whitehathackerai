"""Tests for ResponseValidator — Phase 1.1 of Revolution Plan.

Covers all 7 validation steps, WAF detection, auth-redirect detection,
SPA catch-all, content-type mismatch, host-profile context, convenience
functions, and edge cases.
"""

from __future__ import annotations

import hashlib
import re
import pytest
from dataclasses import asdict

from src.utils.response_validator import (
    ResponseValidator,
    ValidationResult,
    is_meaningful_response,
    reject_reason,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rv() -> ResponseValidator:
    return ResponseValidator()


# ===================================================================
# Step 1 — Redirect Detection (3xx)
# ===================================================================

class TestStep1Redirects:
    def test_301_redirect(self, rv: ResponseValidator):
        r = rv.validate(301, {"location": "https://example.com/"}, "")
        assert not r.is_valid
        assert r.is_redirect
        assert "redirect" in r.rejection_reason

    def test_302_auth_redirect(self, rv: ResponseValidator):
        r = rv.validate(302, {"location": "/login"}, "")
        assert r.is_redirect and r.is_auth_redirect

    def test_302_non_auth_redirect(self, rv: ResponseValidator):
        r = rv.validate(302, {"location": "/other-page"}, "")
        assert r.is_redirect
        assert not r.is_auth_redirect

    def test_307_redirect(self, rv: ResponseValidator):
        r = rv.validate(307, {"location": "/new"}, "")
        assert r.is_redirect
        assert "redirect" in r.rejection_reason

    def test_200_not_redirect(self, rv: ResponseValidator):
        r = rv.validate(200, {}, "ok")
        assert not r.is_redirect

    @pytest.mark.parametrize("location", [
        "/login", "/signin", "/auth/login", "/sso/redirect",
        "/oauth/authorize", "/accounts/login",
    ])
    def test_auth_redirect_patterns(self, rv: ResponseValidator, location: str):
        r = rv.validate(302, {"location": location}, "")
        assert r.is_auth_redirect, f"{location} should be detected as auth redirect"

    def test_redirect_without_location(self, rv: ResponseValidator):
        r = rv.validate(302, {}, "")
        assert r.is_redirect
        assert not r.is_auth_redirect

    def test_auth_redirect_confidence_penalty(self, rv: ResponseValidator):
        r = rv.validate(302, {"location": "/login"}, "")
        assert r.confidence_modifier < 0

    def test_redirect_has_status_in_reason(self, rv: ResponseValidator):
        r = rv.validate(301, {"location": "/elsewhere"}, "")
        assert "301" in r.rejection_reason


# ===================================================================
# Step 2 — WAF / CDN Block Pages
# ===================================================================

class TestStep2WAFDetection:
    def test_cloudflare_403(self, rv: ResponseValidator):
        r = rv.validate(403, {"cf-ray": "abc123"}, "Attention Required! | Cloudflare")
        assert not r.is_valid
        assert r.is_waf_block
        assert r.waf_name  # some WAF name detected

    def test_akamai_403(self, rv: ResponseValidator):
        r = rv.validate(403, {"x-akamai-transformed": "true"}, "Access Denied")
        assert r.is_waf_block

    def test_sucuri_block(self, rv: ResponseValidator):
        r = rv.validate(403, {"x-sucuri-id": "123"}, "")
        assert r.is_waf_block

    def test_modsecurity_block(self, rv: ResponseValidator):
        r = rv.validate(403, {}, "mod_security blocked this request")
        assert r.is_waf_block

    def test_imperva_block(self, rv: ResponseValidator):
        r = rv.validate(403, {}, "Powered by Incapsula something in body")
        assert r.is_waf_block

    def test_f5_block(self, rv: ResponseValidator):
        r = rv.validate(403, {}, "The requested URL was rejected. Please consult with your administrator.")
        assert r.is_waf_block

    def test_429_rate_limit_with_waf_signal(self, rv: ResponseValidator):
        r = rv.validate(429, {"cf-ray": "abc"}, "Rate limit exceeded")
        assert not r.is_valid
        assert r.is_waf_block

    def test_cloudflare_body_challenge(self, rv: ResponseValidator):
        r = rv.validate(403, {}, "Checking your browser before accessing the site")
        assert r.is_waf_block

    def test_waf_rejection_has_name(self, rv: ResponseValidator):
        r = rv.validate(403, {"cf-ray": "abc123"}, "Cloudflare block page")
        assert r.waf_name != ""

    def test_waf_confidence_penalty(self, rv: ResponseValidator):
        r = rv.validate(403, {"cf-ray": "abc"}, "Attention Required! | Cloudflare")
        assert r.confidence_modifier <= -20.0

    def test_simple_403_no_waf_signals(self, rv: ResponseValidator):
        """A 403 without WAF signatures should not be flagged as WAF block."""
        r = rv.validate(403, {}, "You do not have permission")
        assert not r.is_waf_block


# ===================================================================
# Step 3 — Server Error Pages (5xx)
# ===================================================================

class TestStep3ServerErrors:
    def test_500_generic_reject(self, rv: ResponseValidator):
        r = rv.validate(500, {}, "<h1>Internal Server Error</h1>")
        assert not r.is_valid
        assert r.is_error_page
        assert "server_error" in r.rejection_reason

    def test_500_with_java_exception(self, rv: ResponseValidator):
        r = rv.validate(500, {}, "java.lang.NullPointerException\n  at com.app.Main.run(Main.java:42)")
        assert r.is_valid  # stack trace = useful

    def test_500_with_traceback_python(self, rv: ResponseValidator):
        r = rv.validate(500, {}, "Traceback (most recent call last):\n  File 'app.py', line 3")
        assert r.is_valid

    def test_500_with_sql_error(self, rv: ResponseValidator):
        r = rv.validate(500, {}, "Fatal error: SQL syntax error near 'SELECT'")
        assert r.is_valid

    def test_502_bad_gateway(self, rv: ResponseValidator):
        r = rv.validate(502, {}, "<h1>Bad Gateway</h1>")
        assert not r.is_valid
        assert r.is_error_page

    def test_503_no_waf_signature(self, rv: ResponseValidator):
        """503 without WAF signature -> server error."""
        r = rv.validate(503, {}, "Service Temporarily Unavailable")
        assert not r.is_valid

    def test_500_with_debug_page(self, rv: ResponseValidator):
        r = rv.validate(500, {}, "Debug mode enabled: detailed error output follows")
        assert r.is_valid  # "debug" keyword triggers stack_trace detection


# ===================================================================
# Step 4 — Content-Type Mismatch
# ===================================================================

class TestStep4ContentTypeMismatch:
    def test_html_for_json_endpoint(self, rv: ResponseValidator):
        r = rv.validate(
            200, {"content-type": "text/html"},
            "<html><head><title>Page</title></head><body><p>Hello World</p></body></html>",
            expected_content_type="json",
        )
        assert not r.is_valid
        assert r.is_html_for_data_endpoint

    def test_html_for_xml_endpoint(self, rv: ResponseValidator):
        r = rv.validate(
            200, {"content-type": "text/html"},
            "<html><head><title>Error</title></head><body>Something went wrong</body></html>",
            expected_content_type="xml",
        )
        assert not r.is_valid
        assert r.is_html_for_data_endpoint

    def test_json_for_json_endpoint(self, rv: ResponseValidator):
        r = rv.validate(
            200, {"content-type": "application/json"},
            '{"ok": true}',
            expected_content_type="json",
        )
        assert r.is_valid

    def test_no_expected_content_type(self, rv: ResponseValidator):
        """When no expected_content_type, HTML for 200 should be valid."""
        r = rv.validate(200, {"content-type": "text/html"}, "<html><body>Hello</body></html>")
        assert r.is_valid

    def test_content_type_with_charset(self, rv: ResponseValidator):
        r = rv.validate(
            200, {"content-type": "text/html; charset=utf-8"},
            "<html><head><title>Page</title></head><body>Some generic page</body></html>",
            expected_content_type="json",
        )
        assert not r.is_valid
        assert r.is_html_for_data_endpoint


# ===================================================================
# Step 5 — SPA Catch-All Detection
# ===================================================================

class TestStep5SPACatchAll:
    def test_spa_baseline_match(self, rv: ResponseValidator):
        baseline = "<html><head><meta charset='utf-8'></head><body><div id='root'></div><script src='/static/js/app.bundle.js'></script></body></html>"
        r = rv.validate(
            200, {"content-type": "text/html"}, baseline,
            baseline_body=baseline,
        )
        assert not r.is_valid
        assert r.is_spa_catchall
        assert "spa" in r.rejection_reason

    def test_spa_different_body(self, rv: ResponseValidator):
        baseline = "<html><head><meta charset='utf-8'></head><body><div id='root'></div><script src='/static/js/app.bundle.js'></script></body></html>"
        different = "<html><head><title>Other</title></head><body>Completely different content with lots of text here and more words to pad length</body></html>"
        r = rv.validate(
            200, {"content-type": "text/html"}, different,
            baseline_body=baseline,
        )
        assert r.is_valid
        assert not r.is_spa_catchall

    def test_no_baseline_no_spa_check(self, rv: ResponseValidator):
        body = "<html><head></head><body><div id='root'></div></body></html>"
        r = rv.validate(200, {"content-type": "text/html"}, body)
        assert r.is_valid

    def test_spa_indicators_for_data_endpoint(self, rv: ResponseValidator):
        """SPA HTML returned for JSON endpoint — Step 4 catches content-type mismatch first."""
        body = '<html><head></head><body><div id="__next"></div><script src="/_next/static/main.js"></script></body></html>'
        r = rv.validate(
            200, {"content-type": "text/html"}, body,
            expected_content_type="json",
        )
        assert not r.is_valid
        # Step 4 (html_for_data_endpoint) fires before Step 5 (SPA)
        assert r.is_html_for_data_endpoint

    def test_spa_short_body_not_triggered(self, rv: ResponseValidator):
        short = "<html>x</html>"
        r = rv.validate(200, {"content-type": "text/html"}, short, baseline_body=short)
        assert r.is_valid  # len < 100 skips hash check


# ===================================================================
# Step 6 — Host Profile Context
# ===================================================================

class TestStep6HostProfile:
    def test_cdn_host_penalty(self, rv: ResponseValidator):
        profile = {"host_type": "cdn_only", "confidence_modifier": -20}
        r = rv.validate(
            200, {"content-type": "text/html"}, "<html>test content</html>",
            host_profile=profile,
        )
        assert r.confidence_modifier < 0

    def test_webapp_host_no_penalty(self, rv: ResponseValidator):
        profile = {"host_type": "web_application", "confidence_modifier": 0}
        r = rv.validate(200, {}, "ok", host_profile=profile)
        assert r.confidence_modifier == 0

    def test_no_profile_no_penalty(self, rv: ResponseValidator):
        r = rv.validate(200, {}, "ok")
        assert r.confidence_modifier == 0

    def test_redirect_host_penalty(self, rv: ResponseValidator):
        profile = {"host_type": "redirect_host", "confidence_modifier": -5}
        r = rv.validate(200, {}, "ok", host_profile=profile)
        assert r.confidence_modifier < 0

    def test_auth_gated_penalty(self, rv: ResponseValidator):
        profile = {"host_type": "auth_gated", "confidence_modifier": -3}
        r = rv.validate(200, {}, "ok", host_profile=profile)
        assert r.confidence_modifier < 0

    def test_static_site_for_json(self, rv: ResponseValidator):
        profile = {"host_type": "static_site", "confidence_modifier": -8}
        r = rv.validate(200, {}, "ok", host_profile=profile, expected_content_type="json")
        assert r.confidence_modifier < 0


# ===================================================================
# Step 7 — Empty / Tiny Body
# ===================================================================

class TestStep7EmptyBody:
    def test_empty_body_for_json(self, rv: ResponseValidator):
        r = rv.validate(200, {}, "", expected_content_type="json")
        assert not r.is_valid
        assert "empty" in r.rejection_reason

    def test_empty_body_for_xml(self, rv: ResponseValidator):
        r = rv.validate(200, {}, "", expected_content_type="xml")
        assert not r.is_valid

    def test_whitespace_body_for_json(self, rv: ResponseValidator):
        r = rv.validate(200, {}, "   \n\t  ", expected_content_type="json")
        assert not r.is_valid

    def test_empty_body_no_expectation(self, rv: ResponseValidator):
        """Empty body without expected_content_type passes check 7."""
        r = rv.validate(200, {}, "")
        assert r.is_valid

    def test_very_short_body_for_json(self, rv: ResponseValidator):
        r = rv.validate(200, {}, "ok", expected_content_type="json")
        assert not r.is_valid

    def test_minimal_json_valid(self, rv: ResponseValidator):
        r = rv.validate(
            200, {"content-type": "application/json"}, '{"a":1}',
            expected_content_type="json",
        )
        assert r.is_valid


# ===================================================================
# Convenience Functions
# ===================================================================

class TestConvenienceFunctions:
    def test_is_meaningful_true(self):
        assert is_meaningful_response(
            200, {"content-type": "application/json"}, '{"ok":true}', "json"
        )

    def test_is_meaningful_false_redirect(self):
        assert not is_meaningful_response(302, {"location": "/login"}, "")

    def test_is_meaningful_false_waf(self):
        assert not is_meaningful_response(
            403, {"cf-ray": "abc"}, "Attention Required! | Cloudflare"
        )

    def test_reject_reason_none_for_valid(self):
        r = reject_reason(200, {}, "ok")
        assert r is None or r == ""

    def test_reject_reason_for_redirect(self):
        result = reject_reason(302, {"location": "/login"}, "")
        assert result
        assert "redirect" in result


# ===================================================================
# validate_for_checker
# ===================================================================

class TestValidateForChecker:
    def test_valid_response(self, rv: ResponseValidator):
        r = rv.validate_for_checker(
            200, {"content-type": "text/html"}, "<html>config page</html>",
            checker_name="cloud_checker",
        )
        assert r.is_valid

    def test_waf_blocked_response(self, rv: ResponseValidator):
        r = rv.validate_for_checker(
            403, {"cf-ray": "abc"}, "Attention Required! | Cloudflare",
            checker_name="cicd_checker",
        )
        assert not r.is_valid
        assert r.is_waf_block

    def test_checker_name_in_log(self, rv: ResponseValidator):
        r = rv.validate_for_checker(
            302, {"location": "/login"}, "",
            checker_name="deserialization_checker",
            url="https://example.com/api",
        )
        assert not r.is_valid


# ===================================================================
# ValidationResult Dataclass
# ===================================================================

class TestValidationResult:
    def test_explicit_values(self):
        r = ValidationResult(
            is_valid=False,
            rejection_reason="test",
            is_waf_block=True,
            waf_name="cf",
        )
        assert not r.is_valid
        assert r.waf_name == "cf"

    def test_asdict(self):
        r = ValidationResult(is_valid=False, rejection_reason="waf_block")
        d = asdict(r)
        assert d["is_valid"] is False
        assert d["rejection_reason"] == "waf_block"

    def test_valid_result_defaults(self):
        r = ValidationResult(is_valid=True)
        assert r.is_valid
        assert r.rejection_reason == ""
        assert r.confidence_modifier == 0
        assert not r.is_redirect
        assert not r.is_waf_block


# ===================================================================
# set_baseline helper
# ===================================================================

class TestSetBaseline:
    def test_set_baseline_stores_hash(self, rv: ResponseValidator):
        rv.set_baseline("example.com", "<html>home page content here</html>")
        assert "example.com" in rv._baseline_hashes

    def test_baseline_hash_is_string(self, rv: ResponseValidator):
        rv.set_baseline("example.com", "some body")
        assert isinstance(rv._baseline_hashes["example.com"], str)


# ===================================================================
# Edge Cases
# ===================================================================

class TestEdgeCases:
    def test_headers_case_insensitive(self, rv: ResponseValidator):
        r = rv.validate(
            200, {"Content-Type": "application/json"}, '{"ok": true}',
            expected_content_type="json",
        )
        assert r.is_valid

    def test_waf_header_only_no_body_403(self, rv: ResponseValidator):
        r = rv.validate(403, {"cf-ray": "abc"}, "")
        assert r.is_waf_block

    def test_200_with_long_json(self, rv: ResponseValidator):
        body = '{"items": [' + ','.join([f'{{"id": {i}}}' for i in range(100)]) + ']}'
        r = rv.validate(
            200, {"content-type": "application/json"}, body,
            expected_content_type="json",
        )
        assert r.is_valid

    def test_binary_content_type(self, rv: ResponseValidator):
        r = rv.validate(200, {"content-type": "application/octet-stream"}, "binary data here")
        assert r.is_valid

    def test_multiple_steps_first_wins(self, rv: ResponseValidator):
        """302 + WAF header: redirect (step 1) should fire before WAF (step 2)."""
        r = rv.validate(302, {"cf-ray": "abc", "location": "/login"}, "")
        assert "redirect" in r.rejection_reason

    def test_status_401_rejected_as_auth_required(self, rv: ResponseValidator):
        """401 should be rejected as auth_required (Phase 1 fix)."""
        r = rv.validate(401, {}, "Unauthorized")
        assert not r.is_valid
        assert "auth_required" in r.rejection_reason
        assert r.is_auth_redirect is True

    def test_huge_html_page(self, rv: ResponseValidator):
        body = "<html><body>" + "x" * 100000 + "</body></html>"
        r = rv.validate(200, {"content-type": "text/html"}, body)
        assert r.is_valid

    def test_none_headers(self, rv: ResponseValidator):
        r = rv.validate(200, None, "ok")
        assert r.is_valid

    def test_none_body(self, rv: ResponseValidator):
        """None body should not crash."""
        try:
            r = rv.validate(200, {}, None)
            # If it doesn't crash, any result is acceptable
        except TypeError:
            pytest.fail("validate() should handle None body gracefully")
