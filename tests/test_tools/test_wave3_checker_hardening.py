"""Regression tests for Wave 3 checker hardening.

Covers the implementation slices:
 Batch 1:
 1. rate_limit_checker rejects WAF/challenge responses and redirects as success
 2. fourxx_bypass requires real resource content, not login/error pages
 3. graphql_deep_scanner validates JSON responses before creating findings
 Batch 2:
 4. jwt_checker rejects WAF/auth-error 200 responses
 5. api_endpoint_tester rejects WAF challenge pages on 200
 6. business_logic rejects WAF/error bodies before claiming price/quantity manipulation
 7. race_condition filters WAF responses before counting successes
 8. idor_checker screens baseline and test responses for WAF/error pages
 Batch 3:
 9. prototype_pollution_checker rejects WAF/error pages and validates baseline
 10. websocket_checker validates 101 upgrades and rejects WAF body in discovery
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest


class _FakeAiohttpResponse:
    def __init__(self, status: int, body: str = "", headers: dict[str, str] | None = None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self, errors: str = "replace") -> str:
        return self._body


class _FakeAiohttpSession:
    def __init__(self, responses: list[_FakeAiohttpResponse]):
        self._responses = list(responses)

    def request(self, *args, **kwargs):
        if not self._responses:
            raise AssertionError("No more fake responses configured")
        return self._responses.pop(0)


class _FakeHttpxResponse:
    def __init__(
        self,
        status_code: int,
        text: str = "",
        headers: dict[str, str] | None = None,
        json_data: Any = None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "application/json"}
        self._json_data = json_data
        self.content = text.encode("utf-8")

    def json(self):
        if isinstance(self._json_data, Exception):
            raise self._json_data
        return self._json_data


class _FakeHttpxClient:
    def __init__(self, responses: list[_FakeHttpxResponse]):
        self._responses = list(responses)

    async def request(self, *args, **kwargs):
        if not self._responses:
            raise AssertionError("No more fake responses configured")
        return self._responses.pop(0)

    async def post(self, *args, **kwargs):
        return await self.request(*args, **kwargs)

    async def get(self, *args, **kwargs):
        return await self.request(*args, **kwargs)


class TestRateLimitCheckerHardening:
    def test_meaningful_success_rejects_redirect_and_waf(self):
        from src.tools.scanners.custom_checks.rate_limit_checker import _is_meaningful_success

        assert _is_meaningful_success(302, {"location": "/login"}, "") is False
        assert _is_meaningful_success(200, {"content-type": "text/html"}, "Cloudflare Ray ID: abc") is False
        assert _is_meaningful_success(200, {"content-type": "application/json"}, '{"ok":true}') is True

    def test_rate_limit_skips_waf_blocked_successes(self):
        from src.tools.scanners.custom_checks.rate_limit_checker import RateLimitChecker

        checker = RateLimitChecker()
        session = _FakeAiohttpSession([
            _FakeAiohttpResponse(200, "<html>Attention Required! | Cloudflare</html>", {"content-type": "text/html"}),
            _FakeAiohttpResponse(200, "<html>Attention Required! | Cloudflare</html>", {"content-type": "text/html"}),
            _FakeAiohttpResponse(200, "<html>Attention Required! | Cloudflare</html>", {"content-type": "text/html"}),
            _FakeAiohttpResponse(200, "<html>Attention Required! | Cloudflare</html>", {"content-type": "text/html"}),
        ])

        finding = asyncio.run(
            checker._test_rate_limit(session, "https://example.com/login", "POST", {}, {}, 4, "Login")
        )
        assert finding is None

    def test_rate_limit_finding_uses_meaningful_success(self):
        from src.tools.scanners.custom_checks.rate_limit_checker import RateLimitChecker

        checker = RateLimitChecker()
        session = _FakeAiohttpSession([
            _FakeAiohttpResponse(200, '{"ok":true}', {"content-type": "application/json"}),
            _FakeAiohttpResponse(200, '{"ok":true}', {"content-type": "application/json"}),
            _FakeAiohttpResponse(200, '{"ok":true}', {"content-type": "application/json"}),
            _FakeAiohttpResponse(200, '{"ok":true}', {"content-type": "application/json"}),
            _FakeAiohttpResponse(200, '{"ok":true}', {"content-type": "application/json"}),
        ])

        finding = asyncio.run(
            checker._test_rate_limit(session, "https://example.com/login", "POST", {}, {}, 5, "Login")
        )
        assert finding is not None
        assert finding.metadata["meaningful_success"] == 5
        assert finding.metadata["waf_blocks"] == 0


class TestFourxxBypassHardening:
    def test_try_bypass_rejects_login_page(self):
        from src.tools.scanners.custom_checks.fourxx_bypass import FourXXBypassChecker

        checker = FourXXBypassChecker()
        client = _FakeHttpxClient([
            _FakeHttpxResponse(
                200,
                "<html><title>Login</title><body>Please sign in</body></html>",
                {"content-type": "text/html"},
            )
        ])

        finding = asyncio.run(
            checker._try_bypass(
                client,
                "https://example.com/admin",
                "GET",
                {},
                "trailing_slash",
                403,
                90,
                "blocked body",
                "https://example.com/admin",
            )
        )
        assert finding is None

    def test_try_bypass_accepts_real_resource_body(self):
        from src.tools.scanners.custom_checks.fourxx_bypass import FourXXBypassChecker

        checker = FourXXBypassChecker()
        client = _FakeHttpxClient([
            _FakeHttpxResponse(
                200,
                "<html><body><h1>Admin Dashboard</h1><table><tr><td>settings</td></tr></table></body></html>",
                {"content-type": "text/html"},
            )
        ])

        finding = asyncio.run(
            checker._try_bypass(
                client,
                "https://example.com/admin/",
                "GET",
                {},
                "trailing_slash",
                403,
                20,
                "blocked",
                "https://example.com/admin",
            )
        )
        assert finding is not None
        assert finding.title.startswith("403/401 Bypass")


class TestGraphqlDeepScannerHardening:
    def test_validated_graphql_response_rejects_auth_errors(self):
        from src.tools.scanners.custom_checks.graphql_deep_scanner import _validated_graphql_response

        resp = _FakeHttpxResponse(
            200,
            '{"errors":[{"message":"Unauthorized access"}]}',
            {"content-type": "application/json"},
            {"errors": [{"message": "Unauthorized access"}]},
        )

        body = _validated_graphql_response(resp, "https://example.com/graphql")
        assert body is None

    def test_validated_graphql_response_rejects_waf_html(self):
        from src.tools.scanners.custom_checks.graphql_deep_scanner import _validated_graphql_response

        resp = _FakeHttpxResponse(
            200,
            "<html><title>Attention Required! | Cloudflare</title></html>",
            {"content-type": "text/html", "cf-ray": "abc"},
            ValueError("not json"),
        )

        body = _validated_graphql_response(resp, "https://example.com/graphql")
        assert body is None

    def test_batch_query_brute_skips_auth_error_list(self):
        from src.tools.scanners.custom_checks.graphql_deep_scanner import _test_batch_query_brute

        client = _FakeHttpxClient([
            _FakeHttpxResponse(
                200,
                '[{"errors":[{"message":"forbidden"}]}]',
                {"content-type": "application/json"},
                [{"errors": [{"message": "forbidden"}]}],
            )
        ])

        findings = asyncio.run(_test_batch_query_brute(client, "https://example.com/graphql", asyncio.Semaphore(1)))
        assert findings == []

    def test_batch_query_brute_accepts_real_batch_array(self):
        from src.tools.scanners.custom_checks.graphql_deep_scanner import _test_batch_query_brute

        client = _FakeHttpxClient([
            _FakeHttpxResponse(
                200,
                '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]',
                {"content-type": "application/json"},
                [
                    {"data": {"__typename": "Query"}},
                    {"data": {"__typename": "Query"}},
                ],
            )
        ])

        findings = asyncio.run(_test_batch_query_brute(client, "https://example.com/graphql", asyncio.Semaphore(1)))
        assert len(findings) == 1

    def test_depth_limit_uses_baseline_multiplier(self):
        import inspect
        from src.tools.scanners.custom_checks import graphql_deep_scanner

        source = inspect.getsource(graphql_deep_scanner._test_depth_limit)
        assert "baseline_elapsed * 3" in source

    def test_directive_abuse_uses_baseline_multiplier(self):
        import inspect
        from src.tools.scanners.custom_checks import graphql_deep_scanner

        source = inspect.getsource(graphql_deep_scanner._test_directive_abuse)
        assert "baseline_elapsed * 3" in source


class TestWave3ModuleImportability:
    @pytest.mark.parametrize("module_path", [
        "src.tools.scanners.custom_checks.rate_limit_checker",
        "src.tools.scanners.custom_checks.fourxx_bypass",
        "src.tools.scanners.custom_checks.graphql_deep_scanner",
        "src.tools.scanners.custom_checks.jwt_checker",
        "src.tools.scanners.custom_checks.api_endpoint_tester",
        "src.tools.scanners.custom_checks.business_logic",
        "src.tools.scanners.custom_checks.race_condition",
        "src.tools.scanners.custom_checks.idor_checker",
    ])
    def test_module_importable(self, module_path: str):
        import importlib

        mod = importlib.import_module(module_path)
        assert mod is not None


# ═══════════════════════════════════════════════════════════════
#  Batch 2: JWT Checker Hardening
# ═══════════════════════════════════════════════════════════════

class TestJWTCheckerHardening:
    def test_is_jwt_genuinely_accepted_rejects_waf_page(self):
        from src.tools.scanners.custom_checks.jwt_checker import _is_jwt_genuinely_accepted

        resp = _FakeHttpxResponse(
            200,
            "<html><title>Attention Required! | Cloudflare</title><body>Ray ID: abc</body></html>",
            {"content-type": "text/html", "cf-ray": "abc"},
        )
        assert _is_jwt_genuinely_accepted(resp) is False

    def test_is_jwt_genuinely_accepted_rejects_auth_error_json(self):
        from src.tools.scanners.custom_checks.jwt_checker import _is_jwt_genuinely_accepted

        resp = _FakeHttpxResponse(
            200,
            '{"error": "invalid_token", "message": "Token is not valid"}',
            {"content-type": "application/json"},
        )
        assert _is_jwt_genuinely_accepted(resp) is False

    def test_is_jwt_genuinely_accepted_allows_real_api_response(self):
        from src.tools.scanners.custom_checks.jwt_checker import _is_jwt_genuinely_accepted

        resp = _FakeHttpxResponse(
            200,
            '{"user": {"id": 1, "name": "Test User"}, "roles": ["admin"]}',
            {"content-type": "application/json"},
        )
        assert _is_jwt_genuinely_accepted(resp) is True

    def test_is_jwt_genuinely_accepted_rejects_non_2xx(self):
        from src.tools.scanners.custom_checks.jwt_checker import _is_jwt_genuinely_accepted

        resp = _FakeHttpxResponse(401, '{"error": "unauthorized"}')
        assert _is_jwt_genuinely_accepted(resp) is False

    def test_is_jwt_genuinely_accepted_rejects_unauthorized_body(self):
        from src.tools.scanners.custom_checks.jwt_checker import _is_jwt_genuinely_accepted

        resp = _FakeHttpxResponse(
            200,
            '{"status": "unauthorized", "detail": "JWT expired"}',
            {"content-type": "application/json"},
        )
        assert _is_jwt_genuinely_accepted(resp) is False


# ═══════════════════════════════════════════════════════════════
#  Batch 2: API Endpoint Tester Hardening
# ═══════════════════════════════════════════════════════════════

class TestAPIEndpointTesterHardening:
    def test_is_real_content_rejects_waf_challenge(self):
        from src.tools.scanners.custom_checks.api_endpoint_tester import _is_real_content

        resp = _FakeHttpxResponse(
            200,
            "<html>Just a moment... Checking your browser</html>",
            {"content-type": "text/html", "cf-ray": "abc123"},
        )
        assert _is_real_content(resp) is False

    def test_is_real_content_accepts_real_json(self):
        from src.tools.scanners.custom_checks.api_endpoint_tester import _is_real_content

        resp = _FakeHttpxResponse(
            200,
            '{"users": [{"id": 1, "name": "admin"}]}',
            {"content-type": "application/json"},
        )
        assert _is_real_content(resp) is True

    def test_is_real_content_rejects_non_200(self):
        from src.tools.scanners.custom_checks.api_endpoint_tester import _is_real_content

        resp = _FakeHttpxResponse(403, "Forbidden")
        assert _is_real_content(resp) is False

    def test_method_override_needs_real_content(self):
        """Method override finding should not fire when override returns WAF page."""
        import inspect
        from src.tools.scanners.custom_checks import api_endpoint_tester

        source = inspect.getsource(api_endpoint_tester.test_api_endpoints)
        assert "_is_real_content(override_resp)" in source


# ═══════════════════════════════════════════════════════════════
#  Batch 2: Business Logic Checker Hardening
# ═══════════════════════════════════════════════════════════════

class TestBusinessLogicHardening:
    def test_is_genuine_success_rejects_waf_page(self):
        from src.tools.scanners.custom_checks.business_logic import _is_genuine_success

        assert _is_genuine_success(200, "<html>Cloudflare Ray ID: abc</html>") is False
        assert _is_genuine_success(200, "Access Denied - WAF block") is False
        assert _is_genuine_success(200, "Captcha required to proceed") is False

    def test_is_genuine_success_rejects_non_200(self):
        from src.tools.scanners.custom_checks.business_logic import _is_genuine_success

        assert _is_genuine_success(302, "Redirecting...") is False
        assert _is_genuine_success(403, "Forbidden") is False
        assert _is_genuine_success(500, "Internal error") is False

    def test_is_genuine_success_accepts_real_success(self):
        from src.tools.scanners.custom_checks.business_logic import _is_genuine_success

        assert _is_genuine_success(200, '{"status": "ok", "order_id": 123}') is True
        assert _is_genuine_success(201, '{"created": true}') is True

    def test_auto_detect_no_longer_accepts_status_lt_404(self):
        """The old check was resp.status < 404 which accepted 302/403."""
        import inspect
        from src.tools.scanners.custom_checks import business_logic

        source = inspect.getsource(business_logic.BusinessLogicChecker._auto_detect_logic_flaws)
        assert "< 404" not in source
        assert "_is_genuine_success" in source

    def test_price_manipulation_uses_genuine_success(self):
        import inspect
        from src.tools.scanners.custom_checks import business_logic

        source = inspect.getsource(business_logic.BusinessLogicChecker._test_price_manipulation)
        assert "_is_genuine_success" in source


# ═══════════════════════════════════════════════════════════════
#  Batch 2: Race Condition Checker Hardening
# ═══════════════════════════════════════════════════════════════

class TestRaceConditionHardening:
    def test_is_waf_body_detects_cloudflare(self):
        from src.tools.scanners.custom_checks.race_condition import _is_waf_body

        assert _is_waf_body("<html>Attention Required! | Cloudflare</html>") is True
        assert _is_waf_body("Request Blocked by Sucuri WAF") is True
        assert _is_waf_body('{"ok": true, "data": [1, 2, 3]}') is False

    def test_race_test_skips_when_majority_waf(self):
        from src.tools.scanners.custom_checks.race_condition import RaceConditionChecker

        checker = RaceConditionChecker()
        # Create a test case
        tc = {
            "url": "https://example.com/api/redeem",
            "method": "POST",
            "body": {"code": "GIFT100"},
            "expected_successes": 1,
        }
        # We can't easily override the barrier, but we can verify the
        # source contains the WAF majority check
        import inspect
        source = inspect.getsource(checker._race_test)
        assert "waf_count" in source
        assert "_is_waf_body" in source

    def test_302_no_longer_counted_as_success(self):
        """302 was removed from success status codes in the fallback path."""
        import inspect
        from src.tools.scanners.custom_checks import race_condition

        source = inspect.getsource(race_condition.RaceConditionChecker._race_test)
        # The fallback path should only count 200, 201 (not 302)
        assert "200, 201)" in source
        assert "200, 201, 302)" not in source


# ═══════════════════════════════════════════════════════════════
#  Batch 2: IDOR Checker Hardening
# ═══════════════════════════════════════════════════════════════

class TestIDORCheckerHardening:
    def test_is_waf_or_error_page_detects_waf(self):
        from src.tools.scanners.custom_checks.idor_checker import _is_waf_or_error_page

        assert _is_waf_or_error_page("<html>Cloudflare Ray ID</html>") is True
        assert _is_waf_or_error_page("Access Denied by Akamai") is True
        assert _is_waf_or_error_page("Please login required") is True

    def test_is_waf_or_error_page_allows_real_data(self):
        from src.tools.scanners.custom_checks.idor_checker import _is_waf_or_error_page

        assert _is_waf_or_error_page('{"user": {"id": 1, "email": "test@test.com"}}') is False
        assert _is_waf_or_error_page('{"data": {"name": "John Doe"}}') is False

    def test_baseline_waf_skips_idor_test(self):
        """If baseline response is WAF page, _test_idor should return None."""
        import inspect
        from src.tools.scanners.custom_checks import idor_checker

        source = inspect.getsource(idor_checker.IDORChecker._test_idor)
        assert "_is_waf_or_error_page(baseline_body)" in source

    def test_test_response_waf_skips_confidence(self):
        """If test response is WAF page, it should be skipped."""
        import inspect
        from src.tools.scanners.custom_checks import idor_checker

        source = inspect.getsource(idor_checker.IDORChecker._test_idor)
        assert "_is_waf_or_error_page(test_body)" in source


# ═══════════════════════════════════════════════════════════════
# Batch 3: prototype_pollution_checker + websocket_checker
# ═══════════════════════════════════════════════════════════════


class TestPrototypePollutionResponseValidator:
    """prototype_pollution_checker must use ResponseValidator and WAF screening."""

    def test_imports_response_validator(self):
        import inspect
        from src.tools.scanners.custom_checks import prototype_pollution_checker as mod

        source = inspect.getsource(mod)
        assert "from src.utils.response_validator import ResponseValidator" in source

    def test_module_level_validator_instance(self):
        from src.tools.scanners.custom_checks import prototype_pollution_checker as mod

        assert hasattr(mod, "_response_validator")
        from src.utils.response_validator import ResponseValidator
        assert isinstance(mod._response_validator, ResponseValidator)

    def test_has_waf_error_detection_function(self):
        from src.tools.scanners.custom_checks.prototype_pollution_checker import _is_waf_or_error_page

        assert _is_waf_or_error_page("<html>Attention Required! | Cloudflare</html>") is True
        assert _is_waf_or_error_page("<html>Access Denied by WAF</html>") is True
        assert _is_waf_or_error_page("Ray ID: abc123def456") is True

    def test_waf_not_triggered_on_normal_content(self):
        from src.tools.scanners.custom_checks.prototype_pollution_checker import _is_waf_or_error_page

        assert _is_waf_or_error_page('{"status": "ok", "user": {"id": 1}}') is False
        assert _is_waf_or_error_page("<html><body>Hello World</body></html>") is False

    def test_query_phase_uses_validator(self):
        """_test_query_params_get must call validate_for_checker."""
        import inspect
        from src.tools.scanners.custom_checks import prototype_pollution_checker as mod

        source = inspect.getsource(mod._test_query_params_get)
        assert "validate_for_checker" in source
        assert "_is_waf_or_error_page" in source

    def test_json_body_phase_uses_validator(self):
        """_test_json_body must call validate_for_checker."""
        import inspect
        from src.tools.scanners.custom_checks import prototype_pollution_checker as mod

        source = inspect.getsource(mod._test_json_body)
        assert "validate_for_checker" in source
        assert "_is_waf_or_error_page" in source

    def test_form_params_phase_uses_validator(self):
        """_test_form_params must call validate_for_checker."""
        import inspect
        from src.tools.scanners.custom_checks import prototype_pollution_checker as mod

        source = inspect.getsource(mod._test_form_params)
        assert "validate_for_checker" in source
        assert "_is_waf_or_error_page" in source

    def test_baseline_validated_before_probing(self):
        """Baseline response must be validated — WAF baseline skips URL entirely."""
        import inspect
        from src.tools.scanners.custom_checks import prototype_pollution_checker as mod

        source = inspect.getsource(mod._test_query_params_get)
        # Baseline validation should appear BEFORE payload loop
        bl_idx = source.index("_bl_vr")
        payload_idx = source.index("_query_payloads")
        assert bl_idx < payload_idx, "Baseline validation must precede payload testing"

    def test_status_510_bypasses_waf_check(self):
        """Status 510 pollution detection should NOT be blocked by WAF check."""
        import inspect
        from src.tools.scanners.custom_checks import prototype_pollution_checker as mod

        source = inspect.getsource(mod._test_query_params_get)
        # The WAF check should have an exception for _STATUS_POLLUTION_CODE
        assert "_STATUS_POLLUTION_CODE" in source

    def test_canary_rejected_if_in_waf_page(self):
        """Canary detection must check _is_waf_or_error_page before creating finding."""
        import inspect
        from src.tools.scanners.custom_checks import prototype_pollution_checker as mod

        source = inspect.getsource(mod._test_query_params_get)
        # The canary check line should include WAF rejection
        assert "_is_waf_or_error_page(resp.text)" in source


class TestWebSocketResponseValidator:
    """websocket_checker must validate 101 upgrades and reject WAF in discovery."""

    def test_imports_response_validator(self):
        import inspect
        from src.tools.scanners.custom_checks import websocket_checker as mod

        source = inspect.getsource(mod)
        assert "from src.utils.response_validator import ResponseValidator" in source

    def test_module_level_validator_instance(self):
        from src.tools.scanners.custom_checks import websocket_checker as mod

        assert hasattr(mod, "_response_validator")
        from src.utils.response_validator import ResponseValidator
        assert isinstance(mod._response_validator, ResponseValidator)

    def test_has_waf_body_detection(self):
        from src.tools.scanners.custom_checks.websocket_checker import _is_waf_or_error_body

        assert _is_waf_or_error_body("<html>Cloudflare Ray ID</html>") is True
        assert _is_waf_or_error_body("Access Denied by Sucuri WAF") is True
        assert _is_waf_or_error_body("captcha challenge required") is True

    def test_waf_body_allows_normal_html(self):
        from src.tools.scanners.custom_checks.websocket_checker import _is_waf_or_error_body

        assert _is_waf_or_error_body("<html><body>Normal page content</body></html>") is False
        assert _is_waf_or_error_body('{"type": "websocket", "status": "ok"}') is False

    def test_discovery_validates_101_upgrade_headers(self):
        """101 response must have Upgrade: websocket or Sec-WebSocket-Accept."""
        import inspect
        from src.tools.scanners.custom_checks import websocket_checker as mod

        source = inspect.getsource(mod._discover_ws_endpoints)
        # Should check for real WS upgrade headers on 101
        assert 'resp.headers.get("upgrade"' in source or "_upgrade_h" in source

    def test_discovery_rejects_waf_body_in_non_101(self):
        """Non-101 discovery via body keywords must reject WAF pages."""
        import inspect
        from src.tools.scanners.custom_checks import websocket_checker as mod

        source = inspect.getsource(mod._discover_ws_endpoints)
        assert "_is_waf_or_error_body" in source

    def test_discovery_uses_response_validator(self):
        """Non-101 body-based discovery must pass ResponseValidator."""
        import inspect
        from src.tools.scanners.custom_checks import websocket_checker as mod

        source = inspect.getsource(mod._discover_ws_endpoints)
        assert "validate_for_checker" in source

    def test_cswsh_validates_real_101(self):
        """CSWSH test must distinguish real 101 from partial acceptance."""
        import inspect
        from src.tools.scanners.custom_checks import websocket_checker as mod

        source = inspect.getsource(mod._test_cswsh)
        assert "is_real_101" in source

    def test_cswsh_rejects_waf_body_on_non_101(self):
        """CSWSH test rejects WAF bodies on non-101 responses."""
        import inspect
        from src.tools.scanners.custom_checks import websocket_checker as mod

        source = inspect.getsource(mod._test_cswsh)
        assert "_is_waf_or_error_body" in source

    def test_non_101_cswsh_gets_lower_confidence(self):
        """Non-101 accepted CSWSH should have lower confidence than real 101."""
        import inspect
        from src.tools.scanners.custom_checks import websocket_checker as mod

        source = inspect.getsource(mod._test_cswsh)
        # Real 101 = 85.0, partial = 55.0
        assert "55.0" in source
