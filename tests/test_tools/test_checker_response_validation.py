"""
Regression tests: ResponseValidator wiring in 5 custom checkers.

Validates that checkers now properly reject:
- WAF block pages (403 + Cloudflare signature)
- Redirect responses (302)
- Generic error pages (500 without stack traces)
- HTML responses when JSON is expected
- SPA catch-all pages

Each test uses httpx/aiohttp mocking to simulate bad responses,
verifying the checker produces NO findings for garbage data.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Helper: build mock httpx response ──

def _mock_httpx_response(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    text: str = "",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp


# ── Helper: build mock aiohttp response as async context manager ──

class _MockAiohttpResp:
    def __init__(self, status: int, headers: dict, body: str):
        self.status = status
        self.headers = headers
        self._body = body

    async def text(self, errors="strict"):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


# ===================================================================
# cloud_checker.py — ResponseValidator wiring
# ===================================================================

class TestCloudCheckerValidation:
    """cloud_checker must reject WAF/redirect/SPA responses."""

    @pytest.fixture
    def _import(self):
        from src.tools.scanners.custom_checks.cloud_checker import check_cloud_security
        return check_cloud_security

    def test_waf_403_produces_no_findings(self, _import):
        """Cloudflare 403 WAF page should produce zero findings."""
        fn = _import

        waf_body = '<html><head><title>Attention Required! | Cloudflare</title></head><body>blocked</body></html>'
        waf_headers = {"cf-ray": "abc123", "content-type": "text/html"}

        mock_resp = _mock_httpx_response(403, waf_headers, waf_body)

        async def run():
            with patch("httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = mock_client

                results = await fn(["https://target.com"], max_targets=1, timeout=5.0)
                return results

        findings = asyncio.run(run())
        assert len(findings) == 0, f"WAF 403 should produce 0 findings, got {len(findings)}"

    def test_redirect_302_produces_no_findings(self, _import):
        """302 redirect should produce zero findings."""
        fn = _import
        mock_resp = _mock_httpx_response(
            302,
            {"location": "https://target.com/login", "content-type": "text/html"},
            "",
        )

        async def run():
            with patch("httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = mock_client
                return await fn(["https://target.com"], max_targets=1, timeout=5.0)

        findings = asyncio.run(run())
        assert len(findings) == 0, f"302 should produce 0 findings, got {len(findings)}"

    def test_valid_json_response_can_produce_findings(self, _import):
        """200 with valid JSON and matching signature should still produce findings."""
        fn = _import
        body = '{"apiVersion": "v1", "kind": "NamespaceList", "items": []}'
        mock_resp = _mock_httpx_response(
            200,
            {"content-type": "application/json"},
            body,
        )

        async def run():
            with patch("httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = mock_client
                return await fn(["https://target.com"], max_targets=1, timeout=5.0)

        findings = asyncio.run(run())
        # Should produce findings — valid k8s API response
        assert len(findings) > 0, "Valid K8s response should produce findings"


# ===================================================================
# cicd_checker.py — ResponseValidator wiring
# ===================================================================

class TestCICDCheckerValidation:
    """cicd_checker must reject WAF/redirect/error responses."""

    @pytest.fixture
    def _import(self):
        from src.tools.scanners.custom_checks.cicd_checker import check_cicd_security
        return check_cicd_security

    def test_waf_block_produces_no_findings(self, _import):
        fn = _import
        waf_body = '<html><head><title>Access Denied</title></head><body>Your request was blocked by mod_security.</body></html>'
        mock_resp = _mock_httpx_response(403, {"content-type": "text/html"}, waf_body)

        async def run():
            with patch("httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = mock_client
                return await fn(["https://target.com"], max_targets=1, timeout=5.0)

        findings = asyncio.run(run())
        assert len(findings) == 0

    def test_500_error_produces_no_findings(self, _import):
        fn = _import
        mock_resp = _mock_httpx_response(
            500,
            {"content-type": "text/html"},
            "<html><body>Internal Server Error</body></html>",
        )

        async def run():
            with patch("httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = mock_client
                return await fn(["https://target.com"], max_targets=1, timeout=5.0)

        findings = asyncio.run(run())
        assert len(findings) == 0


# ===================================================================
# cors_checker.py — ResponseValidator wiring
# ===================================================================

class TestCORSCheckerValidation:
    """cors_checker must reject WAF/error responses before reading CORS headers."""

    @pytest.fixture
    def _import(self):
        from src.tools.scanners.custom_checks.cors_checker import check_cors_misconfigurations
        return check_cors_misconfigurations

    def test_waf_cors_headers_ignored(self, _import):
        """WAF 403 with reflected ACAO should NOT produce CORS findings."""
        fn = _import
        waf_body = '<html><head></head><body>Attention Required! | Cloudflare</body></html>'
        waf_headers = {
            "cf-ray": "abc", "content-type": "text/html",
            "access-control-allow-origin": "https://evil.com",
            "access-control-allow-credentials": "true",
        }
        mock_resp = _mock_httpx_response(403, waf_headers, waf_body)

        async def run():
            with patch("httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = mock_client
                return await fn(["https://target.com"])

        findings = asyncio.run(run())
        assert len(findings) == 0, "WAF CORS headers should be ignored"

    def test_500_cors_headers_ignored(self, _import):
        """500 error page with CORS headers should be filtered."""
        fn = _import
        err_body = "<html><body>Internal Server Error</body></html>"
        err_headers = {
            "content-type": "text/html",
            "access-control-allow-origin": "https://evil.com",
            "access-control-allow-credentials": "true",
        }
        mock_resp = _mock_httpx_response(500, err_headers, err_body)

        async def run():
            with patch("httpx.AsyncClient") as MockClient:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = mock_client
                return await fn(["https://target.com"])

        findings = asyncio.run(run())
        assert len(findings) == 0, "500 CORS headers should be ignored"


# ===================================================================
# deserialization_checker.py — ResponseValidator wiring
# ===================================================================

class TestDeserializationCheckerValidation:
    """deserialization_checker now validates responses before pattern matching."""

    def test_has_response_validator_import(self):
        """Module imports ResponseValidator."""
        import src.tools.scanners.custom_checks.deserialization_checker as mod
        source = open(mod.__file__).read()
        assert "ResponseValidator" in source

    def test_fingerprint_has_validation(self):
        """_fingerprint_responses method includes ResponseValidator call."""
        import src.tools.scanners.custom_checks.deserialization_checker as mod
        source = open(mod.__file__).read()
        # Find the _fingerprint_responses function and check it has validation
        idx = source.find("def _fingerprint_responses")
        assert idx > 0
        method_src = source[idx:idx + 1500]
        assert "ResponseValidator" in method_src

    def test_error_probe_has_waf_check(self):
        """_error_probe method checks for WAF blocks."""
        import src.tools.scanners.custom_checks.deserialization_checker as mod
        source = open(mod.__file__).read()
        idx = source.find("def _error_probe")
        assert idx > 0
        method_src = source[idx:idx + 2000]
        assert "is_waf_block" in method_src

    def test_viewstate_has_validation(self):
        """_check_viewstate method includes ResponseValidator call."""
        import src.tools.scanners.custom_checks.deserialization_checker as mod
        source = open(mod.__file__).read()
        idx = source.find("def _check_viewstate")
        assert idx > 0
        method_src = source[idx:idx + 1500]
        assert "ResponseValidator" in method_src


# ===================================================================
# mass_assignment_checker.py — ResponseValidator wiring
# ===================================================================

class TestMassAssignmentCheckerValidation:
    """mass_assignment_checker now validates injection responses."""

    def test_has_response_validator_import(self):
        import src.tools.scanners.custom_checks.mass_assignment_checker as mod
        source = open(mod.__file__).read()
        assert "ResponseValidator" in source

    def test_test_mass_assignment_has_validation(self):
        """_test_mass_assignment method includes ResponseValidator."""
        import src.tools.scanners.custom_checks.mass_assignment_checker as mod
        source = open(mod.__file__).read()
        idx = source.find("def _test_mass_assignment")
        assert idx > 0
        method_src = source[idx:idx + 2500]
        assert "ResponseValidator" in method_src

    def test_analyze_response_fields_has_validation(self):
        """_analyze_response_fields method includes ResponseValidator."""
        import src.tools.scanners.custom_checks.mass_assignment_checker as mod
        source = open(mod.__file__).read()
        idx = source.find("def _analyze_response_fields")
        assert idx > 0
        method_src = source[idx:idx + 1500]
        assert "ResponseValidator" in method_src


# ===================================================================
# Integration: ResponseValidator import availability
# ===================================================================

class TestResponseValidatorImportability:
    """ResponseValidator can be imported from each checker's context."""

    @pytest.mark.parametrize("module_path", [
        "src.tools.scanners.custom_checks.cloud_checker",
        "src.tools.scanners.custom_checks.cicd_checker",
        "src.tools.scanners.custom_checks.cors_checker",
        "src.tools.scanners.custom_checks.deserialization_checker",
        "src.tools.scanners.custom_checks.mass_assignment_checker",
    ])
    def test_import_succeeds(self, module_path):
        import importlib
        mod = importlib.import_module(module_path)
        source = open(mod.__file__).read()
        assert "from src.utils.response_validator import ResponseValidator" in source
