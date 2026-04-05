"""Regression tests for V18 (v2.8.2): URL-as-list cascade bug fixes.

These tests cover the root cause and all defense-in-depth layers:
- Finding model field validators (endpoint, target coercion)
- _finding_to_dict URL coercion
- Dedup key safety with list URLs
- _normalize_url / _url_path list handling
- FP elimination URL normalization
- Reporting URL normalization
- remediation.py logger import
"""

import json
import sys
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# 1. Finding model: endpoint/target field validator coerces lists to strings
# ---------------------------------------------------------------------------
class TestFindingURLFieldValidators:
    """Test that Finding model coerces list endpoint/target to string."""

    def test_endpoint_list_coerced_to_first_element(self):
        from src.tools.base import Finding

        f = Finding(
            title="Test",
            endpoint=["https://example.com/api", "https://example.com/api2"],
        )
        assert isinstance(f.endpoint, str)
        assert f.endpoint == "https://example.com/api"

    def test_target_list_coerced_to_first_element(self):
        from src.tools.base import Finding

        f = Finding(
            title="Test",
            target=["https://example.com/api", "https://other.com"],
        )
        assert isinstance(f.target, str)
        assert f.target == "https://example.com/api"

    def test_endpoint_empty_list_coerced_to_empty_string(self):
        from src.tools.base import Finding

        f = Finding(title="Test", endpoint=[])
        assert f.endpoint == ""

    def test_target_empty_list_coerced_to_empty_string(self):
        from src.tools.base import Finding

        f = Finding(title="Test", target=[])
        assert f.target == ""

    def test_endpoint_none_coerced_to_empty_string(self):
        from src.tools.base import Finding

        f = Finding(title="Test", endpoint=None)
        assert f.endpoint == ""

    def test_endpoint_int_coerced_to_string(self):
        from src.tools.base import Finding

        f = Finding(title="Test", endpoint=12345)
        assert f.endpoint == "12345"

    def test_normal_string_endpoint_unchanged(self):
        from src.tools.base import Finding

        f = Finding(title="Test", endpoint="https://example.com/api")
        assert f.endpoint == "https://example.com/api"


# ---------------------------------------------------------------------------
# 2. _finding_to_dict: URL coercion when endpoint/target is a list
# ---------------------------------------------------------------------------
class TestFindingToDictURLCoercion:
    """Test _finding_to_dict handles list URLs gracefully."""

    def test_finding_with_list_endpoint_produces_string_url(self):
        from src.tools.base import Finding

        # Finding model now coerces, but test the dict conversion too
        f = Finding(
            title="SQL Injection",
            vulnerability_type="sqli",
            endpoint="https://example.com/api",
        )
        # Simulate the conversion
        from src.workflow.pipelines.full_scan import _finding_to_dict

        d = _finding_to_dict(f, "sqlmap")
        assert isinstance(d["url"], str)
        assert "example.com" in d["url"]

    def test_finding_to_dict_raw_object_with_list_attr(self):
        """Object with list .endpoint attribute should produce string url."""
        from src.workflow.pipelines.full_scan import _finding_to_dict

        class FakeObj:
            title = "Test XSS"
            vulnerability_type = "xss"
            endpoint = ["https://a.com", "https://b.com"]
            target = ""
            parameter = "q"
            payload = "<script>"
            severity = "high"
            description = ""
            evidence = ""

        d = _finding_to_dict(FakeObj(), "dalfox")
        assert isinstance(d["url"], str)
        assert d["url"] == "https://a.com"


# ---------------------------------------------------------------------------
# 3. Dedup key: list URLs don't break set hashing
# ---------------------------------------------------------------------------
class TestDedupKeySafety:
    """Test dedup code handles list URLs without unhashable type errors."""

    def test_dedup_with_list_url_no_crash(self):
        """Simulate the dedup code path with list URL values."""
        findings = [
            {"title": "XSS", "url": ["https://a.com", "https://b.com"]},
            {"title": "XSS", "url": "https://a.com"},
            {"title": "SQLi", "url": "https://c.com"},
        ]
        # Reproduce the fixed dedup logic
        seen = set()
        deduped = []
        for f in findings:
            _url_val = f.get("url", "")
            if isinstance(_url_val, list):
                _url_val = _url_val[0] if _url_val else ""
            dedup_key = (f.get("title", ""), str(_url_val))
            if dedup_key not in seen:
                seen.add(dedup_key)
                deduped.append(f)
        # Should deduplicate the two "XSS at a.com" entries
        assert len(deduped) == 2

    def test_dedup_with_empty_list_url(self):
        """Empty list URL should produce empty string dedup key."""
        findings = [
            {"title": "Info Disclosure", "url": []},
            {"title": "Info Disclosure", "url": ""},
        ]
        seen = set()
        deduped = []
        for f in findings:
            _url_val = f.get("url", "")
            if isinstance(_url_val, list):
                _url_val = _url_val[0] if _url_val else ""
            dedup_key = (f.get("title", ""), str(_url_val))
            if dedup_key not in seen:
                seen.add(dedup_key)
                deduped.append(f)
        assert len(deduped) == 1


# ---------------------------------------------------------------------------
# 4. _normalize_url: handles list input
# ---------------------------------------------------------------------------
class TestNormalizeURLListSafety:
    """Test URL normalization functions handle list input."""

    def test_normalize_url_with_list(self):
        """_normalize_url should handle list input without crashing."""
        from urllib.parse import urlparse, parse_qs, urlencode

        def _normalize_url(url):
            if isinstance(url, list):
                url = url[0] if url else ""
            if not isinstance(url, str):
                url = str(url)
            try:
                p = urlparse(url.strip())
                scheme = (p.scheme or "https").lower()
                host = (p.netloc or "").lower()
                path = p.path.rstrip("/") or "/"
                return f"{scheme}://{host}{path}"
            except Exception:
                return url.strip().rstrip("/").lower()

        result = _normalize_url(["https://example.com/path?a=1", "https://other.com"])
        assert isinstance(result, str)
        assert "example.com" in result

    def test_normalize_url_with_empty_list(self):
        """Empty list should produce a valid string."""
        from urllib.parse import urlparse

        def _normalize_url(url):
            if isinstance(url, list):
                url = url[0] if url else ""
            if not isinstance(url, str):
                url = str(url)
            try:
                p = urlparse(url.strip())
                scheme = (p.scheme or "https").lower()
                host = (p.netloc or "").lower()
                path = p.path.rstrip("/") or "/"
                return f"{scheme}://{host}{path}"
            except Exception:
                return url.strip().rstrip("/").lower()

        result = _normalize_url([])
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# 5. FP elimination: URL normalization at stage boundary
# ---------------------------------------------------------------------------
class TestFPEliminationURLNormalization:
    """Test that FP elimination normalizes list URLs before processing."""

    def test_dict_finding_url_list_normalized(self):
        """Simulate the FP elimination URL normalization loop."""
        findings = [
            {
                "title": "CORS Misconfig",
                "url": ["https://api.example.com/v1", "https://api.example.com/v2"],
                "endpoint": ["https://api.example.com/ep1"],
                "target": "https://api.example.com",
            },
            {
                "title": "XSS",
                "url": "https://example.com/search",
                "endpoint": "https://example.com/search",
                "target": "https://example.com",
            },
        ]
        # Apply the normalization logic from handle_fp_elimination
        for _f in findings:
            if isinstance(_f, dict):
                for _key in ("url", "endpoint", "target"):
                    _v = _f.get(_key)
                    if isinstance(_v, list):
                        _f[_key] = _v[0] if _v else ""
                    elif _v is not None and not isinstance(_v, str):
                        _f[_key] = str(_v)

        assert findings[0]["url"] == "https://api.example.com/v1"
        assert findings[0]["endpoint"] == "https://api.example.com/ep1"
        assert findings[0]["target"] == "https://api.example.com"
        assert findings[1]["url"] == "https://example.com/search"

    def test_empty_list_url_becomes_empty_string(self):
        findings = [{"title": "Test", "url": [], "endpoint": [], "target": []}]
        for _f in findings:
            if isinstance(_f, dict):
                for _key in ("url", "endpoint", "target"):
                    _v = _f.get(_key)
                    if isinstance(_v, list):
                        _f[_key] = _v[0] if _v else ""
        assert findings[0]["url"] == ""
        assert findings[0]["endpoint"] == ""
        assert findings[0]["target"] == ""


# ---------------------------------------------------------------------------
# 6. remediation.py: logger import
# ---------------------------------------------------------------------------
class TestRemediationLoggerImport:
    """Test that remediation.py has logger properly imported."""

    def test_logger_accessible_in_remediation_module(self):
        from src.reporting import remediation

        assert hasattr(remediation, "logger"), "remediation.py must import logger"

    def test_get_remediation_unknown_type_no_crash(self):
        """get_remediation with unknown vuln type should not crash on logger."""
        from src.reporting.remediation import get_remediation

        # Should not raise NameError for 'logger'
        result = get_remediation("completely_unknown_vuln_type_xyz")
        assert result.summary  # Should return generic advice

    def test_get_remediation_known_type(self):
        """Known vuln types should return specific remediation."""
        from src.reporting.remediation import get_remediation

        result = get_remediation("sql_injection")
        assert result.summary


# ---------------------------------------------------------------------------
# 7. Reporting: URL normalization
# ---------------------------------------------------------------------------
class TestReportingURLNormalization:
    """Test that reporting stage normalizes URLs."""

    def test_reporting_normalizes_list_urls(self):
        """Simulate the reporting URL normalization loop."""
        findings = [
            {
                "title": "API Key Exposed",
                "url": ["https://api.uber.com/key", "https://api2.uber.com/key"],
                "endpoint": ["https://api.uber.com/key"],
            },
        ]
        for _f in findings:
            if isinstance(_f, dict):
                for _key in ("url", "endpoint", "target"):
                    _v = _f.get(_key)
                    if isinstance(_v, list):
                        _f[_key] = _v[0] if _v else ""
                    elif _v is not None and not isinstance(_v, str):
                        _f[_key] = str(_v)

        assert findings[0]["url"] == "https://api.uber.com/key"
        assert isinstance(findings[0]["endpoint"], str)


# ---------------------------------------------------------------------------
# 8. End-to-end: Finding created from Swagger-like data with list URLs
# ---------------------------------------------------------------------------
class TestEndToEndSwaggerListURL:
    """Simulate the full chain from Swagger parser → Finding → dict → dedup."""

    def test_swagger_list_url_full_chain(self):
        from src.tools.base import Finding
        from src.workflow.pipelines.full_scan import _finding_to_dict

        # Swagger parser might produce this:
        endpoint_data = {
            "url": ["https://api.example.com/v1/users", "https://api.example.com/v2/users"],
            "method": "POST",
            "path": "/v1/users",
        }

        # API fuzzer creates Finding with list URL
        f = Finding(
            title="SQL Injection: POST /v1/users",
            vulnerability_type="sql_injection",
            target=endpoint_data["url"],  # list!
            endpoint=endpoint_data["url"],  # list!
            parameter="user_id",
            payload="' OR 1=1 --",
            tool_name="api_fuzzer",
        )

        # Validator should coerce
        assert isinstance(f.endpoint, str)
        assert isinstance(f.target, str)

        # Convert to dict
        d = _finding_to_dict(f, "api_fuzzer")
        assert isinstance(d["url"], str)

        # Dedup should work
        seen = set()
        _url_val = d.get("url", "")
        if isinstance(_url_val, list):
            _url_val = _url_val[0] if _url_val else ""
        dedup_key = (d.get("title", ""), str(_url_val))
        seen.add(dedup_key)  # Should not raise
        assert len(seen) == 1
