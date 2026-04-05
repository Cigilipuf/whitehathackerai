"""
Regression tests for V19: Type Safety Hardening & Silent Data Loss Prevention.

Covers:
  - _safe_float helper for non-numeric confidence values
  - _coerce_to_str helper for list/None/non-string values
  - _finding_to_dict field coercion for parameter/payload/evidence/description
  - ReportFinding field validators (_coerce_str_fields, _coerce_confidence)
  - ReportFinding URL coercion in _convert_finding()
  - Bare except logging in tool availability check
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ─── Test _safe_float ─────────────────────────────────────────────

class TestSafeFloat:
    """Test the _safe_float helper for robust numeric conversion."""

    def _fn(self, val, default=0.0):
        from src.workflow.pipelines.full_scan import _safe_float
        return _safe_float(val, default)

    def test_normal_float(self):
        assert self._fn(42.5) == 42.5

    def test_normal_int(self):
        assert self._fn(50) == 50.0

    def test_string_number(self):
        assert self._fn("75.5") == 75.5

    def test_none_returns_default(self):
        assert self._fn(None, 30.0) == 30.0

    def test_empty_string_returns_default(self):
        assert self._fn("", 50.0) == 50.0

    def test_non_numeric_string_returns_default(self):
        """Brain/LLM may produce 'high', 'unknown', etc."""
        assert self._fn("high", 50.0) == 50.0
        assert self._fn("unknown", 30.0) == 30.0
        assert self._fn("N/A", 0.0) == 0.0

    def test_list_returns_default(self):
        assert self._fn([1, 2, 3], 0.0) == 0.0

    def test_dict_returns_default(self):
        assert self._fn({"score": 80}, 0.0) == 0.0

    def test_bool_converts(self):
        # float(True) == 1.0, float(False) == 0.0 — valid Python behavior
        assert self._fn(True) == 1.0
        assert self._fn(False) == 0.0


# ─── Test _coerce_to_str ──────────────────────────────────────────

class TestCoerceToStr:
    """Test the _coerce_to_str helper for type coercion."""

    def _fn(self, val):
        from src.workflow.pipelines.full_scan import _coerce_to_str
        return _coerce_to_str(val)

    def test_normal_string(self):
        assert self._fn("hello") == "hello"

    def test_empty_string(self):
        assert self._fn("") == ""

    def test_none(self):
        assert self._fn(None) == ""

    def test_list_returns_first(self):
        assert self._fn(["first", "second"]) == "first"

    def test_empty_list(self):
        assert self._fn([]) == ""

    def test_int_to_str(self):
        assert self._fn(42) == "42"

    def test_float_to_str(self):
        assert self._fn(3.14) == "3.14"

    def test_dict_to_str(self):
        result = self._fn({"key": "val"})
        assert isinstance(result, str)


# ─── Test _finding_to_dict field coercion ─────────────────────────

class TestFindingToDictFieldCoercion:
    """Verify _finding_to_dict coerces all string fields properly."""

    def _convert(self, **attrs):
        from src.workflow.pipelines.full_scan import _finding_to_dict

        class FakeFinding:
            pass

        obj = FakeFinding()
        for k, v in attrs.items():
            setattr(obj, k, v)
        return _finding_to_dict(obj, "test_tool")

    def test_parameter_list_coerced(self):
        d = self._convert(
            title="Test", vulnerability_type="xss",
            endpoint="https://example.com",
            parameter=["id", "name"],
        )
        assert isinstance(d["parameter"], str)
        assert d["parameter"] == "id"

    def test_payload_none_coerced(self):
        d = self._convert(
            title="Test", vulnerability_type="xss",
            endpoint="https://example.com",
            payload=None,
        )
        assert isinstance(d["payload"], str)
        assert d["payload"] == ""

    def test_evidence_list_coerced(self):
        d = self._convert(
            title="Test", vulnerability_type="xss",
            endpoint="https://example.com",
            evidence=["evidence line 1", "evidence line 2"],
        )
        assert isinstance(d["evidence"], str)
        assert d["evidence"] == "evidence line 1"

    def test_description_int_coerced(self):
        d = self._convert(
            title="Test", vulnerability_type="xss",
            endpoint="https://example.com",
            description=42,
        )
        assert isinstance(d["description"], str)
        assert d["description"] == "42"


# ─── Test ReportFinding field validators ──────────────────────────

class TestReportFindingFieldValidators:
    """Test ReportFinding Pydantic validators for type coercion."""

    def _create(self, **kwargs):
        from src.reporting.report_generator import ReportFinding
        defaults = {
            "title": "Test",
            "vulnerability_type": "xss",
        }
        defaults.update(kwargs)
        return ReportFinding(**defaults)

    def test_endpoint_list_coerced(self):
        rf = self._create(endpoint=["https://api.example.com/v1", "https://api2.example.com"])
        assert rf.endpoint == "https://api.example.com/v1"

    def test_endpoint_empty_list(self):
        rf = self._create(endpoint=[])
        assert rf.endpoint == ""

    def test_endpoint_none(self):
        rf = self._create(endpoint=None)
        assert rf.endpoint == ""

    def test_target_list_coerced(self):
        rf = self._create(target=["target1.com", "target2.com"])
        assert rf.target == "target1.com"

    def test_parameter_int_coerced(self):
        rf = self._create(parameter=42)
        assert rf.parameter == "42"

    def test_payload_none_coerced(self):
        rf = self._create(payload=None)
        assert rf.payload == ""

    def test_http_request_list_coerced(self):
        rf = self._create(http_request=["GET /api HTTP/1.1", "Host: example.com"])
        assert rf.http_request == "GET /api HTTP/1.1"

    def test_http_response_none_coerced(self):
        rf = self._create(http_response=None)
        assert rf.http_response == ""

    def test_poc_code_list_coerced(self):
        rf = self._create(poc_code=["import requests", "r = requests.get(url)"])
        assert rf.poc_code == "import requests"

    def test_summary_dict_coerced(self):
        rf = self._create(summary={"text": "summary"})
        assert isinstance(rf.summary, str)

    def test_description_normal_string(self):
        rf = self._create(description="Normal description")
        assert rf.description == "Normal description"

    def test_impact_none_coerced(self):
        rf = self._create(impact=None)
        assert rf.impact == ""

    def test_remediation_list_coerced(self):
        rf = self._create(remediation=["Fix 1", "Fix 2"])
        assert rf.remediation == "Fix 1"


# ─── Test ReportFinding confidence_score validator ─────────────────

class TestReportFindingConfidenceValidator:
    """Test confidence_score coercion from non-numeric values."""

    def _create(self, **kwargs):
        from src.reporting.report_generator import ReportFinding
        return ReportFinding(title="Test", vulnerability_type="xss", **kwargs)

    def test_string_number(self):
        rf = self._create(confidence_score="85.5")
        assert rf.confidence_score == 85.5

    def test_none_returns_zero(self):
        rf = self._create(confidence_score=None)
        assert rf.confidence_score == 0.0

    def test_non_numeric_string_returns_zero(self):
        rf = self._create(confidence_score="high")
        assert rf.confidence_score == 0.0

    def test_empty_string_returns_zero(self):
        rf = self._create(confidence_score="")
        assert rf.confidence_score == 0.0

    def test_int_converts(self):
        rf = self._create(confidence_score=75)
        assert rf.confidence_score == 75.0

    def test_normal_float(self):
        rf = self._create(confidence_score=92.3)
        assert rf.confidence_score == 92.3


# ─── Test confidence→severity calibration with bad values ─────────

class TestConfidenceSeverityCalibration:
    """Verify confidence→severity calibration doesn't crash on non-numeric confidence."""

    def test_non_numeric_confidence_no_crash(self):
        """Simulate the calibration loop with 'high' as confidence_score."""
        from src.workflow.pipelines.full_scan import _safe_float

        findings = [
            {"severity": "high", "confidence_score": "high"},     # LLM garbage
            {"severity": "critical", "confidence_score": ""},     # empty string
            {"severity": "medium", "confidence_score": None},     # None
            {"severity": "low", "confidence_score": [80, 90]},   # list
            {"severity": "high", "confidence_score": 75.0},       # normal
        ]

        _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        for f in findings:
            conf = _safe_float(f.get("confidence_score", 50.0), 50.0)
            assert isinstance(conf, float)
            sev = str(f.get("severity", "medium")).lower()
            sev_rank = _SEVERITY_ORDER.get(sev, 2)
            # No crash means success
            assert sev_rank >= 0


# ─── Test end-to-end: ReportFinding from Swagger-style dict ──────

class TestEndToEndReportFinding:
    """Full chain: dict with list URLs → ReportFinding creation succeeds."""

    def test_swagger_list_url_finding(self):
        """Simulate finding from Swagger parser with list endpoint."""
        from src.reporting.report_generator import ReportFinding

        # This is exactly what happened in the Uber scan
        finding_dict = {
            "title": "API Endpoint Exposed",
            "vulnerability_type": "api_exposure",
            "endpoint": ["https://api.uber.com/v1", "https://api2.uber.com/v2"],
            "target": ["uber.com", "api.uber.com"],
            "parameter": None,
            "payload": ["test_payload_1", "test_payload_2"],
            "http_request": None,
            "http_response": None,
            "confidence_score": "medium",  # LLM-generated string
            "poc_code": ["import requests", "r = requests.get(url)"],
        }

        # Should not raise ValidationError
        rf = ReportFinding(
            title=finding_dict["title"],
            vulnerability_type=finding_dict["vulnerability_type"],
            endpoint=finding_dict["endpoint"],
            target=finding_dict["target"],
            parameter=finding_dict["parameter"],
            payload=finding_dict["payload"],
            http_request=finding_dict["http_request"],
            http_response=finding_dict["http_response"],
            confidence_score=finding_dict["confidence_score"],
            poc_code=finding_dict["poc_code"],
        )

        assert rf.endpoint == "https://api.uber.com/v1"
        assert rf.target == "uber.com"
        assert rf.parameter == ""
        assert rf.payload == "test_payload_1"
        assert rf.http_request == ""
        assert rf.http_response == ""
        assert rf.confidence_score == 0.0  # "medium" → 0.0
        assert rf.poc_code == "import requests"


# ─── Test bare except logging ─────────────────────────────────────

class TestToolAvailabilityLogging:
    """Verify tool availability check includes exception info."""

    def test_exception_variable_named(self):
        """The except clause should capture the exception for logging."""
        import ast

        path = ROOT / "src" / "workflow" / "pipelines" / "full_scan.py"
        source = path.read_text()
        tree = ast.parse(source)

        # Find the handle_scope_analysis function
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                # Look for except handlers near tool availability check
                if node.name and "tool_avail" in node.name:
                    # Has a named exception variable — PASS
                    assert node.name == "_tool_avail_err"
                    return

        # If we get here, we didn't find it — but the expect clause may
        # be in a different form. Check that no bare 'except Exception:'
        # exists in the tool availability section.
        assert "except Exception as _tool_avail_err:" in source
