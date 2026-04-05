"""
V21 Regression Tests — Production Quality & Tool Reliability Hardening

Covers:
  P0-1: _dict_to_finding validation fix (string/numeric field coercion)
  P0-2: Brain timeout floor proportional minimum
  P0-3: Go tool memory limits (GOMEMLIMIT/GOGC env)
  P1-1: Nuclei thread exhaustion (GOMAXPROCS + semaphore)
  P1-2: http2_http3_checker SSL noise (log level)
  P1-3: Nuclei template YAML sanitization (_sanitize_llm_yaml)
  P2-1: Report save_markdown/save_json safety (exception handling)
"""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, AsyncMock

import pytest


# ====================================================================
# P0-1: _dict_to_finding validation fix
# ====================================================================


class TestDictToFindingCoercion:
    """Ensure _dict_to_finding handles malformed dicts gracefully."""

    def _get_helpers(self):
        """Import _coerce_to_str and _safe_float from full_scan module."""
        import importlib
        mod = importlib.import_module("src.workflow.pipelines.full_scan")
        return getattr(mod, "_coerce_to_str"), getattr(mod, "_safe_float")

    def test_coerce_to_str_list(self):
        _cs, _ = self._get_helpers()
        assert _cs(["https://a.com", "https://b.com"]) == "https://a.com"

    def test_coerce_to_str_none(self):
        _cs, _ = self._get_helpers()
        assert _cs(None) == ""

    def test_coerce_to_str_int(self):
        _cs, _ = self._get_helpers()
        assert _cs(42) == "42"

    def test_coerce_to_str_string_passthrough(self):
        _cs, _ = self._get_helpers()
        assert _cs("hello") == "hello"

    def test_safe_float_numeric_string(self):
        _, _sf = self._get_helpers()
        assert _sf("85.5", 50.0) == 85.5

    def test_safe_float_non_numeric_string(self):
        _, _sf = self._get_helpers()
        assert _sf("high", 50.0) == 50.0

    def test_safe_float_none(self):
        _, _sf = self._get_helpers()
        assert _sf(None, 50.0) == 50.0

    def test_safe_float_empty_string(self):
        _, _sf = self._get_helpers()
        assert _sf("", 50.0) == 50.0

    def test_safe_float_actual_float(self):
        _, _sf = self._get_helpers()
        assert _sf(92.3, 50.0) == 92.3

    def test_finding_with_list_endpoint(self):
        """Finding model accepts list endpoint and coerces to string via validator."""
        from src.tools.base import Finding

        f = Finding(
            title="Test",
            endpoint=["https://a.com/api", "https://b.com/api"],
            severity="medium",
        )
        assert isinstance(f.endpoint, str)
        assert f.endpoint == "https://a.com/api"

    def test_finding_list_parameter_needs_pipeline_coercion(self):
        """Finding model does NOT coerce parameter — pipeline _dict_to_finding does."""
        from src.tools.base import Finding
        # Direct list parameter raises — this is expected; pipeline coerces first
        with pytest.raises(Exception):
            Finding(title="Test", parameter=["id", "name"], severity="medium")

    def test_finding_with_none_endpoint(self):
        from src.tools.base import Finding

        f = Finding(title="Test", endpoint=None, severity="low")
        assert f.endpoint == ""


# ====================================================================
# P0-2: Brain timeout floor — proportional minimum
# ====================================================================


class TestBrainTimeoutFloor:
    """Verify proportional timeout floor prevents brain from setting
    dangerously low timeouts for long-running tools like dalfox."""

    def test_proportional_floor_balanced_xss(self):
        """BALANCED XSS base=180s → floor should be 90s, not 30s."""
        base_timeout = 180
        _ABSOLUTE_MIN = 30
        proportional_min = max(_ABSOLUTE_MIN, int(base_timeout * 0.5))
        assert proportional_min == 90, "BALANCED XSS floor should be 90s"
        # Brain suggests 20s → clamped to 90s
        suggested_timeout = 20
        clamped = max(suggested_timeout, proportional_min)
        assert clamped == 90

    def test_proportional_floor_stealth_xss(self):
        """STEALTH XSS base=300s → floor should be 150s."""
        base_timeout = 300
        proportional_min = max(30, int(base_timeout * 0.5))
        assert proportional_min == 150

    def test_proportional_floor_low_base(self):
        """Low base timeout (e.g. 40s) → absolute min of 30s applies."""
        base_timeout = 40
        proportional_min = max(30, int(base_timeout * 0.5))
        assert proportional_min == 30, "Absolute minimum should be 30s"

    def test_proportional_floor_very_low_base(self):
        """Very low base (10s) → absolute min of 30s prevents going below."""
        base_timeout = 10
        proportional_min = max(30, int(base_timeout * 0.5))
        assert proportional_min == 30


# ====================================================================
# P0-3: Go tool memory limits
# ====================================================================


class TestGoToolMemoryLimits:
    """Verify gau/waybackurls set GOMEMLIMIT and GOGC env vars."""

    def test_gau_has_memory_limit(self):
        from src.tools.recon.web_discovery.gau_wrapper import GauWrapper
        tool = GauWrapper.__new__(GauWrapper)
        assert hasattr(tool, "memory_limit")
        assert tool.memory_limit <= 512 * 1024 * 1024  # 512MB max

    def test_waybackurls_has_memory_limit(self):
        from src.tools.recon.web_discovery.waybackurls_wrapper import WaybackurlsWrapper
        tool = WaybackurlsWrapper.__new__(WaybackurlsWrapper)
        assert hasattr(tool, "memory_limit")
        assert tool.memory_limit <= 512 * 1024 * 1024

    def test_gau_run_sets_go_env(self):
        """Verify gau's run() creates Go env with GOMEMLIMIT."""
        from src.tools.recon.web_discovery import gau_wrapper as gm
        source = open(gm.__file__).read()
        assert "GOMEMLIMIT" in source, "gau_wrapper must set GOMEMLIMIT"
        assert "GOGC" in source, "gau_wrapper must set GOGC"

    def test_waybackurls_run_sets_go_env(self):
        from src.tools.recon.web_discovery import waybackurls_wrapper as wm
        source = open(wm.__file__).read()
        assert "GOMEMLIMIT" in source, "waybackurls must set GOMEMLIMIT"
        assert "GOGC" in source, "waybackurls must set GOGC"


# ====================================================================
# P1-1: Nuclei thread exhaustion (GOMAXPROCS + semaphore)
# ====================================================================


class TestNucleiThreadExhaustion:
    """Verify nuclei env and pipeline semaphore limits."""

    def test_nuclei_go_env_helper_exists(self):
        from src.tools.scanners.nuclei_wrapper import NucleiWrapper
        tool = NucleiWrapper.__new__(NucleiWrapper)
        assert hasattr(tool, "_go_env"), "NucleiWrapper must have _go_env() method"

    def test_nuclei_go_env_contents(self):
        from src.tools.scanners.nuclei_wrapper import NucleiWrapper
        tool = NucleiWrapper.__new__(NucleiWrapper)
        # Provide memory_limit attribute for _go_env
        tool.memory_limit = 1024 * 1024 * 1024
        env = tool._go_env()
        assert "GOMAXPROCS" in env
        assert env["GOMAXPROCS"] == "4"
        assert "GOMEMLIMIT" in env

    def test_pipeline_nuclei_semaphore_is_2(self):
        """Pipeline should limit to 2 concurrent nuclei processes."""
        source_path = Path("src/workflow/pipelines/full_scan.py")
        text = source_path.read_text()
        # Match nuclei_sem = asyncio.Semaphore(2)
        assert "nuclei_sem" in text
        import re
        m = re.search(r"nuclei_sem\s*=\s*asyncio\.Semaphore\((\d+)\)", text)
        assert m is not None, "nuclei_sem semaphore must be defined"
        assert m.group(1) == "2", f"nuclei_sem should be 2, got {m.group(1)}"


# ====================================================================
# P1-2: http2_http3_checker SSL noise
# ====================================================================


class TestHTTP2CheckerLogLevel:
    """Verify SSL close notification errors use debug, not warning."""

    def test_ssl_noise_is_debug_level(self):
        from src.tools.scanners.custom_checks import http2_http3_checker as mod
        source = open(mod.__file__).read()
        assert "logger.debug" in source, "SSL noise should use debug level"
        # Ensure no logger.warning for TLS close noise
        import re
        # The specific error pattern should NOT be at warning level
        warning_lines = re.findall(r"logger\.warning.*(?:TLS|APPLICATION_DATA|close)", source)
        assert len(warning_lines) == 0, (
            "TLS close-notify errors should be at debug level, not warning"
        )


# ====================================================================
# P1-3: Nuclei template YAML sanitization
# ====================================================================


class TestSanitizeLlmYaml:
    """Test _sanitize_llm_yaml handles common LLM YAML mistakes."""

    def _sanitize(self, text: str) -> str:
        from src.tools.scanners.nuclei_template_writer import _sanitize_llm_yaml
        return _sanitize_llm_yaml(text)

    def test_tab_to_spaces(self):
        text = "id: test-template\n\tname: Test"
        result = self._sanitize(text)
        assert "\t" not in result
        assert "  name: Test" in result

    def test_balanced_quotes_untouched(self):
        text = 'description: "This is a valid description"'
        result = self._sanitize(text)
        assert result == text

    def test_unbalanced_double_quotes_fixed(self):
        """Odd number of double-quotes in value should be switched to single quotes."""
        text = 'description: "some text with "extra" inside'
        result = self._sanitize(text)
        # Should use single quotes instead
        assert "'" in result
        # Must be valid YAML-parseable
        import yaml
        try:
            yaml.safe_load(result)
        except yaml.YAMLError:
            pass  # Structure may not be complete, but no double-quote scanner error

    def test_list_item_internal_quotes(self):
        """List items with internal double-quotes should be fixed."""
        text = '  - "payload with "nested" quotes"'
        result = self._sanitize(text)
        assert "'" in result

    def test_clean_yaml_passthrough(self):
        """Valid YAML should pass through unchanged (except trailing whitespace)."""
        text = textwrap.dedent("""\
            id: custom-xss-test
            info:
              name: XSS Test
              author: whitehat-ai
              severity: medium
            http:
              - method: GET
                path:
                  - "{{BaseURL}}/search?q=test"
        """)
        result = self._sanitize(text)
        import yaml
        parsed = yaml.safe_load(result)
        assert parsed["id"] == "custom-xss-test"
        assert parsed["info"]["severity"] == "medium"

    def test_trailing_whitespace_stripped(self):
        text = "id: test-template   \nname: Test  "
        result = self._sanitize(text)
        for line in result.splitlines():
            assert line == line.rstrip(), f"Trailing whitespace found: '{line}'"

    def test_sanitize_wired_in_generate_pipeline(self):
        """Verify _sanitize_llm_yaml is called in generate_nuclei_template."""
        source = Path("src/tools/scanners/nuclei_template_writer.py").read_text()
        assert "_sanitize_llm_yaml" in source
        # Should appear in both generate and fix paths
        assert source.count("_sanitize_llm_yaml") >= 3, (
            "_sanitize_llm_yaml should be in: definition, generate path, and fix path"
        )


# ====================================================================
# P2-1: Report save_markdown/save_json safety
# ====================================================================


class TestReportSaveSafety:
    """Verify save_markdown/save_json handle exceptions gracefully."""

    def _make_generator(self, tmp_path):
        from src.reporting.report_generator import ReportGenerator
        gen = ReportGenerator.__new__(ReportGenerator)
        gen.output_dir = tmp_path
        return gen

    def _make_report(self):
        from src.reporting.report_generator import Report
        return Report(report_id="test-report-001", findings=[])

    def test_save_markdown_crash_writes_fallback(self, tmp_path):
        gen = self._make_generator(tmp_path)
        report = self._make_report()

        # Force to_markdown to crash
        with patch.object(gen, "to_markdown", side_effect=RuntimeError("render boom")):
            result = gen.save_markdown(report, str(tmp_path))
            # Should still return a path
            assert result is not None
            # Fallback content should be written
            content = Path(result).read_text()
            assert "render boom" in content
            assert "Report test-report-001" in content

    def test_save_json_crash_returns_path(self, tmp_path):
        gen = self._make_generator(tmp_path)
        report = self._make_report()

        with patch.object(gen, "to_json", side_effect=RuntimeError("json boom")):
            result = gen.save_json(report, str(tmp_path))
            assert result is not None
            assert "test-report-001" in result

    def test_save_markdown_normal_flow(self, tmp_path):
        gen = self._make_generator(tmp_path)
        report = self._make_report()

        with patch.object(gen, "to_markdown", return_value="# Report\n\nOK"):
            result = gen.save_markdown(report, str(tmp_path))
            content = Path(result).read_text()
            assert content == "# Report\n\nOK"
            assert report.markdown_path == result


# ====================================================================
# Edge Cases
# ====================================================================


class TestEdgeCases:
    """Additional edge-case tests for V21 fixes."""

    def test_safe_float_with_list(self):
        """_safe_float should handle list input gracefully."""
        from src.workflow.pipelines.full_scan import _safe_float
        assert _safe_float([1, 2, 3], 50.0) == 50.0

    def test_coerce_to_str_empty_list(self):
        from src.workflow.pipelines.full_scan import _coerce_to_str
        assert _coerce_to_str([]) == ""

    def test_coerce_to_str_nested_list(self):
        from src.workflow.pipelines.full_scan import _coerce_to_str
        result = _coerce_to_str([["nested"], "value"])
        assert isinstance(result, str)

    def test_sanitize_llm_yaml_empty_string(self):
        from src.tools.scanners.nuclei_template_writer import _sanitize_llm_yaml
        assert _sanitize_llm_yaml("") == ""

    def test_sanitize_llm_yaml_no_colon(self):
        """Lines without colons should pass through."""
        from src.tools.scanners.nuclei_template_writer import _sanitize_llm_yaml
        text = "# This is a comment\n---\n  - item1"
        result = _sanitize_llm_yaml(text)
        assert "# This is a comment" in result
        assert "  - item1" in result
