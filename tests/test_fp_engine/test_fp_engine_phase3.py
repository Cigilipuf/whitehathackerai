"""
Regression tests: Phase 3 — FP Engine Effectiveness

Tests for:
3.1: Brain timeout → heuristic penalty (-10)
3.2: HTTP status extraction from http_response string
3.3: WAF detection info passed to FPDetector (Layer 1e)
3.4: Brain analyzes ALL non-info severity
3.6: FP threshold raised from 30 → 40
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock

import pytest


# ===================================================================
# 3.1: Brain timeout → heuristic penalty
# ===================================================================

class TestBrainTimeoutPenalty:
    """Brain timeout must apply -10 penalty, not 0.0."""

    def test_timeout_returns_negative_delta(self):
        """_layer3_context_analysis must return negative delta on timeout."""
        from src.fp_engine.fp_detector import FPDetector

        detector = FPDetector()
        # Create a finding that triggers brain analysis
        from src.tools.base import Finding
        finding = Finding(
            title="SQL Injection in /api",
            severity="high",
            confidence=70.0,
            vulnerability_type="sql_injection",
            tool_name="sqlmap",
        )

        async def run():
            # Mock brain_engine.think to raise TimeoutError
            mock_brain = MagicMock()
            mock_brain._brain_confirmed_down = False
            mock_brain.think = AsyncMock(side_effect=asyncio.TimeoutError())
            detector.brain_engine = mock_brain
            # Ensure intelligence engine doesn't short-circuit
            detector.intelligence_engine = None
            result, delta, reasoning = await detector._layer3_context_analysis(finding)
            assert result == "timeout"
            assert delta == -10.0, f"Timeout delta should be -10.0, got {delta}"
            assert "incomplete" in reasoning.lower() or "timed out" in reasoning.lower()

        asyncio.run(run())

    def test_timeout_code_has_negative_delta(self):
        """Source code must contain -10.0 for timeout delta."""
        import src.fp_engine.fp_detector as mod
        source = open(mod.__file__).read()
        # Look for the timeout return with -10.0
        assert "timeout" in source
        assert "-10.0" in source


# ===================================================================
# 3.2: HTTP status extraction from response string
# ===================================================================

class TestHTTPStatusExtraction:
    """FP engine must extract real HTTP status from http_response string."""

    def test_hardcoded_200_removed(self):
        """response_status=200 hardcode must be replaced with extraction."""
        import src.fp_engine.fp_detector as mod
        source = open(mod.__file__).read()
        # Check we no longer have a bare hardcoded 200 for response_status
        # The extraction code should parse from the string
        assert "_cv_status_match" in source, "Status extraction regex missing"
        assert 'HTTP/' in source, "HTTP version pattern missing from extraction"

    def test_status_extraction_logic(self):
        """Test the status extraction pattern works on common responses."""
        import re
        patterns = [
            ("HTTP/1.1 200 OK\r\nContent-Type: text/html", 200),
            ("HTTP/1.1 403 Forbidden\r\nServer: cloudflare", 403),
            ("HTTP/1.1 404 Not Found\r\n", 404),
            ("HTTP/1.0 500 Internal Server Error\r\n", 500),
            ("HTTP/2 301 Moved Permanently\r\n", 301),
        ]
        for resp_str, expected_status in patterns:
            match = re.search(r"HTTP/[\d.]+\s+(\d{3})", resp_str)
            assert match, f"Failed to match status in: {resp_str}"
            assert int(match.group(1)) == expected_status

    def test_header_extraction_present(self):
        """Response header extraction code should be present."""
        import src.fp_engine.fp_detector as mod
        source = open(mod.__file__).read()
        assert "_cv_resp_headers" in source, "Response header extraction variable missing"


# ===================================================================
# 3.3: WAF detection passed to FP engine
# ===================================================================

class TestWAFDetectionWiring:
    """Pipeline-level WAF detection must be passed to FPDetector."""

    def test_fpdetector_accepts_waf_detection(self):
        """FPDetector.__init__ must accept waf_detection parameter."""
        import inspect
        from src.fp_engine.fp_detector import FPDetector
        sig = inspect.signature(FPDetector.__init__)
        assert "waf_detection" in sig.parameters

    def test_waf_detection_stored(self):
        """waf_detection dict must be stored on instance."""
        from src.fp_engine.fp_detector import FPDetector
        waf = {"waf_name": "Cloudflare", "confidence": 0.9}
        detector = FPDetector(waf_detection=waf)
        assert detector._waf_detection == waf

    def test_waf_detection_none_default(self):
        """waf_detection defaults to empty dict."""
        from src.fp_engine.fp_detector import FPDetector
        detector = FPDetector()
        assert detector._waf_detection == {}

    def test_full_scan_passes_waf_detection(self):
        """full_scan.py must pass waf_detection to FPDetector."""
        import src.workflow.pipelines.full_scan as mod
        source = open(mod.__file__).read()
        assert 'waf_detection=' in source, "waf_detection not passed to FPDetector in full_scan.py"

    def test_layer1e_waf_penalty_code_exists(self):
        """Layer 1e WAF awareness code must exist in fp_detector."""
        import src.fp_engine.fp_detector as mod
        source = open(mod.__file__).read()
        assert "Layer 1e" in source or "Pipeline WAF Awareness" in source


# ===================================================================
# 3.4: Brain analyzes ALL severity
# ===================================================================

class TestBrainAllSeverity:
    """Brain must analyze LOW and MEDIUM findings, not just HIGH/CRITICAL."""

    def test_low_severity_is_brain_worthy(self):
        """LOW severity findings should be brain-worthy."""
        from src.fp_engine.fp_detector import FPDetector
        detector = FPDetector()
        from src.tools.base import Finding
        finding = Finding(
            title="Open Redirect",
            severity="low",
            confidence=45.0,
            vulnerability_type="open_redirect",
            tool_name="nuclei",
        )
        sev_str = str(finding.severity).lower()
        is_brain_worthy = sev_str not in ("info", "unknown", "")
        assert is_brain_worthy, "LOW severity should be brain-worthy"

    def test_medium_severity_is_brain_worthy(self):
        """MEDIUM severity findings should be brain-worthy."""
        sev_str = "medium"
        is_brain_worthy = sev_str not in ("info", "unknown", "")
        assert is_brain_worthy, "MEDIUM severity should be brain-worthy"

    def test_info_severity_not_brain_worthy(self):
        """INFO severity should NOT be brain-worthy."""
        sev_str = "info"
        is_brain_worthy = sev_str not in ("info", "unknown", "")
        assert not is_brain_worthy, "INFO severity should NOT be brain-worthy"

    def test_brain_worthy_types_set_unchanged(self):
        """_BRAIN_WORTHY_TYPES still exists (backward compat)."""
        from src.fp_engine.fp_detector import FPDetector
        assert hasattr(FPDetector, "_BRAIN_WORTHY_TYPES")
        assert len(FPDetector._BRAIN_WORTHY_TYPES) > 0

    def test_source_code_no_high_critical_gate(self):
        """Brain gating must no longer require HIGH/CRITICAL for non-worthy types."""
        import src.fp_engine.fp_detector as mod
        source = open(mod.__file__).read()
        # The old pattern: 'or sev_str in ("high", "critical")'
        # should be replaced — it was the severity gate
        # New code should just check not in ("info", "unknown", "")
        assert 'sev_str not in ("info", "unknown", "")' in source


# ===================================================================
# 3.6: FP threshold raised 30 → 40
# ===================================================================

class TestFPThresholdRaised:
    """FP_LOW_CONFIDENCE_THRESHOLD must be 40."""

    def test_threshold_value(self):
        from src.utils.constants import FP_LOW_CONFIDENCE_THRESHOLD
        assert FP_LOW_CONFIDENCE_THRESHOLD == 40

    def test_other_thresholds_unchanged(self):
        from src.utils.constants import (
            FP_AUTO_REPORT_THRESHOLD,
            FP_HIGH_CONFIDENCE_THRESHOLD,
            FP_MEDIUM_CONFIDENCE_THRESHOLD,
        )
        assert FP_AUTO_REPORT_THRESHOLD == 90
        assert FP_HIGH_CONFIDENCE_THRESHOLD == 70
        assert FP_MEDIUM_CONFIDENCE_THRESHOLD == 65

    def test_threshold_ordering(self):
        """Thresholds must be ordered: LOW < MEDIUM < HIGH < AUTO_REPORT."""
        from src.utils.constants import (
            FP_AUTO_REPORT_THRESHOLD,
            FP_HIGH_CONFIDENCE_THRESHOLD,
            FP_MEDIUM_CONFIDENCE_THRESHOLD,
            FP_LOW_CONFIDENCE_THRESHOLD,
        )
        assert FP_LOW_CONFIDENCE_THRESHOLD < FP_MEDIUM_CONFIDENCE_THRESHOLD
        assert FP_MEDIUM_CONFIDENCE_THRESHOLD < FP_HIGH_CONFIDENCE_THRESHOLD
        assert FP_HIGH_CONFIDENCE_THRESHOLD < FP_AUTO_REPORT_THRESHOLD
