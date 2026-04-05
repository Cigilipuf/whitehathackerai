"""Tests for False Positive Elimination Engine."""

from __future__ import annotations

import pytest

from src.fp_engine.scoring.bayesian_filter import BayesianFilter, EvidenceSignal
from src.fp_engine.scoring.confidence_scorer import ConfidenceScorer
from src.fp_engine.verification.context_verify import ContextVerifier, HttpContext
from src.fp_engine.verification.manual_verify import ManualVerifyGuideGenerator
from src.fp_engine.patterns.known_fps import KnownFPMatcher


class TestBayesianFilter:
    """Test Bayesian FP/TP classifier."""

    def setup_method(self):
        self.bf = BayesianFilter(default_prior=0.5)

    def test_strong_tp_evidence(self):
        """Multiple strong TP signals should yield high posterior."""
        result = self.bf.evaluate("sqli", {
            "sqlmap_confirmed": True,
            "data_extracted": True,
            "time_based_delay": True,
        })
        assert result.posterior > 0.8
        assert result.verdict == "true_positive"

    def test_strong_fp_evidence(self):
        """Negative signals should lower posterior."""
        result = self.bf.evaluate("sqli", {
            "sqlmap_confirmed": False,
            "data_extracted": False,
            "waf_block": True,
        })
        assert result.posterior < 0.5

    def test_no_evidence(self):
        """No evidence should return prior."""
        result = self.bf.evaluate("sqli", {})
        assert result.signals_used == 0
        assert abs(result.posterior - 0.5) < 0.01

    def test_custom_prior(self):
        result = self.bf.evaluate("sqli", {}, prior=0.8)
        assert abs(result.prior - 0.8) < 0.01

    def test_add_signal(self):
        sig = EvidenceSignal(name="custom_check", observed=True, true_positive_rate=0.9, false_positive_rate=0.1)
        self.bf.add_signal("sqli", sig)
        signals = self.bf.get_signals("sqli")
        assert any(s.name == "custom_check" for s in signals)


class TestContextVerifier:
    """Test HTTP context verification."""

    def setup_method(self):
        self.cv = ContextVerifier()

    def test_waf_detection_cloudflare(self):
        ctx = HttpContext(
            request_url="https://example.com",
            response_status=200,
            response_headers={"cf-ray": "abc123", "Content-Type": "text/html"},
            response_body="<html>normal page</html>",
        )
        result = self.cv.verify("xss", ctx)
        assert result.waf_detected is True
        assert "Cloudflare" in result.waf_name

    def test_waf_block_page(self):
        ctx = HttpContext(
            request_url="https://example.com",
            response_status=403,
            response_headers={"Content-Type": "text/html"},
            response_body="Access Denied - Your request has been blocked by our security system",
        )
        result = self.cv.verify("sqli", ctx)
        assert len(result.checks_failed) > 0

    def test_payload_reflection_check(self):
        payload = "<script>alert(1)</script>"
        ctx = HttpContext(
            request_url="https://example.com/search?q=test",
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body=f"<html>Search results: {payload}</html>",
        )
        result = self.cv.verify("xss", ctx, payload=payload)
        assert any("reflected verbatim" in c for c in result.checks_passed)

    def test_payload_encoded(self):
        payload = "<script>alert(1)</script>"
        ctx = HttpContext(
            request_url="https://example.com/search",
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>",
        )
        result = self.cv.verify("xss", ctx, payload=payload)
        assert any("HTML-encoded" in c for c in result.checks_failed)


class TestManualVerifyGuide:
    """Test manual verification guide generation."""

    def setup_method(self):
        self.gen = ManualVerifyGuideGenerator()

    def test_generate_sqli_guide(self):
        guide = self.gen.generate("sqli", "https://example.com/login", parameter="username")
        assert guide.vuln_type == "sqli"
        assert len(guide.steps) > 0
        assert len(guide.success_criteria) > 0

    def test_generate_xss_guide(self):
        guide = self.gen.generate("xss", "https://example.com/profile")
        assert guide.difficulty == "easy"

    def test_generate_unknown_uses_default(self):
        guide = self.gen.generate("unknown_vuln_type", "https://example.com")
        assert len(guide.steps) > 0

    def test_render_markdown(self):
        guide = self.gen.generate("ssrf", "https://example.com/fetch")
        md = self.gen.generate_markdown(guide)
        assert "# Manual Verification" in md
        assert "SSRF" in md.upper()


class TestConfidenceScorer:
    """Test confidence scoring."""

    def test_scorer_creation(self):
        scorer = ConfidenceScorer()
        assert scorer is not None


class TestFPDetectorBrainDownIntegration:
    """Test FPDetector correctly uses intelligence_engine for brain-down state."""

    def test_init_accepts_intelligence_engine(self):
        from src.fp_engine.fp_detector import FPDetector
        detector = FPDetector(brain_engine=None, intelligence_engine=None)
        assert detector.intelligence_engine is None

    def test_brain_down_check_uses_intelligence_engine(self):
        """When intelligence_engine._brain_down is True, Layer 3 should skip."""
        from types import SimpleNamespace
        from src.fp_engine.fp_detector import FPDetector
        import asyncio

        mock_intel = SimpleNamespace(_brain_down=True)
        mock_brain = SimpleNamespace()  # Dummy brain without _brain_down

        detector = FPDetector(brain_engine=mock_brain, intelligence_engine=mock_intel)

        finding = SimpleNamespace(
            severity="high", vulnerability_type="sql_injection",
            target="https://example.com", endpoint="https://example.com/test",
            http_request="", payload="", evidence="", title="Test",
            tool_name="sqlmap",
        )

        result = asyncio.new_event_loop().run_until_complete(
            detector._layer3_context_analysis(finding)
        )
        assert result[0] == "skipped_brain_down"
        assert result[1] == 0.0


class TestFPDetectorResponseIntel:
    """Test FPDetector response_intel integration (V13-T0-1)."""

    def test_init_accepts_response_intel(self):
        from src.fp_engine.fp_detector import FPDetector
        ri = {"technologies": {"nginx": "1.21"}, "interesting_headers": []}
        detector = FPDetector(response_intel=ri)
        assert detector.response_intel == ri

    def test_init_defaults_empty_response_intel(self):
        from src.fp_engine.fp_detector import FPDetector
        detector = FPDetector()
        assert detector.response_intel == {}

    def test_layer5_waf_via_response_intel(self):
        """ResponseIntel WAF header signal should trigger WAF detection."""
        from src.fp_engine.fp_detector import FPDetector
        from types import SimpleNamespace

        ri = {"interesting_headers": [
            {"header": "X-CDN", "value": "Cloudflare", "signal": "WAF/CDN detected", "url": "https://example.com"},
        ]}
        detector = FPDetector(response_intel=ri)
        finding = SimpleNamespace(http_response="HTTP/1.1 200 OK\r\n\r\nOK")
        waf_detected, waf_name, delta = detector._layer5_waf_detection(finding)
        assert waf_detected is True
        assert "ResponseIntel" in waf_name
        assert delta == -10.0

    def test_layer5_no_waf_without_response_intel(self):
        """Without ResponseIntel WAF signals, normal detection should proceed."""
        from src.fp_engine.fp_detector import FPDetector
        from types import SimpleNamespace

        detector = FPDetector()
        finding = SimpleNamespace(http_response="HTTP/1.1 200 OK\r\n\r\nOK")
        waf_detected, waf_name, delta = detector._layer5_waf_detection(finding)
        assert waf_detected is False
        assert delta == 5.0
