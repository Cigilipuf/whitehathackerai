"""
Phase 1 regression tests — Evidence Quality Gate + OOB Callback Filtering.

Tests cover:
  - EvidenceQualityGate evaluate() logic per severity tier
  - Interactsh infrastructure IP detection
  - Interactsh callback quality classification
  - Interactsh interactions_to_findings() quality-based confidence
  - ConfidenceScorer tiered OOB factors
  - FPDetector OOB factor routing
"""

from __future__ import annotations

import pytest


# ══════════════════════════════════════════════════════════════
# 1. EvidenceQualityGate
# ══════════════════════════════════════════════════════════════

class TestEvidenceQualityGate:
    """Tests for src/fp_engine/evidence_quality_gate.py"""

    def _make_finding(self, **overrides) -> dict:
        base = {
            "severity": "high",
            "evidence": "",
            "http_response": "",
            "payload": "",
            "metadata": {},
            "tags": [],
        }
        base.update(overrides)
        return base

    # ── CRITICAL/HIGH tier ──

    def test_critical_with_payload_reflection_passes(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(
            severity="critical",
            payload="<script>alert(1)</script>",
            evidence="reflected: <script>alert(1)</script> in body",
        )
        v = evaluate(f)
        assert v.passed is True
        assert "payload_reflected" in v.signals_found

    def test_critical_with_error_leakage_passes(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(
            severity="critical",
            evidence="You have an error in your SQL syntax near 'admin'",
        )
        v = evaluate(f)
        assert v.passed is True
        assert "error_leakage" in v.signals_found

    def test_high_with_oob_passes(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(
            severity="high",
            tags=["interactsh", "oob"],
            metadata={"oob_domain": "abc.oast.fun"},
        )
        v = evaluate(f)
        assert v.passed is True
        assert "oob_callback" in v.signals_found

    def test_high_no_evidence_capped(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(severity="high")
        v = evaluate(f)
        assert v.passed is False
        assert v.confidence_cap == 35.0

    def test_high_only_timing_capped_at_45(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(
            severity="high",
            metadata={"time_based": True},
        )
        v = evaluate(f)
        assert v.passed is False
        assert v.confidence_cap == 45.0
        assert "timing_anomaly" in v.signals_found

    def test_critical_with_data_extraction_passes(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(
            severity="critical",
            metadata={"data_extracted": True},
        )
        v = evaluate(f)
        assert v.passed is True
        assert "data_extracted" in v.signals_found

    # ── MEDIUM tier ──

    def test_medium_with_body_diff_passes(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(
            severity="medium",
            metadata={"body_diff": True},
        )
        v = evaluate(f)
        assert v.passed is True

    def test_medium_with_meaningful_text_passes(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(
            severity="medium",
            evidence="Server responded with detailed stack trace showing internal path /var/www/app",
        )
        v = evaluate(f)
        assert v.passed is True
        assert "evidence_text" in v.signals_found

    def test_medium_no_evidence_capped(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(severity="medium")
        v = evaluate(f)
        assert v.passed is False
        assert v.confidence_cap == 35.0

    # ── LOW/INFO tier ──

    def test_low_always_passes(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(severity="low")
        v = evaluate(f)
        assert v.passed is True

    def test_info_always_passes(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        f = self._make_finding(severity="info")
        v = evaluate(f)
        assert v.passed is True

    # ── Batch ──

    def test_evaluate_batch(self):
        from src.fp_engine.evidence_quality_gate import evaluate_batch
        findings = [
            self._make_finding(severity="low"),
            self._make_finding(severity="high"),
        ]
        results = evaluate_batch(findings)
        assert len(results) == 2
        assert results[0][1].passed is True   # LOW passes
        assert results[1][1].passed is False   # HIGH no evidence


# ══════════════════════════════════════════════════════════════
# 2. Interactsh Infrastructure IP Detection
# ══════════════════════════════════════════════════════════════

class TestInfrastructureIPDetection:

    def test_cloudflare_dns_is_infra(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("1.1.1.1") is True

    def test_google_dns_is_infra(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("8.8.8.8") is True

    def test_quad9_is_infra(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("9.9.9.9") is True

    def test_random_ip_not_infra(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("192.168.1.100") is False

    def test_private_ip_not_infra(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("10.0.0.1") is False

    def test_ip_with_port_stripped(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("1.1.1.1:53") is True

    def test_invalid_address_returns_false(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("not-an-ip") is False

    def test_cloudflare_cdn_range(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("104.16.0.1") is True


# ══════════════════════════════════════════════════════════════
# 3. Callback Quality Classification
# ══════════════════════════════════════════════════════════════

class TestCallbackQualityClassification:

    def test_http_from_normal_ip_is_high(self):
        from src.tools.scanners.interactsh_wrapper import classify_callback_quality
        assert classify_callback_quality("HTTP", "203.0.113.50") == "high"

    def test_http_from_cloudflare_is_low(self):
        from src.tools.scanners.interactsh_wrapper import classify_callback_quality
        assert classify_callback_quality("HTTP", "104.16.0.1") == "low"

    def test_dns_from_normal_ip_is_medium(self):
        from src.tools.scanners.interactsh_wrapper import classify_callback_quality
        assert classify_callback_quality("DNS", "203.0.113.50") == "medium"

    def test_dns_from_google_dns_is_infrastructure(self):
        from src.tools.scanners.interactsh_wrapper import classify_callback_quality
        assert classify_callback_quality("DNS", "8.8.8.8") == "infrastructure"

    def test_smtp_from_normal_ip_is_high(self):
        from src.tools.scanners.interactsh_wrapper import classify_callback_quality
        assert classify_callback_quality("SMTP", "198.51.100.10") == "high"


# ══════════════════════════════════════════════════════════════
# 4. interactions_to_findings Quality-Based Confidence
# ══════════════════════════════════════════════════════════════

class TestInteractshFindingsConfidence:

    def _make_wrapper(self):
        """Create an InteractshWrapper with mocked interactions."""
        from src.tools.scanners.interactsh_wrapper import InteractshWrapper
        w = InteractshWrapper()
        w._oob_domain = "test.oast.fun"
        return w

    def test_http_non_infra_gets_high_confidence(self):
        w = self._make_wrapper()
        w._interactions = [{
            "protocol": "HTTP",
            "remote-address": "203.0.113.50",
            "unique-id": "abc",
            "_callback_quality": "high",
            "_is_infrastructure": False,
        }]
        findings = w.interactions_to_findings("https://target.com")
        assert len(findings) == 1
        assert findings[0].confidence == 80.0

    def test_dns_cloudflare_skipped(self):
        w = self._make_wrapper()
        w._interactions = [{
            "protocol": "DNS",
            "remote-address": "1.1.1.1",
            "unique-id": "def",
            "_callback_quality": "infrastructure",
            "_is_infrastructure": True,
        }]
        findings = w.interactions_to_findings("https://target.com")
        assert len(findings) == 0  # Infrastructure callbacks are skipped

    def test_dns_non_infra_gets_medium_confidence(self):
        w = self._make_wrapper()
        w._interactions = [{
            "protocol": "DNS",
            "remote-address": "203.0.113.50",
            "unique-id": "ghi",
            "_callback_quality": "medium",
            "_is_infrastructure": False,
        }]
        findings = w.interactions_to_findings("https://target.com")
        assert len(findings) == 1
        assert findings[0].confidence == 55.0

    def test_http_from_cdn_gets_low_confidence(self):
        w = self._make_wrapper()
        w._interactions = [{
            "protocol": "HTTP",
            "remote-address": "104.16.0.1",
            "unique-id": "jkl",
            "_callback_quality": "low",
            "_is_infrastructure": True,
        }]
        findings = w.interactions_to_findings("https://target.com")
        assert len(findings) == 1
        assert findings[0].confidence == 30.0

    def test_metadata_includes_quality(self):
        w = self._make_wrapper()
        w._interactions = [{
            "protocol": "HTTP",
            "remote-address": "203.0.113.50",
            "unique-id": "mno",
            "_callback_quality": "high",
            "_is_infrastructure": False,
        }]
        findings = w.interactions_to_findings("https://target.com")
        assert findings[0].metadata["callback_quality"] == "high"
        assert findings[0].metadata["is_infrastructure"] is False


# ══════════════════════════════════════════════════════════════
# 5. ConfidenceScorer Tiered OOB Factors
# ══════════════════════════════════════════════════════════════

class TestConfidenceScorerOOBTiers:

    def test_oob_high_gives_plus_28(self):
        from src.fp_engine.scoring.confidence_scorer import ConfidenceScorer
        cs = ConfidenceScorer()
        result = cs.calculate(factors=["oob_callback_high"], base_score=50.0)
        assert result.final_score == pytest.approx(78.0, abs=1.0)

    def test_oob_medium_gives_plus_15(self):
        from src.fp_engine.scoring.confidence_scorer import ConfidenceScorer
        cs = ConfidenceScorer()
        result = cs.calculate(factors=["oob_callback_medium"], base_score=50.0)
        assert result.final_score == pytest.approx(65.0, abs=1.0)

    def test_oob_low_gives_plus_5(self):
        from src.fp_engine.scoring.confidence_scorer import ConfidenceScorer
        cs = ConfidenceScorer()
        result = cs.calculate(factors=["oob_callback_low"], base_score=50.0)
        assert result.final_score == pytest.approx(55.0, abs=1.0)

    def test_oob_infrastructure_gives_zero(self):
        from src.fp_engine.scoring.confidence_scorer import ConfidenceScorer
        cs = ConfidenceScorer()
        result = cs.calculate(factors=["oob_callback_infrastructure"], base_score=50.0)
        assert result.final_score == pytest.approx(50.0, abs=1.0)

    def test_legacy_oob_still_works(self):
        from src.fp_engine.scoring.confidence_scorer import ConfidenceScorer
        cs = ConfidenceScorer()
        result = cs.calculate(factors=["oob_callback_received"], base_score=50.0)
        assert result.final_score == pytest.approx(78.0, abs=1.0)

    def test_context_method_uses_quality(self):
        from src.fp_engine.scoring.confidence_scorer import ConfidenceScorer
        cs = ConfidenceScorer()
        result = cs.calculate_from_finding_context(
            oob_callback=True,
            oob_callback_quality="medium",
        )
        # Should use oob_callback_medium (+15) not oob_callback_received (+28)
        factors_used = [f["name"] for f in result.factors]
        assert "oob_callback_medium" in factors_used
        assert "oob_callback_received" not in factors_used

    def test_context_method_legacy_when_no_quality(self):
        from src.fp_engine.scoring.confidence_scorer import ConfidenceScorer
        cs = ConfidenceScorer()
        result = cs.calculate_from_finding_context(
            oob_callback=True,
            oob_callback_quality="",
        )
        factors_used = [f["name"] for f in result.factors]
        assert "oob_callback_received" in factors_used


# ══════════════════════════════════════════════════════════════
# 6. Pipeline integration — evidence gate replaces inline check
# ══════════════════════════════════════════════════════════════

class TestPipelineEvidenceGateIntegration:

    def test_evidence_gate_import_succeeds(self):
        """The module the pipeline imports must exist and be importable."""
        from src.fp_engine.evidence_quality_gate import evaluate, EvidenceVerdict
        assert callable(evaluate)
        assert EvidenceVerdict is not None

    def test_high_finding_without_evidence_gets_capped(self):
        """Simulates what _analyze_one does with the new gate."""
        from src.fp_engine.evidence_quality_gate import evaluate
        finding = {
            "severity": "high",
            "evidence": "",
            "http_response": "",
            "payload": "",
            "metadata": {},
            "tags": [],
            "confidence_score": 75.0,
        }
        v = evaluate(finding)
        assert v.passed is False
        cap = v.confidence_cap or 35.0
        finding["confidence_score"] = min(finding["confidence_score"], cap)
        assert finding["confidence_score"] <= 35.0
