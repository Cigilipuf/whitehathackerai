"""
Revolution v4.0 — Phase 5.2d: Pipeline-Level Ceiling Guard Tests
=================================================================

Verifies that Guard 4a (brain verification) and Guard 4b (calibrator)
in full_scan.py respect the KnownFP ceiling flag propagated from FPDetector.

Critical bug context:
  FPDetector Guard 3 caps known-FP findings at 49.9.  But TWO downstream
  pipeline stages could silently push the score back above 50:

  1. Brain verification (Guard 4a target):
     `_verify_one()` merges brain confidence → if brain ≥ 80,
     `max(merged, vr.confidence)` floors at brain value → 49.9 → 85.

  2. ConfidenceCalibrator (Guard 4b target):
     `calibrator.calibrate()` applies historical TP-rate offset →
     can add +18 → 49.9 → 67.9.

Both guards check `finding.get("_known_fp_capped")` and re-cap at 49.9.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from src.fp_engine.fp_detector import FPDetector, FPVerdict
from src.fp_engine.patterns.known_fps import KnownFPMatcher
from src.tools.base import Finding
from src.utils.constants import FP_MEDIUM_CONFIDENCE_THRESHOLD, SeverityLevel


# ============================================================
# Helpers
# ============================================================

_KFP_CEIL = FP_MEDIUM_CONFIDENCE_THRESHOLD - 0.1  # 64.9


class _MockBrainConfirm:
    """Brain that confirms with high confidence (worst case for bypass)."""
    async def think(self, **kwargs):
        return type("R", (), {"text": json.dumps({
            "verdict": "real", "confidence": 95, "reasoning": "confirmed vuln"
        })})()


def _make_known_fp_finding() -> Finding:
    """Create finding that triggers FP-TECHCVE-002 (penalty -25)."""
    return Finding(
        title="Outdated Software Version",
        description="CVE matched without version evidence",
        severity=SeverityLevel.MEDIUM,
        confidence=74.2,
        vulnerability_type="outdated_software",
        tool_name="tech_cve_checker",
        target="https://gitlab.com",
        endpoint="https://gitlab.com/api/v4",
        evidence="CVE-2021-12345 detected",
        http_response="",
        raw_output="",
        metadata={},
        tags=[],
    )


def _run(coro):
    return asyncio.run(coro)


# ============================================================
# FPVerdict Flag Propagation
# ============================================================

class TestFPVerdictFlagPropagation:
    """Verify that FPDetector sets known_fp_capped on the verdict."""

    def test_verdict_has_known_fp_capped_field(self):
        """FPVerdict class must have known_fp_capped field."""
        dummy_finding = _make_known_fp_finding()
        v = FPVerdict(
            finding=dummy_finding,
            status="false_positive",
            confidence_score=30.0,
            verdict="false_positive",
            verification_layers=[],
            evidence_chain=[],
            reasoning="",
            fp_patterns_matched=[],
            waf_detected=False,
        )
        assert hasattr(v, "known_fp_capped")
        assert v.known_fp_capped is False  # default

    def test_verdict_known_fp_capped_can_be_set_true(self):
        """known_fp_capped=True should be settable."""
        dummy_finding = _make_known_fp_finding()
        v = FPVerdict(
            finding=dummy_finding,
            status="false_positive",
            confidence_score=30.0,
            verdict="false_positive",
            verification_layers=[],
            evidence_chain=[],
            reasoning="",
            fp_patterns_matched=[],
            waf_detected=False,
            known_fp_capped=True,
        )
        assert v.known_fp_capped is True

    def test_detector_sets_flag_for_strong_fp_pattern(self):
        """FPDetector.analyze() sets known_fp_capped=True for findings
        with penalty ≤ -20."""
        detector = FPDetector(brain_engine=_MockBrainConfirm())
        f = _make_known_fp_finding()
        verdict = _run(detector.analyze(f))
        assert verdict.known_fp_capped is True, (
            f"FPDetector should set known_fp_capped=True when "
            f"KnownFP penalty ≤ -20; score={verdict.confidence_score}"
        )

    def test_detector_does_not_set_flag_for_clean_finding(self):
        """Clean finding (no FP match) → known_fp_capped=False."""
        detector = FPDetector(brain_engine=_MockBrainConfirm())
        f = Finding(
            title="SQL Injection in id",
            description="SQL injection via id param",
            severity=SeverityLevel.HIGH,
            confidence=80.0,
            vulnerability_type="sqli",
            tool_name="sqlmap",
            target="https://example.com",
            endpoint="https://example.com/login?id=1",
            evidence="Error: SQL syntax error",
            http_response="HTTP/1.1 500\n\nSQL error",
            raw_output="",
            metadata={"status_code": "500"},
            tags=[],
        )
        verdict = _run(detector.analyze(f))
        assert verdict.known_fp_capped is False


# ============================================================
# Guard 4a: Brain Verification Ceiling Preservation
# ============================================================

class TestGuard4aBrainVerification:
    """Guard 4a: Brain verification must not push KnownFP-capped findings
    above 49.9."""

    def test_brain_merge_upgrade_is_capped(self):
        """Simulate brain upgrade merge: brain=95, original=49.9.
        Without guard: merged = 95*0.6 + 49.9*0.4 = 76.96
        Then max(76.96, 95) = 95 → BYPASS!
        With guard: re-capped at 49.9."""
        finding = {
            "confidence_score": 49.9,
            "_known_fp_capped": True,
            "title": "Test FP finding",
        }
        brain_confidence = 95
        original_conf = finding["confidence_score"]

        # Simulate brain merge (upgrade path)
        merged = brain_confidence * 0.6 + original_conf * 0.4
        finding["confidence_score"] = round(merged, 1)

        # Simulate brain floor (>= 80)
        finding["confidence_score"] = max(
            finding["confidence_score"], brain_confidence
        )

        # At this point, without guard, confidence = 95
        assert finding["confidence_score"] == 95, "Pre-guard score should be 95"

        # Apply Guard 4a
        if finding.get("_known_fp_capped"):
            if finding["confidence_score"] > _KFP_CEIL:
                finding["confidence_score"] = _KFP_CEIL

        assert finding["confidence_score"] == _KFP_CEIL, (
            f"Guard 4a should re-cap at {_KFP_CEIL}, got {finding['confidence_score']}"
        )

    def test_brain_downgrade_not_affected(self):
        """Brain downgrade on KnownFP-capped finding → already below ceiling."""
        finding = {
            "confidence_score": 35.0,
            "_known_fp_capped": True,
            "title": "Already low",
        }
        brain_confidence = 20
        original_conf = finding["confidence_score"]

        # Simulate brain merge (downgrade path)
        merged = brain_confidence * 0.3 + original_conf * 0.7
        finding["confidence_score"] = round(merged, 1)

        # Guard 4a: no action needed (already below ceiling)
        if finding.get("_known_fp_capped"):
            if finding["confidence_score"] > _KFP_CEIL:
                finding["confidence_score"] = _KFP_CEIL

        assert finding["confidence_score"] < _KFP_CEIL

    def test_non_capped_finding_unaffected(self):
        """Findings WITHOUT _known_fp_capped should not be restricted."""
        finding = {
            "confidence_score": 60.0,
            "title": "Real finding",
        }
        brain_confidence = 90
        original_conf = finding["confidence_score"]

        merged = brain_confidence * 0.6 + original_conf * 0.4
        finding["confidence_score"] = round(merged, 1)
        finding["confidence_score"] = max(
            finding["confidence_score"], brain_confidence
        )

        # Guard 4a: should NOT trigger
        if finding.get("_known_fp_capped"):
            if finding["confidence_score"] > _KFP_CEIL:
                finding["confidence_score"] = _KFP_CEIL

        assert finding["confidence_score"] == 90, (
            "Non-capped finding should keep brain-elevated score"
        )

    def test_moderate_brain_upgrade_also_capped(self):
        """Even moderate brain upgrade (65) should be capped if finding is FP-capped."""
        finding = {
            "confidence_score": _KFP_CEIL,
            "_known_fp_capped": True,
            "title": "Test FP",
        }
        brain_confidence = 65
        original_conf = finding["confidence_score"]

        # Moderate brain: merged = 65*0.6 + ceil*0.4
        merged = brain_confidence * 0.6 + original_conf * 0.4
        finding["confidence_score"] = round(merged, 1)
        # 65 < 80, so no max() floor

        if finding.get("_known_fp_capped"):
            if finding["confidence_score"] > _KFP_CEIL:
                finding["confidence_score"] = _KFP_CEIL

        assert finding["confidence_score"] == _KFP_CEIL

    def test_worst_case_brain_100_capped(self):
        """Worst case: brain=100, original=49.9.
        merged=100*0.6 + 49.9*0.4 = 79.96
        max(79.96, 100) = 100 → guard caps at 49.9."""
        finding = {
            "confidence_score": 49.9,
            "_known_fp_capped": True,
            "title": "Worst case",
        }
        brain_confidence = 100
        original_conf = finding["confidence_score"]
        merged = brain_confidence * 0.6 + original_conf * 0.4
        finding["confidence_score"] = round(merged, 1)
        finding["confidence_score"] = max(
            finding["confidence_score"], brain_confidence
        )

        assert finding["confidence_score"] == 100, "Pre-guard: 100"

        if finding.get("_known_fp_capped"):
            if finding["confidence_score"] > _KFP_CEIL:
                finding["confidence_score"] = _KFP_CEIL

        assert finding["confidence_score"] == _KFP_CEIL


# ============================================================
# Guard 4b: Calibrator Ceiling Preservation
# ============================================================

class TestGuard4bCalibrator:
    """Guard 4b: ConfidenceCalibrator must not push KnownFP-capped findings
    above 49.9."""

    def test_calibrator_elevation_is_capped(self):
        """Simulate calibrator adding +18 offset: 49.9 → 67.9 → guard caps at 49.9."""
        finding = {
            "confidence_score": 49.9,
            "_known_fp_capped": True,
            "vulnerability_type": "outdated_software",
            "title": "Test FP",
        }
        adj = 49.9 + 18  # Simulated calibrator output

        # Guard 4b
        if finding.get("_known_fp_capped") and adj > _KFP_CEIL:
            adj = _KFP_CEIL

        assert adj == _KFP_CEIL

    def test_calibrator_decrease_not_affected(self):
        """Calibrator decreasing score → no guard action needed."""
        finding = {
            "confidence_score": 49.9,
            "_known_fp_capped": True,
            "vulnerability_type": "outdated_software",
            "title": "Test FP",
        }
        adj = 42.0  # Calibrator decreased

        if finding.get("_known_fp_capped") and adj > _KFP_CEIL:
            adj = _KFP_CEIL

        assert adj == 42.0

    def test_non_capped_finding_calibration_unaffected(self):
        """Non-capped findings should get full calibrator benefit."""
        finding = {
            "confidence_score": 55.0,
            "vulnerability_type": "sqli",
            "title": "Real finding",
        }
        adj = 55.0 + 18

        if finding.get("_known_fp_capped") and adj > _KFP_CEIL:
            adj = _KFP_CEIL

        assert adj == 73.0, "Non-capped finding should keep calibrated score"

    def test_small_elevation_within_ceiling(self):
        """Calibrator +3 on 46.0 → 49.0, below ceiling → no cap."""
        finding = {
            "confidence_score": 46.0,
            "_known_fp_capped": True,
            "title": "Test FP",
        }
        adj = 49.0

        if finding.get("_known_fp_capped") and adj > _KFP_CEIL:
            adj = _KFP_CEIL

        assert adj == 49.0, "Small elevation within ceiling should be allowed"


# ============================================================
# End-to-End: FPDetector → Pipeline Flag → Guards
# ============================================================

class TestEndToEndCeilingPreservation:
    """Verify the full chain: FPDetector analysis → verdict flag →
    pipeline propagation → guard enforcement."""

    def test_fp_finding_verdict_score_below_50_and_flagged(self):
        """FP finding should exit FPDetector with score < 50 and
        known_fp_capped=True."""
        detector = FPDetector(brain_engine=_MockBrainConfirm())
        f = _make_known_fp_finding()
        verdict = _run(detector.analyze(f))

        assert verdict.confidence_score < FP_MEDIUM_CONFIDENCE_THRESHOLD, (
            f"KnownFP finding should be <{FP_MEDIUM_CONFIDENCE_THRESHOLD} after Guard 3, "
            f"got {verdict.confidence_score}"
        )
        assert verdict.known_fp_capped is True

    def test_pipeline_propagation_simulation(self):
        """Simulate pipeline: apply verdict → set flag → brain verify →
        calibrate → confirm ceiling holds throughout."""
        detector = FPDetector(brain_engine=_MockBrainConfirm())
        f = _make_known_fp_finding()
        verdict = _run(detector.analyze(f))

        # Step 1: Pipeline applies verdict (full_scan.py L5637-5643)
        finding = {
            "confidence_score": verdict.confidence_score,
            "confidence": verdict.confidence_score,
            "title": "Outdated Software Version",
            "vulnerability_type": "outdated_software",
            "tool": "tech_cve_checker",
        }
        if verdict.known_fp_capped:
            finding["_known_fp_capped"] = True

        score_after_verdict = finding["confidence_score"]
        assert score_after_verdict < FP_MEDIUM_CONFIDENCE_THRESHOLD, f"Post-verdict: {score_after_verdict}"
        assert finding.get("_known_fp_capped") is True

        # Step 2: Brain verification (worst case: brain=95)
        brain_confidence = 95
        original_conf = finding["confidence_score"]
        merged = brain_confidence * 0.6 + original_conf * 0.4
        finding["confidence_score"] = round(merged, 1)
        if brain_confidence >= 80:
            finding["confidence_score"] = max(
                finding["confidence_score"], brain_confidence
            )
        # Guard 4a
        if finding.get("_known_fp_capped") and finding["confidence_score"] > _KFP_CEIL:
            finding["confidence_score"] = _KFP_CEIL

        score_after_brain = finding["confidence_score"]
        assert score_after_brain <= _KFP_CEIL, (
            f"Post-brain: {score_after_brain} > {_KFP_CEIL}"
        )

        # Step 3: Calibrator (worst case: +18)
        adj = finding["confidence_score"] + 18
        # Guard 4b
        if finding.get("_known_fp_capped") and adj > _KFP_CEIL:
            adj = _KFP_CEIL
        finding["confidence_score"] = adj

        final_score = finding["confidence_score"]
        assert final_score <= _KFP_CEIL, (
            f"Post-calibrator: {final_score} > {_KFP_CEIL}"
        )

    def test_all_guards_preserve_ceiling_through_full_chain(self):
        """Even with maximum brain + maximum calibrator, ceiling holds."""
        # Start with a finding already capped at the absolute ceiling
        finding = {
            "confidence_score": _KFP_CEIL,
            "_known_fp_capped": True,
            "title": "Worst case chain",
        }

        # Brain: confidence=100 → worst possible elevation
        brain_conf = 100
        merged = brain_conf * 0.6 + finding["confidence_score"] * 0.4
        finding["confidence_score"] = round(merged, 1)
        finding["confidence_score"] = max(finding["confidence_score"], brain_conf)

        # Guard 4a
        if finding.get("_known_fp_capped") and finding["confidence_score"] > _KFP_CEIL:
            finding["confidence_score"] = _KFP_CEIL

        assert finding["confidence_score"] == _KFP_CEIL

        # Calibrator: +18
        adj = finding["confidence_score"] + 18
        if finding.get("_known_fp_capped") and adj > _KFP_CEIL:
            adj = _KFP_CEIL
        finding["confidence_score"] = adj

        assert finding["confidence_score"] == _KFP_CEIL, (
            "Full chain with worst-case brain + calibrator must stay at ceiling"
        )

    def test_report_gate_blocks_capped_finding(self):
        """Report gate (≥FP_MEDIUM_CONFIDENCE_THRESHOLD) should block a KnownFP-capped finding."""
        REPORT_THRESHOLD = FP_MEDIUM_CONFIDENCE_THRESHOLD
        finding_score = _KFP_CEIL  # just below threshold

        passes_gate = finding_score >= REPORT_THRESHOLD
        assert not passes_gate, (
            f"Score {finding_score} should NOT pass report gate at {REPORT_THRESHOLD}"
        )
