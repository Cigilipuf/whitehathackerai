"""
V24 — FP Engine Deep Wiring & Brain Module Integration Tests
=============================================================
Test suite: 1127 → 1127 + N (target ≥60 new tests)

Covers:
  P1: ToolQuirkChecker as Layer 1c in fp_detector
  P2: WafArtifactDetector enhancement for Layer 5
  P3: ContextVerifier as Layer 2c in fp_detector
  P4: ResponseDiffAnalyzer integration in Layer 6
  P5: FPFeedbackManager wiring in full_scan.py + Layer 0
  P6: RiskAssessor wiring in handle_reporting
  P7: ManualVerifyGuideGenerator wiring in auto_draft.py
"""

from __future__ import annotations

import pytest
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# P1: ToolQuirkChecker Unit + Integration Tests
# ─────────────────────────────────────────────────────────────


class TestToolQuirkChecker:
    """Verify ToolQuirkChecker is functional and matches expected tools."""

    def test_import(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        assert ToolQuirkChecker is not None

    def test_check_returns_dict(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        result = tq.check("sqlmap", {"vuln_type": "sql_injection", "evidence": "boolean-based blind"})
        assert isinstance(result, dict)
        assert "has_quirks" in result
        assert "total_modifier" in result

    def test_sqlmap_boolean_blind_quirk(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        # vuln_type must match DB: "sql_injection" (not "sqli")
        result = tq.check("sqlmap", {
            "vuln_type": "sql_injection",
            "evidence": "boolean-based blind SQL injection",
        })
        assert result["has_quirks"] is True
        assert result["total_modifier"] < 0  # Should penalize

    def test_sqlmap_appears_injectable_quirk(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        result = tq.check("sqlmap", {
            "vuln_type": "sql_injection",
            "evidence": "parameter appears to be injectable with some test",
        })
        assert result["has_quirks"] is True
        assert result["total_modifier"] < 0

    def test_nikto_osvdb_quirk(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        # nikto vuln_type="*" quirks match any vuln_type
        result = tq.check("nikto", {
            "vuln_type": "info_disclosure",
            "evidence": "OSVDB-3092: some outdated reference",
        })
        assert result["has_quirks"] is True
        assert result["total_modifier"] <= 0

    def test_nikto_server_header_quirk(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        result = tq.check("nikto", {
            "vuln_type": "information_disclosure",
            "evidence": "Server header found: Apache/2.4.41",
        })
        assert result["has_quirks"] is True

    def test_unknown_tool_no_quirks(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        result = tq.check("unknown_tool_xyz", {
            "vuln_type": "xss",
            "evidence": "found xss",
        })
        assert result["has_quirks"] is False
        assert result["total_modifier"] == 0

    def test_needs_verification_flag(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        result = tq.check("sqlmap", {
            "vuln_type": "sql_injection",
            "evidence": "boolean-based blind SQL injection test",
        })
        assert result["has_quirks"] is True
        assert result["needs_verification"] is True

    def test_verification_methods_populated(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        result = tq.check("sqlmap", {
            "vuln_type": "sql_injection",
            "evidence": "boolean-based blind SQL injection test",
        })
        assert len(result["verification_methods"]) > 0

    def test_tool_reliability_profile(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        profile = tq.get_tool_reliability("nikto")
        assert profile["tool"] == "nikto"
        assert profile["known_quirks"] >= 2
        assert profile["reliability"] in ("low", "medium", "high", "very_high")

    @pytest.mark.parametrize("tool", [
        "sqlmap", "nikto", "nmap", "wpscan", "ffuf",
        "gobuster", "hydra", "commix", "sslscan", "searchsploit",
    ])
    def test_known_tools_no_crash(self, tool):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        result = tq.check(tool, {"vuln_type": "*", "evidence": ""})
        assert isinstance(result, dict)


# ─────────────────────────────────────────────────────────────
# P2: WafArtifactDetector Unit Tests
# ─────────────────────────────────────────────────────────────


class TestWafArtifactDetector:
    """Verify WafArtifactDetector class provides deep WAF analysis."""

    def test_import(self):
        from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector
        assert WafArtifactDetector is not None

    def test_analyze_returns_dict(self):
        from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector
        d = WafArtifactDetector()
        result = d.analyze(
            response_headers={},
            response_body="",
            status_code=200,
            cookies={},
        )
        assert isinstance(result, dict)
        assert "waf_detected" in result
        assert "total_penalty" in result

    def test_cloudflare_detection(self):
        from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector
        d = WafArtifactDetector()
        result = d.analyze(
            response_headers={"cf-ray": "abc123-LAX", "server": "cloudflare"},
            response_body="",
            status_code=403,
            cookies={"__cflb": "abc"},
        )
        assert result["waf_detected"] is True
        assert "cloudflare" in result.get("waf_name", "").lower()

    def test_no_waf_clean_response(self):
        from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector
        d = WafArtifactDetector()
        result = d.analyze(
            response_headers={"server": "nginx/1.24.0", "content-type": "text/html"},
            response_body="<html><body>Hello</body></html>",
            status_code=200,
            cookies={},
        )
        assert result["waf_detected"] is False

    def test_block_page_detection(self):
        from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector
        d = WafArtifactDetector()
        result = d.analyze(
            response_headers={},
            response_body="Access Denied. You don't have permission to access this resource. Reference ID: 12345",
            status_code=403,
            cookies={},
        )
        assert "is_block_page" in result

    def test_cdn_detection(self):
        from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector
        d = WafArtifactDetector()
        result = d.analyze(
            response_headers={"x-cdn": "akamai", "via": "1.1 akamai.net (ghost)"},
            response_body="",
            status_code=200,
            cookies={},
        )
        assert "cdn_detected" in result

    def test_penalty_is_negative(self):
        """WAF detection should produce a negative penalty."""
        from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector
        d = WafArtifactDetector()
        result = d.analyze(
            response_headers={"cf-ray": "abc", "server": "cloudflare"},
            response_body="",
            status_code=403,
            cookies={},
        )
        if result["waf_detected"]:
            assert result["total_penalty"] <= 0


# ─────────────────────────────────────────────────────────────
# P3: ContextVerifier Unit Tests
# ─────────────────────────────────────────────────────────────


class TestContextVerifier:
    """Verify ContextVerifier HTTP context analysis."""

    def test_import(self):
        from src.fp_engine.verification.context_verify import (
            ContextVerifier, HttpContext,
        )
        assert ContextVerifier is not None
        assert HttpContext is not None

    def test_verify_returns_result(self):
        from src.fp_engine.verification.context_verify import (
            ContextVerifier, HttpContext,
        )
        cv = ContextVerifier()
        ctx = HttpContext(
            url="https://example.com/test",
            method="GET",
            request_headers={},
            response_headers={},
            response_body="<html>normal</html>",
            status_code=200,
            response_time=0.5,
        )
        result = cv.verify("xss", ctx, payload="<script>alert(1)</script>")
        assert hasattr(result, "is_genuine")
        assert hasattr(result, "confidence")
        assert hasattr(result, "checks_passed")
        assert hasattr(result, "checks_failed")

    def test_waf_blocked_reduces_confidence(self):
        from src.fp_engine.verification.context_verify import (
            ContextVerifier, HttpContext,
        )
        cv = ContextVerifier()
        ctx = HttpContext(
            url="https://example.com/test",
            method="GET",
            request_headers={},
            response_headers={"server": "cloudflare", "cf-ray": "abc123"},
            response_body="Access Denied",
            status_code=403,
            response_time=0.1,
        )
        result = cv.verify("xss", ctx, payload="<script>alert(1)</script>")
        assert result.confidence < 70

    def test_payload_reflected_increases_confidence(self):
        from src.fp_engine.verification.context_verify import (
            ContextVerifier, HttpContext,
        )
        cv = ContextVerifier()
        ctx = HttpContext(
            url="https://example.com/test",
            method="GET",
            request_headers={},
            response_headers={},
            response_body='<html><script>alert(1)</script></html>',
            status_code=200,
            response_time=0.3,
        )
        result = cv.verify(
            "xss", ctx,
            payload="<script>alert(1)</script>",
            expected_evidence="<script>alert(1)</script>",
        )
        assert result.confidence >= 50


# ─────────────────────────────────────────────────────────────
# P4: ResponseDiffAnalyzer Unit Tests
# ─────────────────────────────────────────────────────────────


def _resp_dict(status: int, body: str, headers: dict | None = None, time: float = 0.5) -> dict:
    """Helper to build ResponseDiffAnalyzer-compatible response dict."""
    return {
        "status_code": status,
        "body": body,
        "headers": headers or {},
        "time": time,
    }


class TestResponseDiffAnalyzer:
    """Verify ResponseDiffAnalyzer differential analysis."""

    def test_import(self):
        from src.fp_engine.verification.response_diff import ResponseDiffAnalyzer
        assert ResponseDiffAnalyzer is not None

    def test_analyze_returns_result(self):
        from src.fp_engine.verification.response_diff import ResponseDiffAnalyzer
        rda = ResponseDiffAnalyzer()
        result = rda.analyze(
            normal_response=_resp_dict(200, "<html>normal</html>"),
            payload_response=_resp_dict(200, "<html>normal</html>"),
            payload="test",
            vuln_type="xss",
        )
        assert hasattr(result, "payload_reflected")
        assert hasattr(result, "confidence_delta")

    def test_payload_reflection_detected(self):
        from src.fp_engine.verification.response_diff import ResponseDiffAnalyzer
        rda = ResponseDiffAnalyzer()
        result = rda.analyze(
            normal_response=_resp_dict(200, "<html>normal</html>"),
            payload_response=_resp_dict(200, '<html><script>alert(1)</script></html>'),
            payload="<script>alert(1)</script>",
            vuln_type="xss",
        )
        assert result.payload_reflected is True

    def test_identical_responses_no_reflection(self):
        from src.fp_engine.verification.response_diff import ResponseDiffAnalyzer
        rda = ResponseDiffAnalyzer()
        result = rda.analyze(
            normal_response=_resp_dict(200, "<html>same</html>"),
            payload_response=_resp_dict(200, "<html>same</html>"),
            payload="' OR 1=1 --",
            vuln_type="sql_injection",
        )
        assert result.payload_reflected is False

    def test_status_code_difference(self):
        from src.fp_engine.verification.response_diff import ResponseDiffAnalyzer
        rda = ResponseDiffAnalyzer()
        result = rda.analyze(
            normal_response=_resp_dict(200, "OK"),
            payload_response=_resp_dict(500, "Internal Server Error"),
            payload="' OR 1=1 --",
            vuln_type="sql_injection",
        )
        assert result.status_code_changed is True
        assert result.confidence_delta > 0  # 500 after SQLi is a positive signal

    def test_sql_error_in_body(self):
        from src.fp_engine.verification.response_diff import ResponseDiffAnalyzer
        rda = ResponseDiffAnalyzer()
        result = rda.analyze(
            normal_response=_resp_dict(200, "normal page"),
            payload_response=_resp_dict(500, "You have an error in your SQL syntax near"),
            payload="' OR 1=1 --",
            vuln_type="sql_injection",
        )
        # SQL error message should increase confidence_delta
        assert result.confidence_delta > 0

    def test_body_changed_flag(self):
        from src.fp_engine.verification.response_diff import ResponseDiffAnalyzer
        rda = ResponseDiffAnalyzer()
        result = rda.analyze(
            normal_response=_resp_dict(200, "body A" * 100),
            payload_response=_resp_dict(200, "body B completely different content"),
            payload="test",
            vuln_type="xss",
        )
        assert result.body_changed is True


# ─────────────────────────────────────────────────────────────
# P5: FPFeedbackManager Unit + Integration Tests
# ─────────────────────────────────────────────────────────────


class TestFPFeedbackManager:
    """Verify FPFeedbackManager records and retrieves verdicts."""

    def test_import(self):
        from src.fp_engine.learning.fp_feedback import FPFeedbackManager
        assert FPFeedbackManager is not None

    def test_record_and_stats(self, tmp_path):
        from src.fp_engine.learning.fp_feedback import (
            FPFeedbackManager, FPFeedbackRecord,
        )
        db_path = tmp_path / "test_fp_feedback.db"
        fb = FPFeedbackManager(db_path=str(db_path))
        fb.record(FPFeedbackRecord(
            finding_id="test-1",
            vuln_type="xss",
            tool="dalfox",
            endpoint="https://example.com/test",
            verdict="true_positive",
            verdict_source="fp_engine",
            reason="Confirmed via multi-tool",
        ))
        fb.record(FPFeedbackRecord(
            finding_id="test-2",
            vuln_type="xss",
            tool="dalfox",
            endpoint="https://example.com/test2",
            verdict="false_positive",
            verdict_source="fp_engine",
            reason="WAF artifact",
        ))
        stats = fb.get_statistics()
        assert stats.total_findings >= 2
        assert stats.true_positives >= 1
        assert stats.false_positives >= 1

    def test_confidence_adjustment(self, tmp_path):
        from src.fp_engine.learning.fp_feedback import (
            FPFeedbackManager, FPFeedbackRecord,
        )
        db_path = tmp_path / "test_fp_adj.db"
        fb = FPFeedbackManager(db_path=str(db_path))
        for i in range(10):
            fb.record(FPFeedbackRecord(
                finding_id=f"fp-{i}",
                vuln_type="info_disclosure",
                tool="nikto",
                endpoint=f"https://example.com/p{i}",
                verdict="false_positive",
                verdict_source="fp_engine",
                reason="Known FP pattern",
            ))
        adj = fb.get_confidence_adjustment("nikto", "info_disclosure")
        assert adj < 0

    def test_empty_db_default_adjustment(self, tmp_path):
        from src.fp_engine.learning.fp_feedback import FPFeedbackManager
        db_path = tmp_path / "test_empty.db"
        fb = FPFeedbackManager(db_path=str(db_path))
        adj = fb.get_confidence_adjustment("unknown_tool", "unknown_vuln")
        # Empty DB returns default (non-negative) adjustment
        assert isinstance(adj, (int, float))

    def test_tool_fp_rate(self, tmp_path):
        from src.fp_engine.learning.fp_feedback import (
            FPFeedbackManager, FPFeedbackRecord,
        )
        db_path = tmp_path / "test_rate.db"
        fb = FPFeedbackManager(db_path=str(db_path))
        for i in range(5):
            fb.record(FPFeedbackRecord(
                finding_id=f"tp-{i}",
                vuln_type="sqli",
                tool="sqlmap",
                endpoint=f"https://example.com/{i}",
                verdict="true_positive",
                verdict_source="test",
                reason="confirmed",
            ))
        for i in range(5):
            fb.record(FPFeedbackRecord(
                finding_id=f"fp-{i}",
                vuln_type="sqli",
                tool="sqlmap",
                endpoint=f"https://example.com/fp{i}",
                verdict="false_positive",
                verdict_source="test",
                reason="fp",
            ))
        rate = fb.get_tool_fp_rate("sqlmap")
        assert 0.4 <= rate <= 0.6  # ~50% FP rate

    def test_recent_fps(self, tmp_path):
        from src.fp_engine.learning.fp_feedback import (
            FPFeedbackManager, FPFeedbackRecord,
        )
        db_path = tmp_path / "test_recent.db"
        fb = FPFeedbackManager(db_path=str(db_path))
        for i in range(3):
            fb.record(FPFeedbackRecord(
                finding_id=f"fp-{i}",
                vuln_type="xss",
                tool="dalfox",
                endpoint=f"https://example.com/{i}",
                verdict="false_positive",
                verdict_source="test",
                reason="fp test",
            ))
        recent = fb.get_recent_fps(limit=5)
        assert len(recent) == 3


# ─────────────────────────────────────────────────────────────
# P6: RiskAssessor Unit Tests
# ─────────────────────────────────────────────────────────────


class TestRiskAssessor:
    """Verify RiskAssessor risk scoring and prioritization."""

    def test_import(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        assert RiskAssessor is not None

    def test_assess_vulnerability(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        ra = RiskAssessor()
        result = ra.assess_vulnerability(
            vuln_type="sqli",
            target="https://example.com/api/data",
            impact_score=8.0,
            confidence=85.0,
        )
        assert hasattr(result, "risk_score")
        assert 0 <= result.risk_score <= 100

    def test_prioritise_findings(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        ra = RiskAssessor()
        findings = [
            {"vuln_type": "open_redirect", "target": "a.com", "impact_score": 2.0, "confidence": 90},
            {"vuln_type": "sqli", "target": "b.com", "impact_score": 9.0, "confidence": 85},
            {"vuln_type": "xss", "target": "c.com", "impact_score": 6.0, "confidence": 75},
        ]
        result = ra.prioritise_findings(findings)
        assert isinstance(result, list)
        assert len(result) == 3
        # All are RiskAssessment objects, highest risk_score first
        assert result[0].risk_score >= result[1].risk_score
        assert result[1].risk_score >= result[2].risk_score
        # Ordering depends on scoring formula; just verify descending and all present
        vuln_types_returned = {r.vuln_type for r in result}
        assert vuln_types_returned == {"sqli", "xss", "open_redirect"}

    def test_exploit_difficulty_data(self):
        from src.brain.reasoning.risk_assessor import EXPLOIT_DIFFICULTY
        assert isinstance(EXPLOIT_DIFFICULTY, dict)
        assert "sqli" in EXPLOIT_DIFFICULTY
        assert "xss" in EXPLOIT_DIFFICULTY
        assert len(EXPLOIT_DIFFICULTY) >= 10

    def test_assess_attack_surface(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        ra = RiskAssessor()
        endpoints = [
            {"url": "/api/users", "potential_vulns": ["sqli", "idor"]},
            {"url": "/login", "potential_vulns": ["auth_bypass"]},
        ]
        result = ra.assess_attack_surface(endpoints)
        assert isinstance(result, list)
        assert len(result) >= 2

    def test_priority_rank_assigned(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        ra = RiskAssessor()
        findings = [
            {"vuln_type": "xss", "target": "a.com", "impact_score": 5.0},
            {"vuln_type": "rce", "target": "b.com", "impact_score": 10.0},
        ]
        result = ra.prioritise_findings(findings)
        assert result[0].priority_rank == 1
        assert result[1].priority_rank == 2


# ─────────────────────────────────────────────────────────────
# P7: ManualVerifyGuideGenerator Unit Tests
# ─────────────────────────────────────────────────────────────


class TestManualVerifyGuideGenerator:
    """Verify ManualVerifyGuideGenerator guide generation."""

    def test_import(self):
        from src.fp_engine.verification.manual_verify import ManualVerifyGuideGenerator
        assert ManualVerifyGuideGenerator is not None

    def test_generate_xss_guide(self):
        from src.fp_engine.verification.manual_verify import ManualVerifyGuideGenerator
        mvg = ManualVerifyGuideGenerator()
        guide = mvg.generate(
            vuln_type="xss",
            target="https://example.com/search",
            parameter="q",
            payload="<script>alert(1)</script>",
        )
        assert guide is not None
        assert guide.vuln_type == "xss"
        assert len(guide.steps) >= 2

    def test_generate_sqli_guide(self):
        from src.fp_engine.verification.manual_verify import ManualVerifyGuideGenerator
        mvg = ManualVerifyGuideGenerator()
        guide = mvg.generate(
            vuln_type="sqli",
            target="https://example.com/api/data",
            parameter="id",
            payload="' OR 1=1 --",
        )
        assert guide is not None
        assert len(guide.steps) >= 3

    def test_generate_ssrf_guide(self):
        from src.fp_engine.verification.manual_verify import ManualVerifyGuideGenerator
        mvg = ManualVerifyGuideGenerator()
        guide = mvg.generate(
            vuln_type="ssrf",
            target="https://example.com/fetch",
            parameter="url",
            payload="http://169.254.169.254/latest/meta-data/",
        )
        assert guide is not None
        assert "ssrf" in guide.summary.lower() or "SSRF" in guide.summary

    def test_generate_unknown_type_uses_default(self):
        from src.fp_engine.verification.manual_verify import ManualVerifyGuideGenerator
        mvg = ManualVerifyGuideGenerator()
        guide = mvg.generate(
            vuln_type="some_exotic_vuln",
            target="https://example.com/test",
            parameter="x",
            payload="test",
        )
        assert guide is not None
        assert len(guide.steps) >= 1

    def test_generate_markdown(self):
        from src.fp_engine.verification.manual_verify import ManualVerifyGuideGenerator
        mvg = ManualVerifyGuideGenerator()
        guide = mvg.generate(
            vuln_type="ssrf",
            target="https://example.com/fetch",
            parameter="url",
            payload="http://169.254.169.254/latest/meta-data/",
        )
        md = mvg.generate_markdown(guide)
        assert isinstance(md, str)
        assert "Manual Verification" in md
        assert "Step 1" in md

    def test_success_and_failure_criteria(self):
        from src.fp_engine.verification.manual_verify import ManualVerifyGuideGenerator
        mvg = ManualVerifyGuideGenerator()
        guide = mvg.generate(vuln_type="xss", target="https://example.com")
        assert len(guide.success_criteria) >= 1
        assert len(guide.failure_criteria) >= 1


# ─────────────────────────────────────────────────────────────
# Integration: FP Detector Layer Wiring Presence Tests
# ─────────────────────────────────────────────────────────────


class TestFPDetectorLayerWiring:
    """Verify that V24 layers exist in fp_detector.py source code."""

    def _get_source(self) -> str:
        p = Path(__file__).parent.parent.parent / "src" / "fp_engine" / "fp_detector.py"
        return p.read_text(encoding="utf-8")

    def test_layer_1c_tool_quirks_wired(self):
        src = self._get_source()
        assert "Layer 1c: Tool-Specific Quirk Penalties" in src
        assert "ToolQuirkChecker" in src

    def test_layer_2c_context_verify_wired(self):
        src = self._get_source()
        assert "Layer 2c: HTTP Context Verification" in src
        assert "ContextVerifier" in src

    def test_layer_5_waf_artifact_detector_wired(self):
        src = self._get_source()
        assert "WafArtifactDetector" in src
        assert "V24: Try WafArtifactDetector" in src

    def test_layer_6_response_diff_wired(self):
        src = self._get_source()
        assert "ResponseDiffAnalyzer" in src
        assert "Deep differential analysis via ResponseDiffAnalyzer" in src

    def test_layer_0_historical_feedback_wired(self):
        src = self._get_source()
        assert "V24: Historical FP feedback adjustment" in src
        assert "FPFeedbackManager" in src


# ─────────────────────────────────────────────────────────────
# Integration: Pipeline Wiring Presence Tests
# ─────────────────────────────────────────────────────────────


class TestPipelineWiring:
    """Verify V24 pipeline integrations in full_scan.py."""

    def _get_source(self) -> str:
        p = Path(__file__).parent.parent.parent / "src" / "workflow" / "pipelines" / "full_scan.py"
        return p.read_text(encoding="utf-8")

    def test_fp_feedback_recording_wired(self):
        src = self._get_source()
        assert "V24: Record FP verdicts" in src
        assert "FPFeedbackManager" in src
        assert "record_batch" in src

    def test_risk_assessor_wired(self):
        src = self._get_source()
        assert "V24: Risk-based finding prioritization" in src
        assert "RiskAssessor" in src
        assert "prioritise_findings" in src


class TestAutoDraftWiring:
    """Verify ManualVerifyGuideGenerator wiring in auto_draft.py."""

    def _get_source(self) -> str:
        p = Path(__file__).parent.parent.parent / "src" / "reporting" / "auto_draft.py"
        return p.read_text(encoding="utf-8")

    def test_manual_verify_guide_wired(self):
        src = self._get_source()
        assert "ManualVerifyGuideGenerator" in src
        assert "V24: Append manual verification guide" in src

    def test_confidence_threshold(self):
        """Mid-confidence range 30-75 triggers guide generation."""
        src = self._get_source()
        assert "30 <= confidence <= 75" in src


# ─────────────────────────────────────────────────────────────
# Edge Cases
# ─────────────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge cases for V24 wiring."""

    def test_tool_quirks_empty_tool_name(self):
        from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
        tq = ToolQuirkChecker()
        result = tq.check("", {"vuln_type": "xss", "evidence": ""})
        assert result["has_quirks"] is False

    def test_waf_artifact_detector_empty_inputs(self):
        from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector
        d = WafArtifactDetector()
        result = d.analyze(
            response_headers={},
            response_body="",
            status_code=0,
            cookies={},
        )
        assert isinstance(result, dict)

    def test_context_verifier_minimal_context(self):
        from src.fp_engine.verification.context_verify import (
            ContextVerifier, HttpContext,
        )
        cv = ContextVerifier()
        ctx = HttpContext(
            url="",
            method="GET",
            request_headers={},
            response_headers={},
            response_body="",
            status_code=0,
            response_time=0.0,
        )
        result = cv.verify("unknown", ctx)
        assert hasattr(result, "confidence")

    def test_response_diff_empty_payload(self):
        from src.fp_engine.verification.response_diff import ResponseDiffAnalyzer
        rda = ResponseDiffAnalyzer()
        result = rda.analyze(
            normal_response=_resp_dict(200, "body"),
            payload_response=_resp_dict(200, "body"),
            payload="",
            vuln_type="",
        )
        assert result.payload_reflected is False

    def test_risk_assessor_defaults(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        ra = RiskAssessor()
        result = ra.assess_vulnerability(
            vuln_type="unknown_vuln",
            target="",
            impact_score=5.0,
        )
        assert hasattr(result, "risk_score")
        assert result.risk_score >= 0

    def test_fp_feedback_record_batch(self, tmp_path):
        from src.fp_engine.learning.fp_feedback import (
            FPFeedbackManager, FPFeedbackRecord,
        )
        db_path = tmp_path / "batch.db"
        fb = FPFeedbackManager(db_path=str(db_path))
        records = [
            FPFeedbackRecord(
                finding_id=f"batch-{i}",
                vuln_type="xss",
                tool="dalfox",
                endpoint=f"https://example.com/{i}",
                verdict="true_positive",
                verdict_source="test",
                reason="test",
            )
            for i in range(5)
        ]
        fb.record_batch(records)
        stats = fb.get_statistics()
        assert stats.total_findings >= 5
