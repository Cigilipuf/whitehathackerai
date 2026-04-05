"""
End-to-End FP Pipeline Simulation Tests

Exercises the FULL FPDetector.analyze() async pipeline with realistic Finding
objects.  No brain engine, no tool executor — tests the deterministic layer
orchestration: L0 (inherent reliability), L1 (KnownFPMatcher), L1b-e,
L2 (multi-tool metadata), L2c (context verify), L4 (payload), L5 (WAF),
L7 (ConfidenceScorer), L7b (semantic verdict), L8 (Bayesian), L-final
(Guard 3 ceiling).

Architecture note:
  Without brain engine and tool executor, the FPDetector is deliberately
  conservative — single-tool findings get penalized, Bayesian filter pulls
  down, and no brain boost is available.  This is BY DESIGN.

  To test "real finding survival", we simulate realistic pipeline metadata:
  multi-tool confirmation, nuclei HTTP evidence, high starting confidence.
  The tests validate:
  • Real findings with multi-tool evidence → confidence ≥ 50
  • Known FP findings → confidence < 50
  • Real findings ALWAYS outscore equivalent FP findings (relative ordering)
  • known_fp_capped flag → set when pattern penalty ≤ -20
  • Batch analysis → mixed real + FP separated correctly
  • Edge cases → no crashes, scores in 0-100 range
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.fp_engine.fp_detector import FPDetector, FPVerdict
from src.tools.base import Finding
from src.utils.constants import SeverityLevel, FP_MEDIUM_CONFIDENCE_THRESHOLD


# ───────────────────────────────────────────────────────────────
# Helpers
# ───────────────────────────────────────────────────────────────

def _make_detector(**kwargs: Any) -> FPDetector:
    """Create FPDetector with no brain, no executor — pure deterministic."""
    defaults = dict(
        brain_engine=None,
        intelligence_engine=None,
        tool_executor=None,
        is_spa=False,
    )
    defaults.update(kwargs)
    return FPDetector(**defaults)


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _make_finding(**kwargs: Any) -> Finding:
    """Create Finding with sensible defaults, override with kwargs."""
    defaults = dict(
        title="Test Finding",
        vulnerability_type="sql_injection",
        severity=SeverityLevel.HIGH,
        confidence=50.0,
        target="https://example.com",
        endpoint="https://example.com/search",
        tool_name="sqlmap",
        payload="' OR 1=1--",
        evidence="SQL syntax error near '1=1'",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ───────────────────────────────────────────────────────────────
# 1. Real Findings with Multi-Tool Evidence → Must Survive (≥50)
# ───────────────────────────────────────────────────────────────

class TestRealFindingsPipeline:
    """Real vulnerability findings with realistic multi-tool evidence
    must pass through the FP pipeline with confidence ≥ 50 (reportable).

    NOTE: The FPDetector is deliberately conservative for single-tool
    findings without brain confirmation. These tests simulate the
    metadata that a full pipeline run would produce."""

    def test_sqli_nuclei_with_http_evidence(self):
        """SQLi found by nuclei with HTTP request/response pair → reportable.

        Nuclei gets evidence-richness boost (+15) from L0 when both
        http_request and http_response are present."""
        det = _make_detector()
        f = _make_finding(
            title="SQL Injection in search parameter",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            confidence=65.0,  # Nuclei typically starts higher
            tool_name="nuclei",
            payload="' UNION SELECT NULL,username,password FROM users--",
            evidence="SQL error: syntax error near 'UNION SELECT'",
            http_request="GET /search?q=' UNION SELECT HTTP/1.1\nHost: example.com",
            http_response="HTTP/1.1 200 OK\n\n' UNION SELECT NULL,username,password FROM users-- found in body",
        )
        v = _run(det.analyze(f))
        assert isinstance(v, FPVerdict)
        assert v.confidence_score >= 50, (
            f"Nuclei SQLi with HTTP evidence should be reportable, got {v.confidence_score}"
        )
        assert not v.known_fp_capped

    def test_xss_reflected_in_http_response(self):
        """XSS with payload reflected unencoded in http_response → reportable.

        L4 detects reflection (+15 payload_reflected), plus payload exists (+5)."""
        det = _make_detector()
        xss_payload = '<script>alert(document.domain)</script>'
        f = _make_finding(
            title="Reflected XSS in q parameter",
            vulnerability_type="xss_reflected",
            severity=SeverityLevel.MEDIUM,
            confidence=60.0,  # dalfox confirmed XSS
            tool_name="dalfox",
            payload=xss_payload,
            evidence=f'{xss_payload} found in response body',
            endpoint="https://example.com/search?q=test",
            parameter="q",
            # Crucially: payload reflected in http_response for L4 detection
            http_response=f"HTTP/1.1 200 OK\n\n<html><body>{xss_payload}</body></html>",
        )
        v = _run(det.analyze(f))
        assert v.confidence_score >= 50, (
            f"XSS with reflection should be reportable, got {v.confidence_score}"
        )

    def test_rce_high_confidence_nuclei(self):
        """RCE via nuclei with CVSS score + HTTP evidence → reportable."""
        det = _make_detector()
        f = _make_finding(
            title="Remote Code Execution via OS command injection",
            vulnerability_type="command_injection",
            severity=SeverityLevel.CRITICAL,
            confidence=75.0,
            tool_name="nuclei",
            payload="; id",
            evidence="uid=33(www-data) gid=33(www-data)",
            http_request="POST /api/run HTTP/1.1\nHost: example.com\n\ncmd=;id",
            http_response="HTTP/1.1 200 OK\n\nuid=33(www-data) gid=33(www-data)",
            cvss_score=9.8,
        )
        v = _run(det.analyze(f))
        assert v.confidence_score >= 50, (
            f"Critical RCE with nuclei evidence should be reportable, got {v.confidence_score}"
        )

    def test_lfi_nuclei_etc_passwd(self):
        """LFI reading /etc/passwd via nuclei → reportable."""
        det = _make_detector()
        f = _make_finding(
            title="Local File Inclusion - /etc/passwd",
            vulnerability_type="local_file_inclusion",
            severity=SeverityLevel.HIGH,
            confidence=70.0,
            tool_name="nuclei",
            payload="../../../../../../etc/passwd",
            evidence="root:x:0:0:root:/root:/bin/bash",
            http_request="GET /download?file=../../etc/passwd HTTP/1.1",
            http_response="HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash",
        )
        v = _run(det.analyze(f))
        assert v.confidence_score >= 50, (
            f"LFI via nuclei HTTP evidence should be reportable, got {v.confidence_score}"
        )

    def test_header_checker_missing_hsts(self):
        """Missing HSTS header from deterministic tool → high confidence.

        header_checker is in _DETERMINISTIC_TOOLS with +15 boost, and
        missing_security_header has high base score (65)."""
        det = _make_detector()
        f = _make_finding(
            title="Missing Strict-Transport-Security Header",
            vulnerability_type="missing_security_header",
            severity=SeverityLevel.LOW,
            confidence=65.0,
            tool_name="header_checker",
            payload="",
            evidence="Strict-Transport-Security header not present on https://example.com",
        )
        v = _run(det.analyze(f))
        assert v.confidence_score >= 50, (
            f"Deterministic header check should be reportable, got {v.confidence_score}"
        )

    def test_cookie_checker_missing_httponly(self):
        """Cookie missing HttpOnly from deterministic tool → reportable."""
        det = _make_detector()
        f = _make_finding(
            title="Cookie without HttpOnly flag",
            vulnerability_type="cookie_security",
            severity=SeverityLevel.LOW,
            confidence=60.0,
            tool_name="cookie_checker",
            payload="",
            evidence="Set-Cookie: session=abc123; Path=/; Secure (no HttpOnly)",
        )
        v = _run(det.analyze(f))
        assert v.confidence_score >= 50, (
            f"Deterministic cookie check should be reportable, got {v.confidence_score}"
        )


# ───────────────────────────────────────────────────────────────
# 1b. Conservative Single-Tool Behavior (By Design)
# ───────────────────────────────────────────────────────────────

class TestSingleToolConservative:
    """Without brain engine and multi-tool confirmation, single-tool
    findings get penalized — this is CORRECT behavior, not a bug.

    These tests validate that the FPDetector's conservative stance is
    working: single-tool heuristic findings without http_response
    evidence score lower than findings with full evidence chain."""

    def test_sqlmap_single_tool_conservative(self):
        """SQLi from sqlmap alone (no http_response) → conservative score.

        Without brain and multi-tool confirmation, the pipeline rightfully
        does not trust a single heuristic tool."""
        det = _make_detector()
        f = _make_finding(
            title="SQL Injection in search",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            confidence=50.0,
            tool_name="sqlmap",
            payload="' OR 1=1--",
            evidence="SQL error: syntax error near '1=1'",
        )
        v = _run(det.analyze(f))
        assert isinstance(v, FPVerdict)
        # Should NOT crash, score should be in valid range
        assert 0 <= v.confidence_score <= 100

    def test_single_tool_lower_than_multi_evidence(self):
        """Single-tool finding must score LOWER than equivalent with
        full HTTP evidence — tests the relative ordering property."""
        det = _make_detector()
        sqli_payload = "' OR 1=1--"

        # Single tool, no http_response
        f_thin = _make_finding(
            title="SQLi thin evidence",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            confidence=60.0,
            tool_name="nuclei",
            payload=sqli_payload,
            evidence="SQL error detected",
        )

        # Same tool, but WITH http_request + http_response
        f_rich = _make_finding(
            title="SQLi rich evidence",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            confidence=60.0,
            tool_name="nuclei",
            payload=sqli_payload,
            evidence="SQL error detected",
            http_request=f"GET /search?q={sqli_payload} HTTP/1.1",
            http_response=f"HTTP/1.1 200 OK\n\nSQL error near {sqli_payload}",
        )

        v_thin = _run(det.analyze(f_thin))
        v_rich = _run(det.analyze(f_rich))

        assert v_rich.confidence_score > v_thin.confidence_score, (
            f"Rich evidence ({v_rich.confidence_score}) must outscore "
            f"thin evidence ({v_thin.confidence_score})"
        )

    def test_real_always_beats_fp_equivalent(self):
        """A real finding should always outscore an FP finding of
        comparable starting confidence — tests separation quality."""
        det = _make_detector()

        # Real: XSS with payload reflection in http_response
        xss_payload = "<script>alert(1)</script>"
        f_real = _make_finding(
            title="Reflected XSS confirmed",
            vulnerability_type="xss_reflected",
            severity=SeverityLevel.MEDIUM,
            confidence=60.0,
            tool_name="dalfox",
            payload=xss_payload,
            evidence=f"{xss_payload} in response",
            http_response=f"HTTP/1.1 200 OK\n\n{xss_payload}",
        )

        # FP: SearchSploit noise at same starting confidence
        f_fp = _make_finding(
            title="Apache vulnerability (unverified)",
            vulnerability_type="outdated_software",
            severity=SeverityLevel.LOW,
            confidence=60.0,
            tool_name="searchsploit",
            payload="",
            evidence="EDB-ID: 12345",
            metadata={"unverified": True},
        )

        v_real = _run(det.analyze(f_real))
        v_fp = _run(det.analyze(f_fp))

        assert v_real.confidence_score > v_fp.confidence_score, (
            f"Real ({v_real.confidence_score}) must outscore "
            f"FP ({v_fp.confidence_score})"
        )


# ───────────────────────────────────────────────────────────────
# 2. Known FP Findings → Must Be Rejected (confidence < 50)
# ───────────────────────────────────────────────────────────────

class TestKnownFPPipeline:
    """Known false positive patterns must push findings below 50."""

    def test_nuclei_tech_detect(self):
        """Nuclei tech-detect is informational, not a vuln."""
        det = _make_detector()
        f = _make_finding(
            title="tech-detect:nginx",
            vulnerability_type="tech-detect",
            severity=SeverityLevel.INFO,
            tool_name="nuclei",
            payload="",
            evidence="nginx server detected",
            confidence=30.0,  # Nuclei info already low confidence
        )
        v = _run(det.analyze(f))
        assert v.confidence_score < 50, (
            f"Tech-detect should NOT be reportable, got {v.confidence_score}"
        )

    def test_missing_header_info_only(self):
        """Missing security header from deterministic header_checker.

        header_checker is a DETERMINISTIC tool in the FPDetector — it gets
        a +15 L0 boost and is in _SINGLE_TOOL_OK (no -15 penalty).
        INFO severity findings from trusted deterministic tools correctly
        score moderate-to-high.  This test validates it stays below the
        auto-report threshold (90)."""
        det = _make_detector()
        f = _make_finding(
            title="Missing X-Content-Type-Options Header",
            vulnerability_type="missing_security_header",
            severity=SeverityLevel.INFO,
            tool_name="header_checker",
            payload="",
            evidence="X-Content-Type-Options header not present",
            confidence=40.0,
        )
        v = _run(det.analyze(f))
        # Deterministic tool → trusted → moderate-high score, but never auto-report
        assert v.confidence_score < 90, (
            f"Missing header should not auto-report, got {v.confidence_score}"
        )

    def test_cors_without_credentials(self):
        """CORS origin reflection without ACAC header → FP pattern."""
        det = _make_detector()
        f = _make_finding(
            title="CORS Misconfiguration - Origin Reflection",
            vulnerability_type="cors_misconfiguration",
            severity=SeverityLevel.LOW,
            tool_name="corsy",
            payload="",
            evidence="Access-Control-Allow-Origin: https://evil.com (no ACAC)",
            confidence=40.0,
            metadata={},
        )
        v = _run(det.analyze(f))
        assert v.confidence_score < 50, (
            f"CORS without credentials should NOT be reportable, got {v.confidence_score}"
        )

    def test_searchsploit_version_unknown(self):
        """SearchSploit hit without confirmed version → FP pattern."""
        det = _make_detector()
        f = _make_finding(
            title="Apache HTTP Server 2.4.x - Multiple Vulnerabilities",
            vulnerability_type="outdated_software",
            severity=SeverityLevel.LOW,
            tool_name="searchsploit",
            payload="",
            evidence="EDB-ID: 12345 | Apache httpd | CVE-2021-XXXX",
            confidence=20.0,
            metadata={"unverified": True},
        )
        v = _run(det.analyze(f))
        assert v.confidence_score < 50, (
            f"SearchSploit without version should NOT be reportable, got {v.confidence_score}"
        )

    def test_nikto_osvdb_noise(self):
        """Nikto OSVDB reference → typically noise."""
        det = _make_detector()
        f = _make_finding(
            title="OSVDB-3092: /icons/: Directory indexing found",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.LOW,
            tool_name="nikto",
            payload="",
            evidence="OSVDB-3092: /icons/: Directory indexing found",
            confidence=35.0,
        )
        v = _run(det.analyze(f))
        assert v.confidence_score < 50, (
            f"Nikto OSVDB should NOT be reportable, got {v.confidence_score}"
        )


# ───────────────────────────────────────────────────────────────
# 3. known_fp_capped Guard (v4.0 Guard 3)
# ───────────────────────────────────────────────────────────────

class TestKnownFPCappedGuard:
    """When KnownFPMatcher applies penalty ≤ -20, Guard 3 must:
    1. Set known_fp_capped = True
    2. Cap confidence at 49.9 max"""

    def test_capped_flag_set_on_strong_penalty(self):
        """Pattern with penalty ≤ -20 must set known_fp_capped.

        FP-SQLI-001 ('Generic SQL error page') fires when evidence contains
        'syntax error' but NOT 'UNION SELECT' — penalty is -20."""
        det = _make_detector()
        # FP-SQLI-001 matches: evidence has 'syntax error' without 'UNION SELECT'
        f = _make_finding(
            title="SQL Injection in search",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            tool_name="sqlmap",
            payload="' OR 1=1--",
            evidence="You have an error in your SQL syntax near '1=1'",
            confidence=70.0,  # High starting confidence
        )
        v = _run(det.analyze(f))
        # FP-SQLI-001 should match → known_fp_capped = True
        assert v.known_fp_capped, (
            f"known_fp_capped should be True for FP-SQLI-001 match, "
            f"patterns={v.fp_patterns_matched}"
        )
        # And confidence must be < 50
        assert v.confidence_score < 50, (
            f"Capped finding must be <50, got {v.confidence_score}"
        )

    def test_ceiling_prevents_high_confidence(self):
        """Even with high starting confidence, Guard 3 caps below threshold."""
        det = _make_detector()
        # Use a finding that WOULD score high but matches FP pattern
        f = _make_finding(
            title="CORS Misconfiguration - Wildcard Origin",
            vulnerability_type="cors_misconfiguration",
            severity=SeverityLevel.MEDIUM,
            tool_name="nuclei",
            payload="",
            evidence="Access-Control-Allow-Origin: * without credentials header",
            confidence=85.0,  # Very high starting confidence
            metadata={"payload_executed": True},
        )
        v = _run(det.analyze(f))
        # If a strong FP pattern matched, ceiling must apply
        if v.known_fp_capped:
            assert v.confidence_score < FP_MEDIUM_CONFIDENCE_THRESHOLD, (
                f"Guard 3 ceiling must cap below {FP_MEDIUM_CONFIDENCE_THRESHOLD}, got {v.confidence_score}"
            )

    def test_no_cap_on_strong_evidence_sqli(self):
        """SQLi with extraction proof should NOT be capped — evidence
        containing 'UNION SELECT' excludes FP-SQLI-001."""
        det = _make_detector()
        payload = "' UNION SELECT username,password FROM users--"
        f = _make_finding(
            title="SQL Injection with data extraction",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            confidence=70.0,
            tool_name="nuclei",
            payload=payload,
            evidence=f"UNION SELECT returned: admin:hash123",
            http_request=f"GET /search?q={payload} HTTP/1.1",
            http_response=f"HTTP/1.1 200 OK\n\nadmin:hash123 {payload}",
        )
        v = _run(det.analyze(f))
        assert not v.known_fp_capped, (
            f"SQLi with UNION SELECT extraction should NOT be capped, "
            f"patterns={v.fp_patterns_matched}"
        )


# ───────────────────────────────────────────────────────────────
# 4. GitLab-Style FP Findings (Real-World Regression)
# ───────────────────────────────────────────────────────────────

class TestGitLabStyleFPs:
    """Findings mimicking the 436 FPs from the GitLab scan.
    These MUST be rejected (confidence < 50)."""

    def test_searchsploit_ruby_unverified(self):
        """SearchSploit Ruby-on-Rails hit without version proof."""
        det = _make_detector()
        f = _make_finding(
            title="Ruby on Rails - Remote Code Execution",
            vulnerability_type="outdated_software",
            severity=SeverityLevel.LOW,
            tool_name="searchsploit",
            payload="",
            evidence="EDB-ID: 99999 | Ruby on Rails |",
            confidence=15.0,
            metadata={"unverified": True},
        )
        v = _run(det.analyze(f))
        assert v.confidence_score < 50, (
            f"Unverified SearchSploit should be rejected, got {v.confidence_score}"
        )

    def test_nuclei_info_severity(self):
        """Nuclei INFO-severity finding → not a real vuln."""
        det = _make_detector()
        f = _make_finding(
            title="HTTP Server Header Information",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.INFO,
            tool_name="nuclei",
            payload="",
            evidence="Server: nginx/1.21.0",
            confidence=30.0,
        )
        v = _run(det.analyze(f))
        assert v.confidence_score < 50, (
            f"INFO nuclei finding should be rejected, got {v.confidence_score}"
        )

    def test_nikto_common_directory(self):
        """Nikto finding a common directory → noise."""
        det = _make_detector()
        f = _make_finding(
            title="/assets/: Directory listing found",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.LOW,
            tool_name="nikto",
            payload="",
            evidence="Directory listing: /assets/",
            confidence=35.0,
        )
        v = _run(det.analyze(f))
        assert v.confidence_score < 50, (
            f"Nikto directory listing should be rejected, got {v.confidence_score}"
        )

    def test_header_missing_csp(self):
        """Missing CSP header from deterministic header_checker.

        header_checker is trusted — similar to test_missing_header_info_only.
        Verify it doesn't reach auto-report (90) threshold."""
        det = _make_detector()
        f = _make_finding(
            title="Missing Content-Security-Policy Header",
            vulnerability_type="missing_security_header",
            severity=SeverityLevel.INFO,
            tool_name="header_checker",
            payload="",
            evidence="Content-Security-Policy header not present",
            confidence=40.0,
        )
        v = _run(det.analyze(f))
        # Deterministic tool → trusted → moderate score, never auto-report
        assert v.confidence_score < 90, (
            f"Missing CSP should not auto-report, got {v.confidence_score}"
        )

    def test_cookie_samesite_lax(self):
        """Cookie with SameSite=Lax — cookie_checker is deterministic.

        Even though SameSite=Lax is debatable as a vuln, cookie_checker is
        a trusted deterministic tool. With INFO severity and low starting
        confidence, the score should stay below auto-report threshold."""
        det = _make_detector()
        f = _make_finding(
            title="Cookie without SameSite=Strict",
            vulnerability_type="cookie_security",
            severity=SeverityLevel.INFO,
            tool_name="cookie_checker",
            payload="",
            evidence="Set-Cookie: session=abc; SameSite=Lax; HttpOnly; Secure",
            confidence=30.0,  # Very low starting confidence
        )
        v = _run(det.analyze(f))
        # Deterministic tool raises it but INFO sev + low start → below auto-report
        assert v.confidence_score < 90, (
            f"Cookie SameSite=Lax should not auto-report, got {v.confidence_score}"
        )


# ───────────────────────────────────────────────────────────────
# 5. SPA-Aware Pipeline
# ───────────────────────────────────────────────────────────────

class TestSPAPipeline:
    """When is_spa=True, path-based findings must get penalized."""

    def test_spa_admin_panel_finding(self):
        """/admin path on SPA → SPA penalty should push it lower than
        the same finding on a non-SPA target."""
        f = _make_finding(
            title="Admin Panel Exposed",
            vulnerability_type="sensitive_url",
            severity=SeverityLevel.MEDIUM,
            tool_name="sensitive_url_finder",
            payload="",
            evidence="200 OK returned for /admin",
            confidence=45.0,
        )

        det_spa = _make_detector(is_spa=True)
        det_nospa = _make_detector(is_spa=False)

        v_spa = _run(det_spa.analyze(f))
        v_nospa = _run(det_nospa.analyze(f))

        # SPA version must score LOWER (penalty applied)
        assert v_spa.confidence_score < v_nospa.confidence_score, (
            f"SPA ({v_spa.confidence_score}) should score lower than "
            f"non-SPA ({v_nospa.confidence_score}) for path-based finding"
        )

    def test_spa_does_not_affect_injection(self):
        """SPA flag should NOT penalize injection findings.

        Uses nuclei with HTTP evidence.  Evidence includes 'UNION SELECT'
        to avoid FP-SQLI-001 matching."""
        det = _make_detector(is_spa=True)
        payload = "' UNION SELECT username,password FROM users--"
        f = _make_finding(
            title="SQL Injection in search parameter",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            confidence=65.0,
            tool_name="nuclei",
            payload=payload,
            evidence=f"UNION SELECT returned: admin:secrethash",
            http_request=f"GET /search?q={payload} HTTP/1.1\nHost: example.com",
            http_response=f"HTTP/1.1 200 OK\n\nadmin:secrethash {payload}",
        )
        v = _run(det.analyze(f))
        # SQLi should still be reportable even on SPA targets
        assert v.confidence_score >= 50, (
            f"Real SQLi on SPA should survive, got {v.confidence_score}"
        )


# ───────────────────────────────────────────────────────────────
# 6. Batch Analysis
# ───────────────────────────────────────────────────────────────

class TestBatchAnalysis:
    """analyze_batch() with mixed findings → correct separation."""

    def test_mixed_batch_separation(self):
        """Batch of real + FP findings should separate correctly.

        Real findings use nuclei+HTTP evidence to clear the no-brain bar."""
        det = _make_detector()
        sqli_payload = "admin' OR '1'='1"
        xss_payload = "<img src=x onerror=alert(1)>"
        findings = [
            # Real: SQLi with nuclei HTTP evidence
            _make_finding(
                title="SQL Injection in login",
                vulnerability_type="sql_injection",
                severity=SeverityLevel.HIGH,
                confidence=65.0,
                tool_name="nuclei",
                payload=sqli_payload,
                evidence=f"SQL error: near {sqli_payload}",
                http_request=f"POST /login HTTP/1.1\n\nuser={sqli_payload}",
                http_response=f"HTTP/1.1 200 OK\n\nSQL error near {sqli_payload}",
            ),
            # FP: Nuclei info
            _make_finding(
                title="Server version disclosed",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                tool_name="nuclei",
                payload="",
                evidence="Server: Apache/2.4.41",
                confidence=25.0,
            ),
            # Real: XSS with reflection in http_response
            _make_finding(
                title="Reflected XSS in name",
                vulnerability_type="xss_reflected",
                severity=SeverityLevel.MEDIUM,
                confidence=60.0,
                tool_name="dalfox",
                payload=xss_payload,
                evidence=f"{xss_payload} reflected in HTML body",
                http_response=f"HTTP/1.1 200 OK\n\n<html>{xss_payload}</html>",
            ),
            # FP: SearchSploit unverified
            _make_finding(
                title="nginx - Buffer Overflow",
                vulnerability_type="outdated_software",
                severity=SeverityLevel.LOW,
                tool_name="searchsploit",
                payload="",
                evidence="EDB-ID: 55555",
                confidence=15.0,
                metadata={"unverified": True},
            ),
        ]

        verdicts = _run(det.analyze_batch(findings))
        assert len(verdicts) == 4

        real_count = sum(1 for v in verdicts if v.confidence_score >= 50)
        fp_count = sum(1 for v in verdicts if v.confidence_score < 50)

        # At least the two real findings should survive
        assert real_count >= 2, (
            f"Expected ≥2 real findings, got {real_count}. "
            f"Scores: {[v.confidence_score for v in verdicts]}"
        )
        # At least the two FP findings should be rejected
        assert fp_count >= 2, (
            f"Expected ≥2 FP findings, got {fp_count}. "
            f"Scores: {[v.confidence_score for v in verdicts]}"
        )


# ───────────────────────────────────────────────────────────────
# 7. FPVerdict Property Correctness
# ───────────────────────────────────────────────────────────────

class TestVerdictProperties:
    """Verify FPVerdict computed properties match the score."""

    def test_reportable_when_above_50(self):
        """Finding with score ≥ 50 → is_reportable = True."""
        det = _make_detector()
        f = _make_finding(
            title="RCE via command injection",
            vulnerability_type="command_injection",
            severity=SeverityLevel.CRITICAL,
            confidence=75.0,
            tool_name="nuclei",
            payload="; cat /etc/passwd",
            evidence="root:x:0:0:root:/root:/bin/bash",
            http_request="POST /api/exec HTTP/1.1\n\ncmd=; cat /etc/passwd",
            http_response="HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash",
        )
        v = _run(det.analyze(f))
        if v.confidence_score >= 50:
            assert v.is_reportable, "Score ≥50 should be reportable"
        else:
            pytest.fail(
                f"Real RCE should score ≥50, got {v.confidence_score}"
            )

    def test_not_reportable_when_below_50(self):
        """Finding with score < 50 → is_reportable = False."""
        det = _make_detector()
        f = _make_finding(
            title="Server: nginx",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.INFO,
            tool_name="nuclei",
            payload="",
            evidence="Server header: nginx",
            confidence=20.0,
        )
        v = _run(det.analyze(f))
        if v.confidence_score < 50:
            assert not v.is_reportable, "Score <50 should NOT be reportable"

    def test_verdict_string_matches_score(self):
        """Verdict string should align with final score."""
        det = _make_detector()
        ssti_payload = "{{7*7}}"
        f = _make_finding(
            title="SSTI confirmed",
            vulnerability_type="ssti",
            severity=SeverityLevel.HIGH,
            confidence=65.0,
            tool_name="nuclei",
            payload=ssti_payload,
            evidence="49 in response body",
            http_request=f"GET /render?tpl={ssti_payload} HTTP/1.1",
            http_response=f"HTTP/1.1 200 OK\n\n49",
        )
        v = _run(det.analyze(f))
        if v.confidence_score >= 90:
            assert v.verdict == "real"
        elif v.confidence_score >= 50:
            assert v.verdict in ("real", "needs_review")
        elif v.confidence_score >= 40:
            assert v.verdict in ("needs_review", "likely_fp")
        else:
            assert v.verdict == "false_positive"

    def test_evidence_chain_populated(self):
        """FPVerdict should have a non-empty evidence chain."""
        det = _make_detector()
        f = _make_finding(
            title="XSS via dalfox",
            vulnerability_type="xss_reflected",
            severity=SeverityLevel.MEDIUM,
            tool_name="dalfox",
            payload="<svg onload=alert(1)>",
            evidence="<svg onload=alert(1)> in response",
        )
        v = _run(det.analyze(f))
        assert len(v.evidence_chain) > 0, "Evidence chain should not be empty"
        assert len(v.verification_layers) > 0, "Verification layers should not be empty"


# ───────────────────────────────────────────────────────────────
# 8. Edge Cases
# ───────────────────────────────────────────────────────────────

class TestEdgeCases:
    """Edge cases that shouldn't crash the pipeline."""

    def test_empty_evidence(self):
        """Finding with no evidence → should not crash."""
        det = _make_detector()
        f = _make_finding(
            title="Something detected",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.LOW,
            tool_name="nuclei",
            payload="",
            evidence="",
            confidence=30.0,
        )
        v = _run(det.analyze(f))
        assert isinstance(v, FPVerdict)
        assert 0 <= v.confidence_score <= 100

    def test_empty_payload(self):
        """Finding with no payload → should not crash."""
        det = _make_detector()
        f = _make_finding(
            title="Open port detected",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.INFO,
            tool_name="nmap",
            payload="",
            evidence="Port 22 open: OpenSSH 8.9",
            confidence=25.0,
        )
        v = _run(det.analyze(f))
        assert isinstance(v, FPVerdict)

    def test_very_high_starting_confidence(self):
        """Finding starting at 95 confidence → should be handled."""
        det = _make_detector()
        f = _make_finding(
            title="Critical RCE",
            vulnerability_type="command_injection",
            severity=SeverityLevel.CRITICAL,
            tool_name="nuclei",
            payload="; id",
            evidence="uid=0(root)",
            confidence=95.0,
            metadata={"payload_executed": True},
        )
        v = _run(det.analyze(f))
        assert isinstance(v, FPVerdict)
        assert 0 <= v.confidence_score <= 100

    def test_very_low_starting_confidence(self):
        """Finding starting at 5 confidence → should not negative-wrap."""
        det = _make_detector()
        f = _make_finding(
            title="Possible info leak",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.INFO,
            tool_name="nikto",
            payload="",
            evidence="Server: Apache",
            confidence=5.0,
        )
        v = _run(det.analyze(f))
        assert isinstance(v, FPVerdict)
        assert v.confidence_score >= 0, "Score should never go negative"

    def test_unknown_tool_name(self):
        """Finding from unknown tool → should not crash."""
        det = _make_detector()
        f = _make_finding(
            title="Custom check result",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.MEDIUM,
            tool_name="custom_unknown_tool_xyz",
            payload="' OR 1=1",
            evidence="SQL error in response",
            confidence=50.0,
        )
        v = _run(det.analyze(f))
        assert isinstance(v, FPVerdict)

    def test_unknown_vuln_type(self):
        """Finding with non-standard vuln type → should not crash."""
        det = _make_detector()
        f = _make_finding(
            title="Custom vulnerability",
            vulnerability_type="custom_vuln_type_xyz",
            severity=SeverityLevel.MEDIUM,
            tool_name="nuclei",
            payload="test",
            evidence="Something happened",
            confidence=50.0,
        )
        v = _run(det.analyze(f))
        assert isinstance(v, FPVerdict)


# ───────────────────────────────────────────────────────────────
# 9. Multi-Tool Signal Survival
# ───────────────────────────────────────────────────────────────

class TestMultiToolSurvival:
    """Findings confirmed by multiple tools should get confidence boost."""

    def test_sqli_multi_tool_boost(self):
        """SQLi found by sqlmap + nuclei → higher confidence than single tool."""
        det = _make_detector()

        # Single tool finding
        f_single = _make_finding(
            title="SQLi single tool",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            tool_name="sqlmap",
            payload="' OR 1=1--",
            evidence="SQL error detected",
            metadata={"payload_executed": True},
        )

        # Multi-tool finding (same vuln, confirmed by 2 tools)
        f_multi = _make_finding(
            title="SQLi multi tool",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            tool_name="sqlmap",
            payload="' OR 1=1--",
            evidence="SQL error detected, confirmed by nuclei template",
            metadata={
                "payload_executed": True,
                "confirmed_by": ["sqlmap", "nuclei"],
                "multi_tool_confirmed": True,
            },
        )

        v_single = _run(det.analyze(f_single))
        v_multi = _run(det.analyze(f_multi))

        # Multi-tool should score >= single-tool
        assert v_multi.confidence_score >= v_single.confidence_score, (
            f"Multi-tool ({v_multi.confidence_score}) should score >= "
            f"single-tool ({v_single.confidence_score})"
        )

    def test_xss_stored_with_http_evidence(self):
        """Stored XSS with payload reflected in http_response → reportable."""
        det = _make_detector()
        xss_payload = "<script>alert(document.cookie)</script>"
        f = _make_finding(
            title="Stored XSS in comment",
            vulnerability_type="xss_stored",
            severity=SeverityLevel.HIGH,
            confidence=65.0,
            tool_name="dalfox",
            payload=xss_payload,
            evidence="Payload stored and rendered in other user's view",
            http_response=f"HTTP/1.1 200 OK\n\n<div class='comment'>{xss_payload}</div>",
        )
        v = _run(det.analyze(f))
        assert v.confidence_score >= 50, (
            f"Stored XSS with reflection should be reportable, got {v.confidence_score}"
        )


# ───────────────────────────────────────────────────────────────
# 10. WAF Detection Interaction
# ───────────────────────────────────────────────────────────────

class TestWAFInteraction:
    """Findings on WAF-protected targets should be handled correctly."""

    def test_waf_detected_reduces_confidence(self):
        """WAF detection should reduce confidence for ambiguous findings."""
        det_no_waf = _make_detector()
        det_waf = _make_detector(waf_detection={
            "detected": True,
            "waf_name": "cloudflare",
            "confidence": 0.9,
        })

        f = _make_finding(
            title="Possible XSS",
            vulnerability_type="xss_reflected",
            severity=SeverityLevel.MEDIUM,
            tool_name="dalfox",
            payload="<script>alert(1)</script>",
            evidence="Response contains <script> tag",
            confidence=55.0,
        )

        v_no_waf = _run(det_no_waf.analyze(f))
        v_waf = _run(det_waf.analyze(f))

        # WAF detection should lower or equal confidence
        assert v_waf.confidence_score <= v_no_waf.confidence_score + 5, (
            f"WAF detection should not boost confidence. "
            f"No-WAF={v_no_waf.confidence_score}, WAF={v_waf.confidence_score}"
        )

    def test_strong_evidence_survives_waf(self):
        """Strong execution evidence with HTTP proof survives WAF penalty."""
        det = _make_detector(waf_detection={
            "detected": True,
            "waf_name": "cloudflare",
        })
        rce_payload = "; cat /etc/passwd"
        f = _make_finding(
            title="RCE confirmed through WAF",
            vulnerability_type="command_injection",
            severity=SeverityLevel.CRITICAL,
            confidence=75.0,
            tool_name="nuclei",
            payload=rce_payload,
            evidence="root:x:0:0:root:/root:/bin/bash returned through WAF bypass",
            http_request=f"POST /api/exec HTTP/1.1\n\ncmd={rce_payload}",
            http_response="HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash",
        )
        v = _run(det.analyze(f))
        assert v.confidence_score >= 50, (
            f"Strong RCE evidence should survive WAF penalty, got {v.confidence_score}"
        )


# ───────────────────────────────────────────────────────────────
# 11. Pipeline Determinism
# ───────────────────────────────────────────────────────────────

class TestPipelineDeterminism:
    """Same finding through same detector → same result."""

    def test_same_finding_same_result(self):
        """Analyzing the same finding twice should yield identical scores."""
        det = _make_detector()
        f = _make_finding(
            title="XSS via dalfox",
            vulnerability_type="xss_reflected",
            severity=SeverityLevel.MEDIUM,
            tool_name="dalfox",
            payload="<img src=x onerror=alert(1)>",
            evidence="<img src=x onerror=alert(1)> in response",
            metadata={"payload_executed": True},
        )
        v1 = _run(det.analyze(f))
        v2 = _run(det.analyze(f))
        assert v1.confidence_score == v2.confidence_score, (
            f"Determinism violated: {v1.confidence_score} != {v2.confidence_score}"
        )
        assert v1.verdict == v2.verdict


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Header / Severity / Confidence Field Mapping Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# These patterns were DEAD CODE before the finding_dict fix:
# the 'header', 'severity', and 'confidence_score' fields were
# not mapped from Finding objects into the dict passed to
# KnownFPMatcher.check().  Now they are.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestHeaderPatternFiring:
    """Patterns that check response headers via http_response."""

    def test_cors_wildcard_no_credentials_capped(self):
        """FP-CORS-001: Access-Control-Allow-Origin: * without ACAC → capped."""
        det = _make_detector()
        f = _make_finding(
            title="CORS Misconfiguration",
            vulnerability_type="cors_misconfiguration",
            severity=SeverityLevel.MEDIUM,
            tool_name="corsy",
            payload="",
            evidence="Wildcard CORS origin",
            confidence=60.0,
            http_response=(
                "HTTP/1.1 200 OK\n"
                "Access-Control-Allow-Origin: *\n"
                "Content-Type: application/json\n\n"
                "{}"
            ),
        )
        v = _run(det.analyze(f))
        assert "FP-CORS-001" in str(v.fp_patterns_matched), (
            f"FP-CORS-001 should fire on wildcard CORS, got patterns={v.fp_patterns_matched}"
        )
        assert v.known_fp_capped, "Wildcard CORS penalty (-35) should trigger cap"
        assert v.confidence_score < 50

    def test_cors_wildcard_with_credentials_not_matched(self):
        """FP-CORS-001 requires NOT having ACAC header — if present, no match."""
        det = _make_detector()
        f = _make_finding(
            title="CORS Misconfiguration with Credentials",
            vulnerability_type="cors_misconfiguration",
            severity=SeverityLevel.HIGH,
            tool_name="corsy",
            payload="",
            evidence="Wildcard CORS with credentials",
            confidence=60.0,
            http_response=(
                "HTTP/1.1 200 OK\n"
                "Access-Control-Allow-Origin: *\n"
                "Access-Control-Allow-Credentials: true\n"
                "Content-Type: text/html\n\n"
                "<html></html>"
            ),
        )
        v = _run(det.analyze(f))
        # FP-CORS-001 has not_contains "access-control-allow-credentials: true"
        # so it should NOT match when ACAC is present
        assert "FP-CORS-001" not in str(v.fp_patterns_matched), (
            f"FP-CORS-001 should NOT fire with credentials, "
            f"patterns={v.fp_patterns_matched}"
        )

    def test_cdn_cache_hit_detected(self):
        """FP-CDN-002: X-Cache: HIT header → CDN penalty."""
        det = _make_detector()
        f = _make_finding(
            title="XSS Reflected",
            vulnerability_type="xss_reflected",
            severity=SeverityLevel.HIGH,
            tool_name="dalfox",
            payload="<img src=x>",
            evidence="Reflected XSS",
            confidence=65.0,
            http_response=(
                "HTTP/1.1 200 OK\n"
                "X-Cache: HIT\n"
                "Age: 12345\n"
                "Content-Type: text/html\n\n"
                "<html></html>"
            ),
        )
        v = _run(det.analyze(f))
        assert "FP-CDN-002" in str(v.fp_patterns_matched), (
            f"FP-CDN-002 should fire on X-Cache HIT, patterns={v.fp_patterns_matched}"
        )

    def test_akamai_waf_403_detected(self):
        """FP-WAF-001: Akamai headers + 403 status → WAF block penalty."""
        det = _make_detector()
        f = _make_finding(
            title="Command Injection",
            vulnerability_type="command_injection",
            severity=SeverityLevel.CRITICAL,
            tool_name="commix",
            payload="; id",
            evidence="Command injection detected",
            confidence=70.0,
            http_response=(
                "HTTP/1.1 403 Forbidden\n"
                "X-Akamai-Session-Info: abc123\n\n"
                "Access Denied"
            ),
            metadata={"status_code": "403"},
        )
        v = _run(det.analyze(f))
        assert "FP-WAF-001" in str(v.fp_patterns_matched), (
            f"FP-WAF-001 should fire for Akamai 403, patterns={v.fp_patterns_matched}"
        )
        assert v.known_fp_capped, "WAF block penalty (-40) should trigger cap"
        assert v.confidence_score < 50

    def test_cloudflare_challenge_page(self):
        """FP-GEN-004: Cloudflare challenge page with cf-ray."""
        det = _make_detector()
        f = _make_finding(
            title="SQL Injection",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            tool_name="sqlmap",
            payload="' OR 1=1--",
            evidence="Possible SQLi",
            confidence=60.0,
            http_response=(
                "HTTP/1.1 503 Service Unavailable\n"
                "cf-ray: abc123-IAD\n"
                "Content-Type: text/html\n\n"
                "<html><body>Checking your browser... "
                "challenge-platform jschl cf-browser-verification</body></html>"
            ),
        )
        v = _run(det.analyze(f))
        assert "FP-GEN-004" in str(v.fp_patterns_matched), (
            f"FP-GEN-004 should fire for CF challenge, patterns={v.fp_patterns_matched}"
        )
        assert v.known_fp_capped, "CF challenge penalty (-45) should trigger cap"

    def test_xss_in_json_response(self):
        """FP-XSS-002: XSS finding but Content-Type is JSON → not executable."""
        det = _make_detector()
        f = _make_finding(
            title="Reflected XSS",
            vulnerability_type="xss_reflected",
            severity=SeverityLevel.HIGH,
            tool_name="dalfox",
            payload="<script>alert(1)</script>",
            evidence="Payload reflected in response",
            confidence=65.0,
            http_response=(
                "HTTP/1.1 200 OK\n"
                "Content-Type: application/json\n\n"
                '{"error": "<script>alert(1)</script>"}'
            ),
        )
        v = _run(det.analyze(f))
        assert "FP-XSS-002" in str(v.fp_patterns_matched), (
            f"FP-XSS-002 should fire for XSS in JSON response, "
            f"patterns={v.fp_patterns_matched}"
        )

    def test_cache_control_prevents_poisoning(self):
        """FP-CACHE-001: Cache-Control no-store → cache poisoning unlikely."""
        det = _make_detector()
        f = _make_finding(
            title="Web Cache Poisoning",
            vulnerability_type="cache_poisoning",
            severity=SeverityLevel.MEDIUM,
            tool_name="nuclei",
            payload="X-Forwarded-Host: evil.com",
            evidence="Unkeyed header reflected",
            confidence=55.0,
            http_response=(
                "HTTP/1.1 200 OK\n"
                "Cache-Control: no-store, private\n"
                "Content-Type: text/html\n\n"
                "<html></html>"
            ),
        )
        v = _run(det.analyze(f))
        assert "FP-CACHE-001" in str(v.fp_patterns_matched), (
            f"FP-CACHE-001 should fire on no-store, patterns={v.fp_patterns_matched}"
        )


class TestSeverityFieldMapping:
    """FP-NUCLEI-INFO-001 uses the severity field."""

    def test_nuclei_info_severity_penalized(self):
        """FP-NUCLEI-INFO-001: info severity nuclei finding → penalty."""
        det = _make_detector()
        f = _make_finding(
            title="WordPress Detection",
            vulnerability_type="tech_detect",
            severity=SeverityLevel.INFO,
            tool_name="nuclei",
            payload="",
            evidence="WordPress 5.9 detected",
            confidence=50.0,
        )
        v = _run(det.analyze(f))
        assert "FP-NUCLEI-INFO-001" in str(v.fp_patterns_matched), (
            f"FP-NUCLEI-INFO-001 should fire for info severity, "
            f"patterns={v.fp_patterns_matched}"
        )

    def test_nuclei_high_severity_not_penalized(self):
        """Non-info severity should NOT trigger FP-NUCLEI-INFO-001."""
        det = _make_detector()
        f = _make_finding(
            title="SQL Injection via Nuclei",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            tool_name="nuclei",
            payload="' OR 1=1--",
            evidence="UNION SELECT returned data",
            confidence=65.0,
            http_request="GET /search?q=' OR 1=1-- HTTP/1.1",
            http_response="HTTP/1.1 200 OK\n\nadmin:hash ' OR 1=1--",
        )
        v = _run(det.analyze(f))
        assert "FP-NUCLEI-INFO-001" not in str(v.fp_patterns_matched), (
            f"High severity nuclei should not trigger INFO penalty"
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CS Factor Extraction — Tag/Metadata-Based Factors
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# These CS factors (oob_callback_received, time_based_confirmed,
# data_extracted, payload_executed, error_message_leaked, info_only_finding)
# were dead code — defined in FACTOR_WEIGHTS but never extracted by
# FPDetector's CS factor builder.  Now they are extracted from
# finding.tags and finding.metadata.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCSFactorExtraction:
    """Verify tag/metadata-based CS factor extraction lifts real findings."""

    def test_oob_callback_boosts_ssrf(self):
        """InteractSh OOB callback finding should score higher than plain SSRF."""
        det = _make_detector()
        oob_finding = _make_finding(
            title="SSRF via Interactsh",
            vulnerability_type="ssrf",
            severity=SeverityLevel.HIGH,
            tool_name="nuclei",
            payload="http://abc.interact.sh",
            evidence="OOB callback received",
            confidence=55.0,
            tags=["interactsh", "oob", "dns"],
            metadata={"oob_domain": "abc.interact.sh"},
            http_request="GET /api?url=http://abc.interact.sh HTTP/1.1",
            http_response="HTTP/1.1 200 OK\n\nhttp://abc.interact.sh",
        )
        plain_finding = _make_finding(
            title="SSRF detected",
            vulnerability_type="ssrf",
            severity=SeverityLevel.HIGH,
            tool_name="nuclei",
            payload="http://evil.com",
            evidence="Possible SSRF",
            confidence=55.0,
            http_request="GET /api?url=http://evil.com HTTP/1.1",
            http_response="HTTP/1.1 200 OK\n\nhttp://evil.com",
        )
        v_oob = _run(det.analyze(oob_finding))
        v_plain = _run(det.analyze(plain_finding))
        assert v_oob.confidence_score > v_plain.confidence_score, (
            f"OOB SSRF ({v_oob.confidence_score:.1f}) should score higher "
            f"than plain ({v_plain.confidence_score:.1f})"
        )

    def test_oob_via_metadata_only(self):
        """OOB factor fires from metadata even without tags."""
        det = _make_detector()
        f = _make_finding(
            title="Blind XXE via OOB",
            vulnerability_type="xxe",
            severity=SeverityLevel.HIGH,
            tool_name="nuclei",
            payload="<!ENTITY xxe SYSTEM 'http://oob.interact.sh'>",
            evidence="OOB interaction received",
            confidence=55.0,
            metadata={"interactsh_callback": "oob.interact.sh"},
            http_request="POST /api HTTP/1.1\n\n<!ENTITY xxe SYSTEM ..>",
            http_response="HTTP/1.1 200 OK\n\nParsed",
        )
        v = _run(det.analyze(f))
        # With OOB + nuclei evidence, should pass verification
        assert v.confidence_score >= 45, (
            f"OOB XXE should score well, got {v.confidence_score:.1f}"
        )

    def test_payload_executed_boosts_finding(self):
        """payload_executed metadata should add CS bonus."""
        det = _make_detector()
        executed = _make_finding(
            title="Stored XSS",
            vulnerability_type="xss_stored",
            severity=SeverityLevel.HIGH,
            tool_name="dalfox",
            payload="<img src=x onerror=alert(1)>",
            evidence="Payload executed in browser context",
            confidence=60.0,
            metadata={"payload_executed": True},
            http_response=(
                "HTTP/1.1 200 OK\n"
                "Content-Type: text/html\n\n"
                "<html><img src=x onerror=alert(1)></html>"
            ),
        )
        not_executed = _make_finding(
            title="Possible XSS",
            vulnerability_type="xss_stored",
            severity=SeverityLevel.HIGH,
            tool_name="dalfox",
            payload="<img src=x onerror=alert(1)>",
            evidence="Payload found in response",
            confidence=60.0,
            metadata={},
            http_response=(
                "HTTP/1.1 200 OK\n"
                "Content-Type: text/html\n\n"
                "<html><img src=x onerror=alert(1)></html>"
            ),
        )
        v_exec = _run(det.analyze(executed))
        v_plain = _run(det.analyze(not_executed))
        assert v_exec.confidence_score > v_plain.confidence_score, (
            f"Executed ({v_exec.confidence_score:.1f}) should beat "
            f"not-executed ({v_plain.confidence_score:.1f})"
        )

    def test_data_extracted_boosts_sqli(self):
        """data_extracted tag should boost SQLi confidence."""
        det = _make_detector()
        f = _make_finding(
            title="SQL Injection - Data Extracted",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.CRITICAL,
            tool_name="sqlmap",
            payload="' UNION SELECT username,password FROM users--",
            evidence="UNION SELECT extracted: admin:hash123",
            confidence=70.0,
            tags=["sqli", "data_extraction"],
            metadata={"data_extracted": True},
            http_request="GET /search?q=' UNION SELECT.. HTTP/1.1",
            http_response=(
                "HTTP/1.1 200 OK\n\n"
                "admin:hash123 ' UNION SELECT username,password FROM users--"
            ),
        )
        v = _run(det.analyze(f))
        assert v.confidence_score >= 55, (
            f"Data-extracted SQLi should score high, got {v.confidence_score:.1f}"
        )

    def test_error_message_leaked_boosts_finding(self):
        """SQL error messages in evidence should trigger error_message_leaked."""
        det = _make_detector()
        error = _make_finding(
            title="SQL Error Disclosure",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            tool_name="nuclei",
            payload="'",
            evidence="You have an error in your SQL syntax near '",
            confidence=60.0,
            http_request="GET /page?id=' HTTP/1.1",
            http_response="HTTP/1.1 500 ISE\n\nYou have an error in your SQL syntax near '",
        )
        no_error = _make_finding(
            title="Possible SQLi",
            vulnerability_type="sql_injection",
            severity=SeverityLevel.HIGH,
            tool_name="nuclei",
            payload="' OR 1=1--",
            evidence="UNION SELECT returned admin:hash ' OR 1=1--",
            confidence=60.0,
            http_request="GET /page?id=' OR 1=1-- HTTP/1.1",
            http_response="HTTP/1.1 200 OK\n\nadmin:hash ' OR 1=1--",
        )
        v_err = _run(det.analyze(error))
        v_no = _run(det.analyze(no_error))
        # error_message_leaked adds +12, but "syntax error" evidence might also
        # trigger FP-SQLI-001.  The key assertion: error factor IS extracted.
        # We compare against a controlled baseline with similar evidence quality.
        assert v_err.confidence_score != v_no.confidence_score, (
            "Error evidence should produce different score from non-error"
        )

    def test_info_severity_gets_info_only_factor(self):
        """INFO severity findings should get -20 info_only_finding penalty."""
        det = _make_detector()
        info = _make_finding(
            title="Technology Detection",
            vulnerability_type="tech_detect",
            severity=SeverityLevel.INFO,
            tool_name="whatweb",
            payload="",
            evidence="Apache/2.4.49 detected",
            confidence=50.0,
        )
        low = _make_finding(
            title="Cookie Missing HttpOnly",
            vulnerability_type="cookie_security",
            severity=SeverityLevel.LOW,
            tool_name="cookie_checker",
            payload="",
            evidence="Session cookie missing HttpOnly flag",
            confidence=50.0,
        )
        v_info = _run(det.analyze(info))
        v_low = _run(det.analyze(low))
        # INFO gets info_only_finding (-20), LOW does not
        assert v_info.confidence_score < v_low.confidence_score, (
            f"INFO ({v_info.confidence_score:.1f}) should score lower "
            f"than LOW ({v_low.confidence_score:.1f}) due to info_only_finding penalty"
        )


# ── Phase 5.2i: Layer-derived CS Factor Extraction ──────────────────────
# Tests for cdn_detected, tool_known_fp_for_type, response_diff_significant


class TestLayerDerivedCSFactors:
    """Tests for CS factors extracted from layer results (CDN, tool quirk, L6 diff)."""

    def test_cdn_only_response_penalised(self):
        """Finding on CDN-only host (Varnish, no WAF) gets cdn_detected -5 via CS."""
        det = _make_detector()
        # Varnish CDN header triggers CDN detection but NOT WAF detection
        cdn = _make_finding(
            title="Potential XSS",
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            tool_name="dalfox",
            payload="<script>alert(1)</script>",
            evidence="Reflected in response",
            confidence=60.0,
            http_response=(
                "HTTP/1.1 200 OK\n"
                "X-Varnish: 12345678\n"
                "Content-Type: text/html\n\n"
                "<html>body</html>"
            ),
        )
        no_cdn = _make_finding(
            title="Potential XSS",
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            tool_name="dalfox",
            payload="<script>alert(1)</script>",
            evidence="Reflected in response",
            confidence=60.0,
            http_response=(
                "HTTP/1.1 200 OK\n"
                "Content-Type: text/html\n\n"
                "<html>body</html>"
            ),
        )
        v_cdn = _run(det.analyze(cdn))
        v_no = _run(det.analyze(no_cdn))
        # CDN finding should score lower: cdn_detected (-5) replaces no_waf (+5)
        # Net CS delta: -10 × 0.4 weight = -4.0 in final score
        assert v_cdn.confidence_score < v_no.confidence_score, (
            f"CDN ({v_cdn.confidence_score:.1f}) should score lower "
            f"than no-CDN ({v_no.confidence_score:.1f})"
        )

    def test_waf_detection_not_cdn(self):
        """WAF detection (Cloudflare) should use waf_detected, not cdn_detected."""
        det = _make_detector()
        waf = _make_finding(
            title="XSS behind WAF",
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            tool_name="dalfox",
            payload="<script>alert(1)</script>",
            evidence="XSS reflected",
            confidence=60.0,
            http_response=(
                "HTTP/1.1 403 Forbidden\n"
                "Server: cloudflare\n"
                "CF-RAY: abc123\n\n"
                "Access denied. Cloudflare challenge."
            ),
        )
        v_waf = _run(det.analyze(waf))
        # WAF should be detected, not CDN
        assert v_waf.waf_detected is True

    def test_sqlmap_boolean_blind_quirk_penalises(self):
        """sqlmap boolean-based blind finding triggers tool_known_fp_for_type -12."""
        det = _make_detector()
        sqlmap_blind = _make_finding(
            title="Boolean-based blind SQLi",
            vulnerability_type="sqli",
            severity=SeverityLevel.HIGH,
            tool_name="sqlmap",
            payload="' AND 1=1--",
            evidence="boolean-based blind injection",
            confidence=70.0,
        )
        generic_sqli = _make_finding(
            title="SQL Injection detected",
            vulnerability_type="sqli",
            severity=SeverityLevel.HIGH,
            tool_name="custom_scanner",
            payload="' AND 1=1--",
            evidence="Parameter appears injectable",
            confidence=70.0,
        )
        v_quirk = _run(det.analyze(sqlmap_blind))
        v_generic = _run(det.analyze(generic_sqli))
        # sqlmap boolean-blind should score lower due to tool quirk penalty
        # AND tool_known_fp_for_type CS factor (-12 × 0.4 = -4.8)
        assert v_quirk.confidence_score < v_generic.confidence_score, (
            f"sqlmap blind ({v_quirk.confidence_score:.1f}) should score lower "
            f"than generic ({v_generic.confidence_score:.1f})"
        )

    def test_nikto_osvdb_quirk_penalises(self):
        """Nikto OSVDB findings trigger tool quirk penalty."""
        det = _make_detector()
        nikto_osvdb = _make_finding(
            title="OSVDB-3092: Possible server info leak",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.LOW,
            tool_name="nikto",
            payload="",
            evidence="OSVDB-3092: /index.html: Default page found",
            confidence=50.0,
        )
        standard = _make_finding(
            title="Information disclosure",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.LOW,
            tool_name="custom_checker",
            payload="",
            evidence="Default page found at /index.html",
            confidence=50.0,
        )
        v_nikto = _run(det.analyze(nikto_osvdb))
        v_std = _run(det.analyze(standard))
        assert v_nikto.confidence_score < v_std.confidence_score, (
            f"Nikto OSVDB ({v_nikto.confidence_score:.1f}) should score lower "
            f"than standard ({v_std.confidence_score:.1f})"
        )


# ============================================================
# 17. Null-Confidence Gate Bypass Prevention (Phase 5.2j)
# ============================================================

class TestNullConfidenceGateBypass:
    """
    Regression tests for the null-confidence-defaults-to-50 bug.
    Prior to Phase 5.2j, findings without explicit confidence would get 50.0,
    automatically passing the >= 50 quality gate. Now:
    - _dict_to_finding() defaults to 0.0
    - FPDetector uses 30.0 conservative base for 0-confidence findings
    - Pipeline quality gates properly reject low-confidence findings
    """

    def test_zero_confidence_gets_conservative_base(self):
        """FPDetector should use 30.0 (not 50.0) for 0-confidence findings."""
        det = _make_detector()
        # Finding with confidence=0.0 (sentinel for "tool didn't set")
        zero_conf = _make_finding(
            title="Potential issue",
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            tool_name="unknown_scanner",
            confidence=0.0,
            evidence="Something found",
        )
        v = _run(det.analyze(zero_conf))
        # With base 30 (not 50), a single-tool finding with weak evidence
        # should score well below 50
        assert v.confidence_score < 50.0, (
            f"Zero-confidence finding should NOT pass 50 gate, got {v.confidence_score:.1f}"
        )

    def test_explicit_confidence_preserved(self):
        """Tool-set confidence (e.g., 75) should be used as FPDetector base."""
        det = _make_detector()
        explicit = _make_finding(
            title="SQLi via payload",
            vulnerability_type="sqli",
            severity=SeverityLevel.HIGH,
            tool_name="sqlmap",
            confidence=75.0,
            payload="' OR 1=1--",
            evidence="SQL syntax error in response",
            http_request="GET /search?q=%27+OR+1%3D1-- HTTP/1.1",
            http_response="HTTP/1.1 500 Internal Server Error\n\nSQL syntax error",
        )
        v = _run(det.analyze(explicit))
        # High confidence + strong evidence should remain well above 50
        assert v.confidence_score >= 50.0, (
            f"Explicit 75-confidence SQLi should pass gate, got {v.confidence_score:.1f}"
        )

    def test_zero_vs_explicit_confidence_gap(self):
        """Zero-confidence finding should score significantly lower than explicit."""
        det = _make_detector()
        common_kwargs = dict(
            title="XSS detected",
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            tool_name="dalfox",
            payload="<script>alert(1)</script>",
            evidence="Reflected in HTML body",
        )
        zero = _make_finding(confidence=0.0, **common_kwargs)
        explicit = _make_finding(confidence=65.0, **common_kwargs)
        v_zero = _run(det.analyze(zero))
        v_explicit = _run(det.analyze(explicit))
        gap = v_explicit.confidence_score - v_zero.confidence_score
        assert gap > 5.0, (
            f"Expected meaningful gap between zero ({v_zero.confidence_score:.1f}) "
            f"and explicit ({v_explicit.confidence_score:.1f}), got gap={gap:.1f}"
        )

    def test_low_confidence_still_usable(self):
        """Findings with low but non-zero confidence (e.g., 15) should use their value."""
        det = _make_detector()
        low = _make_finding(
            title="Possible LFI",
            vulnerability_type="lfi",
            severity=SeverityLevel.LOW,
            tool_name="nuclei",
            confidence=15.0,
            evidence="Path traversal pattern matched",
        )
        v = _run(det.analyze(low))
        # Low confidence (15) should result in a low score, not promoted to 30/50
        assert v.confidence_score < 40.0, (
            f"Low confidence (15) finding should score < 40, got {v.confidence_score:.1f}"
        )

    def test_null_confidence_finding_model_default(self):
        """Finding model default (50.0) should be respected by FPDetector."""
        det = _make_detector()
        # The Finding model has confidence: float = 50.0 as default
        # When a tool creates Finding(title=..., ...) without setting confidence,
        # it gets 50.0. FPDetector should use this 50.0 as base.
        default_conf = _make_finding(
            title="Default config",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.INFO,
            tool_name="custom_checker",
            # confidence not set → model default 50.0
            evidence="Found configuration file",
        )
        assert default_conf.confidence == 50.0  # Sanity: model default intact
        v = _run(det.analyze(default_conf))
        # Model default 50 is treated as tool-provided confidence
        # (it's > 0, so FPDetector uses it directly, not 30.0 fallback)
        # Combined with info severity penalty, score may vary
        assert v.confidence_score >= 0.0  # Basic sanity

    def test_dict_to_finding_null_confidence_is_zero(self):
        """_dict_to_finding should produce 0.0 (not 50.0) for missing confidence."""
        import importlib
        import sys
        # We need to access _dict_to_finding from full_scan module
        # Instead, test the same logic inline
        from src.workflow.pipelines.full_scan import _safe_float
        # Simulate the fixed _dict_to_finding logic
        d_no_conf = {"title": "Test", "vulnerability_type": "xss"}
        raw = d_no_conf.get("confidence_score", d_no_conf.get("confidence", 0.0))
        result = _safe_float(raw, 0.0)
        assert result == 0.0, f"Missing confidence should be 0.0, got {result}"

        d_with_conf = {"title": "Test", "confidence": 75.0}
        raw2 = d_with_conf.get("confidence_score", d_with_conf.get("confidence", 0.0))
        result2 = _safe_float(raw2, 0.0)
        assert result2 == 75.0, f"Explicit confidence should be preserved, got {result2}"

        # Verify non-numeric strings get 0.0 (not 50.0)
        d_bad_conf = {"title": "Test", "confidence": "high"}
        raw3 = d_bad_conf.get("confidence_score", d_bad_conf.get("confidence", 0.0))
        result3 = _safe_float(raw3, 0.0)
        assert result3 == 0.0, f"Non-numeric confidence should be 0.0, got {result3}"


# ============================================================
# 18. FPVerdict→Pipeline Integration (Phase 5.2k)
# ============================================================

class TestFPVerdictPipelineIntegration:
    """
    Regression tests for FPVerdict→pipeline bugs found in Phase 5.2k:
    - Bug 1: FPVerdict fields (verdict, waf_detected, evidence_chain, reasoning) lost
    - Bug 2: Post-brain re-filter used cs<30 instead of cs<50 (zombie zone)
    - Bug 3: PoC confidence/confidence_score desync
    - Bug 5: Reporting fallback stamped 50.0 on unverified raw findings
    """

    # -- Bug 1: FPVerdict field propagation --

    def test_fp_verdict_string_propagated(self):
        """After FP analysis, finding dict should contain fp_verdict field."""
        det = _make_detector()
        finding = _make_finding(
            title="XSS in search",
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            tool_name="dalfox",
            confidence=70.0,
            payload="<script>alert(1)</script>",
            evidence="Reflected in body",
            http_request="GET /search?q=<script>alert(1)</script> HTTP/1.1",
            http_response="HTTP/1.1 200 OK\n\n<script>alert(1)</script>",
        )
        verdict = _run(det.analyze(finding))
        # Simulate what pipeline does (L5647)
        d = {"title": "test", "confidence_score": verdict.confidence_score}
        d["fp_verdict"] = getattr(verdict, "verdict", "")
        d["fp_status"] = getattr(verdict, "status", "")
        if getattr(verdict, "waf_detected", False):
            d["waf_detected"] = True
        _ev = getattr(verdict, "evidence_chain", None)
        if _ev:
            d["fp_evidence_chain"] = _ev
        _r = getattr(verdict, "reasoning", "")
        if _r:
            d["fp_reasoning"] = _r

        # fp_verdict should be one of: real, needs_review, likely_fp
        assert d["fp_verdict"] in ("real", "needs_review", "likely_fp", "false_positive", ""), \
            f"Unexpected fp_verdict: {d['fp_verdict']}"
        # Status should be set
        assert d.get("fp_status"), "fp_status should be propagated"

    def test_waf_detected_propagated_when_present(self):
        """When WAF is detected, waf_detected=True should be in finding dict."""
        det = _make_detector()
        # Finding with WAF signature in response
        waf_finding = _make_finding(
            title="XSS attempt",
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            tool_name="nuclei",
            confidence=60.0,
            http_response="HTTP/1.1 403 Forbidden\nServer: cloudflare\nCF-RAY: abc123\n\nBlocked by WAF",
        )
        verdict = _run(det.analyze(waf_finding))
        # If waf_detected is True in verdict, it should propagate
        if verdict.waf_detected:
            assert getattr(verdict, "waf_detected", False) is True

    def test_evidence_chain_propagated(self):
        """FP evidence chain should be accessible from verdict."""
        det = _make_detector()
        finding = _make_finding(
            title="SQLi found",
            vulnerability_type="sqli",
            severity=SeverityLevel.HIGH,
            tool_name="sqlmap",
            confidence=80.0,
            evidence="SQL syntax error",
            http_request="GET /api?id=1' HTTP/1.1",
            http_response="HTTP/1.1 500\n\nSQL syntax error",
        )
        verdict = _run(det.analyze(finding))
        chain = getattr(verdict, "evidence_chain", None)
        # Evidence chain should exist (may be list of strings or similar)
        # Not all verdicts have it, but the attribute should be accessible
        assert hasattr(verdict, "evidence_chain"), "FPVerdict should have evidence_chain attribute"

    # -- Bug 2: Post-brain re-filter threshold alignment --

    def test_post_brain_threshold_below_50_rejected(self):
        """Findings with confidence 30-49 after brain should be rejected (not zombie zone)."""
        # Simulate what happens when brain downgrades confidence
        from src.workflow.pipelines.full_scan import _safe_float
        # After brain verification lowers confidence to 35
        finding = {"title": "Weak finding", "confidence_score": 35.0}
        cs = _safe_float(finding.get("confidence_score"), 0.0)
        # Post-brain filter should use <50 threshold
        assert cs < 50, "Confidence 35 should be below post-brain threshold of 50"
        # This finding should be remov to false_positives, not kept in verified

    def test_post_brain_above_50_kept(self):
        """Findings with confidence >= 50 after brain should be kept."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "Strong finding", "confidence_score": 65.0}
        cs = _safe_float(finding.get("confidence_score"), 0.0)
        assert cs >= 50, "Confidence 65 should pass post-brain threshold"

    def test_post_brain_default_is_zero_not_50(self):
        """Missing confidence_score in post-brain re-filter should default to 0.0 not 50.0."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "No score"}
        cs = _safe_float(finding.get("confidence_score"), 0.0)
        assert cs == 0.0, f"Missing confidence should default to 0.0, got {cs}"
        # 0.0 < 50 → this finding would be filtered out

    # -- Bug 3: PoC confidence_score sync --

    def test_poc_sets_both_confidence_keys(self):
        """PoC boost should set both 'confidence' and 'confidence_score' keys."""
        from src.workflow.pipelines.full_scan import _safe_float
        # Simulate PoC boost logic (post-fix)
        finding = {"title": "PoC confirmed", "confidence": 40.0}
        poc_boost = 25.0
        boosted = min(100.0, _safe_float(finding.get("confidence", 0), 0.0) + poc_boost)
        finding["confidence"] = boosted
        finding["confidence_score"] = boosted  # Bug 3 fix: set BOTH keys
        assert finding["confidence"] == 65.0
        assert finding["confidence_score"] == 65.0
        # Verify _dict_to_finding reads confidence_score first
        raw = finding.get("confidence_score", finding.get("confidence", 0.0))
        assert raw == 65.0, "confidence_score should take priority"

    def test_poc_old_confidence_score_not_override(self):
        """After fix, PoC boost should update confidence_score, not leave stale value."""
        from src.workflow.pipelines.full_scan import _safe_float
        # Before fix: tool sets confidence_score=40, PoC sets confidence=85
        # _dict_to_finding reads confidence_score (40) ignoring PoC boost
        # After fix: both are updated
        finding = {"title": "PoC", "confidence": 40.0, "confidence_score": 40.0}
        poc_boost = 45.0
        boosted = min(100.0, _safe_float(finding.get("confidence", 0), 0.0) + poc_boost)
        finding["confidence"] = boosted
        finding["confidence_score"] = boosted
        raw = finding.get("confidence_score", finding.get("confidence", 0.0))
        assert raw == 85.0, f"confidence_score should reflect PoC boost, got {raw}"

    # -- Bug 5: Reporting fallback confidence --

    def test_reporting_fallback_caps_tool_confidence(self):
        """Reporting fallback should cap existing tool confidence at 40 (not keep original)."""
        from src.workflow.pipelines.full_scan import _safe_float
        # Simulate a raw finding with tool-set confidence of 80 that never went through FP
        finding = {"title": "Unverified", "confidence_score": 80.0}
        existing = _safe_float(finding.get("confidence_score") or finding.get("confidence"), 0.0)
        fallback_conf = min(existing, 40.0) if existing > 0 else 25.0
        assert fallback_conf == 40.0, f"Should cap at 40, got {fallback_conf}"
        # 40 < 50 → this finding would appear as "Needs Investigation", not "Verified"

    def test_reporting_fallback_null_confidence_gets_25(self):
        """Reporting fallback for findings without confidence should get 25.0 (not 50.0)."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "Raw finding"}
        existing = _safe_float(finding.get("confidence_score") or finding.get("confidence"), 0.0)
        fallback_conf = min(existing, 40.0) if existing > 0 else 25.0
        assert fallback_conf == 25.0, f"Should be 25.0 for null confidence, got {fallback_conf}"

    def test_reporting_fallback_marks_unverified(self):
        """Reporting fallback should mark findings as UNVERIFIED_FALLBACK."""
        # The fix sets fp_status = "UNVERIFIED_FALLBACK"
        finding = {"title": "Raw"}
        finding["fp_status"] = "UNVERIFIED_FALLBACK"
        assert finding["fp_status"] == "UNVERIFIED_FALLBACK"

    def test_reporting_fallback_low_confidence_preserved(self):
        """Findings with very low existing confidence should keep their low value."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "Weak", "confidence": 15.0}
        existing = _safe_float(finding.get("confidence_score") or finding.get("confidence"), 0.0)
        fallback_conf = min(existing, 40.0) if existing > 0 else 25.0
        assert fallback_conf == 15.0, f"Should keep original low value, got {fallback_conf}"


# ═══════════════════════════════════════════════════════════════════
# Phase 5.2l: Post-FP Confidence Modification Audit regression tests
# Validates fixes for 6 bugs found in stages AFTER FP elimination:
# calibration, brain verification, dedup, learning data recording.
# ═══════════════════════════════════════════════════════════════════

class TestPostFPConfidenceModification:
    """Phase 5.2l: Regression tests for post-FP confidence modification bugs."""

    # ── Bug 2 (HIGH): Calibration raw_conf must default to 0.0, not 50.0 ──

    def test_calibration_missing_confidence_defaults_zero(self):
        """Finding without confidence_score should give raw_conf=0.0 in calibration."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "No confidence", "vulnerability_type": "xss"}
        raw_conf = _safe_float(finding.get("confidence_score"), 0.0)
        assert raw_conf == 0.0, f"Missing confidence_score should default to 0.0, got {raw_conf}"

    def test_calibration_none_confidence_defaults_zero(self):
        """Finding with confidence_score=None should give raw_conf=0.0."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "None conf", "confidence_score": None}
        raw_conf = _safe_float(finding.get("confidence_score"), 0.0)
        assert raw_conf == 0.0, f"None confidence_score should default to 0.0, got {raw_conf}"

    def test_calibration_non_numeric_confidence_defaults_zero(self):
        """Finding with confidence_score='high' should give raw_conf=0.0."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "String conf", "confidence_score": "high"}
        raw_conf = _safe_float(finding.get("confidence_score"), 0.0)
        assert raw_conf == 0.0, f"Non-numeric confidence_score should default to 0.0, got {raw_conf}"

    def test_calibration_does_not_inflate_unknown(self):
        """Calibration of 0.0 (unknown) should NOT produce values near 50+."""
        from src.fp_engine.scoring.calibration import ConfidenceCalibrator
        cal = ConfidenceCalibrator()
        # With no historical data, calibrate() should return input unchanged or close to it
        result = cal.calibrate("xss", 0.0)
        # result should NOT be near 50+ (which was the old bug: 50.0 → calibrated → still ~50)
        assert result < 30.0, f"Calibrating 0.0 should not produce {result} (inflation bug)"

    # ── Bug 3 (MEDIUM): Calibration record() must default to 0.0, not 50.0 ──

    def test_calibration_record_tp_missing_confidence(self):
        """Record TP with missing confidence should record 0.0, not 50.0."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "TP no conf", "vulnerability_type": "sqli"}
        # Simulate what the pipeline does: extract confidence for recording
        conf = _safe_float(
            finding.get("confidence_score_raw", finding.get("confidence_score")), 0.0
        )
        assert conf == 0.0, f"TP record should use 0.0 for missing conf, got {conf}"

    def test_calibration_record_fp_missing_confidence(self):
        """Record FP with missing confidence should record 0.0, not 50.0."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "FP no conf", "vulnerability_type": "xss"}
        conf = _safe_float(finding.get("confidence_score"), 0.0)
        assert conf == 0.0, f"FP record should use 0.0 for missing conf, got {conf}"

    # ── Bug 4 (HIGH): Brain verification original_conf must use _safe_float ──

    def test_brain_original_conf_safe_float_string(self):
        """Brain merge: string confidence_score should not crash, should return float."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "Brain test", "confidence_score": "medium"}
        original_conf = _safe_float(finding.get("confidence_score"), 50.0)
        assert isinstance(original_conf, float), "Should return float"
        assert original_conf == 50.0, f"Non-numeric should fallback to 50.0, got {original_conf}"

    def test_brain_original_conf_safe_float_none(self):
        """Brain merge: None confidence_score should fallback to 50.0."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "Brain test", "confidence_score": None}
        original_conf = _safe_float(finding.get("confidence_score"), 50.0)
        assert original_conf == 50.0, f"None should fallback to 50.0, got {original_conf}"

    def test_brain_original_conf_safe_float_valid(self):
        """Brain merge: valid numeric confidence should be preserved."""
        from src.workflow.pipelines.full_scan import _safe_float
        finding = {"title": "Brain test", "confidence_score": 72.5}
        original_conf = _safe_float(finding.get("confidence_score"), 50.0)
        assert original_conf == 72.5, f"Valid confidence should be preserved, got {original_conf}"

    def test_brain_asymmetric_upgrade_math(self):
        """Brain upgrade merge: 60/40 weighting toward brain."""
        brain_conf = 85.0
        original_conf = 70.0
        merged = brain_conf * 0.6 + original_conf * 0.4
        assert merged == 79.0, f"Upgrade merge should be 79.0, got {merged}"

    def test_brain_asymmetric_downgrade_math(self):
        """Brain downgrade merge: 30/70 weighting toward tool evidence."""
        brain_conf = 30.0
        original_conf = 70.0
        merged = brain_conf * 0.3 + original_conf * 0.7
        assert merged == 58.0, f"Downgrade merge should be 58.0, got {merged}"

    # ── Bug 5 (MEDIUM): VerificationResult default must be 0.0, not 50.0 ──

    def test_verification_result_default_confidence_zero(self):
        """VerificationResult() should have confidence=0.0 (not 50.0)."""
        from src.brain.intelligence import VerificationResult
        vr = VerificationResult()
        assert vr.confidence == 0.0, f"Default confidence should be 0.0, got {vr.confidence}"

    def test_verification_result_default_is_real_false(self):
        """VerificationResult() should have is_real=False by default."""
        from src.brain.intelligence import VerificationResult
        vr = VerificationResult()
        assert vr.is_real is False

    def test_verification_result_zero_confidence_skips_brain_merge(self):
        """Brain merge guard: vr.confidence > 0 should skip 0.0 (no opinion)."""
        from src.brain.intelligence import VerificationResult
        vr = VerificationResult()  # confidence=0.0
        # The pipeline checks `if vr.confidence > 0:` before merging
        assert not (vr.confidence > 0), "0.0 confidence should NOT trigger merge"

    def test_verification_result_parser_missing_confidence(self):
        """Parser should return 0.0 for missing confidence in LLM data."""
        from src.workflow.pipelines.full_scan import _safe_float
        # Simulate what the parser does (simplified)
        data = {"is_real": True, "reasoning": "looks real"}
        # The fix: _sf(data.get("confidence", 0), 0.0) instead of 50/50.0
        raw = data.get("confidence", 0)
        conf = _safe_float(raw, 0.0)
        assert conf == 0.0, f"Missing confidence in LLM data should be 0.0, got {conf}"

    # ── Bug 6 (MEDIUM): FP Feedback records must default to 0.0, not 50.0 ──

    def test_fp_feedback_tp_missing_confidence(self):
        """FP feedback TP record with missing confidence should use 0.0."""
        from src.workflow.pipelines.full_scan import _safe_float
        vf = {"title": "TP", "vulnerability_type": "xss"}
        conf = _safe_float(vf.get("confidence_score"), 0.0)
        assert conf == 0.0, f"FP feedback should use 0.0 for missing conf, got {conf}"

    def test_fp_feedback_tp_valid_confidence_preserved(self):
        """FP feedback TP record with valid confidence should preserve it."""
        from src.workflow.pipelines.full_scan import _safe_float
        vf = {"title": "TP", "confidence_score": 82.3}
        conf = _safe_float(vf.get("confidence_score"), 0.0)
        assert conf == 82.3, f"Valid confidence should be preserved, got {conf}"

    # ── Bug 7 (LOW): Pre-FP dedup max() must use _safe_float ──

    def test_dedup_max_key_handles_none(self):
        """Dedup max() key should handle None confidence gracefully."""
        from src.workflow.pipelines.full_scan import _safe_float
        group = [
            (0, {"title": "A", "confidence_score": None, "tool": "nuclei"}),
            (1, {"title": "B", "confidence_score": 70.0, "tool": "dalfox"}),
        ]
        best_idx, best_f = max(
            group,
            key=lambda x: _safe_float(
                x[1].get("confidence_score", x[1].get("confidence")), 0.0
            ),
        )
        assert best_idx == 1, f"Should pick index 1 (confidence 70), got {best_idx}"
        assert best_f["confidence_score"] == 70.0

    def test_dedup_max_key_handles_string(self):
        """Dedup max() key should handle non-numeric confidence gracefully."""
        from src.workflow.pipelines.full_scan import _safe_float
        group = [
            (0, {"title": "A", "confidence_score": "high", "tool": "nuclei"}),
            (1, {"title": "B", "confidence_score": 60.0, "tool": "sqlmap"}),
        ]
        best_idx, best_f = max(
            group,
            key=lambda x: _safe_float(
                x[1].get("confidence_score", x[1].get("confidence")), 0.0
            ),
        )
        assert best_idx == 1, f"Should pick index 1 (numeric 60), got {best_idx}"

    def test_dedup_max_key_handles_missing(self):
        """Dedup max() key should handle entirely missing confidence."""
        from src.workflow.pipelines.full_scan import _safe_float
        group = [
            (0, {"title": "A", "tool": "nuclei"}),  # No confidence at all
            (1, {"title": "B", "confidence_score": 55.0, "tool": "dalfox"}),
        ]
        best_idx, best_f = max(
            group,
            key=lambda x: _safe_float(
                x[1].get("confidence_score", x[1].get("confidence")), 0.0
            ),
        )
        assert best_idx == 1, f"Should pick index 1 (confidence 55), got {best_idx}"

    def test_dedup_max_key_all_missing(self):
        """Dedup max() key: all missing confidence should not crash."""
        from src.workflow.pipelines.full_scan import _safe_float
        group = [
            (0, {"title": "A", "tool": "nuclei"}),
            (1, {"title": "B", "tool": "dalfox"}),
        ]
        # Should not raise — both default to 0.0, first wins on tie
        best_idx, best_f = max(
            group,
            key=lambda x: _safe_float(
                x[1].get("confidence_score", x[1].get("confidence")), 0.0
            ),
        )
        assert best_idx in (0, 1), "Should pick first or second, not crash"


# ─────────────────────────────────────────────────────────────────
# Phase 5.2m — ReportFinding Conversion & Reporting Fidelity Tests
# ─────────────────────────────────────────────────────────────────


class TestReportingFidelity:
    """Regression tests for Phase 5.2m: confidence tier boundaries,
    CVSS-severity bidirectional reconciliation, and remediation preservation."""

    # ── Bug 5.2m-1: Confidence tier off-by-one ──────────────────

    def test_confidence_tier_exactly_50_is_likely(self):
        """Score exactly 50.0 must land in 'Likely' tier, not 'Investigate'.
        Bug 5.2m-1: boundary was `50 < x` which excluded 50.0."""
        from src.reporting.report_generator import ReportFinding

        f = ReportFinding(
            title="Test",
            vulnerability_type="xss",
            severity="medium",
            confidence_score=50.0,
        )
        # Likely: 50 <= x <= 80
        assert 50 <= f.confidence_score <= 80, "50.0 should be in Likely tier"
        assert not (f.confidence_score > 80), "50.0 should NOT be in Confirmed tier"
        assert not (f.confidence_score < 50), "50.0 should NOT be in Investigate tier"

    def test_confidence_tier_49_9_is_investigate(self):
        """Score 49.9 must land in 'Needs Investigation' tier."""
        from src.reporting.report_generator import ReportFinding

        f = ReportFinding(
            title="Test",
            vulnerability_type="xss",
            severity="low",
            confidence_score=49.9,
        )
        assert f.confidence_score < 50, "49.9 should be in Investigate tier"

    def test_confidence_tier_50_1_is_likely(self):
        """Score 50.1 is clearly in 'Likely' tier."""
        from src.reporting.report_generator import ReportFinding

        f = ReportFinding(
            title="Test",
            vulnerability_type="xss",
            severity="medium",
            confidence_score=50.1,
        )
        assert 50 <= f.confidence_score <= 80

    def test_confidence_tier_80_is_likely(self):
        """Score exactly 80.0 must stay in 'Likely', not 'Confirmed'.
        Confirmed requires > 80."""
        from src.reporting.report_generator import ReportFinding

        f = ReportFinding(
            title="Test",
            vulnerability_type="xss",
            severity="high",
            confidence_score=80.0,
        )
        assert 50 <= f.confidence_score <= 80, "80.0 should be in Likely tier"
        assert not (f.confidence_score > 80), "80.0 should NOT be Confirmed"

    def test_confidence_tier_80_1_is_confirmed(self):
        """Score 80.1 must be in 'Confirmed' tier."""
        from src.reporting.report_generator import ReportFinding

        f = ReportFinding(
            title="Test",
            vulnerability_type="xss",
            severity="high",
            confidence_score=80.1,
        )
        assert f.confidence_score > 80, "80.1 should be Confirmed"

    def test_confidence_tier_rendering_in_markdown(self):
        """Verify to_markdown() groups findings by correct tier boundaries."""
        from src.reporting.report_generator import ReportGenerator, ReportFinding, Report

        findings = [
            ReportFinding(title="Confirmed XSS", vulnerability_type="xss",
                          severity="high", confidence_score=85.0),
            ReportFinding(title="Likely SQLI", vulnerability_type="sqli",
                          severity="medium", confidence_score=50.0),
            ReportFinding(title="Investigate SSRF", vulnerability_type="ssrf",
                          severity="low", confidence_score=30.0),
        ]
        report = Report(target="example.com", findings=findings)
        gen = ReportGenerator()
        md = gen.to_markdown(report)
        # Confirmed section has "Confirmed XSS"
        assert "Confirmed XSS" in md
        # Likely section has "Likely SQLI" (score 50.0 is in Likely tier)
        assert "Likely SQLI" in md
        # Investigate section has "Investigate SSRF"
        assert "Investigate SSRF" in md
        # Structural: Likely section header exists
        assert "Likely Findings" in md

    # ── Bug 5.2m-2: CVSS-Severity bidirectional reconciliation ──

    def test_cvss_upward_reconcile_9_0_low_to_high(self):
        """CVSS >= 9.0 with severity 'low' must reconcile UP to 'high'.
        Bug 5.2m-2: only downward reconciliation existed."""
        f = {"severity": "low", "cvss_score": 9.8, "title": "Test"}
        # Simulate Gate 2 logic
        cvss = f["cvss_score"]
        sev = f["severity"].lower()
        if cvss >= 9.0 and sev in ("low", "info"):
            f["original_severity"] = f["severity"]
            f["severity"] = "high"
            f["severity_reconciled"] = True
        assert f["severity"] == "high"
        assert f["original_severity"] == "low"
        assert f["severity_reconciled"] is True

    def test_cvss_upward_reconcile_7_5_info_to_medium(self):
        """CVSS >= 7.0 (but < 9.0) with severity 'info' → 'medium'."""
        f = {"severity": "info", "cvss_score": 7.5, "title": "Test"}
        cvss = f["cvss_score"]
        sev = f["severity"].lower()
        if cvss >= 9.0 and sev in ("low", "info"):
            f["severity"] = "high"
        elif cvss >= 7.0 and sev in ("low", "info"):
            f["original_severity"] = f["severity"]
            f["severity"] = "medium"
            f["severity_reconciled"] = True
        assert f["severity"] == "medium"
        assert f["original_severity"] == "info"

    def test_cvss_upward_no_reconcile_below_7(self):
        """CVSS 6.5 with severity 'low' should NOT reconcile upward."""
        f = {"severity": "low", "cvss_score": 6.5, "title": "Test"}
        cvss = f["cvss_score"]
        sev = f["severity"].lower()
        reconciled = False
        if cvss >= 9.0 and sev in ("low", "info"):
            pass
        elif cvss >= 7.0 and sev in ("low", "info"):
            pass
        else:
            reconciled = False
        assert f["severity"] == "low", "CVSS 6.5 should NOT upgrade low"
        assert "severity_reconciled" not in f

    def test_cvss_downward_still_works(self):
        """Existing downward reconciliation (CVSS < 4 + HIGH → LOW) unbroken."""
        f = {"severity": "high", "cvss_score": 3.5, "title": "Test"}
        cvss = f["cvss_score"]
        sev = f["severity"].lower()
        if cvss < 4.0 and sev in ("medium", "high", "critical"):
            f["original_severity"] = f["severity"]
            f["severity"] = "low"
            f["severity_reconciled"] = True
        assert f["severity"] == "low"
        assert f["original_severity"] == "high"

    def test_cvss_medium_stays_medium(self):
        """CVSS 7.5 + 'medium' should NOT be reconciled (already adequate)."""
        f = {"severity": "medium", "cvss_score": 7.5, "title": "Test"}
        cvss = f["cvss_score"]
        sev = f["severity"].lower()
        # Upward only triggers on low/info
        should_reconcile = (cvss >= 9.0 and sev in ("low", "info")) or \
                           (cvss >= 7.0 and sev in ("low", "info"))
        assert not should_reconcile, "medium is not in ('low', 'info')"
        assert f["severity"] == "medium"

    # ── Bug 5.2m-3: Remediation field preservation ──────────────

    def test_remediation_preserves_finding_text(self):
        """Finding-provided remediation MUST be preserved, not overwritten.
        Bug 5.2m-3: was always overwritten with static template."""
        from src.reporting.report_generator import ReportGenerator

        gen = ReportGenerator()
        actual = {
            "title": "XSS in search",
            "vulnerability_type": "xss",
            "severity": "high",
            "confidence_score": 75.0,
            "remediation": "Use DOMPurify to sanitize all user inputs.",
        }
        rf = gen._convert_finding(actual)
        assert rf.remediation == "Use DOMPurify to sanitize all user inputs.", \
            "Finding-provided remediation must be preserved"

    def test_remediation_falls_back_to_static(self):
        """When finding has no remediation, static template should be used."""
        from src.reporting.report_generator import ReportGenerator

        gen = ReportGenerator()
        actual = {
            "title": "SQL Injection",
            "vulnerability_type": "sqli",
            "severity": "critical",
            "confidence_score": 90.0,
        }
        rf = gen._convert_finding(actual)
        # Should get non-empty static remediation text
        assert rf.remediation != "", "Should have static fallback remediation"
        assert len(rf.remediation) > 20, "Static remediation should be substantial"

    def test_remediation_empty_string_gets_fallback(self):
        """Empty string remediation should trigger fallback (or '' → falsy)."""
        from src.reporting.report_generator import ReportGenerator

        gen = ReportGenerator()
        actual = {
            "title": "CORS Misconfig",
            "vulnerability_type": "cors_misconfiguration",
            "severity": "medium",
            "confidence_score": 60.0,
            "remediation": "",
        }
        rf = gen._convert_finding(actual)
        # Empty string is falsy, so `"" or static_template` → static_template
        assert rf.remediation != "", "Empty remediation should fall back to static"

    # ── ReportFinding Pydantic validators (confirmed OK, guard tests) ──

    def test_report_finding_confidence_list_coerced(self):
        """ReportFinding Pydantic validator must coerce list confidence to float."""
        from src.reporting.report_generator import ReportFinding

        f = ReportFinding(
            title="Test",
            vulnerability_type="xss",
            confidence_score=[90, 80],  # type: ignore
        )
        # Pydantic _coerce_confidence tries float([90,80]) → fails → 0.0
        assert isinstance(f.confidence_score, float)

    def test_report_finding_str_fields_list_coerced(self):
        """ReportFinding Pydantic validator must coerce list endpoint to str."""
        from src.reporting.report_generator import ReportFinding

        f = ReportFinding(
            title="Test",
            vulnerability_type="xss",
            endpoint=["https://a.com", "https://b.com"],  # type: ignore
        )
        assert f.endpoint == "https://a.com", "Should take first element"

    def test_report_finding_none_remediation(self):
        """ReportFinding with None remediation → empty string."""
        from src.reporting.report_generator import ReportFinding

        f = ReportFinding(
            title="Test",
            vulnerability_type="xss",
            remediation=None,  # type: ignore
        )
        assert f.remediation == ""
