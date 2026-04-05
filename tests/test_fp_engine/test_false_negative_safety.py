"""
False Negative Safety Net Tests

GOAL: After aggressive FP elimination (100% catch rate on 436 GitLab FPs),
verify that REAL vulnerabilities with genuine evidence still pass through
the scoring pipeline with confidence > 50.

These tests protect against accidental false negatives introduced by:
- FP patterns being too broad
- ConfidenceScorer being too harsh
- Pipeline threshold being too high

Tests are organised in three tiers:
1. RealFindings — strong evidence → MUST score ≥ 50
2. Borderline   — weak evidence   → understood to score 30-55 (OK)
3. PatternSafety — real findings MUST NOT match any FP pattern with penalty ≤ -20
"""

from __future__ import annotations

import pytest

from src.fp_engine.scoring.confidence_scorer import (
    ConfidenceScorer,
    VULN_TYPE_BASE_SCORES,
)
from src.fp_engine.patterns.known_fps import KnownFPMatcher


# ────────────────────────── helpers ──────────────────────────

def _cs() -> ConfidenceScorer:
    return ConfidenceScorer()


def _matcher() -> KnownFPMatcher:
    return KnownFPMatcher()


# ────────────────────────────────────────────────────────────
# TIER 1 — Real Findings With Strong Evidence (MUST ≥ 50)
# ────────────────────────────────────────────────────────────

class TestRealFindings_ConfidenceScorer:
    """
    Real vulnerabilities with solid exploitation evidence.
    Every test asserts CS score ≥ 50.
    """

    def test_sqli_error_based_single_tool(self):
        """sqlmap: error-based SQLi with data extraction."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli_error",
            multi_tool_count=1,
            payload_executed=True,
            error_leaked=True,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"Error-based SQLi got {bd.final_score}"

    def test_sqli_error_with_extraction(self):
        """sqlmap: error-based SQLi + actual data extracted."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli",
            multi_tool_count=1,
            payload_executed=True,
            data_extracted=True,
            error_leaked=True,
            has_evidence=True,
        )
        assert bd.final_score >= 70, f"SQLi with extraction got {bd.final_score}"

    def test_blind_sqli_time_confirmed(self):
        """sqlmap: time-based blind SQLi confirmed."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli_blind",
            multi_tool_count=1,
            time_based_confirmed=True,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"Blind SQLi got {bd.final_score}"

    def test_xss_reflected_unencoded(self):
        """dalfox: reflected XSS, payload in response unencoded."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="xss_reflected",
            multi_tool_count=1,
            payload_reflected=True,
            payload_encoded=False,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"Reflected XSS got {bd.final_score}"

    def test_xss_stored_payload_executed(self):
        """Stored XSS: payload persisted and executed on view."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="xss_stored",
            multi_tool_count=1,
            payload_executed=True,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"Stored XSS got {bd.final_score}"

    def test_ssrf_oob_callback(self):
        """ssrfmap: SSRF confirmed via OOB callback."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="ssrf",
            multi_tool_count=1,
            oob_callback=True,
            has_evidence=True,
        )
        assert bd.final_score >= 60, f"SSRF OOB got {bd.final_score}"

    def test_rce_payload_executed(self):
        """commix: command injection with executed output."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="rce",
            multi_tool_count=1,
            payload_executed=True,
            data_extracted=True,
            has_evidence=True,
        )
        assert bd.final_score >= 70, f"RCE executed got {bd.final_score}"

    def test_ssti_template_evaluated(self):
        """tplmap: SSTI — template expression evaluated."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="ssti",
            multi_tool_count=1,
            payload_executed=True,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"SSTI got {bd.final_score}"

    def test_idor_data_extracted(self):
        """idor_checker: cross-user data access confirmed."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="idor",
            multi_tool_count=1,
            data_extracted=True,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"IDOR data got {bd.final_score}"

    def test_xxe_oob(self):
        """XXE with OOB data exfiltration."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="xxe",
            multi_tool_count=1,
            oob_callback=True,
            data_extracted=True,
            has_evidence=True,
        )
        assert bd.final_score >= 70, f"XXE OOB got {bd.final_score}"

    def test_lfi_data_extracted(self):
        """LFI: /etc/passwd contents returned."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="lfi",
            multi_tool_count=1,
            data_extracted=True,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"LFI data got {bd.final_score}"

    def test_auth_bypass_confirmed(self):
        """auth_bypass_checker: accessed admin panel without creds."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="auth_bypass",
            multi_tool_count=1,
            payload_executed=True,
            data_extracted=True,
            has_evidence=True,
        )
        assert bd.final_score >= 60, f"Auth bypass got {bd.final_score}"

    def test_subdomain_takeover_confirmed(self):
        """Dangling CNAME → successful claim proof."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="subdomain_takeover",
            multi_tool_count=1,
            payload_executed=True,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"Subtakeover got {bd.final_score}"

    def test_multi_tool_xss(self):
        """Both dalfox AND xsstrike confirm reflected XSS."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="xss_reflected",
            multi_tool_count=2,
            payload_reflected=True,
            payload_encoded=False,
            has_evidence=True,
        )
        assert bd.final_score >= 70, f"Multi-tool XSS got {bd.final_score}"

    def test_multi_tool_sqli(self):
        """sqlmap AND nuclei confirm SQL injection."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli",
            multi_tool_count=2,
            payload_executed=True,
            data_extracted=True,
            has_evidence=True,
        )
        assert bd.final_score >= 80, f"Multi-tool SQLi got {bd.final_score}"

    def test_open_redirect_confirmed(self):
        """openredirex: redirect to attacker domain confirmed."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="open_redirect",
            multi_tool_count=1,
            payload_reflected=True,
            payload_encoded=False,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"Open redirect got {bd.final_score}"

    def test_cors_with_credentials(self):
        """corsy: CORS with ACAC + origin reflected."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="cors",
            multi_tool_count=1,
            payload_reflected=True,
            payload_encoded=False,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"CORS ACAC got {bd.final_score}"

    def test_http_smuggling_confirmed(self):
        """HTTP request smuggling with desync proof."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="http_smuggling",
            multi_tool_count=1,
            payload_executed=True,
            response_diff_significant=True,
            has_evidence=True,
        )
        assert bd.final_score >= 60, f"Smuggling got {bd.final_score}"

    def test_crlf_injection_confirmed(self):
        """crlfuzz: header injection with injected header in response."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="crlf",
            multi_tool_count=1,
            payload_reflected=True,
            payload_encoded=False,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"CRLF got {bd.final_score}"


# ────────────────────────────────────────────────────────────
# Brain-Boosted Scenarios — confirm brain never drags real below 50
# ────────────────────────────────────────────────────────────

class TestBrainBoosted_ConfidenceScorer:
    """When brain confirms a real finding, score must stay well above 50."""

    def test_brain_confirms_sqli(self):
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli",
            multi_tool_count=1,
            payload_executed=True,
            brain_primary_confirms=True,
            has_evidence=True,
        )
        assert bd.final_score >= 70, f"Brain+SQLi got {bd.final_score}"

    def test_brain_denies_but_evidence_strong(self):
        """Brain disagrees, but data extracted + multi-tool → should still pass."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli",
            multi_tool_count=2,
            payload_executed=True,
            data_extracted=True,
            brain_primary_confirms=False,
            has_evidence=True,
        )
        assert bd.final_score >= 50, f"Brain-deny+strong-evidence got {bd.final_score}"

    def test_both_brains_confirm(self):
        bd = _cs().calculate_from_finding_context(
            vuln_type="xss_reflected",
            multi_tool_count=1,
            payload_reflected=True,
            payload_encoded=False,
            brain_primary_confirms=True,
            brain_secondary_confirms=True,
            has_evidence=True,
        )
        assert bd.final_score >= 70, f"Both-brains+XSS got {bd.final_score}"


# ────────────────────────────────────────────────────────────
# Worst-Case Single-Tool (no brain, no multi)
# ────────────────────────────────────────────────────────────

class TestWorstCaseSingleTool:
    """Single tool, no brain, but HAS genuine execution evidence."""

    def test_single_tool_sqli_with_execution(self):
        """Minimum viable real SQLi: one tool, executed, no brain."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli",
            multi_tool_count=1,
            payload_executed=True,
            has_evidence=True,
        )
        assert bd.final_score >= 50, (
            f"Single-tool SQLi with execution should pass (got {bd.final_score})"
        )

    def test_single_tool_xss_unencoded_reflection(self):
        bd = _cs().calculate_from_finding_context(
            vuln_type="xss_reflected",
            multi_tool_count=1,
            payload_reflected=True,
            payload_encoded=False,
        )
        assert bd.final_score >= 50, (
            f"Single-tool XSS with unencoded reflection should pass (got {bd.final_score})"
        )

    def test_single_tool_ssrf_oob(self):
        bd = _cs().calculate_from_finding_context(
            vuln_type="ssrf",
            multi_tool_count=1,
            oob_callback=True,
        )
        assert bd.final_score >= 50

    def test_single_tool_rce_executed(self):
        bd = _cs().calculate_from_finding_context(
            vuln_type="rce",
            multi_tool_count=1,
            payload_executed=True,
        )
        assert bd.final_score >= 50

    def test_single_tool_blind_sqli_time(self):
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli_blind",
            multi_tool_count=1,
            time_based_confirmed=True,
        )
        assert bd.final_score >= 50


# ────────────────────────────────────────────────────────────
# TIER 2 — Borderline Findings (understood to be 30-55)
# ────────────────────────────────────────────────────────────

class TestBorderlineFindings:
    """
    Findings with partial evidence. We document their expected range
    so future changes don't accidentally promote OR suppress them.
    """

    def test_tech_cve_with_version_no_exploit(self):
        """Version matches CVE, but no exploitation evidence.
        Expected to be near 40; below 50 is OK — requires human review."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="",  # default base 50
            multi_tool_count=1,
            known_vuln_pattern=True,
            has_evidence=True,
        )
        # Should be above "fp" tier (30+) but below pipeline threshold
        assert 25 <= bd.final_score <= 60, f"Version-CVE got {bd.final_score}"

    def test_info_disclosure_no_evidence(self):
        """Nikto finds admin path but no content proof."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="information_disclosure",
            multi_tool_count=1,
            has_payload=False,
        )
        # Known to be low — info_disclosure base is 42, single_tool -15, no_payload -10
        assert 10 <= bd.final_score <= 40, f"Info-disc no evidence got {bd.final_score}"

    def test_dom_xss_single_tool_no_execution(self):
        """DOM XSS detected via regex, not confirmed in browser."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="xss_dom",
            multi_tool_count=1,
            has_payload=False,
        )
        # xss_dom base is 48, -15 -10 = 23  → should be low
        assert 10 <= bd.final_score <= 40, f"DOM XSS no exec got {bd.final_score}"

    def test_cors_without_acac(self):
        """Origin reflected but no Access-Control-Allow-Credentials."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="cors",
            multi_tool_count=1,
            payload_reflected=True,
            payload_encoded=True,  # reflected but encoded = weaker signal
        )
        # cors base 48 -15 -8 = 25, within known FP range
        assert 15 <= bd.final_score <= 45, f"CORS no ACAC got {bd.final_score}"

    def test_header_finding_always_true(self):
        """Missing security header — almost always true, just low severity."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="missing_security_header",
            multi_tool_count=1,
            has_evidence=True,
        )
        # Base 65 -15 +10 = 60 — should pass pipeline
        assert bd.final_score >= 50, f"Missing header got {bd.final_score}"

    def test_cookie_finding(self):
        """Insecure cookie — usually true, just informational."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="cookie_security",
            multi_tool_count=1,
            has_evidence=True,
        )
        # Base 60 -15 +10 = 55 — should pass
        assert bd.final_score >= 50, f"Cookie finding got {bd.final_score}"


# ────────────────────────────────────────────────────────────
# TIER 3 — FP Pattern Safety (Real Findings ≠ FP Match)
# ────────────────────────────────────────────────────────────

class TestRealFindings_NoFPPatternMatch:
    """
    Realistically-structured real findings MUST NOT match any FP pattern
    with total_penalty ≤ -20 (which would trigger Guard 3 ceiling).
    """

    def test_real_sqli_union_not_flagged(self):
        """Real UNION-based SQLi from sqlmap — has extraction evidence."""
        finding = {
            "vuln_type": "sql_injection",
            "tool": "sqlmap",
            "evidence": "UNION SELECT 1,username,password FROM users -- extracted 5 rows",
            "status_code": "200",
            "url": "https://target.com/search?q=test",
            "payload": "' UNION SELECT 1,2,3--",
        }
        result = _matcher().check(finding)
        heavy_penalty = result["total_penalty"] <= -20
        assert not heavy_penalty, (
            f"Real SQLi UNION matched FP pattern(s) with penalty {result['total_penalty']}: "
            f"{[m.id for m in result['matches']]}"
        )

    def test_real_sqli_error_not_flagged(self):
        """Error-based SQLi WITH extraction — not a false positive."""
        finding = {
            "vuln_type": "sql_injection",
            "tool": "sqlmap",
            "evidence": "syntax error near 'test' AND extractvalue(1,concat(0x7e,version())) returned 5.7.38",
            "status_code": "200",
            "url": "https://target.com/api/search",
        }
        result = _matcher().check(finding)
        # FP-SQLI-001 requires NOT_CONTAINS "UNION SELECT" AND NOT_CONTAINS "extractvalue"
        # This evidence CONTAINS extractvalue → rule fails → no match
        assert result["total_penalty"] > -20, (
            f"Real error SQLi got penalty {result['total_penalty']}"
        )

    def test_real_xss_not_cloudflare(self):
        """Genuine DOM XSS — NOT in Cloudflare challenge script."""
        finding = {
            "vuln_type": "xss_dom",
            "tool": "js_analyzer",
            "title": "DOM XSS: document.write with location.hash",
            "evidence": "document.write(location.hash.substring(1))",
            "url": "https://app.target.com/dashboard",
            "response_body": "<script>document.write(location.hash.substring(1))</script>",
        }
        result = _matcher().check(finding)
        assert result["total_penalty"] > -20, (
            f"Real DOM XSS got penalty {result['total_penalty']}: "
            f"{[m.id for m in result['matches']]}"
        )

    def test_real_xss_reflected(self):
        """Reflected XSS from dalfox — genuine payload execution."""
        finding = {
            "vuln_type": "xss_reflected",
            "tool": "dalfox",
            "title": "Reflected XSS in search parameter",
            "evidence": '<input value=""><script>alert(1)</script>',
            "status_code": "200",
            "url": "https://target.com/search?q=test",
            "payload": '"><script>alert(1)</script>',
        }
        result = _matcher().check(finding)
        assert result["total_penalty"] > -20

    def test_real_ssrf_not_external(self):
        """Real SSRF hitting internal metadata — genuinely exploitable."""
        finding = {
            "vuln_type": "ssrf",
            "tool": "ssrfmap",
            "evidence": "Response contains: ami-id, instance-type (AWS metadata)",
            "status_code": "200",
            "url": "https://target.com/proxy?url=http://169.254.169.254/latest/meta-data/",
        }
        result = _matcher().check(finding)
        assert result["total_penalty"] > -20

    def test_real_idor_not_false(self):
        """IDOR: accessed user B's data with user A's token."""
        finding = {
            "vuln_type": "idor",
            "tool": "idor_checker",
            "evidence": "User A (id=1) accessed User B (id=2) profile: name, email, phone returned",
            "status_code": "200",
            "url": "https://api.target.com/users/2/profile",
        }
        result = _matcher().check(finding)
        assert result["total_penalty"] > -20

    def test_real_rce_not_waf_block(self):
        """Command injection with actual output — not a WAF block."""
        finding = {
            "vuln_type": "command_injection",
            "tool": "commix",
            "evidence": "Executed: id; output: uid=33(www-data) gid=33(www-data)",
            "status_code": "200",
            "url": "https://target.com/ping?host=127.0.0.1",
        }
        result = _matcher().check(finding)
        assert result["total_penalty"] > -20

    def test_real_ssti_evaluated(self):
        """SSTI — template expression returned computed value."""
        finding = {
            "vuln_type": "ssti",
            "tool": "tplmap",
            "evidence": "Input: {{7*7}} Output: 49",
            "status_code": "200",
            "url": "https://target.com/render?template=test",
        }
        result = _matcher().check(finding)
        assert result["total_penalty"] > -20

    def test_tech_cve_WITH_version_not_flagged(self):
        """tech_cve finding WITH version → must NOT match FP-TECHCVE-002."""
        finding = {
            "vuln_type": "outdated_software",
            "tool": "tech_cve_checker",
            "title": "Apache 2.4.49 — CVE-2021-41773 Path Traversal",
            "evidence": "Version 2.4.49 detected via Server header, CVE-2021-41773 applies to 2.4.49-2.4.50",
            "url": "https://target.com/",
            # Key: this finding HAS a version string
        }
        result = _matcher().check(finding)
        # FP-TECHCVE-002 should NOT fire because evidence contains version info
        techcve_002_matched = any(
            m.id == "FP-TECHCVE-002" for m in result["matches"]
        )
        assert not techcve_002_matched, "FP-TECHCVE-002 matched finding WITH version"

    def test_business_logic_on_api_not_flagged(self):
        """Business logic flaw on real API endpoint, not an SPA page."""
        finding = {
            "vuln_type": "business_logic",
            "tool": "business_logic_checker",
            "title": "Price manipulation in cart API",
            "evidence": "Changed price=100 to price=-1, order total became -$1.00",
            "url": "https://api.target.com/v2/cart/checkout",
            "response_body": '{"order_id": 12345, "total": -1.00, "status": "confirmed"}',
            "status_code": "200",
        }
        result = _matcher().check(finding)
        heavy = result["total_penalty"] <= -20
        assert not heavy, (
            f"Real business_logic got penalty {result['total_penalty']}: "
            f"{[m.id for m in result['matches']]}"
        )

    def test_cicd_exposure_200_with_signature(self):
        """CI/CD endpoint returning 200 with genuine Jenkins signature."""
        finding = {
            "vuln_type": "cicd_exposure",
            "tool": "cicd_checker",
            "title": "Jenkins dashboard exposed",
            "evidence": "Jenkins dashboard accessible at /jenkins/",
            "url": "https://ci.target.com/jenkins/",
            "status_code": "200",
            "response_body": '<html><head><title>Dashboard [Jenkins]</title></head>',
        }
        result = _matcher().check(finding)
        # FP-CICD-001 requires status 404 — this is 200
        # FP-CICD-002 requires CDN markers — this has none
        assert result["total_penalty"] > -20, (
            f"Real CI/CD 200+signature got penalty {result['total_penalty']}"
        )


# ────────────────────────────────────────────────────────────
# TIER 4 — Combined Scoring: CS + KnownFP blend simulation
# ────────────────────────────────────────────────────────────

class TestCombinedScoringSimulation:
    """
    Simulate the FPDetector's final score formula:
      final = layer_score * 0.6 + cs_score * 0.4

    For a real finding with no FP match, layer_score ≈ 50 (neutral).
    The CS score from evidence factors determines the final.
    """

    BLEND = lambda self, layer, cs: layer * 0.6 + cs * 0.4

    def test_real_sqli_blend(self):
        """SQLi error-based: layer ~50, CS ~82 → blend ~63"""
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli_error",
            multi_tool_count=1,
            payload_executed=True,
            error_leaked=True,
            has_evidence=True,
        )
        blended = self.BLEND(50, bd.final_score)
        assert blended >= 50, f"SQLi blend = {blended:.1f} (CS={bd.final_score})"

    def test_real_xss_blend(self):
        """XSS reflected: layer ~50, CS ~58 → blend ~53"""
        bd = _cs().calculate_from_finding_context(
            vuln_type="xss_reflected",
            multi_tool_count=1,
            payload_reflected=True,
            payload_encoded=False,
            has_evidence=True,
        )
        blended = self.BLEND(50, bd.final_score)
        assert blended >= 50, f"XSS blend = {blended:.1f} (CS={bd.final_score})"

    def test_real_rce_blend(self):
        """RCE: layer ~50, CS ~80 → blend ~62"""
        bd = _cs().calculate_from_finding_context(
            vuln_type="rce",
            multi_tool_count=1,
            payload_executed=True,
            data_extracted=True,
            has_evidence=True,
        )
        blended = self.BLEND(50, bd.final_score)
        assert blended >= 50, f"RCE blend = {blended:.1f} (CS={bd.final_score})"

    def test_real_ssrf_oob_blend(self):
        """SSRF OOB: layer ~50, CS ~70 → blend ~58"""
        bd = _cs().calculate_from_finding_context(
            vuln_type="ssrf",
            multi_tool_count=1,
            oob_callback=True,
            has_evidence=True,
        )
        blended = self.BLEND(50, bd.final_score)
        assert blended >= 50, f"SSRF OOB blend = {blended:.1f} (CS={bd.final_score})"

    def test_borderline_tech_cve_blend(self):
        """Tech CVE (version-matched, no exploit): layer ~50, CS ~38 → blend ~45
        Below 50 is accepted — this is a borderline finding."""
        bd = _cs().calculate_from_finding_context(
            vuln_type="",
            multi_tool_count=1,
            known_vuln_pattern=True,
            has_evidence=True,
        )
        blended = self.BLEND(50, bd.final_score)
        # Borderline: 40-55 range is expected
        assert 35 <= blended <= 60, f"TechCVE blend = {blended:.1f} (CS={bd.final_score})"

    def test_negative_layer_doesnt_kill_real(self):
        """Even with slightly negative layer (WAF penalty), strong CS saves."""
        # Scenario: WAF detected (-10 on layer) but payload DID execute
        bd = _cs().calculate_from_finding_context(
            vuln_type="sqli",
            multi_tool_count=1,
            payload_executed=True,
            data_extracted=True,
            waf_detected=True,
            has_evidence=True,
        )
        # Layer might be ~40 (50 - WAF penalty), CS ~80
        blended = self.BLEND(40, bd.final_score)
        assert blended >= 50, f"WAF+real blend = {blended:.1f} (CS={bd.final_score})"


# ────────────────────────────────────────────────────────────
# TIER 5 — Vuln Type Base Score Sanity Checks
# ────────────────────────────────────────────────────────────

class TestVulnTypeBaseScores:
    """Verify base scores make sense for false-negative prevention."""

    @pytest.mark.parametrize("vtype,min_base", [
        ("rce", 55),
        ("command_injection", 55),
        ("sqli", 52),
        ("sqli_error", 55),
        ("lfi", 52),
        ("ssti", 52),
        ("auth_bypass", 52),
        ("ssrf", 50),
        ("xxe", 52),
        ("xss", 48),
        ("xss_reflected", 48),
        ("xss_stored", 50),
        ("subdomain_takeover", 52),
        ("http_smuggling", 50),
    ])
    def test_high_impact_base_above_threshold(self, vtype, min_base):
        """High-impact vuln types must have base score ≥ min_base."""
        actual = VULN_TYPE_BASE_SCORES.get(vtype, VULN_TYPE_BASE_SCORES["_default"])
        assert actual >= min_base, (
            f"{vtype} base score {actual} < expected minimum {min_base}"
        )

    def test_default_base_is_50(self):
        """Unknown vuln types should start at 50 (neutral)."""
        assert VULN_TYPE_BASE_SCORES["_default"] == 50.0

    def test_no_base_below_40(self):
        """No vuln type should have a base score below 40 — that's auto-reject territory."""
        for vtype, base in VULN_TYPE_BASE_SCORES.items():
            if vtype == "_default":
                continue
            assert base >= 40.0, f"{vtype} has dangerously low base score {base}"


# ────────────────────────────────────────────────────────────
# TIER 6 — Factor Weight Sanity
# ────────────────────────────────────────────────────────────

class TestFactorWeightSanity:
    """Verify factor weights maintain scoring balance."""

    def test_execution_evidence_always_positive_enough(self):
        """Payload execution (+22) must overcome single_tool penalty (-15)."""
        from src.fp_engine.scoring.confidence_scorer import FACTOR_WEIGHTS
        execution = FACTOR_WEIGHTS["payload_executed"]["delta"]
        single_tool = FACTOR_WEIGHTS["single_tool_only"]["delta"]
        net = execution + single_tool
        assert net >= 5, (
            f"Execution ({execution}) + single_tool ({single_tool}) = {net} < +5"
        )

    def test_oob_callback_always_positive_enough(self):
        """OOB callback (+28) must overcome single_tool (-15) alone."""
        from src.fp_engine.scoring.confidence_scorer import FACTOR_WEIGHTS
        oob = FACTOR_WEIGHTS["oob_callback_received"]["delta"]
        single_tool = FACTOR_WEIGHTS["single_tool_only"]["delta"]
        net = oob + single_tool
        assert net >= 10, f"OOB ({oob}) + single ({single_tool}) = {net}"

    def test_data_extracted_overcomes_single(self):
        """Data extraction (+25) must overcome single_tool (-15)."""
        from src.fp_engine.scoring.confidence_scorer import FACTOR_WEIGHTS
        extracted = FACTOR_WEIGHTS["data_extracted"]["delta"]
        single = FACTOR_WEIGHTS["single_tool_only"]["delta"]
        assert extracted + single >= 5

    def test_time_based_overcomes_single(self):
        """Time-based confirmation (+20) must overcome single_tool (-15)."""
        from src.fp_engine.scoring.confidence_scorer import FACTOR_WEIGHTS
        time_based = FACTOR_WEIGHTS["time_based_confirmed"]["delta"]
        single = FACTOR_WEIGHTS["single_tool_only"]["delta"]
        assert time_based + single >= 3

    def test_unencoded_reflection_overcomes_single(self):
        """Unencoded reflection (+18) must overcome single_tool (-15)."""
        from src.fp_engine.scoring.confidence_scorer import FACTOR_WEIGHTS
        reflection = FACTOR_WEIGHTS["payload_reflected_unencoded"]["delta"]
        single = FACTOR_WEIGHTS["single_tool_only"]["delta"]
        assert reflection + single >= 1

    def test_known_fp_pattern_is_strongest_negative(self):
        """known_fp_pattern_match (-30) must be the strongest single penalty.
        This ensures real FP patterns dominate the score."""
        from src.fp_engine.scoring.confidence_scorer import FACTOR_WEIGHTS
        fp_penalty = FACTOR_WEIGHTS["known_fp_pattern_match"]["delta"]
        for name, w in FACTOR_WEIGHTS.items():
            if name == "known_fp_pattern_match":
                continue
            assert w["delta"] >= fp_penalty, (
                f"{name} ({w['delta']}) is more negative than known_fp_pattern_match ({fp_penalty})"
            )
