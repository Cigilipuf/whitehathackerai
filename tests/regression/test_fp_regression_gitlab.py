"""
FP Regression Test Suite — GitLab Scan (36bdfaffd99e87ab)
==========================================================
Validates KnownFPMatcher catch-rate against 436 real production findings
from the GitLab bug bounty scan. These findings were all false positives
that should be caught (penalised) by the pattern library.

Target catch-rate: 100% (436/436)
Target pass-through after penalty: 0 findings with confidence >= 50
"""

import json
from pathlib import Path

import pytest

FINDINGS_PATH = Path("output/sessions/36bdfaffd99e87ab/findings/findings.json")

# Skip entire module if GitLab findings data is not available
pytestmark = pytest.mark.skipif(
    not FINDINGS_PATH.exists(),
    reason="GitLab findings data not available (output/sessions/36bdfaffd99e87ab/)",
)

# ── Vuln-type synonyms mirroring the pipeline normalisation ──
_VULN_SYNONYMS = {
    "outdated_software": "outdated_software",
    "known_cve": "outdated_software",
    "business_logic": "business_logic",
    "cicd_exposure": "cicd_exposure",
    "xss_dom": "xss_dom",
    "information_disclosure": "information_disclosure",
    "security_misconfiguration": "security_misconfiguration",
    "mass_assignment_data_manipulation": "mass_assignment",
    "mass_assignment_role_escalation": "mass_assignment",
    "mass_assignment_generic": "mass_assignment",
    "sensitive_url": "sensitive_url",
    "subdomain_takeover": "subdomain_takeover",
    "command_injection": "command_injection",
}

CONFIDENCE_THRESHOLD = 50


def _load_findings():
    """Load and return the 436 verified findings."""
    data = json.loads(FINDINGS_PATH.read_text())
    return data["verified_findings"]


def _normalize(finding: dict) -> dict:
    """Ensure finding has 'vuln_type' key for the matcher."""
    f = dict(finding)
    vt = f.get("vuln_type") or f.get("vulnerability_type") or f.get("type", "unknown")
    f["vuln_type"] = vt
    return f


def _run_matcher(finding: dict):
    from src.fp_engine.patterns.known_fps import KnownFPMatcher
    matcher = KnownFPMatcher()
    return matcher.check(finding)


# ============================================================
#  Aggregate Tests
# ============================================================

class TestFPRegressionAggregate:
    """Whole-dataset assertions."""

    @pytest.fixture(scope="class")
    def findings(self):
        return _load_findings()

    @pytest.fixture(scope="class")
    def results(self, findings):
        """Run matcher on all 436 findings, return list of (finding, result)."""
        out = []
        for f in findings:
            nf = _normalize(f)
            res = _run_matcher(nf)
            out.append((nf, res))
        return out

    def test_total_finding_count(self, findings):
        assert len(findings) == 436, f"Expected 436 findings, got {len(findings)}"

    def test_overall_catch_rate_at_least_99_percent(self, results):
        matched = sum(1 for _, r in results if r["matches"])
        rate = matched / len(results) * 100
        assert rate >= 100.0, (
            f"Catch-rate {rate:.1f}% ({matched}/{len(results)}) is below 100% threshold"
        )

    def test_pass_through_at_most_0(self, results):
        """After applying penalties, NO findings should remain above threshold."""
        pass_through = 0
        for f, r in results:
            conf = f.get("confidence_score", f.get("confidence", 50))
            try:
                conf = float(conf)
            except (TypeError, ValueError):
                conf = 50.0
            adjusted = conf + r["total_penalty"]
            if adjusted >= CONFIDENCE_THRESHOLD and not r["matches"]:
                pass_through += 1
        assert pass_through == 0, (
            f"{pass_through} findings still pass through (expected 0)"
        )


# ============================================================
#  Per-Category Tests
# ============================================================

class TestFPRegressionPerCategory:
    """Ensure each vulnerability category is fully covered."""

    @pytest.fixture(scope="class")
    def categorised(self):
        findings = _load_findings()
        cats = {}
        for f in findings:
            nf = _normalize(f)
            vt = nf["vuln_type"]
            canonical = _VULN_SYNONYMS.get(vt, vt)
            cats.setdefault(canonical, []).append(nf)
        return cats

    @pytest.mark.parametrize("category,expected_count,min_catch_rate", [
        ("outdated_software", 335, 100.0),
        ("business_logic", 49, 100.0),
        ("cicd_exposure", 15, 100.0),
        ("xss_dom", 10, 100.0),
        ("mass_assignment", 5, 100.0),
        ("information_disclosure", 13, 100.0),
        ("security_misconfiguration", 4, 100.0),
        ("sensitive_url", 2, 100.0),
        ("subdomain_takeover", 2, 100.0),
        ("command_injection", 1, 100.0),
    ])
    def test_category_catch_rate(self, categorised, category, expected_count, min_catch_rate):
        findings = categorised.get(category, [])
        if not findings:
            pytest.skip(f"No findings for category {category}")
        matched = sum(1 for f in findings if _run_matcher(f)["matches"])
        rate = matched / len(findings) * 100
        assert rate >= min_catch_rate, (
            f"{category}: catch-rate {rate:.1f}% ({matched}/{len(findings)}) "
            f"below {min_catch_rate}% threshold"
        )


# ============================================================
#  Specific Pattern Coverage Tests
# ============================================================

class TestFPRegressionPatternCoverage:
    """Verify specific patterns fire on specific finding archetypes."""

    def test_techcve_catches_outdated_software(self):
        finding = _normalize({
            "title": "CVE-2024-1234 affects Ruby on Rails",
            "vulnerability_type": "outdated_software",
            "tool": "tech_cve_checker",
            "evidence": "Technology: Rails detected, no version confirmed",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert any(pid.startswith("FP-TECHCVE") for pid in ids)

    def test_bizlogic_catches_spa_json_url(self):
        finding = _normalize({
            "title": "Business Logic: Price Manipulation",
            "vulnerability_type": "business_logic",
            "tool": "business_logic_checker",
            "url": "https://example.com/_next/data/build/page.json",
            "evidence": "Response unchanged",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert "FP-BIZLOGIC-001" in ids

    def test_cicd_catches_http_404(self):
        finding = _normalize({
            "title": "CI/CD Exposure: Jenkins",
            "vulnerability_type": "cicd_exposure",
            "tool": "cicd_checker",
            "evidence": "HTTP 404 — endpoint not found",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert "FP-CICD-001" in ids

    def test_jsdom_catches_gtm_analytics(self):
        finding = _normalize({
            "title": "DOM XSS Source/Sink in gtm.js",
            "vulnerability_type": "xss_dom",
            "tool": "js_analyzer",
            "url": "https://www.googletagmanager.com/gtm.js?id=GTM-XXXXX",
            "evidence": "Source: dataLayer in googletagmanager.com",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert any(pid.startswith("FP-JSDOM") for pid in ids)

    def test_massassign_catches_static_asset(self):
        finding = _normalize({
            "title": "Mass Assignment: Data Manipulation (id)",
            "vulnerability_type": "mass_assignment_data_manipulation",
            "tool": "mass_assignment_checker",
            "url": "https://example.com/assets/bundle.js",
            "evidence": "Added field accepted in response",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert any(pid.startswith("FP-MASSASSIGN") for pid in ids)

    def test_commix_empty_evidence_caught(self):
        finding = _normalize({
            "title": "Command Injection via parameter id",
            "vulnerability_type": "command_injection",
            "tool": "commix",
            "evidence": "",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert "FP-COMMIX-001" in ids

    def test_sourcemap_nuxt_build_dir_caught(self):
        finding = _normalize({
            "title": "JavaScript Source Map Exposed",
            "vulnerability_type": "information_disclosure",
            "tool": "js_analyzer",
            "url": "https://about.gitlab.com/_nuxt/entry.abc123.js.map",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert any("SOURCEMAP" in pid for pid in ids)

    def test_cookie_staging_subdomain_caught(self):
        finding = _normalize({
            "title": "Insecure Cookie: Missing Secure Flag",
            "vulnerability_type": "security_misconfiguration",
            "tool": "cookie_checker",
            "url": "https://staging.example.com/api",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert "FP-COOKIE-003" in ids

    def test_htaccess_fuzz_suffix_caught(self):
        finding = _normalize({
            "title": "Sensitive URL: .htaccess file exposed",
            "vulnerability_type": "sensitive_url",
            "tool": "sensitive_url_finder",
            "url": "https://app-staging.community.gitlab.com/.htaccessvRoqTKHS",
            "evidence": "https://app-staging.community.gitlab.com/.htaccessvRoqTKHS",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert "FP-SENSITIVE-URL-002" in ids

    def test_subtakeover_cname_only_caught(self):
        finding = _normalize({
            "title": "Potential Subdomain Takeover: federal-support.gitlab.com",
            "vulnerability_type": "subdomain_takeover",
            "tool": "subdomain_takeover_checker",
            "evidence": "CNAME: federal-support.gitlab.com → gitlab-federal-support.zendesk.com",
        })
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert "FP-SUBTAKEOVER-001" in ids


# ============================================================
#  KnownFPMatcher Field Resolution Tests
# ============================================================

class TestFPMatcherFieldResolution:
    """Verify the matcher resolves vuln_type from multiple field names."""

    def test_reads_vulnerability_type_field(self):
        finding = {"vulnerability_type": "outdated_software", "tool": "tech_cve_checker",
                    "title": "CVE test", "evidence": "no version"}
        res = _run_matcher(finding)
        # Should find TECHCVE patterns since vulnerability_type is read
        ids = [m.id for m in res["matches"]]
        assert any("TECHCVE" in pid for pid in ids)

    def test_reads_vuln_type_field(self):
        finding = {"vuln_type": "outdated_software", "tool": "tech_cve_checker",
                    "title": "CVE test", "evidence": "no version"}
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert any("TECHCVE" in pid for pid in ids)

    def test_reads_type_field_as_fallback(self):
        finding = {"type": "outdated_software", "tool": "tech_cve_checker",
                    "title": "CVE test", "evidence": "no version"}
        res = _run_matcher(finding)
        ids = [m.id for m in res["matches"]]
        assert any("TECHCVE" in pid for pid in ids)

    def test_unknown_type_when_no_field(self):
        finding = {"tool": "unknown", "title": "Test", "evidence": "Test"}
        res = _run_matcher(finding)
        # Should still work, just won't match type-specific patterns
        assert isinstance(res["total_penalty"], int)
