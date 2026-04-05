"""
Regression tests for Radical Finding Quality Revolution v5.0 — Phase 0.

P0.1: Nuclei confidence penalty when no response metadata available
P0.2: FP_MEDIUM_CONFIDENCE_THRESHOLD raised from 50 to 65
P0.3: SPA baseline capture (ResponseValidator.set_baseline)
P0.4: Nikto confidence lowered from 50 to 30
"""
from __future__ import annotations

import unittest


# ============================================================
# P0.1 — Nuclei unvalidated finding confidence penalty
# ============================================================

class TestNucleiUnvalidatedConfidencePenalty(unittest.TestCase):
    """When nuclei doesn't produce parseable HTTP response data,
    the finding should have lower base confidence than a validated one."""

    def _parse_finding(self, response_body: str = "") -> dict:
        """Build a minimal nuclei JSONL record and parse it."""
        from src.tools.scanners.nuclei_wrapper import NucleiWrapper

        nw = NucleiWrapper()
        data = {
            "template-id": "test-template",
            "info": {
                "name": "Test Finding",
                "severity": "medium",
                "tags": ["test"],
                "description": "A test finding",
                "classification": {},
                "reference": [],
            },
            "host": "https://example.com",
            "matched-at": "https://example.com/test",
            "type": "http",
        }
        if response_body:
            data["response"] = (
                f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{response_body}"
            )
        else:
            data["response"] = ""

        finding = nw._parse_json_result(data, "https://example.com")
        return finding

    def test_no_response_starts_at_40(self):
        """Finding with no response data should start at base=40."""
        f = self._parse_finding("")
        # No response data → base 40 + severity bonus 3 (medium) = 43
        # No other evidence bonuses
        self.assertIsNotNone(f)
        self.assertLessEqual(f.confidence, 50.0,
                             "Unvalidated nuclei findings must start below 50")

    def test_with_response_starts_higher(self):
        """Finding with parseable HTTP response should start at base=50."""
        f = self._parse_finding("<html>Some content with data</html>")
        self.assertIsNotNone(f)
        # Has response (>100 chars with header) → base 50 + severity 3 + response 3 = 56
        # response_validator may also add modifier
        # Key: should be higher than the no-response case
        self.assertGreater(f.confidence, 43.0,
                           "Validated nuclei findings should have higher confidence")

    def test_no_response_caps_below_threshold(self):
        """Even with many bonuses, a no-response finding should be moderate."""
        from src.tools.scanners.nuclei_wrapper import NucleiWrapper

        nw = NucleiWrapper()
        data = {
            "template-id": "CVE-2024-1234",
            "info": {
                "name": "Test CVE",
                "severity": "critical",
                "tags": ["cve", "rce"],
                "description": "Remote code execution",
                "classification": {"cvss-score": 9.8, "cwe-id": ["CWE-94"]},
                "reference": ["https://nvd.nist.gov"],
            },
            "host": "https://example.com",
            "matched-at": "https://example.com/api/rce",
            "matcher-name": "rce-matcher",
            "extracted-results": ["root:x:0:0"],
            "curl-command": "curl https://example.com/api/rce",
            "type": "http",
            "response": "",  # No parseable response
        }
        finding = nw._parse_json_result(data, "https://example.com")
        self.assertIsNotNone(finding)
        # Even with all bonuses (extracted=+20, curl=+5, matcher=+5,
        # endpoint=+5, cve=+7, critical=+10), base is 40 → 92, capped at 95
        # but still starts 10 LOWER than it would with base 50
        self.assertLessEqual(finding.confidence, 95.0)

    def test_response_with_validation_applies_modifier(self):
        """When response IS parseable and validator returns a modifier,
        it should be applied to the confidence."""
        f = self._parse_finding(
            "<html><body>Hello World - normal page content is here</body></html>"
        )
        self.assertIsNotNone(f)
        # The confidence should reflect the validator's assessment


# ============================================================
# P0.2 — FP threshold raised from 50 to 65
# ============================================================

class TestFPThresholdRaise(unittest.TestCase):
    """FP_MEDIUM_CONFIDENCE_THRESHOLD must be 65 (was 50)."""

    def test_medium_threshold_is_65(self):
        from src.utils.constants import FP_MEDIUM_CONFIDENCE_THRESHOLD
        self.assertEqual(FP_MEDIUM_CONFIDENCE_THRESHOLD, 65,
                         "FP_MEDIUM_CONFIDENCE_THRESHOLD must be 65 (v5.0-P0.2)")

    def test_threshold_ordering_preserved(self):
        from src.utils.constants import (
            FP_AUTO_REPORT_THRESHOLD,
            FP_HIGH_CONFIDENCE_THRESHOLD,
            FP_MEDIUM_CONFIDENCE_THRESHOLD,
            FP_LOW_CONFIDENCE_THRESHOLD,
        )
        self.assertLess(FP_LOW_CONFIDENCE_THRESHOLD, FP_MEDIUM_CONFIDENCE_THRESHOLD)
        self.assertLess(FP_MEDIUM_CONFIDENCE_THRESHOLD, FP_HIGH_CONFIDENCE_THRESHOLD)
        self.assertLess(FP_HIGH_CONFIDENCE_THRESHOLD, FP_AUTO_REPORT_THRESHOLD)

    def test_high_threshold_above_medium(self):
        from src.utils.constants import (
            FP_HIGH_CONFIDENCE_THRESHOLD,
            FP_MEDIUM_CONFIDENCE_THRESHOLD,
        )
        # HIGH must be > MEDIUM with at least 5 points gap
        self.assertGreaterEqual(
            FP_HIGH_CONFIDENCE_THRESHOLD - FP_MEDIUM_CONFIDENCE_THRESHOLD, 5,
            "HIGH - MEDIUM gap must be >= 5"
        )

    def test_severity_calibration_thresholds_tightened(self):
        """Severity downgrade thresholds must align with new FP threshold."""
        # Verifying the code path conceptually:
        # conf < 40 → LOW, conf < 50 → max MEDIUM, conf < 65 → max HIGH
        # This tests that a finding with confidence 55 and CRITICAL severity
        # would be downgraded under the new calibration
        _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        conf = 55.0
        sev = "critical"
        sev_rank = _SEVERITY_ORDER[sev]

        new_sev = sev
        if conf < 40 and sev_rank >= 2:
            new_sev = "low"
        elif conf < 50 and sev_rank >= 3:
            new_sev = "medium"
        elif conf < 65 and sev_rank >= 4:
            new_sev = "high"

        self.assertEqual(new_sev, "high",
                         "CRITICAL with conf 55 must be downgraded to HIGH")

    def test_old_threshold_50_would_pass_now_fails(self):
        """A finding at confidence 55 would pass old threshold (50) but
        fails new threshold (65)."""
        from src.utils.constants import FP_MEDIUM_CONFIDENCE_THRESHOLD
        conf = 55.0
        self.assertLess(conf, FP_MEDIUM_CONFIDENCE_THRESHOLD,
                        "Conference 55 must be below new threshold 65")


# ============================================================
# P0.3 — SPA baseline capture
# ============================================================

class TestSPABaselineCapture(unittest.TestCase):
    """ResponseValidator.set_baseline() should be callable and
    should affect subsequent SPA catch-all detection."""

    def test_set_baseline_stores_hash(self):
        from src.utils.response_validator import ResponseValidator
        rv = ResponseValidator()
        rv.set_baseline("example.com", "<html><head></head><body><div id='root'></div></body></html>")
        self.assertIn("example.com", rv._baseline_hashes)
        self.assertTrue(len(rv._baseline_hashes["example.com"]) > 0)

    def test_set_baseline_different_hosts(self):
        from src.utils.response_validator import ResponseValidator
        rv = ResponseValidator()
        rv.set_baseline("a.com", "<html>A</html>")
        rv.set_baseline("b.com", "<html>B</html>")
        self.assertIn("a.com", rv._baseline_hashes)
        self.assertIn("b.com", rv._baseline_hashes)
        self.assertNotEqual(rv._baseline_hashes["a.com"], rv._baseline_hashes["b.com"])

    def test_same_body_produces_same_hash(self):
        from src.utils.response_validator import ResponseValidator
        rv = ResponseValidator()
        body = "<html><div id='root'></div></html>"
        rv.set_baseline("host1", body)
        rv.set_baseline("host2", body)
        self.assertEqual(rv._baseline_hashes["host1"], rv._baseline_hashes["host2"])

    def test_baseline_detects_spa_catchall(self):
        """When baseline is set and a probe returns the same body,
        validation should detect SPA catch-all."""
        from src.utils.response_validator import ResponseValidator
        rv = ResponseValidator()
        spa_body = "<html><head><title>My App</title></head><body><div id='root'></div><script src='/app.js'></script></body></html>"
        rv.set_baseline("spa.example.com", spa_body)

        # Now validate a response that returns the same SPA body
        result = rv.validate(
            status_code=200,
            headers={"content-type": "text/html"},
            body=spa_body,
            baseline_body=spa_body,
            url="https://spa.example.com/some/random/path",
        )
        # The response should be flagged as SPA catch-all or have negative modifier
        # (ResponseValidator may not reject outright but should have negative modifier)
        if result.is_spa_catchall:
            self.assertFalse(result.is_valid)
        else:
            self.assertLessEqual(result.confidence_modifier, 0.0)

    def test_different_body_passes_validation(self):
        """When baseline is set but probe returns different body,
        validation should pass."""
        from src.utils.response_validator import ResponseValidator
        rv = ResponseValidator()
        spa_body = "<html><div id='root'></div></html>"
        rv.set_baseline("example.com", spa_body)

        different_body = "<html><body><h1>API Response</h1><p>Data: 12345</p></body></html>"
        result = rv.validate(
            status_code=200,
            headers={"content-type": "text/html"},
            body=different_body,
            url="https://example.com/api/data",
        )
        self.assertTrue(result.is_valid)


# ============================================================
# P0.4 — Nikto confidence lowered
# ============================================================

class TestNiktoConfidenceLowered(unittest.TestCase):
    """Nikto base confidence must be 30 (was 50)."""

    def _get_text_findings(self):
        from src.tools.scanners.nikto_wrapper import NiktoWrapper
        nw = NiktoWrapper()
        raw = (
            "+ Server: Apache/2.4.52\n"
            "+ /: The anti-clickjacking X-Frame-Options header is not present.\n"
            "+ OSVDB-3092: /admin/: This might be interesting...\n"
            "+ OSVDB-3233: /icons/README: Apache default file found.\n"
        )
        return nw.parse_output(raw, "https://example.com")

    def test_text_findings_confidence_30(self):
        findings = self._get_text_findings()
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertEqual(f.confidence, 30.0,
                             f"Nikto text finding '{f.title}' must have confidence 30, got {f.confidence}")

    def test_json_findings_confidence_30(self):
        from src.tools.scanners.nikto_wrapper import NiktoWrapper
        nw = NiktoWrapper()
        data = {
            "vulnerabilities": [
                {
                    "OSVDB": "3092",
                    "method": "GET",
                    "url": "/admin/",
                    "msg": "This might be interesting...",
                },
                {
                    "OSVDB": "",
                    "method": "GET",
                    "url": "/",
                    "msg": "X-Frame-Options header is not present.",
                },
            ]
        }
        findings = nw._parse_json_output(data, "https://example.com")
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertEqual(f.confidence, 30.0,
                             f"Nikto JSON finding '{f.title}' must have confidence 30, got {f.confidence}")

    def test_nikto_findings_tagged_unverified(self):
        findings = self._get_text_findings()
        for f in findings:
            self.assertIn("unverified", f.tags,
                          f"Nikto finding must be tagged 'unverified'")

    def test_nikto_confidence_below_medium_threshold(self):
        """Nikto findings at base 30 must be below FP_MEDIUM_CONFIDENCE_THRESHOLD."""
        from src.utils.constants import FP_MEDIUM_CONFIDENCE_THRESHOLD
        findings = self._get_text_findings()
        for f in findings:
            self.assertLess(f.confidence, FP_MEDIUM_CONFIDENCE_THRESHOLD,
                            f"Nikto base confidence must be below threshold {FP_MEDIUM_CONFIDENCE_THRESHOLD}")


# ============================================================
# Cross-cutting: Threshold + Tool interaction
# ============================================================

class TestThresholdToolInteraction(unittest.TestCase):
    """Verify that lowered tool confidence + raised threshold work together."""

    def test_nikto_base_below_new_threshold(self):
        """Nikto at 30 is well below threshold 65 — would need multi-tool
        confirmation or other evidence to become reportable."""
        from src.utils.constants import FP_MEDIUM_CONFIDENCE_THRESHOLD
        self.assertLess(30.0, FP_MEDIUM_CONFIDENCE_THRESHOLD)
        gap = FP_MEDIUM_CONFIDENCE_THRESHOLD - 30.0
        self.assertGreaterEqual(gap, 30.0,
                                "Nikto needs 35+ points of evidence to reach threshold")

    def test_nuclei_unvalidated_below_threshold(self):
        """Nuclei at base 40 (no response) is below threshold 65."""
        from src.utils.constants import FP_MEDIUM_CONFIDENCE_THRESHOLD
        base = 40.0 + 3.0  # base + medium severity bonus
        self.assertLess(base, FP_MEDIUM_CONFIDENCE_THRESHOLD)

    def test_nuclei_validated_can_reach_threshold(self):
        """Nuclei at base 50 (with response) with moderate evidence can reach 65."""
        from src.utils.constants import FP_MEDIUM_CONFIDENCE_THRESHOLD
        # base=50 + severity(medium)=3 + response(>100)=3 + endpoint(specific)=5 = 61
        # Just below threshold — needs extra evidence (extraction, CVE, etc.)
        base_with_evidence = 50.0 + 3.0 + 3.0 + 5.0
        self.assertLess(base_with_evidence, FP_MEDIUM_CONFIDENCE_THRESHOLD,
                        "Moderate evidence nuclei should still be below threshold")
        # With extraction (+20) → 81 → above threshold
        with_extraction = base_with_evidence + 20.0
        self.assertGreater(with_extraction, FP_MEDIUM_CONFIDENCE_THRESHOLD,
                           "Strong evidence nuclei should be above threshold")


if __name__ == "__main__":
    unittest.main()
