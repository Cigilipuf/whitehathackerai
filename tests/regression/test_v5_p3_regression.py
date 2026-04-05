"""Phase 3 regression tests — Checker-Level Response Validation.

Covers:
  P3.1: PostValidator framework
  P3.2: Dalfox confidence calibration
  P3.3: SQLMap blind confidence calibration
  P3.4: Subdomain takeover unknown-CNAME confidence
  P3.5: SearchSploit version matching
  P3.6: Commix time-based / SSRFMap generic confidence
"""

import textwrap

import pytest


# ---------------------------------------------------------------------------
# P3.1 — PostValidator framework
# ---------------------------------------------------------------------------
class TestPostValidator:
    """Tests for src/tools/scanners/post_validator.py helpers."""

    def test_has_payload_reflection_found(self):
        from src.tools.scanners.post_validator import has_payload_reflection
        body = '<html><script>alert(1)</script></html>'
        assert has_payload_reflection(body, "<script>alert(1)</script>") is True

    def test_has_payload_reflection_not_found(self):
        from src.tools.scanners.post_validator import has_payload_reflection
        assert has_payload_reflection("<html>safe</html>", "<script>alert(1)</script>") is False

    def test_has_payload_reflection_too_short(self):
        from src.tools.scanners.post_validator import has_payload_reflection
        # Payload shorter than min_length should be rejected
        assert has_payload_reflection("body abc", "ab", min_length=4) is False

    def test_has_error_signature_sqli(self):
        from src.tools.scanners.post_validator import has_error_signature
        body = 'You have an error in your SQL syntax near'
        assert has_error_signature(body) is True

    def test_has_error_signature_clean(self):
        from src.tools.scanners.post_validator import has_error_signature
        assert has_error_signature('<html>Welcome to our site</html>') is False

    def test_has_timing_anomaly_true(self):
        from src.tools.scanners.post_validator import has_timing_anomaly
        assert has_timing_anomaly(100.0, 6000.0) is True

    def test_has_timing_anomaly_false_high_baseline(self):
        from src.tools.scanners.post_validator import has_timing_anomaly
        # High baseline means latency is normal variation
        assert has_timing_anomaly(2000.0, 6000.0, max_baseline_ms=1000.0) is False

    def test_has_timing_anomaly_false_small_diff(self):
        from src.tools.scanners.post_validator import has_timing_anomaly
        assert has_timing_anomaly(100.0, 500.0) is False

    def test_body_differs_meaningfully_yes(self):
        from src.tools.scanners.post_validator import body_differs_meaningfully
        baseline = "a" * 1000
        probe = "b" * 1200  # 20% diff
        assert body_differs_meaningfully(baseline, probe) is True

    def test_body_differs_meaningfully_no(self):
        from src.tools.scanners.post_validator import body_differs_meaningfully
        baseline = "a" * 1000
        probe = "a" * 1010  # 1% diff
        assert body_differs_meaningfully(baseline, probe) is False

    def test_body_differs_empty_baseline(self):
        from src.tools.scanners.post_validator import body_differs_meaningfully
        # Empty baseline with substantial probe body → meaningful
        assert body_differs_meaningfully("", "x" * 100) is True
        # Empty baseline with tiny probe body → not meaningful
        assert body_differs_meaningfully("", "tiny") is False

    def test_has_error_signature_oracle(self):
        from src.tools.scanners.post_validator import has_error_signature
        body = 'ORA-12345: some oracle error'
        assert has_error_signature(body) is True

    def test_has_error_signature_pgsql(self):
        from src.tools.scanners.post_validator import has_error_signature
        assert has_error_signature('ERROR: syntax error at or near') is True


# ---------------------------------------------------------------------------
# P3.2 — Dalfox confidence calibration
# ---------------------------------------------------------------------------
class TestDalfoxConfidence:
    """Verify dalfox _TYPE_CONFIDENCE lowered values."""

    def test_grep_confidence(self):
        from src.tools.scanners.dalfox_wrapper import _TYPE_CONFIDENCE
        assert _TYPE_CONFIDENCE["G"] == 20.0, "G-type (grep) should be 20"

    def test_reflected_confidence(self):
        from src.tools.scanners.dalfox_wrapper import _TYPE_CONFIDENCE
        assert _TYPE_CONFIDENCE["R"] == 60.0, "R-type (reflected) should be 60"

    def test_verified_confidence(self):
        from src.tools.scanners.dalfox_wrapper import _TYPE_CONFIDENCE
        assert _TYPE_CONFIDENCE["V"] == 80.0, "V-type (verified) should be 80"


# ---------------------------------------------------------------------------
# P3.3 — SQLMap blind confidence calibration
# ---------------------------------------------------------------------------
class TestSQLMapConfidence:
    """Verify sqlmap _TECH_CONFIDENCE lowered blind values."""

    def test_time_based_confidence(self):
        import inspect
        from src.tools.scanners import sqlmap_wrapper
        src = inspect.getsource(sqlmap_wrapper)
        assert '"time_based": 40.0' in src or "'time_based': 40.0" in src or '"time_based": 40' in src

    def test_boolean_based_confidence(self):
        import inspect
        from src.tools.scanners import sqlmap_wrapper
        src = inspect.getsource(sqlmap_wrapper)
        assert '"boolean_based": 55' in src

    def test_error_based_unchanged(self):
        import inspect
        from src.tools.scanners import sqlmap_wrapper
        src = inspect.getsource(sqlmap_wrapper)
        assert '"error_based": 80' in src

    def test_union_based_unchanged(self):
        import inspect
        from src.tools.scanners import sqlmap_wrapper
        src = inspect.getsource(sqlmap_wrapper)
        assert '"union_based": 85' in src


# ---------------------------------------------------------------------------
# P3.4 — Subdomain takeover unknown-CNAME confidence
# ---------------------------------------------------------------------------
class TestSubdomainTakeoverConfidence:
    """Verify unknown dangling CNAME confidence lowered to 20."""

    def test_unknown_cname_confidence_in_source(self):
        import inspect
        from src.tools.scanners.custom_checks import subdomain_takeover
        src = inspect.getsource(subdomain_takeover)
        # The generic dangling CNAME confidence should be 20.0
        assert "confidence = 20.0" in src
        # The old value should NOT be present
        assert "confidence = 35.0" not in src


# ---------------------------------------------------------------------------
# P3.5 — SearchSploit version matching activation
# ---------------------------------------------------------------------------
class TestSearchSploitVersionMatching:
    """Verify version matching is now active in parse_output."""

    def test_version_extract(self):
        from src.tools.exploit.searchsploit_wrapper import SearchsploitWrapper
        assert SearchsploitWrapper._extract_version_from_title("apache 2.4.49 - rce") == "2.4.49"

    def test_version_extract_no_version(self):
        from src.tools.exploit.searchsploit_wrapper import SearchsploitWrapper
        assert SearchsploitWrapper._extract_version_from_title("generic exploit title") is None

    def test_versions_compatible_same_major(self):
        from src.tools.exploit.searchsploit_wrapper import SearchsploitWrapper
        assert SearchsploitWrapper._versions_compatible("2.4.49", "2.4.50") is True

    def test_versions_incompatible_diff_major(self):
        from src.tools.exploit.searchsploit_wrapper import SearchsploitWrapper
        assert SearchsploitWrapper._versions_compatible("2.4.49", "3.0.0") is False

    def test_version_mismatch_lowers_confidence(self):
        """When exploit version doesn't match detected tech version, confidence should be 10."""
        import json
        from src.tools.exploit.searchsploit_wrapper import SearchsploitWrapper

        w = SearchsploitWrapper.__new__(SearchsploitWrapper)
        w.name = "searchsploit"

        # Exploit for nginx 1.18.0, but detected tech is nginx 1.25.3
        raw = json.dumps({
            "RESULTS_EXPLOIT": [{
                "Title": "nginx 1.18.0 - Path Traversal",
                "Path": "/usr/share/exploitdb/exploits/linux/webapps/12345.py",
                "EDB-ID": "12345",
                "Date_Published": "2021-01-01",
                "Platform": "linux",
                "Type": "webapps",
            }]
        })
        findings = w.parse_output(raw, target="example.com", technologies=["nginx", "nginx 1.25.3"])
        assert len(findings) == 1
        # Major version matches (1.x) but minor differs by >5 (18 vs 25)
        assert findings[0].confidence == 10.0

    def test_version_match_keeps_normal_confidence(self):
        """When versions are compatible, confidence should be 25."""
        import json
        from src.tools.exploit.searchsploit_wrapper import SearchsploitWrapper

        w = SearchsploitWrapper.__new__(SearchsploitWrapper)
        w.name = "searchsploit"

        raw = json.dumps({
            "RESULTS_EXPLOIT": [{
                "Title": "nginx 1.25.2 - Buffer Overflow",
                "Path": "/usr/share/exploitdb/exploits/linux/webapps/12346.py",
                "EDB-ID": "12346",
                "Date_Published": "2023-01-01",
                "Platform": "linux",
                "Type": "webapps",
            }]
        })
        findings = w.parse_output(raw, target="example.com", technologies=["nginx", "nginx 1.25.3"])
        assert len(findings) == 1
        assert findings[0].confidence == 25.0

    def test_no_tech_context_confidence(self):
        """No technologies → confidence 15."""
        import json
        from src.tools.exploit.searchsploit_wrapper import SearchsploitWrapper

        w = SearchsploitWrapper.__new__(SearchsploitWrapper)
        w.name = "searchsploit"

        raw = json.dumps({
            "RESULTS_EXPLOIT": [{
                "Title": "Generic thing 1.0 - Some Vuln",
                "Path": "/path/to/exploit.py",
                "EDB-ID": "99999",
                "Date_Published": "2020-01-01",
                "Platform": "linux",
                "Type": "webapps",
            }]
        })
        findings = w.parse_output(raw, target="example.com", technologies=[])
        assert len(findings) == 1
        assert findings[0].confidence == 15.0


# ---------------------------------------------------------------------------
# P3.6 — Commix time-based / SSRFMap generic confidence
# ---------------------------------------------------------------------------
class TestCommixConfidence:
    """Verify commix time-based blind confidence lowered to 35."""

    def test_time_based_confidence_in_source(self):
        import inspect
        from src.tools.scanners import commix_wrapper
        src = inspect.getsource(commix_wrapper)
        assert "35.0 if is_blind" in src
        # Old value should not be present
        assert "50.0 if is_blind" not in src


class TestSSRFMapConfidence:
    """Verify SSRFMap generic confirmed confidence lowered to 55."""

    def test_generic_ssrf_confidence_in_source(self):
        import inspect
        from src.tools.scanners import ssrfmap_wrapper
        src = inspect.getsource(ssrfmap_wrapper)
        # In Pattern 6 (general SSRF confirmed), confidence should be 55.0
        assert "confidence=55.0," in src
        # Old value for Pattern 6 should not be present
        # (Other patterns legitimately use 80+ so we can't just check globally)
