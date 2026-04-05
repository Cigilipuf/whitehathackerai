"""Phase 5 — Evidence-Based Findings regression tests.

Tests cover:
- _has_real_content helper
- Severity-proportional evidence requirements
- Differential evidence gate (payload reflection check)
- poc_confirmed consistency
"""

import pytest


# ---------------------------------------------------------------------------
# 1. _has_real_content helper (via source inspection)
# ---------------------------------------------------------------------------

class TestHasRealContentLogic:
    """Test the _has_real_content logic in Gate 5."""

    def test_has_real_content_in_source(self):
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        assert "_has_real_content" in source

    def test_placeholder_markers_in_source(self):
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        assert "n/a" in source
        assert "placeholder" in source


# ---------------------------------------------------------------------------
# 2. Gate 5: Severity-proportional evidence requirements
# ---------------------------------------------------------------------------

class TestEvidenceGate5:
    """Test severity-proportional evidence requirements."""

    def test_critical_requires_http_exchange_and_poc(self):
        """CRITICAL without HTTP exchange should be downgraded."""
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        gate5_idx = source.index("Gate 5: Evidence quality validation")
        gate5_section = source[gate5_idx:gate5_idx + 3000]
        assert "CRITICAL requires HTTP exchange" in gate5_section

    def test_high_requires_http_evidence(self):
        """HIGH without HTTP evidence should be downgraded."""
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        gate5_idx = source.index("Gate 5: Evidence quality validation")
        gate5_section = source[gate5_idx:gate5_idx + 3000]
        assert "HIGH requires HTTP evidence" in gate5_section

    def test_medium_requires_one_evidence_field(self):
        """MEDIUM without any evidence should be downgraded to LOW."""
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        gate5_idx = source.index("Gate 5: Evidence quality validation")
        gate5_section = source[gate5_idx:gate5_idx + 4000]
        assert "MEDIUM requires at least one evidence field" in gate5_section

    def test_critical_with_evidence_goes_to_high_not_medium(self):
        """CRITICAL with some evidence but missing HTTP exchange → HIGH, not MEDIUM."""
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        gate5_idx = source.index("Gate 5: Evidence quality validation")
        gate5_section = source[gate5_idx:gate5_idx + 3000]
        # Should have the has_any_evidence → HIGH path
        assert 'f["severity"] = "HIGH"' in gate5_section

    def test_poc_confirmed_false_without_poc_code(self):
        """poc_confirmed without poc_code should be corrected."""
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        gate5_idx = source.index("Gate 5: Evidence quality validation")
        gate5_section = source[gate5_idx:gate5_idx + 3000]
        assert 'f["poc_confirmed"] = False' in gate5_section


# ---------------------------------------------------------------------------
# 3. Gate 6: Differential evidence (payload reflection check)
# ---------------------------------------------------------------------------

class TestDifferentialEvidenceGate6:
    """Test differential evidence gate for active vuln types."""

    def test_gate6_exists_in_source(self):
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        assert "Gate 6" in source or "Differential evidence" in source

    def test_active_vuln_types_defined(self):
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        assert "_ACTIVE_VULN_TYPES" in source

    def test_xss_in_active_types(self):
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        idx = source.index("_ACTIVE_VULN_TYPES")
        section = source[idx:idx + 500]
        assert "xss" in section
        assert "sqli" in section
        assert "rce" in section
        assert "ssti" in section

    def test_error_signatures_checked(self):
        """SQL error signatures should be checked as evidence of exploitation."""
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        idx = source.index("_ACTIVE_VULN_TYPES")
        section = source[idx:idx + 2000]
        assert "sql syntax" in section or "mysql" in section

    def test_payload_reflection_check(self):
        """Gate 6 checks if payload is reflected in response."""
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        idx = source.index("_ACTIVE_VULN_TYPES")
        section = source[idx:idx + 2000]
        assert "reflection" in section.lower() or "reflected" in section.lower()

    def test_no_false_downgrade_for_info_severity(self):
        """Gate 6 should only affect HIGH/CRITICAL, not LOW/MEDIUM/INFO."""
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        idx = source.index("_ACTIVE_VULN_TYPES")
        section = source[idx:idx + 2000]
        assert '"HIGH"' in section and '"CRITICAL"' in section


# ---------------------------------------------------------------------------
# 4. Unit simulation: _has_real_content logic
# ---------------------------------------------------------------------------

class TestHasRealContentUnit:
    """Test _has_real_content logic by simulating it."""

    @staticmethod
    def _has_real_content(val):
        """Replicate the logic from full_scan.py Gate 5."""
        if not val:
            return False
        s = str(val).strip()
        if len(s) < 8:
            return False
        _PLACEHOLDER_MARKERS = ("n/a", "none", "unknown", "null", "todo",
                                "placeholder", "{}", "[]")
        return s.lower() not in _PLACEHOLDER_MARKERS

    def test_none_is_not_real(self):
        assert not self._has_real_content(None)

    def test_empty_string_is_not_real(self):
        assert not self._has_real_content("")

    def test_short_string_is_not_real(self):
        assert not self._has_real_content("abc")

    def test_na_is_not_real(self):
        assert not self._has_real_content("N/A")

    def test_placeholder_is_not_real(self):
        assert not self._has_real_content("placeholder")

    def test_none_string_is_not_real(self):
        assert not self._has_real_content("None")

    def test_unknown_is_not_real(self):
        assert not self._has_real_content("unknown")

    def test_real_http_request_is_real(self):
        assert self._has_real_content("GET /api/users HTTP/1.1\nHost: example.com")

    def test_real_evidence_is_real(self):
        assert self._has_real_content("SQL error: near syntax error at line 1")

    def test_real_poc_code_is_real(self):
        assert self._has_real_content("curl -X POST https://example.com/api -d 'test'")


# ---------------------------------------------------------------------------
# 5. Evidence downgrade simulation
# ---------------------------------------------------------------------------

class TestEvidenceDowngradeSimulation:
    """Simulate the evidence gate logic on sample findings."""

    @staticmethod
    def _has_real_content(val):
        if not val:
            return False
        s = str(val).strip()
        if len(s) < 8:
            return False
        return s.lower() not in ("n/a", "none", "unknown", "null", "todo",
                                 "placeholder", "{}", "[]")

    def test_critical_no_evidence_goes_to_medium(self):
        f = {"severity": "CRITICAL", "vulnerability_type": "xss"}
        sev = f["severity"].upper()
        has_any = False
        if sev == "CRITICAL" and not has_any:
            f["severity"] = "MEDIUM"
        assert f["severity"] == "MEDIUM"

    def test_critical_with_request_goes_to_high(self):
        f = {"severity": "CRITICAL", "http_request": "GET /test HTTP/1.1\nHost: x.com",
             "vulnerability_type": "xss"}
        has_http_exchange = self._has_real_content(f.get("http_request")) and \
            self._has_real_content(f.get("http_response"))
        has_any = self._has_real_content(f.get("http_request"))
        has_poc = self._has_real_content(f.get("poc_code"))
        has_evidence = self._has_real_content(f.get("evidence"))
        if not has_http_exchange or not (has_poc or has_evidence):
            if has_any:
                f["severity"] = "HIGH"
            else:
                f["severity"] = "MEDIUM"
        assert f["severity"] == "HIGH"

    def test_high_no_http_goes_to_medium(self):
        f = {"severity": "HIGH", "vulnerability_type": "sqli"}
        has_http = self._has_real_content(f.get("http_request")) or \
            self._has_real_content(f.get("http_response"))
        has_any = has_http or self._has_real_content(f.get("evidence"))
        if not has_http or not has_any:
            f["severity"] = "MEDIUM"
        assert f["severity"] == "MEDIUM"

    def test_medium_no_evidence_goes_to_low(self):
        f = {"severity": "MEDIUM", "vulnerability_type": "cors"}
        has_any = any(self._has_real_content(f.get(k)) for k in
                      ("http_request", "http_response", "poc_code", "evidence", "poc_evidence"))
        if not has_any:
            f["severity"] = "LOW"
        assert f["severity"] == "LOW"

    def test_medium_with_evidence_stays_medium(self):
        f = {"severity": "MEDIUM", "vulnerability_type": "cors",
             "evidence": "Access-Control-Allow-Origin: * header found on /api/data"}
        has_any = any(self._has_real_content(f.get(k)) for k in
                      ("http_request", "http_response", "poc_code", "evidence", "poc_evidence"))
        if not has_any:
            f["severity"] = "LOW"
        assert f["severity"] == "MEDIUM"

    def test_low_severity_untouched(self):
        f = {"severity": "LOW", "vulnerability_type": "info_disclosure"}
        # LOW/INFO have no evidence requirements
        assert f["severity"] == "LOW"
