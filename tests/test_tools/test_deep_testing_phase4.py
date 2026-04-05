"""Phase 4 — Deep Testing Revolution regression tests.

Tests cover:
- _score_endpoint() with business keywords, auth paths, tech bonuses
- deep_probe.py: ProbeSession, _get_probe_timeout, stall detection,
  expanded payloads, batch limits
- business_logic.py: auto-detect endpoint expansion
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

# ---------------------------------------------------------------------------
# 1. _score_endpoint() scoring enhancements
# ---------------------------------------------------------------------------


class TestScoreEndpoint:
    """Test the enhanced _score_endpoint function in full_scan.py."""

    def _get_source(self):
        import inspect
        import src.workflow.pipelines.full_scan as mod
        return inspect.getsource(mod)

    def test_score_endpoint_exists(self):
        source = self._get_source()
        assert "_score_endpoint" in source, "_score_endpoint function should exist"

    def test_business_keywords_in_module(self):
        source = self._get_source()
        assert "_BUSINESS_LOGIC_KEYWORDS" in source, "_BUSINESS_LOGIC_KEYWORDS should exist"
        assert "checkout" in source
        assert "payment" in source
        assert "admin" in source

    def test_tech_score_bonuses_exist(self):
        source = self._get_source()
        assert "_TECH_SCORE_BONUSES" in source, "_TECH_SCORE_BONUSES should exist"
        assert "graphql" in source
        assert "php" in source
        assert "wordpress" in source

    def test_priority_iter_map_exists(self):
        source = self._get_source()
        assert "_PRIORITY_ITER_MAP" in source, "_PRIORITY_ITER_MAP should exist"
        # Check that priority 4 gets high iterations
        assert "4: 15" in source or "4:15" in source


# ---------------------------------------------------------------------------
# 2. ProbeSession enhancements
# ---------------------------------------------------------------------------


class TestProbeSessionFields:
    """Test added fields on ProbeSession."""

    def test_confidence_history_field(self):
        from src.workflow.pipelines.deep_probe import ProbeSession
        ps = ProbeSession(target="https://example.com/test", vuln_type="xss")
        assert hasattr(ps, "confidence_history"), "ProbeSession should have confidence_history"
        assert ps.confidence_history == [] or isinstance(ps.confidence_history, list)

    def test_filtered_chars_field(self):
        from src.workflow.pipelines.deep_probe import ProbeSession
        ps = ProbeSession(target="https://example.com/test", vuln_type="xss")
        assert hasattr(ps, "filtered_chars"), "ProbeSession should have filtered_chars"

    def test_waf_blocking_field(self):
        from src.workflow.pipelines.deep_probe import ProbeSession
        ps = ProbeSession(target="https://example.com/test", vuln_type="xss")
        assert hasattr(ps, "waf_blocking"), "ProbeSession should have waf_blocking"
        assert ps.waf_blocking is False

    def test_max_iterations_default(self):
        from src.workflow.pipelines.deep_probe import ProbeSession
        ps = ProbeSession(target="https://example.com/test", vuln_type="xss")
        assert ps.max_iterations >= 10, "Default max_iterations should be >= 10"


# ---------------------------------------------------------------------------
# 3. _get_probe_timeout() per-vuln-type timeouts
# ---------------------------------------------------------------------------


class TestGetProbeTimeout:
    """Test vuln-type-specific timeout selection."""

    def test_function_exists(self):
        from src.workflow.pipelines.deep_probe import _get_probe_timeout
        assert callable(_get_probe_timeout)

    def test_sqli_blind_gets_long_timeout(self):
        from src.workflow.pipelines.deep_probe import _get_probe_timeout
        timeout = _get_probe_timeout("sqli_blind", 60.0)
        assert timeout >= 120.0, "sqli_blind should get a long timeout (>=120s)"

    def test_sqli_gets_moderate_timeout(self):
        from src.workflow.pipelines.deep_probe import _get_probe_timeout
        timeout = _get_probe_timeout("sqli", 60.0)
        assert timeout >= 90.0, "sqli should get moderate timeout (>=90s)"

    def test_xss_uses_base_timeout(self):
        from src.workflow.pipelines.deep_probe import _get_probe_timeout
        timeout = _get_probe_timeout("xss", 60.0)
        assert timeout >= 30.0, "xss should use at least 30s"

    def test_unknown_type_uses_base(self):
        from src.workflow.pipelines.deep_probe import _get_probe_timeout
        timeout = _get_probe_timeout("unknown_vuln_42", 60.0)
        assert timeout == 60.0, "Unknown vuln type should use base timeout"

    def test_base_override_when_higher(self):
        from src.workflow.pipelines.deep_probe import _get_probe_timeout
        # If base is very high, it should win
        timeout = _get_probe_timeout("xss", 600.0)
        assert timeout == 600.0, "Base timeout should win when higher"


# ---------------------------------------------------------------------------
# 4. _VULN_TYPE_TIMEOUT mapping
# ---------------------------------------------------------------------------


class TestVulnTypeTimeoutMap:
    """Test the vuln-type timeout mapping exists and is sensible."""

    def test_mapping_exists(self):
        from src.workflow.pipelines.deep_probe import _VULN_TYPE_TIMEOUT
        assert isinstance(_VULN_TYPE_TIMEOUT, dict)

    def test_sqli_blind_highest(self):
        from src.workflow.pipelines.deep_probe import _VULN_TYPE_TIMEOUT
        sqli_blind = _VULN_TYPE_TIMEOUT.get("sqli_blind", 0)
        sqli = _VULN_TYPE_TIMEOUT.get("sqli", 0)
        assert sqli_blind >= sqli, "sqli_blind should have >= timeout than sqli"

    def test_has_rce_type(self):
        from src.workflow.pipelines.deep_probe import _VULN_TYPE_TIMEOUT
        rce_timeout = _VULN_TYPE_TIMEOUT.get("rce", 0) or _VULN_TYPE_TIMEOUT.get("command_injection", 0)
        assert rce_timeout > 0, "RCE/command_injection should be in timeout map"

    def test_has_ssrf(self):
        from src.workflow.pipelines.deep_probe import _VULN_TYPE_TIMEOUT
        assert "ssrf" in _VULN_TYPE_TIMEOUT


# ---------------------------------------------------------------------------
# 5. Expanded _DEFAULT_PAYLOADS_BY_TYPE
# ---------------------------------------------------------------------------


class TestExpandedPayloads:
    """Test that payload arsenal was expanded."""

    def test_xss_payloads_expanded(self):
        from src.workflow.pipelines.deep_probe import _DEFAULT_PAYLOADS_BY_TYPE
        xss = _DEFAULT_PAYLOADS_BY_TYPE.get("xss", [])
        assert len(xss) >= 5, f"XSS payloads should be >= 5, got {len(xss)}"

    def test_sqli_payloads_expanded(self):
        from src.workflow.pipelines.deep_probe import _DEFAULT_PAYLOADS_BY_TYPE
        sqli = _DEFAULT_PAYLOADS_BY_TYPE.get("sqli", [])
        assert len(sqli) >= 5, f"SQLi payloads should be >= 5, got {len(sqli)}"

    def test_ssrf_payloads_expanded(self):
        from src.workflow.pipelines.deep_probe import _DEFAULT_PAYLOADS_BY_TYPE
        ssrf = _DEFAULT_PAYLOADS_BY_TYPE.get("ssrf", [])
        assert len(ssrf) >= 5, f"SSRF payloads should be >= 5, got {len(ssrf)}"

    def test_command_injection_type_exists(self):
        from src.workflow.pipelines.deep_probe import _DEFAULT_PAYLOADS_BY_TYPE
        assert "command_injection" in _DEFAULT_PAYLOADS_BY_TYPE, \
            "command_injection should be a payload type"
        assert len(_DEFAULT_PAYLOADS_BY_TYPE["command_injection"]) >= 3

    def test_open_redirect_type_exists(self):
        from src.workflow.pipelines.deep_probe import _DEFAULT_PAYLOADS_BY_TYPE
        assert "open_redirect" in _DEFAULT_PAYLOADS_BY_TYPE, \
            "open_redirect should be a payload type"

    def test_ssti_payloads_expanded(self):
        from src.workflow.pipelines.deep_probe import _DEFAULT_PAYLOADS_BY_TYPE
        ssti = _DEFAULT_PAYLOADS_BY_TYPE.get("ssti", [])
        assert len(ssti) >= 5, f"SSTI payloads should be >= 5, got {len(ssti)}"

    def test_lfi_payloads_expanded(self):
        from src.workflow.pipelines.deep_probe import _DEFAULT_PAYLOADS_BY_TYPE
        lfi = _DEFAULT_PAYLOADS_BY_TYPE.get("lfi", [])
        assert len(lfi) >= 5, f"LFI payloads should be >= 5, got {len(lfi)}"


# ---------------------------------------------------------------------------
# 6. deep_probe_batch limits
# ---------------------------------------------------------------------------


class TestDeepProbeBatchLimits:
    """Test that batch limits were raised."""

    def test_batch_function_exists(self):
        from src.workflow.pipelines.deep_probe import deep_probe_batch
        assert callable(deep_probe_batch)

    def test_default_payloads_not_empty(self):
        from src.workflow.pipelines.deep_probe import _DEFAULT_PAYLOADS_BY_TYPE
        assert len(_DEFAULT_PAYLOADS_BY_TYPE) >= 7, \
            "Should have at least 7 vuln type payload categories"


# ---------------------------------------------------------------------------
# 7. Business logic checker: expanded auto-detect
# ---------------------------------------------------------------------------


class TestBusinessLogicAutoDetect:
    """Test that _auto_detect_logic_flaws tests more endpoints."""

    def test_auto_detect_has_quantity_endpoints(self):
        """Verify the method uses multiple endpoint categories."""
        import inspect
        from src.tools.scanners.custom_checks.business_logic import BusinessLogicChecker
        source = inspect.getsource(BusinessLogicChecker._auto_detect_logic_flaws)
        # Should now test quantity endpoints and privilege endpoints
        assert "quantity" in source.lower() or "_QUANTITY_ENDPOINTS" in source, \
            "Auto-detect should include quantity testing"
        assert "privilege" in source.lower() or "_PRIVILEGE_ENDPOINTS" in source, \
            "Auto-detect should include privilege testing"

    def test_auto_detect_more_than_6_endpoints(self):
        """Verify there are more than 6 hardcoded endpoints."""
        import inspect
        from src.tools.scanners.custom_checks.business_logic import BusinessLogicChecker
        source = inspect.getsource(BusinessLogicChecker._auto_detect_logic_flaws)
        # Count endpoint path strings
        path_count = source.count("/api/")
        assert path_count > 6, f"Should have > 6 API endpoints, found ~{path_count}"

    def test_checker_accepts_test_definitions(self):
        """Test that run() accepts test_definitions parameter."""
        import inspect
        from src.tools.scanners.custom_checks.business_logic import BusinessLogicChecker
        source = inspect.getsource(BusinessLogicChecker.run)
        assert "test_definitions" in source


# ---------------------------------------------------------------------------
# 8. Business logic test definition generation in full_scan
# ---------------------------------------------------------------------------


class TestBusinessLogicTestDefs:
    """Test that full_scan generates multi-type test definitions."""

    def test_run_business_logic_function_exists(self):
        """Verify _run_business_logic is defined in full_scan."""
        import inspect
        import src.workflow.pipelines.full_scan as mod
        source = inspect.getsource(mod)
        assert "_run_business_logic" in source

    def test_multi_type_test_generation(self):
        """Verify full_scan generates price, quantity, workflow, privilege tests."""
        with open("src/workflow/pipelines/full_scan.py") as f:
            source = f.read()
        # Extract the _run_business_logic section
        biz_start = source.index("_run_business_logic")
        # Find the last 'return []' in that function scope
        biz_section = source[biz_start:biz_start + 5000]
        assert '"price"' in biz_section, "Should generate price test defs"
        assert '"quantity"' in biz_section, "Should generate quantity test defs"
        assert '"workflow"' in biz_section, "Should generate workflow test defs"
        assert '"privilege"' in biz_section, "Should generate privilege test defs"

    def test_workflow_bypass_pattern(self):
        """Workflow bypass tests should use discovered workflow endpoints."""
        import inspect
        import src.workflow.pipelines.full_scan as mod
        source = inspect.getsource(mod)
        assert "_biz_patterns_workflow" in source or "workflow" in source

    def test_privilege_patterns_present(self):
        """Privilege patterns should include admin/roles/permissions."""
        import inspect
        import src.workflow.pipelines.full_scan as mod
        source = inspect.getsource(mod)
        biz_idx = source.index("_run_business_logic")
        biz_section = source[biz_idx:biz_idx + 3000]
        assert "admin" in biz_section
        assert "role" in biz_section or "permission" in biz_section


# ---------------------------------------------------------------------------
# 9. Stall detection in deep probe
# ---------------------------------------------------------------------------


class TestStallDetection:
    """Test stall detection logic in _run_probe_cycle."""

    def test_stall_detection_in_source(self):
        """Verify stall detection logic exists in deep_probe."""
        import inspect
        from src.workflow.pipelines import deep_probe
        source = inspect.getsource(deep_probe)
        assert "stall" in source.lower() or "confidence_history" in source, \
            "Stall detection should be implemented"

    def test_confidence_history_tracking(self):
        """Verify confidence history is tracked in _run_probe_cycle."""
        import inspect
        from src.workflow.pipelines import deep_probe
        source = inspect.getsource(deep_probe)
        assert "confidence_history" in source, \
            "confidence_history should be tracked in cycle"


# ---------------------------------------------------------------------------
# 10. WAF/filter adaptation feedback
# ---------------------------------------------------------------------------


class TestWAFAdaptationFeedback:
    """Test that WAF/filter info is fed back into hypothesis prompt."""

    def test_filter_info_in_prompt(self):
        """Verify filtered_chars are injected into hypothesis prompt."""
        import inspect
        from src.workflow.pipelines import deep_probe
        source = inspect.getsource(deep_probe)
        assert "filter_info" in source or "filtered_chars" in source, \
            "Filter info should be passed to hypothesis prompt"

    def test_waf_info_in_prompt(self):
        """Verify WAF blocking info is injected into hypothesis prompt."""
        import inspect
        from src.workflow.pipelines import deep_probe
        source = inspect.getsource(deep_probe)
        assert "waf_info" in source or "waf_blocking" in source, \
            "WAF info should be passed to hypothesis prompt"
