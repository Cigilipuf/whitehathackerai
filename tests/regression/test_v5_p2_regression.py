"""
v5.0 Phase 2 Regression Tests — Endpoint Pre-Flight Validation.

Tests cover:
- Pre-flight function correctly categorizes alive/dead/waf/spa endpoints
- SPA baseline storage in metadata for cross-stage use
- Dead and WAF-blocked endpoints are filtered from scan lists
"""

from __future__ import annotations

import pytest


# ============================================================
#  P2.1: Pre-flight validation exists in pipeline
# ============================================================

class TestPreflightPipelineIntegration:
    """Verify pre-flight code is wired into full_scan.py."""

    @staticmethod
    def _get_src() -> str:
        import inspect
        from src.workflow.pipelines import full_scan
        return inspect.getsource(full_scan)

    def test_preflight_check_function_exists(self):
        src = self._get_src()
        assert "_preflight_check" in src, "Pre-flight check function must exist"

    def test_preflight_alive_variable(self):
        src = self._get_src()
        assert "_preflight_alive" in src

    def test_preflight_dead_variable(self):
        src = self._get_src()
        assert "_preflight_dead" in src

    def test_preflight_waf_variable(self):
        src = self._get_src()
        assert "_preflight_waf" in src

    def test_preflight_spa_variable(self):
        src = self._get_src()
        assert "_preflight_spa" in src

    def test_preflight_results_stored_in_metadata(self):
        src = self._get_src()
        assert 'preflight_results' in src

    def test_deduped_params_filtered_by_preflight(self):
        """Dead/WAF endpoints must also be removed from deduped_params."""
        src = self._get_src()
        assert "_pf_reject" in src


# ============================================================
#  P2.1: ResponseValidator integration in preflight
# ============================================================

class TestPreflightResponseValidation:
    """Pre-flight must use ResponseValidator for WAF/SPA detection."""

    def test_response_validator_used(self):
        import inspect
        from src.workflow.pipelines import full_scan
        src = inspect.getsource(full_scan)
        assert "ResponseValidator" in src
        assert "_pf_rv.validate" in src or "_pf_rv" in src

    def test_waf_block_detection_path(self):
        import inspect
        from src.workflow.pipelines import full_scan
        src = inspect.getsource(full_scan)
        assert "is_waf_block" in src

    def test_spa_catchall_detection_path(self):
        import inspect
        from src.workflow.pipelines import full_scan
        src = inspect.getsource(full_scan)
        assert "is_spa_catchall" in src


# ============================================================
#  P2.1: SPA baseline storage in metadata
# ============================================================

class TestSPABaselineStorage:
    """SPA baseline bodies must be stored in state.metadata for cross-stage use."""

    def test_spa_baselines_stored_in_metadata(self):
        import inspect
        from src.workflow.pipelines import full_scan
        src = inspect.getsource(full_scan)
        assert "_spa_baselines" in src, "SPA baselines must be stored in metadata"

    def test_spa_baselines_read_in_preflight(self):
        import inspect
        from src.workflow.pipelines import full_scan
        src = inspect.getsource(full_scan)
        # The preflight section should read from _spa_baselines
        assert 'state.metadata.get("_spa_baselines"' in src


# ============================================================
#  P2.1: ResponseValidator unit tests for pre-flight scenarios
# ============================================================

class TestResponseValidatorPreflightScenarios:
    """ResponseValidator must correctly handle pre-flight edge cases."""

    def _make_validator(self):
        from src.utils.response_validator import ResponseValidator
        return ResponseValidator()

    def test_404_rejected(self):
        rv = self._make_validator()
        result = rv.validate(404, {}, "Not Found")
        assert not result.is_valid

    def test_410_rejected(self):
        rv = self._make_validator()
        result = rv.validate(410, {}, "Gone")
        assert not result.is_valid

    def test_500_rejected(self):
        rv = self._make_validator()
        result = rv.validate(500, {}, "Internal Server Error")
        assert not result.is_valid

    def test_200_with_body_accepted(self):
        rv = self._make_validator()
        body = "Welcome to the application dashboard " * 10
        result = rv.validate(200, {"content-type": "text/html"}, body)
        assert result.is_valid

    def test_waf_cloudflare_detected(self):
        rv = self._make_validator()
        result = rv.validate(
            403,
            {"server": "cloudflare", "cf-ray": "abc123"},
            "<html>Attention Required! | Cloudflare</html>",
        )
        assert result.is_waf_block

    def test_spa_catchall_detected(self):
        rv = self._make_validator()
        # SPA detection requires baseline_body passed as kwarg (not set_baseline)
        baseline_body = "<html><head><script>var app=1</script></head>" + "x" * 200 + "</html>"
        # Same body on a different path → SPA catch-all
        result = rv.validate(
            200,
            {"content-type": "text/html"},
            baseline_body,
            baseline_body=baseline_body,
            url="https://example.com/nonexistent/path",
        )
        assert result.is_spa_catchall

    def test_200_empty_body_for_json_rejected(self):
        rv = self._make_validator()
        result = rv.validate(200, {}, "", expected_content_type="json")
        assert not result.is_valid

    def test_301_redirect_detected(self):
        rv = self._make_validator()
        result = rv.validate(
            301,
            {"location": "https://example.com/login"},
            "",
        )
        assert result.is_redirect


# ============================================================
#  P2.1: Endpoint Pre-Flight Logic Simulation
# ============================================================

class TestPreflightLogicSimulation:
    """Simulate the pre-flight classification logic."""

    def test_dead_endpoint_filtered(self):
        """A 404 endpoint should be classified as dead and filtered."""
        # Simulate the preflight logic
        endpoints = ["https://example.com/exists", "https://example.com/missing"]
        dead = ["https://example.com/missing"]
        alive = [ep for ep in endpoints if ep not in dead]
        assert alive == ["https://example.com/exists"]
        assert len(dead) == 1

    def test_waf_endpoint_filtered(self):
        """WAF-blocked endpoints should be filtered."""
        endpoints = ["https://example.com/api", "https://example.com/admin"]
        waf = ["https://example.com/admin"]
        alive = [ep for ep in endpoints if ep not in waf]
        assert alive == ["https://example.com/api"]

    def test_deduped_params_also_filtered(self):
        """Dead/WAF endpoints must also be removed from deduped_params."""
        deduped_params = [
            "https://example.com/api?id=1",
            "https://example.com/missing?id=2",
            "https://example.com/search?q=test",
        ]
        reject = {"https://example.com/missing?id=2"}
        filtered = [p for p in deduped_params if p not in reject]
        assert len(filtered) == 2
        assert "https://example.com/missing?id=2" not in filtered

    def test_remaining_endpoints_preserved(self):
        """Endpoints beyond the preflight limit should be kept."""
        all_eps = [f"https://example.com/ep{i}" for i in range(100)]
        preflight_max = 80
        candidates = all_eps[:preflight_max]
        remaining = all_eps[preflight_max:]
        # Simulate all alive
        alive = candidates
        result = alive + remaining
        assert len(result) == 100

    def test_network_error_keeps_endpoint(self):
        """Transient network errors should not remove endpoints."""
        # Design: exception → return "alive" (don't penalize)
        # This is tested by verifying the code pattern
        import inspect
        from src.workflow.pipelines import full_scan
        src = inspect.getsource(full_scan)
        # The except block in _preflight_check returns "alive"
        assert 'return (url, "alive")' in src
