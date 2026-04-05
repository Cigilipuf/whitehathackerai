"""
Phase 4 regression tests — HUNTER Mode Redesign.

P4.1: Statistical baseline engine (3 requests, timing stats, body hash set)
P4.2: Smart indicator detection (contextual XSS, statistical timing SQLi,
       multi-calc SSTI, expanded RCE patterns, baseline-aware error matching)
P4.3: LLM response context (timing info in hypothesis prompt)
P4.4: Stall detection expansion (6 iterations, blind max_iterations 20)
"""

import hashlib
import statistics
from dataclasses import field

import pytest


# ---------------------------------------------------------------------------
# P4.1 — Statistical baseline: ProbeTarget fields
# ---------------------------------------------------------------------------


class TestProbeTargetBaselineFields:
    """Verify ProbeTarget has new statistical baseline fields."""

    def test_timing_median_field(self):
        from src.workflow.pipelines.deep_probe import ProbeTarget

        t = ProbeTarget(url="https://example.com")
        assert hasattr(t, "baseline_timing_median")
        assert t.baseline_timing_median == 0.0

    def test_timing_stddev_field(self):
        from src.workflow.pipelines.deep_probe import ProbeTarget

        t = ProbeTarget(url="https://example.com")
        assert hasattr(t, "baseline_timing_stddev")
        assert t.baseline_timing_stddev == 0.0

    def test_body_hashes_field(self):
        from src.workflow.pipelines.deep_probe import ProbeTarget

        t = ProbeTarget(url="https://example.com")
        assert hasattr(t, "baseline_body_hashes")
        assert isinstance(t.baseline_body_hashes, set)
        assert len(t.baseline_body_hashes) == 0


# ---------------------------------------------------------------------------
# P4.2 — Smart indicator detection
# ---------------------------------------------------------------------------


class TestIndicatorDetection:
    """Test enhanced _detect_indicators() logic."""

    def _call(self, **kwargs):
        from src.workflow.pipelines.deep_probe import _detect_indicators

        defaults = dict(
            vuln_type="xss",
            payload="<script>alert(1)</script>",
            body="hello world",
            headers={},
            status=200,
            elapsed=0.3,
            baseline_timing_median=0.0,
            baseline_timing_stddev=0.0,
            baseline_body="",
        )
        defaults.update(kwargs)
        return _detect_indicators(**defaults)

    # -- XSS context detection --
    def test_xss_unencoded_in_html_body(self):
        """Unencoded XSS payload in HTML body context."""
        payload = "<img src=x onerror=alert(1)>"
        body = f"<div>{payload}</div>"
        inds = self._call(payload=payload, body=body)
        assert any("HTML body" in i for i in inds)

    def test_xss_unencoded_in_attribute(self):
        """Unencoded XSS payload inside HTML attribute context."""
        payload = "<img src=x onerror=alert(1)>"
        # Context before payload includes value= (attribute)
        body = f'<input value="{payload}">'
        inds = self._call(payload=payload, body=body)
        assert any("attribute" in i.lower() for i in inds)

    def test_xss_encoded_detected_as_filtered(self):
        payload = "<script>alert(1)</script>"
        encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"
        inds = self._call(payload=payload, body=encoded)
        assert any("encoded" in i.lower() or "filtered" in i.lower() for i in inds)

    def test_xss_no_reflection(self):
        """No indicators when payload is not reflected."""
        inds = self._call(payload="<script>alert(1)</script>", body="safe page")
        assert len(inds) == 0

    # -- SQLi statistical timing --
    def test_sqli_time_based_with_stats(self):
        """Time-based SQLi using statistical baseline — significant delay."""
        inds = self._call(
            vuln_type="sqli",
            payload="'; WAITFOR DELAY '0:0:5'--",
            body="ok",
            elapsed=5.2,
            baseline_timing_median=0.15,
            baseline_timing_stddev=0.05,
        )
        assert any("Time-based" in i for i in inds)
        assert any("σ" in i for i in inds)  # Should show sigma

    def test_sqli_time_based_within_normal_range(self):
        """No indicator when delay is within normal range."""
        inds = self._call(
            vuln_type="sqli",
            payload="'; SELECT SLEEP(0)--",
            body="ok",
            elapsed=0.5,
            baseline_timing_median=0.3,
            baseline_timing_stddev=0.15,
        )
        assert not any("Time-based" in i for i in inds)

    def test_sqli_error_not_in_baseline(self):
        """SQL error indicator only if not present in baseline."""
        inds = self._call(
            vuln_type="sqli",
            payload="' OR 1=1--",
            body="You have an error in your SQL syntax",
            baseline_body="",
        )
        assert any("Database error" in i for i in inds)

    def test_sqli_error_already_in_baseline_no_indicator(self):
        """SQL error in baseline should not produce indicator."""
        inds = self._call(
            vuln_type="sqli",
            payload="' OR 1=1--",
            body="You have an error in your SQL syntax",
            baseline_body="You have an error in your SQL syntax near ...",
        )
        assert not any("Database error" in i for i in inds)

    # -- SSTI multi-calculation --
    def test_ssti_single_calc(self):
        """Single 7*7=49 check."""
        inds = self._call(
            vuln_type="ssti",
            payload="{{7*7}}",
            body="Result: 49",
        )
        assert any("7*7=49" in i for i in inds)
        assert not any("Multiple" in i for i in inds)  # Only single calc

    def test_ssti_double_calc_high_confidence(self):
        """Both 7*7=49 and 7*6=42 → multiple calculation confirmed."""
        inds = self._call(
            vuln_type="ssti",
            payload="{{7*7}}{{7*6}}",
            body="49 and 42",
        )
        assert any("7*7=49" in i for i in inds)
        assert any("7*6=42" in i for i in inds)
        assert any("Multiple" in i for i in inds)

    # -- RCE expanded patterns --
    def test_rce_new_patterns(self):
        """New RCE patterns: 'drwx', '-rw-', 'total '."""
        inds = self._call(
            vuln_type="rce",
            payload=";ls -la",
            body="total 24\ndrwxr-xr-x 2 root root 4096",
        )
        assert any("Command output" in i for i in inds)

    def test_rce_pattern_in_baseline_no_indicator(self):
        """RCE pattern already in baseline should not trigger."""
        inds = self._call(
            vuln_type="rce",
            payload=";ls -la",
            body="uid=1000(user)",
            baseline_body="uid=1000(user) gid=1000",
        )
        assert not any("Command output" in i for i in inds)

    def test_rce_time_based_with_stats(self):
        """Time-based RCE detection with statistical baseline."""
        inds = self._call(
            vuln_type="rce",
            payload="; sleep 5",
            body="ok",
            elapsed=5.5,
            baseline_timing_median=0.2,
            baseline_timing_stddev=0.1,
        )
        assert any("Time-based" in i for i in inds)


# ---------------------------------------------------------------------------
# P4.3 — LLM hypothesis prompt includes timing stats
# ---------------------------------------------------------------------------


class TestLLMPromptContext:
    """Verify LLM prompt includes baseline timing statistics."""

    def test_hypothesis_prompt_contains_timing(self):
        """The hypothesis prompt template should include baseline timing info."""
        import inspect
        from src.workflow.pipelines.deep_probe import _llm_generate_hypothesis

        source = inspect.getsource(_llm_generate_hypothesis)
        assert "baseline_timing_median" in source or "Baseline Timing" in source


# ---------------------------------------------------------------------------
# P4.4 — Stall detection expansion
# ---------------------------------------------------------------------------


class TestStallDetection:
    """Verify expanded stall detection and blind max_iterations."""

    def test_stall_requires_7_history_entries(self):
        """Stall now requires 7+ confidence_history entries (was 4)."""
        import inspect
        from src.workflow.pipelines.deep_probe import _run_probe_cycle

        source = inspect.getsource(_run_probe_cycle)
        # Should check for >= 7 (6 recent entries + 1)
        assert ">= 7" in source or ">=7" in source

    def test_stall_checks_last_6(self):
        """Stall detection checks last 6 entries (was 3)."""
        import inspect
        from src.workflow.pipelines.deep_probe import _run_probe_cycle

        source = inspect.getsource(_run_probe_cycle)
        assert "[-6:]" in source

    def test_low_confidence_stop_at_4(self):
        """Low confidence early stop at iteration 4 (was 3)."""
        import inspect
        from src.workflow.pipelines.deep_probe import _run_probe_cycle

        source = inspect.getsource(_run_probe_cycle)
        assert "iteration >= 4" in source

    def test_blind_types_get_doubled_iterations(self):
        """Blind vuln types get max 20 iterations (doubled from base)."""
        import inspect
        from src.workflow.pipelines.deep_probe import deep_probe_endpoint

        source = inspect.getsource(deep_probe_endpoint)
        assert "_BLIND_TYPES" in source
        assert "* 2" in source or "*2" in source
        assert "20" in source


# ---------------------------------------------------------------------------
# P4.1+P4.2 — Integration: _detect_indicators with zero stddev edge case
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases for statistical timing and indicator detection."""

    def _call(self, **kwargs):
        from src.workflow.pipelines.deep_probe import _detect_indicators

        defaults = dict(
            vuln_type="sqli",
            payload="'; SELECT SLEEP(5)--",
            body="ok",
            headers={},
            status=200,
            elapsed=5.5,
            baseline_timing_median=0.0,
            baseline_timing_stddev=0.0,
            baseline_body="",
        )
        defaults.update(kwargs)
        return _detect_indicators(**defaults)

    def test_zero_stddev_uses_fixed_threshold(self):
        """When stddev=0 (single baseline), use median+3.0s threshold."""
        inds = self._call(
            baseline_timing_median=0.2,
            baseline_timing_stddev=0.0,
            elapsed=3.5,
        )
        # threshold = 0.2 + 3.0 = 3.2, elapsed=3.5 > 3.2 → indicator
        assert any("Time-based" in i for i in inds)

    def test_zero_stddev_below_threshold(self):
        """Below fixed threshold → no indicator."""
        inds = self._call(
            baseline_timing_median=0.2,
            baseline_timing_stddev=0.0,
            elapsed=2.8,
        )
        # threshold = max(0.2+3.0, 2.0) = 3.2, elapsed 2.8 < 3.2 → no indicator
        assert not any("Time-based" in i for i in inds)

    def test_minimum_2s_absolute_threshold(self):
        """Absolute minimum threshold of 2.0s prevents noise."""
        inds = self._call(
            baseline_timing_median=0.0,
            baseline_timing_stddev=0.0,
            elapsed=1.8,
        )
        # threshold = max(0+3.0, 2.0) = 3.0, elapsed 1.8 < 3.0 → no indicator
        assert not any("Time-based" in i for i in inds)

    def test_imports_present(self):
        """Verify statistics and hashlib imports exist."""
        import inspect
        import src.workflow.pipelines.deep_probe as dp

        source = inspect.getsource(dp)
        assert "import statistics" in source
        assert "import hashlib" in source
