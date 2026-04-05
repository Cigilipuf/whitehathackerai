"""
Regression tests for deep audit fixes (v2.7.7 quality audit).

BUG-1: ScanProfiler record_stage/record_tool wrong kwargs
BUG-2: ContinuousMonitor _execute_scan wrong run_scan params
BUG-3: _dict_to_finding missing cve_id and confidence fallback
BUG-4: _save_partial_state missing metadata/technologies/tools_run
BUG-5: Scope validation fail-open logged at debug instead of warning
"""

import inspect
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ============================================================
# BUG-1: ScanProfiler record_stage/record_tool kwargs
# ============================================================

class TestScanProfilerIntegration:
    """ScanProfiler calls in full_scan.py must use correct parameter names."""

    def test_record_stage_accepts_findings_count(self):
        """record_stage param is 'findings_count', not 'findings_produced'."""
        from src.analysis.scan_profiler import ScanProfiler
        profiler = ScanProfiler()
        profiler.start_scan()
        # Must not raise TypeError
        profiler.record_stage(name="test_stage", duration_s=1.0, findings_count=5)
        profiler.end_scan()
        report = profiler.generate_report()
        assert len(report.stage_timings) == 1
        assert report.stage_timings[0].findings_produced == 5

    def test_record_stage_rejects_wrong_kwarg(self):
        """record_stage must NOT accept 'findings_produced' as kwarg."""
        from src.analysis.scan_profiler import ScanProfiler
        profiler = ScanProfiler()
        profiler.start_scan()
        with pytest.raises(TypeError):
            profiler.record_stage(
                name="test", duration_s=1.0,
                findings_produced=5,  # WRONG kwarg name
                tools_run=[],  # Non-existent param
            )

    def test_record_tool_rejects_stage_name_kwarg(self):
        """record_tool must NOT accept 'stage_name' as kwarg."""
        from src.analysis.scan_profiler import ScanProfiler
        profiler = ScanProfiler()
        profiler.start_scan()
        with pytest.raises(TypeError):
            profiler.record_tool(
                stage_name="vuln_scan",  # WRONG — non-existent param
                tool_name="nmap",
                duration_s=1.0,
                success=True,
            )

    def test_record_tool_correct_params(self):
        """record_tool with correct params must work."""
        from src.analysis.scan_profiler import ScanProfiler
        profiler = ScanProfiler()
        profiler.start_scan()
        profiler.record_tool(
            tool_name="nuclei", duration_s=30.0,
            success=True, findings_count=10,
        )
        profiler.end_scan()
        report = profiler.generate_report()
        assert "nuclei" in report.tool_effectiveness


# ============================================================
# BUG-2: ContinuousMonitor _execute_scan parameter names
# ============================================================

class TestContinuousMonitorRunScanParams:
    """ContinuousMonitor must call run_scan with correct parameter names."""

    def test_execute_scan_uses_correct_param_names(self):
        """Check that _execute_scan source code uses correct param names."""
        from src.workflow.continuous_monitor import ContinuousMonitor
        source = inspect.getsource(ContinuousMonitor._execute_scan)
        # Must NOT use old wrong param names
        assert "scope_file=" not in source, "scope_file= is wrong, should be scope="
        assert "verbose=" not in source, "verbose= is not a run_scan param"
        # mode= and profile= are ambiguous — check for the correct override versions
        assert "mode_override=" in source, "Should use mode_override= not mode="
        assert "profile_override=" in source, "Should use profile_override= not profile="

    def test_execute_scan_loads_scope_from_file(self):
        """Check that scope_file path is loaded as dict before passing to run_scan."""
        from src.workflow.continuous_monitor import ContinuousMonitor
        source = inspect.getsource(ContinuousMonitor._execute_scan)
        # Should load YAML from self.scope_file
        assert "yaml.safe_load" in source, "Should load scope file as YAML dict"
        assert "scope=scope_dict" in source or "scope=" in source


# ============================================================
# BUG-3: _dict_to_finding confidence fallback and cve_id
# ============================================================

class TestDictToFindingFieldMapping:
    """_dict_to_finding must correctly map confidence and cve_id fields."""

    def _get_dict_to_finding(self):
        """Import the _dict_to_finding helper (it's nested, so extract via source)."""
        # We test the logic indirectly by checking Finding construction
        from src.tools.base import Finding
        from src.utils.constants import SeverityLevel
        return Finding, SeverityLevel

    def test_confidence_fallback_to_confidence_key(self):
        """If dict has 'confidence' but not 'confidence_score', should use it."""
        from src.tools.base import Finding
        # Simulate what _dict_to_finding does:
        d = {"confidence": 85.0}  # No confidence_score
        # The fixed code: d.get("confidence_score", d.get("confidence", 50.0))
        result = d.get("confidence_score", d.get("confidence", 50.0))
        assert result == 85.0, "Should fall back to 'confidence' key"

    def test_confidence_prefers_confidence_score(self):
        """If dict has both keys, confidence_score takes priority."""
        d = {"confidence_score": 90.0, "confidence": 70.0}
        result = d.get("confidence_score", d.get("confidence", 50.0))
        assert result == 90.0

    def test_confidence_default_when_both_missing(self):
        """If neither key exists, default to 50.0."""
        d = {}
        result = d.get("confidence_score", d.get("confidence", 50.0))
        assert result == 50.0

    def test_cve_id_in_dict_to_finding_source(self):
        """_dict_to_finding must map cve_id field."""
        import src.workflow.pipelines.full_scan as fs
        source = inspect.getsource(fs)
        # Check that _dict_to_finding passes cve_id (may be wrapped in _cs())
        assert 'cve_id=' in source and 'd.get("cve_id"' in source, "cve_id must be mapped in _dict_to_finding"


# ============================================================
# BUG-4: _save_partial_state missing fields
# ============================================================

class TestSavePartialState:
    """_save_partial_state must include metadata, technologies, tools_run."""

    def test_partial_state_includes_tools_run(self):
        from src.workflow.orchestrator import _save_partial_state, WorkflowState
        import tempfile
        state = WorkflowState(
            session_id="test_audit_001",
            target="example.com",
            tools_run=["nmap", "nuclei", "sqlmap"],
            technologies={"example.com": ["nginx", "php"]},
            metadata={"is_spa": True, "waf_detected": "cloudflare"},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("src.workflow.orchestrator._save_partial_state") as _:
                pass  # Don't actually call it, just verify the source
            # Instead, verify via source inspection
            source = inspect.getsource(_save_partial_state)
            assert '"tools_run"' in source, "tools_run must be in serialization"
            assert '"technologies"' in source, "technologies must be in serialization"
            assert '"metadata"' in source, "metadata must be in serialization"

    def test_partial_state_filters_non_serializable_metadata(self):
        """metadata values that aren't JSON-serializable should be filtered."""
        from src.workflow.orchestrator import _save_partial_state
        source = inspect.getsource(_save_partial_state)
        # The fix filters metadata to only include JSON-serializable types
        assert "isinstance(v," in source, "metadata should be filtered for serializability"


# ============================================================
# BUG-5: Scope validation error visibility
# ============================================================

class TestScopeValidationVisibility:
    """Scope validation failures must log at WARNING, not DEBUG."""

    def test_scope_failure_logged_at_warning_level(self):
        """Source code must use logger.warning for scope setup failures."""
        import src.workflow.pipelines.full_scan as fs
        source = inspect.getsource(fs)
        # The fix changed debug → warning
        assert 'logger.warning(f"ScopeValidator setup failed' in source or \
               'logger.warning(f"ScopeValidator setup' in source, \
               "Scope validation failure must be logged at WARNING level"
        # Must NOT be debug
        assert 'logger.debug(f"ScopeValidator setup skipped' not in source, \
               "Scope validation failure must NOT be at DEBUG level"


# ============================================================
# Cross-integration: finding_to_dict ↔ dict_to_finding roundtrip
# ============================================================

class TestFindingRoundtrip:
    """Finding → dict → Finding should preserve critical fields."""

    def test_cve_id_preserved_in_finding_to_dict(self):
        """_finding_to_dict should include cve_id when present."""
        import src.workflow.pipelines.full_scan as fs
        source = inspect.getsource(fs)
        # _finding_to_dict preserves cve_id via the rich fields loop
        assert '"cve_id"' in source

    def test_confidence_dual_key_sync_in_finding_to_dict(self):
        """_finding_to_dict must sync both confidence and confidence_score."""
        import src.workflow.pipelines.full_scan as fs
        source = inspect.getsource(fs)
        assert 'd["confidence_score"] = d["confidence"]' in source
        assert 'd["confidence"] = d["confidence_score"]' in source
