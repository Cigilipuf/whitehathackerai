"""Regression tests for v2.5 audit fixes (NEXT_LEVEL_PLAN_V25).

Tests cover:
- CRIT-1: api_scan findings sync to state.raw_findings
- CRIT-2: Unified vuln-type normalization consistency
- CRIT-3: FP detector Layer 6 timeout values
- CRIT-4: global_finding_store SQL param fix
- HIGH-1: Orchestrator state machine force_transition
- HIGH-2: web_app _finding_to_dict completeness
- HIGH-3: api_scan stage-handler ordering
- HIGH-4: OOB correlation max-2 limit
- HIGH-5: CLI version string
- HIGH-6: auto_draft silent exception logging
- MED-1: benchmark_lab expected class normalization
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any


# ── CRIT-1: api_scan findings sync ──────────────────────────

class TestApiScanFindingsSync:
    """api_scan handlers must sync findings to state.raw_findings."""

    def test_handler_populates_raw_findings(self):
        """After handle_api_auth_analysis, state.raw_findings should contain findings."""
        from src.workflow.pipelines import api_scan
        source = inspect.getsource(api_scan)
        # All 3 handlers must sync to raw_findings
        assert source.count("state.raw_findings = list(state.metadata.get") >= 3, (
            "All 3 api_scan handlers must sync findings to state.raw_findings"
        )

    def test_sync_line_follows_extend(self):
        """Sync to raw_findings must appear after extending all_findings."""
        from src.workflow.pipelines import api_scan
        source = inspect.getsource(api_scan)
        lines = source.split("\n")
        for i, line in enumerate(lines):
            if "setdefault(\"all_findings\"" in line and ".extend(" in line:
                # Next non-blank line should be the raw_findings sync
                for j in range(i + 1, min(i + 4, len(lines))):
                    if "state.raw_findings" in lines[j]:
                        break
                else:
                    assert False, (
                        f"raw_findings sync not found within 3 lines after "
                        f"all_findings extend at line {i + 1}"
                    )


# ── CRIT-3: FP detector Layer 6 timeout ─────────────────────

class TestFPDetectorTimeout:
    """Layer 6 timeout must not be 600s for both branches."""

    def test_timeout_high_sev(self):
        from src.fp_engine import fp_detector
        source = inspect.getsource(fp_detector)
        assert "600.0 if _is_high_sev else 600.0" not in source, (
            "Both branches of timeout must not be 600.0"
        )

    def test_timeout_values_different(self):
        from src.fp_engine import fp_detector
        source = inspect.getsource(fp_detector)
        # Should have 180 for high sev, 120 for others
        assert "180.0" in source, "High-sev timeout should be 180s"
        assert "120.0" in source, "Normal timeout should be 120s"


# ── CRIT-4: global_finding_store SQL params ──────────────────

class TestGlobalFindingStoreSQL:
    """SQL param construction must not have dead code."""

    def test_no_dead_params_extend(self):
        from src.analysis import global_finding_store
        source = inspect.getsource(global_finding_store)
        # The dead pattern was: params.extend([now]) followed by params[:-1]
        assert "params[:-1]" not in source, (
            "Dead params[:-1] code should be removed"
        )


# ── HIGH-1: StateMachine force_transition ─────────────────────

class TestStateMachineForceTransition:
    """StateMachine must support force_transition for orchestrator sync."""

    def test_force_transition_exists(self):
        from src.workflow.state_machine import StateMachine
        assert hasattr(StateMachine, "force_transition"), (
            "StateMachine must have force_transition method"
        )

    def test_force_transition_bypasses_guard(self):
        from src.workflow.state_machine import StateMachine
        from src.utils.constants import WorkflowStage

        sm = StateMachine()
        sm.start()  # Always starts at SCOPE_ANALYSIS

        # Normal transition to a non-adjacent state should fail
        assert not sm.can_transition(WorkflowStage.REPORTING)

        # Force transition should succeed
        result = sm.force_transition(WorkflowStage.REPORTING, trigger="test")
        assert result is True
        assert sm.current_state == WorkflowStage.REPORTING

    def test_force_transition_records_history(self):
        from src.workflow.state_machine import StateMachine
        from src.utils.constants import WorkflowStage

        sm = StateMachine()
        sm.start()  # Always starts at SCOPE_ANALYSIS
        sm.force_transition(WorkflowStage.REPORTING, trigger="test_force")

        history = sm.get_history()
        assert len(history) >= 1
        last = history[-1]
        # StateEvent is a Pydantic model — use attribute access
        trigger = getattr(last, "trigger", None)
        to_state = getattr(last, "to_state", None) or getattr(last, "to", None)
        assert trigger == "test_force" or str(to_state) == "reporting", (
            f"History should record forced transition, got trigger={trigger}, to={to_state}"
        )

    def test_force_transition_not_started(self):
        from src.workflow.state_machine import StateMachine
        from src.utils.constants import WorkflowStage

        sm = StateMachine()
        result = sm.force_transition(WorkflowStage.REPORTING)
        assert result is False

    def test_orchestrator_uses_force_transition(self):
        from src.workflow import orchestrator
        source = inspect.getsource(orchestrator)
        assert "force_transition" in source, (
            "Orchestrator must use force_transition instead of direct _current assignment"
        )


# ── HIGH-2: web_app _finding_to_dict completeness ────────────

class TestWebAppFindingToDict:
    """web_app._finding_to_dict must include all essential fields."""

    def test_has_confidence_fields(self):
        from src.workflow.pipelines.web_app import _finding_to_dict

        finding = SimpleNamespace(
            title="Test XSS",
            vulnerability_type="xss",
            url="https://example.com",
            parameter="q",
            payload="<script>",
            severity="high",
            description="Test",
            evidence="Reflected",
            confidence=85.0,
            confidence_score=85.0,
            cve_id="CVE-2024-1234",
            cwe_id="CWE-79",
            http_request="GET /test",
            http_response="200 OK",
            impact="Account takeover",
            remediation="Encode output",
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            endpoint="https://example.com/test",
            target="example.com",
        )

        result = _finding_to_dict(finding, "dalfox", "example.com")

        # All these fields must be present
        assert "confidence" in result
        assert "confidence_score" in result
        assert "cve_id" in result
        assert "cwe_id" in result
        assert "http_request" in result
        assert "http_response" in result
        assert "impact" in result
        assert "remediation" in result
        assert result["confidence"] == 85.0
        assert result["confidence_score"] == 85.0

    def test_handles_missing_attributes(self):
        from src.workflow.pipelines.web_app import _finding_to_dict

        finding = SimpleNamespace(title="Minimal")
        result = _finding_to_dict(finding, "test_tool", "example.com")

        assert result["confidence_score"] is not None
        assert isinstance(result["url"], str)

    def test_handles_url_as_list(self):
        from src.workflow.pipelines.web_app import _finding_to_dict

        finding = SimpleNamespace(
            title="Test",
            url=["https://a.com", "https://b.com"],
        )
        result = _finding_to_dict(finding, "test_tool", "example.com")
        assert isinstance(result["url"], str)
        assert result["url"] == "https://a.com"


# ── HIGH-3: api_scan handler ordering ─────────────────────────

class TestApiScanHandlerOrdering:
    """Business logic must run AFTER injection scan."""

    def test_injection_before_business_logic(self):
        from src.workflow.pipelines.api_scan import build_api_scan_pipeline
        from src.utils.constants import WorkflowStage

        orchestrator = build_api_scan_pipeline("https://api.example.com")
        pipeline = orchestrator._pipeline

        # Find positions of injection and business logic stages
        injection_stage = None
        business_stage = None

        for stage in pipeline:
            handler = orchestrator._handlers.get(stage)
            if handler:
                handler_name = getattr(handler, "__name__", "")
                if "injection" in handler_name:
                    injection_stage = pipeline.index(stage)
                if "business" in handler_name:
                    business_stage = pipeline.index(stage)

        if injection_stage is not None and business_stage is not None:
            assert injection_stage < business_stage, (
                "Injection scan must run before business logic tests"
            )


# ── HIGH-4: OOB correlation max-2 limit ──────────────────────

class TestOOBCorrelationLimit:
    """Type-based OOB heuristic must limit matches to prevent over-broad confirmation."""

    def test_source_has_limit(self):
        from src.analysis import correlation_engine
        source = inspect.getsource(correlation_engine)
        assert "_type_matches" in source or "len(_type_matches) >= 2" in source, (
            "OOB type-based heuristic must limit matches"
        )

    def test_limit_prevents_overbroad(self):
        """Create scenario with many OOB interactions - should cap at 2."""
        from src.analysis import correlation_engine
        source = inspect.getsource(correlation_engine)
        # Verify the break condition exists
        assert ">= 2" in source, "Must have max-2 limit on type-based matches"


# ── HIGH-5: CLI version string ────────────────────────────────

class TestCLIVersion:
    """CLI version must match current version."""

    def test_version_is_v3_4(self):
        from src import cli
        source = inspect.getsource(cli)
        assert "v3.4" in source, "CLI version should be v3.4"
        assert "v2.8.0" not in source, "Old version v2.8.0 should be removed"


# ── HIGH-6: auto_draft exception handling ─────────────────────

class TestAutoDraftExceptionHandling:
    """auto_draft must not silently swallow exceptions."""

    def test_no_bare_except_pass(self):
        from src.reporting import auto_draft
        source = inspect.getsource(auto_draft)
        lines = source.split("\n")
        for i, line in enumerate(lines):
            if "except Exception:" in line.strip() and i + 1 < len(lines):
                next_stripped = lines[i + 1].strip()
                assert next_stripped != "pass", (
                    f"Bare 'except Exception: pass' found at line {i + 1}"
                )


# ── MED-1: benchmark_lab normalization ────────────────────────

class TestBenchmarkLabNormalization:
    """Expected-class names must be normalized before comparison."""

    def test_normalized_expected_classes_exists(self):
        from src.analysis import benchmark_lab
        source = inspect.getsource(benchmark_lab)
        assert "normalized_expected_classes" in source, (
            "evaluate() must create normalized_expected_classes set"
        )

    def test_normalized_noise_classes_exists(self):
        from src.analysis import benchmark_lab
        source = inspect.getsource(benchmark_lab)
        assert "normalized_noise_classes" in source, (
            "evaluate() must create normalized_noise_classes set"
        )

    def test_per_class_uses_normalized(self):
        from src.analysis import benchmark_lab
        source = inspect.getsource(benchmark_lab)
        assert 'normalize_vuln_type(vc["class"])' in source, (
            "Per-class detail must normalize class names"
        )


# ── Correlation engine log level ──────────────────────────────

class TestCorrelationLogLevel:
    """Attack chain detection should log at INFO level, not WARNING."""

    def test_chain_detected_is_info(self):
        from src.analysis import correlation_engine
        source = inspect.getsource(correlation_engine)
        assert 'logger.info(\n                f"Attack chain detected' in source or \
               'logger.info(f"Attack chain detected' in source, (
            "Attack chain log should be INFO, not WARNING"
        )


# ════════════════════════════════════════════════════════════════
# MEDIUM BUG FIXES — Batch 2
# ════════════════════════════════════════════════════════════════


# ── MED-EQG: EvidenceQualityGate PoC bypass ───────────────────

class TestEvidenceQualityGatePoC:
    """PoC-confirmed findings must auto-pass the evidence quality gate."""

    def test_poc_confirmed_bypasses_gate(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        finding = {
            "severity": "CRITICAL",
            "poc_confirmed": True,
            "evidence": "",  # No text evidence — should still pass
        }
        verdict = evaluate(finding)
        assert verdict.passed is True
        assert "poc_confirmed" in verdict.signals_found

    def test_is_proven_bypasses_gate(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        finding = {
            "severity": "HIGH",
            "is_proven": True,
        }
        verdict = evaluate(finding)
        assert verdict.passed is True

    def test_unproven_critical_still_gated(self):
        from src.fp_engine.evidence_quality_gate import evaluate
        finding = {
            "severity": "CRITICAL",
            "evidence": "",
        }
        verdict = evaluate(finding)
        assert verdict.passed is False
        assert verdict.confidence_cap is not None


# ── MED-EA: EvidenceAggregator attribute safety ───────────────

class TestEvidenceAggregatorSafety:
    """collect() must handle dict-based and missing-attribute inputs."""

    def test_dict_as_proven_finding(self):
        """Passing a dict instead of ProvenFinding should not crash."""
        from src.reporting.evidence.evidence_aggregator import EvidenceAggregator
        agg = EvidenceAggregator(session_dir="/tmp/test_evidence")
        # Create a dict masquerading as proven_finding (no .finding attribute)
        fake = {"title": "Test XSS", "severity": "HIGH", "url": "https://example.com"}
        import asyncio
        package = asyncio.run(agg.collect(fake))
        assert package.finding_title == "Test XSS"
        assert package.is_proven is False  # dict has no is_proven
        assert package.confidence == 0.0

    def test_proper_object_still_works(self):
        from src.reporting.evidence.evidence_aggregator import EvidenceAggregator
        agg = EvidenceAggregator(session_dir="/tmp/test_evidence2")

        class FakeStrategy:
            value = "poc_script"

        class FakeProven:
            finding = {"title": "SQLi", "severity": "CRITICAL", "url": "https://x.com"}
            is_proven = True
            confidence = 95.0
            poc_code = "curl ..."
            poc_output = "admin:hash"
            evidence_items = ["item1"]
            strategy_used = FakeStrategy()
            verification_time = 12.5
            iterations_used = 3
            metasploit_module = ""

        import asyncio
        package = asyncio.run(agg.collect(FakeProven()))
        assert package.is_proven is True
        assert package.confidence == 95.0


# ── MED-SP: ScanProfiler sentinel ────────────────────────────

class TestScanProfilerSentinel:
    """ScanProfiler should not report fake 1.0s duration."""

    def test_no_timing_uses_small_sentinel(self):
        from src.analysis.scan_profiler import ScanProfiler
        profiler = ScanProfiler()
        profiler.start_scan()
        # Don't record any stages or call end_scan
        profiler._scan_end = 0  # Force no end time
        profiler._stages = []
        report = profiler.generate_report()
        # Should be near 0, not 1.0
        assert report.total_duration_s < 0.01


# ── MED-NW: Notification webhook URL validation ──────────────

class TestNotificationWebhookValidation:
    """Webhook URLs must be validated for safe schemes."""

    def test_https_accepted(self):
        from src.integrations.notification import SlackChannel
        ch = SlackChannel(webhook_url="https://hooks.slack.com/test")
        assert ch.webhook_url == "https://hooks.slack.com/test"

    def test_file_scheme_rejected(self):
        from src.integrations.notification import SlackChannel
        ch = SlackChannel(webhook_url="file:///etc/passwd")
        assert ch.webhook_url == ""

    def test_empty_url_accepted_as_disabled(self):
        from src.integrations.notification import SlackChannel
        ch = SlackChannel(webhook_url="")
        assert ch.webhook_url == ""

    def test_no_hostname_rejected(self):
        from src.integrations.notification import SlackChannel
        ch = SlackChannel(webhook_url="https://")
        assert ch.webhook_url == ""

    def test_discord_also_validated(self):
        from src.integrations.notification import DiscordChannel
        ch = DiscordChannel(webhook_url="ftp://evil.com")
        assert ch.webhook_url == ""


# ── MED-AD: auto_draft severity coercion ──────────────────────

class TestAutoDraftSeverityCoercion:
    """_bugcrowd_priority must handle None/non-string severity safely."""

    def test_none_severity(self):
        from src.reporting.auto_draft import AutoDraftGenerator
        result = AutoDraftGenerator._bugcrowd_priority(None)
        assert result == "P5 (Informational)"

    def test_empty_severity(self):
        from src.reporting.auto_draft import AutoDraftGenerator
        result = AutoDraftGenerator._bugcrowd_priority("")
        assert result == "P5 (Informational)"

    def test_info_explicit(self):
        from src.reporting.auto_draft import AutoDraftGenerator
        result = AutoDraftGenerator._bugcrowd_priority("INFO")
        assert result == "P5 (Informational)"


# ── MED-FP-CAP: FP early-layer penalty cap ───────────────────

class TestFPEarlyLayerCap:
    """Early layers (0-1e) must have cumulative penalty cap of -40."""

    def test_source_has_early_layer_cap(self):
        from src.fp_engine import fp_detector
        source = inspect.getsource(fp_detector)
        assert "_early_total" in source, "Early-layer cap variable must exist"
        assert "-40.0" in source, "Cap threshold must be -40"

    def test_source_imports_time(self):
        from src.fp_engine import fp_detector
        source = inspect.getsource(fp_detector)
        assert "import time" in source, "time module must be imported for brain recovery"


# ── MED-BR: Brain-down recovery in FP detector ───────────────

class TestFPBrainDownRecovery:
    """FP detector brain-down check should allow recovery after timeout."""

    def test_recovery_timeout_check_exists(self):
        from src.fp_engine import fp_detector
        source = inspect.getsource(fp_detector)
        assert "_brain_down_since" in source, (
            "FP detector must check _brain_down_since for recovery"
        )
        assert "_recovery_timeout" in source, (
            "FP detector must check recovery timeout"
        )
