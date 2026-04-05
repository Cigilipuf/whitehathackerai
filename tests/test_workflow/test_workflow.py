"""Tests for Workflow Orchestrator and Pipelines."""

from __future__ import annotations

from unittest.mock import MagicMock, AsyncMock

import pytest

from src.workflow.state_machine import StateMachine
from src.workflow.decision_engine import DecisionEngine


class TestStateMachine:
    """Test workflow state machine."""

    def test_creation(self):
        sm = StateMachine()
        assert sm is not None

    def test_initial_state(self):
        sm = StateMachine()
        # StateMachine starts with _current = None (no stage until transition)
        assert sm.current_state is None


class TestDecisionEngine:
    """Test decision engine."""

    def test_creation(self):
        engine = DecisionEngine()
        assert engine is not None


class TestStateMachineOrchestratorWiring:
    """Test that StateMachine is wired into WorkflowOrchestrator."""

    def test_orchestrator_has_state_machine(self):
        from src.workflow.orchestrator import WorkflowOrchestrator
        orch = WorkflowOrchestrator()
        assert hasattr(orch, '_state_machine')
        assert isinstance(orch._state_machine, StateMachine)

    def test_state_machine_starts_at_scope_analysis(self):
        from src.workflow.orchestrator import WorkflowOrchestrator
        from src.utils.constants import WorkflowStage
        orch = WorkflowOrchestrator()
        assert orch._state_machine.current_state == WorkflowStage.SCOPE_ANALYSIS

    def test_state_machine_can_transition_normal_flow(self):
        sm = StateMachine()
        sm.start()
        from src.utils.constants import WorkflowStage
        assert sm.can_transition(WorkflowStage.PASSIVE_RECON) is True
        assert sm.can_transition(WorkflowStage.VULNERABILITY_SCAN) is False  # Can't skip directly


class TestDecisionEngineSelectTools:
    """Test DecisionEngine.select_tools() with technology context (V13-T0-2)."""

    def test_select_tools_returns_result(self):
        import asyncio
        from src.utils.constants import WorkflowStage
        engine = DecisionEngine()
        result = asyncio.new_event_loop().run_until_complete(
            engine.select_tools(
                stage=WorkflowStage.VULNERABILITY_SCAN,
                target_type="web",
            )
        )
        assert result is not None
        assert hasattr(result, "selected_tools")

    def test_select_tools_with_tech_context(self):
        import asyncio
        from src.utils.constants import WorkflowStage
        engine = DecisionEngine()
        result = asyncio.new_event_loop().run_until_complete(
            engine.select_tools(
                stage=WorkflowStage.VULNERABILITY_SCAN,
                target_type="web",
                context={"technologies": {"detected": ["wordpress", "php"]}},
            )
        )
        assert "wpscan" in result.selected_tools


class TestFullScanPipelineSessionManager:
    """Test that the full scan pipeline wires SessionManager through."""

    def test_build_pipeline_accepts_session_manager(self, tmp_output_dir):
        from src.workflow.pipelines.full_scan import build_full_scan_pipeline
        from src.workflow.session_manager import SessionManager

        sm = SessionManager(output_dir=tmp_output_dir)
        orchestrator = build_full_scan_pipeline(session_manager=sm)

        assert orchestrator.session_manager is sm
