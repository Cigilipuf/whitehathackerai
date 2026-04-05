"""Regression tests for SessionManager resume fidelity."""

from __future__ import annotations

from src.utils.constants import WorkflowStage
from src.workflow.orchestrator import StageResult, WorkflowState
from src.workflow.session_manager import SessionManager


class TestSessionManagerResume:
    """Ensure resume restores the workflow context later stages require."""

    def test_sync_roundtrip_restores_metadata_tools_and_stage_results(self, tmp_output_dir):
        manager = SessionManager(output_dir=tmp_output_dir)
        session = manager.create_session(target="example.com")

        state = WorkflowState(
            target="example.com",
            metadata={
                "auth_headers": {"Authorization": "Bearer token"},
                "intelligence_plan": {"brain_vectors": ["idor", "jwt"]},
            },
            tools_run=["httpx", "jwt_checker"],
            reports_generated=["output/reports/rpt.md"],
            completed_stages=[WorkflowStage.PASSIVE_RECON],
            stage_results={
                "passive_recon": StageResult(
                    stage=WorkflowStage.PASSIVE_RECON,
                    success=True,
                    duration=12.5,
                    findings_count=3,
                    data={"subdomains": ["api.example.com"]},
                )
            },
            subdomains=["api.example.com"],
        )

        manager.sync_from_workflow_state(session, state)

        assert session.workflow_metadata["auth_headers"]["Authorization"] == "Bearer token"
        assert session.tools_run == ["httpx", "jwt_checker"]
        assert session.metadata.tools_executed == 2

        manager.record_stage_start(session, "passive_recon")
        manager.record_stage_complete(
            session,
            "passive_recon",
            findings_count=3,
            data={"subdomains": ["api.example.com"]},
        )

        restored = WorkflowState(target="example.com")
        manager.sync_to_workflow_state(session, restored)

        assert restored.metadata["auth_headers"]["Authorization"] == "Bearer token"
        assert restored.metadata["intelligence_plan"]["brain_vectors"] == ["idor", "jwt"]
        assert restored.tools_run == ["httpx", "jwt_checker"]
        assert restored.reports_generated == ["output/reports/rpt.md"]
        assert "passive_recon" in restored.stage_results
        assert restored.stage_results["passive_recon"].data["subdomains"] == ["api.example.com"]
        assert restored.stage_results["passive_recon"].findings_count == 3

    def test_find_incomplete_sessions_filters_by_target(self, tmp_output_dir):
        manager = SessionManager(output_dir=tmp_output_dir)

        session_a = manager.create_session(target="alpha.example.com")
        session_b = manager.create_session(target="beta.example.com")

        manager.start_session(session_a.metadata.session_id)
        manager.start_session(session_b.metadata.session_id)

        filtered = manager.find_incomplete_sessions(target="beta.example.com")

        assert len(filtered) == 1
        assert filtered[0].metadata.target == "beta.example.com"

    def test_sync_roundtrip_restores_auth_fields_and_enum_stage_keys(self, tmp_output_dir):
        manager = SessionManager(output_dir=tmp_output_dir)
        session = manager.create_session(target="example.com")

        state = WorkflowState(
            target="example.com",
            auth_headers={"Authorization": "Bearer token"},
            auth_roles=[{"role_name": "admin", "headers": {"Authorization": "Bearer admin"}}],
            completed_stages=[WorkflowStage.PASSIVE_RECON],
            stage_results={
                WorkflowStage.PASSIVE_RECON: StageResult(
                    stage=WorkflowStage.PASSIVE_RECON,
                    success=True,
                    findings_count=1,
                )
            },
        )

        manager.sync_from_workflow_state(session, state)

        restored = WorkflowState(target="example.com")
        manager.sync_to_workflow_state(session, restored)

        assert restored.auth_headers["Authorization"] == "Bearer token"
        assert restored.auth_roles[0]["role_name"] == "admin"
        assert WorkflowStage.PASSIVE_RECON in restored.completed_stages
        assert WorkflowStage.PASSIVE_RECON in restored.stage_results