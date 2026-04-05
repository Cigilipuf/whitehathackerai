"""Tests for DecisionEngine — tool selection, transition, filtering."""

import asyncio
import pytest

from src.workflow.decision_engine import (
    DecisionEngine,
    Decision,
    ToolSelectionResult,
    StageTransitionResult,
    STAGE_TOOL_MATRIX,
    PROFILE_LIMITS,
)
from src.workflow.state_machine import WorkflowStage


# ── Model defaults ───────────────────────────────────────

def test_decision_defaults():
    d = Decision()
    assert d.confidence == 0.0
    assert not d.is_confident


def test_decision_confident_threshold():
    d = Decision(confidence=0.8)
    assert d.is_confident
    d2 = Decision(confidence=0.5)
    assert not d2.is_confident


def test_tool_selection_defaults():
    ts = ToolSelectionResult(selected_tools=["nmap"])
    assert ts.execution_order == "parallel"


def test_stage_transition_defaults():
    st = StageTransitionResult()
    assert st.should_proceed is True
    assert st.next_stage == ""


# ── Constants ────────────────────────────────────────────

def test_stage_tool_matrix_populated():
    assert isinstance(STAGE_TOOL_MATRIX, dict)
    assert "passive_recon" in STAGE_TOOL_MATRIX
    assert "vulnerability_scanning" in STAGE_TOOL_MATRIX


def test_stage_tool_matrix_has_target_types():
    for stage, targets in STAGE_TOOL_MATRIX.items():
        assert isinstance(targets, dict)
        # Should have at least domain and web
        assert any(k in targets for k in ("domain", "web", "url", "ip"))


def test_profile_limits_all_profiles():
    for profile in ("stealth", "balanced", "aggressive"):
        assert profile in PROFILE_LIMITS
        assert "max_parallel" in PROFILE_LIMITS[profile]
        assert "rate_multiplier" in PROFILE_LIMITS[profile]


def test_profile_stealth_is_restrictive():
    s = PROFILE_LIMITS["stealth"]
    a = PROFILE_LIMITS["aggressive"]
    assert s["max_parallel"] <= a["max_parallel"]
    assert s["rate_multiplier"] <= a["rate_multiplier"]


# ── Engine init ──────────────────────────────────────────

def test_engine_init_no_brain():
    engine = DecisionEngine()
    assert engine.brain is None
    assert isinstance(engine.get_decision_log(), list)


def test_engine_stats():
    engine = DecisionEngine()
    stats = engine.get_stats()
    assert isinstance(stats, dict)


# ── select_tools (rule-based without brain) ──────────────

def test_select_tools_passive_recon():
    engine = DecisionEngine()
    result = asyncio.run(engine.select_tools(
        stage=WorkflowStage.PASSIVE_RECON,
        target_type="domain",
    ))
    assert isinstance(result, ToolSelectionResult)
    assert len(result.selected_tools) >= 1


def test_select_tools_vuln_scan():
    engine = DecisionEngine()
    result = asyncio.run(engine.select_tools(
        stage=WorkflowStage.VULNERABILITY_SCAN,
        target_type="web",
    ))
    assert isinstance(result, ToolSelectionResult)
    assert len(result.selected_tools) >= 1


def test_select_tools_with_context():
    engine = DecisionEngine()
    result = asyncio.run(engine.select_tools(
        stage=WorkflowStage.ACTIVE_RECON,
        target_type="domain",
        context={"technologies": {"cms": ["wordpress"]}},
    ))
    assert isinstance(result, ToolSelectionResult)


# ── filter_irrelevant_tools ──────────────────────────────

def test_filter_irrelevant_tools_removes_wp_without_wordpress():
    engine = DecisionEngine()
    tools = ["nmap", "wpscan", "nuclei"]
    technologies = {"frameworks": ["django"]}  # no wordpress
    filtered = engine.filter_irrelevant_tools(tools, technologies)
    assert "wpscan" not in filtered
    assert "nmap" in filtered
    assert "nuclei" in filtered


def test_filter_irrelevant_tools_keeps_wp_with_wordpress():
    engine = DecisionEngine()
    tools = ["nmap", "wpscan", "nuclei"]
    technologies = {"cms": ["wordpress"]}
    filtered = engine.filter_irrelevant_tools(tools, technologies)
    assert "wpscan" in filtered


def test_filter_irrelevant_tools_empty_tech():
    engine = DecisionEngine()
    tools = ["nmap", "nuclei", "httpx"]
    # Empty tech → general tools stay
    filtered = engine.filter_irrelevant_tools(tools, {})
    assert "nmap" in filtered
    assert "nuclei" in filtered


def test_filter_irrelevant_tools_empty_list():
    engine = DecisionEngine()
    filtered = engine.filter_irrelevant_tools([], {"cms": ["wordpress"]})
    assert filtered == []


# ── should_transition (rule-based) ───────────────────────

def _make_mock_state(stage, findings=None, subdomains=None, endpoints=None):
    """Minimal mock state for transition decisions."""

    class MockState:
        current_stage = stage
        scan_profile = "balanced"

        def __init__(self):
            self.findings = findings or []
            self.subdomains = subdomains or []
            self.endpoints = endpoints or []
            self.metadata = {}
            self.technologies = {}
            self.live_hosts = []
            self.error_count = 0

    return MockState()


def test_should_transition_recon_to_active():
    engine = DecisionEngine()
    state = _make_mock_state(WorkflowStage.PASSIVE_RECON, subdomains=["a.com", "b.com"])
    result = asyncio.run(engine.should_transition(
        WorkflowStage.PASSIVE_RECON, state
    ))
    assert isinstance(result, StageTransitionResult)
    assert result.should_proceed is True


def test_should_transition_returns_result():
    engine = DecisionEngine()
    state = _make_mock_state(WorkflowStage.ENUMERATION)
    result = asyncio.run(engine.should_transition(
        WorkflowStage.ENUMERATION, state
    ))
    assert isinstance(result, StageTransitionResult)


# ── should_abort ─────────────────────────────────────────

def test_should_abort_normal_state():
    engine = DecisionEngine()
    state = _make_mock_state(WorkflowStage.ACTIVE_RECON)
    should, reason = asyncio.run(engine.should_abort(state))
    assert isinstance(should, bool)
    assert isinstance(reason, str)


# ── _TECH_TOOL_MAP / _TECH_ONLY_TOOLS ───────────────────

def test_tech_tool_map_populated():
    assert isinstance(DecisionEngine._TECH_TOOL_MAP, dict)
    assert len(DecisionEngine._TECH_TOOL_MAP) >= 50


def test_tech_only_tools_populated():
    assert isinstance(DecisionEngine._TECH_ONLY_TOOLS, dict)
    assert len(DecisionEngine._TECH_ONLY_TOOLS) >= 10
    # Wpscan should require wordpress
    if "wpscan" in DecisionEngine._TECH_ONLY_TOOLS:
        assert "wordpress" in DecisionEngine._TECH_ONLY_TOOLS["wpscan"]
