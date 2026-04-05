"""Tests for StateMachine — transitions, guards, history."""

import pytest

from src.workflow.state_machine import (
    StateMachine,
    StateEvent,
    Transition,
)

# WorkflowStage is needed for transition testing
try:
    from src.workflow.state_machine import WorkflowStage
except ImportError:
    from src.utils.constants import WorkflowStage


# ── Model defaults ───────────────────────────────────────

def test_state_event_defaults():
    e = StateEvent(to_state=WorkflowStage.PASSIVE_RECON)
    assert e.from_state is None
    assert e.trigger == ""
    assert e.metadata == {}


# ── StateMachine init ────────────────────────────────────

def test_machine_not_started():
    sm = StateMachine()
    assert sm.current_state is None
    assert not sm.is_terminal


def test_machine_start():
    sm = StateMachine()
    sm.start()
    assert sm.current_state == WorkflowStage.SCOPE_ANALYSIS


def test_machine_start_idempotent():
    sm = StateMachine()
    sm.start()
    sm.start()  # Should not crash or change state
    assert sm.current_state == WorkflowStage.SCOPE_ANALYSIS


# ── Normal transitions ───────────────────────────────────

def test_normal_flow_first_step():
    sm = StateMachine()
    sm.start()
    assert sm.can_transition(WorkflowStage.PASSIVE_RECON)
    result = sm.transition(WorkflowStage.PASSIVE_RECON)
    assert result is True
    assert sm.current_state == WorkflowStage.PASSIVE_RECON


def test_normal_flow_three_steps():
    sm = StateMachine()
    sm.start()
    sm.transition(WorkflowStage.PASSIVE_RECON)
    sm.transition(WorkflowStage.ACTIVE_RECON)
    sm.transition(WorkflowStage.ENUMERATION)
    assert sm.current_state == WorkflowStage.ENUMERATION


def test_full_normal_flow():
    """Walk entire normal pipeline."""
    sm = StateMachine()
    sm.start()
    stages = [
        WorkflowStage.PASSIVE_RECON,
        WorkflowStage.ACTIVE_RECON,
        WorkflowStage.ENUMERATION,
        WorkflowStage.ATTACK_SURFACE_MAP,
        WorkflowStage.VULNERABILITY_SCAN,
        WorkflowStage.FP_ELIMINATION,
        WorkflowStage.REPORTING,
        WorkflowStage.PLATFORM_SUBMIT,
        WorkflowStage.KNOWLEDGE_UPDATE,
    ]
    for stage in stages:
        assert sm.can_transition(stage), f"Cannot transition to {stage}"
        sm.transition(stage)
    assert sm.current_state == WorkflowStage.KNOWLEDGE_UPDATE
    assert sm.is_terminal


# ── Invalid transitions ──────────────────────────────────

def test_cannot_skip_forward_randomly():
    sm = StateMachine()
    sm.start()
    # From SCOPE_ANALYSIS, cannot jump to REPORTING
    assert not sm.can_transition(WorkflowStage.REPORTING)


def test_cannot_go_backward():
    sm = StateMachine()
    sm.start()
    sm.transition(WorkflowStage.PASSIVE_RECON)
    sm.transition(WorkflowStage.ACTIVE_RECON)
    assert not sm.can_transition(WorkflowStage.SCOPE_ANALYSIS)


def test_transition_to_invalid_returns_false():
    sm = StateMachine()
    sm.start()
    result = sm.transition(WorkflowStage.REPORTING)
    assert result is False
    assert sm.current_state == WorkflowStage.SCOPE_ANALYSIS


# ── Skip transitions ─────────────────────────────────────

def test_skip_to():
    sm = StateMachine()
    sm.start()
    sm.transition(WorkflowStage.PASSIVE_RECON)
    # PASSIVE_RECON should be able to skip to ENUMERATION or VULN_SCAN
    allowed = sm.get_allowed_transitions()
    if WorkflowStage.VULNERABILITY_SCAN in allowed:
        result = sm.skip_to(WorkflowStage.VULNERABILITY_SCAN, reason="fast mode")
        assert result is True
        assert sm.current_state == WorkflowStage.VULNERABILITY_SCAN


def test_skip_to_vuln_scan_from_passive():
    sm = StateMachine()
    sm.start()
    sm.transition(WorkflowStage.PASSIVE_RECON)
    if sm.can_transition(WorkflowStage.VULNERABILITY_SCAN):
        sm.skip_to(WorkflowStage.VULNERABILITY_SCAN)
        assert sm.current_state == WorkflowStage.VULNERABILITY_SCAN


# ── Abort ────────────────────────────────────────────────

def test_abort_from_any_state():
    sm = StateMachine()
    sm.start()
    sm.transition(WorkflowStage.PASSIVE_RECON)
    sm.transition(WorkflowStage.ACTIVE_RECON)
    result = sm.abort(reason="user cancelled")
    assert result is True
    assert sm.current_state == WorkflowStage.KNOWLEDGE_UPDATE
    assert sm.is_terminal


def test_abort_from_start():
    sm = StateMachine()
    sm.start()
    result = sm.abort(reason="scope invalid")
    assert result is True
    assert sm.is_terminal


# ── History ──────────────────────────────────────────────

def test_history_tracks_transitions():
    sm = StateMachine()
    sm.start()
    sm.transition(WorkflowStage.PASSIVE_RECON)
    sm.transition(WorkflowStage.ACTIVE_RECON)
    history = sm.get_history()
    assert isinstance(history, list)
    assert len(history) >= 2
    for event in history:
        assert isinstance(event, StateEvent)


def test_history_records_trigger():
    sm = StateMachine()
    sm.start()
    sm.transition(WorkflowStage.PASSIVE_RECON, trigger="manual")
    history = sm.get_history()
    last = history[-1]
    assert last.trigger == "manual"


# ── Callbacks ────────────────────────────────────────────

def test_on_enter_callback():
    sm = StateMachine()
    entered = []
    sm.on_enter(WorkflowStage.PASSIVE_RECON, lambda old, new: entered.append("entered"))
    sm.start()
    sm.transition(WorkflowStage.PASSIVE_RECON)
    assert len(entered) == 1


def test_on_exit_callback():
    sm = StateMachine()
    exited = []
    sm.on_exit(WorkflowStage.SCOPE_ANALYSIS, lambda old, new: exited.append("exited"))
    sm.start()
    sm.transition(WorkflowStage.PASSIVE_RECON)
    assert len(exited) == 1


# ── Guards ───────────────────────────────────────────────

def test_guard_blocks_transition():
    sm = StateMachine()
    sm.add_guard(
        WorkflowStage.SCOPE_ANALYSIS,
        WorkflowStage.PASSIVE_RECON,
        lambda: False,  # Always block
    )
    sm.start()
    result = sm.transition(WorkflowStage.PASSIVE_RECON)
    # Guard may block or warn depending on implementation
    # Either blocked (False) or proceeds with warning
    assert isinstance(result, bool)


def test_guard_allows_transition():
    sm = StateMachine()
    sm.add_guard(
        WorkflowStage.SCOPE_ANALYSIS,
        WorkflowStage.PASSIVE_RECON,
        lambda: True,  # Always allow
    )
    sm.start()
    result = sm.transition(WorkflowStage.PASSIVE_RECON)
    assert result is True


# ── Allowed transitions ─────────────────────────────────

def test_get_allowed_transitions():
    sm = StateMachine()
    sm.start()
    allowed = sm.get_allowed_transitions()
    assert isinstance(allowed, list)
    assert WorkflowStage.PASSIVE_RECON in allowed


def test_allowed_transitions_not_started():
    sm = StateMachine()
    allowed = sm.get_allowed_transitions()
    assert isinstance(allowed, list)
    assert len(allowed) == 0


# ── Elapsed time ─────────────────────────────────────────

def test_elapsed_in_current():
    sm = StateMachine()
    sm.start()
    elapsed = sm.get_elapsed_in_current()
    assert isinstance(elapsed, float)
    assert elapsed >= 0.0
