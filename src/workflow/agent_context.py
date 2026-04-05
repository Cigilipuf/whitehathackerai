"""
WhiteHatHacker AI — Agent Context

Per-iteration context snapshot for the agentic loop.

``AgentContext`` is the single object that contains everything the
brain needs to make a decision: the current working memory, the
available tool units, elapsed time, stage state, and iteration
counters.  Prompt builders (Phase 1.4) consume this to render a
compact brain-ready prompt string.

Usage in the ReAct loop::

    ctx = AgentContext.build(
        working_memory=wm,
        unit_registry=registry,
        current_stage=stage,
        iteration=i,
        profile=ScanProfile.BALANCED,
    )
    prompt = build_agent_think_prompt(ctx)
    decision = await brain.call(prompt)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from src.brain.memory.working_memory import WorkingMemory
from src.utils.constants import ScanProfile, WorkflowStage


# ──────────────────────────────────────────────────────────────
# Agent Action Definitions
# ──────────────────────────────────────────────────────────────

class AgentAction(StrEnum):
    """Actions the agent can request in a THINK step."""

    EXECUTE_UNIT = "execute_unit"
    EXECUTE_PARALLEL = "execute_parallel"
    GO_BACK_STAGE = "go_back_stage"
    SKIP_TO_STAGE = "skip_to_stage"
    DEEP_DIVE = "deep_dive"
    CHAIN_ATTACK = "chain_attack"
    CHANGE_STRATEGY = "change_strategy"
    ADD_HYPOTHESIS = "add_hypothesis"
    RETRY_WITH_AUTH = "retry_with_auth"
    REQUEST_OOB = "request_oob"
    PAUSE = "pause"
    COMPLETE = "complete"


# ──────────────────────────────────────────────────────────────
# Agent Decision (brain output parsed into this)
# ──────────────────────────────────────────────────────────────

class AgentDecision(BaseModel):
    """Structured output expected from the brain's THINK step."""

    action: AgentAction
    unit_id: str | None = None             # for EXECUTE_UNIT
    unit_ids: list[str] = Field(default_factory=list)  # for EXECUTE_PARALLEL
    target_stage: str | None = None        # for GO_BACK_STAGE / SKIP_TO_STAGE
    reason: str = ""
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    strategy: str | None = None            # for CHANGE_STRATEGY
    deep_dive_target: str | None = None    # URL/endpoint for DEEP_DIVE
    deep_dive_tool: str | None = None      # specific tool for deep dive
    chain_findings: list[str] = Field(default_factory=list)  # finding IDs for CHAIN_ATTACK
    confidence: float = 0.5                # how confident the brain is in this decision


class EvaluationResult(BaseModel):
    """Structured output expected from the brain's EVALUATE step."""

    analysis: str = ""
    new_hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    confirmed_hypotheses: list[str] = Field(default_factory=list)   # h_ids
    refuted_hypotheses: list[str] = Field(default_factory=list)     # h_ids
    confidence_adjustments: dict[str, float] = Field(default_factory=dict)
    chain_opportunities: list[dict[str, Any]] = Field(default_factory=list)
    recommended_next: str = ""             # hint for THINK step
    stage_complete: bool = False           # agent believes current stage is done
    new_targets: list[str] = Field(default_factory=list)  # newly discovered urls/endpoints


# ──────────────────────────────────────────────────────────────
# Profile-based limits
# ──────────────────────────────────────────────────────────────

_PROFILE_MAX_ITERATIONS: dict[str, int] = {
    ScanProfile.STEALTH: 50,
    ScanProfile.BALANCED: 80,
    ScanProfile.AGGRESSIVE: 120,
    ScanProfile.CUSTOM: 80,
}

_PROFILE_TIME_BUDGET: dict[str, float] = {
    ScanProfile.STEALTH: 10800.0,   # 3 hours
    ScanProfile.BALANCED: 7200.0,   # 2 hours
    ScanProfile.AGGRESSIVE: 5400.0, # 1.5 hours
    ScanProfile.CUSTOM: 7200.0,
}


# ──────────────────────────────────────────────────────────────
# Agent Context
# ──────────────────────────────────────────────────────────────

class UnitDescriptor(BaseModel):
    """Lightweight description of a ToolUnit for the brain prompt."""

    unit_id: str
    stage: str
    category: str
    tools: list[str] = Field(default_factory=list)
    estimated_duration: int = 0


class AgentContext(BaseModel):
    """
    Per-iteration context snapshot for the agent loop.

    Assembled by the AgentOrchestrator before each brain call.
    Consumed by prompt builders to render compact brain context.
    """

    model_config = {"arbitrary_types_allowed": True}

    # Iteration tracking
    iteration: int = 0
    max_iterations: int = 80

    # Memory
    working_memory: WorkingMemory

    # Unit state — use descriptors for serialization friendliness
    available_units: list[UnitDescriptor] = Field(default_factory=list)
    completed_units: list[str] = Field(default_factory=list)
    skipped_units: list[str] = Field(default_factory=list)

    # Stage state
    current_stage: str = WorkflowStage.SCOPE_ANALYSIS
    stage_history: list[str] = Field(default_factory=list)
    backward_transitions: dict[str, int] = Field(default_factory=dict)

    # Current iteration data
    findings_this_iteration: list[dict[str, Any]] = Field(default_factory=list)

    # Profile
    profile: str = ScanProfile.BALANCED

    # Scan metadata
    target: str = ""
    mode: str = "autonomous"
    brain_available: bool = True

    @classmethod
    def build(
        cls,
        working_memory: WorkingMemory,
        current_stage: str,
        iteration: int,
        profile: str = ScanProfile.BALANCED,
        target: str = "",
        mode: str = "autonomous",
        available_unit_descs: list[UnitDescriptor] | None = None,
        completed_units: list[str] | None = None,
        skipped_units: list[str] | None = None,
        stage_history: list[str] | None = None,
        backward_transitions: dict[str, int] | None = None,
        brain_available: bool = True,
    ) -> AgentContext:
        """Construct an AgentContext with profile-based limits."""
        max_iter = _PROFILE_MAX_ITERATIONS.get(profile, 80)
        return cls(
            iteration=iteration,
            max_iterations=max_iter,
            working_memory=working_memory,
            available_units=available_unit_descs or [],
            completed_units=completed_units or [],
            skipped_units=skipped_units or [],
            current_stage=current_stage,
            stage_history=stage_history or [],
            backward_transitions=backward_transitions or {},
            profile=profile,
            target=target,
            mode=mode,
            brain_available=brain_available,
        )

    # ── Derived properties ────────────────────────────────────

    @property
    def time_elapsed(self) -> float:
        return self.working_memory.time_budget.elapsed

    @property
    def time_remaining(self) -> float:
        return self.working_memory.time_budget.remaining

    @property
    def time_fraction_used(self) -> float:
        return self.working_memory.time_budget.fraction_used

    @property
    def iteration_fraction_used(self) -> float:
        if self.max_iterations <= 0:
            return 1.0
        return min(1.0, self.iteration / self.max_iterations)

    @property
    def is_over_budget(self) -> bool:
        return (
            self.working_memory.time_budget.is_expired
            or self.iteration >= self.max_iterations
        )

    @property
    def total_backward_count(self) -> int:
        return sum(self.backward_transitions.values())

    @property
    def remaining_unit_count(self) -> int:
        return len(self.available_units)

    # ── Prompt helpers ────────────────────────────────────────

    def available_actions_for_prompt(self) -> str:
        """List of allowed actions given current state."""
        actions: list[str] = [
            AgentAction.EXECUTE_UNIT,
            AgentAction.EXECUTE_PARALLEL,
            AgentAction.DEEP_DIVE,
            AgentAction.ADD_HYPOTHESIS,
            AgentAction.COMPLETE,
        ]
        # Backward only if at least one stage hasn't hit per-stage limit (2)
        if any(v < 2 for v in self.backward_transitions.values()) or len(self.backward_transitions) == 0:
            actions.append(AgentAction.GO_BACK_STAGE)
        # Forward skip always possible
        actions.append(AgentAction.SKIP_TO_STAGE)
        actions.append(AgentAction.CHANGE_STRATEGY)
        if self.working_memory.findings_summary.total > 1:
            actions.append(AgentAction.CHAIN_ATTACK)
        if self.mode == "semi_autonomous":
            actions.append(AgentAction.PAUSE)
        actions.append(AgentAction.REQUEST_OOB)
        actions.append(AgentAction.RETRY_WITH_AUTH)
        return ", ".join(actions)

    def units_for_prompt(self, max_units: int = 15) -> str:
        """Compact list of available units for the brain prompt."""
        if not self.available_units:
            return "No available units."
        lines: list[str] = []
        for u in self.available_units[:max_units]:
            tools_str = ", ".join(u.tools[:4])
            lines.append(f"  - {u.unit_id} [{u.stage}] tools={tools_str} ~{u.estimated_duration}s")
        if len(self.available_units) > max_units:
            lines.append(f"  ... (+{len(self.available_units) - max_units} more)")
        return "\n".join(lines)

    def completed_for_prompt(self) -> str:
        """Compact list of completed units."""
        if not self.completed_units:
            return "None yet."
        return ", ".join(self.completed_units[-20:])

    def progress_summary(self) -> str:
        """One-line progress summary."""
        return (
            f"Iteration {self.iteration}/{self.max_iterations} | "
            f"Stage: {self.current_stage} | "
            f"Units: {len(self.completed_units)} done, {len(self.available_units)} avail | "
            f"Findings: {self.working_memory.findings_summary.total} | "
            f"Time: {self.time_elapsed:.0f}s/{self.working_memory.time_budget.total_seconds:.0f}s"
        )


# ──────────────────────────────────────────────────────────────
# Utility: Get time budget for a given profile
# ──────────────────────────────────────────────────────────────

def get_profile_time_budget(profile: str) -> float:
    return _PROFILE_TIME_BUDGET.get(profile, 7200.0)


def get_profile_max_iterations(profile: str) -> int:
    return _PROFILE_MAX_ITERATIONS.get(profile, 80)


__all__ = [
    "AgentAction",
    "AgentContext",
    "AgentDecision",
    "EvaluationResult",
    "UnitDescriptor",
    "get_profile_time_budget",
    "get_profile_max_iterations",
]
