"""
WhiteHatHacker AI — Agentic Orchestrator

ReAct-style agent loop that replaces the fixed 10-stage pipeline with a
brain-driven decision loop:

    OBSERVE → THINK → ACT → EVALUATE → DECIDE → (loop)

The brain (BaronLLM v2) decides *every* action: which tool to run, when
to go back to a previous stage, when to deep-dive, and when to stop.
Safety rails ensure scope compliance, budget limits, and backward caps.

Usage::

    orch = AgentOrchestrator(
        brain_engine=brain,
        intelligence_engine=intel,
        tool_executor=executor,
        ...
    )
    state = await orch.run(target="example.com", scope=scope_cfg)
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from loguru import logger

from src.brain.memory.working_memory import (
    FindingsSummary,
    TargetProfile,
    TimeBudget,
    WorkingMemory,
)
from src.brain.prompts.agent_prompts import (
    AGENT_CHAIN_SYSTEM,
    AGENT_EVALUATE_SYSTEM,
    AGENT_THINK_SYSTEM,
    build_agent_evaluate_prompt,
    build_agent_think_prompt,
    build_chain_attack_prompt,
)
from src.utils.constants import (
    BrainType,
    OperationMode,
    RiskLevel,
    ScanProfile,
    WorkflowStage,
)
from src.utils.json_utils import extract_json
from src.workflow.agent_context import (
    AgentAction,
    AgentContext,
    AgentDecision,
    EvaluationResult,
    UnitDescriptor,
    get_profile_max_iterations,
    get_profile_time_budget,
)
from src.workflow.tool_unit import ToolUnit, ToolUnitRegistry, ToolUnitResult

if TYPE_CHECKING:
    from src.brain.engine import BrainEngine
    from src.brain.intelligence import IntelligenceEngine
    from src.brain.reasoning.self_reflection import SelfReflectionEngine
    from src.fp_engine.fp_detector import FPDetector
    from src.tools.executor import ToolExecutor
    from src.workflow.adaptive_strategy import AdaptiveStrategyEngine
    from src.workflow.decision_engine import DecisionEngine
    from src.workflow.orchestrator import WorkflowState
    from src.workflow.session_manager import SessionManager


# ──────────────────────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────────────────────

class BrainRequiredError(RuntimeError):
    """Raised when the brain is unreachable and scanning cannot proceed."""


# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────

_STALL_THRESHOLD = 3          # consecutive no-progress iterations before warning
_REFLECTION_EVERY = 5         # mid-scan self-reflection interval
_CHECKPOINT_EVERY = 1         # checkpoint after every iteration
_MAX_PARALLEL_UNITS = 4       # max units in a single execute_parallel
_EVALUATE_SKIP_DURATION = 10  # skip brain evaluate if result took < this many seconds + 0 findings


# ──────────────────────────────────────────────────────────────
# Agent Orchestrator
# ──────────────────────────────────────────────────────────────

class AgentOrchestrator:
    """
    Brain-driven agentic orchestrator.

    Instead of walking through a fixed pipeline, the orchestrator asks
    the brain at every iteration what to do next.  Safety rails (scope,
    budgets, backward limits) ensure that the brain's decisions stay
    within acceptable bounds.
    """

    def __init__(
        self,
        brain_engine: BrainEngine,
        intelligence_engine: IntelligenceEngine,
        tool_executor: ToolExecutor,
        fp_detector: FPDetector,
        adaptive_strategy: AdaptiveStrategyEngine,
        self_reflection: SelfReflectionEngine,
        decision_engine: DecisionEngine,
        session_manager: SessionManager | None,
        working_memory: WorkingMemory,
        tool_unit_registry: ToolUnitRegistry,
        mode: OperationMode = OperationMode.AUTONOMOUS,
        profile: ScanProfile = ScanProfile.BALANCED,
        human_callback: Any = None,
        max_iterations_override: int | None = None,
        time_budget_seconds_override: int | None = None,
    ) -> None:
        # Core engines
        self.brain = brain_engine
        self.intel = intelligence_engine
        self.executor = tool_executor
        self.fp_detector = fp_detector
        self.adaptive = adaptive_strategy
        self.reflection = self_reflection
        self.decision_engine = decision_engine
        self.session_manager = session_manager
        self.human_callback = human_callback

        # Agent-specific
        self.memory = working_memory
        self.registry = tool_unit_registry
        self.mode = mode
        self.profile = profile

        # CLI overrides (None → use profile defaults)
        self._max_iterations_override = max_iterations_override
        self._time_budget_seconds_override = time_budget_seconds_override

        # Runtime tracking
        self._completed_units: set[str] = set()
        self._skipped_units: set[str] = set()
        self._backward_transitions: dict[str, int] = {}
        self._stage_history: list[str] = []
        self._stall_counter: int = 0
        self._brain_call_count: int = 0

    # ══════════════════════════════════════════════════════════
    #  PUBLIC: run the agent loop
    # ══════════════════════════════════════════════════════════

    async def run(
        self,
        state: WorkflowState,
        *,
        extra_metadata: dict[str, Any] | None = None,
    ) -> WorkflowState:
        """
        Execute the full agentic scan.

        Parameters
        ----------
        state : WorkflowState
            Pre-built workflow state (target, scope, auth etc. already set).
        extra_metadata : dict, optional
            Additional metadata to inject into state.

        Returns
        -------
        WorkflowState with verified_findings, reports_generated, etc.
        """
        if extra_metadata:
            state.metadata.update(extra_metadata)

        # ── 0. Brain readiness check (mandatory) ─────────────
        ready = await self.brain.verify_brain_ready()
        if not ready.get("ready", False):
            raise BrainRequiredError(
                "Brain unavailable — WhiteHatHacker AI requires an active "
                "brain connection. Check SSH tunnel and LM Studio.\n"
                f"Details: {ready}"
            )
        logger.info("Brain ready — starting agentic scan")

        # ── 1. Initialise time budget + memory ───────────────
        state.start_time = time.time()
        budget_seconds = self._time_budget_seconds_override or get_profile_time_budget(self.profile)
        max_iter = self._max_iterations_override or get_profile_max_iterations(self.profile)

        self.memory.time_budget = TimeBudget(
            total_seconds=budget_seconds,
            start_time=state.start_time,
        )
        self.memory.target_profile = self._build_target_profile(state)

        current_stage = WorkflowStage.SCOPE_ANALYSIS
        self._stage_history.append(current_stage.value)

        # ── 2. Scope analysis (always first, one-shot) ───────
        await self._run_scope_analysis(state)
        current_stage = WorkflowStage.PASSIVE_RECON
        self._stage_history.append(current_stage.value)

        # ── 3. Agent loop ────────────────────────────────────
        for iteration in range(1, max_iter + 1):
            # Build context snapshot for this iteration
            ctx = self._build_context(state, current_stage, iteration, max_iter)

            # Budget guards
            if self._should_terminate(ctx, state):
                logger.info(
                    f"Termination condition met at iteration {iteration}"
                )
                break

            # Brain down mid-scan?
            if not self.intel.is_available:
                logger.critical("Brain down during scan — aborting agent loop")
                break

            # ── THINK ────────────────────────────────────────
            decision = await self._agent_think(ctx)

            # Validate
            if not self._validate_decision(decision, ctx, state):
                logger.warning(
                    f"Invalid decision: {decision.action}/{decision.unit_id} — "
                    f"falling back"
                )
                decision = self._safe_fallback_decision(ctx, state)

            logger.info(
                f"[iter {iteration}] action={decision.action} "
                f"unit={decision.unit_id or '-'} "
                f"stage={current_stage.value} "
                f"reason={decision.reason[:80]}"
            )

            # ── ACT ──────────────────────────────────────────
            result: ToolUnitResult | None = None

            match decision.action:
                case AgentAction.EXECUTE_UNIT:
                    result = await self._execute_unit(
                        decision.unit_id, state, ctx
                    )

                case AgentAction.EXECUTE_PARALLEL:
                    result = await self._execute_parallel(
                        decision.unit_ids, state, ctx
                    )

                case AgentAction.GO_BACK_STAGE:
                    current_stage = self._go_back_stage(
                        decision.target_stage, state, ctx
                    )
                    continue  # no evaluate needed for nav

                case AgentAction.SKIP_TO_STAGE:
                    current_stage = self._skip_to_stage(
                        decision.target_stage, state, ctx
                    )
                    continue

                case AgentAction.DEEP_DIVE:
                    result = await self._deep_dive(decision, state, ctx)

                case AgentAction.CHAIN_ATTACK:
                    result = await self._chain_attack(decision, state, ctx)

                case AgentAction.CHANGE_STRATEGY:
                    self._change_strategy(decision, state, ctx)
                    continue

                case AgentAction.ADD_HYPOTHESIS:
                    self._add_hypotheses_from_decision(decision)
                    continue

                case AgentAction.COMPLETE:
                    logger.info(
                        f"Brain requested COMPLETE at iteration {iteration}: "
                        f"{decision.reason}"
                    )
                    break

                case AgentAction.RETRY_WITH_AUTH:
                    if state.auth_headers:
                        unit_id = decision.unit_id
                        if not unit_id and self.memory.iteration_history:
                            unit_id = self.memory.iteration_history[-1].unit_id
                        if unit_id:
                            logger.info(
                                f"Retrying unit '{unit_id}' with auth headers"
                            )
                            state.metadata["agentic_retry_with_auth"] = True
                            result = await self._execute_unit(
                                unit_id, state, ctx
                            )
                        else:
                            logger.warning(
                                "RETRY_WITH_AUTH: no unit to retry"
                            )
                            continue
                    else:
                        logger.warning(
                            "RETRY_WITH_AUTH requested but no "
                            "auth_headers available in state"
                        )
                        continue

                case AgentAction.REQUEST_OOB:
                    logger.info(
                        f"OOB callback requested: {decision.reason}"
                    )
                    state.metadata["agentic_request_oob_check"] = True
                    continue

                case AgentAction.PAUSE:
                    if self.human_callback:
                        await self.human_callback(
                            "Brain requests human review", state
                        )
                    continue

                case _:
                    logger.warning(f"Unknown action: {decision.action}")
                    continue

            # ── EVALUATE ─────────────────────────────────────
            if result is not None:
                evaluation = await self._agent_evaluate(result, ctx)

                # Apply observations + findings
                self._apply_result(result, state, ctx)
                self._apply_evaluation(evaluation, ctx)

                # Adaptive strategy signals
                self._feed_signals(result, state)

                # Stall detection
                if result.finding_count == 0 and not result.context_updates:
                    self._stall_counter += 1
                else:
                    self._stall_counter = 0

            # ── REFLECT (periodic) ───────────────────────────
            if iteration % _REFLECTION_EVERY == 0:
                await self._mid_scan_reflection(ctx, state)

            # ── CHECKPOINT ───────────────────────────────────
            if iteration % _CHECKPOINT_EVERY == 0:
                await self._checkpoint(state)

        # ── 4. Post-loop: FP elimination ─────────────────────
        logger.info("Agent loop finished — running FP elimination")
        await self._run_fp_elimination(state)

        # ── 5. Reporting ─────────────────────────────────────
        logger.info("Running reporting")
        await self._run_reporting(state)

        # ── 6. Knowledge update ──────────────────────────────
        await self._run_knowledge_update(state)

        state.end_time = time.time()
        logger.info(
            f"Agentic scan complete: {len(state.verified_findings)} verified "
            f"findings in {state.elapsed_time:.0f}s, "
            f"{len(self._completed_units)} units run"
        )
        return state

    # ══════════════════════════════════════════════════════════
    #  THINK — ask the brain what to do next
    # ══════════════════════════════════════════════════════════

    async def _agent_think(self, ctx: AgentContext) -> AgentDecision:
        """Call brain to decide the next action."""
        prompt = build_agent_think_prompt(ctx)
        self._brain_call_count += 1

        raw = await self.intel._brain_call_json(
            prompt=prompt,
            system_prompt=AGENT_THINK_SYSTEM,
            brain=BrainType.SECONDARY,  # fast decision
            timeout=120.0,
            task_type="agent_decide",
        )

        if not raw or not isinstance(raw, dict):
            logger.warning("Brain returned empty/invalid THINK response — fallback")
            return self._safe_fallback_decision(ctx, None)

        try:
            return AgentDecision(
                action=AgentAction(raw.get("action", "complete")),
                unit_id=raw.get("unit_id"),
                unit_ids=raw.get("unit_ids", []),
                target_stage=raw.get("target_stage"),
                reason=raw.get("reason", ""),
                hypotheses=raw.get("hypotheses", []),
                strategy=raw.get("strategy"),
                deep_dive_target=raw.get("deep_dive_target"),
                deep_dive_tool=raw.get("deep_dive_tool"),
                chain_findings=raw.get("chain_findings", []),
                confidence=float(raw.get("confidence", 0.5)),
            )
        except (ValueError, KeyError) as exc:
            logger.warning(f"Failed to parse brain decision: {exc}")
            return self._safe_fallback_decision(ctx, None)

    # ══════════════════════════════════════════════════════════
    #  EVALUATE — analyse tool result
    # ══════════════════════════════════════════════════════════

    async def _agent_evaluate(
        self, result: ToolUnitResult, ctx: AgentContext
    ) -> EvaluationResult:
        """Ask brain to analyse a tool result (skip for trivial results)."""
        # Optimisation: skip brain call for short, finding-less results
        if (
            not result.has_findings
            and result.duration < _EVALUATE_SKIP_DURATION
            and not result.errors
        ):
            return EvaluationResult(
                analysis=f"{result.unit_id}: quick run, no findings",
            )

        prompt = build_agent_evaluate_prompt(result, ctx)
        self._brain_call_count += 1

        raw = await self.intel._brain_call_json(
            prompt=prompt,
            system_prompt=AGENT_EVALUATE_SYSTEM,
            brain=BrainType.PRIMARY,  # deep analysis for evaluation
            timeout=180.0,
            task_type="agent_evaluate",
        )

        if not raw or not isinstance(raw, dict):
            return EvaluationResult(
                analysis=f"{result.unit_id}: brain evaluate unavailable",
            )

        try:
            return EvaluationResult(
                analysis=raw.get("analysis", ""),
                new_hypotheses=raw.get("new_hypotheses", []),
                confirmed_hypotheses=raw.get("confirmed_hypotheses", []),
                refuted_hypotheses=raw.get("refuted_hypotheses", []),
                confidence_adjustments=raw.get("confidence_adjustments", {}),
                chain_opportunities=raw.get("chain_opportunities", []),
                recommended_next=raw.get("recommended_next", ""),
                stage_complete=raw.get("stage_complete", False),
                new_targets=raw.get("new_targets", []),
            )
        except (ValueError, KeyError) as exc:
            logger.warning(f"Failed to parse evaluation: {exc}")
            return EvaluationResult(analysis=f"parse error: {exc}")

    # ══════════════════════════════════════════════════════════
    #  ACT — execute a single tool unit
    # ══════════════════════════════════════════════════════════

    async def _execute_unit(
        self, unit_id: str, state: WorkflowState, ctx: AgentContext
    ) -> ToolUnitResult:
        """Execute a single ToolUnit by ID."""
        unit = self.registry.get(unit_id)
        if unit is None:
            return ToolUnitResult(
                unit_id=unit_id,
                success=False,
                errors=[f"Unknown unit: {unit_id}"],
                observations=f"Unit '{unit_id}' not found in registry",
            )

        timeout = unit.effective_timeout(self.profile)
        try:
            result = await asyncio.wait_for(
                unit.execute(state, ctx),
                timeout=timeout + 30,  # grace
            )
        except asyncio.TimeoutError:
            result = ToolUnitResult(
                unit_id=unit_id,
                success=False,
                errors=[f"Timeout after {timeout:.0f}s"],
                observations=f"{unit_id}: timed out after {timeout:.0f}s",
            )
        except Exception as exc:
            logger.warning(f"Unit {unit_id} raised: {exc}")
            result = ToolUnitResult(
                unit_id=unit_id,
                success=False,
                errors=[str(exc)],
                observations=f"{unit_id}: error — {exc}",
            )

        self._completed_units.add(unit_id)
        state.tools_run.extend(result.tools_run)

        if self.reflection:
            self.reflection.record_tool_result(
                stage=str(state.current_stage),
                tool_name=unit_id,
                success=result.success,
                findings_count=result.finding_count,
                execution_time=result.duration,
            )

        return result

    async def _execute_parallel(
        self, unit_ids: list[str], state: WorkflowState, ctx: AgentContext
    ) -> ToolUnitResult:
        """Execute multiple ToolUnits concurrently, merge results."""
        valid_ids = [
            uid for uid in unit_ids[:_MAX_PARALLEL_UNITS]
            if self.registry.get(uid) is not None
        ]
        if not valid_ids:
            return ToolUnitResult(
                success=False,
                errors=["No valid units for parallel execution"],
                observations="execute_parallel: no valid units",
            )

        tasks = [self._execute_unit(uid, state, ctx) for uid in valid_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        merged = ToolUnitResult(
            unit_id=",".join(valid_ids),
            success=True,
        )
        for r in results:
            if isinstance(r, Exception):
                merged.errors.append(str(r))
                merged.success = False
                continue
            if isinstance(r, ToolUnitResult):
                merged.findings.extend(r.findings)
                merged.tools_run.extend(r.tools_run)
                merged.duration = max(merged.duration, r.duration)
                if r.context_updates:
                    for k, v in r.context_updates.items():
                        existing = merged.context_updates.get(k)
                        if isinstance(existing, list) and isinstance(v, list):
                            existing.extend(v)
                        elif isinstance(existing, dict) and isinstance(v, dict):
                            existing.update(v)
                        else:
                            merged.context_updates[k] = v
                if r.observations:
                    merged.observations += f"\n{r.observations}"
                if not r.success:
                    merged.success = False

        return merged

    # ══════════════════════════════════════════════════════════
    #  NAVIGATION — stage transitions
    # ══════════════════════════════════════════════════════════

    def _go_back_stage(
        self,
        target_stage: str | None,
        state: WorkflowState,
        ctx: AgentContext,
    ) -> WorkflowStage:
        """Navigate backward to a previous stage."""
        if not target_stage:
            logger.warning("go_back_stage with no target — staying put")
            return WorkflowStage(ctx.current_stage)

        bk_count = self._backward_transitions.get(target_stage, 0)
        if bk_count >= 2:
            logger.warning(
                f"Backward limit reached for {target_stage} ({bk_count}/2)"
            )
            return WorkflowStage(ctx.current_stage)

        try:
            stage_enum = WorkflowStage(target_stage)
        except ValueError:
            logger.warning(f"Invalid stage for backward: {target_stage}")
            return WorkflowStage(ctx.current_stage)

        self._backward_transitions[target_stage] = bk_count + 1
        state.current_stage = stage_enum
        self._stage_history.append(stage_enum.value)

        # Re-expose stage units (brain decides which to re-run)
        logger.info(
            f"BACKWARD → {stage_enum.value} "
            f"(count: {bk_count + 1}/2)"
        )
        return stage_enum

    def _skip_to_stage(
        self,
        target_stage: str | None,
        state: WorkflowState,
        ctx: AgentContext,
    ) -> WorkflowStage:
        """Skip forward to a later stage."""
        if not target_stage:
            logger.warning("skip_to_stage with no target — staying put")
            return WorkflowStage(ctx.current_stage)

        try:
            stage_enum = WorkflowStage(target_stage)
        except ValueError:
            logger.warning(f"Invalid stage for skip: {target_stage}")
            return WorkflowStage(ctx.current_stage)

        state.current_stage = stage_enum
        self._stage_history.append(stage_enum.value)

        logger.info(f"SKIP → {stage_enum.value}")
        return stage_enum

    # ══════════════════════════════════════════════════════════
    #  DEEP DIVE & CHAIN ATTACK
    # ══════════════════════════════════════════════════════════

    async def _deep_dive(
        self, decision: AgentDecision, state: WorkflowState, ctx: AgentContext
    ) -> ToolUnitResult:
        """Execute a focused deep-dive on a specific endpoint/parameter."""
        target_url = decision.deep_dive_target or ""
        tool_id = decision.deep_dive_tool or decision.unit_id

        logger.info(f"DEEP DIVE on {target_url} with {tool_id}")

        if tool_id and self.registry.get(tool_id):
            # Temporarily narrow scope for the unit
            orig_endpoints = state.endpoints
            if target_url:
                state.endpoints = [target_url]
            result = await self._execute_unit(tool_id, state, ctx)
            state.endpoints = orig_endpoints
            result.observations = f"[DEEP DIVE] {result.observations}"
            return result

        return ToolUnitResult(
            unit_id=f"deep_dive_{tool_id or 'unknown'}",
            success=False,
            observations=f"Deep dive failed: tool {tool_id} not found",
        )

    async def _chain_attack(
        self, decision: AgentDecision, state: WorkflowState, ctx: AgentContext
    ) -> ToolUnitResult:
        """
        Combine multiple findings into an attack chain.

        The brain identified findings that can be chained.  We ask for a
        detailed chain plan and execute the suggested follow-up unit.
        """
        chain_finding_ids = decision.chain_findings
        if not chain_finding_ids:
            return ToolUnitResult(
                success=False,
                observations="chain_attack: no finding IDs provided",
            )

        # Collect referenced findings
        relevant = [
            f for f in state.raw_findings
            if f.get("id") in chain_finding_ids
            or f.get("title") in chain_finding_ids
        ]

        if not relevant:
            return ToolUnitResult(
                success=False,
                observations="chain_attack: referenced findings not found",
            )

        # Ask brain for chain plan
        prompt = build_chain_attack_prompt(relevant, ctx)
        self._brain_call_count += 1
        raw = await self.intel._brain_call_json(
            prompt=prompt,
            system_prompt=AGENT_CHAIN_SYSTEM,
            brain=BrainType.PRIMARY,
            timeout=180.0,
            task_type="chain_attack",
        )

        chain_unit = None
        if raw and isinstance(raw, dict):
            chains = raw.get("chains", [])
            if chains and isinstance(chains[0], dict):
                next_step = chains[0].get("next_step")
                if next_step and self.registry.get(next_step):
                    chain_unit = next_step

        if chain_unit:
            result = await self._execute_unit(chain_unit, state, ctx)
            result.observations = f"[CHAIN] {result.observations}"
            return result

        return ToolUnitResult(
            observations="chain_attack: no actionable chain found",
        )

    # ══════════════════════════════════════════════════════════
    #  STRATEGY CHANGE & HYPOTHESES
    # ══════════════════════════════════════════════════════════

    def _change_strategy(
        self,
        decision: AgentDecision,
        state: WorkflowState,
        ctx: AgentContext,
    ) -> None:
        """Switch scan profile (stealth/balanced/aggressive)."""
        new_profile = decision.strategy
        if not new_profile:
            return

        try:
            profile_enum = ScanProfile(new_profile)
        except ValueError:
            logger.warning(f"Invalid strategy: {new_profile}")
            return

        self.profile = profile_enum
        if self.adaptive:
            from src.workflow.adaptive_strategy import SignalType
            self.adaptive.observe(
                signal_type=SignalType.STRATEGY_CHANGE,
                source="agent_brain",
                value=new_profile,
                details={"reason": decision.reason},
            )

        logger.info(f"Strategy changed to {new_profile}: {decision.reason}")

    def _add_hypotheses_from_decision(self, decision: AgentDecision) -> None:
        """Add brain-generated hypotheses to working memory."""
        from src.brain.memory.working_memory import Hypothesis

        for h in decision.hypotheses:
            if isinstance(h, dict) and h.get("text"):
                self.memory.add_hypothesis(Hypothesis(
                    text=h["text"],
                    source="brain_think",
                    priority=float(h.get("priority", 0.5)),
                    suggested_units=h.get("suggested_units", []),
                ))

    # ══════════════════════════════════════════════════════════
    #  DECISION VALIDATION — safety rails
    # ══════════════════════════════════════════════════════════

    def _validate_decision(
        self,
        decision: AgentDecision,
        ctx: AgentContext,
        state: WorkflowState | None,
    ) -> bool:
        """
        Validate the brain's decision against safety constraints.

        Returns True if decision is acceptable, False otherwise.
        """
        action = decision.action

        # 1. execute_unit — unit must exist and be available
        if action == AgentAction.EXECUTE_UNIT:
            unit = self.registry.get(decision.unit_id or "")
            if unit is None:
                logger.warning(f"Brain hallucinated unit: {decision.unit_id}")
                return False

        # 2. execute_parallel — all units must exist
        if action == AgentAction.EXECUTE_PARALLEL:
            for uid in decision.unit_ids:
                if self.registry.get(uid) is None:
                    logger.warning(f"Brain hallucinated parallel unit: {uid}")
                    return False
            if len(decision.unit_ids) > _MAX_PARALLEL_UNITS:
                logger.warning(
                    f"Too many parallel units: {len(decision.unit_ids)}"
                )
                return False

        # 3. go_back_stage — backward limit
        if action == AgentAction.GO_BACK_STAGE:
            ts = decision.target_stage or ""
            if self._backward_transitions.get(ts, 0) >= 2:
                logger.warning(f"Backward limit for {ts}")
                return False

        # 4. deep_dive — scope check
        if action == AgentAction.DEEP_DIVE and decision.deep_dive_target:
            try:
                from src.utils.scope_validator import ScopeValidator
                sv = ScopeValidator(state.scope_config if state else {})
                if not sv.is_in_scope(decision.deep_dive_target):
                    logger.warning(
                        f"Deep dive target out of scope: "
                        f"{decision.deep_dive_target}"
                    )
                    return False
            except Exception:
                pass  # scope validator unavailable — allow

        # 5. semi-autonomous high-risk gate
        if (
            action == AgentAction.EXECUTE_UNIT
            and self.mode == OperationMode.SEMI_AUTONOMOUS
        ):
            unit = self.registry.get(decision.unit_id or "")
            if unit and unit.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                logger.info(
                    f"High-risk unit {decision.unit_id} in semi-auto mode "
                    f"— requires approval"
                )
                # In a full implementation this would pause for human approval;
                # for now we allow it with a log.

        return True

    def _safe_fallback_decision(
        self, ctx: AgentContext, state: WorkflowState | None
    ) -> AgentDecision:
        """
        Return a safe fallback when the brain's response is unparseable
        or invalid.

        Strategy: pick the lowest-risk remaining unit, or complete if
        none remain.
        """
        remaining = self.registry.get_remaining(
            state,
            completed_ids=self._completed_units,
            skipped_ids=self._skipped_units,
        ) if state else []

        if remaining:
            # Sort by risk (ascending), then estimated_duration (descending)
            best = min(
                remaining,
                key=lambda u: (
                    {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
                        u.risk_level.value if hasattr(u.risk_level, 'value') else str(u.risk_level), 2
                    ),
                    -u.estimated_duration,
                ),
            )
            return AgentDecision(
                action=AgentAction.EXECUTE_UNIT,
                unit_id=best.unit_id,
                reason="safe_fallback: brain unavailable/invalid",
            )

        return AgentDecision(
            action=AgentAction.COMPLETE,
            reason="safe_fallback: no remaining units",
        )

    # ══════════════════════════════════════════════════════════
    #  TERMINATION CHECKS
    # ══════════════════════════════════════════════════════════

    def _should_terminate(
        self, ctx: AgentContext, state: WorkflowState
    ) -> bool:
        """Check all termination conditions."""
        # 1. Iteration limit
        if ctx.iteration >= ctx.max_iterations:
            logger.info("Iteration limit reached")
            return True

        # 2. Time budget
        if ctx.is_over_budget:
            logger.info("Time budget exhausted")
            return True

        # 3. Brain down
        if state.brain_confirmed_down and not self.intel.is_available:
            logger.info("Brain confirmed down — terminating")
            return True

        # 4. Stall detection
        if self._stall_counter >= _STALL_THRESHOLD:
            remaining = self.registry.get_remaining(
                state,
                completed_ids=self._completed_units,
                skipped_ids=self._skipped_units,
            )
            if not remaining:
                logger.info("Stall + no remaining units → terminating")
                return True
            # Reset stall counter — there are still things to try
            self._stall_counter = 0

        return False

    # ══════════════════════════════════════════════════════════
    #  RESULT APPLICATION
    # ══════════════════════════════════════════════════════════

    def _apply_result(
        self,
        result: ToolUnitResult,
        state: WorkflowState,
        ctx: AgentContext | None,
    ) -> None:
        """Apply a ToolUnitResult to workflow state and working memory."""
        # Findings
        if result.findings:
            state.raw_findings.extend(result.findings)

        # Context updates → state
        updates = result.context_updates
        if updates:
            new_subs = updates.get("new_subdomains") or updates.get("subdomains")
            if isinstance(new_subs, list):
                for s in new_subs:
                    if s not in state.subdomains:
                        state.subdomains.append(s)

            new_hosts = updates.get("new_live_hosts") or updates.get("live_hosts")
            if isinstance(new_hosts, list):
                for h in new_hosts:
                    if h not in state.live_hosts:
                        state.live_hosts.append(h)

            new_eps = updates.get("new_endpoints") or updates.get("endpoints")
            if isinstance(new_eps, list):
                for ep in new_eps:
                    if ep not in state.endpoints:
                        state.endpoints.append(ep)

            new_tech = updates.get("new_technologies") or updates.get("technologies")
            if isinstance(new_tech, (list, dict)):
                if isinstance(new_tech, list):
                    state.technologies.setdefault("detected", []).extend(new_tech)
                elif isinstance(new_tech, dict):
                    for host, techs in new_tech.items():
                        existing = state.technologies.get(host, [])
                        if isinstance(existing, list) and isinstance(techs, list):
                            existing.extend(t for t in techs if t not in existing)
                            state.technologies[host] = existing

        # Update working memory  (incremental — update_from_tool_result
        # already calls findings_summary.ingest(result.findings), so we
        # do NOT rebuild from scratch on every iteration.)
        self.memory.update_from_tool_result(
            unit_id=result.unit_id,
            observation=result.observations,
            findings=result.findings,
            duration=result.duration,
            success=result.success,
        )

        # Update target profile counts
        self.memory.target_profile.subdomain_count = len(state.subdomains)
        self.memory.target_profile.live_host_count = len(state.live_hosts)
        self.memory.target_profile.endpoint_count = len(state.endpoints)

    def _apply_evaluation(
        self, evaluation: EvaluationResult, ctx: AgentContext
    ) -> None:
        """Apply brain's evaluation results to working memory."""
        from src.brain.memory.working_memory import Hypothesis, HypothesisStatus

        # New hypotheses
        for h_dict in evaluation.new_hypotheses:
            if isinstance(h_dict, dict) and h_dict.get("text"):
                self.memory.add_hypothesis(Hypothesis(
                    text=h_dict["text"],
                    source="brain_evaluate",
                    priority=float(h_dict.get("priority", 0.5)),
                    suggested_units=h_dict.get("suggested_units", []),
                ))

        # Confirmed/refuted hypotheses
        for h_id in evaluation.confirmed_hypotheses:
            self.memory.resolve_hypothesis(h_id, HypothesisStatus.CONFIRMED)
        for h_id in evaluation.refuted_hypotheses:
            self.memory.resolve_hypothesis(h_id, HypothesisStatus.REFUTED)

        # New targets → state endpoints (done at result application stage)

    # ══════════════════════════════════════════════════════════
    #  SIGNALS & REFLECTION
    # ══════════════════════════════════════════════════════════

    def _feed_signals(
        self, result: ToolUnitResult, state: WorkflowState
    ) -> None:
        """Feed tool results into AdaptiveStrategy + SelfReflection."""
        if not self.adaptive:
            return

        try:
            from src.workflow.adaptive_strategy import SignalType

            if result.findings:
                self.adaptive.observe(
                    signal_type=SignalType.FINDING_CONFIRMED,
                    source=result.unit_id,
                    value=result.finding_count,
                    details={"severity_counts": self._severity_breakdown(result)},
                )

            if result.context_updates.get("waf_detected"):
                self.adaptive.observe(
                    signal_type=SignalType.WAF_DETECTED,
                    source=result.unit_id,
                    value=result.context_updates["waf_detected"],
                    details={},
                )
        except Exception as exc:
            logger.warning(f"Adaptive signal error: {exc}")

    async def _mid_scan_reflection(
        self, ctx: AgentContext, state: WorkflowState
    ) -> None:
        """Periodic self-reflection: critique progress and adjust."""
        if not self.reflection:
            return

        try:
            critique = await self.reflection.critique_stage(
                stage=ctx.current_stage,
            )
            if critique:
                logger.info(
                    f"Mid-scan reflection: score={getattr(critique, 'score', 'N/A')}"
                )
        except Exception as exc:
            logger.warning(f"Reflection error: {exc}")

    # ══════════════════════════════════════════════════════════
    #  CHECKPOINT & RESUME
    # ══════════════════════════════════════════════════════════

    async def _checkpoint(self, state: WorkflowState) -> None:
        """Persist current state for crash recovery."""
        if not self.session_manager:
            return

        try:
            state.metadata["agentic_progress"] = {
                "completed_units": sorted(self._completed_units),
                "skipped_units": sorted(self._skipped_units),
                "backward_transitions": self._backward_transitions,
                "stage_history": self._stage_history,
                "brain_call_count": self._brain_call_count,
                "stall_counter": self._stall_counter,
            }
            self.session_manager.checkpoint(state)
        except Exception as exc:
            logger.warning(f"Checkpoint error: {exc}")

    # ══════════════════════════════════════════════════════════
    #  FIXED PHASES (run once, outside agent loop)
    # ══════════════════════════════════════════════════════════

    async def _run_scope_analysis(self, state: WorkflowState) -> None:
        """Scope analysis — always first, one-shot."""
        logger.info("Running scope analysis")
        scope_units = self.registry.get_by_stage(WorkflowStage.SCOPE_ANALYSIS)
        for unit in scope_units:
            try:
                result = await asyncio.wait_for(
                    unit.execute(state, None),
                    timeout=120,
                )
                self._apply_result(result, state, None)
                self._completed_units.add(unit.unit_id)
            except Exception as exc:
                logger.warning(f"Scope unit {unit.unit_id} error: {exc}")

        state.current_stage = WorkflowStage.PASSIVE_RECON

    async def _run_fp_elimination(self, state: WorkflowState) -> None:
        """
        FP elimination — runs AFTER the agent loop on all raw_findings.

        Delegates to the existing FPDetector pipeline (8 layers, cross-finding
        comparison).  The agent loop does NOT do FP inline — batch is more
        accurate.
        """
        if not state.raw_findings:
            logger.info("No raw findings — skipping FP elimination")
            return

        if not self.fp_detector:
            state.verified_findings = state.raw_findings
            return

        logger.info(
            f"FP elimination on {len(state.raw_findings)} raw findings"
        )

        try:
            verified = []
            false_positives = []

            for finding in state.raw_findings:
                try:
                    fp_result = await asyncio.wait_for(
                        self.fp_detector.analyze(finding),
                        timeout=60,
                    )
                    score = getattr(fp_result, "score", 50)
                    if score >= 50:
                        finding["confidence_score"] = score
                        finding["confidence"] = score
                        verified.append(finding)
                    else:
                        false_positives.append(finding)
                except asyncio.TimeoutError:
                    # On timeout, keep the finding with reduced confidence
                    finding["confidence_score"] = 40
                    finding["confidence"] = 40
                    verified.append(finding)
                except Exception as exc:
                    logger.warning(f"FP analysis error: {exc}")
                    verified.append(finding)

            state.verified_findings = verified
            state.false_positives = false_positives

            logger.info(
                f"FP result: {len(verified)} verified, "
                f"{len(false_positives)} false positives"
            )
        except Exception as exc:
            logger.warning(f"FP elimination failed: {exc}")
            state.verified_findings = state.raw_findings

    async def _run_reporting(self, state: WorkflowState) -> None:
        """Generate reports from verified findings."""
        if not state.verified_findings:
            logger.info("No verified findings — skipping reporting")
            return

        try:
            from src.reporting.report_generator import ReportGenerator

            generator = ReportGenerator()
            report_path = generator.generate(
                findings=state.verified_findings,
                target=state.target,
                session_id=state.session_id,
                metadata=state.metadata,
            )
            if report_path:
                state.reports_generated.append(str(report_path))
                logger.info(f"Report generated: {report_path}")
        except Exception as exc:
            logger.warning(f"Reporting error: {exc}")

    async def _run_knowledge_update(self, state: WorkflowState) -> None:
        """Persist learnings from this scan."""
        try:
            from src.brain.memory.knowledge_base import KnowledgeBase

            kb = KnowledgeBase()
            kb.record_scan_learning(
                target=state.target,
                technology_stack=list(state.technologies.keys()),
                productive_tools=sorted(self._completed_units),
                verified_vuln_types=[
                    f.get("vulnerability_type", "unknown")
                    for f in state.verified_findings
                ],
                false_positive_patterns=[],
                tool_effectiveness={},
            )

            # Agent-specific learning
            state.metadata["agentic_learning"] = {
                "total_iterations": len(self._stage_history),
                "backward_transitions": self._backward_transitions,
                "brain_call_count": self._brain_call_count,
                "completed_units": len(self._completed_units),
                "skipped_units": len(self._skipped_units),
                "hypothesis_count": len(self.memory.get_active_hypotheses()),
            }

        except Exception as exc:
            logger.warning(f"Knowledge update error: {exc}")

    # ══════════════════════════════════════════════════════════
    #  HELPERS
    # ══════════════════════════════════════════════════════════

    def _build_context(
        self,
        state: WorkflowState,
        current_stage: WorkflowStage,
        iteration: int,
        max_iterations: int,
    ) -> AgentContext:
        """Build an AgentContext snapshot for the current iteration."""
        remaining = self.registry.get_remaining(
            state,
            completed_ids=self._completed_units,
            skipped_ids=self._skipped_units,
        )

        descs = [
            UnitDescriptor(
                unit_id=u.unit_id,
                stage=u.stage.value if hasattr(u.stage, "value") else str(u.stage),
                category=u.category.value if hasattr(u.category, "value") else str(u.category),
                tools=u.tools,
                estimated_duration=u.estimated_duration,
            )
            for u in remaining
        ]

        return AgentContext.build(
            working_memory=self.memory,
            current_stage=current_stage.value if hasattr(current_stage, "value") else str(current_stage),
            iteration=iteration,
            profile=self.profile.value if hasattr(self.profile, "value") else str(self.profile),
            target=state.target,
            mode=self.mode.value if hasattr(self.mode, "value") else str(self.mode),
            available_unit_descs=descs,
            completed_units=sorted(self._completed_units),
            skipped_units=sorted(self._skipped_units),
            stage_history=self._stage_history,
            backward_transitions=self._backward_transitions,
            brain_available=self.intel.is_available,
        )

    def _build_target_profile(self, state: WorkflowState) -> TargetProfile:
        """Build initial target profile from state."""
        return TargetProfile(
            domain=state.target,
            target_url=state.target,
            scope_domains=state.scope_config.get("domains", []),
            subdomain_count=len(state.subdomains),
            live_host_count=len(state.live_hosts),
            endpoint_count=len(state.endpoints),
        )

    @staticmethod
    def _severity_breakdown(result: ToolUnitResult) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in result.findings:
            sev = str(f.get("severity", "info")).lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts


__all__ = [
    "AgentOrchestrator",
    "BrainRequiredError",
]
