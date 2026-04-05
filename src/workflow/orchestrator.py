"""
WhiteHatHacker AI — Workflow Orchestrator

Ana iş akışı yöneticisi. 10 aşamalı tarama pipeline'ını orkestra eder:
1. Scope Analysis → 2. Passive Recon → 3. Active Recon → 4. Enumeration
→ 5. Attack Surface Map → 6. Vulnerability Scan → 7. FP Elimination
→ 8. Reporting → 9. Platform Submit → 10. Knowledge Update

Enhanced with cognitive modules:
- SessionManager: crash recovery, pause/resume, persistence
- ResultAggregator: cross-tool deduplication & correlation
- AdaptiveStrategyEngine: dynamic WAF/rate-limit adaptation
- ToolChainEngine: smart tool sequencing
- SelfReflectionEngine: post-stage self-critique
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any, Callable, Awaitable

from loguru import logger
from pydantic import BaseModel

from src.utils.perf_profiler import PerfProfiler
from src.utils.constants import (
    OperationMode,
    ScanProfile,
    WorkflowStage,
)
from src.workflow.state_machine import StateMachine


# ============================================================
# Veri Modelleri
# ============================================================

class StageResult(BaseModel):
    """Tek bir aşamanın sonucu."""

    stage: WorkflowStage
    success: bool = True
    duration: float = 0.0              # Saniye
    findings_count: int = 0
    data: dict[str, Any] = {}          # Aşama çıktı verileri
    errors: list[str] = []
    skipped: bool = False
    skip_reason: str = ""


class WorkflowState(BaseModel):
    """Workflow'un mevcut durumu."""

    model_config = {"arbitrary_types_allowed": True}

    session_id: str = ""
    target: str = ""
    mode: OperationMode = OperationMode.SEMI_AUTONOMOUS
    profile: ScanProfile = ScanProfile.BALANCED

    current_stage: WorkflowStage = WorkflowStage.SCOPE_ANALYSIS
    completed_stages: list[WorkflowStage] = []
    stage_results: dict[str, StageResult] = {}

    # ── Injected components (orchestrator tarafından set edilir) ──
    tool_executor: Any | None = None
    brain_engine: Any | None = None
    fp_detector: Any | None = None
    intelligence_engine: Any | None = None  # IntelligenceEngine — LLM-driven planning & analysis

    # Auth configuration — first-class access to auth state
    auth_headers: dict[str, str] = {}     # Merged auth headers for the primary session
    auth_roles: list[dict[str, Any]] = [] # [{role_name, headers}] for multi-role IDOR

    # Toplanan veriler
    subdomains: list[str] = []
    live_hosts: list[str] = []
    open_ports: dict[str, list[int]] = {}
    endpoints: list[str] = []
    technologies: dict[str, list[str]] = {}

    # Bulgular
    raw_findings: list[dict[str, Any]] = []
    verified_findings: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []

    # All tools that ran during the scan (for report completeness)
    tools_run: list[str] = []

    # Scope configuration (for pre-filtering)
    scope_config: dict[str, Any] = {}

    # Raporlar
    reports_generated: list[str] = []

    # Metadata — attack chains, systemic issues, OOB domain vb.
    metadata: dict[str, Any] = {}

    # Extra data for cross-stage communication (WAF strategy, etc.)
    extra_data: dict[str, Any] = {}

    # B2: Central brain-down flag — set to True when brain is confirmed
    # unreachable/broken, so subsequent stages skip brain calls immediately
    # instead of each independently timing out.
    brain_confirmed_down: bool = False

    # Cognitive modules (injected by orchestrator)
    adaptive_strategy: Any = None       # AdaptiveStrategyEngine instance
    self_reflection: Any = None         # SelfReflectionEngine instance

    # Zamanlama
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def elapsed_time(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time if self.start_time else 0.0

    @property
    def is_complete(self) -> bool:
        return WorkflowStage.KNOWLEDGE_UPDATE in self.completed_stages


# ============================================================
# Stage Handler Tipi
# ============================================================

StageHandler = Callable[[WorkflowState], Awaitable[StageResult]]


# ============================================================
# Orchestrator
# ============================================================

class WorkflowOrchestrator:
    """
    Ana workflow orkestratör.

    10 aşamalı tarama pipeline'ını yönetir.
    Her aşama bağımsız handler fonksiyonları tarafından işlenir.
    Hibrit modda kritik aşamalarda insan onayı ister.

    Kullanım:
        orchestrator = WorkflowOrchestrator(
            brain_engine=engine,
            tool_executor=executor,
            fp_detector=detector,
        )

        state = await orchestrator.run(target="example.com", scope={...})
    """

    def __init__(
        self,
        brain_engine: Any | None = None,
        tool_executor: Any | None = None,
        fp_detector: Any | None = None,
        mode: OperationMode = OperationMode.SEMI_AUTONOMOUS,
        profile: ScanProfile = ScanProfile.BALANCED,
        human_approval_callback: Callable[[str], Awaitable[bool]] | None = None,
        # ── Cognitive modules (optional, injected) ──
        session_manager: Any | None = None,
        result_aggregator: Any | None = None,
        adaptive_strategy: Any | None = None,
        tool_chain_engine: Any | None = None,
        self_reflection: Any | None = None,
        brain_router: Any | None = None,
    ) -> None:
        self.brain_engine = brain_engine
        self.brain_router = brain_router
        self.tool_executor = tool_executor
        self.fp_detector = fp_detector
        self.mode = mode
        self.profile = profile
        self.human_approval_callback = human_approval_callback

        # ── Cognitive modules ──
        self.session_manager = session_manager
        self.result_aggregator = result_aggregator
        self.adaptive_strategy = adaptive_strategy
        self.tool_chain_engine = tool_chain_engine
        self.self_reflection = self_reflection

        # Stage handler'ları
        self._handlers: dict[WorkflowStage, StageHandler] = {}

        # Pipeline sırası
        self._pipeline: list[WorkflowStage] = [
            WorkflowStage.SCOPE_ANALYSIS,
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

        # Yarı-otonom modda onay gerektiren aşamalar
        self._requires_approval: set[WorkflowStage] = {
            WorkflowStage.ACTIVE_RECON,
            WorkflowStage.VULNERABILITY_SCAN,
        }

        # ── SAFETY: Platform submit aşaması her zaman atlanır ──
        # Rapor gönderimi ASLA otomatik yapılmaz.
        # Kullanıcı raporları her zaman elle göndermelidir.
        # Bu set, hangi modda olursa olsun uygulanır.
        self._always_skip: set[WorkflowStage] = {
            WorkflowStage.PLATFORM_SUBMIT,
        }

        # ── StateMachine: transition observability guard ──
        self._state_machine = StateMachine()
        self._state_machine.start()

        # ── Stage timeout'ları (saniye) ──
        # BaronLLM v2 /think mode brain calls take 30-120s each.
        # Stage timeouts — designed for thorough bug bounty scanning (up to 24h total)
        # Bug bounty scans prioritize thoroughness over speed.
        self._stage_timeouts: dict[WorkflowStage, float] = {
            WorkflowStage.SCOPE_ANALYSIS: 1800,        #  30 min
            WorkflowStage.PASSIVE_RECON: 7200,         #   2 hours (subfinder + amass + OSINT + dorking)
            WorkflowStage.ACTIVE_RECON: 10800,         #   3 hours (full port scan + crawling + tech detect)
            WorkflowStage.ENUMERATION: 14400,          #   4 hours (deep URL discovery, parameter mining)
            WorkflowStage.ATTACK_SURFACE_MAP: 3600,    #   1 hour  (LLM planning + threat model + template gen)
            WorkflowStage.VULNERABILITY_SCAN: 36000,   #  10 hours (nuclei multi-pass + injection + custom checkers + HUNTER)
            WorkflowStage.FP_ELIMINATION: 7200,        #   2 hours (LLM verify + deep brain verify + re-request)
            WorkflowStage.REPORTING: 7200,             #   2 hours (LLM enrichment + PoC gen + correlation + report writing)
            WorkflowStage.PLATFORM_SUBMIT: 1800,       #  30 min
            WorkflowStage.KNOWLEDGE_UPDATE: 1800,      #  30 min
        }

        # ── Graceful shutdown flag ──
        self._shutdown_requested = False
        self._current_stage_task: asyncio.Task | None = None
        self._current_state: WorkflowState | None = None

        # ── Attributes created during run() — init here to avoid AttributeError ──
        self._profiler: Any | None = None
        self._bg_critique_tasks: list[asyncio.Task] = []
        self._sm_session: Any | None = None

    def request_shutdown(self) -> None:
        """Request graceful shutdown of the current scan.

        This is the public API for stopping a running scan. Prefer this
        over directly setting ``_shutdown_requested``.
        """
        self._shutdown_requested = True
        logger.info("Graceful shutdown requested via request_shutdown()")
        # Cancel any background critique tasks
        for task in self._bg_critique_tasks:
            if not task.done():
                task.cancel()
        self._bg_critique_tasks.clear()

    def clear_shutdown_request(self) -> None:
        """Clear graceful shutdown flag for controlled re-use scenarios.

        This is primarily used by GUI multi-target scans that execute targets
        sequentially with the same orchestrator instance.
        """
        self._shutdown_requested = False
        logger.debug("Graceful shutdown flag cleared via clear_shutdown_request()")

    def register_handler(self, stage: WorkflowStage, handler: StageHandler) -> None:
        """Aşama handler'ını kaydet."""
        self._handlers[stage] = handler
        logger.debug(f"Handler registered | stage={stage}")

    async def run(
        self,
        target: str,
        scope: dict[str, Any] | None = None,
        start_from: WorkflowStage | None = None,
        stop_after: WorkflowStage | None = None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> WorkflowState:
        """
        Tam tarama pipeline'ını çalıştır.

        Args:
            target: Ana hedef (domain/URL)
            scope: Scope tanımı
            start_from: Bu aşamadan başla (None = baştan)
            stop_after: Bu aşamadan sonra dur (None = sonuna kadar)

        Returns:
            WorkflowState — tüm toplanan veriler ve bulgular
        """
        from src.utils.logger import get_session_id

        state = WorkflowState(
            session_id=get_session_id(),
            target=target,
            mode=self.mode,
            profile=self.profile,
            start_time=time.time(),
            scope_config=scope or {},
            # ── Inject components so handlers can use them ──
            tool_executor=self.tool_executor,
            brain_engine=self.brain_engine,
            fp_detector=self.fp_detector,
            # ── Cognitive modules for stage handlers ──
            adaptive_strategy=self.adaptive_strategy,
            self_reflection=self.self_reflection,
        )

        # ── Merge extra metadata (auth_headers, etc.) ──
        if extra_metadata:
            state.metadata.update(extra_metadata)
            # Promote auth data to first-class fields
            if "auth_headers" in extra_metadata:
                state.auth_headers = extra_metadata["auth_headers"]
            if "auth_roles" in extra_metadata:
                state.auth_roles = extra_metadata["auth_roles"]

        # ── Resume support: restore data from previous session (T4-1) ──
        _resume_session = getattr(self, "_resume_session", None)
        _resume_sm = getattr(self, "_resume_sm", None)
        if _resume_session and _resume_sm:
            _resume_sm.sync_to_workflow_state(_resume_session, state)
            logger.info(
                f"Session data restored | subdomains={len(state.subdomains)} | "
                f"endpoints={len(state.endpoints)} | findings={len(state.raw_findings)} | "
                f"completed_stages={len(state.completed_stages)}"
            )
            # Clear to avoid re-use
            self._resume_session = None
            self._resume_sm = None

        # ── Initialize IntelligenceEngine if brain is available ──
        if self.brain_engine:
            try:
                from src.brain.intelligence import IntelligenceEngine
                state.intelligence_engine = IntelligenceEngine(
                    self.brain_engine, router=self.brain_router
                )
                logger.info("IntelligenceEngine activated — LLM-driven scanning enabled")
            except Exception as e:
                logger.warning(f"IntelligenceEngine init failed (non-critical): {e}")
                state.intelligence_engine = None

        logger.info(
            f"{'='*60}\n"
            f"  WORKFLOW STARTED\n"
            f"  Target: {target}\n"
            f"  Mode: {self.mode}\n"
            f"  Profile: {self.profile}\n"
            f"  Session: {state.session_id}\n"
            f"{'='*60}"
        )

        # ── Performance Profiler (T4-4) ──
        self._profiler = PerfProfiler()
        self._profiler.start()

        # Wire profiler into tool executor for per-tool timing
        if self.tool_executor:
            self.tool_executor.perf_profiler = self._profiler

        # Store reference for signal handler access
        self._current_state = state

        # ── Session Manager: create session for crash recovery ──
        _is_resume = getattr(self, "_resume_session", None) is not None
        if self.session_manager and not _is_resume:
            for _attempt in range(2):  # H2 fix: retry once on init failure
                try:
                    sm_session = self.session_manager.create_session(
                        target=target,
                        scope_config=scope or {},
                        profile=str(self.profile),
                        mode=str(self.mode),
                    )
                    self.session_manager.start_session(sm_session.metadata.session_id)
                    self._sm_session = sm_session  # store for stage tracking
                    logger.debug("SessionManager: session created and started")
                    break
                except Exception as e:
                    if _attempt == 0:
                        logger.warning(f"SessionManager init attempt 1 failed, retrying: {e}")
                    else:
                        self._sm_session = None
                        logger.warning(
                            f"SessionManager init failed after 2 attempts — "
                            f"crash recovery DISABLED for this scan: {e}"
                        )

        # Pipeline'daki aşamaları sırasıyla çalıştır
        started = start_from is None

        # 3.2: Reset StateMachine when resuming from a specific stage
        if start_from is not None:
            self._state_machine = StateMachine()
            self._state_machine.start()

        for stage in self._pipeline:
            # Başlangıç noktası kontrolü
            if not started:
                if stage == start_from:
                    started = True
                else:
                    continue

            state.current_stage = stage

            # ── StateMachine observability guard (non-blocking) ──
            if not self._state_machine.can_transition(stage):
                logger.warning(
                    f"StateMachine: unexpected transition "
                    f"{self._state_machine.current_state} → {stage} "
                    f"(not in allowed transitions — forcing sync)"
                )
                # Force state machine to stay in sync — use force_transition
                # to preserve callbacks and history
                try:
                    self._state_machine.force_transition(stage, trigger="forced_sync")
                except Exception:
                    # Last resort fallback if force_transition itself errors
                    self._state_machine._current = stage
            else:
                self._state_machine.transition(stage, trigger="auto")

            # ── SAFETY: Her zaman atlanması gereken aşamalar ──
            if stage in self._always_skip:
                logger.warning(
                    f"Stage SKIPPED (always_skip policy) | stage={stage} | "
                    "Rapor gönderimi kullanıcı tarafından elle yapılmalıdır."
                )
                state.stage_results[stage] = StageResult(
                    stage=stage,
                    skipped=True,
                    skip_reason="Safety policy: auto-submit permanently disabled",
                )
                continue

            # İnsan onayı kontrolü (yarı-otonom mod)
            if (
                self.mode == OperationMode.SEMI_AUTONOMOUS
                and stage in self._requires_approval
            ):
                approved = await self._request_approval(stage, target)
                if not approved:
                    logger.warning(f"Stage SKIPPED (human rejected) | stage={stage}")
                    state.stage_results[stage] = StageResult(
                        stage=stage, skipped=True, skip_reason="Human rejected"
                    )
                    continue

            # Handler var mı?
            handler = self._handlers.get(stage)
            if handler is None:
                logger.warning(f"No handler for stage: {stage} — skipping")
                state.stage_results[stage] = StageResult(
                    stage=stage, skipped=True, skip_reason="No handler registered"
                )
                continue

            # ── Smart skip: skip stages that have no meaningful input ──
            skip_reason = self._should_skip_stage(stage, state)
            if skip_reason:
                logger.info(f"Skipping stage {stage}: {skip_reason}")
                state.stage_results[stage] = StageResult(
                    stage=stage, skipped=True, skip_reason=skip_reason,
                )
                if stage not in state.completed_stages:
                    state.completed_stages.append(stage)
                continue

            # ── Self-Reflection: record stage start ──
            # Snapshot tools_run and findings before stage so we can diff after
            self._pre_stage_tools = list(state.tools_run)
            self._pre_stage_findings_count = len(state.raw_findings)
            if self.self_reflection:
                try:
                    self.self_reflection.record_stage_start(str(stage))
                except Exception as _e:
                    logger.warning(f"Non-critical error: {_e}")

            # ── Session Manager: record stage start ──
            if self.session_manager:
                try:
                    sm_session = getattr(self, '_sm_session', None)
                    if sm_session:
                        self.session_manager.record_stage_start(sm_session, str(stage))
                except Exception as _e:
                    logger.warning(f"Non-critical error: {_e}")

            # Aşamayı çalıştır
            logger.info(f"{'─'*40}")
            logger.info(f"STAGE: {stage}")
            logger.info(f"{'─'*40}")

            # Check graceful shutdown
            if self._shutdown_requested:
                logger.warning(f"Shutdown requested — skipping stage {stage}")
                state.stage_results[stage] = StageResult(
                    stage=stage, skipped=True, skip_reason="Shutdown requested",
                )
                break

            stage_timeout = self._stage_timeouts.get(stage, 1800)  # default 30 min
            start = time.monotonic()

            # ── Heartbeat task: log progress every 30s during long stages ──
            async def _heartbeat(stage_name: WorkflowStage, t0: float) -> None:
                """Periodically log that the stage is still running."""
                while True:
                    await asyncio.sleep(30)
                    elapsed = time.monotonic() - t0
                    remaining = stage_timeout - elapsed
                    findings_count = len(state.raw_findings)
                    logger.info(
                        f"⏳ Stage heartbeat | stage={stage_name} | "
                        f"elapsed={elapsed:.0f}s | remaining={remaining:.0f}s | "
                        f"findings={findings_count} | tools_run={len(state.tools_run)} | "
                        f"stages={len(state.completed_stages)}/{len(self._pipeline)}"
                    )

            heartbeat_task = asyncio.create_task(_heartbeat(stage, start))

            # ── Auth session refresh: ensure tokens are valid before each stage ──
            _auth_mgr = getattr(state.tool_executor, "auth_session", None) if state.tool_executor else None
            if _auth_mgr and hasattr(_auth_mgr, "ensure_valid"):
                try:
                    _auth_ok = await asyncio.wait_for(_auth_mgr.ensure_valid(), timeout=30)
                    if not _auth_ok:
                        logger.warning(f"Auth session invalid before stage {stage} — proceeding without auth")
                except Exception as _auth_err:
                    logger.warning(f"Auth refresh failed before stage {stage}: {_auth_err}")

            try:
                stage_task = asyncio.create_task(handler(state))
                self._current_stage_task = stage_task
                result = await asyncio.wait_for(
                    stage_task, timeout=stage_timeout
                )
                self._current_stage_task = None
                result.duration = time.monotonic() - start

                state.stage_results[stage] = result
                if stage not in state.completed_stages:
                    state.completed_stages.append(stage)

                # ── Self-Reflection: record + critique completed stage ──
                if self.self_reflection:
                    try:
                        tools_used = list(set(state.tools_run) - set(
                            getattr(self, '_pre_stage_tools', [])
                        ))
                        # Use findings delta — findings lack a 'stage' key
                        _pre_count = getattr(self, '_pre_stage_findings_count', 0)
                        _stage_findings = state.raw_findings[_pre_count:]
                        self.self_reflection.record_stage_end(
                            str(stage),
                            tools_used=tools_used,
                            findings=_stage_findings,
                            errors=result.errors,
                        )
                        # Self-critique: BLOCKING for zero-finding vuln stages,
                        # background for stages that produced results
                        _zero_finding_vuln_stage = (
                            result.findings_count == 0
                            and stage in (WorkflowStage.VULNERABILITY_SCAN, WorkflowStage.ENUMERATION)
                            and not getattr(self, f'_critique_retried_{stage}', False)
                        )
                        if _zero_finding_vuln_stage:
                            # Blocking critique — wait for result and potentially retry
                            critique = await asyncio.wait_for(
                                self.self_reflection.critique_stage(
                                    str(stage),
                                    results_summary=f"Findings: {result.findings_count}; "
                                    f"Duration: {result.duration:.1f}s; "
                                    f"Errors: {', '.join(result.errors[:3]) if result.errors else 'none'}",
                                ),
                                timeout=1200.0,
                            )
                            logger.info(
                                f"[Self-Critique BLOCKING] stage={stage} | level={critique.level} | "
                                f"score={critique.score:.0f} | action={critique.adapt_action}"
                            )
                            # If critique recommends retry/deepen → re-run stage ONCE
                            if critique.adapt_action.value in ("retry", "deepen", "add_tools", "adjust_params"):
                                setattr(self, f'_critique_retried_{stage}', True)
                                logger.info(
                                    f"[Self-Critique] Retrying stage {stage} based on critique "
                                    f"(action={critique.adapt_action})"
                                )
                                # Feed recommendations into state metadata for the retried stage
                                if not state.metadata:
                                    state.metadata = {}
                                state.metadata["critique_recommendations"] = critique.recommendations[:5]
                                state.metadata["critique_adapt_action"] = critique.adapt_action.value
                                # Snapshot pre-retry finding count to deduplicate
                                _pre_retry_finding_count = len(state.raw_findings)
                                # Re-run the stage
                                retry_result = await handler(state)
                                if retry_result.findings_count > result.findings_count:
                                    old_count = result.findings_count
                                    result = retry_result
                                    state.stage_results[stage] = result
                                    logger.info(
                                        f"[Self-Critique] Retry produced {retry_result.findings_count} "
                                        f"findings (improved from {old_count})"
                                    )
                                else:
                                    # Retry didn't improve — remove duplicated findings
                                    state.raw_findings = state.raw_findings[:_pre_retry_finding_count]
                                    # Sync stage_results to match the truncated findings
                                    state.stage_results[stage] = result
                        else:
                            # Non-blocking critique for productive stages
                            task = asyncio.create_task(
                                self._run_stage_critique(stage, result, state)
                            )
                            if not hasattr(self, '_bg_critique_tasks'):
                                self._bg_critique_tasks: list[asyncio.Task] = []
                            # Clean up completed tasks
                            self._bg_critique_tasks = [
                                t for t in self._bg_critique_tasks if not t.done()
                            ]
                            self._bg_critique_tasks.append(task)
                    except asyncio.TimeoutError:
                        logger.warning(f"Blocking self-critique timed out for {stage}")
                    except Exception as _refl_err:
                        logger.warning(f"Self-reflection record failed: {_refl_err}")

                # ── Session Manager: record stage completion ──
                if self.session_manager:
                    try:
                        sm_session = getattr(self, '_sm_session', None)
                        if sm_session:
                            self.session_manager.record_stage_complete(
                                sm_session, str(stage), data=result.data
                            )
                    except Exception as _e:
                        logger.warning(f"Non-critical error: {_e}")

                # ── Adaptive Strategy: observe stage results ──
                if self.adaptive_strategy and result.data:
                    try:
                        self._feed_adaptive_strategy(stage, result, state)
                    except Exception as _e:
                        logger.warning(f"Non-critical error: {_e}")

                # ── Session Manager: checkpoint after each stage ──
                if self.session_manager:
                    try:
                        sm_session = getattr(self, '_sm_session', None)
                        if sm_session:
                            self.session_manager.sync_from_workflow_state(sm_session, state)
                            self.session_manager.checkpoint(sm_session)
                    except Exception as _ckpt_err:
                        # 3.4: Retry sync+checkpoint once on failure
                        logger.warning(f"Session checkpoint failed, retrying once: {_ckpt_err}")
                        try:
                            sm_session = getattr(self, '_sm_session', None)
                            if sm_session:
                                self.session_manager.sync_from_workflow_state(sm_session, state)
                                self.session_manager.checkpoint(sm_session)
                        except Exception as _ckpt_retry_err:
                            logger.warning(f"Session checkpoint retry also failed: {_ckpt_retry_err}")

                logger.info(
                    f"Stage complete | stage={stage} | "
                    f"success={result.success} | "
                    f"findings={result.findings_count} | "
                    f"duration={result.duration:.1f}s"
                )

                # ── 3.1: Halt pipeline if scope analysis reports invalid target ──
                if stage == WorkflowStage.SCOPE_ANALYSIS:
                    _scope_valid = (result.data or {}).get("scope_valid", True)
                    if not _scope_valid:
                        logger.error(
                            "Scope analysis returned scope_valid=False — "
                            "aborting pipeline to prevent out-of-scope scanning"
                        )
                        break

            except Exception as e:
                elapsed = time.monotonic() - start

                # Distinguish timeout from other errors
                if isinstance(e, asyncio.TimeoutError):
                    # Check if the handler synced partial findings to state
                    partial_findings = len(getattr(state, 'raw_findings', None) or [])
                    partial_verified = len(getattr(state, 'verified_findings', None) or [])
                    logger.error(
                        f"Stage TIMEOUT | stage={stage} | "
                        f"timeout={stage_timeout}s | elapsed={elapsed:.1f}s | "
                        f"partial_findings={partial_findings} | "
                        f"partial_verified={partial_verified}"
                    )

                    # ── Preserve partial work on FP elimination timeout ──
                    if stage == WorkflowStage.FP_ELIMINATION and partial_findings > 0:
                        # Identify unprocessed findings (not yet in verified or false_positives)
                        verified_titles = {f.get("title", "") for f in (state.verified_findings or []) if isinstance(f, dict)}
                        fp_titles = {f.get("title", "") for f in (state.false_positives or []) if isinstance(f, dict)}
                        processed_titles = verified_titles | fp_titles

                        unprocessed = [
                            f for f in (state.raw_findings or [])
                            if isinstance(f, dict) and f.get("title", "") not in processed_titles
                               and (f.get("severity") or "info").lower() in ("medium", "high", "critical")
                        ]

                        if unprocessed:
                            logger.warning(
                                f"FP elimination timed out — {partial_verified} verified, "
                                f"{len(unprocessed)} unprocessed findings promoted as unverified"
                            )
                            for f in unprocessed:
                                f.setdefault("confidence_score", 50.0)
                                f["fp_status"] = "unverified_timeout"
                            state.verified_findings.extend(unprocessed)
                        elif partial_verified > 0:
                            logger.warning(
                                f"FP elimination timed out but all {partial_verified} "
                                f"findings were processed"
                            )

                    state.stage_results[stage] = StageResult(
                        stage=stage,
                        success=False,
                        duration=elapsed,
                        findings_count=partial_findings,
                        errors=[f"Stage timed out after {stage_timeout}s"],
                    )
                else:
                    logger.error(f"Stage FAILED | stage={stage} | error={e} | duration={elapsed:.1f}s")
                    state.stage_results[stage] = StageResult(
                        stage=stage,
                        success=False,
                        duration=elapsed,
                        errors=[str(e)],
                    )

                # Stage ran (even if failed/timed-out) — add to completed so
                # the pipeline continues to the next stage instead of leaving
                # a gap in stage_results.
                if stage not in state.completed_stages:
                    state.completed_stages.append(stage)

                # ── Self-Reflection: record failure ──
                if self.self_reflection:
                    try:
                        self.self_reflection.record_stage_end(
                            str(stage),
                            errors=[str(e)],
                        )
                    except Exception as _e:
                        logger.warning(f"Non-critical error: {_e}")

                # ── Session Manager: record error + persist partial work ──
                if self.session_manager:
                    try:
                        sm_session = getattr(self, '_sm_session', None)
                        if sm_session:
                            self.session_manager.record_stage_error(
                                sm_session, str(stage), str(e)
                            )
                            # P0-3 (V20): Persist partial work from failed/timed-out stages
                            self.session_manager.sync_from_workflow_state(sm_session, state)
                            self.session_manager.checkpoint(sm_session, force=True)
                    except Exception as _e:
                        logger.warning(f"Non-critical error: {_e}")

            finally:
                # ALWAYS cancel heartbeat — prevents orphaned tasks on
                # BaseException (CancelledError, KeyboardInterrupt, etc.)
                heartbeat_task.cancel()
                self._current_stage_task = None

                # ── C3 Fix: Sync brain_confirmed_down from IntelligenceEngine ──
                _intel = getattr(state, 'intelligence_engine', None)
                if _intel and getattr(_intel, '_brain_down', False):
                    if not state.brain_confirmed_down:
                        state.brain_confirmed_down = True
                        logger.warning(
                            "Brain confirmed down — subsequent stages will skip brain calls"
                        )

                # ── PerfProfiler: record stage timing (T4-4) ──
                _sr = state.stage_results.get(stage)
                if _sr and self._profiler:
                    self._profiler.record_stage(
                        name=str(stage.value) if hasattr(stage, 'value') else str(stage),
                        duration=_sr.duration,
                        findings=_sr.findings_count,
                        tools=len([t for t in state.tools_run if t]),
                        skipped=_sr.skipped,
                    )

            # Bitiş noktası kontrolü
            if stop_after and stage == stop_after:
                logger.info(f"Pipeline stopped after: {stage}")
                break

        state.end_time = time.time()

        # ── Await background critique tasks before returning ──
        bg_tasks = getattr(self, '_bg_critique_tasks', [])
        if bg_tasks:
            pending = [t for t in bg_tasks if not t.done()]
            if pending:
                logger.debug(f"Awaiting {len(pending)} background critique tasks")
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*pending, return_exceptions=True),
                        timeout=300.0,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        f"Background critique tasks timed out after 300s — "
                        f"cancelling {len(pending)} remaining tasks"
                    )
                    for t in pending:
                        if not t.done():
                            t.cancel()
            self._bg_critique_tasks = []

        # ── Self-Reflection: final review (async) ──
        if self.self_reflection:
            try:
                await self.self_reflection.final_review(target=target)
            except Exception as _fr_err:
                logger.warning(f"Self-reflection final review failed: {_fr_err}")

        # ── Session Manager: complete session ──
        if self.session_manager:
            try:
                sm_session = getattr(self, '_sm_session', None)
                if sm_session:
                    self.session_manager.sync_from_workflow_state(sm_session, state)
                    self.session_manager.complete_session(sm_session.metadata.session_id)
            except Exception as _sess_err:
                logger.warning(f"Session completion failed: {_sess_err}")

        # ── PerfProfiler: finalize and save (T4-4) ──
        if self._profiler:
            try:
                self._profiler.stop()
                self._profiler.log_summary()
                scan_dir = f"output/scans/{state.session_id}"
                self._profiler.save(scan_dir)
                state.metadata["performance"] = self._profiler.report()
            except Exception as _perf_err:
                logger.warning(f"PerfProfiler finalize failed: {_perf_err}")

        # ── Per-stage summary ──
        stage_lines: list[str] = []
        for stage in self._pipeline:
            label = stage.value if hasattr(stage, 'value') else str(stage)
            sr = state.stage_results.get(stage)
            if sr is None:
                stage_lines.append(f"    {label:<30s} SKIPPED")
            elif sr.skipped:
                reason = sr.skip_reason[:40] if sr.skip_reason else "policy"
                stage_lines.append(f"    {label:<30s} SKIP   ({reason})")
            elif sr.success:
                stage_lines.append(
                    f"    {label:<30s} OK     "
                    f"({sr.duration:.1f}s, {sr.findings_count} findings)"
                )
            else:
                err = sr.errors[0][:40] if sr.errors else "unknown"
                stage_lines.append(
                    f"    {label:<30s} FAIL   "
                    f"({sr.duration:.1f}s) {err}"
                )
        stage_summary = "\n".join(stage_lines)

        logger.info(
            f"\n{'='*60}\n"
            f"  WORKFLOW COMPLETED\n"
            f"  Target: {target}\n"
            f"  Duration: {state.elapsed_time:.1f}s "
            f"({state.elapsed_time/60:.1f} min)\n"
            f"  Stages: {len(state.completed_stages)}/{len(self._pipeline)}\n"
            f"  Subdomains: {len(state.subdomains)}\n"
            f"  Live hosts: {len(state.live_hosts)}\n"
            f"  Endpoints: {len(state.endpoints)}\n"
            f"  Raw findings: {len(state.raw_findings)}\n"
            f"  Verified findings: {len(state.verified_findings)}\n"
            f"  False positives: {len(state.false_positives)}\n"
            f"  Reports: {len(state.reports_generated)}\n"
            f"\n  Per-Stage Results:\n{stage_summary}\n"
            f"{'='*60}"
        )

        # ── Save full state to JSON for later analysis ──
        try:
            import json as _json
            from pathlib import Path as _Path
            state_path = f"output/scans/{state.session_id}_state.json"
            _Path(state_path).parent.mkdir(parents=True, exist_ok=True)
            state_data = {
                "session_id": state.session_id,
                "target": state.target,
                "profile": str(state.profile),
                "mode": str(state.mode),
                "duration": state.elapsed_time,
                "subdomains": len(state.subdomains),
                "live_hosts": state.live_hosts,
                "endpoints_count": len(state.endpoints),
                "technologies": state.technologies,
                "raw_findings_count": len(state.raw_findings),
                "raw_findings": state.raw_findings,
                "verified_findings_count": len(state.verified_findings),
                "verified_findings": state.verified_findings,
                "false_positives_count": len(state.false_positives),
                "false_positives": state.false_positives,
                "reports": state.reports_generated,
                "tools_run": state.tools_run,
                "metadata": state.metadata,
                "completed_stages": [s.value if hasattr(s, 'value') else str(s) for s in state.completed_stages],
                "stage_results": {
                    (s.value if hasattr(s, 'value') else str(s)): {
                        "success": sr.success,
                        "skipped": sr.skipped,
                        "duration": sr.duration,
                        "findings_count": sr.findings_count,
                        "errors": sr.errors[:3],
                    }
                    for s, sr in state.stage_results.items()
                },
                "findings": state.raw_findings,
            }
            _Path(state_path).write_text(_json.dumps(state_data, indent=2, default=str))
            logger.info(f"State saved to {state_path}")
        except Exception as e:
            logger.warning(f"Failed to save state JSON: {e}")

        # Clear reference to allow GC if orchestrator is reused
        self._current_state = None
        return state

    async def run_stage(
        self,
        stage: WorkflowStage,
        state: WorkflowState,
    ) -> StageResult:
        """Tek bir aşamayı çalıştır."""
        handler = self._handlers.get(stage)
        if handler is None:
            raise ValueError(f"No handler for stage: {stage}")
        return await handler(state)

    async def _request_approval(self, stage: WorkflowStage, target: str) -> bool:
        """İnsan onayı iste (BUG-6 fix: non-blocking)."""
        if self.human_approval_callback:
            return await self.human_approval_callback(
                f"Approve stage '{stage}' for target '{target}'?"
            )

        # Callback yoksa terminal'den sor — run_in_executor ile async-safe
        try:
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: input(
                    f"\n[APPROVAL REQUIRED] Stage: {stage} | Target: {target}\n"
                    f"Proceed? (y/n): "
                ),
            )
            return response.strip().lower() in ("y", "yes")
        except EOFError:
            # Non-interactive context (GUI, background process, piped stdin).
            # Auto-approve so stages aren't silently skipped.
            logger.warning(
                f"No interactive terminal for approval — auto-approving stage {stage} "
                f"(target={target}). Use autonomous mode or provide human_approval_callback "
                f"to suppress this warning."
            )
            return True
        except KeyboardInterrupt:
            return False

    def get_progress(self, state: WorkflowState) -> dict[str, Any]:
        """Mevcut ilerleme durumunu döndür."""
        total = len(self._pipeline)
        completed = len(state.completed_stages)

        progress = {
            "total_stages": total,
            "completed_stages": completed,
            "progress_pct": round(completed / total * 100, 1) if total > 0 else 0,
            "current_stage": state.current_stage,
            "elapsed_time": state.elapsed_time,
            "findings": {
                "raw": len(state.raw_findings),
                "verified": len(state.verified_findings),
                "false_positives": len(state.false_positives),
            },
        }

        # Include adaptive strategy explanation if available
        if self.adaptive_strategy:
            try:
                progress["strategy"] = self.adaptive_strategy.explain()
            except Exception as _e:
                logger.warning(f"Non-critical error: {_e}")

        return progress

    async def _run_stage_critique(
        self,
        stage: WorkflowStage,
        result: StageResult,
        state: WorkflowState,
    ) -> None:
        """
        Run LLM-powered self-critique on a completed stage (background task).

        Produces a Critique object with score, strengths, weaknesses, and
        recommended adapt_action (continue/adjust/pivot/deepen/etc.).
        """
        try:
            summary_parts = [
                f"Findings: {result.findings_count}",
                f"Duration: {result.duration:.1f}s",
                f"Errors: {', '.join(result.errors[:3]) if result.errors else 'none'}",
            ]
            # Add key data points from result
            for key in ("live_hosts_count", "endpoints_count", "subdomains_count"):
                if key in result.data:
                    summary_parts.append(f"{key}: {result.data[key]}")

            critique = await self.self_reflection.critique_stage(
                str(stage),
                results_summary="; ".join(summary_parts),
            )

            logger.info(
                f"[Self-Critique] stage={stage} | level={critique.level} | "
                f"score={critique.score:.0f} | action={critique.adapt_action}"
            )

            # Feed critique insights into adaptive strategy if available
            if self.adaptive_strategy and critique.adapt_action.value != "continue":
                from src.workflow.adaptive_strategy import SignalType
                detail_map = {
                    "deepen": SignalType.ZERO_FINDINGS,
                    "broaden": SignalType.LARGE_ATTACK_SURFACE,
                    "retry": SignalType.TOOL_FAILED,
                    "pivot": SignalType.ZERO_FINDINGS,
                }
                sig = detail_map.get(critique.adapt_action.value)
                if sig:
                    self.adaptive_strategy.observe(
                        sig,
                        source=f"self_reflection_{stage}",
                        value=f"critique_score={critique.score:.0f}",
                        details={"adapt_action": critique.adapt_action.value},
                    )

        except Exception as e:
            logger.warning(f"Stage critique failed (non-critical): {e}")

    @staticmethod
    def _should_skip_stage(
        stage: WorkflowStage,
        state: WorkflowState,
    ) -> str | None:
        """
        Return a skip reason if the stage has no useful input, else None.

        This prevents running e.g. FP elimination on 0 findings,
        or reporting when there's nothing to report.
        """
        if stage == WorkflowStage.FP_ELIMINATION:
            if not state.raw_findings:
                return "No raw findings to verify"

        elif stage == WorkflowStage.REPORTING:
            if not state.verified_findings and not state.raw_findings:
                return "No findings to report"

        elif stage == WorkflowStage.PLATFORM_SUBMIT:
            if not state.reports_generated:
                return "No reports generated"

        elif stage == WorkflowStage.KNOWLEDGE_UPDATE:
            # Always run knowledge update — even 0 findings is useful info
            pass

        return None

    def _feed_adaptive_strategy(
        self,
        stage: WorkflowStage,
        result: StageResult,
        state: WorkflowState,
    ) -> None:
        """
        Feed stage results into the AdaptiveStrategyEngine.

        Extracts environmental signals from stage output and feeds
        them to let the strategy adapt for subsequent stages.
        """
        from src.workflow.adaptive_strategy import SignalType

        data = result.data

        # WAF detection signals
        if data.get("waf_detected"):
            self.adaptive_strategy.observe(
                SignalType.WAF_DETECTED,
                source=str(stage),
                value=data.get("waf_type", ""),
            )

        # Technology detection signals
        for tech in data.get("technologies", []):
            self.adaptive_strategy.observe(
                SignalType.TECH_DETECTED,
                source=str(stage),
                value=tech,
            )

        # Rate limiting signals
        if data.get("rate_limited"):
            self.adaptive_strategy.observe(
                SignalType.RATE_LIMITED,
                source=str(stage),
            )

        # CDN detection
        if data.get("cdn_detected"):
            self.adaptive_strategy.observe(
                SignalType.CDN_DETECTED,
                source=str(stage),
                value=data.get("cdn_type", ""),
            )

        # Zero findings → may need strategy adjustment
        if result.findings_count == 0 and stage in (
            WorkflowStage.VULNERABILITY_SCAN,
            WorkflowStage.ENUMERATION,
        ):
            self.adaptive_strategy.observe(
                SignalType.ZERO_FINDINGS,
                source=str(stage),
                details={"stage": str(stage)},
            )

        # Attack surface size signals
        if len(state.subdomains) > 100:
            self.adaptive_strategy.observe(
                SignalType.LARGE_ATTACK_SURFACE,
                details={"subdomain_count": len(state.subdomains)},
            )


__all__ = ["WorkflowOrchestrator", "WorkflowState", "StageResult"]


def install_signal_handlers(orchestrator: WorkflowOrchestrator) -> None:
    """
    Register SIGINT/SIGTERM handlers for graceful shutdown.

    First signal: request graceful shutdown (finish current stage, skip remaining).
    Second signal: force immediate exit.
    """
    import signal

    _force_count = 0

    def _handler(signum: int, frame: Any) -> None:
        nonlocal _force_count
        _force_count += 1
        sig_name = signal.Signals(signum).name

        if _force_count == 1:
            logger.warning(
                f"\n{'!'*60}\n"
                f"  {sig_name} received — GRACEFUL SHUTDOWN requested\n"
                f"  Current stage will finish, remaining stages skipped.\n"
                f"  Press Ctrl+C again to FORCE QUIT.\n"
                f"{'!'*60}"
            )
            orchestrator.request_shutdown()
            # Save partial state if possible
            if orchestrator._current_state:
                try:
                    _save_partial_state(orchestrator._current_state)
                except Exception as _e:
                    logger.warning(f"Non-critical error: {_e}")
        else:
            logger.critical(
                f"\n{sig_name} received AGAIN — FORCE EXIT\n"
                f"Partial results may be lost."
            )
            sys.exit(1)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)
    logger.debug("Signal handlers installed (SIGINT/SIGTERM → graceful shutdown)")


def _save_partial_state(state: WorkflowState) -> None:
    """Save partial workflow state to disk for crash recovery."""
    import json
    from pathlib import Path

    output_dir = Path("output/scans")
    output_dir.mkdir(parents=True, exist_ok=True)

    partial_file = output_dir / f"partial_{state.session_id}.json"

    # Serialize fields needed for crash recovery
    data = {
        "session_id": state.session_id,
        "target": state.target,
        "current_stage": str(state.current_stage),
        "completed_stages": [str(s) for s in state.completed_stages],
        "subdomains_count": len(state.subdomains),
        "live_hosts_count": len(state.live_hosts),
        "endpoints_count": len(state.endpoints),
        "raw_findings_count": len(state.raw_findings),
        "raw_findings": state.raw_findings,
        "verified_findings_count": len(state.verified_findings),
        "verified_findings": state.verified_findings,
        "false_positives": state.false_positives,
        "elapsed_time": state.elapsed_time,
        "tools_run": list(state.tools_run or []),
        "technologies": dict(state.technologies or {}),
        "metadata": {
            k: v for k, v in (state.metadata or {}).items()
            if isinstance(v, (str, int, float, bool, list, dict, type(None)))
        },
    }

    partial_file.write_text(json.dumps(data, indent=2))
    logger.info(f"Partial state saved to {partial_file}")
