"""
WhiteHatHacker AI — Workflow State Machine

Deterministik durum makinesi. Her workflow aşamasını durum (state),
geçiş (transition) ve koşul (guard) olarak modelleyen yapı.
Hatalı aşama geçişlerini engeller.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from loguru import logger
from pydantic import BaseModel

from src.utils.constants import WorkflowStage


class Transition(BaseModel):
    """Bir durum geçişi."""

    from_state: WorkflowStage
    to_state: WorkflowStage
    condition: str = ""        # Guard condition açıklaması
    auto: bool = True          # Otomatik mi (True) yoksa onay mı (False)


class StateEvent(BaseModel):
    """Durum değişikliği kaydı."""

    from_state: WorkflowStage | None = None
    to_state: WorkflowStage
    timestamp: float = 0.0
    trigger: str = ""          # auto | manual | skip | error
    metadata: dict[str, Any] = {}


class StateMachine:
    """
    Workflow durum makinesi.

    Izin verilen durum geçişlerini tanımlar ve uygular.
    Geçersiz geçişleri engeller.

    States:
        SCOPE_ANALYSIS → PASSIVE_RECON → ACTIVE_RECON → ENUMERATION
        → ATTACK_SURFACE_MAP → VULNERABILITY_SCAN → FP_ELIMINATION
        → REPORTING → PLATFORM_SUBMIT → KNOWLEDGE_UPDATE

    Özel geçişler:
        - Herhangi bir state → KNOWLEDGE_UPDATE (abort)
        - VULNERABILITY_SCAN → REPORTING (skip FP if no findings)
        - PASSIVE_RECON → VULNERABILITY_SCAN (quick scan mode)

    Backward geçişler (agentic loop):
        - VULNERABILITY_SCAN → ACTIVE_RECON    (yeni subdomain keşfedildi)
        - VULNERABILITY_SCAN → ENUMERATION     (yeni endpoint keşfedildi)
        - FP_ELIMINATION → VULNERABILITY_SCAN  (FP analizi yeni test önerdi)
        - ENUMERATION → ACTIVE_RECON           (yeni host keşfedildi)
        - ATTACK_SURFACE_MAP → ENUMERATION     (strateji parametreleri genişletildi)

    Her backward geçiş *hedef stage* başına max 2 kez yapılabilir.

    Kullanım:
        sm = StateMachine()
        sm.start()

        if sm.can_transition(WorkflowStage.PASSIVE_RECON):
            sm.transition(WorkflowStage.PASSIVE_RECON)
    """

    # Maximum backward transitions allowed per target stage
    MAX_BACKWARD_PER_STAGE: int = 2

    def __init__(self) -> None:
        self._current: WorkflowStage | None = None
        self._history: list[StateEvent] = []
        self._transitions: dict[WorkflowStage, list[WorkflowStage]] = {}
        self._backward_transitions: set[tuple[WorkflowStage, WorkflowStage]] = set()
        self._backward_counts: dict[WorkflowStage, int] = {}
        self._guards: dict[tuple[WorkflowStage, WorkflowStage], Callable[..., bool]] = {}
        self._on_enter: dict[WorkflowStage, list[Callable]] = {}
        self._on_exit: dict[WorkflowStage, list[Callable]] = {}
        self._started = False

        self._build_transitions()

        logger.debug("StateMachine created with predefined transitions")

    def _build_transitions(self) -> None:
        """Izin verilen durum geçişlerini tanımla."""
        # Normal akış
        normal_flow = [
            (WorkflowStage.SCOPE_ANALYSIS, WorkflowStage.PASSIVE_RECON),
            (WorkflowStage.PASSIVE_RECON, WorkflowStage.ACTIVE_RECON),
            (WorkflowStage.ACTIVE_RECON, WorkflowStage.ENUMERATION),
            (WorkflowStage.ENUMERATION, WorkflowStage.ATTACK_SURFACE_MAP),
            (WorkflowStage.ATTACK_SURFACE_MAP, WorkflowStage.VULNERABILITY_SCAN),
            (WorkflowStage.VULNERABILITY_SCAN, WorkflowStage.FP_ELIMINATION),
            (WorkflowStage.FP_ELIMINATION, WorkflowStage.REPORTING),
            (WorkflowStage.REPORTING, WorkflowStage.PLATFORM_SUBMIT),
            (WorkflowStage.PLATFORM_SUBMIT, WorkflowStage.KNOWLEDGE_UPDATE),
        ]

        for from_s, to_s in normal_flow:
            self._add_transition(from_s, to_s)

        # Skip geçişleri (bazı aşamalar atlanabilir)
        skip_transitions = [
            # No findings → skip FP/Report/Submit
            (WorkflowStage.VULNERABILITY_SCAN, WorkflowStage.REPORTING),
            (WorkflowStage.VULNERABILITY_SCAN, WorkflowStage.KNOWLEDGE_UPDATE),
            (WorkflowStage.FP_ELIMINATION, WorkflowStage.KNOWLEDGE_UPDATE),
            (WorkflowStage.REPORTING, WorkflowStage.KNOWLEDGE_UPDATE),

            # Quick scan: skip enumeration/attack_surface
            (WorkflowStage.PASSIVE_RECON, WorkflowStage.VULNERABILITY_SCAN),
            (WorkflowStage.ACTIVE_RECON, WorkflowStage.VULNERABILITY_SCAN),

            # Skip active recon (passive only mode)
            (WorkflowStage.PASSIVE_RECON, WorkflowStage.ENUMERATION),
        ]

        for from_s, to_s in skip_transitions:
            self._add_transition(from_s, to_s)

        # Abort: herhangi bir state → KNOWLEDGE_UPDATE
        for stage in WorkflowStage:
            if stage != WorkflowStage.KNOWLEDGE_UPDATE:
                self._add_transition(stage, WorkflowStage.KNOWLEDGE_UPDATE)

        # Backward transitions (agentic loop — new intelligence triggers)
        backward_transitions = [
            # New subdomains discovered during vuln scan
            (WorkflowStage.VULNERABILITY_SCAN, WorkflowStage.ACTIVE_RECON),
            # New endpoints discovered during vuln scan
            (WorkflowStage.VULNERABILITY_SCAN, WorkflowStage.ENUMERATION),
            # FP analysis suggests additional vulnerability testing
            (WorkflowStage.FP_ELIMINATION, WorkflowStage.VULNERABILITY_SCAN),
            # New hosts discovered during enumeration
            (WorkflowStage.ENUMERATION, WorkflowStage.ACTIVE_RECON),
            # Strategy parameters need re-enumeration
            (WorkflowStage.ATTACK_SURFACE_MAP, WorkflowStage.ENUMERATION),
        ]

        for from_s, to_s in backward_transitions:
            self._add_transition(from_s, to_s)
            self._backward_transitions.add((from_s, to_s))
            self._guards[(from_s, to_s)] = self._make_backward_guard(to_s)

    def _add_transition(self, from_s: WorkflowStage, to_s: WorkflowStage) -> None:
        """Geçiş ekle."""
        if from_s not in self._transitions:
            self._transitions[from_s] = []
        if to_s not in self._transitions[from_s]:
            self._transitions[from_s].append(to_s)

    def _make_backward_guard(self, to_state: WorkflowStage) -> Callable[..., bool]:
        """Create a guard that limits backward transitions per target stage."""
        def _guard() -> bool:
            count = self._backward_counts.get(to_state, 0)
            if count >= self.MAX_BACKWARD_PER_STAGE:
                logger.warning(
                    f"Backward limit reached for {to_state.value} "
                    f"({count}/{self.MAX_BACKWARD_PER_STAGE})"
                )
                return False
            return True
        return _guard

    def is_backward(self, from_state: WorkflowStage, to_state: WorkflowStage) -> bool:
        """Check whether a transition is a backward transition."""
        return (from_state, to_state) in self._backward_transitions

    def get_backward_count(self, target_stage: WorkflowStage) -> int:
        """Return how many times we've gone backward to *target_stage*."""
        return self._backward_counts.get(target_stage, 0)

    @property
    def total_backward_count(self) -> int:
        """Sum of all backward transitions performed."""
        return sum(self._backward_counts.values())

    # ── Public API ────────────────────────────────────────────

    def start(self) -> None:
        """Durum makinesini başlat."""
        self._current = WorkflowStage.SCOPE_ANALYSIS
        self._started = True
        self._record_event(None, WorkflowStage.SCOPE_ANALYSIS, "start")
        logger.info(f"StateMachine started | initial={self._current}")

    @property
    def current_state(self) -> WorkflowStage | None:
        return self._current

    @property
    def is_terminal(self) -> bool:
        return self._current == WorkflowStage.KNOWLEDGE_UPDATE

    def can_transition(self, to_state: WorkflowStage) -> bool:
        """Bu geçiş izin veriliyor mu?"""
        if self._current is None:
            return False

        allowed = self._transitions.get(self._current, [])
        if to_state not in allowed:
            return False

        # Guard kontrolü
        guard = self._guards.get((self._current, to_state))
        if guard and not guard():
            return False

        return True

    def transition(
        self,
        to_state: WorkflowStage,
        trigger: str = "auto",
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """
        Durumu değiştir.

        Returns:
            True eğer geçiş başarılı, False eğer reddedildi.
        """
        if not self._started:
            logger.error("StateMachine not started")
            return False

        if not self.can_transition(to_state):
            logger.debug(
                f"Invalid transition: {self._current} → {to_state} | "
                f"allowed_count={len(self._transitions.get(self._current, []))}"
            )
            return False

        old_state = self._current

        # Track backward transition count
        if self.is_backward(old_state, to_state):
            self._backward_counts[to_state] = (
                self._backward_counts.get(to_state, 0) + 1
            )
            logger.info(
                f"Backward transition to {to_state.value} "
                f"(count={self._backward_counts[to_state]}/"
                f"{self.MAX_BACKWARD_PER_STAGE})"
            )

        # on_exit callbacks
        for cb in self._on_exit.get(old_state, []):
            try:
                cb(old_state, to_state)
            except Exception as e:
                logger.error(f"on_exit callback error: {e}")

        self._current = to_state
        self._record_event(old_state, to_state, trigger, metadata)

        # on_enter callbacks
        for cb in self._on_enter.get(to_state, []):
            try:
                cb(old_state, to_state)
            except Exception as e:
                logger.error(f"on_enter callback error: {e}")

        logger.info(f"State transition: {old_state} → {to_state} [{trigger}]")
        return True

    def force_transition(
        self,
        to_state: WorkflowStage,
        trigger: str = "forced_sync",
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Force a transition regardless of allowed-transitions guard.

        Preserves on_exit / on_enter callbacks and history recording,
        but bypasses ``can_transition()`` validation.  Used by the
        orchestrator when the pipeline stages don't perfectly match the
        state machine's transition table.

        **Backward guards are still enforced** — a force_transition
        cannot bypass the backward-per-stage limit.  This prevents
        infinite loops even when the orchestrator forces transitions.
        """
        if not self._started:
            logger.error("StateMachine not started — cannot force transition")
            return False

        old_state = self._current

        # Backward guard is NEVER bypassed, even by force
        if old_state is not None and self.is_backward(old_state, to_state):
            guard = self._guards.get((old_state, to_state))
            if guard and not guard():
                logger.warning(
                    f"force_transition BLOCKED by backward guard: "
                    f"{old_state} → {to_state}"
                )
                return False
            self._backward_counts[to_state] = (
                self._backward_counts.get(to_state, 0) + 1
            )
            logger.info(
                f"Forced backward transition to {to_state.value} "
                f"(count={self._backward_counts[to_state]}/"
                f"{self.MAX_BACKWARD_PER_STAGE})"
            )

        for cb in self._on_exit.get(old_state, []):
            try:
                cb(old_state, to_state)
            except Exception as e:
                logger.error(f"on_exit callback error (forced): {e}")

        self._current = to_state
        self._record_event(old_state, to_state, trigger, metadata)

        for cb in self._on_enter.get(to_state, []):
            try:
                cb(old_state, to_state)
            except Exception as e:
                logger.error(f"on_enter callback error (forced): {e}")

        logger.info(f"State transition (forced): {old_state} → {to_state} [{trigger}]")
        return True

    def skip_to(
        self,
        to_state: WorkflowStage,
        reason: str = "",
    ) -> bool:
        """Doğrudan bir aşamaya atla (izin verilen skip geçişleri ile)."""
        return self.transition(to_state, trigger=f"skip:{reason}")

    def abort(self, reason: str = "") -> bool:
        """Workflow'u durdur ve KNOWLEDGE_UPDATE'e git."""
        return self.transition(
            WorkflowStage.KNOWLEDGE_UPDATE,
            trigger=f"abort:{reason}",
        )

    # ── Callbacks ─────────────────────────────────────────────

    def on_enter(self, state: WorkflowStage, callback: Callable) -> None:
        """Bir state'e girildiğinde çağrılacak callback."""
        if state not in self._on_enter:
            self._on_enter[state] = []
        self._on_enter[state].append(callback)

    def on_exit(self, state: WorkflowStage, callback: Callable) -> None:
        """Bir state'ten çıkıldığında çağrılacak callback."""
        if state not in self._on_exit:
            self._on_exit[state] = []
        self._on_exit[state].append(callback)

    def add_guard(
        self,
        from_state: WorkflowStage,
        to_state: WorkflowStage,
        guard: Callable[..., bool],
    ) -> None:
        """Geçiş koşulu ekle."""
        self._guards[(from_state, to_state)] = guard

    # ── History ───────────────────────────────────────────────

    def get_history(self) -> list[StateEvent]:
        """Geçiş geçmişi."""
        return self._history

    def get_elapsed_in_current(self) -> float:
        """Mevcut state'te geçen süre."""
        if not self._history:
            return 0.0
        return time.time() - self._history[-1].timestamp

    def _record_event(
        self,
        from_state: WorkflowStage | None,
        to_state: WorkflowStage,
        trigger: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Geçiş olayını kaydet."""
        self._history.append(StateEvent(
            from_state=from_state,
            to_state=to_state,
            timestamp=time.time(),
            trigger=trigger,
            metadata=metadata or {},
        ))

    def get_allowed_transitions(self) -> list[WorkflowStage]:
        """Mevcut state'ten izin verilen geçişler."""
        if self._current is None:
            return []
        return self._transitions.get(self._current, [])


__all__ = ["StateMachine", "StateEvent", "Transition"]
