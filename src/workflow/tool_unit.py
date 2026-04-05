"""
WhiteHatHacker AI — ToolUnit Abstraction Layer

Atomic, self-describing execution units that the agent loop can select,
compose, and schedule.  Each ToolUnit wraps one or more SecurityTools
(previously hardcoded as if/try blocks inside full_scan.py) and exposes
a uniform async execute() interface.

Architecture:
    ToolUnit (abstract)
    ├── unit_id          — unique key ("nuclei_fast", "sqlmap_injection", …)
    ├── stage            — which workflow stage it belongs to
    ├── category         — recon / scan / exploit / analysis
    ├── requires         — prerequisite data keys ("live_hosts", "endpoints")
    ├── provides         — output data keys ("findings", "technologies")
    ├── tools            — underlying SecurityTool names
    ├── estimated_duration — approximate seconds
    ├── risk_level       — safe/low/medium/high/critical
    └── execute(state, context) → ToolUnitResult

    ToolUnitResult
    ├── unit_id / success / duration / tools_run
    ├── findings         — list[dict] (normalised finding dicts)
    ├── context_updates  — dict (new subdomains, endpoints, …)
    └── observations     — str (human-readable summary for brain)

    ToolUnitRegistry
    ├── register(unit)
    ├── get(unit_id) / get_by_stage() / get_available() / get_remaining()
    └── iter → all registered units

Design decisions:
  • ToolUnit.execute() receives the full WorkflowState + AgentContext so
    it can read whatever it needs and write back through context_updates.
  • The registry performs prerequisite checks so the agent only sees units
    whose requirements are currently satisfiable.
  • Each ToolUnit carries its own concurrency / timeout policy;
    the agent loop does NOT hardcode these.
  • The `observations` field is a compact natural-language string that
    feeds directly into WorkingMemory → brain prompt.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from loguru import logger
from pydantic import BaseModel, Field

from src.utils.constants import (
    RiskLevel,
    ScanProfile,
    SeverityLevel,
    WorkflowStage,
)

if TYPE_CHECKING:
    from src.workflow.orchestrator import WorkflowState


# ──────────────────────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────────────────────

class UnitCategory(StrEnum):
    """Broad functional category for a ToolUnit."""

    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    ANALYSIS = "analysis"
    CUSTOM_CHECK = "custom_check"


# ──────────────────────────────────────────────────────────────
# Result Model
# ──────────────────────────────────────────────────────────────

class ToolUnitResult(BaseModel):
    """Outcome of a single ToolUnit execution."""

    unit_id: str = ""
    success: bool = True
    duration: float = 0.0                  # Wall-clock seconds
    tools_run: list[str] = Field(default_factory=list)

    # Findings (normalised dicts compatible with pipeline)
    findings: list[dict[str, Any]] = Field(default_factory=list)

    # Incremental state updates the orchestrator should apply
    # e.g. {"subdomains": [...], "technologies": {"host": [...]}}
    context_updates: dict[str, Any] = Field(default_factory=dict)

    # Compact observation string for the brain's working memory.
    # Example: "nuclei_fast ran against 14 hosts in 87s. 3 findings:
    #           1× HIGH xss, 1× MEDIUM sqli, 1× LOW info-disclosure."
    observations: str = ""

    # Errors/warnings that occurred during execution
    errors: list[str] = Field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# ──────────────────────────────────────────────────────────────
# Prerequisite Data Keys
# ──────────────────────────────────────────────────────────────

# Canonical strings used in ToolUnit.requires / .provides.
# WorkflowState fields are checked against these.
PREREQ_SUBDOMAINS = "subdomains"
PREREQ_LIVE_HOSTS = "live_hosts"
PREREQ_ENDPOINTS = "endpoints"
PREREQ_TECHNOLOGIES = "technologies"
PREREQ_FINDINGS = "findings"
PREREQ_OPEN_PORTS = "open_ports"
PREREQ_AUTH_HEADERS = "auth_headers"
PREREQ_SCOPE = "scope_config"

_STATE_PREREQUISITE_MAP: dict[str, str] = {
    PREREQ_SUBDOMAINS: "subdomains",
    PREREQ_LIVE_HOSTS: "live_hosts",
    PREREQ_ENDPOINTS: "endpoints",
    PREREQ_TECHNOLOGIES: "technologies",
    PREREQ_FINDINGS: "raw_findings",
    PREREQ_OPEN_PORTS: "open_ports",
    PREREQ_AUTH_HEADERS: "auth_headers",
    PREREQ_SCOPE: "scope_config",
}


def _check_prerequisite(state: WorkflowState, prereq: str) -> bool:
    """Return True if the given prerequisite is satisfied on *state*."""
    attr_name = _STATE_PREREQUISITE_MAP.get(prereq)
    if attr_name is None:
        return True  # Unknown prerequisite — do not block
    value = getattr(state, attr_name, None)
    if value is None:
        return False
    if isinstance(value, (list, dict)):
        return len(value) > 0
    if isinstance(value, str):
        return bool(value)
    return bool(value)


# ──────────────────────────────────────────────────────────────
# ToolUnit Abstract Base
# ──────────────────────────────────────────────────────────────

class ToolUnit(ABC):
    """
    Atomic execution unit that the agent loop can select and run.

    Subclasses (concrete ToolUnits) override ``_execute()`` with the
    actual tool invocation logic, which is typically 15-40 lines lifted
    verbatim from the corresponding full_scan.py block.

    Attributes are plain class-level declarations so that each
    concrete unit reads like a declarative card:

        class NucleiFast(ToolUnit):
            unit_id = "nuclei_fast"
            stage = WorkflowStage.VULNERABILITY_SCAN
            category = UnitCategory.SCAN
            requires = [PREREQ_LIVE_HOSTS]
            provides = [PREREQ_FINDINGS]
            tools = ["nuclei"]
            estimated_duration = 300
            risk_level = RiskLevel.MEDIUM
            concurrency = 2
            per_target_timeout = 600.0
    """

    # ── Declarative card fields (override in subclass) ────────

    unit_id: str = ""
    stage: WorkflowStage = WorkflowStage.VULNERABILITY_SCAN
    category: UnitCategory = UnitCategory.SCAN
    requires: list[str] = []
    provides: list[str] = []
    tools: list[str] = []
    estimated_duration: int = 120          # seconds
    risk_level: RiskLevel = RiskLevel.MEDIUM
    concurrency: int = 3                   # default semaphore width
    per_target_timeout: float = 300.0      # per-host/URL timeout

    # ── Profile-based timeout multipliers ─────────────────────

    _PROFILE_TIMEOUT_SCALE: dict[ScanProfile, float] = {
        ScanProfile.STEALTH: 2.0,
        ScanProfile.BALANCED: 1.0,
        ScanProfile.AGGRESSIVE: 0.6,
        ScanProfile.CUSTOM: 1.0,
    }

    # ── Public interface ──────────────────────────────────────

    async def execute(
        self,
        state: WorkflowState,
        context: Any = None,
    ) -> ToolUnitResult:
        """
        Execute this unit.  Handles timing, error wrapping, and
        observation summary generation.  Delegates to ``_execute()``.
        """
        t0 = time.monotonic()
        result = ToolUnitResult(unit_id=self.unit_id)

        try:
            result = await self._execute(state, context)
            result.unit_id = self.unit_id
        except asyncio.TimeoutError:
            result.success = False
            result.errors.append(f"{self.unit_id}: global timeout")
            logger.warning(f"ToolUnit {self.unit_id} timed out")
        except Exception as exc:
            result.success = False
            result.errors.append(f"{self.unit_id}: {exc!r}")
            logger.warning(f"ToolUnit {self.unit_id} error: {exc}")

        result.duration = time.monotonic() - t0
        if not result.observations:
            result.observations = self._auto_observation(result)
        return result

    def is_available(self, state: WorkflowState) -> bool:
        """Check if all prerequisites are met on *state*."""
        return all(_check_prerequisite(state, p) for p in self.requires)

    def effective_timeout(self, profile: ScanProfile) -> float:
        """Timeout scaled by scan profile."""
        scale = self._PROFILE_TIMEOUT_SCALE.get(profile, 1.0)
        return self.per_target_timeout * scale

    # ── Abstract — must be overridden ─────────────────────────

    @abstractmethod
    async def _execute(
        self,
        state: WorkflowState,
        context: Any = None,
    ) -> ToolUnitResult:
        """Core execution logic.  Implemented by each concrete unit."""
        ...

    # ── Helpers ───────────────────────────────────────────────

    def _auto_observation(self, result: ToolUnitResult) -> str:
        """Generate a compact observation string from a result."""
        parts: list[str] = []
        parts.append(
            f"{self.unit_id} {'completed' if result.success else 'FAILED'} "
            f"in {result.duration:.0f}s."
        )
        if result.tools_run:
            parts.append(f"Tools: {', '.join(result.tools_run)}.")

        if result.findings:
            sev_counts: dict[str, int] = {}
            for f in result.findings:
                s = str(f.get("severity", "info")).lower()
                sev_counts[s] = sev_counts.get(s, 0) + 1
            breakdown = ", ".join(
                f"{c}× {s.upper()}" for s, c in sorted(
                    sev_counts.items(),
                    key=lambda kv: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(kv[0], 0),
                    reverse=True,
                )
            )
            parts.append(f"{len(result.findings)} findings: {breakdown}.")
        else:
            parts.append("0 findings.")

        updates = result.context_updates
        if updates:
            update_items: list[str] = []
            for key, val in updates.items():
                if isinstance(val, list):
                    update_items.append(f"+{len(val)} {key}")
                elif isinstance(val, dict):
                    update_items.append(f"+{len(val)} {key}")
            if update_items:
                parts.append("Discovered: " + ", ".join(update_items) + ".")

        if result.errors:
            parts.append(f"Errors: {len(result.errors)}.")

        return " ".join(parts)

    def _severity_sort_key(self, severity: str) -> int:
        _MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return _MAP.get(severity.lower(), -1)

    def __repr__(self) -> str:
        return (
            f"<ToolUnit {self.unit_id} stage={self.stage} "
            f"tools={self.tools} risk={self.risk_level}>"
        )


# ──────────────────────────────────────────────────────────────
# ToolUnit Registry
# ──────────────────────────────────────────────────────────────

class ToolUnitRegistry:
    """
    Catalogue of all registered ToolUnits.  The agent loop queries
    this registry to discover available actions.
    """

    def __init__(self) -> None:
        self._units: dict[str, ToolUnit] = {}

    # ── Registration ──────────────────────────────────────────

    def register(self, unit: ToolUnit) -> None:
        """Register a ToolUnit.  Silently skip duplicate unit_ids."""
        uid = unit.unit_id
        if uid in self._units:
            existing = self._units[uid]
            if type(existing) is type(unit):
                return  # Same class — skip
            logger.warning(
                f"ToolUnitRegistry: overwriting {uid} "
                f"({type(existing).__name__} → {type(unit).__name__})"
            )
        self._units[uid] = unit

    def register_many(self, units: list[ToolUnit]) -> None:
        for u in units:
            self.register(u)

    # ── Query ─────────────────────────────────────────────────

    def get(self, unit_id: str) -> ToolUnit | None:
        return self._units.get(unit_id)

    def get_by_stage(self, stage: WorkflowStage) -> list[ToolUnit]:
        """All units belonging to *stage*, in registration order."""
        return [u for u in self._units.values() if u.stage == stage]

    def get_by_category(self, category: UnitCategory) -> list[ToolUnit]:
        return [u for u in self._units.values() if u.category == category]

    def get_available(self, state: WorkflowState) -> list[ToolUnit]:
        """Units whose prerequisites are satisfied on *state*."""
        return [u for u in self._units.values() if u.is_available(state)]

    def get_remaining(
        self,
        state: WorkflowState,
        completed_ids: set[str] | None = None,
        skipped_ids: set[str] | None = None,
    ) -> list[ToolUnit]:
        """Available units that haven't been completed or skipped."""
        done = (completed_ids or set()) | (skipped_ids or set())
        return [
            u
            for u in self.get_available(state)
            if u.unit_id not in done
        ]

    def get_stage_remaining(
        self,
        stage: WorkflowStage,
        state: WorkflowState,
        completed_ids: set[str] | None = None,
        skipped_ids: set[str] | None = None,
    ) -> list[ToolUnit]:
        """Remaining units for a specific stage."""
        done = (completed_ids or set()) | (skipped_ids or set())
        return [
            u
            for u in self._units.values()
            if u.stage == stage
            and u.unit_id not in done
            and u.is_available(state)
        ]

    def all_unit_ids(self) -> list[str]:
        return list(self._units.keys())

    def unit_ids_for_stage(self, stage: WorkflowStage) -> list[str]:
        return [u.unit_id for u in self._units.values() if u.stage == stage]

    def describe_units(
        self,
        unit_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Compact descriptions suitable for inclusion in a brain prompt.

        Each dict contains: unit_id, stage, category, tools,
        estimated_duration, risk_level, requires, provides.
        """
        targets = (
            [self._units[uid] for uid in unit_ids if uid in self._units]
            if unit_ids
            else list(self._units.values())
        )
        return [
            {
                "unit_id": u.unit_id,
                "stage": u.stage.value,
                "category": u.category.value,
                "tools": u.tools,
                "estimated_duration": u.estimated_duration,
                "risk_level": u.risk_level.value,
                "requires": u.requires,
                "provides": u.provides,
            }
            for u in targets
        ]

    def __len__(self) -> int:
        return len(self._units)

    def __iter__(self):
        return iter(self._units.values())

    def __contains__(self, unit_id: str) -> bool:
        return unit_id in self._units


__all__ = [
    "ToolUnit",
    "ToolUnitResult",
    "ToolUnitRegistry",
    "UnitCategory",
    "PREREQ_SUBDOMAINS",
    "PREREQ_LIVE_HOSTS",
    "PREREQ_ENDPOINTS",
    "PREREQ_TECHNOLOGIES",
    "PREREQ_FINDINGS",
    "PREREQ_OPEN_PORTS",
    "PREREQ_AUTH_HEADERS",
    "PREREQ_SCOPE",
]
