"""
WhiteHatHacker AI — Working Memory System

Short-term, scan-level memory designed for the agent loop.
Each brain call receives a compact, relevant context snapshot
produced by ``WorkingMemory.to_context()``.

Key Design:
    • TargetProfile — immutable scan-session target summary
    • Hypothesis     — testable security hypotheses that drive the agent
    • FindingsSummary — severity×type matrix (compact, ~300 tokens)
    • ToolExecution  — last N tool results (observations + duration)
    • TimeBudget     — remaining / consumed time
    • to_context()   — renders the whole memory into a token-budgeted
                       string for inclusion in a brain prompt

Token Budget Strategy (for BaronLLM 32K context):
    target_profile     ~500 tokens  (fixed)
    findings_summary   ~300 tokens  (severity×type matrix)
    last 5 tool results ~2000 tokens (observation strings)
    environment_model  ~300 tokens
    active hypotheses  ~500 tokens
    time/budget info   ~100 tokens
    ─────────────────────────────
    TOTAL              ~3700 tokens (~12% of 32K)
"""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────
# Supporting Models
# ──────────────────────────────────────────────────────────────

class HypothesisStatus(StrEnum):
    PENDING = "pending"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class Hypothesis(BaseModel):
    """A testable security hypothesis managed by the agent."""

    h_id: str = Field(default_factory=lambda: f"h-{uuid.uuid4().hex[:8]}")
    text: str                                 # "Target is vulnerable to blind SQLi on /api/search?q= parameter"
    source: str = ""                          # "brain_think" | "tool_observation" | "pattern_match"
    status: HypothesisStatus = HypothesisStatus.PENDING
    priority: float = 0.5                     # 0.0 = low, 1.0 = critical
    suggested_units: list[str] = Field(default_factory=list)  # ToolUnit IDs to test this
    evidence_for: list[str] = Field(default_factory=list)     # supporting observations
    evidence_against: list[str] = Field(default_factory=list) # contradicting observations
    created: float = Field(default_factory=time.time)
    resolved: float = 0.0
    result: str = ""                          # free-form resolution summary

    def resolve(self, status: HypothesisStatus, result: str) -> None:
        self.status = status
        self.result = result
        self.resolved = time.time()


class TargetProfile(BaseModel):
    """Immutable-ish scan-session target summary built during recon."""

    domain: str = ""
    target_url: str = ""
    scope_domains: list[str] = Field(default_factory=list)
    subdomain_count: int = 0
    live_host_count: int = 0
    endpoint_count: int = 0
    technology_stack: list[str] = Field(default_factory=list)  # ["nginx", "react", "django"]
    waf: str = ""                    # "cloudflare" | "" (none detected)
    cdn: str = ""
    auth_type: str = ""              # "jwt" | "session" | ""
    has_api: bool = False
    has_graphql: bool = False
    spa_detected: bool = False
    open_ports: list[int] = Field(default_factory=list)

    def to_compact(self) -> str:
        """~500 token compact representation."""
        lines: list[str] = [f"Target: {self.domain}"]
        if self.scope_domains:
            lines.append(f"Scope domains: {', '.join(self.scope_domains[:10])}")
        lines.append(
            f"Assets: {self.subdomain_count} subdomains, "
            f"{self.live_host_count} live hosts, "
            f"{self.endpoint_count} endpoints"
        )
        if self.technology_stack:
            lines.append(f"Tech: {', '.join(self.technology_stack[:15])}")
        flags: list[str] = []
        if self.waf:
            flags.append(f"WAF={self.waf}")
        if self.cdn:
            flags.append(f"CDN={self.cdn}")
        if self.auth_type:
            flags.append(f"Auth={self.auth_type}")
        if self.has_api:
            flags.append("API")
        if self.has_graphql:
            flags.append("GraphQL")
        if self.spa_detected:
            flags.append("SPA")
        if flags:
            lines.append(f"Flags: {', '.join(flags)}")
        if self.open_ports:
            lines.append(f"Open ports: {', '.join(str(p) for p in self.open_ports[:20])}")
        return "\n".join(lines)


class ToolExecution(BaseModel):
    """Record of a single tool unit execution."""

    unit_id: str
    observation: str         # compact summary (from ToolUnitResult.observations)
    finding_count: int = 0
    duration: float = 0.0
    success: bool = True
    timestamp: float = Field(default_factory=time.time)


class FindingsSummary(BaseModel):
    """Compact severity×type matrix for findings so far."""

    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)   # {"CRITICAL": 2, "HIGH": 5, …}
    by_type: dict[str, int] = Field(default_factory=dict)       # {"xss": 3, "sqli": 2, …}
    confirmed_count: int = 0
    poc_count: int = 0

    def ingest(self, findings: list[dict[str, Any]]) -> None:
        """Incrementally add findings."""
        for f in findings:
            self.total += 1
            sev = str(f.get("severity", "info")).upper()
            self.by_severity[sev] = self.by_severity.get(sev, 0) + 1
            vt = str(f.get("vulnerability_type", f.get("vuln_type", "unknown"))).lower()
            self.by_type[vt] = self.by_type.get(vt, 0) + 1
            if f.get("poc_confirmed"):
                self.poc_count += 1
            if f.get("confirmed") or f.get("confidence_score", 0) >= 80:
                self.confirmed_count += 1

    def to_compact(self) -> str:
        """~300 token representation."""
        if self.total == 0:
            return "Findings: 0 total."
        lines: list[str] = [f"Findings: {self.total} total, {self.confirmed_count} confirmed, {self.poc_count} PoC"]
        if self.by_severity:
            sev_str = ", ".join(
                f"{s}: {c}" for s, c in sorted(
                    self.by_severity.items(),
                    key=lambda kv: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(kv[0], -1),
                    reverse=True,
                )
            )
            lines.append(f"Severity: {sev_str}")
        if self.by_type:
            type_str = ", ".join(
                f"{t}: {c}" for t, c in sorted(
                    self.by_type.items(), key=lambda kv: kv[1], reverse=True,
                )[:10]
            )
            lines.append(f"Types: {type_str}")
        return "\n".join(lines)


class TimeBudget(BaseModel):
    """Time tracking for the agent loop."""

    total_seconds: float = 7200.0       # default 2 hours
    start_time: float = Field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def remaining(self) -> float:
        return max(0.0, self.total_seconds - self.elapsed)

    @property
    def fraction_used(self) -> float:
        if self.total_seconds <= 0:
            return 1.0
        return min(1.0, self.elapsed / self.total_seconds)

    @property
    def is_expired(self) -> bool:
        return self.remaining <= 0

    def to_compact(self) -> str:
        e = self.elapsed
        r = self.remaining
        pct = self.fraction_used * 100
        return (
            f"Time: {e:.0f}s elapsed, {r:.0f}s remaining "
            f"({pct:.0f}% used)"
        )


# ──────────────────────────────────────────────────────────────
# Environment Snapshot (lightweight, derived from AdaptiveStrategy)
# ──────────────────────────────────────────────────────────────

class EnvironmentSnapshot(BaseModel):
    """Lightweight environment description for the brain prompt."""

    waf: str = ""
    cdn: str = ""
    rate_limited: bool = False
    strategy_mode: str = "standard"
    blocked_tools: list[str] = Field(default_factory=list)
    effective_tools: list[str] = Field(default_factory=list)

    def to_compact(self) -> str:
        parts: list[str] = []
        if self.waf:
            parts.append(f"WAF: {self.waf}")
        if self.cdn:
            parts.append(f"CDN: {self.cdn}")
        if self.rate_limited:
            parts.append("Rate-limited: YES")
        parts.append(f"Strategy: {self.strategy_mode}")
        if self.blocked_tools:
            parts.append(f"Blocked tools: {', '.join(self.blocked_tools[:5])}")
        if self.effective_tools:
            parts.append(f"Effective tools: {', '.join(self.effective_tools[:5])}")
        return " | ".join(parts) if parts else "No environment data."


# ──────────────────────────────────────────────────────────────
# Working Memory
# ──────────────────────────────────────────────────────────────

class WorkingMemory:
    """
    Short-term scan-level memory for the agent loop.

    Updated after every ToolUnit execution and before every brain
    call.  ``to_context()`` renders the current state into a
    token-budgeted string suitable for inclusion in a brain prompt.
    """

    # Token estimation: ~3.5 chars per token for mixed security content
    _CHARS_PER_TOKEN = 3.5

    def __init__(
        self,
        target: str = "",
        time_budget_seconds: float = 7200.0,
        max_tool_history: int = 15,
    ) -> None:
        self.target_profile = TargetProfile(domain=target, target_url=target)
        self.findings_summary = FindingsSummary()
        self.time_budget = TimeBudget(total_seconds=time_budget_seconds)
        self.environment = EnvironmentSnapshot()

        self._hypotheses: list[Hypothesis] = []
        self._tool_history: list[ToolExecution] = []
        self._max_tool_history = max_tool_history

        # Backward transition counter (stage_name → count)
        self.backward_count: dict[str, int] = {}

        # Iteration counter
        self.iteration: int = 0

    # ── Updates ───────────────────────────────────────────────

    def update_from_tool_result(
        self,
        unit_id: str,
        observation: str,
        findings: list[dict[str, Any]] | None = None,
        duration: float = 0.0,
        success: bool = True,
    ) -> None:
        """Record a ToolUnit result into working memory."""
        self._tool_history.append(
            ToolExecution(
                unit_id=unit_id,
                observation=observation,
                finding_count=len(findings) if findings else 0,
                duration=duration,
                success=success,
            )
        )
        # Trim oldest entries
        if len(self._tool_history) > self._max_tool_history:
            self._tool_history = self._tool_history[-self._max_tool_history:]

        if findings:
            self.findings_summary.ingest(findings)

    def update_target_profile(self, **kwargs: Any) -> None:
        """Incrementally update target profile fields."""
        for key, value in kwargs.items():
            if hasattr(self.target_profile, key):
                setattr(self.target_profile, key, value)

    def update_environment(self, **kwargs: Any) -> None:
        """Update environment snapshot."""
        for key, value in kwargs.items():
            if hasattr(self.environment, key):
                setattr(self.environment, key, value)

    # ── Hypothesis Management ─────────────────────────────────

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        self._hypotheses.append(hypothesis)

    def add_hypothesis_from_text(
        self,
        text: str,
        source: str = "brain",
        priority: float = 0.5,
        suggested_units: list[str] | None = None,
    ) -> Hypothesis:
        """Create and register a new hypothesis from text."""
        h = Hypothesis(
            text=text,
            source=source,
            priority=priority,
            suggested_units=suggested_units or [],
        )
        self._hypotheses.append(h)
        return h

    def resolve_hypothesis(
        self,
        h_id: str,
        status: HypothesisStatus,
        result: str = "",
    ) -> None:
        for h in self._hypotheses:
            if h.h_id == h_id:
                h.resolve(status, result)
                return
        logger.debug(f"Hypothesis {h_id} not found for resolve")

    def get_active_hypotheses(self) -> list[Hypothesis]:
        """Hypotheses still pending or being tested."""
        return [
            h for h in self._hypotheses
            if h.status in {HypothesisStatus.PENDING, HypothesisStatus.TESTING}
        ]

    def get_all_hypotheses(self) -> list[Hypothesis]:
        return list(self._hypotheses)

    # ── Context Rendering ─────────────────────────────────────

    def to_context(self, max_tokens: int = 6000) -> str:
        """
        Render working memory as a compact string for a brain prompt.

        Sections are added in priority order; if the budget is
        exhausted, lower-priority sections are truncated or dropped.
        """
        budget_chars = int(max_tokens * self._CHARS_PER_TOKEN)
        sections: list[str] = []
        used = 0

        def _add(section_header: str, body: str) -> bool:
            nonlocal used
            text = f"### {section_header}\n{body}"
            cost = len(text)
            if used + cost > budget_chars:
                # Try truncated version
                available = budget_chars - used - len(section_header) - 10
                if available > 100:
                    truncated = body[:available] + "…"
                    sections.append(f"### {section_header}\n{truncated}")
                    used = budget_chars  # Mark budget as full
                    return True
                return False
            sections.append(text)
            used += cost
            return True

        # Priority 1: Target profile (always included)
        _add("Target", self.target_profile.to_compact())

        # Priority 2: Time budget (always included — short)
        _add("Budget", self._render_budget())

        # Priority 3: Findings summary
        _add("Findings", self.findings_summary.to_compact())

        # Priority 4: Recent tool history (last 5)
        _add("Recent Tools", self._render_tool_history(count=5))

        # Priority 5: Active hypotheses
        active = self.get_active_hypotheses()
        if active:
            _add("Active Hypotheses", self._render_hypotheses(active))

        # Priority 6: Environment
        _add("Environment", self.environment.to_compact())

        # Priority 7: Resolved hypotheses (brief)
        resolved = [
            h for h in self._hypotheses
            if h.status in {HypothesisStatus.CONFIRMED, HypothesisStatus.REFUTED}
        ]
        if resolved:
            brief = "\n".join(
                f"- [{h.status.value}] {h.text[:60]}" for h in resolved[-5:]
            )
            _add("Resolved Hypotheses", brief)

        return "\n\n".join(sections)

    # ── Convenience Getters ───────────────────────────────────

    @property
    def tool_execution_count(self) -> int:
        return len(self._tool_history)

    @property
    def last_tool(self) -> ToolExecution | None:
        return self._tool_history[-1] if self._tool_history else None

    def completed_unit_ids(self) -> list[str]:
        """All unit IDs that have been executed."""
        return [t.unit_id for t in self._tool_history]

    # ── Private Renderers ─────────────────────────────────────

    def _render_budget(self) -> str:
        parts: list[str] = [self.time_budget.to_compact()]
        parts.append(f"Iteration: {self.iteration}")
        if self.backward_count:
            bk = ", ".join(f"{k}: {v}" for k, v in self.backward_count.items())
            parts.append(f"Backward transitions: {bk}")
        return "\n".join(parts)

    def _render_tool_history(self, count: int = 5) -> str:
        recent = self._tool_history[-count:]
        if not recent:
            return "No tools run yet."
        lines: list[str] = []
        for t in recent:
            status = "OK" if t.success else "FAIL"
            lines.append(
                f"- {t.unit_id} [{status}] {t.duration:.0f}s, "
                f"{t.finding_count} findings — {t.observation[:120]}"
            )
        return "\n".join(lines)

    def _render_hypotheses(self, hypotheses: list[Hypothesis]) -> str:
        lines: list[str] = []
        for h in hypotheses[:8]:  # max 8 to control token cost
            prio = f"P{h.priority:.1f}"
            units = f" → test with: {', '.join(h.suggested_units[:3])}" if h.suggested_units else ""
            lines.append(f"- [{h.status.value}|{prio}] {h.text[:100]}{units}")
        if len(hypotheses) > 8:
            lines.append(f"  (+ {len(hypotheses) - 8} more)")
        return "\n".join(lines)


__all__ = [
    "WorkingMemory",
    "Hypothesis",
    "HypothesisStatus",
    "TargetProfile",
    "ToolExecution",
    "FindingsSummary",
    "TimeBudget",
    "EnvironmentSnapshot",
]
