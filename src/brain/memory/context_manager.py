"""
WhiteHatHacker AI — Context Manager

Short-term working memory for the current scan session.
Maintains conversation context, tool outputs, decisions,
and findings within the active workflow.
"""

from __future__ import annotations

import time
from collections import deque
from enum import Enum
from typing import Any

from loguru import logger
from pydantic import BaseModel, ConfigDict, Field


class ContextType(str, Enum):
    TOOL_OUTPUT = "tool_output"
    BRAIN_RESPONSE = "brain_response"
    DECISION = "decision"
    FINDING = "finding"
    USER_INPUT = "user_input"
    SYSTEM_EVENT = "system_event"
    REFLECTION = "reflection"
    ERROR = "error"


class ContextEntry(BaseModel):
    """A single entry in the context window."""

    timestamp: float = Field(default_factory=time.time)
    context_type: ContextType
    source: str = ""           # Tool name, brain model, system
    content: str = ""          # Actual text/data
    summary: str = ""          # Short summary for token-efficient retrieval
    tokens_estimated: int = 0  # Estimated token count
    importance: float = 0.5    # 0.0 = low, 1.0 = critical
    stage: str = ""            # Workflow stage when created
    target: str = ""           # Associated target
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=True)


class ContextWindow(BaseModel):
    """
    Sliding context window with token budget management.

    Maintains a rolling window of context entries that fit
    within the model's context length, prioritizing by importance
    and recency.
    """

    max_tokens: int = 28000     # Leave room for system prompt + response
    current_tokens: int = 0
    entries: list[ContextEntry] = Field(default_factory=list)


class ContextManager:
    """
    Short-term working memory for the active scan session.

    Manages:
    - Sliding context window (fits within model's token limit)
    - Tool output summaries (compressed for context efficiency)
    - Decision log (what was decided and why)
    - Finding accumulator (progressive findings list)
    - Stage transitions (workflow state)

    Token Management Strategy:
    - Primary Model (32B, 32K context): max ~28K tokens for context
    - Secondary Model (20B, 1024 training limit): max ~900 tokens
    - Auto-compress old entries when window fills
    - Importance-weighted eviction (least important + oldest first)
    """

    def __init__(self, max_tokens_primary: int = 28000, max_tokens_secondary: int = 900):
        self._primary_window = ContextWindow(max_tokens=max_tokens_primary)
        self._secondary_window = ContextWindow(max_tokens=max_tokens_secondary)

        # Quick access structures
        self._findings: list[dict] = []
        self._decisions: list[dict] = []
        self._tool_history: deque[dict] = deque(maxlen=100)
        self._current_stage: str = ""
        self._current_target: str = ""
        self._session_start: float = time.time()
        self._summary_cache: dict[str, str] = {}

        # Token estimation: ~3 chars per token (security content has URLs,
        # headers, JSON, special chars — ratio is lower than English prose)
        self._chars_per_token = 3

    def add_tool_output(
        self,
        tool_name: str,
        output_summary: str,
        findings_count: int = 0,
        raw_output_length: int = 0,
        importance: float = 0.5,
        metadata: dict | None = None,
    ) -> None:
        """Record a tool execution result in context."""
        content = (
            f"[Tool: {tool_name}] {output_summary}\n"
            f"Findings: {findings_count} | Raw output: {raw_output_length} chars"
        )

        entry = ContextEntry(
            context_type=ContextType.TOOL_OUTPUT,
            source=tool_name,
            content=content,
            summary=f"{tool_name}: {output_summary[:100]}",
            tokens_estimated=self._estimate_tokens(content),
            importance=importance,
            stage=self._current_stage,
            target=self._current_target,
            tags=["tool", tool_name],
            metadata=metadata or {},
        )

        self._add_entry(entry)
        self._tool_history.append({
            "tool": tool_name,
            "summary": output_summary,
            "findings": findings_count,
            "time": time.time(),
        })

    def add_finding(
        self,
        title: str,
        severity: str,
        confidence: float,
        tool_name: str,
        description: str = "",
    ) -> None:
        """Record a new finding in context."""
        importance = {"CRITICAL": 1.0, "HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4, "INFO": 0.2}.get(
            severity.upper(), 0.5
        )

        content = f"[Finding] {severity}: {title} (confidence: {confidence:.0f}%)"

        entry = ContextEntry(
            context_type=ContextType.FINDING,
            source=tool_name,
            content=content,
            summary=f"Finding: {title}",
            tokens_estimated=self._estimate_tokens(content),
            importance=importance,
            stage=self._current_stage,
            target=self._current_target,
            tags=["finding", str(severity or "info").lower()],
        )

        self._add_entry(entry)
        self._findings.append({
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "tool": tool_name,
            "description": description,
            "time": time.time(),
        })

    def add_decision(
        self,
        question: str,
        decision: str,
        reasoning: str,
        importance: float = 0.7,
    ) -> None:
        """Record a decision point."""
        content = f"[Decision] Q: {question}\nA: {decision}\nReason: {reasoning}"

        entry = ContextEntry(
            context_type=ContextType.DECISION,
            source="decision_engine",
            content=content,
            summary=f"Decision: {question[:50]} → {decision[:50]}",
            tokens_estimated=self._estimate_tokens(content),
            importance=importance,
            stage=self._current_stage,
            tags=["decision"],
        )

        self._add_entry(entry)
        self._decisions.append({
            "question": question,
            "decision": decision,
            "reasoning": reasoning,
            "stage": self._current_stage,
            "time": time.time(),
        })

    def add_brain_response(
        self,
        model_name: str,
        prompt_summary: str,
        response_summary: str,
        importance: float = 0.6,
    ) -> None:
        """Record a brain model's response."""
        content = f"[Brain: {model_name}] Prompt: {prompt_summary}\nResponse: {response_summary}"

        entry = ContextEntry(
            context_type=ContextType.BRAIN_RESPONSE,
            source=model_name,
            content=content,
            summary=f"Brain ({model_name}): {response_summary[:80]}",
            tokens_estimated=self._estimate_tokens(content),
            importance=importance,
            stage=self._current_stage,
            tags=["brain", model_name],
        )

        self._add_entry(entry)

    def add_reflection(self, reflection_text: str, importance: float = 0.8) -> None:
        """Record a self-reflection result."""
        entry = ContextEntry(
            context_type=ContextType.REFLECTION,
            source="self_reflection",
            content=f"[Reflection] {reflection_text}",
            summary=f"Reflection: {reflection_text[:80]}",
            tokens_estimated=self._estimate_tokens(reflection_text),
            importance=importance,
            stage=self._current_stage,
            tags=["reflection"],
        )
        self._add_entry(entry)

    def set_stage(self, stage: str) -> None:
        """Update current workflow stage."""
        self._current_stage = stage
        entry = ContextEntry(
            context_type=ContextType.SYSTEM_EVENT,
            source="workflow",
            content=f"[Stage Transition] → {stage}",
            summary=f"Stage: {stage}",
            tokens_estimated=10,
            importance=0.3,
            stage=stage,
            tags=["stage_transition"],
        )
        self._add_entry(entry)

    def set_target(self, target: str) -> None:
        """Update current target."""
        self._current_target = target

    # ── Context Retrieval ──────────────────────────────────────────

    def get_context_for_primary(self) -> str:
        """
        Build context string for the Primary (32B) model.

        Full context with details — up to ~28K tokens.
        """
        return self._build_context_string(self._primary_window)

    def get_context_for_secondary(self) -> str:
        """
        Build context string for the Secondary (20B) model.

        CRITICAL: Must be <900 tokens due to 1024 training limit.
        Uses ultra-compressed summaries.
        """
        return self._build_compressed_context()

    def get_findings_summary(self) -> str:
        """Get a summary of all findings so far."""
        if not self._findings:
            return "No findings yet."

        lines = [f"Total findings: {len(self._findings)}"]
        severity_counts: dict[str, int] = {}
        for f in self._findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append(f"By severity: {severity_counts}")

        # Top findings by severity
        sorted_findings = sorted(
            self._findings,
            key=lambda x: {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(x["severity"], 0),
            reverse=True,
        )
        for f in sorted_findings[:10]:
            lines.append(f"  [{f['severity']}] {f['title']} ({f['confidence']:.0f}%)")

        return "\n".join(lines)

    def get_tool_history(self, last_n: int = 10) -> list[dict]:
        """Get recent tool execution history."""
        return list(self._tool_history)[-last_n:]

    def get_decisions_log(self) -> list[dict]:
        """Get all decisions made during this session."""
        return list(self._decisions)

    def get_session_duration(self) -> float:
        """Get session duration in seconds."""
        return time.time() - self._session_start

    def get_context_stats(self) -> dict:
        """Get memory usage statistics."""
        return {
            "primary_window_tokens": self._primary_window.current_tokens,
            "primary_window_max": self._primary_window.max_tokens,
            "primary_utilization": f"{self._primary_window.current_tokens / self._primary_window.max_tokens:.1%}",
            "secondary_window_tokens": self._secondary_window.current_tokens,
            "total_entries": len(self._primary_window.entries),
            "total_findings": len(self._findings),
            "total_decisions": len(self._decisions),
            "total_tools_run": len(self._tool_history),
            "session_duration_s": self.get_session_duration(),
        }

    # ── Internal Methods ──────────────────────────────────────────

    def _add_entry(self, entry: ContextEntry) -> None:
        """Add entry to both context windows with overflow management."""
        # Primary window (full entry)
        self._add_to_window(self._primary_window, entry)

        # Secondary window (compressed entry)
        compressed = ContextEntry(
            timestamp=entry.timestamp,
            context_type=entry.context_type,
            source=entry.source,
            content=entry.summary,  # Use summary only
            summary=entry.summary[:50],
            tokens_estimated=self._estimate_tokens(entry.summary),
            importance=entry.importance,
            stage=entry.stage,
            tags=entry.tags,
        )
        self._add_to_window(self._secondary_window, compressed)

    def _add_to_window(self, window: ContextWindow, entry: ContextEntry) -> None:
        """Add entry to a specific window, evicting old/unimportant if needed."""
        tokens_needed = entry.tokens_estimated

        # Evict until we have room
        while window.current_tokens + tokens_needed > window.max_tokens and window.entries:
            # Find least important, oldest entry to evict
            evict_idx = self._find_eviction_candidate(window.entries)
            evicted = window.entries.pop(evict_idx)
            window.current_tokens -= evicted.tokens_estimated

        window.entries.append(entry)
        window.current_tokens += tokens_needed

    def _find_eviction_candidate(self, entries: list[ContextEntry]) -> int:
        """Find the best entry to evict (lowest score = first to go)."""
        if not entries:
            return 0

        now = time.time()
        best_idx = 0
        best_score = float("inf")

        for i, entry in enumerate(entries):
            # Score = importance * recency_factor
            age = now - entry.timestamp
            recency = 1.0 / (1.0 + age / 300)  # Decay over ~5 min
            score = entry.importance * 0.7 + recency * 0.3

            if score < best_score:
                best_score = score
                best_idx = i

        return best_idx

    def _build_context_string(self, window: ContextWindow) -> str:
        """Build a formatted context string from window entries."""
        parts = []
        for entry in window.entries:
            parts.append(entry.content)
        return "\n\n".join(parts)

    def _build_compressed_context(self) -> str:
        """
        Build ultra-compressed context for the Secondary (20B) model.

        CRITICAL: Must stay under ~900 tokens (~3600 chars).
        """
        parts = []

        # Current state (very brief)
        parts.append(f"Stage: {self._current_stage}")
        parts.append(f"Target: {self._current_target}")

        # Findings count
        if self._findings:
            severity_counts = {}
            for f in self._findings:
                s = f["severity"]
                severity_counts[s] = severity_counts.get(s, 0) + 1
            parts.append(f"Findings: {severity_counts}")

        # Last 3 tools
        recent = list(self._tool_history)[-3:]
        if recent:
            tool_lines = [f"  {t['tool']}: {t['summary'][:40]}" for t in recent]
            parts.append("Recent tools:\n" + "\n".join(tool_lines))

        # Last decision
        if self._decisions:
            last = self._decisions[-1]
            parts.append(f"Last decision: {last['question'][:40]} → {last['decision'][:40]}")

        result = "\n".join(parts)
        # Hard truncate at ~3500 chars (~875 tokens)
        return result[:3500]

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count from text length."""
        return max(1, len(text) // self._chars_per_token)

    def clear(self) -> None:
        """Clear all context (new session)."""
        self._primary_window = ContextWindow(max_tokens=self._primary_window.max_tokens)
        self._secondary_window = ContextWindow(max_tokens=self._secondary_window.max_tokens)
        self._findings.clear()
        self._decisions.clear()
        self._tool_history.clear()
        self._summary_cache.clear()
        self._session_start = time.time()
        logger.info("Context manager cleared")


__all__ = ["ContextManager", "ContextEntry", "ContextType"]
