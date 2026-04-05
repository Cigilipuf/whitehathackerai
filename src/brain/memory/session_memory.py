"""
WhiteHatHacker AI — Session Memory

Episodic memory for specific scan sessions. Records the full
timeline of events, tool executions, findings, and decisions
within a single scan session. Provides replay capability and
rich audit trails.
"""

from __future__ import annotations

import json
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, ConfigDict, Field


class EventType(str, Enum):
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    STAGE_ENTER = "stage_enter"
    STAGE_EXIT = "stage_exit"
    TOOL_START = "tool_start"
    TOOL_END = "tool_end"
    TOOL_ERROR = "tool_error"
    FINDING_NEW = "finding_new"
    FINDING_CONFIRMED = "finding_confirmed"
    FINDING_FP = "finding_fp"
    DECISION = "decision"
    BRAIN_QUERY = "brain_query"
    BRAIN_RESPONSE = "brain_response"
    REFLECTION = "reflection"
    HUMAN_APPROVAL_REQUEST = "human_approval_request"
    HUMAN_APPROVAL_RESPONSE = "human_approval_response"
    SCOPE_CHECK = "scope_check"
    RATE_LIMIT = "rate_limit"
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


class SessionEvent(BaseModel):
    """A single event in the session timeline."""

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = Field(default_factory=time.time)
    event_type: EventType
    stage: str = ""
    source: str = ""          # Component/tool name
    target: str = ""          # Target being worked on
    title: str = ""           # Short description
    details: str = ""         # Full details
    data: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0  # For timed events
    success: bool | None = None

    model_config = ConfigDict(use_enum_values=True)


class SessionSnapshot(BaseModel):
    """A point-in-time snapshot of session state."""

    timestamp: float = Field(default_factory=time.time)
    stage: str = ""
    findings_count: int = 0
    tools_run: int = 0
    decisions_made: int = 0
    errors_count: int = 0
    elapsed_seconds: float = 0.0


class SessionMemory:
    """
    Episodic memory for a single scan session.

    Records every significant event with full details and timestamps,
    creating a complete audit trail that can be:
    - Replayed for debugging
    - Analyzed for performance insights
    - Used for report generation (timeline of discovery)
    - Persisted to disk as JSON for archival

    Also maintains running statistics and periodic snapshots.
    """

    def __init__(self, session_id: str | None = None, target: str = ""):
        self.session_id = session_id or uuid.uuid4().hex[:16]
        self.target = target
        self.start_time = time.time()
        self.end_time: float | None = None

        self._events: list[SessionEvent] = []
        self._snapshots: list[SessionSnapshot] = []
        self._active_timers: dict[str, float] = {}

        # Running counters
        self._tools_run = 0
        self._findings_count = 0
        self._confirmed_count = 0
        self._fp_count = 0
        self._errors_count = 0
        self._decisions_count = 0
        self._current_stage = ""

        # Tool timing
        self._tool_times: dict[str, list[float]] = {}

        # Record session start
        self.record_event(
            EventType.SESSION_START,
            source="session",
            title=f"Session started: {self.session_id}",
            details=f"Target: {target}",
            data={"session_id": self.session_id, "target": target},
        )

    def record_event(
        self,
        event_type: EventType,
        source: str = "",
        title: str = "",
        details: str = "",
        data: dict[str, Any] | None = None,
        success: bool | None = None,
        duration_ms: float = 0.0,
    ) -> SessionEvent:
        """Record a new event in the timeline."""
        event = SessionEvent(
            event_type=event_type,
            stage=self._current_stage,
            source=source,
            target=self.target,
            title=title,
            details=details,
            data=data or {},
            duration_ms=duration_ms,
            success=success,
        )
        self._events.append(event)
        return event

    # ── Stage Tracking ─────────────────────────────────────────────

    def enter_stage(self, stage: str) -> None:
        """Record entering a workflow stage."""
        if self._current_stage:
            self.exit_stage()

        self._current_stage = stage
        self._active_timers[f"stage_{stage}"] = time.time()
        self.record_event(
            EventType.STAGE_ENTER,
            source="workflow",
            title=f"Entered stage: {stage}",
        )
        self._take_snapshot()

    def exit_stage(self) -> float:
        """Record exiting current stage. Returns duration in ms."""
        stage = self._current_stage
        timer_key = f"stage_{stage}"
        duration = 0.0

        if timer_key in self._active_timers:
            duration = (time.time() - self._active_timers.pop(timer_key)) * 1000

        self.record_event(
            EventType.STAGE_EXIT,
            source="workflow",
            title=f"Exited stage: {stage}",
            duration_ms=duration,
            data={"stage": stage, "duration_ms": duration},
        )
        self._current_stage = ""
        return duration

    # ── Tool Tracking ──────────────────────────────────────────────

    def tool_start(self, tool_name: str, command: str = "", target: str = "") -> str:
        """Record starting a tool. Returns a timer ID."""
        timer_id = f"tool_{tool_name}_{uuid.uuid4().hex[:6]}"
        self._active_timers[timer_id] = time.time()

        self.record_event(
            EventType.TOOL_START,
            source=tool_name,
            title=f"Tool started: {tool_name}",
            details=command,
            data={"tool": tool_name, "command": command, "target": target},
        )
        return timer_id

    def tool_end(
        self,
        timer_id: str,
        tool_name: str,
        success: bool,
        findings: int = 0,
        summary: str = "",
    ) -> float:
        """Record tool completion. Returns duration in ms."""
        duration = 0.0
        if timer_id in self._active_timers:
            duration = (time.time() - self._active_timers.pop(timer_id)) * 1000

        self._tools_run += 1
        self._findings_count += findings

        # Track per-tool timing
        if tool_name not in self._tool_times:
            self._tool_times[tool_name] = []
        self._tool_times[tool_name].append(duration)

        self.record_event(
            EventType.TOOL_END,
            source=tool_name,
            title=f"Tool completed: {tool_name}",
            details=summary,
            data={
                "tool": tool_name,
                "success": success,
                "findings": findings,
                "duration_ms": duration,
            },
            success=success,
            duration_ms=duration,
        )
        return duration

    def tool_error(self, tool_name: str, error: str) -> None:
        """Record a tool execution error."""
        self._errors_count += 1
        self.record_event(
            EventType.TOOL_ERROR,
            source=tool_name,
            title=f"Tool error: {tool_name}",
            details=error,
            success=False,
        )

    # ── Finding Tracking ───────────────────────────────────────────

    def record_finding(
        self,
        title: str,
        severity: str,
        tool_name: str,
        confidence: float,
        details: str = "",
    ) -> None:
        """Record a new finding."""
        self._findings_count += 1
        self.record_event(
            EventType.FINDING_NEW,
            source=tool_name,
            title=f"[{severity}] {title}",
            details=details,
            data={
                "severity": severity,
                "confidence": confidence,
                "tool": tool_name,
            },
        )

    def confirm_finding(self, title: str, confidence: float, verifier: str = "") -> None:
        """Record a finding confirmation."""
        self._confirmed_count += 1
        self.record_event(
            EventType.FINDING_CONFIRMED,
            source=verifier,
            title=f"Confirmed: {title}",
            data={"confidence": confidence},
            success=True,
        )

    def mark_false_positive(self, title: str, reason: str, tool_name: str = "") -> None:
        """Record a finding marked as false positive."""
        self._fp_count += 1
        self.record_event(
            EventType.FINDING_FP,
            source=tool_name,
            title=f"FP: {title}",
            details=reason,
            success=False,
        )

    # ── Decision Tracking ──────────────────────────────────────────

    def record_decision(
        self, question: str, decision: str, reasoning: str, brain_model: str = ""
    ) -> None:
        """Record a decision made by the bot."""
        self._decisions_count += 1
        self.record_event(
            EventType.DECISION,
            source=brain_model or "decision_engine",
            title=f"Decision: {question[:60]}",
            details=f"Answer: {decision}\nReasoning: {reasoning}",
            data={
                "question": question,
                "decision": decision,
                "reasoning": reasoning,
                "brain": brain_model,
            },
        )

    # ── Brain Tracking ─────────────────────────────────────────────

    def record_brain_query(self, model: str, prompt_summary: str) -> str:
        """Record a brain query. Returns timer ID."""
        timer_id = f"brain_{uuid.uuid4().hex[:6]}"
        self._active_timers[timer_id] = time.time()

        self.record_event(
            EventType.BRAIN_QUERY,
            source=model,
            title=f"Brain query: {model}",
            details=prompt_summary[:200],
        )
        return timer_id

    def record_brain_response(
        self, timer_id: str, model: str, response_summary: str
    ) -> None:
        """Record a brain response."""
        duration = 0.0
        if timer_id in self._active_timers:
            duration = (time.time() - self._active_timers.pop(timer_id)) * 1000

        self.record_event(
            EventType.BRAIN_RESPONSE,
            source=model,
            title=f"Brain response: {model}",
            details=response_summary[:300],
            duration_ms=duration,
        )

    def record_reflection(self, reflection_text: str, action: str = "") -> None:
        """Record a self-reflection event."""
        self.record_event(
            EventType.REFLECTION,
            source="self_reflection",
            title=f"Reflection → {action}" if action else "Reflection",
            details=reflection_text,
        )

    # ── Session End ────────────────────────────────────────────────

    def end_session(self, summary: str = "") -> dict:
        """End the session and return final statistics."""
        self.end_time = time.time()
        duration = self.end_time - self.start_time

        self.record_event(
            EventType.SESSION_END,
            source="session",
            title=f"Session ended: {self.session_id}",
            details=summary,
            data=self.get_stats(),
            duration_ms=duration * 1000,
        )

        self._take_snapshot()
        return self.get_stats()

    # ── Statistics & Analysis ──────────────────────────────────────

    def get_stats(self) -> dict:
        """Get comprehensive session statistics."""
        elapsed = (self.end_time or time.time()) - self.start_time

        return {
            "session_id": self.session_id,
            "target": self.target,
            "elapsed_seconds": round(elapsed, 1),
            "elapsed_human": self._format_duration(elapsed),
            "current_stage": self._current_stage,
            "events_total": len(self._events),
            "tools_run": self._tools_run,
            "findings_total": self._findings_count,
            "findings_confirmed": self._confirmed_count,
            "findings_fp": self._fp_count,
            "decisions_made": self._decisions_count,
            "errors": self._errors_count,
            "tool_timing": self._get_tool_timing_summary(),
            "stage_durations": self._get_stage_durations(),
        }

    def get_timeline(
        self,
        event_types: list[EventType] | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[SessionEvent]:
        """Get filtered event timeline."""
        events = self._events

        if event_types:
            type_values = [t.value if isinstance(t, EventType) else t for t in event_types]
            events = [e for e in events if e.event_type in type_values]

        if since:
            events = [e for e in events if e.timestamp >= since]

        return events[-limit:]

    def get_tool_timeline(self) -> list[dict]:
        """Get a timeline of just tool executions."""
        tool_events = [
            e for e in self._events
            if e.event_type in (EventType.TOOL_START.value, EventType.TOOL_END.value, EventType.TOOL_ERROR.value)
        ]
        return [
            {
                "time": e.timestamp,
                "type": e.event_type,
                "tool": e.source,
                "title": e.title,
                "success": e.success,
                "duration_ms": e.duration_ms,
            }
            for e in tool_events
        ]

    def get_finding_timeline(self) -> list[dict]:
        """Get a timeline of findings (discovered, confirmed, FP)."""
        finding_types = {
            EventType.FINDING_NEW.value,
            EventType.FINDING_CONFIRMED.value,
            EventType.FINDING_FP.value,
        }
        return [
            {
                "time": e.timestamp,
                "type": e.event_type,
                "title": e.title,
                "source": e.source,
                "data": e.data,
            }
            for e in self._events
            if e.event_type in finding_types
        ]

    # ── Persistence ────────────────────────────────────────────────

    def save_to_file(self, output_dir: str | Path = "output/sessions") -> Path:
        """Save complete session to JSON file."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        filepath = output_path / f"session_{self.session_id}.json"

        data = {
            "session_id": self.session_id,
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "stats": self.get_stats(),
            "events": [e.model_dump() for e in self._events],
            "snapshots": [s.model_dump() for s in self._snapshots],
        }

        filepath.write_text(json.dumps(data, indent=2, default=str))
        logger.info(f"Session saved to {filepath}")
        return filepath

    @classmethod
    def load_from_file(cls, filepath: str | Path) -> SessionMemory:
        """Load a session from a saved JSON file."""
        data = json.loads(Path(filepath).read_text())

        session = cls(session_id=data["session_id"], target=data["target"])
        session.start_time = data["start_time"]
        session.end_time = data.get("end_time")
        session._events = [SessionEvent(**e) for e in data["events"]]
        session._snapshots = [SessionSnapshot(**s) for s in data.get("snapshots", [])]

        # Rebuild counters from events
        for event in session._events:
            if event.event_type == EventType.TOOL_END.value:
                session._tools_run += 1
            elif event.event_type == EventType.FINDING_NEW.value:
                session._findings_count += 1
            elif event.event_type == EventType.FINDING_CONFIRMED.value:
                session._confirmed_count += 1
            elif event.event_type == EventType.FINDING_FP.value:
                session._fp_count += 1
            elif event.event_type == EventType.ERROR.value:
                session._errors_count += 1
            elif event.event_type == EventType.DECISION.value:
                session._decisions_count += 1

        return session

    # ── Internal ───────────────────────────────────────────────────

    def _take_snapshot(self) -> None:
        """Take a point-in-time snapshot."""
        self._snapshots.append(SessionSnapshot(
            stage=self._current_stage,
            findings_count=self._findings_count,
            tools_run=self._tools_run,
            decisions_made=self._decisions_count,
            errors_count=self._errors_count,
            elapsed_seconds=time.time() - self.start_time,
        ))

    def _get_tool_timing_summary(self) -> dict:
        """Get average execution times per tool."""
        summary = {}
        for tool, times in self._tool_times.items():
            if times:
                summary[tool] = {
                    "avg_ms": round(sum(times) / len(times), 1),
                    "min_ms": round(min(times), 1),
                    "max_ms": round(max(times), 1),
                    "runs": len(times),
                }
        return summary

    def _get_stage_durations(self) -> dict:
        """Extract stage durations from events."""
        durations = {}
        for event in self._events:
            if event.event_type == EventType.STAGE_EXIT.value and event.data.get("stage"):
                durations[event.data["stage"]] = round(event.duration_ms / 1000, 1)
        return durations

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format seconds into human-readable string."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            m, s = divmod(int(seconds), 60)
            return f"{m}m {s}s"
        else:
            h, remainder = divmod(int(seconds), 3600)
            m, s = divmod(remainder, 60)
            return f"{h}h {m}m {s}s"


__all__ = ["SessionMemory", "SessionEvent", "EventType", "SessionSnapshot"]
