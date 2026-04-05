"""
WhiteHatHacker AI — Evidence Timeline

Tarama süresince tüm olayların kronolojik kaydı.
Her aşama, araç çalıştırma ve bulgu bir timeline event'idir.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel


class TimelineEvent(BaseModel):
    """Timeline'daki tek bir olay."""

    timestamp: float = 0.0
    event_type: str = ""  # stage_start, stage_end, tool_run, finding, decision, error
    stage: str = ""
    tool_name: str = ""
    description: str = ""
    details: dict[str, Any] = {}
    severity: str = ""  # info, warning, critical
    duration_ms: float = 0.0


class Timeline:
    """
    Kronolojik olay kaydı.

    Tarama sürecinin her adımını kaydeder.
    Rapor ve debug için kullanılır.
    """

    def __init__(self, session_id: str = "") -> None:
        self.session_id = session_id or f"tl_{int(time.time())}"
        self.events: list[TimelineEvent] = []
        self.start_time = time.time()

    def add(
        self,
        event_type: str,
        description: str,
        stage: str = "",
        tool_name: str = "",
        severity: str = "info",
        details: dict[str, Any] | None = None,
        duration_ms: float = 0.0,
    ) -> TimelineEvent:
        """Olay ekle."""
        event = TimelineEvent(
            timestamp=time.time(),
            event_type=event_type,
            stage=stage,
            tool_name=tool_name,
            description=description,
            details=details or {},
            severity=severity,
            duration_ms=duration_ms,
        )
        self.events.append(event)
        return event

    def stage_start(self, stage: str) -> None:
        self.add("stage_start", f"Stage started: {stage}", stage=stage)

    def stage_end(self, stage: str, duration_ms: float = 0.0) -> None:
        self.add("stage_end", f"Stage completed: {stage}", stage=stage, duration_ms=duration_ms)

    def tool_run(self, tool_name: str, stage: str = "", details: dict | None = None) -> None:
        self.add("tool_run", f"Tool executed: {tool_name}", stage=stage, tool_name=tool_name, details=details or {})

    def finding(self, title: str, severity: str = "info", details: dict | None = None) -> None:
        self.add("finding", title, severity=severity, details=details or {})

    def error(self, description: str, details: dict | None = None) -> None:
        self.add("error", description, severity="critical", details=details or {})

    def to_markdown(self) -> str:
        """Markdown timeline oluştur."""
        lines = [
            f"# Scan Timeline — {self.session_id}",
            f"**Started:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(self.start_time))}",
            f"**Events:** {len(self.events)}",
            "",
        ]

        for event in self.events:
            ts = time.strftime("%H:%M:%S", time.gmtime(event.timestamp))
            elapsed = event.timestamp - self.start_time

            icon = {
                "stage_start": "🔵",
                "stage_end": "✅",
                "tool_run": "🔧",
                "finding": "🔴" if event.severity == "critical" else "🟡",
                "decision": "🧠",
                "error": "❌",
            }.get(event.event_type, "▪️")

            line = f"- `{ts}` (+{elapsed:.0f}s) {icon} {event.description}"
            if event.duration_ms > 0:
                line += f" ({event.duration_ms:.0f}ms)"
            lines.append(line)

        return "\n".join(lines)

    def save(self, output_dir: str = "output/evidence") -> str:
        """Timeline'ı kaydet."""
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)

        # JSON
        json_path = path / f"{self.session_id}_timeline.json"
        data = {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "total_events": len(self.events),
            "events": [e.model_dump() for e in self.events],
        }
        json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

        # Markdown
        md_path = path / f"{self.session_id}_timeline.md"
        md_path.write_text(self.to_markdown(), encoding="utf-8")

        logger.info(f"Timeline saved | events={len(self.events)} | path={json_path}")
        return str(json_path)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time


__all__ = ["Timeline", "TimelineEvent"]
