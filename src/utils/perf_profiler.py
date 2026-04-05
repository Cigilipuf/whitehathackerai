"""
WhiteHatHacker AI — Performance Profiler (T4-4)

Aggregates timing telemetry from tool executor, orchestrator stages,
and brain calls. Detects bottlenecks and persists a scan-wide
performance report to output/scans/<id>/performance.json.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loguru import logger


@dataclass
class ToolTiming:
    """Timing data for a single tool execution."""
    name: str
    duration: float
    stage: str = ""
    success: bool = True


@dataclass
class StageTiming:
    """Timing data for a workflow stage."""
    name: str
    duration: float
    findings_produced: int = 0
    tools_count: int = 0
    skipped: bool = False


@dataclass
class BrainTiming:
    """Timing data for a single brain call."""
    task: str
    duration: float
    model: str = "primary"
    tokens_approx: int = 0


class PerfProfiler:
    """Scan-wide performance profiler — aggregates timing from all subsystems."""

    def __init__(self) -> None:
        self._tool_timings: list[ToolTiming] = []
        self._stage_timings: list[StageTiming] = []
        self._brain_timings: list[BrainTiming] = []
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0
        self._bottleneck_threshold: float = 2.0  # flag if >2x avg for that category

    def start(self) -> None:
        self._scan_start = time.monotonic()

    def stop(self) -> None:
        self._scan_end = time.monotonic()

    def record_tool(self, name: str, duration: float, stage: str = "", success: bool = True) -> None:
        self._tool_timings.append(ToolTiming(name=name, duration=duration, stage=stage, success=success))

    def record_stage(self, name: str, duration: float, findings: int = 0, tools: int = 0, skipped: bool = False) -> None:
        self._stage_timings.append(StageTiming(name=name, duration=duration, findings_produced=findings, tools_count=tools, skipped=skipped))

    def record_brain(self, task: str, duration: float, model: str = "primary", tokens: int = 0) -> None:
        self._brain_timings.append(BrainTiming(task=task, duration=duration, model=model, tokens_approx=tokens))

    @property
    def total_scan_time(self) -> float:
        if self._scan_end and self._scan_start:
            return self._scan_end - self._scan_start
        return 0.0

    def _detect_bottlenecks(self) -> list[dict[str, Any]]:
        """Flag tools/stages that took significantly longer than average."""
        bottlenecks: list[dict[str, Any]] = []

        # Tool bottlenecks
        if self._tool_timings:
            avg_tool = sum(t.duration for t in self._tool_timings) / len(self._tool_timings)
            threshold = max(avg_tool * self._bottleneck_threshold, 30.0)  # at least 30s
            for t in self._tool_timings:
                if t.duration > threshold:
                    bottlenecks.append({
                        "type": "tool",
                        "name": t.name,
                        "duration": round(t.duration, 1),
                        "avg": round(avg_tool, 1),
                        "ratio": round(t.duration / avg_tool, 1) if avg_tool > 0 else 0,
                    })

        # Stage bottlenecks
        active_stages = [s for s in self._stage_timings if not s.skipped and s.duration > 0]
        if active_stages:
            avg_stage = sum(s.duration for s in active_stages) / len(active_stages)
            threshold = max(avg_stage * self._bottleneck_threshold, 60.0)
            for s in active_stages:
                if s.duration > threshold:
                    bottlenecks.append({
                        "type": "stage",
                        "name": s.name,
                        "duration": round(s.duration, 1),
                        "avg": round(avg_stage, 1),
                        "ratio": round(s.duration / avg_stage, 1) if avg_stage > 0 else 0,
                    })

        return bottlenecks

    def report(self) -> dict[str, Any]:
        """Generate a full performance report."""
        total = self.total_scan_time
        total_tool_time = sum(t.duration for t in self._tool_timings)
        total_brain_time = sum(b.duration for b in self._brain_timings)

        # Per-tool aggregation
        tool_agg: dict[str, dict] = {}
        for t in self._tool_timings:
            if t.name not in tool_agg:
                tool_agg[t.name] = {"runs": 0, "total_s": 0.0, "max_s": 0.0, "failures": 0}
            tool_agg[t.name]["runs"] += 1
            tool_agg[t.name]["total_s"] = round(tool_agg[t.name]["total_s"] + t.duration, 2)
            tool_agg[t.name]["max_s"] = round(max(tool_agg[t.name]["max_s"], t.duration), 2)
            if not t.success:
                tool_agg[t.name]["failures"] += 1
        # Add avg
        for v in tool_agg.values():
            v["avg_s"] = round(v["total_s"] / v["runs"], 2) if v["runs"] else 0

        # Per-stage summary
        stage_summary = [
            {
                "name": s.name,
                "duration_s": round(s.duration, 1),
                "findings": s.findings_produced,
                "tools": s.tools_count,
                "skipped": s.skipped,
            }
            for s in self._stage_timings
        ]

        # Brain summary
        brain_summary = {
            "total_calls": len(self._brain_timings),
            "total_time_s": round(total_brain_time, 1),
            "avg_call_s": round(total_brain_time / len(self._brain_timings), 2) if self._brain_timings else 0,
            "pct_of_scan": round(total_brain_time / total * 100, 1) if total > 0 else 0,
        }

        bottlenecks = self._detect_bottlenecks()

        return {
            "scan_total_s": round(total, 1),
            "tool_time_s": round(total_tool_time, 1),
            "brain_time_s": round(total_brain_time, 1),
            "overhead_s": round(max(0, total - total_tool_time - total_brain_time), 1),
            "tools": tool_agg,
            "stages": stage_summary,
            "brain": brain_summary,
            "bottlenecks": bottlenecks,
            "tool_count": len(self._tool_timings),
            "stage_count": len(self._stage_timings),
        }

    def save(self, output_dir: str | Path) -> Path | None:
        """Persist performance report to JSON."""
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        out_file = path / "performance.json"
        try:
            data = self.report()
            out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            logger.info(f"Performance report saved: {out_file}")
            return out_file
        except Exception as exc:
            logger.debug(f"Failed to save perf report: {exc}")
            return None

    def log_summary(self) -> None:
        """Log a concise performance summary."""
        r = self.report()
        lines = [
            f"Total scan: {r['scan_total_s']}s | "
            f"Tool time: {r['tool_time_s']}s | "
            f"Brain time: {r['brain_time_s']}s | "
            f"Overhead: {r['overhead_s']}s"
        ]
        if r["bottlenecks"]:
            bn_strs = [f"{b['name']}({b['duration']}s, {b['ratio']}x avg)" for b in r["bottlenecks"][:5]]
            lines.append(f"Bottlenecks: {', '.join(bn_strs)}")

        # Top 5 slowest tools
        sorted_tools = sorted(r["tools"].items(), key=lambda x: x[1]["total_s"], reverse=True)[:5]
        if sorted_tools:
            top = [f"{name}={v['total_s']}s" for name, v in sorted_tools]
            lines.append(f"Top tools: {', '.join(top)}")

        logger.info("PERFORMANCE SUMMARY:\n  " + "\n  ".join(lines))


__all__ = ["PerfProfiler", "ToolTiming", "StageTiming", "BrainTiming"]
