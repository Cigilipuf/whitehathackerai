"""
WhiteHatHacker AI — Scan Performance Profiler (P6-5)

Per-stage and per-tool timing instrumentation plus bottleneck detection.
Provides:
- StageTimer context manager for accurate stage duration tracking
- ToolTimer for individual tool execution profiling
- PerformanceReport with bottleneck analysis and recommendations
- Integration hooks for full_scan.py pipeline stages
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from loguru import logger


@dataclass
class ToolTiming:
    """Timing record for a single tool execution."""
    tool_name: str
    duration_s: float
    success: bool
    findings_count: int = 0
    error: str = ""


@dataclass
class StageTiming:
    """Timing record for a pipeline stage."""
    stage_name: str
    start_time: float = 0.0
    end_time: float = 0.0
    duration_s: float = 0.0
    tools_run: list[ToolTiming] = field(default_factory=list)
    findings_produced: int = 0
    error: str = ""

    @property
    def tool_count(self) -> int:
        return len(self.tools_run)

    @property
    def slowest_tool(self) -> ToolTiming | None:
        if not self.tools_run:
            return None
        return max(self.tools_run, key=lambda t: t.duration_s)


@dataclass
class Bottleneck:
    """An identified performance bottleneck."""
    category: str       # "stage", "tool", "brain", "timeout"
    name: str           # stage or tool name
    duration_s: float
    pct_of_total: float  # percentage of total scan time
    recommendation: str


@dataclass
class PerformanceReport:
    """Complete scan performance analysis."""
    total_duration_s: float
    stage_timings: list[StageTiming]
    bottlenecks: list[Bottleneck]
    tool_effectiveness: dict[str, dict[str, Any]]  # tool → {duration, findings, rate}
    recommendations: list[str]

    def to_markdown(self) -> str:
        """Generate a markdown performance report."""
        lines = ["# Scan Performance Report\n"]
        lines.append(f"**Total Duration:** {self.total_duration_s:.1f}s "
                      f"({self.total_duration_s / 60:.1f} min)\n")

        # Stage breakdown
        lines.append("## Stage Timings\n")
        lines.append("| Stage | Duration | Tools | Findings | Slowest Tool |")
        lines.append("|-------|----------|-------|----------|--------------|")
        for st in sorted(self.stage_timings, key=lambda x: x.duration_s, reverse=True):
            slowest = st.slowest_tool
            slowest_str = f"{slowest.tool_name} ({slowest.duration_s:.1f}s)" if slowest else "-"
            lines.append(
                f"| {st.stage_name} | {st.duration_s:.1f}s | {st.tool_count} | "
                f"{st.findings_produced} | {slowest_str} |"
            )

        # Bottlenecks
        if self.bottlenecks:
            lines.append("\n## Bottlenecks\n")
            for b in self.bottlenecks:
                lines.append(
                    f"- **{b.category.upper()}: {b.name}** — {b.duration_s:.1f}s "
                    f"({b.pct_of_total:.1f}% of total). {b.recommendation}"
                )

        # Tool effectiveness
        if self.tool_effectiveness:
            lines.append("\n## Tool Effectiveness\n")
            lines.append("| Tool | Duration | Findings | Rate (f/min) | Status |")
            lines.append("|------|----------|----------|-------------|--------|")
            for tool, data in sorted(
                self.tool_effectiveness.items(),
                key=lambda x: x[1].get("findings", 0),
                reverse=True,
            ):
                rate = data.get("findings_per_min", 0)
                status = "productive" if data["findings"] > 0 else "dead weight"
                emoji = "✅" if data["findings"] > 0 else "⚠️"
                lines.append(
                    f"| {tool} | {data['duration']:.1f}s | {data['findings']} | "
                    f"{rate:.2f} | {emoji} {status} |"
                )

        # Recommendations
        if self.recommendations:
            lines.append("\n## Recommendations\n")
            for r in self.recommendations:
                lines.append(f"- {r}")

        return "\n".join(lines)


class ScanProfiler:
    """
    Instruments a scan pipeline for performance analysis.

    Usage:
        profiler = ScanProfiler()
        with profiler.stage("passive_recon"):
            profiler.record_tool("subfinder", 12.3, True, findings_count=5)
            profiler.record_tool("amass", 45.0, True, findings_count=12)
        report = profiler.generate_report()
    """

    def __init__(self) -> None:
        self._stages: list[StageTiming] = []
        self._current_stage: StageTiming | None = None
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0
        self._tool_aggregate: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"total_duration": 0.0, "runs": 0, "findings": 0, "errors": 0}
        )

    def start_scan(self) -> None:
        """Mark scan start time."""
        self._scan_start = time.monotonic()

    def end_scan(self) -> None:
        """Mark scan end time."""
        self._scan_end = time.monotonic()

    class _StageContext:
        """Context manager for stage timing."""

        def __init__(self, profiler: ScanProfiler, stage_name: str):
            self._profiler = profiler
            self._stage = StageTiming(stage_name=stage_name)

        def __enter__(self):
            self._stage.start_time = time.monotonic()
            self._profiler._current_stage = self._stage
            return self._stage

        def __exit__(self, exc_type, exc_val, exc_tb):
            self._stage.end_time = time.monotonic()
            self._stage.duration_s = self._stage.end_time - self._stage.start_time
            if exc_type:
                self._stage.error = str(exc_val)
            self._profiler._stages.append(self._stage)
            self._profiler._current_stage = None
            return False  # don't suppress exceptions

    def stage(self, name: str) -> _StageContext:
        """Context manager that times a pipeline stage."""
        return self._StageContext(self, name)

    def record_stage(
        self,
        name: str,
        duration_s: float,
        findings_count: int = 0,
    ) -> None:
        """Record a stage timing directly (for non-context-manager usage)."""
        st = StageTiming(
            stage_name=name,
            duration_s=duration_s,
            findings_produced=findings_count,
        )
        self._stages.append(st)

    def record_tool(
        self,
        tool_name: str,
        duration_s: float,
        success: bool,
        findings_count: int = 0,
        error: str = "",
    ) -> None:
        """Record a tool execution timing."""
        tt = ToolTiming(
            tool_name=tool_name,
            duration_s=duration_s,
            success=success,
            findings_count=findings_count,
            error=error,
        )
        # Attach to current stage if active
        if self._current_stage is not None:
            self._current_stage.tools_run.append(tt)
            self._current_stage.findings_produced += findings_count

        # Aggregate
        agg = self._tool_aggregate[tool_name]
        agg["total_duration"] += duration_s
        agg["runs"] += 1
        agg["findings"] += findings_count
        if not success:
            agg["errors"] += 1

    def generate_report(self) -> PerformanceReport:
        """Analyse collected timings and produce a performance report."""
        total = self._scan_end - self._scan_start if self._scan_end else sum(
            s.duration_s for s in self._stages
        )
        _no_timing_data = total <= 0
        if _no_timing_data:
            total = 0.001  # sentinel — report will show ~0s, percentages meaningless

        # Build tool effectiveness
        tool_eff: dict[str, dict[str, Any]] = {}
        for tool, agg in self._tool_aggregate.items():
            dur = agg["total_duration"]
            findings = agg["findings"]
            rate = (findings / dur * 60) if dur > 0 else 0.0
            tool_eff[tool] = {
                "duration": dur,
                "findings": findings,
                "runs": agg["runs"],
                "errors": agg["errors"],
                "findings_per_min": round(rate, 2),
            }

        # Detect bottlenecks
        bottlenecks = self._detect_bottlenecks(total)

        # Generate recommendations
        recommendations = self._generate_recommendations(total, tool_eff)

        return PerformanceReport(
            total_duration_s=total,
            stage_timings=list(self._stages),
            bottlenecks=bottlenecks,
            tool_effectiveness=tool_eff,
            recommendations=recommendations,
        )

    def _detect_bottlenecks(self, total: float) -> list[Bottleneck]:
        """Identify stages and tools consuming disproportionate time."""
        bottlenecks: list[Bottleneck] = []

        # Stage bottlenecks (>30% of total scan time)
        for st in self._stages:
            pct = (st.duration_s / total) * 100
            if pct > 30 and st.duration_s > 60:
                bottlenecks.append(Bottleneck(
                    category="stage",
                    name=st.stage_name,
                    duration_s=st.duration_s,
                    pct_of_total=pct,
                    recommendation=f"Consider parallelising or setting tighter timeouts for {st.stage_name}.",
                ))

        # Tool bottlenecks (>15% of total, or >120s with 0 findings)
        for tool, agg in self._tool_aggregate.items():
            dur = agg["total_duration"]
            pct = (dur / total) * 100
            if pct > 15 and dur > 60:
                bottlenecks.append(Bottleneck(
                    category="tool",
                    name=tool,
                    duration_s=dur,
                    pct_of_total=pct,
                    recommendation=f"Reduce timeout or skip {tool} if not productive.",
                ))
            elif dur > 120 and agg["findings"] == 0:
                bottlenecks.append(Bottleneck(
                    category="tool",
                    name=tool,
                    duration_s=dur,
                    pct_of_total=pct,
                    recommendation=f"{tool} took {dur:.0f}s with 0 findings — consider skipping for this target.",
                ))

        # Timeout bottlenecks (tools that errored)
        for tool, agg in self._tool_aggregate.items():
            if agg["errors"] > 0 and agg["errors"] >= agg["runs"]:
                bottlenecks.append(Bottleneck(
                    category="timeout",
                    name=tool,
                    duration_s=agg["total_duration"],
                    pct_of_total=(agg["total_duration"] / total) * 100,
                    recommendation=f"{tool} failed every run ({agg['errors']}/{agg['runs']}). Check if it's installed and configured.",
                ))

        return sorted(bottlenecks, key=lambda b: b.duration_s, reverse=True)

    def _generate_recommendations(
        self, total: float, tool_eff: dict[str, dict[str, Any]]
    ) -> list[str]:
        """Generate actionable recommendations from timing data."""
        recs: list[str] = []

        # Dead weight tools
        dead_tools = [
            t for t, d in tool_eff.items()
            if d["findings"] == 0 and d["duration"] > 30
        ]
        if dead_tools:
            total_waste = sum(tool_eff[t]["duration"] for t in dead_tools)
            recs.append(
                f"{len(dead_tools)} tools produced 0 findings but consumed "
                f"{total_waste:.0f}s ({total_waste / total * 100:.1f}%): "
                f"{', '.join(dead_tools[:5])}{'...' if len(dead_tools) > 5 else ''}"
            )

        # Productive tools
        productive = sorted(
            [(t, d) for t, d in tool_eff.items() if d["findings"] > 0],
            key=lambda x: x[1]["findings"],
            reverse=True,
        )
        if productive:
            top = productive[0]
            recs.append(
                f"Most productive tool: {top[0]} ({top[1]['findings']} findings "
                f"in {top[1]['duration']:.1f}s)"
            )

        # Long stages with few findings
        for st in self._stages:
            if st.duration_s > 300 and st.findings_produced == 0:
                recs.append(
                    f"Stage '{st.stage_name}' took {st.duration_s:.0f}s but produced "
                    f"0 findings. Consider reducing its timeout."
                )

        return recs

    def to_dict(self) -> dict[str, Any]:
        """Serialize profiler data for persistence."""
        return {
            "total_duration_s": self._scan_end - self._scan_start if self._scan_end else 0,
            "stages": [
                {
                    "name": s.stage_name,
                    "duration_s": round(s.duration_s, 2),
                    "tools": [
                        {
                            "name": t.tool_name,
                            "duration_s": round(t.duration_s, 2),
                            "success": t.success,
                            "findings": t.findings_count,
                        }
                        for t in s.tools_run
                    ],
                    "findings": s.findings_produced,
                    "error": s.error,
                }
                for s in self._stages
            ],
            "tool_aggregate": dict(self._tool_aggregate),
        }
