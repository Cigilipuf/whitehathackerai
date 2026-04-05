"""
WhiteHatHacker AI — Per-Scan Quality Report (V25 T5-3)

Generates a comprehensive quality assessment for each scan run, covering:
- Tool availability and utilisation
- Brain utilisation metrics
- FP rate estimation
- Coverage assessment
- Checker effectiveness
- 0-100 composite quality score
- Comparison with previous scan (if available)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class QualityMetrics:
    """Raw metrics collected from a scan run."""

    # Tool metrics
    total_tools_registered: int = 0
    tools_available: int = 0
    tools_executed: int = 0
    tools_succeeded: int = 0
    tools_failed: int = 0

    # Finding metrics
    raw_findings: int = 0
    after_dedup: int = 0
    after_fp: int = 0
    confirmed_findings: int = 0
    poc_verified: int = 0

    # Severity breakdown
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Brain metrics
    brain_calls_total: int = 0
    brain_calls_success: int = 0
    brain_calls_error: int = 0
    brain_cache_hits: int = 0
    brain_json_parse_ok: int = 0
    brain_json_parse_fail: int = 0

    # Coverage
    endpoints_tested: int = 0
    endpoints_total: int = 0
    hosts_scanned: int = 0
    hosts_total: int = 0

    # Timing
    total_duration_s: float = 0.0
    longest_stage: str = ""
    longest_stage_duration_s: float = 0.0

    # Checker metrics
    checkers_executed: int = 0
    checkers_with_findings: int = 0


@dataclass
class QualityScore:
    """Composite quality score with per-dimension breakdown."""

    overall: float = 0.0  # 0-100
    tool_health: float = 0.0  # 0-100
    brain_health: float = 0.0  # 0-100
    fp_quality: float = 0.0  # 0-100
    coverage: float = 0.0  # 0-100
    evidence_quality: float = 0.0  # 0-100
    dimensions: dict[str, float] = field(default_factory=dict)


@dataclass
class QualityReport:
    """Complete per-scan quality assessment."""

    scan_id: str
    target: str
    metrics: QualityMetrics
    score: QualityScore
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    comparison: dict[str, Any] | None = None  # diff vs previous scan

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)

    def to_markdown(self) -> str:
        m = self.metrics
        s = self.score
        lines = [
            "# Scan Quality Report\n",
            f"**Scan ID:** {self.scan_id}",
            f"**Target:** {self.target}",
            f"**Duration:** {m.total_duration_s:.0f}s ({m.total_duration_s / 60:.1f} min)",
            f"**Overall Quality Score:** **{s.overall:.0f}/100**\n",
            "## Score Breakdown\n",
            "| Dimension | Score |",
            "|-----------|-------|",
            f"| Tool Health | {s.tool_health:.0f}/100 |",
            f"| Brain Health | {s.brain_health:.0f}/100 |",
            f"| FP Quality | {s.fp_quality:.0f}/100 |",
            f"| Coverage | {s.coverage:.0f}/100 |",
            f"| Evidence Quality | {s.evidence_quality:.0f}/100 |",
            "",
            "## Tool Metrics\n",
            f"- Registered: {m.total_tools_registered}",
            f"- Available: {m.tools_available}",
            f"- Executed: {m.tools_executed}",
            f"- Succeeded: {m.tools_succeeded}",
            f"- Failed: {m.tools_failed}",
            "",
            "## Finding Pipeline\n",
            f"- Raw findings: {m.raw_findings}",
            f"- After dedup: {m.after_dedup}",
            f"- After FP elimination: {m.after_fp}",
            f"- Confirmed: {m.confirmed_findings}",
            f"- PoC verified: {m.poc_verified}",
            "",
            "## Severity Distribution\n",
            f"- CRITICAL: {m.critical_count}",
            f"- HIGH: {m.high_count}",
            f"- MEDIUM: {m.medium_count}",
            f"- LOW: {m.low_count}",
            f"- INFO: {m.info_count}",
            "",
            "## Brain Utilisation\n",
            f"- Total calls: {m.brain_calls_total}",
            f"- Success: {m.brain_calls_success}",
            f"- Errors: {m.brain_calls_error}",
            f"- Cache hits: {m.brain_cache_hits}",
            f"- JSON parse OK: {m.brain_json_parse_ok}",
            f"- JSON parse fail: {m.brain_json_parse_fail}",
            "",
            "## Coverage\n",
            f"- Endpoints: {m.endpoints_tested}/{m.endpoints_total}",
            f"- Hosts: {m.hosts_scanned}/{m.hosts_total}",
            f"- Checkers executed: {m.checkers_executed}",
            f"- Checkers with findings: {m.checkers_with_findings}",
        ]

        if self.warnings:
            lines.append("\n## Warnings\n")
            for w in self.warnings:
                lines.append(f"- ⚠️ {w}")

        if self.recommendations:
            lines.append("\n## Recommendations\n")
            for r in self.recommendations:
                lines.append(f"- {r}")

        if self.comparison:
            lines.append("\n## Comparison with Previous Scan\n")
            prev = self.comparison
            for key, val in prev.items():
                lines.append(f"- **{key}:** {val}")

        return "\n".join(lines)


class ScanQualityAnalyzer:
    """Analyses scan state and metadata to produce a quality report."""

    #: Weights for the composite score (must sum to 1.0)
    _WEIGHTS = {
        "tool_health": 0.20,
        "brain_health": 0.20,
        "fp_quality": 0.25,
        "coverage": 0.20,
        "evidence_quality": 0.15,
    }

    def analyze(
        self,
        scan_id: str,
        target: str,
        state_metadata: dict[str, Any],
        raw_findings_count: int,
        deduped_findings_count: int,
        final_findings: list[dict[str, Any]],
        tools_run: list[str] | None = None,
        brain_metrics: dict[str, Any] | None = None,
        previous_metrics: QualityMetrics | None = None,
    ) -> QualityReport:
        """Build a full quality report from scan state."""
        metrics = self._collect_metrics(
            state_metadata=state_metadata,
            raw_findings_count=raw_findings_count,
            deduped_findings_count=deduped_findings_count,
            final_findings=final_findings,
            tools_run=tools_run or [],
            brain_metrics=brain_metrics or {},
        )
        score = self._compute_score(metrics)
        warnings = self._detect_warnings(metrics)
        recommendations = self._generate_recommendations(metrics, score)
        comparison = self._compare(metrics, previous_metrics) if previous_metrics else None

        return QualityReport(
            scan_id=scan_id,
            target=target,
            metrics=metrics,
            score=score,
            warnings=warnings,
            recommendations=recommendations,
            comparison=comparison,
        )

    def _collect_metrics(
        self,
        state_metadata: dict[str, Any],
        raw_findings_count: int,
        deduped_findings_count: int,
        final_findings: list[dict[str, Any]],
        tools_run: list[str],
        brain_metrics: dict[str, Any],
    ) -> QualityMetrics:
        m = QualityMetrics()

        # Tool metrics
        unavailable = state_metadata.get("unavailable_tools", [])
        m.total_tools_registered = len(tools_run) + len(unavailable)
        m.tools_available = len(tools_run)
        m.tools_executed = len(tools_run)
        failed_tools = state_metadata.get("failed_tools", [])
        m.tools_failed = len(failed_tools) if isinstance(failed_tools, list) else 0
        m.tools_succeeded = max(0, m.tools_executed - m.tools_failed)

        # Finding pipeline
        m.raw_findings = raw_findings_count
        m.after_dedup = deduped_findings_count
        m.after_fp = len(final_findings)
        m.confirmed_findings = sum(
            1 for f in final_findings
            if _safe_float(f.get("confidence_score", f.get("confidence", 0))) >= 70
        )
        m.poc_verified = sum(
            1 for f in final_findings if f.get("poc_confirmed")
        )

        # Severity breakdown
        for f in final_findings:
            sev = str(f.get("severity", "")).lower()
            if sev == "critical":
                m.critical_count += 1
            elif sev == "high":
                m.high_count += 1
            elif sev == "medium":
                m.medium_count += 1
            elif sev == "low":
                m.low_count += 1
            else:
                m.info_count += 1

        # Brain metrics
        m.brain_calls_total = brain_metrics.get("total_calls", 0)
        m.brain_calls_success = brain_metrics.get("call_success", 0)
        m.brain_calls_error = brain_metrics.get("call_error", 0)
        m.brain_cache_hits = brain_metrics.get("cache_hits", 0)
        m.brain_json_parse_ok = brain_metrics.get("json_parse_first_try", 0)
        m.brain_json_parse_fail = brain_metrics.get("json_parse_fail", 0)

        # Coverage
        endpoints = state_metadata.get("endpoints", [])
        m.endpoints_total = len(endpoints) if isinstance(endpoints, list) else 0
        m.endpoints_tested = m.endpoints_total  # approximation
        live_hosts = state_metadata.get("live_hosts", [])
        m.hosts_total = len(live_hosts) if isinstance(live_hosts, list) else 0
        m.hosts_scanned = m.hosts_total

        # Timing
        m.total_duration_s = _safe_float(state_metadata.get("total_duration_s", 0))

        # Checker metrics
        stage_findings = state_metadata.get("stage_finding_counts", {})
        if isinstance(stage_findings, dict):
            m.checkers_executed = len(stage_findings)
            m.checkers_with_findings = sum(1 for v in stage_findings.values() if v)

        return m

    def _compute_score(self, m: QualityMetrics) -> QualityScore:
        s = QualityScore()

        # Tool Health: ratio of succeeded/executed, penalize unavailable
        if m.tools_executed > 0:
            success_ratio = m.tools_succeeded / m.tools_executed
            s.tool_health = min(100, success_ratio * 100)
        else:
            s.tool_health = 0

        # Brain Health: success ratio + JSON parse ratio
        if m.brain_calls_total > 0:
            brain_success = m.brain_calls_success / m.brain_calls_total
            json_total = m.brain_json_parse_ok + m.brain_json_parse_fail
            json_ratio = m.brain_json_parse_ok / json_total if json_total > 0 else 0.5
            s.brain_health = min(100, (brain_success * 60 + json_ratio * 40))
        else:
            s.brain_health = 50  # no brain = neutral

        # FP Quality: how much filtering was done successfully
        if m.raw_findings > 0:
            fp_filtering_ratio = 1 - (m.after_fp / m.raw_findings)
            # Good FP filtering = removed some noise but not everything
            if fp_filtering_ratio > 0.95:
                s.fp_quality = 60  # too aggressive
            elif fp_filtering_ratio > 0.5:
                s.fp_quality = 90  # good filtering
            elif fp_filtering_ratio > 0.2:
                s.fp_quality = 75  # moderate
            else:
                s.fp_quality = 50  # too permissive
        else:
            s.fp_quality = 50  # no findings = neutral

        # Evidence quality: PoC ratio
        if m.confirmed_findings > 0:
            poc_ratio = m.poc_verified / m.confirmed_findings
            s.evidence_quality = min(100, poc_ratio * 100)
        elif m.after_fp > 0:
            s.evidence_quality = 30  # findings but no PoC
        else:
            s.evidence_quality = 50

        # Coverage: checker utilisation
        if m.checkers_executed > 0:
            s.coverage = min(100, (m.checkers_executed / max(m.checkers_executed, 20)) * 100)
        else:
            s.coverage = 0

        # Composite
        s.dimensions = {
            "tool_health": s.tool_health,
            "brain_health": s.brain_health,
            "fp_quality": s.fp_quality,
            "coverage": s.coverage,
            "evidence_quality": s.evidence_quality,
        }
        s.overall = sum(
            score * self._WEIGHTS[dim]
            for dim, score in s.dimensions.items()
        )
        return s

    def _detect_warnings(self, m: QualityMetrics) -> list[str]:
        warnings: list[str] = []
        if m.tools_failed > 3:
            warnings.append(f"{m.tools_failed} tools failed during scan")
        if m.brain_calls_error > m.brain_calls_total * 0.3 and m.brain_calls_total > 0:
            warnings.append(
                f"Brain error rate {m.brain_calls_error}/{m.brain_calls_total} "
                f"({m.brain_calls_error / m.brain_calls_total * 100:.0f}%)"
            )
        if m.raw_findings > 0 and m.after_fp == 0:
            warnings.append("All findings eliminated by FP engine — review thresholds")
        if m.brain_json_parse_fail > m.brain_json_parse_ok and m.brain_json_parse_fail > 5:
            warnings.append("Brain JSON parse failures exceed successes")
        if m.endpoints_total == 0:
            warnings.append("No endpoints discovered — recon may have failed")
        return warnings

    def _generate_recommendations(
        self, m: QualityMetrics, s: QualityScore
    ) -> list[str]:
        recs: list[str] = []
        if s.tool_health < 60:
            recs.append("Investigate tool failures — run 'whai diagnose' to check availability")
        if s.brain_health < 50:
            recs.append("Brain utilisation is low — check SSH tunnel and model availability")
        if s.fp_quality < 50:
            recs.append("FP filtering may be too permissive — review confidence thresholds")
        if s.evidence_quality < 40 and m.confirmed_findings > 3:
            recs.append("PoC verification rate is low — increase HUNTER mode budget")
        if s.coverage < 40:
            recs.append("Low checker coverage — verify tool registry and scan profile")
        if m.poc_verified == 0 and m.confirmed_findings > 0:
            recs.append("No PoC-verified findings — enable ExploitVerifier in pipeline")
        return recs

    def _compare(
        self, current: QualityMetrics, previous: QualityMetrics
    ) -> dict[str, str]:
        diff: dict[str, str] = {}

        def _delta(label: str, cur: int | float, prev: int | float) -> None:
            d = cur - prev
            if d > 0:
                diff[label] = f"{cur} (+{d})"
            elif d < 0:
                diff[label] = f"{cur} ({d})"
            else:
                diff[label] = f"{cur} (unchanged)"

        _delta("Raw findings", current.raw_findings, previous.raw_findings)
        _delta("Confirmed findings", current.confirmed_findings, previous.confirmed_findings)
        _delta("PoC verified", current.poc_verified, previous.poc_verified)
        _delta("Tools executed", current.tools_executed, previous.tools_executed)
        _delta("Tools failed", current.tools_failed, previous.tools_failed)
        _delta("Brain errors", current.brain_calls_error, previous.brain_calls_error)
        return diff


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default
