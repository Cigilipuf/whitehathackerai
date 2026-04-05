"""
WhiteHatHacker AI — Benchmark Framework (V7-T0-1)

Scan sonuçlarından metrik çıkarma, SQLite'a kaydetme ve
benchmark karşılaştırma modülü. Bot performansının objektif
ölçülmesini sağlar.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from loguru import logger


_JSON_COLUMNS = {
    "tool_finding_counts",
    "tool_execution_counts",
    "stage_finding_counts",
    "module_impact",
}

_TRACKED_IMPACT_TOOLS = {
    "jwt_checker",
    "fourxx_bypass",
    "http_smuggling_prober",
    "graphql_deep_scanner",
    "github_secret_scanner",
    "mail_security_checker",
    "cdn_detector",
    "reverse_ip",
    "vhost_fuzzer",
    "cloud_enum",
    "metadata_extractor",
    "dynamic_wordlist",
}


# ============================================================
# Models
# ============================================================


@dataclass
class ScanBenchmark:
    """Tek bir scan çalışmasının performans metrikleri."""

    scan_id: str = ""
    target: str = ""
    timestamp: str = ""
    duration_seconds: float = 0.0

    # Coverage
    total_endpoints_tested: int = 0
    total_tools_run: int = 0
    total_payloads_sent: int = 0

    # Findings
    raw_findings: int = 0
    confirmed_findings: int = 0
    fp_rate: float = 0.0

    # Severity distribution
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # PoC
    poc_attempted: int = 0
    poc_confirmed: int = 0
    poc_success_rate: float = 0.0

    # Brain usage
    brain_calls: int = 0
    brain_avg_latency_ms: float = 0.0
    brain_cache_hits: int = 0

    # Per-tool finding counts
    tool_finding_counts: dict[str, int] = field(default_factory=dict)
    tool_execution_counts: dict[str, int] = field(default_factory=dict)
    stage_finding_counts: dict[str, int] = field(default_factory=dict)
    module_impact: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for col in _JSON_COLUMNS:
            d[col] = json.dumps(d.get(col, {}))
        return d


@dataclass
class BenchmarkDiff:
    """İki benchmark arasındaki farklar."""

    scan_id_old: str = ""
    scan_id_new: str = ""
    target: str = ""

    duration_change: float = 0.0
    endpoints_change: int = 0
    raw_findings_change: int = 0
    confirmed_change: int = 0
    fp_rate_change: float = 0.0
    poc_rate_change: float = 0.0
    brain_calls_change: int = 0

    severity_changes: dict[str, int] = field(default_factory=dict)
    tool_effectiveness_changes: dict[str, int] = field(default_factory=dict)


# ============================================================
# Schema
# ============================================================

_BENCH_SCHEMA = """
CREATE TABLE IF NOT EXISTS benchmarks (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    duration_seconds REAL DEFAULT 0.0,
    total_endpoints_tested INTEGER DEFAULT 0,
    total_tools_run INTEGER DEFAULT 0,
    total_payloads_sent INTEGER DEFAULT 0,
    raw_findings INTEGER DEFAULT 0,
    confirmed_findings INTEGER DEFAULT 0,
    fp_rate REAL DEFAULT 0.0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    poc_attempted INTEGER DEFAULT 0,
    poc_confirmed INTEGER DEFAULT 0,
    poc_success_rate REAL DEFAULT 0.0,
    brain_calls INTEGER DEFAULT 0,
    brain_avg_latency_ms REAL DEFAULT 0.0,
    brain_cache_hits INTEGER DEFAULT 0,
    tool_finding_counts TEXT DEFAULT '{}',
    tool_execution_counts TEXT DEFAULT '{}',
    stage_finding_counts TEXT DEFAULT '{}',
    module_impact TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_bench_target ON benchmarks(target);
CREATE INDEX IF NOT EXISTS idx_bench_ts ON benchmarks(timestamp);
"""

# ============================================================
# Metric Collector
# ============================================================


def collect_scan_metrics(
    scan_id: str,
    target: str,
    started_at: float,
    finished_at: float,
    raw_findings: list[Any],
    confirmed_findings: list[Any],
    tool_runs: list[dict[str, Any]] | None = None,
    poc_results: dict[str, Any] | None = None,
    brain_stats: dict[str, Any] | None = None,
) -> ScanBenchmark:
    """
    Scan sonuçlarından ScanBenchmark metrikleri çıkar.

    Args:
        scan_id: Benzersiz scan kimliği
        target: Hedef domain/IP
        started_at: Başlangıç epoch
        finished_at: Bitiş epoch
        raw_findings: FP filtresi öncesi tüm bulgular
        confirmed_findings: FP filtresi sonrası doğrulanmış bulgular
        tool_runs: Araç çalıştırma kayıtları
        poc_results: PoC denemelerinin sonuçları
        brain_stats: Brain engine istatistikleri
    """
    tool_runs = tool_runs or []
    poc_results = poc_results or {}
    brain_stats = brain_stats or {}

    # Severity dağılımı
    sev_counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    for f in confirmed_findings:
        sev = _get_severity(f)
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Araç başına bulgu sayısı
    tool_counts: dict[str, int] = {}
    for f in confirmed_findings:
        tool = _get_tool_name(f)
        if tool:
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

    # FP rate
    raw_count = len(raw_findings)
    confirmed_count = len(confirmed_findings)
    fp_rate = ((raw_count - confirmed_count) / raw_count * 100.0) if raw_count > 0 else 0.0

    # PoC
    poc_attempted = poc_results.get("attempted", 0)
    poc_confirmed = poc_results.get("confirmed", 0)
    poc_success = (poc_confirmed / poc_attempted * 100.0) if poc_attempted > 0 else 0.0

    # Endpoint sayısı (confirmed bulguların benzersiz endpoint'leri)
    endpoints = set()
    for f in confirmed_findings:
        ep = _get_endpoint(f)
        if ep:
            endpoints.add(ep)

    return ScanBenchmark(
        scan_id=scan_id,
        target=target,
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        duration_seconds=round(finished_at - started_at, 2),
        total_endpoints_tested=len(endpoints),
        total_tools_run=len(tool_runs),
        total_payloads_sent=brain_stats.get("total_payloads", 0),
        raw_findings=raw_count,
        confirmed_findings=confirmed_count,
        fp_rate=round(fp_rate, 2),
        critical_count=sev_counts["critical"],
        high_count=sev_counts["high"],
        medium_count=sev_counts["medium"],
        low_count=sev_counts["low"],
        info_count=sev_counts["info"],
        poc_attempted=poc_attempted,
        poc_confirmed=poc_confirmed,
        poc_success_rate=round(poc_success, 2),
        brain_calls=brain_stats.get("total_calls", 0),
        brain_avg_latency_ms=brain_stats.get("avg_latency_ms", 0.0),
        brain_cache_hits=brain_stats.get("cache_hits", 0),
        tool_finding_counts=tool_counts,
    )


# ============================================================
# Storage
# ============================================================


class BenchmarkStore:
    """SQLite-backed benchmark depolama ve karşılaştırma motoru."""

    def __init__(self, db_path: str | Path = "output/benchmarks.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_BENCH_SCHEMA)
            self._migrate_schema(conn)
        logger.debug(f"Benchmark DB initialized: {self.db_path}")

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        existing_cols = {
            row[1] for row in conn.execute("PRAGMA table_info(benchmarks)").fetchall()
        }
        for col in sorted(_JSON_COLUMNS - existing_cols):
            conn.execute(f"ALTER TABLE benchmarks ADD COLUMN {col} TEXT DEFAULT '{{}}'")

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # --------- Write ---------

    def save(self, bm: ScanBenchmark) -> None:
        """Benchmark kaydet (upsert)."""
        d = bm.to_dict()
        cols = ", ".join(d.keys())
        placeholders = ", ".join("?" for _ in d)
        with self._conn() as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO benchmarks ({cols}) VALUES ({placeholders})",
                tuple(d.values()),
            )
        logger.info(f"Benchmark saved: {bm.scan_id} ({bm.target})")

    # --------- Read ---------

    def get(self, scan_id: str) -> ScanBenchmark | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM benchmarks WHERE scan_id = ?", (scan_id,),
            ).fetchone()
            return _row_to_benchmark(row) if row else None

    def list_all(self, target: str | None = None, limit: int = 50) -> list[ScanBenchmark]:
        with self._conn() as conn:
            if target:
                rows = conn.execute(
                    "SELECT * FROM benchmarks WHERE target = ? ORDER BY timestamp DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM benchmarks ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [_row_to_benchmark(r) for r in rows]

    def get_latest(self, target: str) -> ScanBenchmark | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM benchmarks WHERE target = ? ORDER BY timestamp DESC LIMIT 1",
                (target,),
            ).fetchone()
            return _row_to_benchmark(row) if row else None

    # --------- Compare ---------

    def compare(self, scan_id_old: str, scan_id_new: str) -> BenchmarkDiff | None:
        """İki benchmark karşılaştır."""
        old = self.get(scan_id_old)
        new = self.get(scan_id_new)
        if not old or not new:
            logger.warning(f"Cannot compare: {'old missing' if not old else 'new missing'}")
            return None
        return _compute_diff(old, new)

    # --------- Report ---------

    def generate_report(
        self,
        target: str | None = None,
        limit: int = 10,
    ) -> str:
        """Markdown benchmark raporu oluştur."""
        benchmarks = self.list_all(target=target, limit=limit)
        if not benchmarks:
            return "No benchmarks found."

        lines = [
            "# Benchmark Report",
            "",
            f"**Generated:** {datetime.now(tz=timezone.utc).isoformat()}",
            f"**Total scans:** {len(benchmarks)}",
            "",
            "| Scan ID | Target | Duration | Raw | Confirmed | FP% | PoC% | Critical | High |",
            "|---------|--------|----------|-----|-----------|-----|------|----------|------|",
        ]

        for bm in benchmarks:
            lines.append(
                f"| {bm.scan_id[:12]} | {bm.target} | {bm.duration_seconds:.0f}s "
                f"| {bm.raw_findings} | {bm.confirmed_findings} | {bm.fp_rate:.1f}% "
                f"| {bm.poc_success_rate:.1f}% | {bm.critical_count} | {bm.high_count} |"
            )

        # Trend analizi (en son 2 scan varsa)
        if len(benchmarks) >= 2:
            diff = _compute_diff(benchmarks[1], benchmarks[0])  # old, new
            lines.extend([
                "",
                "## Latest Trend",
                "",
                f"- Duration: {_trend_str(diff.duration_change)}s",
                f"- Confirmed findings: {_trend_str(diff.confirmed_change, reverse=True)}",
                f"- FP rate: {_trend_str(diff.fp_rate_change)}%",
                f"- PoC success: {_trend_str(diff.poc_rate_change, reverse=True)}%",
            ])

        latest = benchmarks[0]
        if latest.module_impact:
            top_impact = sorted(
                latest.module_impact.items(),
                key=lambda item: item[1],
                reverse=True,
            )[:8]
            lines.extend([
                "",
                "## Latest High-Value Module Impact",
                "",
            ])
            for tool_name, count in top_impact:
                lines.append(f"- {tool_name}: {count} finding(s)")

        return "\n".join(lines)


# ============================================================
# Helpers
# ============================================================


def _get_severity(finding: Any) -> str:
    if hasattr(finding, "severity"):
        return str(finding.severity).lower()
    if isinstance(finding, dict):
        return str(finding.get("severity", "info")).lower()
    return "info"


def _get_tool_name(finding: Any) -> str:
    if hasattr(finding, "tool_name"):
        return finding.tool_name
    if isinstance(finding, dict):
        return finding.get("tool_name", finding.get("tool", ""))
    return ""


def _get_endpoint(finding: Any) -> str:
    if hasattr(finding, "endpoint"):
        return finding.endpoint
    if isinstance(finding, dict):
        return finding.get("endpoint", "")
    return ""


def _row_to_benchmark(row: sqlite3.Row) -> ScanBenchmark:
    d = dict(row)
    for col in _JSON_COLUMNS:
        raw_value = d.pop(col, "{}")
        try:
            d[col] = json.loads(raw_value) if isinstance(raw_value, str) else (raw_value or {})
        except (json.JSONDecodeError, TypeError):
            d[col] = {}
    return ScanBenchmark(**d)


def build_stage_finding_counts(stage_results: dict[str, Any] | None) -> dict[str, int]:
    """Extract per-stage finding counts from workflow stage results."""
    stage_results = stage_results or {}
    counts: dict[str, int] = {}
    for stage_name, stage_result in stage_results.items():
        finding_count = int(getattr(stage_result, "findings_count", 0) or 0)
        counts[str(stage_name)] = finding_count
    return counts


def build_tool_execution_counts(tools_run: list[str] | None) -> dict[str, int]:
    """Normalize tool execution history to a count map."""
    counts: dict[str, int] = {}
    for tool_name in tools_run or []:
        counts[str(tool_name)] = counts.get(str(tool_name), 0) + 1
    return counts


def build_module_impact(
    tool_finding_counts: dict[str, int] | None,
    tools_run: list[str] | None = None,
    *,
    tracked_tools: set[str] | None = None,
) -> dict[str, int]:
    """Summarize contribution of strategically important modules.

    Includes executed tracked tools even when they produced zero findings,
    so scan-to-scan comparisons show both coverage and contribution.
    """
    tool_finding_counts = tool_finding_counts or {}
    tracked = tracked_tools or _TRACKED_IMPACT_TOOLS
    executed = set(tools_run or [])
    relevant_tools = sorted(tracked | (executed & tracked))
    impact: dict[str, int] = {}
    for tool_name in relevant_tools:
        if tool_name in executed or tool_name in tool_finding_counts:
            impact[tool_name] = int(tool_finding_counts.get(tool_name, 0) or 0)
    return impact


def _compute_diff(old: ScanBenchmark, new: ScanBenchmark) -> BenchmarkDiff:
    sev_changes = {
        "critical": new.critical_count - old.critical_count,
        "high": new.high_count - old.high_count,
        "medium": new.medium_count - old.medium_count,
        "low": new.low_count - old.low_count,
    }

    all_tools = set(old.tool_finding_counts) | set(new.tool_finding_counts)
    tool_changes = {
        t: new.tool_finding_counts.get(t, 0) - old.tool_finding_counts.get(t, 0)
        for t in all_tools
    }

    return BenchmarkDiff(
        scan_id_old=old.scan_id,
        scan_id_new=new.scan_id,
        target=new.target,
        duration_change=round(new.duration_seconds - old.duration_seconds, 2),
        endpoints_change=new.total_endpoints_tested - old.total_endpoints_tested,
        raw_findings_change=new.raw_findings - old.raw_findings,
        confirmed_change=new.confirmed_findings - old.confirmed_findings,
        fp_rate_change=round(new.fp_rate - old.fp_rate, 2),
        poc_rate_change=round(new.poc_success_rate - old.poc_success_rate, 2),
        brain_calls_change=new.brain_calls - old.brain_calls,
        severity_changes=sev_changes,
        tool_effectiveness_changes=tool_changes,
    )


def _trend_str(value: float, reverse: bool = False) -> str:
    """Artış/azalış göstergesi. reverse=True ise artış iyi."""
    if value > 0:
        arrow = "↗️" if reverse else "↗️"
        return f"+{value} {arrow}"
    if value < 0:
        return f"{value} ↘️"
    return "0 →"
