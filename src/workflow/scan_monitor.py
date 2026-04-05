"""WhiteHatHacker AI — Scan monitor and operator notes."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import time

from loguru import logger
from pydantic import BaseModel, Field

from src.workflow.session_manager import ScanSession, SessionManager


class ScanObservation(BaseModel):
    """A point-in-time summary of a scan session."""

    session_id: str
    target: str
    status: str
    current_stage: str = ""
    elapsed_seconds: float = 0.0
    pct_complete: float = 0.0       # V14-T3-1
    eta_label: str = ""             # V14-T3-1
    remaining_seconds: float = 0.0  # V14-T3-1
    findings_total: int = 0
    findings_verified: int = 0
    findings_fp: int = 0
    checkpoints_saved: int = 0
    last_checkpoint_at: float = 0.0
    warning_count: int = 0
    error_count: int = 0
    timeout_count: int = 0
    log_files: list[str] = Field(default_factory=list)
    latest_signals: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            f"# Scan Observation: {self.session_id}",
            "",
            f"- Target: {self.target}",
            f"- Status: {self.status}",
            f"- Current Stage: {self.current_stage or 'unknown'}",
            f"- Elapsed: {self.elapsed_seconds:.0f}s",
            f"- Progress: {self.pct_complete:.1f}% — ETA: {self.eta_label or 'unknown'}",
            f"- Findings: raw={self.findings_total}, verified={self.findings_verified}, fp={self.findings_fp}",
            f"- Checkpoints Saved: {self.checkpoints_saved}",
            f"- Log Signals: warnings={self.warning_count}, errors={self.error_count}, timeouts={self.timeout_count}",
            "",
            "## Recent Signals",
        ]
        if self.latest_signals:
            lines.extend(f"- {signal}" for signal in self.latest_signals)
        else:
            lines.append("- No notable signals captured")
        lines.extend(["", "## Recommendations"])
        if self.recommendations:
            lines.extend(f"- {item}" for item in self.recommendations)
        else:
            lines.append("- No immediate action required")
        return "\n".join(lines) + "\n"


class ScanMonitor:
    """Observes running or interrupted scans through session state and logs."""

    _SIGNAL_RE = re.compile(r"warning|error|critical|failed|timed out|traceback", re.IGNORECASE)
    _TIMEOUT_RE = re.compile(r"timed out|timeout", re.IGNORECASE)

    def __init__(
        self,
        session_manager: SessionManager | None = None,
        log_dir: str | Path = "output/logs",
    ) -> None:
        self.session_manager = session_manager or SessionManager(output_dir="output")
        self.log_dir = Path(log_dir)

    def collect_observation(
        self,
        session_id: str | None = None,
        target: str | None = None,
        tail_lines: int = 200,
    ) -> ScanObservation:
        """Collect a current observation for the selected session."""
        session = self._select_session(session_id=session_id, target=target)
        metadata = session.metadata
        recent_lines, log_files = self._collect_recent_log_lines(tail_lines=tail_lines)
        signals = self._extract_signals(recent_lines)

        # V14-T3-1: Progress estimation
        _completed = getattr(metadata, "completed_stages", None) or []
        _cur_stage_str = metadata.current_stage or ""
        try:
            _estimator = ProgressEstimator()
            _progress = _estimator.estimate(
                completed_stages=_completed,
                current_stage=_cur_stage_str,
                current_stage_elapsed=0.0,  # not tracked in session metadata
            )
        except Exception:
            _progress = {"pct_complete": 0.0, "remaining_s": 0.0, "eta_label": ""}

        observation = ScanObservation(
            session_id=metadata.session_id,
            target=metadata.target,
            status=str(metadata.status),
            current_stage=metadata.current_stage,
            elapsed_seconds=metadata.elapsed_seconds,
            pct_complete=_progress.get("pct_complete", 0.0),
            eta_label=_progress.get("eta_label", ""),
            remaining_seconds=_progress.get("remaining_s", 0.0),
            findings_total=metadata.findings_total,
            findings_verified=metadata.findings_verified,
            findings_fp=metadata.findings_fp,
            checkpoints_saved=metadata.checkpoints_saved,
            last_checkpoint_at=metadata.last_checkpoint_at,
            warning_count=sum(1 for line in recent_lines if "warning" in line.lower() and "error" not in line.lower()),
            error_count=sum(1 for line in recent_lines if re.search(r"error|critical|failed|traceback", line, re.IGNORECASE)),
            timeout_count=sum(1 for line in recent_lines if self._TIMEOUT_RE.search(line)),
            log_files=log_files,
            latest_signals=signals[:8],
            recommendations=self._build_recommendations(session, recent_lines),
        )
        return observation

    def write_observation_note(self, observation: ScanObservation) -> Path:
        """Persist an observation as a markdown note under the session directory."""
        session_dir = self.session_manager.sessions_dir / observation.session_id
        notes_dir = session_dir / "monitor_notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        note_path = notes_dir / f"observation_{ts}.md"
        note_path.write_text(observation.to_markdown(), encoding="utf-8")
        summary = (
            f"[OBSERVE {ts}] status={observation.status} stage={observation.current_stage or 'unknown'} "
            f"findings={observation.findings_total}/{observation.findings_verified} "
            f"warnings={observation.warning_count} errors={observation.error_count}"
        )
        self.session_manager.append_note(observation.session_id, summary)
        logger.info("Scan observation written | session={} | path={}", observation.session_id, note_path)
        return note_path

    def _select_session(
        self,
        session_id: str | None = None,
        target: str | None = None,
    ) -> ScanSession:
        if session_id:
            session = self.session_manager.load_session(session_id)
            if session is None:
                raise FileNotFoundError(f"Session not found: {session_id}")
            return session

        incomplete = self.session_manager.find_incomplete_sessions(target=target)
        if incomplete:
            return incomplete[0]

        if target:
            latest = self.session_manager.get_latest_session(target)
            if latest is not None:
                return latest

        sessions = self.session_manager.list_sessions(target=target)
        if not sessions:
            raise FileNotFoundError("No matching sessions found")
        session = self.session_manager.load_session(sessions[0].session_id)
        if session is None:
            raise FileNotFoundError(f"Session not found: {sessions[0].session_id}")
        return session

    def _collect_recent_log_lines(self, tail_lines: int) -> tuple[list[str], list[str]]:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        log_candidates = [
            self.log_dir / f"errors_{today}.log",
            self.log_dir / f"tools_{today}.log",
            self.log_dir / f"brain_{today}.log",
            self.log_dir / f"whai_{today}.log",
        ]
        all_lines: list[str] = []
        used_files: list[str] = []
        for path in log_candidates:
            if not path.exists():
                continue
            used_files.append(str(path))
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
                all_lines.extend(lines[-tail_lines:])
            except Exception as exc:
                logger.debug("Monitor skipped log file {}: {}", path, exc)
        return all_lines[-tail_lines:], used_files

    def _extract_signals(self, lines: list[str]) -> list[str]:
        signals: list[str] = []
        for raw_line in reversed(lines):
            if not self._SIGNAL_RE.search(raw_line):
                continue
            cleaned = raw_line.strip()
            if cleaned and cleaned not in signals:
                signals.append(cleaned[-240:])
            if len(signals) >= 8:
                break
        return signals

    def _build_recommendations(self, session: ScanSession, lines: list[str]) -> list[str]:
        meta = session.metadata
        now = time.time()
        recommendations: list[str] = []
        if meta.status in ("running", "checkpointed", "paused") and meta.last_checkpoint_at:
            since_checkpoint = now - meta.last_checkpoint_at
            if since_checkpoint >= 20 * 60:
                recommendations.append(
                    f"No checkpoint for {since_checkpoint / 60:.1f} minutes; inspect stage stall around {meta.current_stage or 'unknown'}."
                )
        if any(self._TIMEOUT_RE.search(line) for line in lines):
            recommendations.append("Timeout signals detected; inspect per-tool timeouts and retry strategy.")
        if any("brain" in line.lower() and self._SIGNAL_RE.search(line) for line in lines):
            recommendations.append("Brain-related warnings seen; verify tunnel, model availability, and prompt budget.")
        if meta.elapsed_seconds >= 20 * 60 and meta.findings_total == 0:
            recommendations.append("Long-running scan without findings; verify scope quality, auth context, and tool selection.")
        if meta.status == "failed":
            recommendations.append("Session failed; review latest errors and resume from the last checkpoint after remediation.")
        if meta.status == "completed":
            recommendations.append("Session completed; review diff report, evidence packages, and post-scan learning output.")
        if not recommendations:
            recommendations.append("Continue monitoring; no immediate regression or stall signal detected.")
        return recommendations


# ── Scan Progress Estimator (V14-T3-1) ──────────────────────────────

# Average stage durations (seconds) from profiled scans — used as fallback
# when no historical data is available.
_DEFAULT_STAGE_DURATIONS: dict[str, float] = {
    "scope_analysis": 15,
    "passive_recon": 120,
    "active_recon": 300,
    "enumeration": 240,
    "attack_surface_mapping": 30,
    "vulnerability_scan": 900,
    "fp_elimination": 180,
    "reporting": 60,
}

_STAGE_ORDER: list[str] = list(_DEFAULT_STAGE_DURATIONS.keys())


class ProgressEstimator:
    """
    Estimate scan progress and remaining time (V14-T3-1).

    Uses completed stage durations + default estimates for remaining stages.
    """

    def __init__(
        self,
        stage_durations: dict[str, float] | None = None,
    ) -> None:
        """
        Args:
            stage_durations: Historical average per-stage durations (seconds).
                Falls back to built-in defaults for missing stages.
        """
        self._stage_est = dict(_DEFAULT_STAGE_DURATIONS)
        if stage_durations:
            self._stage_est.update(stage_durations)

    def estimate(
        self,
        completed_stages: list[str],
        current_stage: str = "",
        current_stage_elapsed: float = 0.0,
        stage_results: dict[str, object] | None = None,
    ) -> dict[str, float | str]:
        """
        Calculate estimated progress and remaining time.

        Args:
            completed_stages: List of stage names already finished.
            current_stage: Stage currently executing ("" if scan idle).
            current_stage_elapsed: Seconds spent in the current stage so far.
            stage_results: Optional mapping of stage → result objects. If each
                result has a ``duration`` attribute, those are used to refine
                the estimate for completed stages.

        Returns:
            dict with keys:
                pct_complete (float): 0-100 percent complete.
                elapsed_s   (float): Total elapsed seconds.
                remaining_s (float): Estimated seconds remaining.
                eta_label   (str):   Human-readable ETA string.
        """
        done_set = {s.lower().strip() for s in completed_stages}
        total_estimated = sum(self._stage_est.get(s, 60) for s in _STAGE_ORDER)

        # Sum actual time for completed stages when available
        done_actual = 0.0
        for s in _STAGE_ORDER:
            if s not in done_set:
                continue
            actual = self._actual_duration(s, stage_results)
            done_actual += actual if actual > 0 else self._stage_est.get(s, 60)

        # Estimate remaining stages
        remaining_estimated = 0.0
        for s in _STAGE_ORDER:
            if s in done_set:
                continue
            if current_stage and s.lower() == current_stage.lower():
                # Current stage: subtract time already spent
                est = self._stage_est.get(s, 60)
                remaining_estimated += max(0.0, est - current_stage_elapsed)
                continue
            remaining_estimated += self._stage_est.get(s, 60)

        elapsed = done_actual + current_stage_elapsed
        total = elapsed + remaining_estimated
        pct = min(100.0, (elapsed / total * 100.0) if total > 0 else 0.0)

        return {
            "pct_complete": round(pct, 1),
            "elapsed_s": round(elapsed, 1),
            "remaining_s": round(remaining_estimated, 1),
            "eta_label": self._format_eta(remaining_estimated),
        }

    @staticmethod
    def _actual_duration(stage: str, stage_results: dict[str, object] | None) -> float:
        if not stage_results:
            return 0.0
        sr = stage_results.get(stage)
        if sr is None:
            return 0.0
        dur = getattr(sr, "duration", None)
        if dur is None and isinstance(sr, dict):
            dur = sr.get("duration")  # type: ignore[union-attr]
        try:
            return float(dur) if dur is not None else 0.0
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def _format_eta(seconds: float) -> str:
        if seconds <= 0:
            return "complete"
        if seconds < 60:
            return f"~{int(seconds)}s"
        if seconds < 3600:
            return f"~{int(seconds / 60)}m"
        return f"~{int(seconds / 3600)}h {int((seconds % 3600) / 60)}m"
