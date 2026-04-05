"""
WhiteHatHacker AI — Scan Session Manager

Manages the entire lifecycle of a scan session with persistence,
crash recovery, pause/resume capability, and session comparison.

A professional bug bounty hunter works across multiple sessions,
sometimes pausing mid-scan to continue later. This module ensures:
- No work is ever lost (periodic checkpoints)
- Scans can be paused and resumed mid-pipeline
- Previous scans of the same target can be compared (delta analysis)
- Full audit trail for legal protection
- Session metadata for performance analysis

Architecture:
    SessionManager
    ├── create()      → ScanSession (new session)
    ├── resume()      → ScanSession (from checkpoint)
    ├── checkpoint()  → save to disk
    ├── complete()    → finalize session
    ├── compare()     → diff two sessions
    └── list()        → all sessions for a target
"""

from __future__ import annotations

import json
import shutil
import time
import uuid
from enum import StrEnum
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ────────────────────────────────────────────────────────────
# Enumerations
# ────────────────────────────────────────────────────────────


class SessionStatus(StrEnum):
    """Scan session lifecycle states."""

    CREATED = "created"          # Session created, not yet started
    RUNNING = "running"          # Actively scanning
    PAUSED = "paused"            # Paused by user / system
    CHECKPOINTED = "checkpointed"  # Saved to disk, can be resumed
    COMPLETED = "completed"      # All stages finished
    FAILED = "failed"            # Unrecoverable error
    ABORTED = "aborted"          # User aborted


# ────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────


class StageCheckpoint(BaseModel):
    """Checkpoint data for a single pipeline stage."""

    stage: str
    status: str = "pending"         # pending | running | completed | skipped | failed
    started_at: float = 0.0
    completed_at: float = 0.0
    findings_count: int = 0
    errors: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class SessionMetadata(BaseModel):
    """Metadata about a scan session."""

    session_id: str
    target: str
    mode: str = "semi-autonomous"
    profile: str = "balanced"
    status: SessionStatus = SessionStatus.CREATED

    # Timing
    created_at: float = Field(default_factory=time.time)
    started_at: float = 0.0
    paused_at: float = 0.0
    resumed_at: float = 0.0
    completed_at: float = 0.0
    last_checkpoint_at: float = 0.0

    # Progress
    current_stage: str = ""
    completed_stages: list[str] = Field(default_factory=list)
    total_stages: int = 10

    # Counters
    findings_total: int = 0
    findings_verified: int = 0
    findings_fp: int = 0
    tools_executed: int = 0
    errors_total: int = 0
    checkpoints_saved: int = 0

    # Scope
    scope_config: dict[str, Any] = Field(default_factory=dict)

    # Tags for organisation
    tags: list[str] = Field(default_factory=list)
    notes: str = ""

    @property
    def elapsed_seconds(self) -> float:
        """Total active runtime (excludes paused time)."""
        if not self.started_at:
            return 0.0
        end = self.completed_at or time.time()
        return end - self.started_at

    @property
    def progress_pct(self) -> float:
        if self.total_stages == 0:
            return 0.0
        return len(self.completed_stages) / self.total_stages * 100


class ScanSession(BaseModel):
    """Complete scan session state — serialisable to JSON."""

    metadata: SessionMetadata

    # Stage-level checkpoints
    stage_checkpoints: dict[str, StageCheckpoint] = Field(default_factory=dict)

    # Accumulated data (mirrors WorkflowState)
    subdomains: list[str] = Field(default_factory=list)
    live_hosts: list[str] = Field(default_factory=list)
    open_ports: dict[str, list[int]] = Field(default_factory=dict)
    endpoints: list[str] = Field(default_factory=list)
    technologies: dict[str, list[str]] = Field(default_factory=dict)

    # Findings
    raw_findings: list[dict[str, Any]] = Field(default_factory=list)
    verified_findings: list[dict[str, Any]] = Field(default_factory=list)
    false_positives: list[dict[str, Any]] = Field(default_factory=list)

    # Reports
    reports_generated: list[str] = Field(default_factory=list)

    # Workflow context that later stages depend on when resuming
    tools_run: list[str] = Field(default_factory=list)
    workflow_metadata: dict[str, Any] = Field(default_factory=dict)
    auth_headers: dict[str, str] = Field(default_factory=dict)
    auth_roles: list[dict[str, Any]] = Field(default_factory=list)

    # Reflection/learning data
    reflections: list[dict[str, Any]] = Field(default_factory=list)
    strategy_adjustments: list[dict[str, Any]] = Field(default_factory=list)
    decision_journal: list[dict[str, Any]] = Field(default_factory=list)


class SessionDiff(BaseModel):
    """Difference between two scan sessions (delta analysis)."""

    session_a_id: str
    session_b_id: str
    target: str

    # New items in session B
    new_subdomains: list[str] = Field(default_factory=list)
    new_endpoints: list[str] = Field(default_factory=list)
    new_findings: list[dict[str, Any]] = Field(default_factory=list)
    new_technologies: dict[str, list[str]] = Field(default_factory=dict)

    # Removed (no longer found)
    removed_subdomains: list[str] = Field(default_factory=list)
    removed_endpoints: list[str] = Field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = Field(default_factory=list)

    # Changed
    port_changes: dict[str, dict[str, list[int]]] = Field(default_factory=dict)

    # Summary
    summary: str = ""


# ────────────────────────────────────────────────────────────
# Session Manager
# ────────────────────────────────────────────────────────────


class SessionManager:
    """
    Manages scan session lifecycle with persistence.

    Sessions are stored as JSON files in the output directory:
        output/sessions/{target_hash}/{session_id}/
        ├── session.json         # Full session state
        ├── metadata.json        # Quick-read metadata
        ├── checkpoints/         # Periodic checkpoints
        │   ├── cp_001.json
        │   └── cp_002.json
        └── findings/            # Individual finding files
            ├── finding_001.json
            └── finding_002.json

    Usage::

        manager = SessionManager(output_dir="output")

        # Create & start
        session = manager.create_session("example.com", profile="balanced")
        session = manager.start_session(session.metadata.session_id)

        # During scan — periodic checkpoints
        manager.checkpoint(session)

        # Pause & resume
        manager.pause_session(session.metadata.session_id)
        session = manager.resume_session(session.metadata.session_id)

        # Complete
        manager.complete_session(session.metadata.session_id)

        # Compare two scans
        diff = manager.compare(session_id_a, session_id_b)
    """

    CHECKPOINT_INTERVAL_SECONDS = 120  # Auto-checkpoint every 2 minutes
    MAX_CHECKPOINTS_PER_SESSION = 100

    def __init__(
        self,
        output_dir: str | Path = "output",
    ) -> None:
        self.output_dir = Path(output_dir)
        self.sessions_dir = self.output_dir / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

        # In-memory cache of active sessions
        self._active_sessions: dict[str, ScanSession] = {}

        # Last checkpoint timestamp per session
        self._last_checkpoint: dict[str, float] = {}

        logger.info(f"SessionManager initialized | dir={self.sessions_dir}")

    # ─── Session Lifecycle ───────────────────────────────────

    def create_session(
        self,
        target: str,
        mode: str = "semi-autonomous",
        profile: str = "balanced",
        scope_config: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        notes: str = "",
    ) -> ScanSession:
        """Create a new scan session."""
        session_id = f"scan_{uuid.uuid4().hex[:12]}"

        metadata = SessionMetadata(
            session_id=session_id,
            target=target,
            mode=mode,
            profile=profile,
            scope_config=scope_config or {},
            tags=tags or [],
            notes=notes,
        )

        session = ScanSession(metadata=metadata)

        # Create directory structure
        session_dir = self._session_dir(session_id)
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "checkpoints").mkdir(exist_ok=True)
        (session_dir / "findings").mkdir(exist_ok=True)

        # Save initial state
        self._save_session(session)
        self._active_sessions[session_id] = session

        logger.info(
            f"Session created | id={session_id} | target={target} | "
            f"mode={mode} | profile={profile}"
        )
        return session

    def start_session(self, session_id: str) -> ScanSession:
        """Mark a session as running."""
        session = self._get_session(session_id)
        session.metadata.status = SessionStatus.RUNNING
        session.metadata.started_at = time.time()
        self._save_metadata(session)
        logger.info(f"Session started | id={session_id}")
        return session

    def pause_session(self, session_id: str) -> ScanSession:
        """Pause a running session (saves checkpoint first)."""
        session = self._get_session(session_id)

        if session.metadata.status != SessionStatus.RUNNING:
            logger.warning(
                f"Cannot pause session in state {session.metadata.status}"
            )
            return session

        session.metadata.status = SessionStatus.PAUSED
        session.metadata.paused_at = time.time()

        # Save full checkpoint
        self.checkpoint(session, force=True)

        logger.info(
            f"Session paused | id={session_id} | "
            f"elapsed={session.metadata.elapsed_seconds:.0f}s"
        )
        return session

    def resume_session(self, session_id: str) -> ScanSession:
        """Resume a paused/checkpointed session."""
        session = self._get_session(session_id)

        if session.metadata.status not in (
            SessionStatus.PAUSED,
            SessionStatus.CHECKPOINTED,
        ):
            logger.warning(
                f"Cannot resume session in state {session.metadata.status}"
            )
            return session

        session.metadata.status = SessionStatus.RUNNING
        session.metadata.resumed_at = time.time()
        self._save_metadata(session)

        logger.info(
            f"Session resumed | id={session_id} | "
            f"stage={session.metadata.current_stage} | "
            f"completed={len(session.metadata.completed_stages)}/{session.metadata.total_stages}"
        )
        return session

    def complete_session(self, session_id: str) -> ScanSession:
        """Mark session as completed and save final state."""
        session = self._get_session(session_id)
        session.metadata.status = SessionStatus.COMPLETED
        session.metadata.completed_at = time.time()

        # Final save
        self._save_session(session)

        # Remove from active cache
        self._active_sessions.pop(session_id, None)

        logger.info(
            f"Session completed | id={session_id} | "
            f"duration={session.metadata.elapsed_seconds:.0f}s | "
            f"findings={session.metadata.findings_total} | "
            f"verified={session.metadata.findings_verified}"
        )
        return session

    def abort_session(self, session_id: str, reason: str = "") -> ScanSession:
        """Abort a session."""
        session = self._get_session(session_id)
        session.metadata.status = SessionStatus.ABORTED
        session.metadata.completed_at = time.time()
        session.metadata.notes += f"\n[ABORTED] {reason}"

        self._save_session(session)
        self._active_sessions.pop(session_id, None)

        logger.warning(f"Session aborted | id={session_id} | reason={reason}")
        return session

    def fail_session(self, session_id: str, error: str) -> ScanSession:
        """Mark session as failed."""
        session = self._get_session(session_id)
        session.metadata.status = SessionStatus.FAILED
        session.metadata.completed_at = time.time()
        session.metadata.notes += f"\n[FAILED] {error}"

        # Save final state for debugging
        self._save_session(session)
        self._active_sessions.pop(session_id, None)

        logger.error(f"Session failed | id={session_id} | error={error[:200]}")
        return session

    # ─── Checkpoint System ───────────────────────────────────

    def checkpoint(
        self,
        session: ScanSession,
        force: bool = False,
    ) -> bool:
        """
        Save a checkpoint of the current session state.

        Returns True if a checkpoint was actually saved.
        Checkpoints are throttled to CHECKPOINT_INTERVAL_SECONDS
        unless force=True.
        """
        sid = session.metadata.session_id
        now = time.time()
        last = self._last_checkpoint.get(sid, 0.0)

        if not force and (now - last) < self.CHECKPOINT_INTERVAL_SECONDS:
            return False

        session.metadata.last_checkpoint_at = now
        session.metadata.checkpoints_saved += 1
        cp_num = session.metadata.checkpoints_saved

        # Save checkpoint file
        cp_dir = self._session_dir(sid) / "checkpoints"
        cp_dir.mkdir(parents=True, exist_ok=True)
        cp_file = cp_dir / f"cp_{cp_num:04d}.json"

        try:
            cp_file.write_text(
                session.model_dump_json(indent=2),
                encoding="utf-8",
            )
            self._last_checkpoint[sid] = now

            # Also save current session.json
            self._save_session(session)

            # Prune old checkpoints if too many
            self._prune_checkpoints(sid)

            logger.debug(
                f"Checkpoint saved | id={sid} | cp={cp_num} | "
                f"stage={session.metadata.current_stage}"
            )
            return True

        except Exception as e:
            logger.error(f"Checkpoint save failed | id={sid} | error={e}")
            # P1 (V17): Fallback — save with json.dumps(default=str)
            try:
                import json as _cp_json
                _fallback_data = session.model_dump()
                cp_file.write_text(
                    _cp_json.dumps(_fallback_data, indent=2, default=str),
                    encoding="utf-8",
                )
                self._last_checkpoint[sid] = now
                logger.warning(f"Checkpoint saved via fallback serialization | id={sid} | cp={cp_num}")
                return True
            except Exception as e2:
                logger.error(f"Checkpoint fallback also failed | id={sid} | error={e2}")
            return False

    def restore_from_checkpoint(
        self,
        session_id: str,
        checkpoint_number: int | None = None,
    ) -> ScanSession:
        """
        Restore session from a specific checkpoint.

        If checkpoint_number is None, uses the latest checkpoint.
        """
        cp_dir = self._session_dir(session_id) / "checkpoints"

        if checkpoint_number is not None:
            cp_file = cp_dir / f"cp_{checkpoint_number:04d}.json"
        else:
            # Find latest
            cp_files = sorted(cp_dir.glob("cp_*.json"))
            if not cp_files:
                raise FileNotFoundError(
                    f"No checkpoints found for session {session_id}"
                )
            cp_file = cp_files[-1]

        if not cp_file.exists():
            raise FileNotFoundError(f"Checkpoint not found: {cp_file}")

        data = json.loads(cp_file.read_text(encoding="utf-8"))
        session = ScanSession.model_validate(data)
        session.metadata.status = SessionStatus.CHECKPOINTED

        self._active_sessions[session_id] = session

        logger.info(
            f"Session restored from checkpoint | id={session_id} | "
            f"file={cp_file.name} | stage={session.metadata.current_stage}"
        )
        return session

    # ─── Stage Tracking ──────────────────────────────────────

    def record_stage_start(
        self,
        session: ScanSession,
        stage: str,
    ) -> None:
        """Record that a pipeline stage has started."""
        session.metadata.current_stage = stage
        session.stage_checkpoints[stage] = StageCheckpoint(
            stage=stage,
            status="running",
            started_at=time.time(),
        )
        logger.debug(f"Stage started | session={session.metadata.session_id} | stage={stage}")

    def record_stage_complete(
        self,
        session: ScanSession,
        stage: str,
        findings_count: int = 0,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Record that a pipeline stage has completed."""
        cp = session.stage_checkpoints.get(stage)
        if cp:
            cp.status = "completed"
            cp.completed_at = time.time()
            cp.findings_count = findings_count
            if data:
                cp.data = data

        if stage not in session.metadata.completed_stages:
            session.metadata.completed_stages.append(stage)

        # Auto-checkpoint after each stage
        self.checkpoint(session, force=True)

        logger.debug(
            f"Stage completed | session={session.metadata.session_id} | "
            f"stage={stage} | findings={findings_count}"
        )

    def record_stage_error(
        self,
        session: ScanSession,
        stage: str,
        error: str,
    ) -> None:
        """Record a stage error."""
        cp = session.stage_checkpoints.get(stage)
        if cp:
            cp.status = "failed"
            cp.errors.append(error)
        session.metadata.errors_total += 1

    # ─── Data Accumulation ───────────────────────────────────

    def add_subdomains(
        self,
        session: ScanSession,
        subdomains: list[str],
    ) -> int:
        """Add discovered subdomains (deduplicates)."""
        existing = set(session.subdomains)
        new = [s for s in subdomains if s not in existing]
        session.subdomains.extend(new)
        return len(new)

    def add_endpoints(
        self,
        session: ScanSession,
        endpoints: list[str],
    ) -> int:
        """Add discovered endpoints (deduplicates)."""
        existing = set(session.endpoints)
        new = [e for e in endpoints if e not in existing]
        session.endpoints.extend(new)
        return len(new)

    def add_finding(
        self,
        session: ScanSession,
        finding: dict[str, Any],
    ) -> None:
        """Add a raw finding."""
        session.raw_findings.append(finding)
        session.metadata.findings_total += 1

        # Save individual finding file
        self._save_finding(session.metadata.session_id, finding)

    def verify_finding(
        self,
        session: ScanSession,
        finding: dict[str, Any],
        is_true_positive: bool,
    ) -> None:
        """Classify a finding as TP or FP."""
        if is_true_positive:
            session.verified_findings.append(finding)
            session.metadata.findings_verified += 1
        else:
            session.false_positives.append(finding)
            session.metadata.findings_fp += 1

    # ─── Session Queries ─────────────────────────────────────

    def list_sessions(
        self,
        target: str | None = None,
        status: SessionStatus | None = None,
    ) -> list[SessionMetadata]:
        """List all sessions, optionally filtered."""
        sessions: list[SessionMetadata] = []

        for session_dir in self.sessions_dir.iterdir():
            if not session_dir.is_dir():
                continue

            meta_file = session_dir / "metadata.json"
            if not meta_file.exists():
                continue

            try:
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                meta = SessionMetadata.model_validate(data)

                if target and meta.target != target:
                    continue
                if status and meta.status != status:
                    continue

                sessions.append(meta)
            except Exception as e:
                logger.debug(f"Skipping invalid session dir: {session_dir} — {e}")

        # Sort by creation time (newest first)
        sessions.sort(key=lambda m: m.created_at, reverse=True)
        return sessions

    def get_session(self, session_id: str) -> ScanSession:
        """Load a session by ID."""
        return self._get_session(session_id)

    def get_latest_session(self, target: str) -> ScanSession | None:
        """Get the most recent session for a target."""
        sessions = self.list_sessions(target=target)
        if not sessions:
            return None
        return self._get_session(sessions[0].session_id)

    # ─── Session Comparison ──────────────────────────────────

    def compare_sessions(
        self,
        session_id_a: str,
        session_id_b: str,
    ) -> SessionDiff:
        """
        Compare two scan sessions of the same target (delta analysis).

        Useful for tracking changes over time:
        - New subdomains / endpoints discovered
        - New vulnerabilities found
        - Previously found issues now resolved
        """
        a = self._get_session(session_id_a)
        b = self._get_session(session_id_b)

        # Ensure same target
        if a.metadata.target != b.metadata.target:
            logger.warning(
                f"Comparing sessions for different targets: "
                f"{a.metadata.target} vs {b.metadata.target}"
            )

        set_a_subs = set(a.subdomains)
        set_b_subs = set(b.subdomains)
        set_a_eps = set(a.endpoints)
        set_b_eps = set(b.endpoints)

        # New findings in B that weren't in A
        # Using title + type as dedup key
        def finding_key(f: dict) -> str:
            return f"{f.get('title', '')}::{f.get('vuln_type', '')}"

        a_finding_keys = {finding_key(f) for f in a.verified_findings}
        b_finding_keys = {finding_key(f) for f in b.verified_findings}

        new_finding_keys = b_finding_keys - a_finding_keys
        resolved_keys = a_finding_keys - b_finding_keys

        new_findings = [
            f for f in b.verified_findings
            if finding_key(f) in new_finding_keys
        ]
        resolved_findings = [
            f for f in a.verified_findings
            if finding_key(f) in resolved_keys
        ]

        # Port changes
        port_changes: dict[str, dict[str, list[int]]] = {}
        all_hosts = set(a.open_ports.keys()) | set(b.open_ports.keys())
        for host in all_hosts:
            a_ports = set(a.open_ports.get(host, []))
            b_ports = set(b.open_ports.get(host, []))
            if a_ports != b_ports:
                port_changes[host] = {
                    "opened": sorted(b_ports - a_ports),
                    "closed": sorted(a_ports - b_ports),
                }

        # Technology changes
        new_tech: dict[str, list[str]] = {}
        for host, techs in b.technologies.items():
            a_techs = set(a.technologies.get(host, []))
            new = [t for t in techs if t not in a_techs]
            if new:
                new_tech[host] = new

        diff = SessionDiff(
            session_a_id=session_id_a,
            session_b_id=session_id_b,
            target=b.metadata.target,
            new_subdomains=sorted(set_b_subs - set_a_subs),
            new_endpoints=sorted(set_b_eps - set_a_eps),
            new_findings=new_findings,
            new_technologies=new_tech,
            removed_subdomains=sorted(set_a_subs - set_b_subs),
            removed_endpoints=sorted(set_a_eps - set_b_eps),
            resolved_findings=resolved_findings,
            port_changes=port_changes,
        )

        # Generate summary
        diff.summary = self._generate_diff_summary(diff)

        logger.info(
            f"Session comparison complete | "
            f"a={session_id_a} b={session_id_b} | "
            f"new_subs={len(diff.new_subdomains)} "
            f"new_findings={len(diff.new_findings)} "
            f"resolved={len(diff.resolved_findings)}"
        )

        return diff

    # ─── Sync with WorkflowState ─────────────────────────────

    def sync_from_workflow_state(
        self,
        session: ScanSession,
        workflow_state: Any,
    ) -> None:
        """
        Update session data from a WorkflowState object.

        This bridges the orchestrator's in-memory state to the
        persistent session store.
        """
        session.subdomains = list(
            set(session.subdomains)
            | set(getattr(workflow_state, "subdomains", []))
        )
        session.live_hosts = list(
            set(session.live_hosts)
            | set(getattr(workflow_state, "live_hosts", []))
        )
        session.endpoints = list(
            set(session.endpoints)
            | set(getattr(workflow_state, "endpoints", []))
        )

        # Merge ports
        wf_ports = getattr(workflow_state, "open_ports", {})
        for host, ports in wf_ports.items():
            existing = set(session.open_ports.get(host, []))
            existing.update(ports)
            session.open_ports[host] = sorted(existing)

        # Merge technologies
        wf_tech = getattr(workflow_state, "technologies", {})
        for host, techs in wf_tech.items():
            existing = set(session.technologies.get(host, []))
            # Guard against techs being a string (would iterate chars)
            if isinstance(techs, str):
                techs = [techs]
            existing.update(techs)
            session.technologies[host] = sorted(existing)

        # Sync findings
        session.raw_findings = getattr(workflow_state, "raw_findings", [])
        session.verified_findings = getattr(workflow_state, "verified_findings", [])
        session.false_positives = getattr(workflow_state, "false_positives", [])
        session.reports_generated = getattr(workflow_state, "reports_generated", [])
        session.tools_run = list(getattr(workflow_state, "tools_run", []))
        session.metadata.completed_stages = [
            getattr(stage, "value", str(stage))
            for stage in getattr(workflow_state, "completed_stages", [])
        ]
        for stage_key, stage_result in dict(getattr(workflow_state, "stage_results", {}) or {}).items():
            stage_name = getattr(stage_key, "value", str(stage_key))
            session.stage_checkpoints[stage_name] = StageCheckpoint(
                stage=stage_name,
                status="skipped" if getattr(stage_result, "skipped", False) else (
                    "completed" if getattr(stage_result, "success", False) else "failed"
                ),
                findings_count=getattr(stage_result, "findings_count", 0),
                errors=list(getattr(stage_result, "errors", []) or []),
                data=dict(getattr(stage_result, "data", {}) or {}),
            )
        session.auth_headers = dict(getattr(workflow_state, "auth_headers", {}) or {})
        session.auth_roles = list(getattr(workflow_state, "auth_roles", []) or [])
        # P0-1 (V17): Sanitize metadata — convert non-JSON-serializable objects
        _raw_meta = dict(getattr(workflow_state, "metadata", {}) or {})
        _clean_meta: dict[str, Any] = {}
        for _mk, _mv in _raw_meta.items():
            if hasattr(_mv, "to_dict"):
                _clean_meta[_mk] = _mv.to_dict()
            else:
                try:
                    import json as _json_check
                    _json_check.dumps(_mv)
                    _clean_meta[_mk] = _mv
                except (TypeError, ValueError, OverflowError):
                    _clean_meta[_mk] = str(_mv)
        session.workflow_metadata = _clean_meta

        # Update counters
        session.metadata.findings_total = len(session.raw_findings)
        session.metadata.findings_verified = len(session.verified_findings)
        session.metadata.findings_fp = len(session.false_positives)
        session.metadata.tools_executed = len(session.tools_run)

    def sync_to_workflow_state(
        self,
        session: ScanSession,
        workflow_state: Any,
    ) -> None:
        """
        Restore a WorkflowState from session data (for resume).

        Populates the workflow state with all previously discovered data
        so the pipeline can continue from where it left off.
        """
        workflow_state.subdomains = list(session.subdomains)
        workflow_state.live_hosts = list(session.live_hosts)
        workflow_state.open_ports = dict(session.open_ports)
        workflow_state.endpoints = list(session.endpoints)
        workflow_state.technologies = dict(session.technologies)
        workflow_state.raw_findings = list(session.raw_findings)
        workflow_state.verified_findings = list(session.verified_findings)
        workflow_state.false_positives = list(session.false_positives)
        workflow_state.reports_generated = list(session.reports_generated)
        workflow_state.tools_run = list(session.tools_run)
        workflow_state.metadata = dict(session.workflow_metadata)
        workflow_state.auth_headers = dict(session.auth_headers)
        workflow_state.auth_roles = list(session.auth_roles)

        # Restore current_stage with enum conversion (consistent with completed_stages handling)
        _raw_stage = session.metadata.current_stage or getattr(
            workflow_state, "current_stage", ""
        )
        if _raw_stage:
            try:
                from src.utils.constants import WorkflowStage
                workflow_state.current_stage = (
                    _raw_stage if isinstance(_raw_stage, WorkflowStage)
                    else WorkflowStage(_raw_stage)
                )
            except (ValueError, KeyError):
                logger.debug(f"current_stage restore fell back to raw value: {_raw_stage}")
                workflow_state.current_stage = _raw_stage

        # Set stage info
        if session.metadata.completed_stages:
            try:
                from src.utils.constants import WorkflowStage

                workflow_state.completed_stages = [
                    stage if isinstance(stage, WorkflowStage) else WorkflowStage(stage)
                    for stage in session.metadata.completed_stages
                ]
            except Exception as exc:
                logger.debug(f"Completed stage restore fell back to raw values: {exc}")
                workflow_state.completed_stages = list(session.metadata.completed_stages)

        if session.stage_checkpoints:
            try:
                from src.utils.constants import WorkflowStage
                from src.workflow.orchestrator import StageResult

                restored_stage_results = {}
                for stage_name, checkpoint in session.stage_checkpoints.items():
                    try:
                        stage_value = WorkflowStage(stage_name)
                    except ValueError:
                        stage_value = stage_name
                    restored_stage_results[stage_value] = StageResult(
                        stage=stage_value,
                        success=checkpoint.status == "completed",
                        duration=max(checkpoint.completed_at - checkpoint.started_at, 0.0)
                        if checkpoint.completed_at and checkpoint.started_at
                        else 0.0,
                        findings_count=checkpoint.findings_count,
                        data=dict(checkpoint.data or {}),
                        errors=list(checkpoint.errors),
                        skipped=checkpoint.status == "skipped",
                        skip_reason="checkpoint_restore" if checkpoint.status == "skipped" else "",
                    )
                workflow_state.stage_results = restored_stage_results
            except Exception as exc:
                logger.debug(f"StageResult restore skipped: {exc}")

    # ─── Internal Helpers ────────────────────────────────────

    def _session_dir(self, session_id: str) -> Path:
        """Get the directory for a session."""
        return self.sessions_dir / session_id

    def _get_session(self, session_id: str) -> ScanSession:
        """Load a session (from cache or disk)."""
        if session_id in self._active_sessions:
            return self._active_sessions[session_id]

        session_file = self._session_dir(session_id) / "session.json"
        if not session_file.exists():
            raise FileNotFoundError(f"Session not found: {session_id}")

        data = json.loads(session_file.read_text(encoding="utf-8"))
        session = ScanSession.model_validate(data)
        self._active_sessions[session_id] = session
        return session

    def _save_session(self, session: ScanSession) -> None:
        """Save full session state to disk."""
        session_dir = self._session_dir(session.metadata.session_id)
        session_dir.mkdir(parents=True, exist_ok=True)

        session_file = session_dir / "session.json"
        try:
            session_file.write_text(
                session.model_dump_json(indent=2),
                encoding="utf-8",
            )
        except Exception as _save_err:
            # P1 (V17): Fallback serialization with default=str
            import json as _save_json
            logger.warning(f"Session save fallback: {_save_err}")
            session_file.write_text(
                _save_json.dumps(session.model_dump(), indent=2, default=str),
                encoding="utf-8",
            )

        self._save_metadata(session)

    def _save_metadata(self, session: ScanSession) -> None:
        """Save lightweight metadata (for fast listing)."""
        session_dir = self._session_dir(session.metadata.session_id)
        session_dir.mkdir(parents=True, exist_ok=True)

        meta_file = session_dir / "metadata.json"
        meta_file.write_text(
            session.metadata.model_dump_json(indent=2),
            encoding="utf-8",
        )

    def _save_finding(
        self,
        session_id: str,
        finding: dict[str, Any],
    ) -> None:
        """Save a single finding to its own file."""
        findings_dir = self._session_dir(session_id) / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)

        finding_id = finding.get("id", uuid.uuid4().hex[:8])
        finding_file = findings_dir / f"finding_{finding_id}.json"

        try:
            finding_file.write_text(
                json.dumps(finding, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as e:
            logger.debug(f"Failed to save finding file: {e}")

    def _prune_checkpoints(self, session_id: str) -> None:
        """Keep only the most recent N checkpoints."""
        cp_dir = self._session_dir(session_id) / "checkpoints"
        if not cp_dir.exists():
            return

        cp_files = sorted(cp_dir.glob("cp_*.json"))
        if len(cp_files) <= self.MAX_CHECKPOINTS_PER_SESSION:
            return

        to_remove = cp_files[: len(cp_files) - self.MAX_CHECKPOINTS_PER_SESSION]
        for f in to_remove:
            try:
                f.unlink()
            except Exception as _exc:
                logger.debug(f"session manager error: {_exc}")

    @staticmethod
    def _generate_diff_summary(diff: SessionDiff) -> str:
        """Generate a human-readable diff summary."""
        parts: list[str] = []

        if diff.new_subdomains:
            parts.append(f"{len(diff.new_subdomains)} new subdomains discovered")
        if diff.removed_subdomains:
            parts.append(f"{len(diff.removed_subdomains)} subdomains no longer found")
        if diff.new_endpoints:
            parts.append(f"{len(diff.new_endpoints)} new endpoints discovered")
        if diff.new_findings:
            parts.append(f"{len(diff.new_findings)} NEW vulnerabilities found")
        if diff.resolved_findings:
            parts.append(f"{len(diff.resolved_findings)} previously found vulnerabilities appear resolved")
        if diff.port_changes:
            total_opened = sum(len(v.get("opened", [])) for v in diff.port_changes.values())
            total_closed = sum(len(v.get("closed", [])) for v in diff.port_changes.values())
            if total_opened:
                parts.append(f"{total_opened} new open ports detected")
            if total_closed:
                parts.append(f"{total_closed} ports closed")
        if diff.new_technologies:
            total_new_tech = sum(len(v) for v in diff.new_technologies.values())
            parts.append(f"{total_new_tech} new technologies detected")

        if not parts:
            return "No significant changes between the two scans."

        return "Changes: " + "; ".join(parts) + "."

    def delete_session(self, session_id: str) -> bool:
        """Permanently delete a session and all its data."""
        session_dir = self._session_dir(session_id)
        if not session_dir.exists():
            return False

        try:
            shutil.rmtree(session_dir)
            self._active_sessions.pop(session_id, None)
            self._last_checkpoint.pop(session_id, None)
            logger.info(f"Session deleted | id={session_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
            return False

    # ─── Resume Support (T4-1) ───────────────────────────────

    def load_session(self, session_id: str) -> ScanSession | None:
        """Load a session by ID (public wrapper around _get_session)."""
        try:
            return self._get_session(session_id)
        except FileNotFoundError:
            return None

    def append_note(self, session_id: str, note: str) -> bool:
        """Append an operator note to session metadata and persist it."""
        session = self.load_session(session_id)
        if session is None:
            return False
        note = note.strip()
        if not note:
            return False
        existing = session.metadata.notes.strip()
        session.metadata.notes = f"{existing}\n{note}".strip() if existing else note
        self._save_session(session)
        return True

    def find_incomplete_sessions(self, target: str | None = None) -> list[ScanSession]:
        """Find all sessions that were interrupted (RUNNING/CHECKPOINTED/PAUSED).

        Sorted by most recent first.
        """
        incomplete: list[ScanSession] = []
        if not self.sessions_dir.exists():
            return incomplete
        for session_dir in sorted(self.sessions_dir.iterdir(), reverse=True):
            meta_file = session_dir / "metadata.json"
            if not meta_file.exists():
                continue
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                status = meta.get("status", "")
                if status in (
                    SessionStatus.RUNNING,
                    SessionStatus.CHECKPOINTED,
                    SessionStatus.PAUSED,
                ):
                    session = self._get_session(session_dir.name)
                    if target and session.metadata.target != target:
                        continue
                    incomplete.append(session)
            except Exception as _sess_err:
                logger.debug(f"Skipping session dir {session_dir.name}: {_sess_err}")
                continue
        incomplete.sort(
            key=lambda s: (
                s.metadata.last_checkpoint_at,
                s.metadata.resumed_at,
                s.metadata.started_at,
                s.metadata.created_at,
            ),
            reverse=True,
        )
        return incomplete


__all__ = [
    "SessionManager",
    "ScanSession",
    "SessionMetadata",
    "SessionDiff",
    "SessionStatus",
    "StageCheckpoint",
]
