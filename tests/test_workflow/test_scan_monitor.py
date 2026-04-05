"""Tests for scan monitoring and operator note generation."""

from __future__ import annotations

from datetime import datetime, timezone


def test_scan_monitor_collects_signals_and_recommendations(tmp_path):
    from src.workflow.scan_monitor import ScanMonitor
    from src.workflow.session_manager import SessionManager, SessionStatus

    output_dir = tmp_path / "output"
    manager = SessionManager(output_dir=output_dir)
    session = manager.create_session("example.com")
    session.metadata.status = SessionStatus.RUNNING
    session.metadata.current_stage = "vulnerability_scan"
    session.metadata.last_checkpoint_at = 0.0
    session.metadata.started_at = 1.0
    session.metadata.findings_total = 0
    session.metadata.findings_verified = 0
    session.metadata.findings_fp = 0
    manager._save_session(session)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / f"errors_{today}.log").write_text(
        "WARNING tool timed out\nERROR brain connection failed\n",
        encoding="utf-8",
    )

    monitor = ScanMonitor(session_manager=manager, log_dir=log_dir)
    observation = monitor.collect_observation(session_id=session.metadata.session_id)

    assert observation.error_count >= 1    # "ERROR brain connection failed"
    assert observation.warning_count >= 1  # "WARNING tool timed out"
    assert observation.timeout_count >= 1
    assert observation.latest_signals
    assert any("Timeout signals detected" in item for item in observation.recommendations)


def test_scan_monitor_writes_note_and_updates_session_metadata(tmp_path):
    from src.workflow.scan_monitor import ScanMonitor, ScanObservation
    from src.workflow.session_manager import SessionManager

    output_dir = tmp_path / "output"
    manager = SessionManager(output_dir=output_dir)
    session = manager.create_session("example.com")
    manager._save_session(session)

    monitor = ScanMonitor(session_manager=manager, log_dir=output_dir / "logs")
    observation = ScanObservation(
        session_id=session.metadata.session_id,
        target="example.com",
        status="running",
        current_stage="active_recon",
        recommendations=["Inspect stage throughput."],
    )

    note_path = monitor.write_observation_note(observation)
    reloaded = manager.load_session(session.metadata.session_id)

    assert note_path.exists()
    assert reloaded is not None
    assert "OBSERVE" in reloaded.metadata.notes