"""
WhiteHatHacker AI — Continuous Monitor (P6-1)

Scheduling loop for continuous target monitoring:
- First run: full scan
- Subsequent runs: incremental scan (new/changed assets only)
- After each scan: diff comparison + alert on changes
- Configurable interval, max iterations, and on-change-only alerts

Usage:
    monitor = ContinuousMonitor(target, scope_file, ...)
    await monitor.run(interval_minutes=120, max_iterations=0)
"""

from __future__ import annotations

import asyncio
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

from src.analysis.diff_engine import DiffEngine
from src.analysis.global_finding_store import GlobalFindingStore
from src.integrations.asset_db import AssetDB
from src.integrations.diff_alerts import send_diff_alerts
from src.integrations.notification import (
    NotificationManager,
    build_notification_manager,
    load_notification_config,
)


class ContinuousMonitor:
    """
    Orchestrates continuous scanning of a target at fixed intervals.

    Lifecycle:
    1. First iteration: full scan → baseline
    2. Subsequent iterations: incremental scan → diff vs. previous
    3. Alert on new/resolved/regressed findings
    4. Repeat until max_iterations or SIGINT
    """

    def __init__(
        self,
        target: str,
        scope_file: str | None = None,
        profile: str = "balanced",
        mode: str = "autonomous",
        config_path: str = "config/settings.yaml",
        output_dir: str = "output",
        verbose: bool = False,
        no_brain: bool = False,
    ):
        self.target = target
        self.scope_file = scope_file
        self.profile = profile
        self.mode = mode
        self.config_path = config_path
        self.output_dir = output_dir
        self.verbose = verbose
        self.no_brain = no_brain
        self._stop_event = asyncio.Event()
        self._iteration = 0
        self._scan_ids: list[str] = []
        self._db = AssetDB(str(Path(output_dir) / "asset_db.sqlite"))
        self._gfs = GlobalFindingStore(str(Path(output_dir) / "global_findings.db"))
        self._notify = self._build_notify()

    def _build_notify(self) -> NotificationManager:
        """Build notification manager from config."""
        try:
            config = load_notification_config(self.config_path)
            return build_notification_manager(config)
        except Exception:
            logger.warning("No notification config found, using terminal only")
            return NotificationManager()

    async def run(
        self,
        interval_minutes: int = 120,
        max_iterations: int = 0,
    ) -> dict[str, Any]:
        """
        Main monitoring loop.

        Args:
            interval_minutes: Minutes between scan iterations
            max_iterations: 0 = infinite (until SIGINT)

        Returns:
            Summary dict with iterations, findings, alerts
        """
        logger.info(
            f"Starting continuous monitor for {self.target} "
            f"(interval={interval_minutes}min, max_iterations={max_iterations or '∞'})"
        )

        # Handle graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._signal_handler)
            except (NotImplementedError, RuntimeError):
                pass  # Not supported on all platforms

        summary: dict[str, Any] = {
            "target": self.target,
            "iterations": 0,
            "total_new_findings": 0,
            "total_regressions": 0,
            "total_resolved": 0,
            "scan_ids": [],
        }

        while not self._stop_event.is_set():
            self._iteration += 1

            if max_iterations > 0 and self._iteration > max_iterations:
                logger.info(f"Reached max iterations ({max_iterations}), stopping")
                break

            logger.info(f"=== Monitor iteration {self._iteration} ===")

            try:
                result = await self._run_one_iteration()
                summary["iterations"] = self._iteration
                summary["scan_ids"].append(result.get("scan_id", ""))
                summary["total_new_findings"] += result.get("new_findings", 0)
                summary["total_regressions"] += result.get("regressions", 0)
                summary["total_resolved"] += result.get("resolved", 0)

                if result.get("scan_id"):
                    self._scan_ids.append(result["scan_id"])

            except Exception as exc:
                logger.warning(f"Monitor iteration {self._iteration} failed: {exc}")
                await self._notify.notify_error(
                    f"Monitor iteration {self._iteration} failed for {self.target}",
                    str(exc),
                )

            # Wait for next interval (unless stopping)
            if not self._stop_event.is_set() and (
                max_iterations == 0 or self._iteration < max_iterations
            ):
                logger.info(f"Sleeping {interval_minutes} minutes until next iteration...")
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=interval_minutes * 60,
                    )
                except asyncio.TimeoutError:
                    pass  # Expected — interval elapsed

        logger.info(
            f"Monitor stopped after {self._iteration} iterations. "
            f"New findings: {summary['total_new_findings']}, "
            f"Regressions: {summary['total_regressions']}, "
            f"Resolved: {summary['total_resolved']}"
        )
        return summary

    async def _run_one_iteration(self) -> dict[str, Any]:
        """Execute one scan iteration and process results."""
        is_first = self._iteration == 1
        incremental = not is_first

        # Run scan
        scan_result = await self._execute_scan(incremental=incremental)
        scan_id = scan_result.get("session_id", f"monitor_{self._iteration}")

        result: dict[str, Any] = {
            "scan_id": scan_id,
            "iteration": self._iteration,
            "incremental": incremental,
            "new_findings": 0,
            "regressions": 0,
            "resolved": 0,
        }

        # Process findings through GlobalFindingStore
        verified = scan_result.get("verified_findings", [])
        program = self.target.replace(".", "_")

        for f in verified:
            dedup = self._gfs.record(f, scan_id, program=program)
            if dedup.is_new:
                result["new_findings"] += 1
                f["_dedup_status"] = "new"
            elif dedup.is_regression:
                result["regressions"] += 1
                f["_dedup_status"] = "regression"
                logger.warning(
                    f"REGRESSION: {f.get('title', 'unknown')} reappeared "
                    f"(first seen: {dedup.first_seen_scan})"
                )
            else:
                f["_dedup_status"] = "recurring"

        # Diff against previous scan
        if len(self._scan_ids) >= 1 and not is_first:
            try:
                diff_engine = DiffEngine(self._db)
                prev_scan = self._scan_ids[-1]
                diff_report = diff_engine.diff(program, prev_scan, scan_id)

                resolved_count = len(diff_report.resolved_findings)
                result["resolved"] = resolved_count

                # Send diff alerts
                alerts_sent = await send_diff_alerts(
                    diff_report, self._notify.notify
                )
                logger.info(f"Sent {alerts_sent} diff alerts for iteration {self._iteration}")

            except Exception as exc:
                logger.warning(f"Diff/alert failed: {exc}")

        # Log iteration summary
        logger.info(
            f"Iteration {self._iteration} complete: "
            f"{len(verified)} verified, {result['new_findings']} new, "
            f"{result['regressions']} regressions, {result['resolved']} resolved"
        )

        return result

    async def _execute_scan(self, incremental: bool = False) -> dict[str, Any]:
        """
        Execute a scan via the main entry point.

        Returns scan result dict with session_id, verified_findings, etc.
        """
        from src.main import run_scan

        extra_args: dict[str, Any] = {}
        if incremental:
            extra_args["incremental"] = True

        # Load scope dict from file if provided
        scope_dict: dict[str, Any] | None = None
        if self.scope_file:
            try:
                import yaml
                scope_dict = yaml.safe_load(Path(self.scope_file).read_text())
            except Exception as exc:
                logger.warning(f"Failed to load scope file {self.scope_file}: {exc}")

        try:
            result = await run_scan(
                target=self.target,
                scope=scope_dict,
                config_path=self.config_path,
                mode_override=self.mode,
                profile_override=self.profile,
                allow_no_brain=self.no_brain,
                **extra_args,
            )
            # run_scan returns WorkflowState (Pydantic model), convert to dict
            if isinstance(result, dict):
                return result
            return {
                "session_id": getattr(result, "session_id", ""),
                "verified_findings": getattr(result, "verified_findings", []),
                "raw_findings": getattr(result, "raw_findings", []),
                "metadata": getattr(result, "metadata", {}),
                "tools_run": getattr(result, "tools_run", []),
            }
        except Exception as exc:
            logger.warning(f"Scan execution failed: {exc}")
            return {"error": str(exc)}

    def _signal_handler(self) -> None:
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        logger.info("Received shutdown signal, finishing current iteration...")
        self._stop_event.set()

    def stop(self) -> None:
        """Programmatically stop the monitor."""
        self._stop_event.set()
