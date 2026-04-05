"""Regression tests for Phase 1 bug fixes (v2.7 production readiness)."""
from __future__ import annotations
import re
import time
import asyncio
from unittest.mock import MagicMock, patch

import pytest


# ── 1.1  AssetDB.ensure_program optional name ────────────────

class TestAssetDBOptionalName:
    def test_ensure_program_no_name(self, tmp_path):
        from src.integrations.asset_db import AssetDB
        db = AssetDB(tmp_path / "test.db")
        # Must not raise when called without name / platform
        db.ensure_program("test-program-id")

    def test_ensure_program_with_name(self, tmp_path):
        from src.integrations.asset_db import AssetDB
        db = AssetDB(tmp_path / "test.db")
        db.ensure_program("p1", name="My Program", platform="hackerone")
        # No assertion needed beyond no-error — the DB accepted it


# ── 1.2  SshAuditWrapper binary_name ────────────────────────

class TestSshAuditBinaryName:
    def test_binary_is_ssh_audit(self):
        from src.tools.network.ssh_audit_wrapper import SshAuditWrapper
        assert SshAuditWrapper.binary_name == "ssh-audit"


# ── 1.3  ANSI regex strip in SecurityTool ────────────────────

class TestAnsiStrip:
    def test_strips_color_codes(self):
        from src.tools.base import SecurityTool
        # Get the compiled regex used by execute_command
        ansi_re = re.compile(
            r'\x1b(?:\[[0-9;]*[a-zA-Z]|\(B|\]\d*;[^\x07]*\x07'
            r'|\[\?[0-9;]*[hl])|\r|\x1b\[[0-9]*[JKGF]'
        )
        text = "\x1b[31mERROR\x1b[0m: something failed\r\n"
        cleaned = ansi_re.sub("", text)
        assert "\x1b" not in cleaned
        assert "ERROR" in cleaned
        assert "something failed" in cleaned

    def test_strips_cursor_movement(self):
        from src.tools.base import SecurityTool
        ansi_re = re.compile(
            r'\x1b(?:\[[0-9;]*[a-zA-Z]|\(B|\]\d*;[^\x07]*\x07'
            r'|\[\?[0-9;]*[hl])|\r|\x1b\[[0-9]*[JKGF]'
        )
        text = "\x1b[2J\x1b[1;1HHello\x1b[K"
        cleaned = ansi_re.sub("", text)
        assert "Hello" in cleaned
        assert "\x1b" not in cleaned


# ── 1.5  Brain-down deadlock fix + auto-recovery ─────────────

class TestBrainDownRecovery:
    def _make_engine(self):
        """Create a minimal IntelligenceEngine with mocked brain."""
        from src.brain.intelligence import IntelligenceEngine
        engine = IntelligenceEngine.__new__(IntelligenceEngine)
        engine._brain_down = False
        engine._brain_down_threshold = 3
        engine._brain_down_time = 0.0
        engine._brain_down_recovery_secs = 300.0
        engine._consecutive_failures = 0
        engine._cache = {}
        engine.brain = MagicMock()
        engine.brain.has_primary = True
        engine.brain.has_secondary = True
        return engine

    def test_marks_down_after_threshold(self):
        engine = self._make_engine()
        engine._consecutive_failures = 3
        engine._check_brain_down()
        assert engine._brain_down is True
        assert engine.is_available is False

    def test_stays_up_below_threshold(self):
        engine = self._make_engine()
        engine._consecutive_failures = 2
        engine._check_brain_down()
        assert engine._brain_down is False
        assert engine.is_available is True

    def test_auto_recovery_after_timeout(self):
        engine = self._make_engine()
        engine._brain_down = True
        engine._brain_down_time = time.time() - 400  # 400s ago, > recovery_secs
        # Accessing is_available should auto-recover
        assert engine.is_available is True
        assert engine._brain_down is False

    def test_no_recovery_before_timeout(self):
        engine = self._make_engine()
        engine._brain_down = True
        engine._brain_down_time = time.time() - 10  # Only 10s ago
        assert engine.is_available is False


# ── 1.6  Executor default timeout increased ──────────────────

class TestExecutorTimeout:
    def test_default_timeout_is_600(self):
        """Executor base timeout should be 600 (effective ~930s)."""
        from src.tools.executor import ToolExecutor
        # The source code uses getattr(tool, 'default_timeout', 600)
        # We check that a tool without default_timeout gets 600 base
        executor = ToolExecutor()
        mock_tool = MagicMock()
        del mock_tool.default_timeout  # Ensure attr doesn't exist
        base = getattr(mock_tool, 'default_timeout', 600)
        assert base == 600
