"""WhiteHatHacker AI — Pytest Configuration & Shared Fixtures."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Event loop
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Temp directories
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_output_dir(tmp_path: Path) -> Path:
    """Temporary output directory for test artefacts."""
    out = tmp_path / "output"
    out.mkdir()
    (out / "reports").mkdir()
    (out / "screenshots").mkdir()
    (out / "evidence").mkdir()
    (out / "logs").mkdir()
    return out


@pytest.fixture
def tmp_config_dir(tmp_path: Path) -> Path:
    """Temporary config directory."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    return cfg


# ---------------------------------------------------------------------------
# Mock brain engine
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_brain_engine() -> MagicMock:
    """Mock BrainEngine that returns canned responses."""
    engine = MagicMock()
    engine.is_loaded = True
    engine.query = AsyncMock(return_value={
        "response": "Test brain response",
        "model": "test-model",
        "tokens_used": 100,
    })
    engine.query_primary = AsyncMock(return_value="Primary brain response")
    engine.query_secondary = AsyncMock(return_value="Secondary brain response")
    return engine


# ---------------------------------------------------------------------------
# Sample findings
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_finding() -> dict[str, Any]:
    """A single sample vulnerability finding."""
    return {
        "tool_name": "sqlmap",
        "vulnerability_type": "sqli",
        "title": "SQL Injection in login parameter",
        "severity": "high",
        "target": "https://example.com/login",
        "parameter": "username",
        "payload": "' OR '1'='1",
        "confidence": 85.0,
        "description": "Boolean-based blind SQL injection",
        "evidence": "Response differs with payload",
        "metadata": {},
    }


@pytest.fixture
def sample_findings() -> list[dict[str, Any]]:
    """Multiple sample findings across severity levels."""
    return [
        {
            "tool_name": "sqlmap",
            "vulnerability_type": "sqli",
            "title": "SQL Injection in search",
            "severity": "critical",
            "target": "https://example.com/search",
            "parameter": "q",
            "confidence": 95.0,
        },
        {
            "tool_name": "dalfox",
            "vulnerability_type": "xss",
            "title": "Reflected XSS in name param",
            "severity": "high",
            "target": "https://example.com/profile",
            "parameter": "name",
            "confidence": 80.0,
        },
        {
            "tool_name": "nikto",
            "vulnerability_type": "web-server",
            "title": "Server header information disclosure",
            "severity": "info",
            "target": "https://example.com/",
            "confidence": 60.0,
        },
        {
            "tool_name": "custom",
            "vulnerability_type": "idor",
            "title": "IDOR in user profile endpoint",
            "severity": "medium",
            "target": "https://example.com/api/users/123",
            "confidence": 70.0,
        },
    ]


# ---------------------------------------------------------------------------
# Scope config
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_scope() -> dict[str, Any]:
    """Sample scope configuration."""
    return {
        "target": "example.com",
        "in_scope": [
            {"type": "domain", "value": "*.example.com"},
            {"type": "ip", "value": "93.184.216.34"},
        ],
        "out_of_scope": [
            {"type": "domain", "value": "admin.example.com"},
        ],
        "rules": {
            "max_rps": 10,
            "no_dos": True,
            "no_social_engineering": True,
        },
    }


# ---------------------------------------------------------------------------
# HTTP context fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_http_context() -> dict[str, Any]:
    """Sample HTTP request/response context."""
    return {
        "request_method": "GET",
        "request_url": "https://example.com/search?q=test",
        "request_headers": {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html",
        },
        "request_body": "",
        "response_status": 200,
        "response_headers": {
            "Content-Type": "text/html; charset=utf-8",
            "Server": "nginx/1.21",
        },
        "response_body": "<html><body>Search results for: test</body></html>",
        "response_time_ms": 150.0,
    }


# ---------------------------------------------------------------------------
# Mock tool executor
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_tool_executor() -> MagicMock:
    """Mock ToolExecutor."""
    executor = MagicMock()
    executor.execute = AsyncMock(return_value={
        "stdout": "tool output",
        "stderr": "",
        "return_code": 0,
        "duration": 5.0,
    })
    return executor


# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _set_test_env(monkeypatch: pytest.MonkeyPatch, tmp_output_dir: Path) -> None:
    """Set environment variables for test runs."""
    monkeypatch.setenv("WHAI_MODE", "semi-autonomous")
    monkeypatch.setenv("WHAI_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("WHAI_SCAN_PROFILE", "balanced")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_output_dir / 'test.db'}")
