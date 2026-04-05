"""Tests for HTTP/2 & HTTP/3 security checker — constants + structure."""

import pytest

from src.tools.scanners.custom_checks.http2_http3_checker import (
    _H2C_UPGRADE_HEADERS,
    _H2C_SENSITIVE_PATHS,
    check_http2_http3_security,
)


# ── Constants ────────────────────────────────────────────

def test_h2c_upgrade_headers_populated():
    assert isinstance(_H2C_UPGRADE_HEADERS, list)
    assert len(_H2C_UPGRADE_HEADERS) >= 3
    for entry in _H2C_UPGRADE_HEADERS:
        assert isinstance(entry, dict)
        # Should have Upgrade or Connection header
        has_relevant = any(
            k.lower() in ("upgrade", "connection", "http2-settings")
            for k in entry
        )
        assert has_relevant, f"Header variant missing upgrade keys: {entry}"


def test_h2c_sensitive_paths_populated():
    assert isinstance(_H2C_SENSITIVE_PATHS, list)
    assert len(_H2C_SENSITIVE_PATHS) >= 5
    for path in _H2C_SENSITIVE_PATHS:
        assert isinstance(path, str)
        assert path.startswith("/")


def test_sensitive_paths_include_admin():
    paths_lower = [p.lower() for p in _H2C_SENSITIVE_PATHS]
    assert any("admin" in p for p in paths_lower)


# ── Async function signature ─────────────────────────────

def test_check_function_is_coroutine():
    import asyncio
    assert asyncio.iscoroutinefunction(check_http2_http3_security)


def test_check_function_empty_targets():
    """Empty targets should return empty findings."""
    import asyncio

    result = asyncio.run(check_http2_http3_security(targets=[]))
    assert isinstance(result, list)
    assert len(result) == 0
