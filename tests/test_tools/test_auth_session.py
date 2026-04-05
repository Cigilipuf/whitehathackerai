"""Tests for AuthSessionManager (V14-T0)."""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.tools.auth.session_manager import (
    AuthConfig,
    AuthSessionManager,
    AuthState,
    AuthType,
    build_auth_session,
)


# ── AuthConfig.from_dict ──────────────────────────────────────

class TestAuthConfigFromDict:
    def test_empty_returns_defaults(self):
        cfg = AuthConfig.from_dict({})
        assert cfg.auth_type == AuthType.NONE
        assert cfg.login_url == ""
        assert cfg.token == ""

    def test_bearer_token(self):
        cfg = AuthConfig.from_dict({
            "auth_type": "bearer_token",
            "token": "my-jwt-123",
            "header_name": "Authorization",
            "header_prefix": "Bearer",
        })
        assert cfg.auth_type == AuthType.BEARER_TOKEN
        assert cfg.token == "my-jwt-123"
        assert cfg.header_prefix == "Bearer"

    def test_form_login(self):
        cfg = AuthConfig.from_dict({
            "auth_type": "form_login",
            "login_url": "https://example.com/login",
            "username": "admin",
            "password": "pass",
            "csrf_enabled": True,
        })
        assert cfg.auth_type == AuthType.FORM_LOGIN
        assert cfg.login_url == "https://example.com/login"
        assert cfg.csrf_enabled is True

    def test_unknown_type_falls_back_to_none(self):
        cfg = AuthConfig.from_dict({"auth_type": "magic_auth"})
        assert cfg.auth_type == AuthType.NONE

    def test_api_key(self):
        cfg = AuthConfig.from_dict({
            "auth_type": "api_key",
            "token": "ak_12345",
            "header_name": "X-API-Key",
        })
        assert cfg.auth_type == AuthType.API_KEY
        assert cfg.header_name == "X-API-Key"

    def test_custom_headers(self):
        cfg = AuthConfig.from_dict({
            "auth_type": "custom_headers",
            "custom_headers": {"X-Custom": "val", "X-Other": "val2"},
        })
        assert cfg.auth_type == AuthType.CUSTOM_HEADERS
        assert len(cfg.custom_headers) == 2


# ── Static auth strategies ────────────────────────────────────

class TestStaticAuth:
    @pytest.fixture
    def bearer_mgr(self):
        cfg = AuthConfig(auth_type=AuthType.BEARER_TOKEN, token="tok123")
        return AuthSessionManager(cfg)

    @pytest.fixture
    def apikey_mgr(self):
        cfg = AuthConfig(
            auth_type=AuthType.API_KEY, token="key-abc", header_name="X-API-Key"
        )
        return AuthSessionManager(cfg)

    @pytest.fixture
    def custom_mgr(self):
        cfg = AuthConfig(
            auth_type=AuthType.CUSTOM_HEADERS,
            custom_headers={"X-A": "1", "X-B": "2"},
        )
        return AuthSessionManager(cfg)

    def test_bearer_auth(self, bearer_mgr):
        async def _t():
            ok = await bearer_mgr.authenticate()
            assert ok is True
            assert bearer_mgr.is_authenticated
            hdrs = bearer_mgr.get_auth_headers()
            assert hdrs["Authorization"] == "Bearer tok123"
        asyncio.run(_t())

    def test_apikey_auth(self, apikey_mgr):
        async def _t():
            ok = await apikey_mgr.authenticate()
            assert ok is True
            hdrs = apikey_mgr.get_auth_headers()
            assert hdrs["X-API-Key"] == "key-abc"
        asyncio.run(_t())

    def test_custom_headers(self, custom_mgr):
        async def _t():
            ok = await custom_mgr.authenticate()
            assert ok is True
            hdrs = custom_mgr.get_auth_headers()
            assert hdrs["X-A"] == "1"
            assert hdrs["X-B"] == "2"
        asyncio.run(_t())

    def test_bearer_no_token_fails(self):
        async def _t():
            mgr = AuthSessionManager(AuthConfig(auth_type=AuthType.BEARER_TOKEN, token=""))
            ok = await mgr.authenticate()
            assert ok is False
            assert not mgr.is_authenticated
        asyncio.run(_t())

    def test_none_auth_always_valid(self):
        async def _t():
            mgr = AuthSessionManager(AuthConfig(auth_type=AuthType.NONE))
            ok = await mgr.authenticate()
            assert ok is True
        asyncio.run(_t())


# ── CLI flag generation ───────────────────────────────────────

class TestCLIFlags:
    def test_cli_flags_include_cookie(self):
        async def _t():
            cfg = AuthConfig(auth_type=AuthType.BEARER_TOKEN, token="x")
            mgr = AuthSessionManager(cfg)
            await mgr.authenticate()
            mgr.state.cookies = {"session": "abc123"}
            flags = mgr.get_cli_header_flags()
            assert "-H" in flags
            assert "Authorization: Bearer x" in flags
            assert "Cookie: session=abc123" in flags
        asyncio.run(_t())

    def test_cookie_header_format(self):
        mgr = AuthSessionManager(AuthConfig())
        mgr.state.cookies = {"a": "1", "b": "2"}
        cookie_str = mgr.get_cookie_header()
        assert "a=1" in cookie_str
        assert "b=2" in cookie_str


# ── ensure_valid & refresh ────────────────────────────────────

class TestRefresh:
    def test_ensure_valid_none_type(self):
        async def _t():
            mgr = AuthSessionManager(AuthConfig(auth_type=AuthType.NONE))
            ok = await mgr.ensure_valid()
            assert ok is True
        asyncio.run(_t())

    def test_ensure_valid_static_bearer(self):
        async def _t():
            cfg = AuthConfig(auth_type=AuthType.BEARER_TOKEN, token="t")
            mgr = AuthSessionManager(cfg)
            await mgr.authenticate()
            ok = await mgr.ensure_valid()
            assert ok is True
        asyncio.run(_t())

    def test_handle_auth_failure_limit(self):
        async def _t():
            cfg = AuthConfig(auth_type=AuthType.BEARER_TOKEN, token="t")
            mgr = AuthSessionManager(cfg)
            await mgr.authenticate()
            # Exhaust refresh attempts
            for _ in range(4):
                await mgr.handle_auth_failure()
            result = await mgr.handle_auth_failure()
            assert result is False  # Limit exceeded
        asyncio.run(_t())


# ── CSRF extraction ───────────────────────────────────────────

class TestCSRF:
    def test_csrf_from_meta(self):
        mgr = AuthSessionManager(AuthConfig())
        html = '<meta name="csrf-token" content="abc123">'
        token = mgr._extract_csrf(html, {})
        assert token == "abc123"

    def test_csrf_from_input(self):
        mgr = AuthSessionManager(AuthConfig())
        html = '<input type="hidden" name="_token" value="xyz789">'
        token = mgr._extract_csrf(html, {})
        assert token == "xyz789"

    def test_csrf_from_header(self):
        mgr = AuthSessionManager(AuthConfig())
        token = mgr._extract_csrf("", {"x-csrf-token": "hdr_tok"})
        assert token == "hdr_tok"

    def test_csrf_not_found(self):
        mgr = AuthSessionManager(AuthConfig())
        token = mgr._extract_csrf("<html></html>", {})
        assert token == ""


# ── build_auth_session helper ─────────────────────────────────

class TestBuildAuthSession:
    def test_no_auth_returns_none(self):
        assert build_auth_session({}) is None

    def test_none_type_returns_none(self):
        assert build_auth_session({"auth": {"auth_type": "none"}}) is None

    def test_bearer_returns_manager(self):
        mgr = build_auth_session({
            "auth": {"auth_type": "bearer_token", "token": "t"}
        })
        assert mgr is not None
        assert isinstance(mgr, AuthSessionManager)

    def test_authentication_key_alias(self):
        mgr = build_auth_session({
            "authentication": {"auth_type": "api_key", "token": "k"}
        })
        assert mgr is not None


# ── Executor injection ────────────────────────────────────────

class TestExecutorInjection:
    def test_inject_auth_no_session(self):
        from src.tools.executor import ToolExecutor
        executor = ToolExecutor()
        opts = executor._inject_auth({"foo": "bar"})
        assert opts == {"foo": "bar"}

    def test_inject_auth_with_session(self):
        async def _t():
            from src.tools.executor import ToolExecutor
            cfg = AuthConfig(auth_type=AuthType.BEARER_TOKEN, token="t1")
            mgr = AuthSessionManager(cfg)
            await mgr.authenticate()

            executor = ToolExecutor()
            executor.auth_session = mgr
            opts = executor._inject_auth({})
            assert opts["headers"]["Authorization"] == "Bearer t1"
            assert "_auth_cli_flags" in opts
        asyncio.run(_t())

    def test_tool_level_headers_win(self):
        async def _t():
            from src.tools.executor import ToolExecutor
            cfg = AuthConfig(auth_type=AuthType.BEARER_TOKEN, token="auth-token")
            mgr = AuthSessionManager(cfg)
            await mgr.authenticate()

            executor = ToolExecutor()
            executor.auth_session = mgr
            opts = executor._inject_auth({"headers": {"Authorization": "Override"}})
            # Tool-level override should win
            assert opts["headers"]["Authorization"] == "Override"
        asyncio.run(_t())
