"""
WhiteHatHacker AI — Authenticated Session Manager

Maintains authenticated sessions (cookies, JWT, bearer tokens, custom headers)
across all scanner tools in the pipeline.  Handles:
  1. Form-based login (POST + cookie capture)
  2. Bearer / API-key based auth (static header injection)
  3. OAuth2 client-credentials flow
  4. Auto-refresh on 401/403 (re-login with back-off)
  5. CSRF token extraction from HTML meta tags / response headers
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx
from loguru import logger


# ── Auth types ────────────────────────────────────────────────

class AuthType(str, Enum):
    NONE = "none"
    FORM_LOGIN = "form_login"          # POST form → capture Set-Cookie
    BEARER_TOKEN = "bearer_token"      # Static Authorization: Bearer <token>
    API_KEY = "api_key"                # Static header (X-API-Key, etc.)
    CUSTOM_HEADERS = "custom_headers"  # Arbitrary static headers
    OAUTH2_CLIENT = "oauth2_client"    # OAuth2 client_credentials flow


@dataclass
class AuthConfig:
    """Parsed from scope YAML ``auth:`` section."""

    auth_type: AuthType = AuthType.NONE

    # Form login fields
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    extra_fields: dict[str, str] = field(default_factory=dict)

    # Bearer / API key
    token: str = ""
    header_name: str = "Authorization"
    header_prefix: str = "Bearer"

    # OAuth2
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scopes: list[str] = field(default_factory=list)

    # Custom headers (injected as-is)
    custom_headers: dict[str, str] = field(default_factory=dict)

    # CSRF
    csrf_enabled: bool = False
    csrf_field: str = "_token"
    csrf_header: str = "X-CSRF-TOKEN"

    # Role name (for multi-role IDOR testing)
    role_name: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthConfig":
        """Build from scope YAML auth section."""
        if not data:
            return cls()
        auth_type_str = data.get("auth_type", data.get("type", "none"))
        try:
            auth_type = AuthType(auth_type_str)
        except ValueError:
            logger.warning(f"Unknown auth_type '{auth_type_str}', defaulting to none")
            auth_type = AuthType.NONE

        return cls(
            auth_type=auth_type,
            login_url=data.get("login_url", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            username_field=data.get("username_field", "username"),
            password_field=data.get("password_field", "password"),
            extra_fields=data.get("extra_fields", {}),
            token=data.get("token", ""),
            header_name=data.get("header_name", "Authorization"),
            header_prefix=data.get("header_prefix", "Bearer"),
            token_url=data.get("token_url", ""),
            client_id=data.get("client_id", ""),
            client_secret=data.get("client_secret", ""),
            scopes=data.get("scopes", []),
            custom_headers=data.get("custom_headers", {}),
            csrf_enabled=data.get("csrf_enabled", False),
            csrf_field=data.get("csrf_field", "_token"),
            csrf_header=data.get("csrf_header", "X-CSRF-TOKEN"),
            role_name=data.get("role_name", data.get("role", "")),
        )


# ── Session state ─────────────────────────────────────────────

@dataclass
class AuthState:
    """Current authenticated session state."""

    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    csrf_token: str = ""
    authenticated_at: float = 0.0
    refresh_count: int = 0
    is_valid: bool = False

    @property
    def age_seconds(self) -> float:
        if self.authenticated_at == 0.0:
            return 0.0
        return time.monotonic() - self.authenticated_at


# ── Auth Session Manager ──────────────────────────────────────

_CSRF_META_RE = re.compile(
    r'<meta\s+[^>]*name=["\']csrf[_-]?token["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_CSRF_INPUT_RE = re.compile(
    r'<input\s+[^>]*name=["\'](?:_token|csrf_token|csrfmiddlewaretoken|authenticity_token)["\']'
    r'[^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

MAX_REFRESH_ATTEMPTS = 3
SESSION_MAX_AGE = 1800  # 30 min — re-authenticate after this


class AuthSessionManager:
    """Manages authenticated sessions for the entire scan pipeline.

    Usage::

        mgr = AuthSessionManager(config)
        await mgr.authenticate()

        # Get headers/cookies to inject into tools
        headers = mgr.get_auth_headers()
        cookies = mgr.get_auth_cookies()

        # Check & refresh before each tool run
        await mgr.ensure_valid()
    """

    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self.state = AuthState()
        self._lock = asyncio.Lock()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
                verify=True,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ── Public API ────────────────────────────────────────────

    async def authenticate(self) -> bool:
        """Perform initial authentication. Returns True on success."""
        async with self._lock:
            return await self._do_authenticate()

    async def ensure_valid(self) -> bool:
        """Check session validity; refresh if expired."""
        if self.config.auth_type == AuthType.NONE:
            return True  # No auth needed

        # Static auth types don't expire
        if self.config.auth_type in (AuthType.BEARER_TOKEN, AuthType.API_KEY, AuthType.CUSTOM_HEADERS):
            return self.state.is_valid

        # Session-based: check age
        if self.state.age_seconds > SESSION_MAX_AGE:
            logger.info(f"Auth session expired ({self.state.age_seconds:.0f}s), refreshing")
            async with self._lock:
                return await self._do_authenticate()

        return self.state.is_valid

    async def handle_auth_failure(self) -> bool:
        """Called when a tool gets 401/403 — try to re-authenticate."""
        if self.state.refresh_count >= MAX_REFRESH_ATTEMPTS:
            logger.warning(
                f"Auth refresh limit reached ({MAX_REFRESH_ATTEMPTS}), giving up"
            )
            return False

        async with self._lock:
            self.state.refresh_count += 1
            # Back-off: 2^refresh_count seconds
            delay = min(2 ** self.state.refresh_count, 16)
            logger.info(
                f"Re-authenticating (attempt {self.state.refresh_count}/{MAX_REFRESH_ATTEMPTS}), "
                f"delay={delay}s"
            )
            await asyncio.sleep(delay)
            return await self._do_authenticate()

    def get_auth_headers(self) -> dict[str, str]:
        """Get current authentication headers for tool injection."""
        headers = dict(self.state.headers)
        if self.state.csrf_token and self.config.csrf_enabled:
            headers[self.config.csrf_header] = self.state.csrf_token
        return headers

    def get_auth_cookies(self) -> dict[str, str]:
        """Get current session cookies."""
        return dict(self.state.cookies)

    def get_cookie_header(self) -> str:
        """Format cookies as a Cookie header value."""
        if not self.state.cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in self.state.cookies.items())

    def get_cli_header_flags(self, flag: str = "-H") -> list[str]:
        """Build CLI flags for injecting auth headers into external tools.

        Example: ['-H', 'Authorization: Bearer xxx', '-H', 'Cookie: sess=abc']
        """
        flags: list[str] = []
        for name, value in self.get_auth_headers().items():
            flags.extend([flag, f"{name}: {value}"])
        cookie_header = self.get_cookie_header()
        if cookie_header:
            flags.extend([flag, f"Cookie: {cookie_header}"])
        return flags

    @property
    def is_authenticated(self) -> bool:
        return self.state.is_valid

    # ── Internal authentication logic ─────────────────────────

    async def _do_authenticate(self) -> bool:
        """Dispatch to the correct auth strategy."""
        auth_type = self.config.auth_type

        if auth_type == AuthType.NONE:
            self.state.is_valid = True
            return True

        if auth_type == AuthType.BEARER_TOKEN:
            return self._apply_bearer()

        if auth_type == AuthType.API_KEY:
            return self._apply_api_key()

        if auth_type == AuthType.CUSTOM_HEADERS:
            return self._apply_custom_headers()

        if auth_type == AuthType.FORM_LOGIN:
            return await self._form_login()

        if auth_type == AuthType.OAUTH2_CLIENT:
            return await self._oauth2_client_credentials()

        logger.error(f"Unsupported auth type: {auth_type}")
        return False

    def _apply_bearer(self) -> bool:
        if not self.config.token:
            logger.error("Bearer token auth configured but no token provided")
            return False
        prefix = self.config.header_prefix
        self.state.headers[self.config.header_name] = (
            f"{prefix} {self.config.token}" if prefix else self.config.token
        )
        self.state.authenticated_at = time.monotonic()
        self.state.is_valid = True
        logger.info("Auth: bearer token applied")
        return True

    def _apply_api_key(self) -> bool:
        if not self.config.token:
            logger.error("API key auth configured but no token provided")
            return False
        self.state.headers[self.config.header_name] = self.config.token
        self.state.authenticated_at = time.monotonic()
        self.state.is_valid = True
        logger.info(f"Auth: API key applied via header '{self.config.header_name}'")
        return True

    def _apply_custom_headers(self) -> bool:
        if not self.config.custom_headers:
            logger.error("Custom headers auth configured but no headers provided")
            return False
        self.state.headers.update(self.config.custom_headers)
        self.state.authenticated_at = time.monotonic()
        self.state.is_valid = True
        logger.info(f"Auth: {len(self.config.custom_headers)} custom headers applied")
        return True

    async def _form_login(self) -> bool:
        """Perform form-based login and capture session cookies."""
        if not self.config.login_url:
            logger.error("Form login configured but no login_url provided")
            return False

        client = await self._get_client()

        try:
            # Step 1: GET login page for CSRF token
            csrf_token = ""
            if self.config.csrf_enabled:
                get_resp = await client.get(self.config.login_url)
                csrf_token = self._extract_csrf(get_resp.text, dict(get_resp.headers))
                if csrf_token:
                    logger.debug(f"CSRF token extracted: {csrf_token[:8]}...")

            # Step 2: POST login form
            form_data = {
                self.config.username_field: self.config.username,
                self.config.password_field: self.config.password,
            }
            if csrf_token:
                form_data[self.config.csrf_field] = csrf_token
            form_data.update(self.config.extra_fields)

            resp = await client.post(
                self.config.login_url,
                data=form_data,
            )

            # Step 3: Capture cookies
            cookies = dict(resp.cookies)
            # Also merge redirect-chain cookies from client jar
            for cookie in client.cookies.jar:
                cookies[cookie.name] = cookie.value

            if not cookies:
                logger.warning("Form login completed but no cookies received")
                return False

            self.state.cookies = cookies
            self.state.authenticated_at = time.monotonic()
            self.state.is_valid = True

            # Build Cookie header for injection
            cookie_str = self.get_cookie_header()
            self.state.headers["Cookie"] = cookie_str

            logger.info(
                f"Auth: form login successful, {len(cookies)} cookies captured "
                f"(status={resp.status_code})"
            )
            return True

        except httpx.HTTPError as exc:
            logger.error(f"Form login failed: {exc}")
            return False

    async def _oauth2_client_credentials(self) -> bool:
        """OAuth2 client_credentials flow."""
        if not self.config.token_url:
            logger.error("OAuth2 configured but no token_url provided")
            return False

        client = await self._get_client()

        try:
            resp = await client.post(
                self.config.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "scope": " ".join(self.config.scopes),
                },
            )

            if resp.status_code != 200:
                logger.error(f"OAuth2 token request failed: {resp.status_code}")
                return False

            data = resp.json()
            access_token = data.get("access_token", "")
            if not access_token:
                logger.error("OAuth2 response missing access_token")
                return False

            token_type = data.get("token_type", "Bearer")
            self.state.headers["Authorization"] = f"{token_type} {access_token}"
            self.state.authenticated_at = time.monotonic()
            self.state.is_valid = True

            logger.info(
                f"Auth: OAuth2 client_credentials successful "
                f"(expires_in={data.get('expires_in', 'unknown')})"
            )
            return True

        except httpx.HTTPError as exc:
            logger.error(f"OAuth2 token request failed: {exc}")
            return False

    def _extract_csrf(self, html: str, headers: dict[str, str]) -> str:
        """Extract CSRF token from HTML meta tags, hidden inputs, or response headers."""
        # Try meta tag
        meta_match = _CSRF_META_RE.search(html)
        if meta_match:
            return meta_match.group(1)

        # Try hidden input
        input_match = _CSRF_INPUT_RE.search(html)
        if input_match:
            return input_match.group(1)

        # Try response header
        for hdr in ("x-csrf-token", "x-xsrf-token"):
            val = headers.get(hdr, "")
            if val:
                return val

        return ""


# ── Helper: Build from scope config ──────────────────────────

def build_auth_session(scope_config: dict[str, Any]) -> AuthSessionManager | None:
    """Build AuthSessionManager from scope YAML config.

    Returns None if no auth section is present or auth_type is 'none'.
    """
    auth_data = scope_config.get("auth") or scope_config.get("authentication")
    if not auth_data:
        return None

    config = AuthConfig.from_dict(auth_data)
    if config.auth_type == AuthType.NONE:
        return None

    return AuthSessionManager(config)


def build_auth_roles(scope_config: dict[str, Any]) -> list[AuthSessionManager]:
    """Build multiple AuthSessionManagers from scope YAML ``auth.roles`` list.

    Scope YAML example::

        auth:
          auth_type: bearer_token
          token: "admin-token"
          role_name: admin
          roles:
            - role_name: editor
              auth_type: bearer_token
              token: "editor-token"
            - role_name: viewer
              auth_type: bearer_token
              token: "viewer-token"

    Returns list of AuthSessionManagers — one per role (including the
    primary auth section if present). Empty list if no roles configured.
    """
    managers: list[AuthSessionManager] = []
    auth_data = scope_config.get("auth") or scope_config.get("authentication")
    if not auth_data:
        return managers

    # Primary auth section is the first role
    primary = AuthConfig.from_dict(auth_data)
    if primary.auth_type != AuthType.NONE:
        if not primary.role_name:
            primary.role_name = "primary"
        managers.append(AuthSessionManager(primary))

    # Additional roles
    roles_list = auth_data.get("roles", [])
    for role_data in roles_list:
        if not isinstance(role_data, dict):
            continue
        # Inherit common fields from parent auth section
        merged = {**auth_data, **role_data}
        merged.pop("roles", None)  # Don't recurse
        config = AuthConfig.from_dict(merged)
        if config.auth_type != AuthType.NONE:
            if not config.role_name:
                config.role_name = f"role_{len(managers)}"
            managers.append(AuthSessionManager(config))

    return managers
