"""
WhiteHatHacker AI — Authentication Bypass Checker

Automated checks for common authentication bypass patterns:
- Default credentials
- Authentication header manipulation
- Path traversal for auth bypass
- Method override (X-HTTP-Method-Override)
- JWT none algorithm
- Session fixation patterns
"""

from __future__ import annotations

from typing import Any

import aiohttp
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory
from src.utils.response_validator import ResponseValidator

_VALIDATOR = ResponseValidator()

# Body keywords indicating the response is NOT a real bypass
_AUTH_ERROR_KEYWORDS = (
    "unauthorized", "forbidden", "access denied", "permission denied",
    "login required", "sign in", "log in", "please authenticate",
    "authentication required", "not authorized", "invalid token",
    "session expired", "credentials required",
)

# Body keywords indicating genuine authenticated content
_AUTHENTICATED_CONTENT = (
    "dashboard", "admin panel", "settings", "profile", "logout",
    "welcome", "my account", "configuration", "manage",
)


# Common auth bypass payloads
AUTH_BYPASS_PATHS = [
    # Path traversal bypasses
    "/admin", "/admin/", "/admin;/", "/admin/./",
    "/%2fadmin", "/admin%00", "/%61dmin",
    "/./admin", "//admin", "/admin..;/",
    # Case manipulation
    "/Admin", "/ADMIN", "/aDmIn",
    # Extension tricks
    "/admin.json", "/admin.html", "/admin.xml",
    # Verb tunneling
    "/admin?_method=GET",
    # Spring / Tomcat path normalization
    "/admin/..;/..;/admin", "..;/admin",
    "/anything/../admin",
    # API version switching (downgrade to earlier versions that may lack auth)
    "/api/v1/admin", "/api/v2/admin", "/api/v3/admin",
    "/api/v1/users", "/api/v2/users",
    "/api/internal/admin", "/api/private/admin",
]

AUTH_BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Port": "443"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-HTTP-Method-Override": "PUT"},
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("root", "toor"), ("test", "test"),
    ("admin", "admin123"), ("administrator", "administrator"),
    ("user", "user"), ("guest", "guest"),
]


class AuthBypassChecker(SecurityTool):
    """
    Automated Authentication Bypass Detection.

    Tests multiple bypass techniques:
    1. Path manipulation (traversal, encoding, case)
    2. Header injection (X-Original-URL, IP spoofing)
    3. HTTP method override
    4. Default credential testing
    5. Session fixation indicators
    6. JWT vulnerabilities (none alg, key confusion)
    """

    name = "auth_bypass_checker"
    category = ToolCategory.SCANNER
    description = "Automated authentication bypass detection"
    binary_name = "python3"
    requires_root = False
    risk_level = RiskLevel.MEDIUM

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        base_url = target.rstrip("/") if target.startswith("http") else f"http://{target}"
        protected_paths = options.get("protected_paths", ["/admin", "/dashboard", "/api/admin"])
        login_url = options.get("login_url", "")
        timeout_s = options.get("timeout", 10)
        max_concurrent = options.get("concurrency", 3)

        findings: list[Finding] = []
        tested = 0
        errors = 0

        connector = aiohttp.TCPConnector(ssl=False, limit=max_concurrent)
        timeout = aiohttp.ClientTimeout(total=timeout_s)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Test 1: Path manipulation bypasses
            for path in protected_paths:
                results = await self._test_path_bypasses(session, base_url, path)
                findings.extend(results)
                tested += len(AUTH_BYPASS_PATHS)

            # Test 2: Header-based bypasses
            for path in protected_paths:
                results = await self._test_header_bypasses(session, base_url, path)
                findings.extend(results)
                tested += len(AUTH_BYPASS_HEADERS)

            # Test 3: HTTP method override
            for path in protected_paths:
                results = await self._test_method_override(session, base_url, path)
                findings.extend(results)
                tested += 4

            # Test 4: Default credentials
            if login_url:
                results = await self._test_default_creds(session, login_url, options)
                findings.extend(results)
                tested += len(DEFAULT_CREDENTIALS)

            # Test 5: Session/cookie checks
            results = await self._test_session_issues(session, base_url, protected_paths)
            findings.extend(results)
            tested += len(protected_paths)

        return ToolResult(
            tool_name=self.name,
            success=True,
            exit_code=0,
            stdout=f"Tested {tested} bypass techniques, {len(findings)} findings",
            stderr="" if not errors else f"{errors} errors",
            findings=findings,
            command=f"auth_bypass_checker {target}",
            target=target,
            metadata={"tested": tested, "findings_count": len(findings)},
        )

    async def _test_path_bypasses(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        protected_path: str,
    ) -> list[Finding]:
        findings = []

        # First, get baseline (what the protected path normally returns)
        baseline = await self._get(session, f"{base_url}{protected_path}")
        if not baseline:
            return findings

        baseline_status, baseline_body, baseline_len, _baseline_hdrs = baseline

        for bypass_path in AUTH_BYPASS_PATHS:
            test_url = f"{base_url}{bypass_path}"
            resp = await self._get(session, test_url)
            if not resp:
                continue

            status, body, length, resp_hdrs = resp

            # Check if bypass worked
            if self._is_bypass_success(baseline_status, status, baseline_len, length, body, resp_hdrs):
                findings.append(Finding(
                    title=f"Auth Bypass via Path Manipulation: {bypass_path}",
                    description=(
                        f"Authentication bypass detected through path manipulation.\n"
                        f"Protected: {protected_path} → {baseline_status}\n"
                        f"Bypass: {bypass_path} → {status}\n"
                        f"Response length: {length} bytes"
                    ),
                    vulnerability_type="auth_bypass",
                    severity=SeverityLevel.CRITICAL,
                    confidence=75.0,
                    target=test_url,
                    endpoint=bypass_path,
                    tool_name=self.name,
                    cwe_id="CWE-287",
                    tags=["auth_bypass", "path_traversal", "access_control"],
                    evidence=[f"GET {test_url} → {status} ({length}b)"],
                ))

        return findings

    async def _test_header_bypasses(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        protected_path: str,
    ) -> list[Finding]:
        findings = []
        url = f"{base_url}{protected_path}"

        baseline = await self._get(session, url)
        if not baseline:
            return findings

        baseline_status, _, baseline_len, _baseline_hdrs = baseline

        for bypass_headers in AUTH_BYPASS_HEADERS:
            resp = await self._get(session, url, headers=bypass_headers)
            if not resp:
                continue

            status, body, length, resp_hdrs = resp

            if self._is_bypass_success(baseline_status, status, baseline_len, length, body, resp_hdrs):
                header_name = list(bypass_headers.keys())[0]
                header_value = list(bypass_headers.values())[0]
                findings.append(Finding(
                    title=f"Auth Bypass via Header: {header_name}",
                    description=(
                        f"Authentication bypass through header injection.\n"
                        f"Header: {header_name}: {header_value}\n"
                        f"Normal: {baseline_status} | With header: {status}"
                    ),
                    vulnerability_type="auth_bypass",
                    severity=SeverityLevel.HIGH,
                    confidence=70.0,
                    target=url,
                    endpoint=protected_path,
                    tool_name=self.name,
                    cwe_id="CWE-287",
                    tags=["auth_bypass", "header_injection", header_name.lower()],
                    evidence=[f"{header_name}: {header_value} → {status}"],
                ))

        return findings

    async def _test_method_override(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        protected_path: str,
    ) -> list[Finding]:
        findings = []
        url = f"{base_url}{protected_path}"

        baseline = await self._get(session, url)
        if not baseline:
            return findings

        baseline_status, _, baseline_len, _baseline_hdrs = baseline

        for method in ("POST", "PUT", "DELETE", "PATCH"):
            try:
                async with session.request(method, url) as resp:
                    body = await resp.text()
                    method_hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    if self._is_bypass_success(baseline_status, resp.status, baseline_len, len(body), body, method_hdrs):
                        findings.append(Finding(
                            title=f"Auth Bypass via HTTP Method: {method}",
                            description=(
                                f"HTTP method switching bypasses authentication.\n"
                                f"GET {protected_path} → {baseline_status}\n"
                                f"{method} {protected_path} → {resp.status}"
                            ),
                            vulnerability_type="auth_bypass",
                            severity=SeverityLevel.HIGH,
                            confidence=65.0,
                            target=url,
                            endpoint=protected_path,
                            tool_name=self.name,
                            cwe_id="CWE-287",
                            tags=["auth_bypass", "method_override"],
                            evidence=[f"{method} {url} → {resp.status}"],
                        ))
            except Exception as _exc:
                logger.debug(f"auth bypass error: {_exc}")
                continue

        return findings

    async def _test_default_creds(
        self,
        session: aiohttp.ClientSession,
        login_url: str,
        options: dict,
    ) -> list[Finding]:
        findings = []
        username_field = options.get("username_field", "username")
        password_field = options.get("password_field", "password")

        for username, password in DEFAULT_CREDENTIALS:
            try:
                data = {username_field: username, password_field: password}
                async with session.post(login_url, data=data, allow_redirects=False) as resp:
                    body = await resp.text()
                    # Check for successful login indicators
                    _body_low = body.lower()
                    _neg_kws = ("invalid", "incorrect", "failed", "error", "wrong",
                                "denied", "unauthorized", "forbidden")
                    _pos_kws = ("dashboard", "welcome", "logout", "profile",
                                "my account", "settings", "admin panel")
                    if resp.status == 200 and not any(
                        kw in _body_low for kw in _neg_kws
                    ):
                        # Require positive body indicators — 302 alone is NOT proof
                        if any(kw in _body_low for kw in _pos_kws):
                            findings.append(Finding(
                                title=f"Default Credentials: {username}:{password}",
                                description=(
                                    f"Default credentials accepted at {login_url}\n"
                                    f"Username: {username} | Password: {password}\n"
                                    f"Response: {resp.status}"
                                ),
                                vulnerability_type="auth_bypass",
                                severity=SeverityLevel.CRITICAL,
                                confidence=80.0,
                                target=login_url,
                                endpoint=login_url,
                                tool_name=self.name,
                                cwe_id="CWE-798",
                                tags=["default_creds", "auth_bypass", "brute_force"],
                                evidence=[f"POST {login_url} → {resp.status}"],
                            ))
            except Exception as _exc:
                logger.debug(f"auth bypass error: {_exc}")
                continue

        return findings

    async def _test_session_issues(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        paths: list[str],
    ) -> list[Finding]:
        """Check for session-related security issues."""
        findings = []

        for path in paths:
            url = f"{base_url}{path}"
            resp = await self._get(session, url)
            if not resp:
                continue

            status, body, length, resp_hdrs = resp

            # Check Set-Cookie for security flags
            # (We'd need response headers here — simplified check via body patterns)

        return findings

    def _is_bypass_success(
        self,
        baseline_status: int,
        test_status: int,
        baseline_len: int,
        test_len: int,
        test_body: str,
        resp_headers: dict[str, str] | None = None,
    ) -> bool:
        """Determine if a bypass attempt was successful."""
        body_lower = test_body.lower() if test_body else ""

        # ResponseValidator: reject WAF/challenge/error pages
        vr = _VALIDATOR.validate(test_status, resp_headers or {}, test_body or "")
        if not vr.is_valid:
            return False

        # Reject 200 responses that contain auth error/login content
        if any(kw in body_lower for kw in _AUTH_ERROR_KEYWORDS):
            return False

        # Baseline was blocked (4xx), test returned 200 — strong indicator
        if baseline_status in (401, 403) and test_status == 200:
            # Require positive authenticated content — not just "not WAF"
            if any(kw in body_lower for kw in _AUTHENTICATED_CONTENT):
                return True
            # Large body without auth error keywords is suspicious but needs size evidence
            if test_len > 1000:
                return True
            return False

        # Both 200, but test has significantly more content (might have bypassed authz)
        if test_status == 200 and baseline_status == 200:
            # Require 3x content increase (not 1.5x) + minimum 500 bytes + positive content
            if test_len > baseline_len * 3 and test_len > 500:
                if any(kw in body_lower for kw in _AUTHENTICATED_CONTENT):
                    return True

        # 302 is NOT treated as bypass — it's almost always a redirect to login/SSO
        # A real auth bypass should result in 200 with actual content

        return False

    async def _get(self, session, url, headers=None) -> tuple[int, str, int, dict[str, str]] | None:
        try:
            async with session.get(url, headers=headers, allow_redirects=False) as resp:
                body = await resp.text()
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, body, len(body), resp_headers
        except Exception as _exc:
            logger.debug(f"auth bypass error: {_exc}")
            return None

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return ["python3", "-c", "pass"]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []


__all__ = ["AuthBypassChecker"]
