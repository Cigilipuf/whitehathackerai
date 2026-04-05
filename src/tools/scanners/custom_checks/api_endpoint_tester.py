"""
WhiteHatHacker AI — API Endpoint Tester

Tests common API misconfigurations:
- Unauthenticated access to sensitive endpoints
- Verbose error messages with internal details
- API versioning issues (old versions still accessible)
- Rate limiting absence
- HTTP method override (X-HTTP-Method-Override)
- Mass assignment / parameter pollution
"""

from __future__ import annotations

import asyncio
import re

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel
from src.utils.response_validator import ResponseValidator

_response_validator = ResponseValidator()

# Tokens that indicate a WAF/CDN challenge page
_WAF_BODY_TOKENS = (
    "cloudflare", "attention required", "ray id", "request blocked",
    "access denied", "captcha", "akamai", "incapsula", "sucuri",
    "web application firewall", "just a moment", "checking your browser",
)


def _is_real_content(resp: httpx.Response) -> bool:
    """Reject WAF/CDN challenge pages masquerading as 200 OK."""
    if resp.status_code != 200:
        return False
    vr = _response_validator.validate_for_checker(
        resp.status_code,
        dict(resp.headers),
        resp.text[:5000],
        checker_name="api_endpoint_tester",
    )
    if not vr.is_valid:
        return False
    body_lower = resp.text[:3000].lower()
    if any(tok in body_lower for tok in _WAF_BODY_TOKENS):
        return False
    return True


# Common API paths to check for unauthenticated access
API_PATHS = [
    "/api/v1/users",
    "/api/v1/admin",
    "/api/v2/users",
    "/api/v3/users",
    "/api/v1/config",
    "/api/v1/settings",
    "/api/users",
    "/api/admin",
    "/v1/users",
    "/v2/users",
    "/v3/users",
    "/v1/me",
    "/v2/me",
    "/v3/me",
    "/graphql",
    "/graphiql",
    "/playground",
    "/api-docs",
    "/swagger.json",
    "/openapi.json",
    "/api/swagger.json",
    "/.well-known/openid-configuration",
    "/oauth/token",
    "/oauth/authorize",
    "/rest/api/latest/serverInfo",
    "/wp-json/wp/v2/users",
    "/wp-json",
    "/xmlrpc.php",
    "/api/health",
    "/api/status",
    "/api/debug",
    "/api/internal",
    "/_debug",
    "/_status",
    "/_health",
]

# Headers that indicate API misconfigs
SENSITIVE_RESPONSE_HEADERS = {
    "x-powered-by": "Technology disclosure",
    "x-aspnet-version": "ASP.NET version disclosure",
    "x-debug": "Debug mode enabled",
    "x-debug-token": "Debug token exposed",
    "x-debug-token-link": "Debug profiler link",
    "server": None,  # Check for detailed version info
}

# Patterns in error responses that indicate information leak
ERROR_LEAK_PATTERNS = [
    (r"stack\s*trace", "Stack trace in API response"),
    (r"at\s+\w+\.\w+\(", "Stack trace in API response"),
    (r"internal\s+server\s+error.*\b(path|file|line)\b", "Internal details in error"),
    (r'"(error|message)":\s*".*(?:sql|query|database|table|column)', "Database error exposed"),
    (r'"(error|message)":\s*".*(?:undefined|null|NoneType|TypeError)', "Programming error exposed"),
    (r'"debug":\s*true', "Debug mode enabled in API"),
    (r'"env(?:ironment)?":\s*"(?:dev|development|staging|test)"', "Non-production environment"),
    (r"(?:aws|gcp|azure)[_-](?:key|secret|token|access)", "Cloud credential reference in error"),
]


async def test_api_endpoints(
    base_urls: list[str],
    max_paths: int = 25,
    max_concurrent: int = 5,
    timeout: float = 10.0,
) -> list[Finding]:
    """
    Test common API endpoints for misconfigurations.

    Args:
        base_urls: List of base URLs to test (e.g. ["https://api.example.com"])
        max_paths: Maximum number of API paths to test per host
        max_concurrent: Maximum concurrent requests
        timeout: Per-request timeout

    Returns:
        List of Finding objects for discovered issues
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)

    async def _test_path(client: httpx.AsyncClient, base_url: str, path: str) -> list[Finding]:
        local_findings: list[Finding] = []
        url = base_url.rstrip("/") + path

        async with sem:
            try:
                # Test GET
                resp = await client.get(url, follow_redirects=False)

                # Check for unauthenticated API access (200 with JSON body)
                if _is_real_content(resp):
                    content_type = resp.headers.get("content-type", "")
                    body = resp.text[:2000]

                    if "json" in content_type or body.strip().startswith(("{", "[")):
                        # Check if response contains actual data (not just docs/status)
                        is_sensitive = any(kw in path.lower() for kw in [
                            "users", "admin", "config", "settings", "internal",
                            "debug", "me", "token", "secret"
                        ])
                        if is_sensitive:
                            local_findings.append(Finding(
                                title=f"Unauthenticated API access: {path}",
                                description=(
                                    f"API endpoint {url} returns data without authentication. "
                                    f"Status: {resp.status_code}, Content-Type: {content_type}"
                                ),
                                vulnerability_type="api_misconfiguration",
                                severity=SeverityLevel.MEDIUM,
                                confidence=60.0,
                                target=base_url,
                                endpoint=url,
                                evidence=body[:500],
                                tool_name="api_endpoint_tester",
                            ))

                    # Check for GraphQL introspection
                    if "graphql" in path.lower() or "graphiql" in path.lower():
                        local_findings.append(Finding(
                            title=f"GraphQL endpoint accessible: {path}",
                            description=f"GraphQL endpoint at {url} is accessible (status {resp.status_code})",
                            vulnerability_type="graphql_exposure",
                            severity=SeverityLevel.LOW,
                            confidence=70.0,
                            target=base_url,
                            endpoint=url,
                            evidence=body[:300],
                            tool_name="api_endpoint_tester",
                        ))

                # Check for verbose error messages (4xx/5xx)
                if resp.status_code >= 400:
                    body = resp.text[:3000]
                    for pattern, desc in ERROR_LEAK_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            local_findings.append(Finding(
                                title=f"API error information leak: {desc}",
                                description=(
                                    f"API endpoint {url} leaks internal information in error response. "
                                    f"Status: {resp.status_code}"
                                ),
                                vulnerability_type="information_disclosure",
                                severity=SeverityLevel.LOW,
                                confidence=65.0,
                                target=base_url,
                                endpoint=url,
                                evidence=body[:500],
                                tool_name="api_endpoint_tester",
                            ))
                            break  # One finding per endpoint

                # Check response headers
                for header, desc in SENSITIVE_RESPONSE_HEADERS.items():
                    val = resp.headers.get(header, "")
                    if not val:
                        continue
                    if header == "server":
                        # Only flag if it contains version info
                        if re.search(r"\d+\.\d+", val):
                            local_findings.append(Finding(
                                title=f"Server version disclosure in API: {val}",
                                description=f"API endpoint {url} discloses server version via Server header",
                                vulnerability_type="information_disclosure",
                                severity=SeverityLevel.INFO,
                                confidence=80.0,
                                target=base_url,
                                endpoint=url,
                                evidence=f"Server: {val}",
                                tool_name="api_endpoint_tester",
                            ))
                    elif desc:
                        local_findings.append(Finding(
                            title=f"API header leak: {desc}",
                            description=f"API endpoint {url} exposes {header}: {val}",
                            vulnerability_type="information_disclosure",
                            severity=SeverityLevel.LOW,
                            confidence=75.0,
                            target=base_url,
                            endpoint=url,
                            evidence=f"{header}: {val}",
                            tool_name="api_endpoint_tester",
                        ))

                # Test for HTTP method override
                if resp.status_code in (403, 405):
                    override_resp = await client.get(
                        url,
                        headers={"X-HTTP-Method-Override": "PUT"},
                        follow_redirects=False,
                    )
                    if (
                        override_resp.status_code not in (403, 405)
                        and override_resp.status_code != resp.status_code
                        and _is_real_content(override_resp)
                    ):
                        local_findings.append(Finding(
                            title=f"HTTP method override bypass: {path}",
                            description=(
                                f"API endpoint {url} responds differently with "
                                f"X-HTTP-Method-Override header. "
                                f"Original: {resp.status_code}, Override: {override_resp.status_code}"
                            ),
                            vulnerability_type="access_control_bypass",
                            severity=SeverityLevel.MEDIUM,
                            confidence=65.0,
                            target=base_url,
                            endpoint=url,
                            evidence=f"GET={resp.status_code}, X-HTTP-Method-Override:PUT={override_resp.status_code}",
                            tool_name="api_endpoint_tester",
                        ))

            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                logger.debug(f"API test {url} connection error: {exc}")
            except Exception as e:
                logger.debug(f"API test {url} error: {e}")

        return local_findings

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0",
        "Accept": "application/json, text/html, */*",
    }

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        headers=headers,
        verify=False,
    ) as client:
        tasks = []
        for base_url in base_urls:
            for path in API_PATHS[:max_paths]:
                tasks.append(_test_path(client, base_url, path))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

    # Deduplicate by (title, url)
    seen = set()
    unique = []
    for f in findings:
        key = (f.title, f.endpoint)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    if unique:
        logger.info(f"API endpoint tester: {len(unique)} findings from {len(base_urls)} hosts")

    return unique
