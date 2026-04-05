"""
WhiteHatHacker AI — WebSocket Security Checker

Tests for common WebSocket security vulnerabilities:
- Cross-Site WebSocket Hijacking (CSWSH) via Origin validation
- Lack of authentication on WS upgrade
- Sensitive data exposure in WS messages
- Missing TLS (ws:// instead of wss://)
- Input injection via WS frames

References:
- https://portswigger.net/web-security/websockets
- CWE-1385: Missing Origin Validation in WebSockets
- CWE-319: Cleartext Transmission of Sensitive Information
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel
from src.utils.response_validator import ResponseValidator

_response_validator = ResponseValidator()

# ── WAF / error body markers ─────────────────────────────────

_WAF_BODY_TOKENS: tuple[str, ...] = (
    "cloudflare", "captcha", "access denied", "ray id:",
    "attention required", "request blocked", "web application firewall",
    "sucuri", "incapsula", "imperva", "mod_security",
    "403 forbidden",
)


def _is_waf_or_error_body(body: str) -> bool:
    """Return True if body looks like a WAF/challenge/error page."""
    lower = (body or "")[:5000].lower()
    return any(t in lower for t in _WAF_BODY_TOKENS)

# ── Common WebSocket endpoint paths ───────────────────────────

_WS_PATHS: list[str] = [
    "/ws", "/websocket", "/ws/", "/websocket/",
    "/socket.io/", "/sockjs/", "/cable",
    "/realtime", "/events", "/stream",
    "/api/ws", "/api/websocket", "/api/v1/ws",
    "/hub", "/signalr", "/signalr/negotiate",
    "/graphql", "/subscriptions",
    "/chat", "/notifications", "/live",
    "/feed", "/updates",
]

# ── Attack origins for CSWSH testing ──────────────────────────

_EVIL_ORIGINS: list[tuple[str, str]] = [
    ("https://evil.com", "Arbitrary origin"),
    ("null", "Null origin"),
    ("https://localhost", "Localhost origin"),
    ("https://127.0.0.1", "Loopback origin"),
]


# ── Main checker ──────────────────────────────────────────────

async def check_websocket_security(
    target_urls: list[str],
    max_concurrent: int = 3,
    timeout: float = 10.0,
    extra_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """
    Test target URLs for WebSocket security vulnerabilities.

    For each target, discovers WebSocket endpoints and tests:
    1. CSWSH (Cross-Site WebSocket Hijacking) via Origin manipulation
    2. Unencrypted WebSocket (ws:// vs wss://)
    3. Missing authentication on upgrade
    4. Information disclosure in upgrade response

    Args:
        target_urls: Base URLs to test (will probe common WS paths).
        max_concurrent: Max concurrent connections.
        timeout: Per-request timeout in seconds.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)

    _headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WhiteHatHackerAI/2.1"}
    if extra_headers:
        _headers.update(extra_headers)
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=False,
        headers=_headers,
    ) as client:
        tasks = []
        for url in target_urls:
            tasks.append(_test_url(client, url, sem))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug(f"WebSocket check error: {result}")

    logger.info(f"WebSocket security check completed: {len(findings)} findings across {len(target_urls)} URLs")
    return findings


async def _test_url(
    client: httpx.AsyncClient,
    base_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Test a single base URL for WebSocket vulnerabilities."""
    findings: list[Finding] = []

    base_url = base_url.rstrip("/")
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"

    parsed = urlparse(base_url)

    # Phase 1: Discover WebSocket endpoints
    discovered = await _discover_ws_endpoints(client, base_url, sem)

    # Phase 2: Test each discovered endpoint
    for ws_url, upgrade_resp in discovered:
        # Test CSWSH
        findings.extend(await _test_cswsh(client, ws_url, sem))

        # Check for unencrypted WebSocket
        findings.extend(_check_tls(ws_url, base_url))

        # Analyze upgrade response headers
        findings.extend(_analyze_upgrade_response(upgrade_resp, ws_url, base_url))

    # Phase 3: Check for WS paths in page source
    findings.extend(await _check_page_source(client, base_url, sem))

    # Phase 4: WebSocket message injection via raw handshake (T3-3)
    for ws_url, _ in discovered:
        findings.extend(await _test_ws_message_injection(ws_url, parsed, sem))

    return findings


# ── Phase 1: Discover WebSocket Endpoints ─────────────────────

async def _discover_ws_endpoints(
    client: httpx.AsyncClient,
    base_url: str,
    sem: asyncio.Semaphore,
) -> list[tuple[str, httpx.Response]]:
    """
    Probe common WebSocket paths at the target to find active endpoints.

    Sends HTTP Upgrade requests and checks for 101 Switching Protocols
    or other indicators of WebSocket support.
    """
    discovered: list[tuple[str, httpx.Response]] = []

    for ws_path in _WS_PATHS:
        async with sem:
            try:
                url = f"{base_url}{ws_path}"
                resp = await client.get(
                    url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                    },
                )

                # 101 = WebSocket handshake success
                if resp.status_code == 101:
                    # Validate it's a real WS upgrade, not a proxy artifact
                    _upgrade_h = resp.headers.get("upgrade", "").lower()
                    _accept_h = resp.headers.get("sec-websocket-accept", "")
                    if _upgrade_h == "websocket" or _accept_h:
                        discovered.append((url, resp))
                    continue

                # Some servers respond with 200/400/426 but indicate WS support
                upgrade_header = resp.headers.get("upgrade", "").lower()
                ws_accept = resp.headers.get("sec-websocket-accept", "")

                if upgrade_header == "websocket" or ws_accept:
                    discovered.append((url, resp))
                    continue

                # Check body for WebSocket indicators—but reject WAF/error pages
                body_lower = resp.text[:2000].lower()
                if _is_waf_or_error_body(resp.text):
                    continue

                _vr = _response_validator.validate_for_checker(
                    resp.status_code, dict(resp.headers), resp.text,
                    checker_name="websocket_checker", url=url,
                )
                if not _vr.is_valid:
                    continue

                if any(ind in body_lower for ind in (
                    "websocket", "socket.io", "sockjs", "ws://", "wss://",
                )):
                    # Endpoint exists but might not have accepted upgrade
                    discovered.append((url, resp))

            except httpx.HTTPError as exc:
                logger.debug(f"WebSocket discovery HTTP error for {url}: {exc}")
            except Exception as _exc:
                logger.debug(f"websocket checker error: {_exc}")

    logger.debug(f"WebSocket discovery for {base_url}: found {len(discovered)} endpoints")
    return discovered


# ── Phase 2: Cross-Site WebSocket Hijacking ───────────────────

async def _test_cswsh(
    client: httpx.AsyncClient,
    ws_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test for Cross-Site WebSocket Hijacking (CSWSH).

    Send WebSocket upgrade requests with malicious Origin headers.
    If the server accepts the upgrade, CSWSH is possible.
    """
    findings: list[Finding] = []

    for evil_origin, origin_desc in _EVIL_ORIGINS:
        async with sem:
            try:
                resp = await client.get(
                    ws_url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                        "Origin": evil_origin,
                    },
                )

                # Accepted upgrade with malicious origin = CSWSH
                # Require real 101 with proper WS headers for HIGH confidence
                _resp_upgrade = resp.headers.get("upgrade", "").lower()
                _resp_accept = resp.headers.get("sec-websocket-accept", "")
                is_real_101 = (
                    resp.status_code == 101
                    and (_resp_upgrade == "websocket" or _resp_accept)
                )
                is_accepted = is_real_101 or bool(_resp_accept)

                if not is_accepted:
                    continue

                # Reject if body is WAF/error page (non-101 responses)
                if resp.status_code != 101 and _is_waf_or_error_body(resp.text):
                    continue

                # Check if Origin is reflected in CORS headers (double trouble)
                acao = resp.headers.get("access-control-allow-origin", "")
                cors_issue = acao == evil_origin or acao == "*"

                severity = SeverityLevel.HIGH
                confidence = 85.0

                if not is_real_101:
                    # Partial acceptance — lower confidence
                    severity = SeverityLevel.MEDIUM
                    confidence = 55.0

                evidence_parts = [
                    f"Origin: {evil_origin} ({origin_desc})",
                    f"Status: {resp.status_code}",
                    f"Sec-WebSocket-Accept: {resp.headers.get('sec-websocket-accept', 'N/A')}",
                ]
                if cors_issue:
                    evidence_parts.append(f"ACAO: {acao}")

                findings.append(Finding(
                    title="Cross-Site WebSocket Hijacking (CSWSH)",
                    description=(
                        f"The WebSocket endpoint at {ws_url} accepts a connection with "
                        f"Origin '{evil_origin}' ({origin_desc}). This allows an attacker to "
                        f"establish a WebSocket connection from a malicious site and interact "
                        f"with the application on behalf of the victim."
                    ),
                    vulnerability_type="cross_site_websocket_hijacking",
                    severity=severity,
                    confidence=confidence,
                    target=ws_url,
                    endpoint=ws_url,
                    parameter="Origin",
                    payload=evil_origin,
                    evidence="\n".join(evidence_parts),
                    tool_name="websocket_security_checker",
                    cwe_id="CWE-1385",
                    tags=["websocket", "cswsh", "origin-bypass"],
                    metadata={
                        "evil_origin": evil_origin,
                        "status_code": resp.status_code,
                        "cors_issue": cors_issue,
                    },
                ))

                # Only report the first successful origin to avoid noise
                break

            except httpx.HTTPError as e:
                logger.debug(f"CSWSH test error [{evil_origin}] {ws_url}: {e}")
            except Exception as _exc:
                logger.debug(f"websocket checker error: {_exc}")

    return findings


# ── TLS Check ─────────────────────────────────────────────────

def _check_tls(ws_url: str, base_url: str) -> list[Finding]:
    """Check if WebSocket uses TLS (wss://) or cleartext (ws://)."""
    findings: list[Finding] = []

    parsed_base = urlparse(base_url)

    # If the main site is HTTPS but we found ws:// references, flag it
    if parsed_base.scheme == "https":
        # The upgrade URL is HTTP-based; if the site is HTTPS, the WS should be wss://
        # Though the URL we test is always HTTP/HTTPS — real WS URL may differ
        # This is a heuristic check
        pass

    # Check if the WS endpoint was discovered on HTTP (not HTTPS)
    if parsed_base.scheme == "http":
        findings.append(Finding(
            title="Unencrypted WebSocket Connection",
            description=(
                f"WebSocket endpoint at {ws_url} is accessible over unencrypted HTTP. "
                f"All WebSocket traffic including authentication tokens and sensitive data "
                f"can be intercepted by a network attacker."
            ),
            vulnerability_type="cleartext_transmission",
            severity=SeverityLevel.MEDIUM,
            confidence=90.0,
            target=ws_url,
            endpoint=ws_url,
            tool_name="websocket_security_checker",
            cwe_id="CWE-319",
            tags=["websocket", "tls", "cleartext"],
        ))

    return findings


# ── Upgrade Response Analysis ─────────────────────────────────

def _analyze_upgrade_response(
    resp: httpx.Response,
    ws_url: str,
    base_url: str,
) -> list[Finding]:
    """Analyze the WebSocket upgrade response for security issues."""
    findings: list[Finding] = []

    # Check for information disclosure in headers
    server = resp.headers.get("server", "")
    x_powered = resp.headers.get("x-powered-by", "")
    via = resp.headers.get("via", "")

    disclosure_parts = []
    if server:
        disclosure_parts.append(f"Server: {server}")
    if x_powered:
        disclosure_parts.append(f"X-Powered-By: {x_powered}")
    if via:
        disclosure_parts.append(f"Via: {via}")

    if disclosure_parts and resp.status_code == 101:
        findings.append(Finding(
            title="WebSocket Upgrade Information Disclosure",
            description=(
                f"The WebSocket upgrade response at {ws_url} reveals server technology: "
                f"{', '.join(disclosure_parts)}"
            ),
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.INFO,
            confidence=90.0,
            target=base_url,
            endpoint=ws_url,
            evidence="\n".join(disclosure_parts),
            tool_name="websocket_security_checker",
            cwe_id="CWE-200",
            tags=["websocket", "info-disclosure"],
        ))

    # Check for missing security headers on WS upgrade
    if resp.status_code == 101:
        # Permissive CORS on WS endpoint
        acao = resp.headers.get("access-control-allow-origin", "")
        if acao == "*":
            findings.append(Finding(
                title="WebSocket Wildcard CORS",
                description=(
                    f"The WebSocket endpoint at {ws_url} returns a wildcard "
                    f"Access-Control-Allow-Origin (*), potentially allowing any site "
                    f"to interact with the WebSocket."
                ),
                vulnerability_type="cors_misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=85.0,
                target=base_url,
                endpoint=ws_url,
                evidence="ACAO: *",
                tool_name="websocket_security_checker",
                cwe_id="CWE-942",
                tags=["websocket", "cors", "wildcard"],
            ))

    return findings


# ── Page Source WS URL Discovery ──────────────────────────────

async def _check_page_source(
    client: httpx.AsyncClient,
    base_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Check page source for WebSocket URLs and potential issues."""
    findings: list[Finding] = []

    async with sem:
        try:
            resp = await client.get(base_url)
            body = resp.text

            # Find ws:// URLs (unencrypted)
            ws_urls = re.findall(r"ws://[^\s'\"<>]+", body)
            for ws in set(ws_urls):
                findings.append(Finding(
                    title="Cleartext WebSocket URL in Page Source",
                    description=(
                        f"The page source at {base_url} contains a cleartext WebSocket URL: {ws[:200]}. "
                        f"This connection would not be encrypted."
                    ),
                    vulnerability_type="cleartext_transmission",
                    severity=SeverityLevel.LOW,
                    confidence=85.0,
                    target=base_url,
                    endpoint=ws[:200],
                    evidence=f"Found ws:// URL in page source: {ws[:200]}",
                    tool_name="websocket_security_checker",
                    cwe_id="CWE-319",
                    tags=["websocket", "cleartext", "source-code"],
                ))

            # Find WebSocket URLs with tokens/keys embedded
            ws_all = re.findall(r"wss?://[^\s'\"<>]+", body)
            for ws in set(ws_all):
                if any(s in ws.lower() for s in ("token=", "key=", "auth=", "secret=", "jwt=")):
                    findings.append(Finding(
                        title="WebSocket URL Contains Authentication Token",
                        description=(
                            "A WebSocket URL in page source contains an embedded authentication "
                            "token/key that may be leaked via Referer headers or browser history."
                        ),
                        vulnerability_type="information_disclosure",
                        severity=SeverityLevel.MEDIUM,
                        confidence=80.0,
                        target=base_url,
                        endpoint=ws[:200],
                        evidence=f"WS URL with auth params: {ws[:200]}",
                        tool_name="websocket_security_checker",
                        cwe_id="CWE-598",
                        tags=["websocket", "token-leak"],
                    ))

        except httpx.HTTPError as exc:
            logger.debug(f"WebSocket CSWSH probe HTTP error: {exc}")
        except Exception as _exc:
            logger.debug(f"websocket checker error: {_exc}")

    return findings


# ── Phase 4: WebSocket Message Injection (T3-3) ──────────────

import base64
import os
import struct

_WS_INJECTION_PAYLOADS: list[tuple[str, str, str]] = [
    ("XSS", '<img src=x onerror=alert(1)>', "xss"),
    ("SQLi", "' OR 1=1--", "sqli"),
    ("SSTI", "{{7*7}}", "ssti"),
    ("CMD", "; id", "command_injection"),
    ("JSON inject", '{"__proto__":{"admin":true}}', "prototype_pollution"),
]


def _ws_frame(payload: str) -> bytes:
    """Build a masked WebSocket text frame (client → server)."""
    data = payload.encode("utf-8")
    mask_key = os.urandom(4)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))

    frame = bytearray()
    frame.append(0x81)  # FIN + text opcode
    length = len(data)
    if length < 126:
        frame.append(0x80 | length)  # MASK bit set
    elif length < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack("!Q", length))
    frame.extend(mask_key)
    frame.extend(masked)
    return bytes(frame)


def _ws_handshake_request(host: str, path: str) -> bytes:
    """Build a WebSocket upgrade request."""
    key = base64.b64encode(os.urandom(16)).decode()
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: https://{host}\r\n"
        f"\r\n"
    ).encode()


async def _test_ws_message_injection(
    ws_url: str,
    parsed_base: Any,
    sem: asyncio.Semaphore,
    timeout: float = 8.0,
) -> list[Finding]:
    """
    Open a raw WebSocket connection and send injection payloads.

    Checks if the server reflects or processes potentially dangerous content
    without sanitization.
    """
    findings: list[Finding] = []
    parsed = urlparse(ws_url)
    host = parsed.hostname or parsed_base.hostname or ""
    use_ssl = parsed.scheme == "https" or parsed_base.scheme == "https"
    port = parsed.port or parsed_base.port or (443 if use_ssl else 80)
    path = parsed.path or "/"

    if not host:
        return findings

    async with sem:
        loop = asyncio.get_running_loop()

        def _blocking_ws_test() -> list[dict]:
            """Perform WS handshake + message injection in a thread."""
            import socket as _socket
            import ssl as _tls

            results: list[dict] = []
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(timeout)

            try:
                if use_ssl:
                    ctx = _tls.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _tls.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                sock.connect((host, port))

                # Send WS handshake
                sock.sendall(_ws_handshake_request(host, path))

                # Read handshake response
                resp_data = b""
                try:
                    while b"\r\n\r\n" not in resp_data:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        resp_data += chunk
                except _socket.timeout:
                    return results

                resp_text = resp_data.decode("utf-8", errors="replace")
                if "101" not in resp_text:
                    return results  # Handshake failed

                # Send injection payloads
                for name, payload, vuln_type in _WS_INJECTION_PAYLOADS:
                    try:
                        frame = _ws_frame(payload)
                        sock.sendall(frame)
                        time.sleep(0.3)

                        # Read response
                        try:
                            response = sock.recv(4096)
                            resp_str = response.decode("utf-8", errors="replace")

                            # Check if payload is reflected without encoding
                            if payload in resp_str:
                                results.append({
                                    "name": name,
                                    "payload": payload,
                                    "vuln_type": vuln_type,
                                    "reflected": True,
                                    "response_snippet": resp_str[:300],
                                })
                        except _socket.timeout:
                            pass
                    except Exception:
                        break

            except (_socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError):
                pass
            finally:
                try:
                    sock.close()
                except Exception as e:
                    logger.warning(f"websocket_checker error: {e}")

            return results

        try:
            injection_results = await asyncio.wait_for(
                loop.run_in_executor(None, _blocking_ws_test),
                timeout=timeout + 5,
            )
        except (asyncio.TimeoutError, Exception) as _e:
            logger.debug(f"WS message injection test failed for {ws_url}: {_e}")
            return findings

    for result in injection_results:
        findings.append(Finding(
            title=f"WebSocket Message Injection ({result['name']}): {host}",
            description=(
                f"The WebSocket endpoint at {ws_url} reflects injected payload "
                f"without sanitization. Payload '{result['payload']}' was sent as a "
                f"WebSocket text frame and appeared in the server response verbatim.\n"
                f"This may enable {result['name']} attacks via WebSocket messages."
            ),
            vulnerability_type=result["vuln_type"],
            severity=SeverityLevel.HIGH if result["name"] == "XSS" else SeverityLevel.MEDIUM,
            confidence=70.0,
            target=ws_url,
            endpoint=ws_url,
            payload=result["payload"],
            tool_name="websocket_security_checker",
            cwe_id="CWE-79" if result["name"] == "XSS" else "CWE-74",
            tags=["websocket", "message_injection", result["vuln_type"]],
            evidence=(
                f"Payload: {result['payload']}\n"
                f"Response: {result['response_snippet']}"
            ),
        ))

    return findings


__all__ = ["check_websocket_security"]
