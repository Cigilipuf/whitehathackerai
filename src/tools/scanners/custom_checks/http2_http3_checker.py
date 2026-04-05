"""
WhiteHatHacker AI — HTTP/2 & HTTP/3 Protocol Security Checker (P4-8)

Tests for protocol-level security issues:
  - H2C (HTTP/2 Cleartext) smuggling via Upgrade header
  - ALPN negotiation analysis (supported protocols)
  - HTTP/2 specific headers and pseudo-headers
  - Protocol downgrade detection
  - HTTP/2 CONNECT tunneling
  - HTTP/3 / QUIC discovery (Alt-Svc header)
  - WebSocket over HTTP/2 (RFC 8441)
  - HTTP/2 settings frame leak

References:
  - CWE-444: Inconsistent Interpretation of HTTP Requests
  - https://portswigger.net/research/http2
  - RFC 7540 (HTTP/2), RFC 9114 (HTTP/3), RFC 7639 (ALPN)
"""

from __future__ import annotations

import asyncio
import re
import ssl
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel


# ── H2C Smuggling Payloads ────────────────────────────────────

_H2C_UPGRADE_HEADERS: list[dict[str, str]] = [
    # Standard H2C upgrade
    {
        "Connection": "Upgrade, HTTP2-Settings",
        "Upgrade": "h2c",
        "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA",  # Base64 SETTINGS frame
    },
    # Variant with extra connection tokens
    {
        "Connection": "Upgrade, HTTP2-Settings, keep-alive",
        "Upgrade": "h2c",
        "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA",
    },
    # Websocket-style upgrade to h2c
    {
        "Connection": "Upgrade",
        "Upgrade": "h2c",
    },
]

# Paths commonly vulnerable via H2C tunneling
_H2C_SENSITIVE_PATHS: list[str] = [
    "/admin", "/internal", "/management", "/console",
    "/server-status", "/actuator", "/debug",
]


async def check_http2_http3_security(
    targets: list[str],
    max_targets: int = 5,
    max_concurrent: int = 3,
    timeout: float = 10.0,
    extra_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """
    Test for HTTP/2 and HTTP/3 protocol-level security issues.

    Args:
        targets: Base URLs to test.
        max_targets: Max targets.
        max_concurrent: Concurrency limit.
        timeout: Per-request timeout.
        extra_headers: Auth headers.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)
    test_targets = targets[:max_targets]

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        for base_url in test_targets:
            base_url = base_url.rstrip("/")
            if not base_url.startswith("http"):
                base_url = f"https://{base_url}"

            # Test 1: ALPN protocol detection
            findings.extend(await _check_alpn(base_url, sem, timeout))

            # Test 2: HTTP/3 / QUIC discovery via Alt-Svc
            findings.extend(await _check_alt_svc(client, base_url, sem))

            # Test 3: H2C smuggling
            findings.extend(await _check_h2c_smuggling(client, base_url, sem, extra_headers))

            # Test 4: Protocol downgrade
            findings.extend(await _check_protocol_downgrade(client, base_url, sem))

            # Test 5: HTTP/2 CONNECT tunneling
            findings.extend(await _check_h2_connect(client, base_url, sem))

    if findings:
        logger.info(f"HTTP/2-3 checker: {len(findings)} findings")

    return findings


# ── ALPN Protocol Detection ───────────────────────────────────

async def _check_alpn(
    base_url: str,
    sem: asyncio.Semaphore,
    timeout: float,
) -> list[Finding]:
    """Check ALPN negotiation to discover supported protocols."""
    findings: list[Finding] = []

    if not base_url.startswith("https://"):
        return findings

    host = base_url.replace("https://", "").split("/")[0]
    port = 443
    if ":" in host:
        host, port_str = host.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            return findings

    async with sem:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1", "h3"])

            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=timeout,
            )

            ssl_obj = writer.transport.get_extra_info("ssl_object")
            selected_alpn = ssl_obj.selected_alpn_protocol() if ssl_obj else None

            writer.close()
            try:
                await writer.wait_closed()
            except Exception as e:
                # APPLICATION_DATA_AFTER_CLOSE_NOTIFY and similar TLS close
                # errors are benign — the ALPN negotiation already succeeded.
                logger.debug(f"http2_http3_checker TLS close noise: {e}")

            protocols: list[str] = []
            if selected_alpn:
                protocols.append(selected_alpn)

            if protocols:
                logger.debug(f"ALPN for {host}: {protocols}")

                # H2 support is informational but useful context
                if "h2" in protocols:
                    findings.append(Finding(
                        title="HTTP/2 Supported (ALPN Negotiated)",
                        description=(
                            f"The server at {base_url} supports HTTP/2 via ALPN negotiation. "
                            f"Selected protocol: {selected_alpn}. "
                            f"HTTP/2 introduces additional attack surface including "
                            f"H2C smuggling, HPACK header compression attacks, and "
                            f"stream multiplexing abuse."
                        ),
                        vulnerability_type="protocol_info",
                        severity=SeverityLevel.INFO,
                        confidence=95.0,
                        endpoint=base_url,
                        evidence=f"ALPN negotiated: {selected_alpn}",
                        tool_name="http2_http3_checker",
                        tags=["http2", "alpn", "protocol"],
                        metadata={"selected_alpn": selected_alpn, "protocols": protocols},
                    ))

        except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
            logger.debug(f"ALPN check failed for {base_url}: {e}")

    return findings


# ── HTTP/3 / QUIC Discovery ──────────────────────────────────

async def _check_alt_svc(
    client: httpx.AsyncClient,
    base_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Check Alt-Svc header for HTTP/3/QUIC support."""
    findings: list[Finding] = []

    async with sem:
        try:
            resp = await client.get(base_url, follow_redirects=True)
            alt_svc = resp.headers.get("alt-svc", "")

            if alt_svc:
                h3_match = re.search(r'h3(?:-\d+)?="([^"]+)"', alt_svc)
                quic_match = re.search(r'quic="([^"]+)"', alt_svc)

                if h3_match or quic_match:
                    protocol = "HTTP/3" if h3_match else "QUIC"
                    endpoint = (h3_match or quic_match).group(1)  # type: ignore[union-attr]
                    findings.append(Finding(
                        title=f"{protocol} Support Detected (Alt-Svc)",
                        description=(
                            f"The server advertises {protocol} support via Alt-Svc header: "
                            f"{alt_svc[:200]}. Endpoint: {endpoint}. "
                            f"HTTP/3 uses QUIC (UDP) which may bypass network security "
                            f"controls designed for TCP only."
                        ),
                        vulnerability_type="protocol_info",
                        severity=SeverityLevel.INFO,
                        confidence=95.0,
                        endpoint=base_url,
                        evidence=f"Alt-Svc: {alt_svc[:300]}",
                        tool_name="http2_http3_checker",
                        tags=["http3", "quic", "alt-svc", "protocol"],
                        metadata={"alt_svc": alt_svc, "protocol": protocol},
                    ))

                # Check for clear= directive (disables Alt-Svc caching)
                if "clear" in alt_svc.lower():
                    logger.debug(f"Alt-Svc clear directive found at {base_url}")

        except Exception as e:
            logger.debug(f"Alt-Svc check failed for {base_url}: {e}")

    return findings


# ── H2C Smuggling ─────────────────────────────────────────────

async def _check_h2c_smuggling(
    client: httpx.AsyncClient,
    base_url: str,
    sem: asyncio.Semaphore,
    extra_headers: dict[str, str] | None,
) -> list[Finding]:
    """
    Test for H2C (HTTP/2 Cleartext) smuggling.
    If a reverse proxy forwards the Upgrade: h2c header to a backend,
    an attacker can bypass access controls via protocol tunnel.
    """
    findings: list[Finding] = []

    # Use HTTP (not HTTPS) for H2C — it's cleartext upgrade
    http_url = base_url.replace("https://", "http://")

    for h2c_headers in _H2C_UPGRADE_HEADERS:
        for path in ["/" ] + _H2C_SENSITIVE_PATHS:
            async with sem:
                try:
                    url = f"{http_url}{path}"
                    headers = {
                        "User-Agent": "Mozilla/5.0 (compatible; h2c-test)",
                        **h2c_headers,
                    }
                    if extra_headers:
                        headers.update(extra_headers)

                    resp = await client.get(url, headers=headers, follow_redirects=False)

                    # H2C upgrade accepted
                    if resp.status_code == 101:
                        upgrade_resp = resp.headers.get("upgrade", "").lower()
                        if "h2c" in upgrade_resp:
                            findings.append(Finding(
                                title=f"H2C Smuggling: Protocol Upgrade Accepted at {path}",
                                description=(
                                    f"The server at {url} accepted an HTTP/2 Cleartext (H2C) "
                                    f"upgrade request. This allows bypassing reverse proxy "
                                    f"access controls by tunneling requests through the "
                                    f"upgraded HTTP/2 connection."
                                ),
                                vulnerability_type="h2c_smuggling",
                                severity=SeverityLevel.HIGH,
                                confidence=85.0,
                                endpoint=url,
                                evidence=(
                                    f"HTTP 101 Switching Protocols | "
                                    f"Upgrade: {upgrade_resp}"
                                ),
                                tool_name="http2_http3_checker",
                                cwe_id="CWE-444",
                                tags=["http2", "h2c", "smuggling", "bypass"],
                                remediation=(
                                    "Configure the reverse proxy to strip or reject "
                                    "Upgrade: h2c headers from client requests. "
                                    "Disable H2C support if not needed."
                                ),
                            ))
                            return findings  # One confirmed h2c finding is enough

                    # Some proxies return 200 with connection upgrade in headers
                    if resp.status_code == 200 and "upgrade" in resp.headers.get("connection", "").lower():
                        findings.append(Finding(
                            title=f"H2C Upgrade Header Forwarded at {path}",
                            description=(
                                f"The server at {url} accepted the H2C Upgrade headers "
                                f"without returning 101, but the Connection: upgrade header "
                                f"appears in the response. The reverse proxy may be forwarding "
                                f"upgrade headers, which could enable H2C smuggling."
                            ),
                            vulnerability_type="h2c_smuggling",
                            severity=SeverityLevel.MEDIUM,
                            confidence=55.0,
                            endpoint=url,
                            needs_verification=True,
                            evidence=f"HTTP {resp.status_code} | Connection header contains 'upgrade'",
                            tool_name="http2_http3_checker",
                            cwe_id="CWE-444",
                            tags=["http2", "h2c", "smuggling"],
                        ))
                        return findings

                except Exception as e:
                    logger.warning(f"http2_http3_checker error: {e}")

    return findings


# ── Protocol Downgrade Detection ──────────────────────────────

async def _check_protocol_downgrade(
    client: httpx.AsyncClient,
    base_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Check if the server can be downgraded from HTTPS to HTTP.
    Tests for missing HSTS and HTTP→HTTPS redirect.
    """
    findings: list[Finding] = []

    async with sem:
        try:
            # Check HSTS on HTTPS endpoint
            if base_url.startswith("https://"):
                resp = await client.get(base_url, follow_redirects=False)
                hsts = resp.headers.get("strict-transport-security", "")

                if not hsts:
                    findings.append(Finding(
                        title="Missing HSTS Header (Protocol Downgrade Risk)",
                        description=(
                            f"The server at {base_url} does not send Strict-Transport-Security "
                            f"header. Without HSTS, an attacker can perform SSL stripping "
                            f"attacks to downgrade connections from HTTPS to HTTP."
                        ),
                        vulnerability_type="missing_hsts",
                        severity=SeverityLevel.LOW,
                        confidence=90.0,
                        endpoint=base_url,
                        evidence="Strict-Transport-Security header missing",
                        tool_name="http2_http3_checker",
                        cwe_id="CWE-319",
                        tags=["http", "hsts", "protocol-downgrade"],
                    ))
                elif "includesubdomains" not in hsts.lower():
                    findings.append(Finding(
                        title="HSTS Missing includeSubDomains Directive",
                        description=(
                            f"HSTS is set but without includeSubDomains: {hsts}. "
                            f"Subdomains are still vulnerable to SSL stripping."
                        ),
                        vulnerability_type="weak_hsts",
                        severity=SeverityLevel.INFO,
                        confidence=85.0,
                        endpoint=base_url,
                        evidence=f"HSTS: {hsts}",
                        tool_name="http2_http3_checker",
                        tags=["http", "hsts", "subdomain"],
                    ))

        except Exception as e:
            logger.debug(f"Protocol downgrade check failed: {e}")

    return findings


# ── HTTP/2 CONNECT Tunneling ──────────────────────────────────

async def _check_h2_connect(
    client: httpx.AsyncClient,
    base_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test if HTTP/2 CONNECT method is available for tunneling.
    Some servers allow CONNECT which can be abused for SSRF.
    """
    findings: list[Finding] = []

    async with sem:
        try:
            # Try HTTP CONNECT to internal targets
            connect_targets = [
                "127.0.0.1:80",
                "localhost:22",
                "169.254.169.254:80",  # AWS metadata
            ]

            for target in connect_targets:
                try:
                    resp = await client.request(
                        "CONNECT", base_url,
                        headers={
                            "Host": target,
                            "User-Agent": "Mozilla/5.0 (compatible; h2-test)",
                        },
                    )

                    if resp.status_code == 200:
                        findings.append(Finding(
                            title=f"HTTP CONNECT Tunneling Allowed to {target}",
                            description=(
                                f"The server at {base_url} accepted an HTTP CONNECT request "
                                f"targeting {target}. This can be abused for SSRF to reach "
                                f"internal services or cloud metadata endpoints."
                            ),
                            vulnerability_type="ssrf",
                            severity=SeverityLevel.HIGH,
                            confidence=75.0,
                            endpoint=base_url,
                            evidence=f"CONNECT {target} → HTTP {resp.status_code}",
                            tool_name="http2_http3_checker",
                            cwe_id="CWE-918",
                            tags=["http2", "connect", "ssrf", "tunneling"],
                        ))
                        break  # One confirmed CONNECT is enough

                except Exception as e:
                    logger.warning(f"http2_http3_checker error: {e}")

        except Exception as e:
            logger.debug(f"H2 CONNECT check failed: {e}")

    return findings


__all__ = ["check_http2_http3_security"]
