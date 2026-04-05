"""
HTTP Security Header Checker — Custom Security Check

Checks for missing or misconfigured HTTP security headers.
These are common low-hanging-fruit findings in bug bounty programs.
"""

import asyncio
import ssl
from urllib.parse import urlparse

from src.tools.base import Finding, SeverityLevel
from loguru import logger


# Security headers to check and their expected configurations
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": SeverityLevel.LOW,
        "description": "HTTP Strict Transport Security (HSTS) header is missing",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
        "vuln_type": "missing_security_header",
        "check_value": lambda v: "max-age=" in v.lower() and (
            int(ma) >= 31536000
            if len(parts := v.lower().split("max-age=")) > 1
            and (ma := parts[1].split(";")[0].strip()).isdigit()
            else False
        ),
    },
    "Content-Security-Policy": {
        "severity": SeverityLevel.LOW,
        "description": "Content Security Policy (CSP) header is missing or weak",
        "recommendation": "Implement a strict Content-Security-Policy header",
        "vuln_type": "missing_security_header",
        "check_value": lambda v: "unsafe-inline" not in v and "unsafe-eval" not in v,
    },
    "X-Frame-Options": {
        "severity": SeverityLevel.LOW,
        "description": "X-Frame-Options header is missing (clickjacking risk)",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header",
        "vuln_type": "clickjacking",
    },
    "X-Content-Type-Options": {
        "severity": SeverityLevel.INFO,
        "description": "X-Content-Type-Options header is missing",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header",
        "vuln_type": "missing_security_header",
    },
    "Referrer-Policy": {
        "severity": SeverityLevel.INFO,
        "description": "Referrer-Policy header is missing",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header",
        "vuln_type": "missing_security_header",
    },
    "Permissions-Policy": {
        "severity": SeverityLevel.INFO,
        "description": "Permissions-Policy header is missing",
        "recommendation": "Add Permissions-Policy to restrict browser features",
        "vuln_type": "missing_security_header",
    },
}

# Headers that should NOT be present
BAD_HEADERS = {
    "Server": {
        "severity": SeverityLevel.INFO,
        "description": "Server header reveals technology information: {value}",
        "vuln_type": "information_disclosure",
        "check": lambda v: bool(v),  # Any value is a finding
    },
    "X-Powered-By": {
        "severity": SeverityLevel.LOW,
        "description": "X-Powered-By header reveals technology: {value}",
        "vuln_type": "information_disclosure",
        "check": lambda v: bool(v),
    },
    "X-AspNet-Version": {
        "severity": SeverityLevel.LOW,
        "description": "X-AspNet-Version header reveals version: {value}",
        "vuln_type": "information_disclosure",
        "check": lambda v: bool(v),
    },
}


async def check_security_headers(target: str, timeout: int = 15, extra_headers: dict[str, str] | None = None) -> list[Finding]:
    """
    Check HTTP security headers for a target URL.

    Uses raw asyncio HTTP to avoid external dependencies.
    Returns a list of findings for missing or misconfigured headers.
    """
    findings: list[Finding] = []

    # Ensure target has scheme
    if not target.startswith("http"):
        target = f"https://{target}"

    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    path = parsed.path or "/"

    try:
        headers, status_code = await _fetch_headers(host, port, path, use_ssl, timeout, extra_headers=extra_headers)
    except Exception as _exc:
        return findings  # Can't connect, skip

    if not headers:
        return findings

    # Only validate security headers on successful responses (2xx).
    # Missing HSTS on a 503 error page or 302 redirect is NOT meaningful.
    is_success = 200 <= status_code <= 299

    # Normalize header names to lowercase for comparison
    header_map = {k.lower(): v for k, v in headers.items()}

    # Check for missing security headers — only on 2xx responses.
    # Non-2xx (redirects, errors, WAF blocks) don't represent the real
    # application response and would produce false positives.
    for header_name, config in SECURITY_HEADERS.items():
        header_lower = header_name.lower()
        value = header_map.get(header_lower)

        if value is None:
            if not is_success:
                continue  # Missing header on non-2xx is not meaningful
            # Header is completely missing
            findings.append(Finding(
                title=f"Missing Security Header: {header_name}",
                description=config["description"],
                vulnerability_type=config["vuln_type"],
                severity=config["severity"],
                confidence=90.0,
                target=target,
                endpoint=target,
                tool_name="header_checker",
                evidence=f"Response headers do not include {header_name}",
                tags=["header", "security", header_name.lower()],
                metadata={"recommendation": config.get("recommendation", "")},
            ))
        elif "check_value" in config:
            # Header exists but may be misconfigured
            try:
                if not config["check_value"](value):
                    findings.append(Finding(
                        title=f"Weak Security Header: {header_name}",
                        description=f"{config['description']}. Current value: {value[:200]}",
                        vulnerability_type=config["vuln_type"],
                        severity=config["severity"],
                        confidence=70.0,
                        target=target,
                        endpoint=target,
                        tool_name="header_checker",
                        evidence=f"{header_name}: {value[:300]}",
                        tags=["header", "security", "weak", header_name.lower()],
                        metadata={"recommendation": config.get("recommendation", "")},
                    ))
            except Exception as _exc:
                pass  # Value parsing error, skip

    # Check for information disclosure headers
    for header_name, config in BAD_HEADERS.items():
        header_lower = header_name.lower()
        value = header_map.get(header_lower)

        if value and config["check"](value):
            findings.append(Finding(
                title=f"Information Disclosure: {header_name}",
                description=config["description"].format(value=value[:200]),
                vulnerability_type=config["vuln_type"],
                severity=config["severity"],
                confidence=85.0,
                target=target,
                endpoint=target,
                tool_name="header_checker",
                evidence=f"{header_name}: {value[:300]}",
                tags=["header", "information-disclosure", header_name.lower()],
            ))

    # Check CORS headers
    cors_header = header_map.get("access-control-allow-origin")
    if cors_header and cors_header.strip() == "*":
        findings.append(Finding(
            title="Overly Permissive CORS Policy",
            description="Access-Control-Allow-Origin is set to '*', allowing any origin",
            vulnerability_type="cors_misconfiguration",
            severity=SeverityLevel.LOW,
            confidence=90.0,
            target=target,
            endpoint=target,
            tool_name="header_checker",
            evidence=f"Access-Control-Allow-Origin: {cors_header}",
            tags=["cors", "security"],
        ))

    # Check for ACAO with credentials
    # Note: ACAO: * with credentials=true is rejected by browsers (spec),
    # so only flag when origin is a specific domain (reflects origin or fixed value)
    cors_creds = header_map.get("access-control-allow-credentials")
    if cors_creds and cors_creds.lower() == "true" and cors_header:
        if cors_header.strip() not in ("null", "*"):
            findings.append(Finding(
                title="CORS with Credentials Allowed",
                description=(
                    f"CORS allows credentials with origin: {cors_header}. "
                    "This may be exploitable if the origin can be controlled."
                ),
                vulnerability_type="cors_misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=60.0,
                target=target,
                endpoint=target,
                tool_name="header_checker",
                evidence=(
                    f"Access-Control-Allow-Origin: {cors_header}\n"
                    f"Access-Control-Allow-Credentials: {cors_creds}"
                ),
                tags=["cors", "credentials", "security"],
            ))

    return findings


async def _fetch_headers(
    host: str, port: int, path: str, use_ssl: bool, timeout: int,
    extra_headers: dict[str, str] | None = None,
) -> tuple[dict[str, str], int]:
    """Fetch HTTP response headers using raw asyncio sockets.
    
    Returns:
        (headers_dict, status_code) — status_code is 0 on parse failure.
    """
    headers: dict[str, str] = {}
    status_code: int = 0

    # Sanitize inputs to prevent CRLF injection in raw HTTP request
    host = host.replace("\r", "").replace("\n", "")
    path = path.replace("\r", "").replace("\n", "")

    ssl_ctx = None
    if use_ssl:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ssl_ctx),
        timeout=timeout,
    )

    try:
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
        )
        if extra_headers:
            for hk, hv in extra_headers.items():
                # Sanitize header key/value to prevent CRLF injection
                hk = hk.replace("\r", "").replace("\n", "")
                hv = hv.replace("\r", "").replace("\n", "")
                request += f"{hk}: {hv}\r\n"
        request += "Connection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()

        # Read response headers in a loop until we find the end-of-headers
        # marker (\r\n\r\n) or hit 64KB limit.
        chunks: list[bytes] = []
        total = 0
        while total < 65536:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break

        response = b"".join(chunks)
        response_text = response.decode("utf-8", errors="replace")

        # Parse headers
        header_section = response_text.split("\r\n\r\n")[0]
        lines = header_section.split("\r\n")

        # Parse status line
        if lines:
            import re as _re
            m = _re.search(r"HTTP/[\d.]+ (\d{3})", lines[0])
            if m:
                status_code = int(m.group(1))

        for line in lines[1:]:  # Skip status line
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception as _exc:
            logger.debug(f"header checker error: {_exc}")

    return headers, status_code


__all__ = ["check_security_headers"]
