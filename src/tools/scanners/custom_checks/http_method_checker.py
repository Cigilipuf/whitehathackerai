"""
WhiteHatHacker AI — HTTP Method Checker

Tests for dangerous HTTP methods that might be enabled:
  - PUT/DELETE on web servers (file upload/deletion)
  - TRACE (cross-site tracing / XST)
  - OPTIONS enumeration
  - CONNECT proxy
  - PATCH without auth
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel


_DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
_ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "HEAD"]


async def _test_method(
    url: str,
    method: str,
    timeout: float = 10.0,
) -> dict[str, Any] | None:
    """Test a single HTTP method against a URL using curl."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sSL", "-X", method,
            "-m", str(int(timeout)),
            "-o", "/dev/null",
            "-w", "%{http_code}|%{size_download}|%{content_type}",
            "-H", "User-Agent: Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if proc.returncode == 0 and stdout:
            parts = stdout.decode().strip().split("|")
            if len(parts) >= 2:
                return {
                    "method": method,
                    "status": int(parts[0]) if parts[0].isdigit() else 0,
                    "size": int(parts[1]) if parts[1].isdigit() else 0,
                    "content_type": parts[2] if len(parts) > 2 else "",
                }
    except Exception as _exc:
        logger.debug(f"http method checker error: {_exc}")
    return None


async def _test_method_with_body(
    url: str,
    method: str,
    timeout: float = 10.0,
) -> dict[str, Any] | None:
    """Test HTTP method AND capture response body (for TRACE/PUT validation)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-X", method,
            "-m", str(int(timeout)),
            "-D", "-",
            "-H", "User-Agent: Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)",
            "-H", "X-WHAI-Trace-Test: echo-validation-marker",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if proc.returncode != 0 or not stdout:
            return None
        text = stdout.decode(errors="replace")
        parts = text.split("\r\n\r\n", 1)
        headers_section = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""
        status_match = re.search(r"HTTP/[\d.]+ (\d{3})", headers_section)
        status = int(status_match.group(1)) if status_match else 0
        content_type = ""
        for line in headers_section.split("\n"):
            if line.lower().startswith("content-type:"):
                content_type = line.split(":", 1)[1].strip().lower()
                break
        return {
            "method": method,
            "status": status,
            "size": len(body),
            "body": body,
            "content_type": content_type,
            "headers_raw": headers_section,
        }
    except Exception as _exc:
        logger.debug(f"http method checker error: {_exc}")
    return None


async def _test_options(url: str, timeout: float = 10.0) -> list[str]:
    """Send OPTIONS request and parse Allow header."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sSL", "-X", "OPTIONS",
            "-m", str(int(timeout)),
            "-D", "-", "-o", "/dev/null",
            "-H", "User-Agent: Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if proc.returncode == 0 and stdout:
            headers = stdout.decode(errors="replace")
            for line in headers.splitlines():
                if line.lower().startswith("allow:"):
                    methods = [m.strip().upper() for m in line.split(":", 1)[1].split(",")]
                    return methods
    except Exception as _exc:
        logger.debug(f"http method checker error: {_exc}")
    return []


async def check_http_methods(
    urls: list[str],
    max_concurrent: int = 3,
    timeout: float = 10.0,
) -> list[Finding]:
    """
    Check HTTP methods on target URLs for security issues.

    Args:
        urls: List of target URLs to check
        max_concurrent: Maximum concurrent requests
        timeout: Per-request timeout

    Returns:
        List of Finding objects for dangerous methods found
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    sem = asyncio.Semaphore(max_concurrent)

    async def check_one(url: str) -> list[Finding]:
        async with sem:
            host_findings: list[Finding] = []
            hostname = urlparse(url).netloc

            # 1. OPTIONS check for Allow header
            allowed = await _test_options(url, timeout)
            if allowed:
                dangerous_allowed = [m for m in allowed if m in _DANGEROUS_METHODS]
                if dangerous_allowed:
                    key = f"options:{hostname}:{','.join(sorted(dangerous_allowed))}"
                    if key not in seen:
                        seen.add(key)
                        host_findings.append(Finding(
                            title=f"Dangerous HTTP Methods Allowed: {', '.join(dangerous_allowed)}",
                            description=(
                                f"The server at {url} advertises support for potentially dangerous "
                                f"HTTP methods via Allow header.\n"
                                f"Allowed methods: {', '.join(allowed)}\n"
                                f"Dangerous methods: {', '.join(dangerous_allowed)}\n\n"
                                f"PUT/DELETE may allow file manipulation.\n"
                                f"TRACE enables cross-site tracing (XST) attacks."
                            ),
                            vulnerability_type="security_misconfiguration",
                            severity=SeverityLevel.MEDIUM,
                            confidence=70.0,
                            target=hostname,
                            endpoint=url,
                            tool_name="http_method_checker",
                            tags=["http_methods", "misconfiguration"],
                            evidence=f"OPTIONS {url}\nAllow: {', '.join(allowed)}",
                            cwe_id="CWE-16",
                        ))

            # 2. Test TRACE specifically (XST) — must verify body echoes request
            trace_result = await _test_method_with_body(url, "TRACE", timeout)
            if trace_result and trace_result["status"] == 200:
                body = trace_result.get("body", "")
                ct = trace_result.get("content_type", "")
                # Real TRACE echo: content-type is message/http, OR
                # body contains our custom header marker proving echo.
                is_real_echo = (
                    "message/http" in ct
                    or "X-WHAI-Trace-Test" in body
                    or "echo-validation-marker" in body
                )
                if is_real_echo:
                    key = f"trace:{hostname}"
                    if key not in seen:
                        seen.add(key)
                        host_findings.append(Finding(
                            title="TRACE Method Enabled (Cross-Site Tracing)",
                            description=(
                                f"The TRACE HTTP method is enabled on {url}.\n"
                                f"Response: {trace_result['status']} ({trace_result['size']} bytes)\n"
                                f"Content-Type: {ct}\n\n"
                                f"The response body echoes the request headers, confirming "
                                f"TRACE is exploitable for Cross-Site Tracing (XST) attacks."
                            ),
                            vulnerability_type="security_misconfiguration",
                            severity=SeverityLevel.MEDIUM,
                            confidence=90.0,
                            target=hostname,
                            endpoint=url,
                            tool_name="http_method_checker",
                            tags=["trace", "xst", "misconfiguration"],
                            evidence=f"TRACE {url} → {trace_result['status']}\nBody echoes: {body[:300]}",
                            cwe_id="CWE-693",
                        ))

            # 3. Test PUT (file upload) — verify with follow-up GET
            put_url = url.rstrip("/") + "/whai_test_put_check.txt"
            put_result = await _test_method(put_url, "PUT", timeout)
            if put_result and put_result["status"] in (200, 201, 204):
                # Verify: can we GET the file back?
                get_result = await _test_method_with_body(put_url, "GET", timeout)
                file_created = (
                    get_result is not None
                    and get_result["status"] == 200
                    and get_result.get("size", 0) > 0
                    # Reject WAF/error pages masquerading as 200
                    and "access denied" not in get_result.get("body", "").lower()[:500]
                    and "cloudflare" not in get_result.get("body", "").lower()[:500]
                )
                if file_created:
                    key = f"put:{hostname}"
                    if key not in seen:
                        seen.add(key)
                        host_findings.append(Finding(
                            title="PUT Method Enabled (File Upload Confirmed)",
                            description=(
                                f"The PUT HTTP method allows file creation on {url}.\n"
                                f"PUT response: {put_result['status']}\n"
                                f"Follow-up GET confirmed file exists at {put_url}\n\n"
                                f"PUT method allows arbitrary file upload to the server."
                            ),
                            vulnerability_type="security_misconfiguration",
                            severity=SeverityLevel.HIGH,
                            confidence=85.0,
                            target=hostname,
                            endpoint=url,
                            tool_name="http_method_checker",
                            tags=["put", "file_upload", "misconfiguration"],
                            evidence=f"PUT {put_url} → {put_result['status']}\nGET {put_url} → {get_result['status']} ({get_result['size']} bytes)",
                            cwe_id="CWE-434",
                        ))

            return host_findings

    # Deduplicate URLs to unique hosts
    unique_urls: list[str] = []
    seen_hosts: set[str] = set()
    for url in urls:
        host = urlparse(url).netloc
        if host not in seen_hosts:
            seen_hosts.add(host)
            # Ensure https
            if not url.startswith("http"):
                url = f"https://{url}"
            unique_urls.append(url)

    logger.info(f"http_method_checker: Testing {len(unique_urls)} unique hosts")

    tasks = [check_one(url) for url in unique_urls[:10]]  # Max 10 hosts
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    if findings:
        logger.info(f"http_method_checker: {len(findings)} findings")

    return findings


__all__ = ["check_http_methods"]
