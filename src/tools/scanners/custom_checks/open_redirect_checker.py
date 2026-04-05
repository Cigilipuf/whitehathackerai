"""
WhiteHatHacker AI — Open Redirect Checker

Detects open redirect vulnerabilities by testing common redirect parameters
with external URLs and analyzing the response.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel


# Common redirect parameter names
_REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnUrl", "returnTo", "return_to", "next", "next_url", "dest", "destination",
    "redir", "rurl", "target", "view", "link", "goto", "out", "continue",
    "forward", "to", "ref", "referrer", "callback", "cb", "jump",
    "RelayState", "checkout_url", "success_url", "failure_url",
]

# Payloads to test — external domain
_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/%2f..",
    "/\\evil.com",
    "https:evil.com",
]

# Pattern to detect redirect in response headers
_REDIRECT_RE = re.compile(r"(?:location|refresh):\s*(https?://evil\.com|//evil\.com)", re.IGNORECASE)


async def _test_redirect(
    base_url: str,
    param: str,
    payload: str,
    timeout: float = 10.0,
) -> dict[str, Any] | None:
    """Test a single redirect parameter+payload combo."""
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))

    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sSL",
            "-m", str(int(timeout)),
            "--max-redirs", "0",
            "-D", "-",
            "-o", "/dev/null",
            "-H", "User-Agent: Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)",
            test_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if stdout:
            headers = stdout.decode(errors="replace")
            # Check for redirect to evil.com
            if _REDIRECT_RE.search(headers):
                # Extract status code
                status = 0
                first_line = headers.split("\n")[0]
                m = re.search(r"\d{3}", first_line)
                if m:
                    status = int(m.group())
                return {
                    "test_url": test_url,
                    "param": param,
                    "payload": payload,
                    "status": status,
                    "location": _REDIRECT_RE.search(headers).group(1),
                }
    except Exception as _exc:
        logger.debug(f"open redirect checker error: {_exc}")
    return None


async def check_open_redirects(
    urls: list[str],
    max_urls: int = 20,
    max_concurrent: int = 3,
    timeout: float = 10.0,
) -> list[Finding]:
    """
    Check URLs for open redirect vulnerabilities.

    Args:
        urls: List of URLs to check (endpoints with parameters preferred)
        max_urls: Maximum URLs to test
        max_concurrent: Max concurrent requests
        timeout: Per-request timeout

    Returns:
        List of Finding objects for open redirects found
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    sem = asyncio.Semaphore(max_concurrent)

    # Prioritize URLs that already have query parameters
    param_urls = [u for u in urls if "?" in u]
    no_param_urls = [u for u in urls if "?" not in u]

    # For URLs without params, create test URLs with redirect params
    test_urls: list[tuple[str, str, str]] = []  # (url, param, payload)

    # From URLs with existing params: test each redirect-like param
    for url in param_urls[:max_urls]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for param_name in qs:
            if param_name.lower() in [p.lower() for p in _REDIRECT_PARAMS]:
                for payload in _PAYLOADS[:2]:  # First 2 payloads
                    test_urls.append((url, param_name, payload))

    # For no-param URLs: test common redirect params
    remaining = max_urls - len(param_urls)
    for url in no_param_urls[:remaining]:
        for param in _REDIRECT_PARAMS[:8]:  # Top 8 params
            test_urls.append((url, param, _PAYLOADS[0]))

    if not test_urls:
        return findings

    logger.info(f"open_redirect_checker: Testing {len(test_urls)} param/payload combos")

    async def run_one(url: str, param: str, payload: str) -> dict[str, Any] | None:
        async with sem:
            return await _test_redirect(url, param, payload, timeout)

    tasks = [run_one(u, p, pl) for u, p, pl in test_urls[:60]]  # Max 60 tests
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, dict) and result is not None:
            host = urlparse(result["test_url"]).netloc
            key = f"redirect:{host}:{result['param']}"
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    title=f"Open Redirect via '{result['param']}' parameter",
                    description=(
                        f"An open redirect was detected on {host}.\n"
                        f"The parameter '{result['param']}' redirects to an external domain.\n\n"
                        f"**Request:** {result['test_url']}\n"
                        f"**Response Status:** {result['status']}\n"
                        f"**Location Header:** {result['location']}\n\n"
                        f"Open redirects can be used in phishing attacks, "
                        f"OAuth token theft, and SSRF chains."
                    ),
                    vulnerability_type="open_redirect",
                    severity=SeverityLevel.MEDIUM,
                    confidence=80.0,
                    target=host,
                    endpoint=result["test_url"],
                    tool_name="open_redirect_checker",
                    tags=["open_redirect", "cwe-601"],
                    evidence=(
                        f"curl -v -X GET '{result['test_url']}'\n"
                        f"→ {result['status']} Location: {result['location']}"
                    ),
                    cwe_id="CWE-601",
                ))

    if findings:
        logger.info(f"open_redirect_checker: {len(findings)} open redirects found")

    return findings


__all__ = ["check_open_redirects"]
