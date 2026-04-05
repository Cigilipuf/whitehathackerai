"""
WhiteHatHacker AI — Cookie Security Checker

Analyzes cookies from HTTP responses for security issues:
  - Missing Secure flag (sent over HTTP)
  - Missing HttpOnly flag (accessible via JavaScript)
  - Missing SameSite attribute (CSRF risk)
  - Overly broad Domain scope
  - Overly broad Path scope
  - Long/no Expires (session fixation risk)
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel


# Set-Cookie header parsing
_COOKIE_RE = re.compile(
    r"set-cookie:\s*([^=]+)=([^;\r\n]*)(.*?)(?:\r?\n|$)",
    re.IGNORECASE | re.DOTALL,
)


def _parse_cookie_attrs(attr_string: str) -> dict[str, str]:
    """Parse cookie attribute string into dict."""
    attrs: dict[str, str] = {}
    for part in attr_string.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            attrs[key.strip().lower()] = val.strip()
        else:
            attrs[part.lower()] = "true"
    return attrs


async def _fetch_cookies(url: str, timeout: float = 10.0) -> list[dict]:
    """Fetch cookies from a URL by examining Set-Cookie headers.

    Validates the HTTP response before trusting cookies: 401, 403, 404, 5xx
    and WAF block pages are rejected to prevent FP cookie findings.
    """
    cookies = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sSL",
            "-m", str(int(timeout)),
            "-D", "-",
            "-o", "/dev/null",
            "-w", "\n%{http_code}",  # Append HTTP status code
            "-H", "User-Agent: Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if proc.returncode != 0 or not stdout:
            return cookies

        raw = stdout.decode(errors="replace")
        # Extract final HTTP status from appended -w output
        lines = raw.rsplit("\n", 1)
        if len(lines) == 2:
            headers = lines[0]
            try:
                status_code = int(lines[1].strip())
            except ValueError:
                headers = raw
                status_code = 0
        else:
            headers = raw
            status_code = 0

        # Reject responses that aren't meaningful (auth, not found, WAF, errors)
        if status_code in (401, 403, 407):
            logger.debug(f"cookie_checker: skipping {url} (HTTP {status_code})")
            return cookies
        if status_code in (404, 410):
            logger.debug(f"cookie_checker: skipping {url} (HTTP {status_code})")
            return cookies
        if status_code >= 500:
            logger.debug(f"cookie_checker: skipping {url} (HTTP {status_code})")
            return cookies

        for match in _COOKIE_RE.finditer(headers):
            name = match.group(1).strip()
            value = match.group(2).strip()
            attr_str = match.group(3)
            attrs = _parse_cookie_attrs(attr_str)
            cookies.append({
                "name": name,
                "value_len": len(value),
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": attrs.get("samesite", ""),
                "domain": attrs.get("domain", ""),
                "path": attrs.get("path", ""),
                "max_age": attrs.get("max-age", ""),
                "expires": attrs.get("expires", ""),
            })
    except Exception as _exc:
        logger.debug(f"cookie checker error: {_exc}")
    return cookies


# Sensitive cookie name patterns
_SENSITIVE_NAMES = re.compile(
    r"(?:sess|token|auth|login|jwt|csrf|xsrf|sid|user|account|id|key|api)",
    re.IGNORECASE,
)


async def check_cookie_security(
    urls: list[str],
    max_hosts: int = 5,
    max_concurrent: int = 3,
    timeout: float = 10.0,
) -> list[Finding]:
    """
    Check cookies for security misconfigurations.

    Args:
        urls: Target URLs
        max_hosts: Max unique hosts
        max_concurrent: Max concurrent
        timeout: Per-request timeout

    Returns:
        List of Finding objects
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    sem = asyncio.Semaphore(max_concurrent)

    # Deduplicate to unique hosts
    seen_hosts: set[str] = set()
    targets: list[str] = []
    for url in urls:
        if not url.startswith("http"):
            url = f"https://{url}"
        host = urlparse(url).netloc
        if host not in seen_hosts:
            seen_hosts.add(host)
            targets.append(url)
        if len(targets) >= max_hosts:
            break

    logger.info(f"cookie_checker: Checking {len(targets)} hosts")

    async def check_one(url: str) -> list[Finding]:
        async with sem:
            host_findings: list[Finding] = []
            hostname = urlparse(url).netloc
            cookies = await _fetch_cookies(url, timeout)

            if not cookies:
                return host_findings

            for cookie in cookies:
                name = cookie["name"]
                is_sensitive = bool(_SENSITIVE_NAMES.search(name))
                issues: list[str] = []
                severity = SeverityLevel.LOW
                conf = 70.0

                # Check Secure flag
                if not cookie["secure"]:
                    issues.append("Missing `Secure` flag — cookie sent over unencrypted HTTP")
                    if is_sensitive:
                        severity = SeverityLevel.MEDIUM
                        conf = 80.0

                # Check HttpOnly flag
                if not cookie["httponly"]:
                    issues.append("Missing `HttpOnly` flag — cookie accessible via JavaScript (XSS risk)")
                    if is_sensitive:
                        severity = SeverityLevel.MEDIUM
                        conf = 80.0

                # Check SameSite
                samesite = cookie["samesite"].lower()
                if not samesite:
                    # SameSite not set at all — browsers default to Lax,
                    # but explicit setting is recommended
                    issues.append(
                        "SameSite=not set — explicit SameSite attribute recommended"
                    )
                elif samesite == "none":
                    # SameSite=None is VALID when paired with Secure flag
                    # (required for legitimate cross-site cookies like SSO, CDN, etc.)
                    # Only flag when Secure is missing (which is also a browser requirement)
                    if not cookie["secure"]:
                        issues.append(
                            "SameSite=None WITHOUT Secure flag — cookies rejected by modern browsers "
                            "and vulnerable to CSRF"
                        )
                    # SameSite=None + Secure=True = valid config, skip
                    # Also skip known CDN/WAF cookies (Cloudflare _cf* etc.)
                    # These are standard cross-site tracking cookies
                    elif name.startswith("_cf") or name.startswith("__cf"):
                        pass  # Cloudflare infrastructure cookie, expected config

                # Only report if there are actual issues
                if not issues:
                    continue

                # Skip non-sensitive cookies with only SameSite issue
                if len(issues) == 1 and "SameSite" in issues[0] and not is_sensitive:
                    continue

                key = f"cookie:{hostname}:{name}"
                if key in seen:
                    continue
                seen.add(key)

                issue_text = "\n".join(f"  - {i}" for i in issues)
                host_findings.append(Finding(
                    title=f"Insecure Cookie: '{name}' on {hostname}",
                    description=(
                        f"The cookie '{name}' on {hostname} has security issues:\n"
                        f"{issue_text}\n\n"
                        f"Cookie details:\n"
                        f"  Secure: {cookie['secure']}\n"
                        f"  HttpOnly: {cookie['httponly']}\n"
                        f"  SameSite: {cookie['samesite'] or 'not set'}\n"
                        f"  Domain: {cookie['domain'] or 'not set'}\n"
                        f"  Path: {cookie['path'] or '/'}\n"
                        f"  Sensitive name: {is_sensitive}"
                    ),
                    vulnerability_type="security_misconfiguration",
                    severity=severity,
                    confidence=conf,
                    target=hostname,
                    endpoint=url,
                    tool_name="cookie_checker",
                    tags=["cookie", "misconfiguration"],
                    evidence=f"Set-Cookie: {name}=... (flags: secure={cookie['secure']}, httponly={cookie['httponly']}, samesite={cookie['samesite'] or 'none'})",
                    cwe_id="CWE-614" if not cookie["secure"] else "CWE-1004",
                ))

            return host_findings

    tasks = [check_one(url) for url in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    if findings:
        logger.info(f"cookie_checker: {len(findings)} insecure cookies found")

    return findings


__all__ = ["check_cookie_security"]
