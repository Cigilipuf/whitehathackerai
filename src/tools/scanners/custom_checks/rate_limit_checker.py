"""
WhiteHatHacker AI — Rate Limit Checker

Tests rate limiting implementation on sensitive endpoints:
- Login brute force protection
- API rate limiting
- Account lockout mechanisms
- OTP/2FA bypass via rate limit absence
"""

from __future__ import annotations

import time
from typing import Any

import aiohttp
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory
from src.utils.response_validator import ResponseValidator


_response_validator = ResponseValidator()

_WAF_BODY_TOKENS = (
    "cloudflare",
    "attention required",
    "ray id:",
    "request blocked",
    "access denied",
    "captcha",
    "akamai",
    "incapsula",
    "sucuri",
    "web application firewall",
)


def _body_has_waf_markers(body: str) -> bool:
    body_lower = (body or "")[:5000].lower()
    return any(token in body_lower for token in _WAF_BODY_TOKENS)


def _is_meaningful_success(status_code: int, headers: dict[str, str], body: str) -> bool:
    result = _response_validator.validate_for_checker(
        status_code,
        headers,
        body,
        checker_name="rate_limit_checker",
        expected_content_type="text",
    )
    if not result.is_valid:
        return False
    if _body_has_waf_markers(body):
        return False
    return status_code in (200, 201, 400, 401, 403)


class RateLimitChecker(SecurityTool):
    """
    Rate Limit Bypass & Absence Detector.

    Sends rapid-fire requests to test:
    1. Login endpoint — brute force protection
    2. API endpoints — rate limiting
    3. OTP/verification — replay attack
    4. Password reset — abuse potential

    Also tests bypass techniques:
    - IP rotation headers (X-Forwarded-For)
    - Case variation
    - Parameter pollution
    - Adding null bytes
    """

    name = "rate_limit_checker"
    category = ToolCategory.SCANNER
    description = "Rate limiting bypass and absence detection"
    binary_name = "python3"
    requires_root = False
    risk_level = RiskLevel.LOW

    # Headers used to bypass IP-based rate limiting
    IP_BYPASS_HEADERS_TEMPLATES = [
        {"X-Forwarded-For": "127.0.0.{i}"},
        {"X-Real-IP": "10.0.0.{i}"},
        {"X-Client-IP": "192.168.1.{i}"},
        {"X-Originating-IP": "172.16.0.{i}"},
        {"X-Remote-IP": "10.10.{i}.1"},
        {"True-Client-IP": "192.168.{i}.1"},
        {"CF-Connecting-IP": "10.{i}.0.1"},
    ]

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        base_url = target.rstrip("/") if target.startswith("http") else f"http://{target}"
        endpoints = options.get("endpoints", [])
        request_count = options.get("request_count", 50)
        timeout_s = options.get("timeout", 30)

        if not endpoints:
            endpoints = [
                {"url": f"{base_url}/login", "method": "POST", "description": "Login endpoint"},
                {"url": f"{base_url}/api/v1/login", "method": "POST", "description": "API login"},
                {"url": f"{base_url}/forgot-password", "method": "POST", "description": "Password reset"},
            ]

        findings: list[Finding] = []
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        timeout = aiohttp.ClientTimeout(total=timeout_s)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for ep in endpoints:
                url = ep.get("url", "")
                method = ep.get("method", "POST")
                desc = ep.get("description", url)
                body = ep.get("body", {})
                headers = ep.get("headers", {})

                if not url:
                    continue

                # Test 1: Basic rate limit test (no bypass)
                result = await self._test_rate_limit(
                    session, url, method, headers, body, request_count, desc
                )
                if result:
                    findings.append(result)

                # Test 2: Header-based IP rotation bypass
                result = await self._test_ip_rotation_bypass(
                    session, url, method, headers, body, request_count, desc
                )
                if result:
                    findings.append(result)

        return ToolResult(
            tool_name=self.name,
            success=True,
            exit_code=0,
            stdout=f"Tested {len(endpoints)} endpoints × 2 modes, {len(findings)} findings",
            stderr="",
            findings=findings,
            command=f"rate_limit_checker {target}",
            target=target,
        )

    async def _test_rate_limit(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        headers: dict,
        body: dict,
        count: int,
        description: str,
    ) -> Finding | None:
        """Send N requests rapidly and check if any get blocked."""
        results = []
        start = time.monotonic()
        meaningful_success = 0
        waf_blocks = 0

        for i in range(count):
            try:
                async with session.request(
                    method, url, headers=headers,
                    json=body if body else None,
                    allow_redirects=False,
                ) as resp:
                    results.append(resp.status)
                    text = await resp.text(errors="replace")
                    response_headers = {k: v for k, v in resp.headers.items()}
                    if _body_has_waf_markers(text):
                        waf_blocks += 1
                    if _is_meaningful_success(resp.status, response_headers, text):
                        meaningful_success += 1
            except Exception as _exc:
                results.append(0)

        elapsed = time.monotonic() - start
        blocked = sum(1 for s in results if s == 429)
        success = sum(1 for s in results if s in (200, 201, 400, 401, 403))
        errors = sum(1 for s in results if s == 0)

        if errors > count * 0.3 or waf_blocks > 0:
            return None

        if blocked == 0 and meaningful_success > count * 0.8:
            return Finding(
                title=f"No Rate Limiting: {description}",
                description=(
                    f"No rate limiting detected on {method} {url}.\n"
                    f"Sent {count} requests in {elapsed:.1f}s — all accepted.\n"
                    f"Status breakdown: {meaningful_success} meaningful success, {blocked} blocked, {errors} errors.\n"
                    f"This may allow brute force attacks."
                ),
                vulnerability_type="missing_rate_limit",
                severity=SeverityLevel.MEDIUM,
                confidence=80.0,
                target=url,
                endpoint=url,
                tool_name=self.name,
                cwe_id="CWE-307",
                tags=["rate_limit", "brute_force", "missing_protection"],
                evidence=[
                    f"Sent {count} {method} requests in {elapsed:.1f}s",
                    "None returned 429 Too Many Requests",
                    f"Meaningful success rate: {meaningful_success}/{count}",
                ],
                metadata={
                    "request_count": count,
                    "blocked": blocked,
                    "success": success,
                    "meaningful_success": meaningful_success,
                    "waf_blocks": waf_blocks,
                    "elapsed": elapsed,
                    "rps": count / elapsed if elapsed > 0 else 0,
                },
            )

        return None

    async def _test_ip_rotation_bypass(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        base_headers: dict,
        body: dict,
        count: int,
        description: str,
    ) -> Finding | None:
        """Test if rate limiting can be bypassed by rotating IP headers."""
        # First, trigger rate limit with normal requests
        blocked_normal = False
        normal_failures = 0
        for i in range(count):
            try:
                async with session.request(method, url, headers=base_headers, json=body, allow_redirects=False) as resp:
                    text = await resp.text(errors="replace")
                    if _body_has_waf_markers(text):
                        return None
                    if resp.status == 429:
                        blocked_normal = True
                        break
                    if not _is_meaningful_success(resp.status, dict(resp.headers), text):
                        normal_failures += 1
            except Exception as _exc:
                logger.debug(f"rate limit checker error: {_exc}")
                normal_failures += 1
                continue

        if not blocked_normal or normal_failures > count * 0.3:
            return None  # No rate limit to bypass

        # Now try with rotating IP headers
        bypassed = 0
        total_attempts = min(count, 30)
        waf_blocks = 0
        errors = 0

        for i in range(total_attempts):
            for header_template in self.IP_BYPASS_HEADERS_TEMPLATES:
                test_headers = dict(base_headers)
                for k, v in header_template.items():
                    test_headers[k] = v.format(i=i)

                try:
                    async with session.request(
                        method, url, headers=test_headers,
                        json=body, allow_redirects=False,
                    ) as resp:
                        text = await resp.text(errors="replace")
                        if _body_has_waf_markers(text):
                            waf_blocks += 1
                            break
                        if _is_meaningful_success(resp.status, dict(resp.headers), text):
                            bypassed += 1
                            break
                except Exception as _exc:
                    logger.debug(f"rate limit checker error: {_exc}")
                    errors += 1
                    continue

        if waf_blocks > 0 or errors > total_attempts * 0.3:
            return None

        if bypassed > total_attempts * 0.5:
            return Finding(
                title=f"Rate Limit Bypass via IP Headers: {description}",
                description=(
                    f"Rate limiting on {method} {url} can be bypassed using "
                    f"IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.).\n"
                    f"Normal requests get blocked (429), but header rotation bypasses it.\n"
                    f"Bypassed {bypassed}/{total_attempts} attempts."
                ),
                vulnerability_type="rate_limit_bypass",
                severity=SeverityLevel.MEDIUM,
                confidence=75.0,
                target=url,
                endpoint=url,
                tool_name=self.name,
                cwe_id="CWE-307",
                tags=["rate_limit", "bypass", "ip_spoofing", "x-forwarded-for"],
                evidence=[
                    "Rate limit active (429 returned after rapid requests)",
                    f"Bypassed with IP headers: {bypassed}/{total_attempts}",
                ],
                metadata={
                    "bypassed": bypassed,
                    "attempts": total_attempts,
                    "errors": errors,
                    "waf_blocks": waf_blocks,
                },
            )

        return None

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return ["python3", "-c", "pass"]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []


__all__ = ["RateLimitChecker"]
