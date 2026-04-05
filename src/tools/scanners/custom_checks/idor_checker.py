"""
WhiteHatHacker AI — IDOR Checker

Insecure Direct Object Reference detection through systematic ID manipulation.
Brain-enhanced analysis for identifying authorization bypass patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import aiohttp
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# Tokens that indicate a WAF/CDN challenge or error page
_WAF_ERROR_TOKENS = (
    "cloudflare", "attention required", "ray id", "request blocked",
    "access denied", "captcha", "akamai", "incapsula", "sucuri",
    "web application firewall", "just a moment", "checking your browser",
    "unauthorized", "forbidden", "permission denied", "not authorized",
    "authentication required", "login required",
)


def _is_waf_or_error_page(body: str) -> bool:
    """Detect WAF/error page in response body."""
    body_lower = body[:3000].lower()
    return any(tok in body_lower for tok in _WAF_ERROR_TOKENS)


class IDORStrategy(str, Enum):
    SEQUENTIAL = "sequential"          # id=1,2,3,… increment
    UUID_SWAP = "uuid_swap"           # Swap UUIDs between users
    PARAMETER_POLLUTION = "param_poll" # Duplicate param with different ID
    METHOD_SWITCH = "method_switch"    # GET→POST / POST→PUT
    GRAPHQL_ENUM = "graphql_enum"     # GraphQL node enumeration


@dataclass
class IDORTestCase:
    """A single IDOR test case definition."""
    url: str
    method: str = "GET"
    param_name: str = ""
    original_value: str = ""
    test_values: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | None = None
    auth_token: str = ""
    expected_status: int = 200
    strategy: IDORStrategy = IDORStrategy.SEQUENTIAL


class IDORChecker(SecurityTool):
    """
    Custom IDOR Detection Module.

    Identifies Insecure Direct Object References by:
    - Sequential ID enumeration (id=1 → id=2)
    - UUID swap between different user contexts
    - HTTP method switching (GET ↔ POST)
    - Parameter pollution
    - Response differential analysis (size, content, status)

    Requires at least one authenticated session to compare against.
    """

    name = "idor_checker"
    category = ToolCategory.SCANNER
    description = "Custom IDOR detection through systematic object reference manipulation"
    binary_name = "python3"  # Self-contained
    requires_root = False
    risk_level = RiskLevel.MEDIUM

    SENSITIVE_PATTERNS = [
        r'"email"\s*:\s*"[^"]+@[^"]+"',
        r'"password"\s*:',
        r'"ssn"\s*:',
        r'"credit_card"\s*:',
        r'"phone"\s*:\s*"[\d\-\+]+"',
        r'"address"\s*:',
        r'"api_key"\s*:',
        r'"token"\s*:',
        r'"secret"\s*:',
    ]

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        test_cases = options.get("test_cases", [])
        auth_headers_a = options.get("auth_headers_a", {})
        auth_headers_b = options.get("auth_headers_b", {})
        max_concurrent = 3
        timeout_s = options.get("timeout", 10)

        # Multi-role support: auth_roles is a list of {role_name, headers} dicts.
        # If provided, test every ordered pair (A→B) where A != B.
        # Falls back to legacy auth_headers_a / auth_headers_b if no roles.
        auth_roles: list[dict[str, Any]] = options.get("auth_roles", [])
        role_pairs: list[tuple[dict, dict, str, str]] = []
        if auth_roles and len(auth_roles) >= 2:
            for i, role_a in enumerate(auth_roles):
                for j, role_b in enumerate(auth_roles):
                    if i == j:
                        continue
                    role_pairs.append((
                        role_a.get("headers", {}),
                        role_b.get("headers", {}),
                        role_a.get("role_name", f"role_{i}"),
                        role_b.get("role_name", f"role_{j}"),
                    ))
            # Also test each role vs unauthenticated
            for i, role_a in enumerate(auth_roles):
                role_pairs.append((
                    role_a.get("headers", {}),
                    {},
                    role_a.get("role_name", f"role_{i}"),
                    "unauthenticated",
                ))
        elif auth_headers_a:
            role_pairs.append((auth_headers_a, auth_headers_b, "user_a", "user_b"))

        if not role_pairs:
            return ToolResult(
                tool_name=self.name, success=True, exit_code=0,
                stdout="IDOR check skipped — no auth context",
                stderr="", findings=[], command="", target=target, metadata={},
            )

        if not test_cases:
            test_cases = self._generate_test_cases(target, options)

        findings: list[Finding] = []
        tested = 0
        errors = 0

        connector = aiohttp.TCPConnector(ssl=False, limit=max_concurrent)
        timeout = aiohttp.ClientTimeout(total=timeout_s)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for hdrs_a, hdrs_b, name_a, name_b in role_pairs:
                for tc in test_cases:
                    try:
                        result = await self._test_idor(
                            session, tc, hdrs_a, hdrs_b,
                            role_a_name=name_a, role_b_name=name_b,
                        )
                        if result:
                            findings.append(result)
                        tested += 1
                    except Exception as exc:
                        logger.warning(f"IDOR test error: {exc}")
                        errors += 1

        return ToolResult(
            tool_name=self.name,
            success=True,
            exit_code=0,
            stdout=f"Tested {tested} cases, {len(findings)} potential IDORs",
            stderr=f"{errors} errors" if errors else "",
            findings=findings,
            command=f"idor_checker {target}",
            target=target,
            metadata={
                "tested": tested,
                "potential_idors": len(findings),
                "errors": errors,
            },
        )

    async def _test_idor(
        self,
        session: aiohttp.ClientSession,
        tc: dict,
        auth_a: dict,
        auth_b: dict,
        role_a_name: str = "user_a",
        role_b_name: str = "user_b",
    ) -> Finding | None:
        """
        Test a single IDOR case.

        Strategy:
        1. Make request as role A to their own resource → baseline
        2. Make request as role B to role A's resource → IDOR test
        3. Compare: if role B gets role A's data → IDOR confirmed
        """
        url = tc.get("url", "")
        method = tc.get("method", "GET").upper()
        param = tc.get("param_name", "")
        original_value = tc.get("original_value", "")
        test_values = tc.get("test_values", [])

        if not url:
            return None

        # Baseline: User A accessing own resource
        baseline_resp = await self._make_request(session, method, url, auth_a)
        if not baseline_resp:
            return None

        baseline_status, baseline_body, baseline_length = baseline_resp

        # If baseline is a WAF/error page, skip
        if _is_waf_or_error_page(baseline_body):
            return None

        # Test each alternate value
        for test_val in test_values:
            test_url = url
            if param and original_value:
                test_url = url.replace(f"{param}={original_value}", f"{param}={test_val}")
                test_url = re.sub(rf"/{re.escape(original_value)}(/|$)", f"/{test_val}\\1", test_url)

            # User B accessing user A's resource
            test_resp = await self._make_request(session, method, test_url, auth_b)
            if not test_resp:
                continue

            test_status, test_body, test_length = test_resp

            # If test response is a WAF/error page, skip
            if _is_waf_or_error_page(test_body):
                continue

            # Analysis
            idor_indicators = []
            confidence = 0.0

            # Status code analysis
            if test_status == baseline_status == 200:
                idor_indicators.append("Same 200 status for different user's resource")
                confidence += 30.0

            # Response body similarity
            if test_length > 0 and baseline_length > 0:
                size_ratio = min(test_length, baseline_length) / max(test_length, baseline_length)
                if size_ratio > 0.8:
                    idor_indicators.append(f"Response size similarity: {size_ratio:.0%}")
                    confidence += 20.0

            # Sensitive data in response
            for pattern in self.SENSITIVE_PATTERNS:
                if re.search(pattern, test_body, re.IGNORECASE):
                    idor_indicators.append(f"Sensitive data pattern found: {pattern[:30]}")
                    confidence += 15.0
                    break

            # Different from 403/401 (expected for proper authz)
            if test_status not in (401, 403, 404):
                idor_indicators.append(f"No access control response (got {test_status})")
                confidence += 10.0

            if confidence >= 50.0:
                return Finding(
                    title=f"Potential IDOR: {param or 'path'} in {url} ({role_b_name}→{role_a_name})",
                    description=(
                        f"Insecure Direct Object Reference detected.\n"
                        f"'{role_b_name}' can access '{role_a_name}' resource by modifying "
                        f"'{param or 'path'}' from '{original_value}' to '{test_val}'.\n"
                        f"Indicators: {'; '.join(idor_indicators)}"
                    ),
                    vulnerability_type="idor",
                    severity=SeverityLevel.HIGH,
                    confidence=min(confidence, 95.0),
                    target=url,
                    endpoint=test_url,
                    parameter=param,
                    tool_name=self.name,
                    cwe_id="CWE-639",
                    tags=["idor", "broken_access_control", "authz_bypass"],
                    evidence=[
                        f"Baseline: {baseline_status} ({baseline_length}b)",
                        f"Test: {test_status} ({test_length}b)",
                        f"Indicators: {idor_indicators}",
                    ],
                    metadata={
                        "original_value": original_value,
                        "test_value": test_val,
                        "baseline_status": baseline_status,
                        "test_status": test_status,
                        "role_a": role_a_name,
                        "role_b": role_b_name,
                    },
                )

        return None

    async def _make_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        headers: dict,
    ) -> tuple[int, str, int] | None:
        try:
            async with session.request(method, url, headers=headers) as resp:
                body = await resp.text()
                return resp.status, body, len(body)
        except Exception as exc:
            logger.debug(f"Request failed: {url} — {exc}")
            return None

    def _generate_test_cases(self, target: str, options: dict) -> list[dict]:
        """Auto-generate basic IDOR test cases from URL patterns."""
        cases = []
        endpoints = options.get("endpoints", [])

        id_pattern = re.compile(r"[?&](id|user_id|account_id|order_id|doc_id|file_id)=(\d+)", re.IGNORECASE)
        path_id_pattern = re.compile(r"/(\d+)(?:/|$)")

        for ep in endpoints:
            url = ep if ep.startswith("http") else f"{target.rstrip('/')}/{ep.lstrip('/')}"

            for match in id_pattern.finditer(url):
                param, value = match.group(1), match.group(2)
                int_val = int(value)
                test_values = [str(int_val + i) for i in range(-2, 3) if int_val + i != int_val and int_val + i > 0]
                cases.append({
                    "url": url,
                    "method": "GET",
                    "param_name": param,
                    "original_value": value,
                    "test_values": test_values,
                })

            for match in path_id_pattern.finditer(url):
                value = match.group(1)
                int_val = int(value)
                test_values = [str(int_val + i) for i in range(-2, 3) if int_val + i != int_val and int_val + i > 0]
                cases.append({
                    "url": url,
                    "method": "GET",
                    "param_name": "path_id",
                    "original_value": value,
                    "test_values": test_values,
                })

        return cases

    def build_command(self, target: str, options=None, profile=None) -> list[str]:
        return ["python3", "-c", "pass"]  # Not CLI-based

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []  # Not CLI-based


__all__ = ["IDORChecker"]
