"""
WhiteHatHacker AI — BFLA/BOLA API Security Checker

OWASP API Security Top 10:
- API1:2023 Broken Object Level Authorization (BOLA)
- API5:2023 Broken Function Level Authorization (BFLA)

BOLA: A user can access another user's objects by manipulating IDs.
BFLA: A regular user can access admin/privileged API functions.

Detection strategies:
1. Horizontal privilege escalation (BOLA):
   - Swap user IDs in API paths (/api/users/123 → /api/users/456)
   - Swap IDs in request bodies (user_id: 123 → user_id: 456)
   - Compare responses to detect unauthorized data access

2. Vertical privilege escalation (BFLA):
   - Access admin endpoints with regular user tokens
   - Test HTTP method changes (GET→POST/PUT/DELETE)
   - Test role-based endpoint restrictions

3. Response differential analysis:
   - Compare response sizes, structures, field presence
   - Detect if different user data is returned
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import aiohttp

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# ─── Common API patterns for BOLA testing ──────────────────

# Regex patterns that identify parameterized API endpoints
API_ID_PATTERNS = [
    re.compile(r"/api/v?\d*/?\w+/(\d+)"),                  # /api/v1/users/123
    re.compile(r"/api/v?\d*/?\w+/([a-f0-9\-]{36})"),        # UUID in path
    re.compile(r"/api/v?\d*/?\w+/([a-f0-9]{24})"),           # MongoDB ObjectId
    re.compile(r"/\w+/(\d+)/\w+"),                           # /users/123/orders
    re.compile(r"/\w+/([a-f0-9\-]{36})/\w+"),                # /users/uuid/orders
]

# Admin/privileged endpoint patterns for BFLA testing
ADMIN_PATTERNS = [
    re.compile(r"/admin", re.IGNORECASE),
    re.compile(r"/manage", re.IGNORECASE),
    re.compile(r"/internal", re.IGNORECASE),
    re.compile(r"/api/v?\d*/admin", re.IGNORECASE),
    re.compile(r"/api/v?\d*/management", re.IGNORECASE),
    re.compile(r"/api/v?\d*/config", re.IGNORECASE),
    re.compile(r"/api/v?\d*/settings", re.IGNORECASE),
    re.compile(r"/api/v?\d*/users$", re.IGNORECASE),         # User listing
    re.compile(r"/api/v?\d*/roles", re.IGNORECASE),
    re.compile(r"/api/v?\d*/permissions", re.IGNORECASE),
    re.compile(r"/api/v?\d*/audit", re.IGNORECASE),
    re.compile(r"/api/v?\d*/logs", re.IGNORECASE),
    re.compile(r"/api/v?\d*/export", re.IGNORECASE),
    re.compile(r"/api/v?\d*/import", re.IGNORECASE),
    re.compile(r"/api/v?\d*/bulk", re.IGNORECASE),
    re.compile(r"/api/v?\d*/debug", re.IGNORECASE),
]

# Dangerous HTTP methods for BFLA testing
PRIVILEGE_METHODS = ["PUT", "DELETE", "PATCH"]

# ID substitution test values
BOLA_TEST_IDS = {
    "numeric": ["1", "0", "2", "999", "100"],
    "uuid": [
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
    ],
    "objectid": ["000000000000000000000000", "aaaaaaaaaaaaaaaaaaaaaaaa"],
}


class BFLABOLAChecker(SecurityTool):
    """
    BFLA/BOLA API Security Checker.

    Tests for broken authorization at both object level (BOLA) and
    function level (BFLA) in API endpoints. Uses response differential
    analysis to detect unauthorized data access or function execution.
    """

    name = "bfla_bola_checker"
    category = ToolCategory.SCANNER
    description = "BFLA/BOLA API authorization bypass detection"
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
        base_url = target.rstrip("/") if target.startswith("http") else f"https://{target}"
        endpoints = options.get("endpoints", [])
        auth_headers_regular = options.get("auth_headers_regular", {})
        options.get("auth_headers_admin", {})
        timeout_s = options.get("timeout", 15)
        max_concurrent = options.get("concurrency", 3)

        findings: list[Finding] = []
        tested = 0
        errors = 0

        connector = aiohttp.TCPConnector(ssl=False, limit=max_concurrent)
        jar = aiohttp.DummyCookieJar()
        client_timeout = aiohttp.ClientTimeout(total=timeout_s)
        sem = asyncio.Semaphore(max_concurrent)

        async with aiohttp.ClientSession(
            connector=connector,
            cookie_jar=jar,
            timeout=client_timeout,
        ) as session:

            # ── Phase 1: BOLA — Object-level authorization testing ──
            bola_endpoints = self._identify_bola_endpoints(endpoints)
            if bola_endpoints:
                bola_tasks = []
                for ep_info in bola_endpoints[:30]:
                    bola_tasks.append(
                        self._test_bola(
                            sem, session, base_url, ep_info,
                            auth_headers_regular, timeout_s,
                        )
                    )
                bola_results = await asyncio.gather(*bola_tasks, return_exceptions=True)
                for r in bola_results:
                    tested += 1
                    if isinstance(r, Exception):
                        errors += 1
                    elif r is not None:
                        findings.append(r)

            # ── Phase 2: BFLA — Function-level authorization testing ──
            admin_endpoints = self._identify_admin_endpoints(endpoints)
            if admin_endpoints:
                bfla_tasks = []
                for ep in admin_endpoints[:20]:
                    bfla_tasks.append(
                        self._test_bfla(
                            sem, session, base_url, ep,
                            auth_headers_regular, timeout_s,
                        )
                    )
                bfla_results = await asyncio.gather(*bfla_tasks, return_exceptions=True)
                for r in bfla_results:
                    tested += 1
                    if isinstance(r, Exception):
                        errors += 1
                    elif r is not None:
                        if isinstance(r, list):
                            findings.extend(r)
                        else:
                            findings.append(r)

            # ── Phase 3: Method-based BFLA testing ──
            method_endpoints = [ep for ep in endpoints if "/api/" in ep][:15]
            if method_endpoints and auth_headers_regular:
                method_tasks = []
                for ep in method_endpoints:
                    method_tasks.append(
                        self._test_method_bfla(
                            sem, session, base_url, ep,
                            auth_headers_regular, timeout_s,
                        )
                    )
                method_results = await asyncio.gather(*method_tasks, return_exceptions=True)
                for r in method_results:
                    tested += 1
                    if isinstance(r, Exception):
                        errors += 1
                    elif r is not None:
                        findings.extend(r) if isinstance(r, list) else findings.append(r)

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            findings=findings,
            raw_output=f"BFLA/BOLA check: {tested} tests, "
                       f"{len(findings)} findings, {errors} errors",
            execution_time=0.0,
            metadata={
                "bola_endpoints_tested": len(bola_endpoints) if bola_endpoints else 0,
                "admin_endpoints_tested": len(admin_endpoints) if admin_endpoints else 0,
                "total_tests": tested,
                "errors": errors,
            },
        )

    def _identify_bola_endpoints(
        self, endpoints: list[str]
    ) -> list[dict[str, Any]]:
        """Find API endpoints with ID parameters suitable for BOLA testing."""
        bola_targets: list[dict[str, Any]] = []

        for ep in endpoints:
            for pat in API_ID_PATTERNS:
                m = pat.search(ep)
                if m:
                    original_id = m.group(1)
                    # Determine ID type
                    if re.match(r"^\d+$", original_id):
                        id_type = "numeric"
                    elif re.match(r"^[a-f0-9\-]{36}$", original_id):
                        id_type = "uuid"
                    elif re.match(r"^[a-f0-9]{24}$", original_id):
                        id_type = "objectid"
                    else:
                        id_type = "numeric"

                    bola_targets.append({
                        "endpoint": ep,
                        "original_id": original_id,
                        "id_type": id_type,
                        "id_start": m.start(1),
                        "id_end": m.end(1),
                    })
                    break  # One pattern match per endpoint

        return bola_targets

    def _identify_admin_endpoints(
        self, endpoints: list[str]
    ) -> list[str]:
        """Find endpoints that look admin/privileged for BFLA testing."""
        admin_eps: list[str] = []
        for ep in endpoints:
            for pat in ADMIN_PATTERNS:
                if pat.search(ep):
                    admin_eps.append(ep)
                    break
        return admin_eps

    async def _test_bola(
        self,
        sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        base_url: str,
        ep_info: dict[str, Any],
        auth_headers: dict[str, str],
        timeout_s: int,
    ) -> Finding | None:
        """Test a single endpoint for BOLA vulnerability."""
        async with sem:
            endpoint = ep_info["endpoint"]
            original_id = ep_info["original_id"]
            id_type = ep_info["id_type"]
            url = f"{base_url}{endpoint}" if not endpoint.startswith("http") else endpoint

            # First, get the baseline response with original ID
            try:
                baseline_resp = await session.get(url, headers=auth_headers)
                baseline_status = baseline_resp.status
                baseline_body = await baseline_resp.text(errors="replace")
                baseline_len = len(baseline_body)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None

            # Skip if baseline returns error
            if baseline_status >= 400:
                return None

            # Now try different IDs
            test_ids = BOLA_TEST_IDS.get(id_type, BOLA_TEST_IDS["numeric"])
            test_ids = [tid for tid in test_ids if tid != original_id]

            for test_id in test_ids[:3]:
                # Replace the ID in the URL
                test_url = (
                    url[:ep_info["id_start"]] + test_id +
                    url[ep_info["id_end"]:]
                ) if ep_info["id_start"] > 0 else url.replace(original_id, test_id, 1)

                # Adjust for base_url prefix
                if not endpoint.startswith("http"):
                    test_endpoint = endpoint[:ep_info["id_start"]] + test_id + endpoint[ep_info["id_end"]:]
                    test_url = f"{base_url}{test_endpoint}"

                try:
                    test_resp = await session.get(test_url, headers=auth_headers)
                    test_status = test_resp.status
                    test_body = await test_resp.text(errors="replace")
                    test_len = len(test_body)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

                # BOLA detection: we got data for a different ID
                if test_status == 200 and test_len > 50:
                    # Check if we got DIFFERENT data (not just same static page)
                    if test_body != baseline_body and abs(test_len - baseline_len) < baseline_len * 2:
                        # Try to detect if response contains user-specific data
                        has_pii = self._contains_pii(test_body)

                        severity = SeverityLevel.HIGH if has_pii else SeverityLevel.MEDIUM
                        confidence = 70.0 if has_pii else 50.0

                        return Finding(
                            title="BOLA — Unauthorized Object Access via ID Manipulation",
                            description=(
                                f"Endpoint {endpoint} returns data for different object IDs. "
                                f"Replacing {id_type} ID '{original_id}' with '{test_id}' "
                                f"returned a 200 response with {test_len} bytes of data. "
                                f"{'PII-like data detected in response. ' if has_pii else ''}"
                                f"This indicates missing object-level authorization."
                            ),
                            severity=severity,
                            confidence=confidence,
                            endpoint=test_url,
                            evidence=(
                                f"Original URL: {url}\n"
                                f"Original ID: {original_id}\n"
                                f"Test ID: {test_id}\n"
                                f"Original response: {baseline_status} ({baseline_len} bytes)\n"
                                f"Test response: {test_status} ({test_len} bytes)\n"
                                f"PII detected: {has_pii}\n"
                                f"Response preview: {test_body[:300]}"
                            ),
                            tool_name=self.name,
                            vulnerability_type="bola_idor",
                            remediation=(
                                "1. Implement object-level authorization checks in every API endpoint.\n"
                                "2. Verify that the authenticated user owns/has access to the requested object.\n"
                                "3. Use non-sequential, non-guessable IDs (UUIDs) to reduce enumeration risk.\n"
                                "4. Implement rate limiting on object access APIs.\n"
                                "5. Log and alert on unusual object access patterns."
                            ),
                            cwe_id="CWE-639",
                        )

        return None

    async def _test_bfla(
        self,
        sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        base_url: str,
        endpoint: str,
        auth_headers_regular: dict[str, str],
        timeout_s: int,
    ) -> list[Finding]:
        """Test an admin endpoint for BFLA with regular user credentials."""
        async with sem:
            findings: list[Finding] = []
            url = f"{base_url}{endpoint}" if not endpoint.startswith("http") else endpoint

            # Test 1: Access admin endpoint with regular user token
            for method in ["GET", "POST"]:
                try:
                    if method == "GET":
                        resp = await session.get(url, headers=auth_headers_regular)
                    else:
                        resp = await session.post(
                            url, headers=auth_headers_regular, json={},
                        )

                    status = resp.status
                    body = await resp.text(errors="replace")

                    # BFLA: regular user can access admin endpoint
                    if status == 200 and len(body) > 50:
                        # Check for admin-indicative content
                        admin_indicators = [
                            r'"role"\s*:\s*"admin"',
                            r'"users"\s*:\s*\[',
                            r'"permissions"\s*:',
                            r'"settings"\s*:',
                            r'"config"\s*:',
                        ]
                        has_admin_data = any(
                            re.search(p, body, re.IGNORECASE)
                            for p in admin_indicators
                        )

                        if has_admin_data:
                            findings.append(Finding(
                                title=f"BFLA — Regular User Accessing Admin API ({method})",
                                description=(
                                    f"Admin endpoint {endpoint} is accessible with regular user "
                                    f"credentials via {method}. Response contains admin-level data "
                                    f"({len(body)} bytes). This indicates missing function-level "
                                    f"authorization controls."
                                ),
                                severity=SeverityLevel.HIGH,
                                confidence=70.0,
                                endpoint=url,
                                evidence=(
                                    f"Endpoint: {endpoint}\n"
                                    f"Method: {method}\n"
                                    f"Status: {status}\n"
                                    f"Body length: {len(body)}\n"
                                    f"Admin data indicators found: True\n"
                                    f"Response preview: {body[:300]}"
                                ),
                                tool_name=self.name,
                                vulnerability_type="bfla_admin_access",
                                remediation=(
                                    "1. Implement role-based access control (RBAC) for all API endpoints.\n"
                                    "2. Enforce function-level authorization: check user role before executing.\n"
                                    "3. Deny by default — explicitly allow only authorized roles.\n"
                                    "4. Separate admin APIs on a different path/subdomain.\n"
                                    "5. Log all access attempts to admin functions for audit."
                                ),
                                cwe_id="CWE-285",
                            ))

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

            return findings

    async def _test_method_bfla(
        self,
        sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        base_url: str,
        endpoint: str,
        auth_headers: dict[str, str],
        timeout_s: int,
    ) -> list[Finding]:
        """Test if dangerous HTTP methods are allowed on API endpoints."""
        async with sem:
            findings: list[Finding] = []
            url = f"{base_url}{endpoint}" if not endpoint.startswith("http") else endpoint

            for method in PRIVILEGE_METHODS:
                try:
                    resp = await session.request(
                        method, url, headers=auth_headers, json={},
                    )
                    status = resp.status
                    body = await resp.text(errors="replace")

                    # If PUT/DELETE/PATCH returns 200/201/204, possible BFLA
                    # — but reject error/denial bodies that servers return with 200
                    if status in (200, 201, 204):
                        body_lower = body.lower()[:1000]
                        _error_sigs = (
                            "error", "unauthorized", "forbidden", "denied",
                            "not allowed", "invalid", "access denied",
                            "permission denied", "authentication required",
                            "method not allowed", "not supported",
                        )
                        if any(sig in body_lower for sig in _error_sigs):
                            continue
                        findings.append(Finding(
                            title=f"BFLA — Privileged Method {method} Accepted",
                            description=(
                                f"API endpoint {endpoint} accepts {method} requests with "
                                f"status {status}. This may allow unauthorized data "
                                f"modification or deletion if authorization checks are "
                                f"insufficient for write operations."
                            ),
                            severity=SeverityLevel.MEDIUM,
                            confidence=40.0,
                            endpoint=url,
                            evidence=(
                                f"Endpoint: {endpoint}\n"
                                f"Method: {method}\n"
                                f"Status: {status}\n"
                                f"Response length: {len(body)}\n"
                                f"Response preview: {body[:200]}"
                            ),
                            tool_name=self.name,
                            vulnerability_type="bfla_method_allowed",
                            remediation=(
                                f"1. Restrict HTTP method {method} to authorized roles only.\n"
                                "2. Implement proper authorization middleware for write operations.\n"
                                "3. Return 403 Forbidden for unauthorized method attempts.\n"
                                "4. Use API gateway policies to enforce method restrictions."
                            ),
                            cwe_id="CWE-285",
                        ))

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

            return findings

    @staticmethod
    def _contains_pii(body: str) -> bool:
        """Check if response body contains PII-like data."""
        pii_patterns = [
            r'"email"\s*:\s*"[^"]+@[^"]+"',
            r'"phone"\s*:\s*"[\d\-\+\(\) ]+"',
            r'"address"\s*:',
            r'"ssn"\s*:',
            r'"credit_card"\s*:',
            r'"password"\s*:',
            r'"api_key"\s*:',
            r'"secret"\s*:',
            r'"dob"\s*:',
            r'"date_of_birth"\s*:',
        ]
        return any(re.search(p, body, re.IGNORECASE) for p in pii_patterns)

    def is_available(self) -> bool:
        return True

    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        return []

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []

    def get_default_options(self, profile: ScanProfile = ScanProfile.BALANCED) -> dict[str, Any]:
        return {"timeout": 15, "concurrency": 3}
