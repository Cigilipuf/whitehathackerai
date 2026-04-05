"""
WhiteHatHacker AI — Mass Assignment Checker

OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows
CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes

Mass assignment occurs when an API endpoint blindly binds client-provided
data to internal object properties without proper filtering. Attackers
can add unexpected fields (role, isAdmin, price, balance) to modify
data they shouldn't be able to change.

Detection strategies:
1. Parameter guessing: Add common privileged fields to POST/PUT requests
2. Response field promotion: Fields visible in GET but not writable in PUT
3. Role escalation: Add role/permission fields to user update endpoints
4. Price manipulation: Modify price/amount fields in e-commerce endpoints
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import aiohttp
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory
from src.utils.response_validator import ResponseValidator


def _values_match(resp_val: Any, injected_val: Any) -> bool:
    """Check if the response value matches the injected value (loose comparison)."""
    if resp_val == injected_val:
        return True
    # String comparison (e.g. True vs "true", 1 vs "1")
    return str(resp_val).lower().strip() == str(injected_val).lower().strip()


# ─── Common mass assignment field candidates ───────────────

# Fields that attackers commonly try to inject
MASS_ASSIGNMENT_FIELDS: dict[str, list[dict[str, Any]]] = {
    "privilege_escalation": [
        {"name": "role", "values": ["admin", "administrator", "superuser"]},
        {"name": "is_admin", "values": [True, 1, "true"]},
        {"name": "isAdmin", "values": [True, 1]},
        {"name": "admin", "values": [True, 1]},
        {"name": "is_superuser", "values": [True]},
        {"name": "is_staff", "values": [True]},
        {"name": "permissions", "values": [["*"], ["admin"]]},
        {"name": "user_type", "values": ["admin", "staff"]},
        {"name": "account_type", "values": ["premium", "enterprise", "admin"]},
        {"name": "access_level", "values": [99, "full", "admin"]},
        {"name": "privilege", "values": ["admin", "root"]},
        {"name": "group", "values": ["administrators", "admins"]},
        {"name": "groups", "values": [["admin", "staff"]]},
    ],
    "financial": [
        {"name": "price", "values": [0, 0.01, 1]},
        {"name": "amount", "values": [0, 0.01]},
        {"name": "balance", "values": [999999, 0]},
        {"name": "credits", "values": [999999]},
        {"name": "discount", "values": [100, 99.99]},
        {"name": "total", "values": [0, 0.01]},
        {"name": "fee", "values": [0]},
        {"name": "cost", "values": [0]},
    ],
    "account_takeover": [
        {"name": "email", "values": ["attacker@evil.com"]},
        {"name": "verified", "values": [True]},
        {"name": "email_verified", "values": [True]},
        {"name": "phone_verified", "values": [True]},
        {"name": "active", "values": [True]},
        {"name": "enabled", "values": [True]},
        {"name": "locked", "values": [False]},
        {"name": "suspended", "values": [False]},
        {"name": "password_reset_token", "values": [""]},
    ],
    "data_manipulation": [
        {"name": "id", "values": [1, 0]},
        {"name": "user_id", "values": [1]},
        {"name": "owner_id", "values": [1]},
        {"name": "created_at", "values": ["2020-01-01T00:00:00Z"]},
        {"name": "updated_at", "values": ["2099-01-01T00:00:00Z"]},
        {"name": "deleted", "values": [False]},
        {"name": "hidden", "values": [False]},
        {"name": "public", "values": [True]},
        {"name": "published", "values": [True]},
    ],
}


class MassAssignmentChecker(SecurityTool):
    """
    Mass Assignment / Parameter Tampering Detection Module.

    Tests API endpoints for mass assignment vulnerabilities by:
    1. Sending additional fields in POST/PUT/PATCH requests
    2. Checking if the server accepted and stored the injected fields
    3. Comparing response before and after to detect changes
    4. Categorizing by impact (privilege, financial, account, data)
    """

    name = "mass_assignment_checker"
    category = ToolCategory.SCANNER
    description = "Mass assignment and parameter tampering detection"
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
        auth_headers = options.get("auth_headers", {})
        timeout_s = options.get("timeout", 15)
        max_concurrent = options.get("concurrency", 3)
        test_categories = options.get(
            "categories",
            ["privilege_escalation", "financial", "account_takeover", "data_manipulation"],
        )

        findings: list[Finding] = []
        tested = 0
        errors = 0

        # Filter endpoints to API-like paths
        api_endpoints = [
            ep for ep in endpoints
            if re.search(r"/api/|/v\d/|/rest/|/graphql", ep, re.IGNORECASE)
        ]
        if not api_endpoints:
            api_endpoints = endpoints[:10]

        # Filter out static asset URLs that can never accept mass assignment
        _STATIC_EXTS = re.compile(
            r"\.(?:js|css|svg|png|jpe?g|gif|webp|ico|woff2?|ttf|eot|map|"
            r"mp[34]|avi|mov|pdf|zip|gz|tar|bz2|wasm)(?:\?|$)",
            re.IGNORECASE,
        )
        api_endpoints = [ep for ep in api_endpoints if not _STATIC_EXTS.search(ep)]

        connector = aiohttp.TCPConnector(ssl=False, limit=max_concurrent)
        jar = aiohttp.DummyCookieJar()
        client_timeout = aiohttp.ClientTimeout(total=timeout_s)
        sem = asyncio.Semaphore(max_concurrent)

        async with aiohttp.ClientSession(
            connector=connector,
            cookie_jar=jar,
            timeout=client_timeout,
        ) as session:

            # Phase 1: Discover writable endpoints (accept POST/PUT/PATCH)
            writable = await self._discover_writable_endpoints(
                session, base_url, api_endpoints, auth_headers, sem,
            )

            # Phase 2: Test each writable endpoint for mass assignment
            tasks = []
            for ep_info in writable[:20]:
                for category in test_categories:
                    fields = MASS_ASSIGNMENT_FIELDS.get(category, [])
                    if fields:
                        tasks.append(
                            self._test_mass_assignment(
                                sem, session, base_url, ep_info,
                                category, fields, auth_headers, timeout_s,
                            )
                        )

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    tested += 1
                    if isinstance(r, Exception):
                        errors += 1
                    elif r is not None:
                        if isinstance(r, list):
                            findings.extend(r)
                        else:
                            findings.append(r)

            # Phase 3: Response field analysis
            # Compare GET response fields with PUT accepted fields
            field_findings = await self._analyze_response_fields(
                session, base_url, api_endpoints[:10], auth_headers, sem,
            )
            findings.extend(field_findings)

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            findings=findings,
            raw_output=f"Mass assignment check: {tested} tests, "
                       f"{len(findings)} findings, {errors} errors",
            execution_time=0.0,
            metadata={
                "writable_endpoints": len(writable) if writable else 0,
                "categories_tested": test_categories,
                "total_tests": tested,
                "errors": errors,
            },
        )

    async def _discover_writable_endpoints(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        endpoints: list[str],
        auth_headers: dict[str, str],
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """Discover endpoints that accept write methods."""
        writable: list[dict[str, Any]] = []

        async def _check_writable(ep: str) -> dict[str, Any] | None:
            async with sem:
                url = f"{base_url}{ep}" if not ep.startswith("http") else ep
                accepted_methods: list[str] = []

                # Try OPTIONS first
                try:
                    resp = await session.options(url, headers=auth_headers)
                    allow = resp.headers.get("Allow", "")
                    if allow:
                        for m in ["POST", "PUT", "PATCH"]:
                            if m in allow.upper():
                                accepted_methods.append(m)
                        if accepted_methods:
                            return {"endpoint": ep, "methods": accepted_methods}
                except Exception as _exc:
                    logger.debug(f"mass assignment checker error: {_exc}")

                # Probe with empty POST
                for method in ["POST", "PUT", "PATCH"]:
                    try:
                        resp = await session.request(
                            method, url, headers=auth_headers,
                            json={},
                        )
                        # Accept 200, 201, 204, 400 (bad request = accepts method),
                        # 422 (validation error = accepts but rejects payload)
                        if resp.status in (200, 201, 204, 400, 422):
                            accepted_methods.append(method)
                    except Exception as _exc:
                        logger.debug(f"mass assignment checker error: {_exc}")
                        continue

                if accepted_methods:
                    return {"endpoint": ep, "methods": accepted_methods}
                return None

        tasks = [_check_writable(ep) for ep in endpoints[:30]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                writable.append(r)

        return writable

    async def _test_mass_assignment(
        self,
        sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        base_url: str,
        ep_info: dict[str, Any],
        category: str,
        fields: list[dict[str, Any]],
        auth_headers: dict[str, str],
        timeout_s: int,
    ) -> list[Finding]:
        """Test an endpoint for mass assignment with category-specific fields."""
        async with sem:
            findings: list[Finding] = []
            endpoint = ep_info["endpoint"]
            methods = ep_info["methods"]
            url = f"{base_url}{endpoint}" if not endpoint.startswith("http") else endpoint

            # Get baseline response to know which fields ALREADY exist
            baseline_keys: set[str] = set()
            try:
                baseline_resp = await session.get(url, headers=auth_headers)
                if baseline_resp.status == 200:
                    baseline_body = await baseline_resp.text(errors="replace")
                    try:
                        baseline_json = json.loads(baseline_body)
                        baseline_keys = self._extract_keys(baseline_json)
                    except (json.JSONDecodeError, TypeError):
                        pass
            except Exception as _exc:
                logger.debug(f"mass assignment checker error: {_exc}")

            # Test each field injection
            method = methods[0]  # Use first accepted method

            for field_def in fields:
                field_name = field_def["name"]
                for value in field_def["values"][:2]:  # Test max 2 values per field
                    payload = {field_name: value}

                    try:
                        resp = await session.request(
                            method, url, headers=auth_headers, json=payload,
                        )
                        status = resp.status
                        body = await resp.text(errors="replace")

                        # ── ResponseValidator: reject WAF blocks, redirects ──
                        _rv = ResponseValidator()
                        vr = _rv.validate(
                            status, dict(resp.headers), body,
                            expected_content_type="json",
                            url=url,
                        )
                        if not vr.is_valid:
                            continue

                        # Detection: Server accepted our injected field
                        if status in (200, 201, 204):
                            # Check if the response reflects our injected field
                            # AND it wasn't already present in the baseline
                            field_reflected = False
                            field_is_new = False
                            value_matches = False
                            try:
                                resp_json = json.loads(body)
                                if isinstance(resp_json, dict):
                                    # Check direct and nested field presence
                                    resp_val = resp_json.get(field_name)
                                    for wrapper in ("data", "user", "result", "item"):
                                        inner = resp_json.get(wrapper)
                                        if isinstance(inner, dict) and field_name in inner:
                                            resp_val = inner[field_name]
                                            break

                                    if resp_val is not None:
                                        field_reflected = True
                                        # Was this field already in the baseline?
                                        field_is_new = field_name not in baseline_keys
                                        # Does the value match what we injected?
                                        value_matches = _values_match(resp_val, value)
                            except (json.JSONDecodeError, TypeError):
                                # Non-JSON response — unreliable for mass
                                # assignment detection; HTML pages contain
                                # field names as form labels → FP.  Skip.
                                pass

                            # Only report if:
                            # 1. Field was NOT in baseline (new field accepted)
                            # 2. OR field value changed to match our injection
                            if field_reflected and (field_is_new or value_matches):
                                severity_map = {
                                    "privilege_escalation": SeverityLevel.CRITICAL,
                                    "financial": SeverityLevel.HIGH,
                                    "account_takeover": SeverityLevel.HIGH,
                                    "data_manipulation": SeverityLevel.MEDIUM,
                                }
                                severity = severity_map.get(category, SeverityLevel.MEDIUM)

                                # Confidence: new field + value match = strongest
                                conf = 40.0
                                if field_is_new and value_matches:
                                    conf = 80.0
                                elif field_is_new:
                                    conf = 65.0
                                elif value_matches:
                                    conf = 55.0

                                findings.append(Finding(
                                    title=f"Mass Assignment — {category.replace('_', ' ').title()} ({field_name})",
                                    description=(
                                        f"The API endpoint {endpoint} accepted and reflected "
                                        f"the injected field '{field_name}' with value "
                                        f"'{value}' via {method}. Category: {category}. "
                                        f"Field was {'NEW (not in baseline)' if field_is_new else 'already present'}. "
                                        f"Value {'matches injection' if value_matches else 'does not match'}. "
                                        f"This indicates the endpoint binds request data to "
                                        f"internal model properties without proper allowlisting."
                                    ),
                                    severity=severity,
                                    confidence=conf,
                                    endpoint=url,
                                    evidence=(
                                        f"Endpoint: {endpoint}\n"
                                        f"Method: {method}\n"
                                        f"Injected field: {field_name}={value}\n"
                                        f"Response status: {status}\n"
                                        f"Field reflected in response: {field_reflected}\n"
                                        f"Response preview: {body[:300]}"
                                    ),
                                    tool_name=self.name,
                                    vulnerability_type=f"mass_assignment_{category}",
                                    remediation=self._get_remediation(category),
                                    cwe_id="CWE-915",
                                ))
                                break  # One finding per field per endpoint

                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue

            return findings

    async def _analyze_response_fields(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        endpoints: list[str],
        auth_headers: dict[str, str],
        sem: asyncio.Semaphore,
    ) -> list[Finding]:
        """
        Compare GET response fields — if response contains sensitive
        read-only fields, those are candidates for mass assignment.
        """
        findings: list[Finding] = []
        sensitive_field_names = {
            "role", "is_admin", "isAdmin", "admin", "permissions",
            "balance", "credits", "user_type", "account_type",
            "verified", "email_verified", "active", "suspended",
        }

        for endpoint in endpoints:
            url = f"{base_url}{endpoint}" if not endpoint.startswith("http") else endpoint
            async with sem:
                try:
                    resp = await session.get(url, headers=auth_headers)
                    if resp.status != 200:
                        continue
                    body = await resp.text(errors="replace")

                    # ── ResponseValidator: reject WAF, redirects, non-JSON ──
                    _rv = ResponseValidator()
                    vr = _rv.validate(
                        resp.status, dict(resp.headers), body,
                        expected_content_type="json",
                        url=url,
                    )
                    if not vr.is_valid:
                        continue

                    try:
                        data = json.loads(body)
                    except (json.JSONDecodeError, TypeError):
                        continue

                    # Flatten JSON keys
                    all_keys = self._extract_keys(data)
                    exposed = all_keys & sensitive_field_names

                    if exposed:
                        findings.append(Finding(
                            title="Mass Assignment Risk — Sensitive Fields Exposed",
                            description=(
                                f"GET {endpoint} returns sensitive fields that may be "
                                f"writable via POST/PUT: {', '.join(sorted(exposed))}. "
                                f"If these fields are bound to the model without "
                                f"allowlisting, mass assignment is likely possible."
                            ),
                            severity=SeverityLevel.LOW,
                            confidence=30.0,
                            endpoint=url,
                            evidence=(
                                f"Endpoint: {endpoint}\n"
                                f"Exposed sensitive fields: {sorted(exposed)}\n"
                                f"Total fields in response: {len(all_keys)}"
                            ),
                            tool_name=self.name,
                            vulnerability_type="mass_assignment_risk",
                            remediation=self._get_remediation("general"),
                            cwe_id="CWE-915",
                        ))

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

        return findings

    @staticmethod
    def _extract_keys(data: Any, prefix: str = "") -> set[str]:
        """Recursively extract all JSON keys."""
        keys: set[str] = set()
        if isinstance(data, dict):
            for k, v in data.items():
                keys.add(k)
                keys |= MassAssignmentChecker._extract_keys(v, f"{prefix}{k}.")
        elif isinstance(data, list) and data:
            keys |= MassAssignmentChecker._extract_keys(data[0], prefix)
        return keys

    @staticmethod
    def _get_remediation(category: str) -> str:
        """Category-specific remediation advice."""
        remediations = {
            "privilege_escalation": (
                "1. Use explicit allowlists for writable fields — never bind all request data.\n"
                "2. Role/permission fields must NEVER be user-modifiable.\n"
                "3. Use separate DTOs for input (without sensitive fields) vs internal models.\n"
                "4. Implement server-side role validation independent of client data.\n"
                "5. Log attempts to modify protected fields for security monitoring."
            ),
            "financial": (
                "1. Price, balance, and amount fields must be calculated server-side.\n"
                "2. Never trust client-provided financial values.\n"
                "3. Use allowlisted input DTOs without financial fields.\n"
                "4. Implement transaction integrity checks.\n"
                "5. Validate final amounts against server-side price database."
            ),
            "account_takeover": (
                "1. Email/phone changes must require re-authentication.\n"
                "2. Verification status fields must be server-controlled only.\n"
                "3. Use separate endpoints for sensitive account changes.\n"
                "4. Implement email change confirmation flow.\n"
                "5. Log all account modification attempts."
            ),
            "data_manipulation": (
                "1. ID, timestamps, and ownership fields must be server-generated.\n"
                "2. Use allowlisted DTOs — exclude system fields from binding.\n"
                "3. Implement database-level constraints for data integrity.\n"
                "4. Audit log all data modifications."
            ),
        }
        return remediations.get(category, (
            "1. Use explicit allowlists (not blocklists) for writable fields.\n"
            "2. Create input DTOs/schemas that only include user-modifiable fields.\n"
            "3. Never bind raw request data directly to internal models.\n"
            "4. Framework-specific: use serializer field restrictions (DRF), "
            "StrongParameters (Rails), @JsonIgnore (Java).\n"
            "5. Test all API endpoints for unexpected field acceptance."
        ))

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
