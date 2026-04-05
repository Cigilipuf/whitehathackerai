"""
WhiteHatHacker AI — Business Logic Vulnerability Checker

Detects business logic flaws that automated scanners typically miss:
- Price manipulation (negative values, zero price, overflow)
- Quantity manipulation
- Currency confusion
- Coupon/discount abuse
- Workflow step skipping
- Role/privilege escalation via parameter tampering
"""

from __future__ import annotations

import copy
from typing import Any

import aiohttp
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory
from src.utils.response_validator import ResponseValidator

# Tokens that indicate a WAF/CDN challenge or error page, not real acceptance
_WAF_ERROR_TOKENS = (
    "cloudflare", "attention required", "ray id", "request blocked",
    "access denied", "captcha", "akamai", "incapsula", "sucuri",
    "web application firewall", "just a moment", "checking your browser",
    "unauthorized", "forbidden", "permission denied", "method not allowed",
)

# --- v4.0: ResponseValidator + SPA/content detection ---
_VALIDATOR = ResponseValidator()

# SPA / static catch-all patterns that return 200 for any route
_SPA_STATIC_PATTERNS = (
    "_payload.json", "__nuxt", "window.__nuxt__", "_next/data",
    '"buildid"', '"page":"/_app"', "react-root", "app-root",
    "__sveltekit", "vite-plugin",
)

# Keywords indicating a response relates to a transaction/commerce context
_TRANSACTION_KEYWORDS = frozenset({
    "total", "price", "amount", "subtotal", "cart", "order",
    "checkout", "payment", "quantity", "item", "product",
    "discount", "tax", "shipping", "balance", "charge",
    "invoice", "receipt", "billing", "subscription",
})


def _is_genuine_success(
    status: int, body: str, headers: dict | None = None,
) -> bool:
    """Return *True* only when the response is a real application reply.

    v4.0: Uses ResponseValidator (WAF/error/SPA detection) and rejects
    SPA catch-all responses that return 200 for any route.
    """
    if status not in (200, 201):
        return False
    snippet = body[:5000].lower()
    # Legacy WAF token check
    if any(tok in snippet for tok in _WAF_ERROR_TOKENS):
        return False
    # ResponseValidator check (WAF, error page, SPA catch-all)
    validation = _VALIDATOR.validate(
        status_code=status,
        headers=headers or {},
        body=body,
        url="",
    )
    if not validation.is_valid:
        return False
    # Reject SPA / static catch-all responses
    for pat in _SPA_STATIC_PATTERNS:
        if pat in snippet:
            return False
    return True


def _has_transaction_content(body: str) -> bool:
    """Check if response body contains transaction/commerce keywords.

    For price/quantity manipulation to be real, the response must actually
    contain transaction-related data (cart, order, total, etc.).
    """
    body_lower = body[:5000].lower()
    matches = sum(1 for kw in _TRANSACTION_KEYWORDS if kw in body_lower)
    return matches >= 2


def _is_api_json_response(body: str) -> bool:
    """Check if response looks like a JSON API response (not HTML page)."""
    stripped = body.strip()
    if not stripped:
        return False
    return stripped[0] in ("{", "[")


# Common business logic manipulation payloads
PRICE_MANIPULATION_VALUES = [
    0, -1, -100, 0.01, 0.001, 0.0001,
    99999999, -99999999, 2147483647, -2147483648,  # INT_MAX / INT_MIN
    1e308, "NaN", "Infinity", "-Infinity",
    "0", "00", "0.00", "-0.01",
]

QUANTITY_MANIPULATION_VALUES = [
    0, -1, -100, 999999, 2147483647,
    0.5, 0.1, 1e10,
    "0", "-1", "NaN",
]


class BusinessLogicChecker(SecurityTool):
    """
    Business Logic Vulnerability Detector.

    Targets logic flaws in:
    1. E-commerce: price/quantity/discount manipulation
    2. Workflow: step skipping, state manipulation
    3. Access control: privilege escalation via param tampering
    4. Data validation: type confusion, boundary values

    Requires endpoint definitions with expected request format.
    Brain-enhanced analysis for interpreting results.
    """

    name = "business_logic_checker"
    category = ToolCategory.SCANNER
    description = "Business logic flaw detection — price manipulation, workflow bypass, privilege escalation"
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
        base_url = target.rstrip("/") if target.startswith("http") else f"http://{target}"
        test_definitions = options.get("test_definitions", [])
        headers = options.get("headers", {})
        timeout_s = options.get("timeout", 15)

        findings: list[Finding] = []
        tested = 0

        connector = aiohttp.TCPConnector(ssl=False, limit=5)
        timeout = aiohttp.ClientTimeout(total=timeout_s)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Price manipulation tests
            for td in test_definitions:
                if td.get("type") == "price":
                    results = await self._test_price_manipulation(
                        session, td, headers
                    )
                    findings.extend(results)
                    tested += 1

                elif td.get("type") == "quantity":
                    results = await self._test_quantity_manipulation(
                        session, td, headers
                    )
                    findings.extend(results)
                    tested += 1

                elif td.get("type") == "workflow":
                    results = await self._test_workflow_bypass(
                        session, td, headers
                    )
                    findings.extend(results)
                    tested += 1

                elif td.get("type") == "privilege":
                    results = await self._test_privilege_escalation(
                        session, td, headers
                    )
                    findings.extend(results)
                    tested += 1

            # Auto-detect price/quantity fields if no definitions provided
            if not test_definitions:
                results = await self._auto_detect_logic_flaws(session, base_url, headers)
                findings.extend(results)
                tested += 1

        return ToolResult(
            tool_name=self.name,
            success=True,
            exit_code=0,
            stdout=f"Tested {tested} business logic scenarios, {len(findings)} findings",
            stderr="",
            findings=findings,
            command=f"business_logic_checker {target}",
            target=target,
        )

    async def _test_price_manipulation(
        self,
        session: aiohttp.ClientSession,
        test_def: dict,
        headers: dict,
    ) -> list[Finding]:
        """Test price field manipulation."""
        findings = []
        url = test_def.get("url", "")
        method = test_def.get("method", "POST")
        base_body = test_def.get("body", {})
        price_field = test_def.get("field", "price")
        success_indicator = test_def.get("success_indicator", "")

        if not url:
            return findings

        for manip_value in PRICE_MANIPULATION_VALUES:
            test_body = copy.deepcopy(base_body)
            test_body[price_field] = manip_value

            try:
                async with session.request(
                    method, url, headers=headers, json=test_body, allow_redirects=False
                ) as resp:
                    body = await resp.text()

                    accepted = False
                    if _is_genuine_success(resp.status, body, dict(resp.headers)):
                        if success_indicator:
                            accepted = success_indicator in body
                        elif _has_transaction_content(body):
                            accepted = "error" not in body.lower() and "invalid" not in body.lower()

                    if accepted:
                        severity = SeverityLevel.INFO
                        confidence = 50.0

                        if isinstance(manip_value, (int, float)):
                            if manip_value < 0:
                                severity = SeverityLevel.CRITICAL
                                confidence = 85.0
                            elif manip_value == 0:
                                severity = SeverityLevel.HIGH
                                confidence = 80.0
                            elif isinstance(manip_value, float) and manip_value > 1e10:
                                severity = SeverityLevel.MEDIUM
                                confidence = 70.0

                        if severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM):
                            findings.append(Finding(
                                title=f"Price Manipulation: {price_field}={manip_value}",
                                description=(
                                    f"Server accepted manipulated price value.\n"
                                    f"Field: {price_field}\n"
                                    f"Value: {manip_value}\n"
                                    f"Response: {resp.status}\n"
                                    f"This could allow purchasing items at reduced/negative prices."
                                ),
                                vulnerability_type="business_logic",
                                severity=severity,
                                confidence=confidence,
                                target=url,
                                endpoint=url,
                                parameter=price_field,
                                payload=str(manip_value),
                                tool_name=self.name,
                                cwe_id="CWE-20",
                                tags=["business_logic", "price_manipulation", "input_validation"],
                                evidence=[f"{method} {url} with {price_field}={manip_value} → {resp.status}"],
                            ))
            except Exception as exc:
                logger.debug(f"Price manipulation test error: {exc}")

        return findings

    async def _test_quantity_manipulation(
        self,
        session: aiohttp.ClientSession,
        test_def: dict,
        headers: dict,
    ) -> list[Finding]:
        """Test quantity field manipulation."""
        findings = []
        url = test_def.get("url", "")
        method = test_def.get("method", "POST")
        base_body = test_def.get("body", {})
        qty_field = test_def.get("field", "quantity")

        if not url:
            return findings

        for manip_value in QUANTITY_MANIPULATION_VALUES:
            test_body = copy.deepcopy(base_body)
            test_body[qty_field] = manip_value

            try:
                async with session.request(
                    method, url, headers=headers, json=test_body, allow_redirects=False
                ) as resp:
                    body = await resp.text()

                    if (
                        _is_genuine_success(resp.status, body, dict(resp.headers))
                        and _has_transaction_content(body)
                        and "error" not in body.lower()
                    ):
                        if isinstance(manip_value, (int, float)) and manip_value <= 0:
                            findings.append(Finding(
                                title=f"Quantity Manipulation: {qty_field}={manip_value}",
                                description=(
                                    f"Server accepted invalid quantity.\n"
                                    f"Field: {qty_field} = {manip_value}\n"
                                    f"Negative/zero quantities may result in credit or free items."
                                ),
                                vulnerability_type="business_logic",
                                severity=SeverityLevel.HIGH,
                                confidence=80.0,
                                target=url,
                                endpoint=url,
                                parameter=qty_field,
                                payload=str(manip_value),
                                tool_name=self.name,
                                cwe_id="CWE-20",
                                tags=["business_logic", "quantity_manipulation"],
                                evidence=[f"{method} {url} with {qty_field}={manip_value} → {resp.status}"],
                            ))
            except Exception as _exc:
                logger.debug(f"business logic error: {_exc}")
                continue

        return findings

    async def _test_workflow_bypass(
        self,
        session: aiohttp.ClientSession,
        test_def: dict,
        headers: dict,
    ) -> list[Finding]:
        """Test workflow step skipping."""
        findings = []
        steps = test_def.get("steps", [])

        if len(steps) < 2:
            return findings

        # Try accessing later steps without completing earlier ones
        for i, step in enumerate(steps[1:], start=1):
            url = step.get("url", "")
            method = step.get("method", "GET")
            body = step.get("body", None)

            try:
                async with session.request(
                    method, url, headers=headers,
                    json=body, allow_redirects=False,
                ) as resp:
                    resp_body = await resp.text()

                    if _is_genuine_success(resp.status, resp_body, dict(resp.headers)) and "error" not in resp_body.lower()[:200]:
                        findings.append(Finding(
                            title=f"Workflow Bypass: Step {i + 1} accessible without step {i}",
                            description=(
                                f"Step {i + 1} of the workflow is accessible without completing prior steps.\n"
                                f"URL: {method} {url}\n"
                                f"This may allow skipping payment, verification, or approval steps."
                            ),
                            vulnerability_type="business_logic",
                            severity=SeverityLevel.HIGH,
                            confidence=70.0,
                            target=url,
                            endpoint=url,
                            tool_name=self.name,
                            cwe_id="CWE-841",
                            tags=["business_logic", "workflow_bypass", "step_skipping"],
                            evidence=[f"Directly accessed step {i + 1}: {method} {url} → {resp.status}"],
                        ))
            except Exception as _exc:
                logger.debug(f"business logic error: {_exc}")
                continue

        return findings

    async def _test_privilege_escalation(
        self,
        session: aiohttp.ClientSession,
        test_def: dict,
        headers: dict,
    ) -> list[Finding]:
        """Test privilege escalation via parameter tampering."""
        findings = []
        url = test_def.get("url", "")
        method = test_def.get("method", "POST")
        base_body = test_def.get("body", {})

        # Common privilege fields to inject/modify
        priv_fields = [
            ("role", ["admin", "administrator", "root", "superuser"]),
            ("is_admin", [True, 1, "true", "1"]),
            ("admin", [True, 1, "true"]),
            ("user_type", ["admin", "staff", "superadmin"]),
            ("privilege", ["admin", "elevated", "root"]),
            ("group", ["admin", "administrators"]),
            ("permissions", ["*", "all", "admin"]),
        ]

        for field_name, values in priv_fields:
            for value in values:
                test_body = copy.deepcopy(base_body)
                test_body[field_name] = value

                try:
                    async with session.request(
                        method, url, headers=headers, json=test_body, allow_redirects=False,
                    ) as resp:
                        body = await resp.text()

                        if _is_genuine_success(resp.status, body, dict(resp.headers)) and "error" not in body.lower()[:200]:
                            findings.append(Finding(
                                title=f"Privilege Escalation: {field_name}={value}",
                                description=(
                                    f"Server accepted privilege parameter injection.\n"
                                    f"Field: {field_name} = {value}\n"
                                    f"Response: {resp.status}\n"
                                    f"May enable mass assignment / privilege escalation."
                                ),
                                vulnerability_type="privilege_escalation",
                                severity=SeverityLevel.CRITICAL,
                                confidence=65.0,
                                target=url,
                                endpoint=url,
                                parameter=field_name,
                                payload=str(value),
                                tool_name=self.name,
                                cwe_id="CWE-269",
                                tags=["privilege_escalation", "mass_assignment", "parameter_tampering"],
                                evidence=[f"{method} {url} with {field_name}={value} → {resp.status}"],
                            ))
                except Exception as _exc:
                    logger.debug(f"business logic error: {_exc}")
                    continue

        return findings

    async def _auto_detect_logic_flaws(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        headers: dict,
    ) -> list[Finding]:
        """Auto-detect endpoints and test common patterns."""
        findings = []

        # ── Endpoint → test-type mapping ──
        _PRICE_ENDPOINTS = [
            "/api/cart", "/api/order", "/api/checkout", "/api/payment",
            "/api/transfer", "/api/billing", "/api/invoice", "/api/subscribe",
            "/api/purchase", "/api/pay", "/api/charge", "/api/refund",
            "/cart", "/checkout", "/payment", "/order", "/billing",
            "/api/v1/cart", "/api/v1/order", "/api/v1/checkout",
            "/api/v2/cart", "/api/v2/order", "/api/v2/checkout",
        ]
        _QUANTITY_ENDPOINTS = [
            "/api/cart", "/api/cart/add", "/api/cart/update",
            "/api/order", "/api/inventory", "/api/stock",
            "/cart/add", "/cart/update", "/api/v1/cart", "/api/v2/cart",
        ]
        _PRIVILEGE_ENDPOINTS = [
            "/api/user/profile", "/api/admin", "/api/settings",
            "/api/account", "/api/users", "/api/roles",
            "/api/permissions", "/api/user", "/api/me",
            "/admin", "/dashboard", "/api/v1/user", "/api/v2/user",
            "/api/user/settings", "/api/user/role",
        ]
        _PRICE_FIELDS = ("price", "amount", "total", "cost", "value")

        # Collect accessible endpoints
        accessible: dict[str, set[str]] = {"price": set(), "quantity": set(), "privilege": set()}

        all_eps = set(_PRICE_ENDPOINTS + _QUANTITY_ENDPOINTS + _PRIVILEGE_ENDPOINTS)
        for ep in all_eps:
            url = f"{base_url}{ep}"
            try:
                async with session.get(url, headers=headers) as resp:
                    body = await resp.text()
                    if _is_genuine_success(resp.status, body, dict(resp.headers)) and _is_api_json_response(body):
                        if ep in _PRICE_ENDPOINTS:
                            accessible["price"].add(url)
                        if ep in _QUANTITY_ENDPOINTS:
                            accessible["quantity"].add(url)
                        if ep in _PRIVILEGE_ENDPOINTS:
                            accessible["privilege"].add(url)
            except Exception:
                continue

        # Price manipulation tests with multiple fields
        for url in list(accessible["price"])[:8]:
            for field in _PRICE_FIELDS:
                results = await self._test_price_manipulation(
                    session, {"url": url, "method": "POST", "body": {}, "field": field}, headers,
                )
                findings.extend(results)

        # Quantity manipulation tests
        for url in list(accessible["quantity"])[:5]:
            results = await self._test_quantity_manipulation(
                session, {"url": url, "method": "POST", "body": {}, "field": "quantity"}, headers,
            )
            findings.extend(results)

        # Privilege escalation tests
        for url in list(accessible["privilege"])[:5]:
            results = await self._test_privilege_escalation(
                session, {"url": url, "method": "POST", "body": {}}, headers,
            )
            findings.extend(results)

        return findings

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return ["python3", "-c", "pass"]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []


__all__ = ["BusinessLogicChecker"]
