"""
WhiteHatHacker AI — Prototype Pollution Checker

Tests for JavaScript prototype pollution vulnerabilities by injecting
__proto__, constructor.prototype, and Object.prototype payloads into
query parameters, JSON bodies, and URL path segments.

Server-side prototype pollution can lead to:
- Remote Code Execution (Node.js applications)
- Authentication bypass
- Privilege escalation
- Denial of service

Client-side prototype pollution can lead to:
- DOM XSS
- Property injection

References:
- https://portswigger.net/research/server-side-prototype-pollution
- https://portswigger.net/web-security/prototype-pollution
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
"""

from __future__ import annotations

import asyncio
import json
import random
import string

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel
from src.utils.response_validator import ResponseValidator

_response_validator = ResponseValidator()

# ── WAF / error body markers ─────────────────────────────────

_WAF_ERROR_TOKENS: tuple[str, ...] = (
    "cloudflare", "captcha", "access denied", "ray id:",
    "attention required", "request blocked", "web application firewall",
    "sucuri", "incapsula", "imperva", "mod_security",
    "403 forbidden", "error 1005", "error 1006", "error 1020",
)


def _is_waf_or_error_page(body: str) -> bool:
    """Return True if body looks like a WAF block or generic error page."""
    lower = (body or "")[:5000].lower()
    return any(t in lower for t in _WAF_ERROR_TOKENS)


# ── Canary generator ──────────────────────────────────────────

def _canary(prefix: str = "whaiPP") -> str:
    return prefix + "".join(random.choices(string.ascii_lowercase, k=6))


# ── Query param pollution payloads ────────────────────────────

def _query_payloads(canary: str) -> list[tuple[str, str, str]]:
    """
    Returns (param_name, param_value, description) tuples for query string
    prototype pollution testing.
    """
    return [
        ("__proto__[polluted]", canary, "Direct __proto__ via query param"),
        ("__proto__.polluted", canary, "__proto__ dot notation in query"),
        ("constructor[prototype][polluted]", canary, "constructor.prototype via query"),
        ("constructor.prototype.polluted", canary, "constructor.prototype dot notation"),
        ("__proto__[status]", "510", "__proto__.status injection (RCE indicator)"),
        ("__proto__[spaces]", canary, "__proto__.spaces (Express.js RCE)"),
        ("__proto__[env][EVIL]", canary, "__proto__.env injection (spawn RCE)"),
    ]


# ── JSON body pollution payloads ──────────────────────────────

def _json_payloads(canary: str) -> list[tuple[dict, str]]:
    """Returns (json_body, description) tuples for JSON body testing."""
    return [
        (
            {"__proto__": {"polluted": canary}},
            "JSON __proto__ object injection",
        ),
        (
            {"constructor": {"prototype": {"polluted": canary}}},
            "JSON constructor.prototype injection",
        ),
        (
            {"__proto__": {"status": 510}},
            "JSON __proto__.status (response code pollution)",
        ),
        (
            {"__proto__": {"json spaces": canary}},
            "JSON __proto__.json spaces (Express.js detection)",
        ),
        (
            {"__proto__": {"content-type": "text/html"}},
            "JSON __proto__.content-type (header pollution)",
        ),
        (
            {"__proto__": {"__proto__": {"polluted": canary}}},
            "JSON nested __proto__ (double proto)",
        ),
        (
            {"a": 1, "__proto__": {"polluted": canary, "isAdmin": True}},
            "JSON __proto__ with isAdmin escalation",
        ),
    ]


# ── Detection patterns ────────────────────────────────────────

_STATUS_POLLUTION_CODE = 510  # Use uncommon status code as indicator
_EXPRESS_JSON_SPACES_INDICATOR = "json spaces"


# ── Main checker ──────────────────────────────────────────────

async def check_prototype_pollution(
    target_urls: list[str],
    max_concurrent: int = 3,
    timeout: float = 10.0,
) -> list[Finding]:
    """
    Test URLs for prototype pollution vulnerabilities.

    Strategy:
    1. Query parameter pollution (GET & POST form-encoded)
    2. JSON body pollution (POST/PUT/PATCH)
    3. Response analysis for pollution indicators

    Args:
        target_urls: URLs to test.
        max_concurrent: Concurrency limit.
        timeout: Per-request timeout.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WhiteHatHackerAI/2.1"},
    ) as client:
        tasks = []
        for url in target_urls:
            tasks.append(_test_url(client, url, sem))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug(f"Prototype pollution check error: {result}")

    logger.info(f"Prototype pollution check completed: {len(findings)} findings")
    return findings


async def _test_url(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Test a single URL for prototype pollution."""
    findings: list[Finding] = []

    url = url.rstrip("/")
    if not url.startswith("http"):
        url = f"https://{url}"

    # Phase 1: GET query parameter pollution
    findings.extend(await _test_query_params_get(client, url, sem))

    # Phase 2: POST JSON body pollution
    findings.extend(await _test_json_body(client, url, sem))

    # Phase 3: POST form-encoded parameter pollution
    findings.extend(await _test_form_params(client, url, sem))

    return findings


# ── Phase 1: GET Query Parameter Pollution ────────────────────

async def _test_query_params_get(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Test for prototype pollution via GET query parameters."""
    findings: list[Finding] = []
    canary = _canary()

    # First, get a baseline
    async with sem:
        try:
            baseline_resp = await client.get(url)
            baseline_status = baseline_resp.status_code
            baseline_headers = dict(baseline_resp.headers)
            baseline_body = baseline_resp.text
        except httpx.HTTPError:
            return findings

    # Validate baseline — if it's WAF/error, skip this URL entirely
    _bl_vr = _response_validator.validate_for_checker(
        baseline_status, baseline_headers, baseline_body,
        checker_name="prototype_pollution_checker", url=url,
    )
    if not _bl_vr.is_valid:
        return findings

    for param_name, param_value, description in _query_payloads(canary):
        async with sem:
            try:
                separator = "&" if "?" in url else "?"
                test_url = f"{url}{separator}{param_name}={param_value}"

                resp = await client.get(test_url)

                # ── ResponseValidator: reject WAF/redirect/error pages ──
                _vr = _response_validator.validate_for_checker(
                    resp.status_code, dict(resp.headers), resp.text,
                    checker_name="prototype_pollution_checker", url=test_url,
                )
                if not _vr.is_valid and resp.status_code != _STATUS_POLLUTION_CODE:
                    continue
                if _is_waf_or_error_page(resp.text) and resp.status_code != _STATUS_POLLUTION_CODE:
                    continue

                # Detection 1: Status code pollution (510)
                if param_value == "510" and resp.status_code == _STATUS_POLLUTION_CODE:
                    findings.append(Finding(
                        title="Server-Side Prototype Pollution (Status Code)",
                        description=(
                            "Injecting __proto__[status]=510 via query parameter caused the "
                            "server to respond with HTTP 510. This confirms server-side "
                            "prototype pollution in a Node.js/Express application."
                        ),
                        vulnerability_type="prototype_pollution",
                        severity=SeverityLevel.CRITICAL,
                        confidence=95.0,
                        target=url,
                        endpoint=test_url,
                        parameter=param_name,
                        payload=param_value,
                        evidence=f"Status changed: {baseline_status} → {resp.status_code}",
                        tool_name="prototype_pollution_checker",
                        cwe_id="CWE-1321",
                        tags=["prototype-pollution", "server-side", "status-code"],
                        metadata={"baseline_status": baseline_status, "polluted_status": resp.status_code},
                    ))
                    continue

                # Detection 2: Canary reflected in response body
                # Reject if canary is in a WAF/error page (not real app content)
                if canary in resp.text and canary not in baseline_body and not _is_waf_or_error_page(resp.text):
                    findings.append(Finding(
                        title="Prototype Pollution via Query Parameter",
                        description=(
                            f"{description}. The canary value '{canary}' injected via "
                            f"'{param_name}' appeared in the response body, indicating "
                            f"the prototype chain was modified."
                        ),
                        vulnerability_type="prototype_pollution",
                        severity=SeverityLevel.HIGH,
                        confidence=80.0,
                        target=url,
                        endpoint=test_url,
                        parameter=param_name,
                        payload=param_value,
                        evidence=f"Canary '{canary}' found in response body",
                        tool_name="prototype_pollution_checker",
                        cwe_id="CWE-1321",
                        tags=["prototype-pollution", "query-param"],
                    ))
                    continue

                # Detection 3: New headers appear in response
                new_headers = set(resp.headers.keys()) - set(baseline_headers.keys())
                if new_headers:
                    for nh in new_headers:
                        if canary in resp.headers.get(nh, ""):
                            findings.append(Finding(
                                title="Prototype Pollution: Header Injection",
                                description=(
                                    f"{description}. The canary appeared in a new response header "
                                    f"'{nh}', confirming prototype pollution affects HTTP headers."
                                ),
                                vulnerability_type="prototype_pollution",
                                severity=SeverityLevel.HIGH,
                                confidence=85.0,
                                target=url,
                                endpoint=test_url,
                                parameter=param_name,
                                payload=param_value,
                                evidence=f"New header '{nh}: {resp.headers[nh][:200]}' contains canary",
                                tool_name="prototype_pollution_checker",
                                cwe_id="CWE-1321",
                                tags=["prototype-pollution", "header-injection"],
                            ))

                # Detection 4: Response body format changed (JSON spaces)
                if "json spaces" in param_name.lower() or "spaces" in param_name.lower():
                    # Express.js JSON spaces pollution: extra whitespace in JSON response
                    if (
                        resp.headers.get("content-type", "").startswith("application/json")
                        and "  " in resp.text  # indented JSON (not just minified)
                        and "  " not in baseline_body  # baseline was minified
                    ):
                        findings.append(Finding(
                            title="Prototype Pollution: Express.js JSON Spaces",
                            description=(
                                "Injecting __proto__[spaces] changed the JSON response formatting "
                                "from minified to indented, confirming server-side prototype "
                                "pollution in an Express.js application."
                            ),
                            vulnerability_type="prototype_pollution",
                            severity=SeverityLevel.HIGH,
                            confidence=90.0,
                            target=url,
                            endpoint=test_url,
                            parameter=param_name,
                            payload=param_value,
                            evidence="JSON response changed from minified to indented",
                            tool_name="prototype_pollution_checker",
                            cwe_id="CWE-1321",
                            tags=["prototype-pollution", "express", "json-spaces"],
                        ))

            except httpx.HTTPError as e:
                logger.debug(f"Proto pollution query test error: {e}")
            except Exception as _exc:
                logger.debug(f"prototype pollution checker error: {_exc}")

    return findings


# ── Phase 2: JSON Body Pollution ──────────────────────────────

async def _test_json_body(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Test for prototype pollution via JSON body in POST/PUT/PATCH."""
    findings: list[Finding] = []
    canary = _canary()

    # Common API-like paths to test JSON bodies on

    # Get baseline for the URL
    async with sem:
        try:
            baseline = await client.get(url)
        except httpx.HTTPError:
            return findings

    for json_body, description in _json_payloads(canary):
        for method in ["POST"]:  # Limit to POST to reduce noise
            async with sem:
                try:
                    resp = await client.request(
                        method, url,
                        json=json_body,
                        headers={"Content-Type": "application/json"},
                    )

                    # ── ResponseValidator: reject WAF/redirect/error pages ──
                    _vr = _response_validator.validate_for_checker(
                        resp.status_code, dict(resp.headers), resp.text,
                        checker_name="prototype_pollution_checker", url=url,
                    )
                    if not _vr.is_valid and resp.status_code != _STATUS_POLLUTION_CODE:
                        continue
                    if _is_waf_or_error_page(resp.text) and resp.status_code != _STATUS_POLLUTION_CODE:
                        continue

                    # Detection 1: Status code 510
                    status_payload = json_body.get("__proto__", {})
                    if isinstance(status_payload, dict) and status_payload.get("status") == 510:
                        if resp.status_code == _STATUS_POLLUTION_CODE:
                            findings.append(Finding(
                                title="Server-Side Prototype Pollution via JSON Body",
                                description=(
                                    "Sending __proto__.status=510 in JSON body caused HTTP 510 response. "
                                    "This confirms server-side prototype pollution."
                                ),
                                vulnerability_type="prototype_pollution",
                                severity=SeverityLevel.CRITICAL,
                                confidence=95.0,
                                target=url,
                                endpoint=url,
                                payload=json.dumps(json_body),
                                evidence=f"Status: {resp.status_code} (expected 510)",
                                tool_name="prototype_pollution_checker",
                                cwe_id="CWE-1321",
                                tags=["prototype-pollution", "json-body", "server-side"],
                            ))
                            continue

                    # Detection 2: Canary in response
                    if canary in resp.text:
                        findings.append(Finding(
                            title=f"Prototype Pollution via JSON Body ({method})",
                            description=(
                                f"{description}. Canary '{canary}' found in response after "
                                f"sending polluted JSON body."
                            ),
                            vulnerability_type="prototype_pollution",
                            severity=SeverityLevel.HIGH,
                            confidence=75.0,
                            target=url,
                            endpoint=url,
                            payload=json.dumps(json_body)[:300],
                            evidence=f"Canary '{canary}' in response body",
                            tool_name="prototype_pollution_checker",
                            cwe_id="CWE-1321",
                            tags=["prototype-pollution", "json-body"],
                        ))

                    # Detection 3: Content-type pollution
                    ct_payload = json_body.get("__proto__", {})
                    if isinstance(ct_payload, dict) and "content-type" in ct_payload:
                        actual_ct = resp.headers.get("content-type", "")
                        if "text/html" in actual_ct and "text/html" not in (
                            baseline.headers.get("content-type", "")
                        ):
                            findings.append(Finding(
                                title="Prototype Pollution: Content-Type Override",
                                description=(
                                    "Injecting __proto__['content-type'] = 'text/html' changed "
                                    "the response Content-Type header, confirming server-side "
                                    "prototype pollution with header control."
                                ),
                                vulnerability_type="prototype_pollution",
                                severity=SeverityLevel.HIGH,
                                confidence=90.0,
                                target=url,
                                endpoint=url,
                                payload=json.dumps(json_body),
                                evidence=f"Content-Type changed to: {actual_ct}",
                                tool_name="prototype_pollution_checker",
                                cwe_id="CWE-1321",
                                tags=["prototype-pollution", "content-type", "header-override"],
                            ))

                except httpx.HTTPError as exc:
                    logger.debug(f"Prototype pollution probe HTTP error: {exc}")
                except Exception as _exc:
                    logger.debug(f"prototype pollution checker error: {_exc}")

    return findings


# ── Phase 3: Form-Encoded Parameter Pollution ─────────────────

async def _test_form_params(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Test for prototype pollution via form-encoded POST parameters."""
    findings: list[Finding] = []
    canary = _canary()

    form_payloads = [
        ({"__proto__[polluted]": canary}, "Form-encoded __proto__[polluted]"),
        ({"constructor[prototype][polluted]": canary}, "Form-encoded constructor.prototype"),
        ({"__proto__[status]": "510"}, "Form-encoded __proto__[status]=510"),
    ]

    # Baseline
    async with sem:
        try:
            await client.get(url)
        except httpx.HTTPError:
            return findings

    for form_data, description in form_payloads:
        async with sem:
            try:
                resp = await client.post(
                    url,
                    data=form_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                # ── ResponseValidator: reject WAF/redirect/error pages ──
                _vr = _response_validator.validate_for_checker(
                    resp.status_code, dict(resp.headers), resp.text,
                    checker_name="prototype_pollution_checker", url=url,
                )
                if not _vr.is_valid and resp.status_code != _STATUS_POLLUTION_CODE:
                    continue
                if _is_waf_or_error_page(resp.text) and resp.status_code != _STATUS_POLLUTION_CODE:
                    continue

                # Status code pollution
                if "510" in str(form_data.values()) and resp.status_code == _STATUS_POLLUTION_CODE:
                    findings.append(Finding(
                        title="Server-Side Prototype Pollution via Form POST",
                        description=(
                            f"{description}: HTTP 510 response confirms prototype pollution."
                        ),
                        vulnerability_type="prototype_pollution",
                        severity=SeverityLevel.CRITICAL,
                        confidence=95.0,
                        target=url,
                        endpoint=url,
                        payload=str(form_data),
                        evidence=f"Status: {resp.status_code}",
                        tool_name="prototype_pollution_checker",
                        cwe_id="CWE-1321",
                        tags=["prototype-pollution", "form-post", "server-side"],
                    ))
                elif canary in resp.text:
                    findings.append(Finding(
                        title="Prototype Pollution via Form POST",
                        description=f"{description}: canary reflected in response.",
                        vulnerability_type="prototype_pollution",
                        severity=SeverityLevel.HIGH,
                        confidence=75.0,
                        target=url,
                        endpoint=url,
                        payload=str(form_data),
                        evidence=f"Canary '{canary}' in response",
                        tool_name="prototype_pollution_checker",
                        cwe_id="CWE-1321",
                        tags=["prototype-pollution", "form-post"],
                    ))

            except httpx.HTTPError as exc:
                logger.debug(f"Prototype pollution param probe HTTP error: {exc}")
            except Exception as _exc:
                logger.debug(f"prototype pollution checker error: {_exc}")

    return findings


__all__ = ["check_prototype_pollution"]
