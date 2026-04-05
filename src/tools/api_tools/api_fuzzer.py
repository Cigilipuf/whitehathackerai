"""
WhiteHatHacker AI — API Schema Fuzzer (T3-4)

Takes structured endpoint data (from Swagger/OpenAPI/GraphQL parsing) and
performs targeted fuzzing of each parameter with type-aware payloads.

Capabilities:
- Parameter-level injection testing (SQLi, XSS, SSTI, command injection)
- Type-aware payload generation (string/int/array/object)
- BOLA/IDOR detection via ID manipulation
- Parameter pollution (duplicates, type juggling)
- Response differential analysis (status codes, error message leaks)
- Auth-aware requests (Bearer token, API key injection)

References:
- OWASP API Security Top 10 2023
- CWE-20: Improper Input Validation
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel


# ── Fuzzing payloads per vulnerability type ──────────────────

_PAYLOADS: dict[str, list[tuple[str, str, str]]] = {
    # (payload_value, vuln_type, cwe_id)
    "string": [
        ("' OR 1=1--", "sql_injection", "CWE-89"),
        ('" OR ""="', "sql_injection", "CWE-89"),
        ("{{7*7}}", "ssti", "CWE-1336"),
        ("${7*7}", "ssti", "CWE-1336"),
        ("<script>alert(1)</script>", "xss", "CWE-79"),
        ("<img src=x onerror=alert(1)>", "xss", "CWE-79"),
        ("; id", "command_injection", "CWE-78"),
        ("| cat /etc/passwd", "command_injection", "CWE-78"),
        ("../../../etc/passwd", "path_traversal", "CWE-22"),
        ("....//....//etc/passwd", "path_traversal", "CWE-22"),
        ("admin", "unauthorized_access", "CWE-284"),
    ],
    "integer": [
        ("0", "boundary", "CWE-20"),
        ("-1", "boundary", "CWE-20"),
        ("99999999", "boundary", "CWE-20"),
        ("1 OR 1=1", "sql_injection", "CWE-89"),
        ("NaN", "type_juggling", "CWE-843"),
        ("null", "type_juggling", "CWE-843"),
    ],
    "array": [
        ("[]", "empty_input", "CWE-20"),
        ('[{"__proto__":{"admin":true}}]', "prototype_pollution", "CWE-1321"),
    ],
    "boolean": [
        ("true", "auth_bypass", "CWE-284"),
        ("2", "type_juggling", "CWE-843"),
    ],
}

# Known error patterns that indicate the payload was processed
_ERROR_PATTERNS: list[tuple[str, str, str]] = [
    ("sql", "sql_injection", "CWE-89"),
    ("syntax error", "sql_injection", "CWE-89"),
    ("ORA-", "sql_injection", "CWE-89"),
    ("mysql", "sql_injection", "CWE-89"),
    ("postgres", "sql_injection", "CWE-89"),
    ("sqlite3", "sql_injection", "CWE-89"),
    ("stack trace", "information_disclosure", "CWE-209"),
    ("traceback", "information_disclosure", "CWE-209"),
    ("exception", "information_disclosure", "CWE-209"),
    ("internal server error", "information_disclosure", "CWE-209"),
    ("at line", "information_disclosure", "CWE-209"),
    ("template", "ssti", "CWE-1336"),
    ("jinja", "ssti", "CWE-1336"),
    ("49", "ssti", "CWE-1336"),  # 7*7 result
]


async def fuzz_api_endpoints(
    endpoints: list[dict[str, Any]],
    auth_headers: dict[str, str] | None = None,
    max_concurrent: int = 3,
    timeout: float = 10.0,
    max_endpoints: int = 50,
) -> list[Finding]:
    """
    Fuzz API endpoints extracted from OpenAPI/Swagger specs.

    Args:
        endpoints: List of endpoint dicts from SwaggerParserWrapper.extract_fuzzable_endpoints()
            Each dict has: method, path, url, parameters, has_auth, content_types
        auth_headers: Optional auth headers (e.g. {"Authorization": "Bearer xxx"})
        max_concurrent: Max concurrent HTTP requests
        timeout: Per-request timeout
        max_endpoints: Max endpoints to fuzz

    Returns:
        List of Finding objects for detected issues
    """
    if not endpoints:
        return []

    # Skip deprecated endpoints
    active = [e for e in endpoints if not e.get("deprecated")]
    # Prioritize endpoints with parameters
    active.sort(key=lambda e: -len(e.get("parameters", [])))
    active = active[:max_endpoints]

    logger.info(f"API fuzzer: fuzzing {len(active)} endpoints ({len(endpoints)} total)")

    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)

    per_request_timeout = min(timeout, 30.0)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(per_request_timeout, connect=10),
        follow_redirects=False,
        verify=False,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; WhiteHatHackerAI/2.2)",
            **(auth_headers or {}),
        },
    ) as client:
        # Step 1: Get baseline responses for each endpoint
        baselines: dict[str, dict] = {}
        for ep in active:
            async with sem:
                # Ensure url is a string (Swagger parsers may produce lists)
                ep_url = ep.get("url", "")
                if isinstance(ep_url, list):
                    ep_url = ep_url[0] if ep_url else ""
                    ep["url"] = ep_url
                if not isinstance(ep_url, str) or not ep_url:
                    continue
                bl = await _get_baseline(client, ep)
                if bl:
                    baselines[ep_url] = bl

        # Step 2: Fuzz each endpoint's parameters
        tasks = []
        for ep in active:
            ep_url = ep.get("url", "")
            if isinstance(ep_url, list):
                ep_url = ep_url[0] if ep_url else ""
                ep["url"] = ep_url
            bl = baselines.get(ep_url) if isinstance(ep_url, str) else None
            if not bl:
                continue
            for param in ep.get("parameters", []):
                tasks.append(_fuzz_parameter(client, ep, param, bl, sem))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug(f"API fuzz error: {result}")

    # Step 3: BOLA/IDOR check — test ID params with different values
    idor_findings = await _check_bola(endpoints, auth_headers, sem, timeout)
    findings.extend(idor_findings)

    logger.info(f"API fuzzer: {len(findings)} findings from {len(active)} endpoints")
    return findings


async def _get_baseline(
    client: httpx.AsyncClient,
    endpoint: dict[str, Any],
) -> dict | None:
    """Get a baseline response for an endpoint with benign values."""
    method = endpoint["method"]
    url = endpoint["url"]

    # Replace path parameters with benign value
    url = _replace_path_params(url, "1")

    try:
        if method in ("GET", "HEAD", "OPTIONS"):
            resp = await client.request(method, url)
        else:
            resp = await client.request(method, url, json={})
        return {
            "status": resp.status_code,
            "body_len": len(resp.text),
            "body_hash": hash(resp.text[:500]),
            "content_type": resp.headers.get("content-type", ""),
        }
    except (httpx.HTTPError, Exception):
        return None


async def _fuzz_parameter(
    client: httpx.AsyncClient,
    endpoint: dict[str, Any],
    param: dict[str, Any],
    baseline: dict,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Fuzz a single parameter with type-appropriate payloads."""
    findings: list[Finding] = []
    param_name = param.get("name", "")
    param_type = param.get("type", "string")
    param_in = param.get("in", "query")
    method = endpoint["method"]
    url = endpoint["url"]

    # Replace path parameters
    url = _replace_path_params(url, "1")

    # Select payloads based on type
    payload_set = _PAYLOADS.get(param_type, _PAYLOADS["string"])

    for payload_value, vuln_type, cwe_id in payload_set:
        async with sem:
            try:
                resp = await _send_fuzzed_request(
                    client, method, url, param_name, param_in,
                    payload_value, endpoint.get("content_types", ["application/json"]),
                )
                if not resp:
                    continue

                # Analyze response for anomalies
                finding = _analyze_fuzz_response(
                    resp, baseline, endpoint, param_name,
                    payload_value, vuln_type, cwe_id,
                )
                if finding:
                    findings.append(finding)

            except (httpx.HTTPError, Exception):
                continue

    return findings


async def _send_fuzzed_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    param_name: str,
    param_in: str,
    payload: str,
    content_types: list[str],
) -> httpx.Response | None:
    """Send a request with a fuzzed parameter value."""
    try:
        if param_in == "query":
            sep = "&" if "?" in url else "?"
            fuzzed_url = f"{url}{sep}{param_name}={payload}"
            return await client.request(method, fuzzed_url)

        elif param_in == "header":
            return await client.request(method, url, headers={param_name: payload})

        elif param_in in ("body", "formData"):
            if "application/json" in content_types:
                return await client.request(method, url, json={param_name: payload})
            else:
                return await client.request(method, url, data={param_name: payload})

        elif param_in == "path":
            # Replace the path param placeholder
            fuzzed_url = url.replace(f"{{{param_name}}}", payload)
            return await client.request(method, fuzzed_url)

    except (httpx.HTTPError, Exception):
        return None
    return None


def _analyze_fuzz_response(
    resp: httpx.Response,
    baseline: dict,
    endpoint: dict,
    param_name: str,
    payload: str,
    vuln_type: str,
    cwe_id: str,
) -> Finding | None:
    """Analyze a fuzzed response for signs of vulnerability."""
    body = resp.text[:5000].lower()
    status = resp.status_code

    # Check for error pattern matches
    for pattern, err_type, err_cwe in _ERROR_PATTERNS:
        if pattern in body and err_type == vuln_type:
            return Finding(
                title=f"API {vuln_type.replace('_', ' ').title()}: {endpoint['method']} {endpoint['path']}",
                description=(
                    f"The API endpoint {endpoint['url']} returned an error response "
                    f"when parameter '{param_name}' was set to a {vuln_type} payload.\n"
                    f"This indicates the input may not be properly validated/sanitized.\n"
                    f"Payload: {payload}\nStatus: {status}"
                ),
                vulnerability_type=vuln_type,
                severity=SeverityLevel.HIGH if vuln_type in ("sql_injection", "command_injection") else SeverityLevel.MEDIUM,
                confidence=65.0,
                target=endpoint["url"],
                endpoint=endpoint["url"],
                parameter=param_name,
                payload=payload,
                tool_name="api_fuzzer",
                cwe_id=err_cwe,
                tags=["api", "fuzzing", vuln_type],
                evidence=f"Status: {status}\nBody snippet: {resp.text[:300]}",
            )

    # Check for payload reflection (XSS)
    if vuln_type == "xss" and payload.lower() in body:
        return Finding(
            title=f"API XSS Reflection: {endpoint['method']} {endpoint['path']}",
            description=(
                f"The API endpoint reflects the XSS payload in its response without encoding.\n"
                f"Parameter: {param_name}\nPayload: {payload}"
            ),
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            confidence=60.0,
            target=endpoint["url"],
            endpoint=endpoint["url"],
            parameter=param_name,
            payload=payload,
            tool_name="api_fuzzer",
            cwe_id="CWE-79",
            tags=["api", "fuzzing", "xss", "reflection"],
            evidence=f"Payload reflected in response:\n{resp.text[:300]}",
        )

    # Status code anomaly (5xx on injection = possible processing)
    if status >= 500 and baseline["status"] < 500:
        return Finding(
            title=f"API Server Error on Fuzzed Input: {endpoint['method']} {endpoint['path']}",
            description=(
                f"The API returned a {status} error when '{param_name}' was set to "
                f"'{payload}' (baseline was {baseline['status']}). "
                f"This may indicate improper input handling."
            ),
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.LOW,
            confidence=40.0,
            target=endpoint["url"],
            endpoint=endpoint["url"],
            parameter=param_name,
            payload=payload,
            tool_name="api_fuzzer",
            cwe_id="CWE-209",
            tags=["api", "fuzzing", "server_error"],
            evidence=f"Baseline: {baseline['status']}, Fuzzed: {status}\nBody: {resp.text[:200]}",
        )

    return None


async def _check_bola(
    endpoints: list[dict[str, Any]],
    auth_headers: dict[str, str] | None,
    sem: asyncio.Semaphore,
    timeout: float,
) -> list[Finding]:
    """
    Basic BOLA/IDOR check: swap ID-like path parameters.

    If accessing resource with ID=2 when only ID=1 belongs to the user
    returns 200, there may be a BOLA issue.
    """
    findings: list[Finding] = []

    # Find endpoints with path params that look like IDs
    id_endpoints = []
    for ep in endpoints:
        for param in ep.get("parameters", []):
            if param.get("in") == "path" and any(
                kw in param.get("name", "").lower()
                for kw in ("id", "uid", "user_id", "account", "order")
            ):
                id_endpoints.append((ep, param))

    if not id_endpoints:
        return findings

    bola_timeout = min(timeout, 30.0)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(bola_timeout, connect=10),
        follow_redirects=False,
        verify=False,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; WhiteHatHackerAI/2.2)",
            **(auth_headers or {}),
        },
    ) as client:
        for ep, param in id_endpoints[:10]:  # Cap at 10
            url = ep["url"]
            pname = param["name"]

            async with sem:
                try:
                    # Request with ID=1
                    url_1 = url.replace(f"{{{pname}}}", "1")
                    resp_1 = await client.request(ep["method"], url_1)

                    # Request with ID=2
                    url_2 = url.replace(f"{{{pname}}}", "2")
                    resp_2 = await client.request(ep["method"], url_2)

                    # If both return 200 with different content, potential BOLA
                    if (
                        resp_1.status_code == 200
                        and resp_2.status_code == 200
                        and resp_1.text != resp_2.text
                        and len(resp_2.text) > 50
                    ):
                        findings.append(Finding(
                            title=f"Potential BOLA/IDOR: {ep['method']} {ep['path']}",
                            description=(
                                f"Different resource IDs return different valid responses, "
                                f"suggesting the API may not properly validate object-level "
                                f"authorization.\n"
                                f"Endpoint: {ep['url']}\n"
                                f"Parameter: {pname}\n"
                                f"Note: Verify with authenticated session — this may be "
                                f"by-design for public resources."
                            ),
                            vulnerability_type="idor",
                            severity=SeverityLevel.HIGH,
                            confidence=40.0,  # Low confidence — needs auth context
                            target=ep["url"],
                            endpoint=ep["url"],
                            parameter=pname,
                            tool_name="api_fuzzer",
                            cwe_id="CWE-639",
                            tags=["api", "bola", "idor"],
                            evidence=(
                                f"ID=1: {resp_1.status_code} ({len(resp_1.text)} bytes)\n"
                                f"ID=2: {resp_2.status_code} ({len(resp_2.text)} bytes)"
                            ),
                        ))

                except (httpx.HTTPError, Exception):
                    continue

    return findings


def _replace_path_params(url: str, value: str) -> str:
    """Replace {param} placeholders in URL with a given value."""
    import re
    return re.sub(r"\{[^}]+\}", value, url)


__all__ = ["fuzz_api_endpoints"]
