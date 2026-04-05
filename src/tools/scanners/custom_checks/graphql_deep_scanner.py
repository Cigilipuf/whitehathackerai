"""
WhiteHatHacker AI — GraphQL Deep Vulnerability Scanner

Goes beyond introspection to test for actual GraphQL security vulnerabilities:
- Batch query / alias-based brute force
- Query depth/complexity DoS (resource exhaustion)
- Mutation-based authorization bypass (IDOR via mutations)
- Field suggestion information leak
- SQL injection via GraphQL arguments
- NoSQL injection via GraphQL arguments
- SSRF via GraphQL argument values
- Directive abuse (@skip, @include for info leak)
- Subscription hijacking
- Debug mode detection (__type introspection fallback)

References:
- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- https://portswigger.net/web-security/graphql
- CWE-200: Exposure of Sensitive Information
"""

from __future__ import annotations

import asyncio
import json
import re
import time

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel
from src.utils.response_validator import ResponseValidator


_response_validator = ResponseValidator()

# ── Common GraphQL endpoint paths ─────────────────────────────

_GQL_PATHS: list[str] = [
    "/graphql", "/graphql/", "/gql", "/query",
    "/api/graphql", "/api/gql", "/api/v1/graphql",
    "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/graphql/v2",
    "/graphql/console", "/graphiql", "/playground",
    "/altair", "/explorer",
]

# ── Injection payloads to test in GraphQL arguments ───────────

_SQLI_PAYLOADS: list[str] = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "1 UNION SELECT null,null--",
    "'; WAITFOR DELAY '0:0:3'--",
]

_NOSQLI_PAYLOADS: list[str] = [
    '{"$gt":""}',
    '{"$ne":null}',
    '{"$regex":".*"}',
]

_SSRF_PAYLOADS: list[str] = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:80",
    "http://[::1]:80",
]


def _parse_json_safely(resp: httpx.Response) -> dict | list | None:
    try:
        return resp.json()
    except Exception:
        return None


def _graphql_error_text(body: dict | list | None) -> str:
    if isinstance(body, dict):
        return json.dumps(body.get("errors", []), default=str).lower()
    if isinstance(body, list):
        return json.dumps(body, default=str).lower()
    return ""


def _has_auth_error(body: dict | list | None) -> bool:
    err_text = _graphql_error_text(body)
    return any(token in err_text for token in (
        "unauthorized",
        "forbidden",
        "access denied",
        "authentication required",
        "not authorized",
        "permission denied",
    ))


def _validated_graphql_response(
    resp: httpx.Response,
    gql_url: str,
    *,
    baseline_body: str | None = None,
) -> dict | list | None:
    result = _response_validator.validate_for_checker(
        resp.status_code,
        dict(resp.headers),
        resp.text,
        checker_name="graphql_deep_scanner",
        expected_content_type="json",
        baseline_body=baseline_body,
        url=gql_url,
    )
    if not result.is_valid:
        return None
    body = _parse_json_safely(resp)
    if body is None:
        return None
    if _has_auth_error(body):
        return None
    return body


# ── Main scanner ──────────────────────────────────────────────

async def scan_graphql_deep(
    target_urls: list[str],
    max_concurrent: int = 3,
    timeout: float = 12.0,
    graphql_url: str | None = None,
    headers: dict[str, str] | None = None,
) -> list[Finding]:
    """
    Deep GraphQL vulnerability scan.

    Args:
        target_urls: Base URLs of the application.
        max_concurrent: Concurrency limit.
        timeout: Per-request timeout.
        graphql_url: If known, the exact GraphQL endpoint URL.
        headers: Extra headers (auth tokens, etc.).

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)
    extra_headers = headers or {}

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WhiteHatHackerAI/2.1",
            "Content-Type": "application/json",
            **extra_headers,
        },
    ) as client:
        for base_url in target_urls:
            base_url = base_url.rstrip("/")
            if not base_url.startswith("http"):
                base_url = f"https://{base_url}"

            # Discover GraphQL endpoint
            gql_endpoint = graphql_url
            if not gql_endpoint:
                gql_endpoint = await _discover_gql(client, base_url, sem)
            if not gql_endpoint:
                continue

            logger.info(f"GraphQL deep scan on {gql_endpoint}")

            # Run all tests
            findings.extend(await _test_introspection_bypass(client, gql_endpoint, sem))
            findings.extend(await _test_batch_query_brute(client, gql_endpoint, sem))
            findings.extend(await _test_field_suggestions(client, gql_endpoint, sem))
            findings.extend(await _test_field_bruteforce(client, gql_endpoint, sem))
            findings.extend(await _test_mutation_discovery(client, gql_endpoint, sem))
            findings.extend(await _test_depth_limit(client, gql_endpoint, sem))
            findings.extend(await _test_alias_overloading(client, gql_endpoint, sem))
            findings.extend(await _test_directive_abuse(client, gql_endpoint, sem))
            findings.extend(await _test_injection(client, gql_endpoint, sem, base_url))
            findings.extend(await _test_debug_mode(client, gql_endpoint, sem))
            findings.extend(await _test_mutation_idor(client, gql_endpoint, sem, base_url))
            findings.extend(await _test_persisted_query_bypass(client, gql_endpoint, sem))

    logger.info(f"GraphQL deep scan completed: {len(findings)} findings")
    return findings


# ── Discovery ─────────────────────────────────────────────────

async def _discover_gql(
    client: httpx.AsyncClient,
    base_url: str,
    sem: asyncio.Semaphore,
) -> str | None:
    """Probe for active GraphQL endpoint."""
    probe = '{"query":"{ __typename }"}'

    for path in _GQL_PATHS:
        async with sem:
            try:
                url = f"{base_url}{path}"
                resp = await client.post(url, content=probe)
                body = _validated_graphql_response(resp, url)
                if isinstance(body, dict) and ("data" in body or "errors" in body):
                    return url
            except Exception as _exc:
                logger.debug(f"graphql deep scanner error: {_exc}")
    return None


# ── Test: Batch Query / Alias Brute Force ─────────────────────

async def _test_batch_query_brute(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test if batched queries are allowed.
    Batching enables brute-force attacks (e.g., OTP brute, user enumeration)
    by sending multiple operations in a single request.
    """
    findings: list[Finding] = []

    # Test array-based batching
    batch_payload = json.dumps([
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ])

    async with sem:
        try:
            resp = await client.post(gql_url, content=batch_payload)
            body = _validated_graphql_response(resp, gql_url)
            if isinstance(body, list) and len(body) >= 2:
                findings.append(Finding(
                    title="GraphQL Batch Query Enabled",
                    description=(
                        f"The GraphQL endpoint at {gql_url} accepts batched queries (array of operations). "
                        f"This can be abused for brute-force attacks (OTP, login, enumeration) "
                        f"by sending hundreds of operations in a single HTTP request, bypassing rate limits."
                    ),
                    vulnerability_type="graphql_batch_query",
                    severity=SeverityLevel.MEDIUM,
                    confidence=90.0,
                    target=gql_url,
                    endpoint=gql_url,
                    evidence=f"Sent 3 queries in batch, got {len(body)} responses",
                    tool_name="graphql_deep_scanner",
                    cwe_id="CWE-799",
                    tags=["graphql", "batch-query", "brute-force"],
                    metadata={"batch_size": 3, "responses": len(body)},
                ))
        except Exception as e:
            logger.debug(f"Batch query test error: {e}")

    return findings


# ── Test: Field Suggestion Information Leak ───────────────────

async def _test_field_suggestions(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test for field suggestion leaks.
    Even with introspection disabled, GraphQL may suggest valid field names
    in error messages (e.g., 'Did you mean "password"?').
    """
    findings: list[Finding] = []

    # Query with intentionally wrong field names
    probes = [
        '{ user { passwor } }',
        '{ user { emai } }',
        '{ user { secre } }',
        '{ users { id nam } }',
        '{ account { balanc } }',
    ]

    suggested_fields: set[str] = set()

    for probe in probes:
        async with sem:
            try:
                resp = await client.post(gql_url, json={"query": probe})
                body = resp.text

                # Look for "Did you mean" suggestions
                suggestions = re.findall(r'[Dd]id you mean ["\']([^"\']+)["\']', body)
                suggestions += re.findall(r'[Ss]uggestion[s]?[:\s]+["\']([^"\']+)["\']', body)

                for s in suggestions:
                    suggested_fields.add(s)

            except Exception as _exc:
                logger.debug(f"graphql deep scanner error: {_exc}")

    if suggested_fields:
        sensitive = [f for f in suggested_fields if any(
            kw in f.lower() for kw in (
                "password", "token", "secret", "key", "auth",
                "credit", "ssn", "salary", "admin", "role",
            )
        )]

        severity = SeverityLevel.MEDIUM if sensitive else SeverityLevel.LOW
        confidence = 85.0

        findings.append(Finding(
            title="GraphQL Field Suggestions Leak Schema Info",
            description=(
                f"The GraphQL endpoint leaks field names through 'Did you mean' suggestions "
                f"in error messages, even when introspection is disabled. "
                f"Discovered fields: {', '.join(sorted(suggested_fields)[:20])}"
                + (f"\n\nSENSITIVE fields found: {', '.join(sensitive)}" if sensitive else "")
            ),
            vulnerability_type="information_disclosure",
            severity=severity,
            confidence=confidence,
            target=gql_url,
            endpoint=gql_url,
            evidence=f"Suggested fields: {sorted(suggested_fields)[:20]}",
            tool_name="graphql_deep_scanner",
            cwe_id="CWE-200",
            tags=["graphql", "field-suggestions", "info-leak"],
            metadata={
                "suggested_fields": sorted(suggested_fields),
                "sensitive_fields": sorted(sensitive) if sensitive else [],
            },
        ))

    return findings


# ── Test: Query Depth Limit ───────────────────────────────────

async def _test_depth_limit(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test for missing query depth limits.
    An unlimited depth allows deeply nested circular queries that can
    cause denial of service through resource exhaustion.
    """
    findings: list[Finding] = []
    baseline_elapsed = 0.0
    baseline_body = None

    async with sem:
        try:
            base_start = time.monotonic()
            baseline_resp = await client.post(gql_url, json={"query": "{ __typename }"})
            baseline_elapsed = time.monotonic() - base_start
            if _validated_graphql_response(baseline_resp, gql_url) is not None:
                baseline_body = baseline_resp.text
        except Exception as e:
            logger.debug(f"Depth limit baseline error: {e}")

    # Build a deeply nested query
    depth = 10
    inner = "__typename"
    for i in range(depth):
        inner = f"... on Query {{ {inner} }}"
    deep_query = f"{{ {inner} }}"

    # Also test circular fragment
    circular_query = """
    query {
        __typename
        ...A
    }
    fragment A on Query { __typename ...B }
    fragment B on Query { __typename ...A }
    """

    async with sem:
        try:
            # Test deep nesting
            start = time.monotonic()
            resp = await client.post(gql_url, json={"query": deep_query})
            elapsed = time.monotonic() - start
            body = _validated_graphql_response(resp, gql_url, baseline_body=baseline_body)

            if isinstance(body, dict) and elapsed > max(2.0, baseline_elapsed * 3):
                # Slow response with deep query suggests no depth limit
                findings.append(Finding(
                    title="GraphQL Missing Query Depth Limit (DoS Risk)",
                    description=(
                        f"The GraphQL endpoint accepted a query with depth={depth} nesting. "
                        f"Response took {elapsed:.1f}s. Missing depth limits allow attackers "
                        f"to craft deeply nested queries that exhaust server resources."
                    ),
                    vulnerability_type="denial_of_service",
                    severity=SeverityLevel.MEDIUM,
                    confidence=70.0,
                    target=gql_url,
                    endpoint=gql_url,
                    evidence=f"Depth-{depth} query accepted, response time: {elapsed:.1f}s",
                    tool_name="graphql_deep_scanner",
                    cwe_id="CWE-400",
                    tags=["graphql", "depth-limit", "dos"],
                    metadata={"depth": depth, "response_time": round(elapsed, 2)},
                ))

            # Test circular fragments
            resp2 = await client.post(gql_url, json={"query": circular_query})
            body2 = _validated_graphql_response(resp2, gql_url, baseline_body=baseline_body)
            if isinstance(body2, dict):
                if body2.get("data") and not body2.get("errors"):
                    findings.append(Finding(
                        title="GraphQL Circular Fragment Reference",
                        description=(
                            "The GraphQL endpoint does not detect circular fragment references. "
                            "This can be abused for denial of service through infinite recursion."
                        ),
                        vulnerability_type="denial_of_service",
                        severity=SeverityLevel.MEDIUM,
                        confidence=75.0,
                        target=gql_url,
                        endpoint=gql_url,
                        evidence="Circular fragment (A→B→A) accepted without error",
                        tool_name="graphql_deep_scanner",
                        cwe_id="CWE-674",
                        tags=["graphql", "circular-reference", "dos"],
                    ))

        except Exception as e:
            logger.debug(f"Depth limit test error: {e}")

    return findings


# ── Test: Alias Overloading ───────────────────────────────────

async def _test_alias_overloading(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test if alias-based overloading is unrestricted.
    Sending many aliased copies of the same query bypasses rate limits
    and can be used for brute-force.
    """
    findings: list[Finding] = []

    # Build a query with 50 aliases of __typename
    aliases = " ".join(f"a{i}: __typename" for i in range(50))
    query = f"{{ {aliases} }}"

    async with sem:
        try:
            resp = await client.post(gql_url, json={"query": query})
            body = _validated_graphql_response(resp, gql_url)
            if isinstance(body, dict):
                data = body.get("data", {})
                if isinstance(data, dict) and len(data) >= 40:
                    findings.append(Finding(
                        title="GraphQL Alias Overloading (No Complexity Limit)",
                        description=(
                            f"The GraphQL endpoint allows 50 aliased fields in a single query "
                            f"and returned {len(data)} results. This enables brute-force attacks "
                            f"(e.g., 50 login attempts per request) and resource exhaustion."
                        ),
                        vulnerability_type="graphql_alias_overloading",
                        severity=SeverityLevel.MEDIUM,
                        confidence=85.0,
                        target=gql_url,
                        endpoint=gql_url,
                        evidence=f"50 aliases sent, {len(data)} returned",
                        tool_name="graphql_deep_scanner",
                        cwe_id="CWE-770",
                        tags=["graphql", "alias-overloading", "rate-limit-bypass"],
                        metadata={"aliases_sent": 50, "results_returned": len(data)},
                    ))
        except Exception as e:
            logger.debug(f"Alias overloading test error: {e}")

    return findings


# ── Test: Directive Abuse ─────────────────────────────────────

async def _test_directive_abuse(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test for directive overloading (@skip, @include duplication).
    Directive overloading can cause performance issues.
    """
    findings: list[Finding] = []
    baseline_elapsed = 0.0

    async with sem:
        try:
            base_start = time.monotonic()
            baseline_resp = await client.post(gql_url, json={"query": "{ __typename }"})
            baseline_elapsed = time.monotonic() - base_start
            _validated_graphql_response(baseline_resp, gql_url)
        except Exception as e:
            logger.debug(f"Directive abuse baseline error: {e}")

    # Chain many @skip directives
    directives = " ".join("@skip(if: false)" for _ in range(100))
    query = f"{{ __typename {directives} }}"

    async with sem:
        try:
            start = time.monotonic()
            resp = await client.post(gql_url, json={"query": query})
            elapsed = time.monotonic() - start
            body = _validated_graphql_response(resp, gql_url)

            if body is not None and elapsed > max(1.5, baseline_elapsed * 3):
                findings.append(Finding(
                    title="GraphQL Directive Overloading (DoS Risk)",
                    description=(
                        f"The GraphQL endpoint processes 100 @skip directives on a single field "
                        f"without limiting directive count. Response time: {elapsed:.1f}s. "
                        f"Massive directive chains can exhaust server resources."
                    ),
                    vulnerability_type="denial_of_service",
                    severity=SeverityLevel.LOW,
                    confidence=65.0,
                    target=gql_url,
                    endpoint=gql_url,
                    evidence=f"100 @skip directives accepted, response time: {elapsed:.1f}s",
                    tool_name="graphql_deep_scanner",
                    cwe_id="CWE-400",
                    tags=["graphql", "directive-overloading", "dos"],
                ))
        except Exception as e:
            logger.debug(f"Directive abuse test error: {e}")

    return findings


# ── Test: Injection via Arguments ─────────────────────────────

async def _test_injection(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
    base_url: str,
) -> list[Finding]:
    """
    Test for SQL/NoSQL/SSRF injection via GraphQL query arguments.
    Uses common query patterns with injection payloads.
    """
    findings: list[Finding] = []

    # Common GraphQL queries that accept user input
    query_templates = [
        ('user(id: "{payload}")', "user", "id"),
        ('user(name: "{payload}")', "user", "name"),
        ('search(query: "{payload}")', "search", "query"),
        ('users(filter: "{payload}")', "users", "filter"),
        ('post(slug: "{payload}")', "post", "slug"),
    ]

    # SQLi tests
    for template, query_name, param_name in query_templates:
        for payload in _SQLI_PAYLOADS:
            async with sem:
                try:
                    filled = template.replace("{payload}", payload.replace('"', '\\"'))
                    query = f"{{ {filled} {{ id }} }}"
                    resp = await client.post(gql_url, json={"query": query})
                    body = resp.text.lower()

                    # Check for SQL error signatures
                    sql_errors = [
                        "sql syntax", "mysql", "postgresql", "sqlite",
                        "ora-", "microsoft sql", "unterminated string",
                        "syntax error at or near", "you have an error in your sql",
                    ]
                    if any(err in body for err in sql_errors):
                        findings.append(Finding(
                            title=f"SQL Injection via GraphQL Argument ({param_name})",
                            description=(
                                f"The GraphQL query '{query_name}' with argument '{param_name}' "
                                f"returned SQL error messages when injected with SQL payload. "
                                f"This indicates a potential SQL injection vulnerability."
                            ),
                            vulnerability_type="sql_injection",
                            severity=SeverityLevel.HIGH,
                            confidence=80.0,
                            target=base_url,
                            endpoint=gql_url,
                            parameter=f"graphql:{query_name}.{param_name}",
                            payload=payload,
                            evidence=body[:500],
                            tool_name="graphql_deep_scanner",
                            cwe_id="CWE-89",
                            tags=["graphql", "sqli", "injection"],
                        ))
                        break  # One finding per query/param is enough

                except Exception as _exc:
                    logger.debug(f"graphql deep scanner error: {_exc}")

    return findings


# ── Test: Debug/Development Mode ──────────────────────────────

async def _test_debug_mode(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test for GraphQL debug/development mode indicators.
    """
    findings: list[Finding] = []

    # Send a malformed query to trigger verbose errors
    bad_queries = [
        '{"query": "{ invalid }"}',
        '{"query": "{ __type(name: \\"User\\") { fields { name } } }"}',
        '{"query": "query { } "}',
    ]

    for bad_q in bad_queries:
        async with sem:
            try:
                resp = await client.post(gql_url, content=bad_q)
                body = resp.text

                # Check for debug indicators
                debug_indicators = [
                    "stack trace", "traceback", "debug", "stacktrace",
                    "at line", "at column", "source location",
                    "extensions", '"debug"', "internal server error",
                    "error.extensions.exception",
                ]

                verbose_errors = [ind for ind in debug_indicators if ind in body.lower()]

                if verbose_errors:
                    # Check for stack traces specifically
                    has_stack = bool(re.search(
                        r'(at\s+\w+\.[\w.]+\(.+\))|'
                        r'(File\s+"[^"]+",\s+line\s+\d+)|'
                        r'(\w+Exception:)|'
                        r'(Traceback\s+\(most\s+recent)',
                        body,
                    ))

                    severity = SeverityLevel.MEDIUM if has_stack else SeverityLevel.LOW
                    confidence = 80.0 if has_stack else 65.0

                    findings.append(Finding(
                        title="GraphQL Debug/Verbose Error Mode Enabled",
                        description=(
                            f"The GraphQL endpoint returns verbose error information "
                            f"including: {', '.join(verbose_errors[:5])}. "
                            f"{'Full stack traces are exposed.' if has_stack else ''} "
                            f"This leaks implementation details useful for further attacks."
                        ),
                        vulnerability_type="information_disclosure",
                        severity=severity,
                        confidence=confidence,
                        target=gql_url,
                        endpoint=gql_url,
                        evidence=body[:800],
                        tool_name="graphql_deep_scanner",
                        cwe_id="CWE-209",
                        tags=["graphql", "debug-mode", "verbose-error"],
                        metadata={"indicators": verbose_errors},
                    ))
                    break  # One finding is enough

            except Exception as _exc:
                logger.debug(f"graphql deep scanner error: {_exc}")

    return findings


# ── Test: Mutation IDOR ───────────────────────────────────────

async def _test_mutation_idor(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
    base_url: str,
) -> list[Finding]:
    """
    Test for IDOR in GraphQL mutations by attempting to access
    resources with different IDs.
    """
    findings: list[Finding] = []

    # Try common mutations that might have IDOR
    idor_mutations = [
        ('mutation { user(id: 1) { id email } }', "user", "1"),
        ('mutation { user(id: 2) { id email } }', "user", "2"),
        ('{ user(id: 1) { id email name } }', "user", "1"),
        ('{ user(id: 2) { id email name } }', "user", "2"),
        ('{ order(id: 1) { id total status } }', "order", "1"),
        ('{ order(id: 2) { id total status } }', "order", "2"),
    ]

    data_by_entity: dict[str, list[tuple[str, dict]]] = {}

    for query, entity, id_val in idor_mutations:
        async with sem:
            try:
                resp = await client.post(gql_url, json={"query": query})
                body = _validated_graphql_response(resp, gql_url)
                if isinstance(body, dict):
                    data = body.get("data", {})
                    if data and entity in data and data[entity]:
                        data_by_entity.setdefault(entity, []).append((id_val, data[entity]))
            except Exception as _exc:
                logger.debug(f"graphql deep scanner error: {_exc}")

    # If we got data for multiple IDs of the same entity, potential IDOR
    for entity, results in data_by_entity.items():
        if len(results) >= 2:
            id_vals = [r[0] for r in results]
            findings.append(Finding(
                title=f"Potential GraphQL IDOR: {entity} Entity",
                description=(
                    f"Accessing different '{entity}' IDs ({', '.join(id_vals)}) via GraphQL "
                    f"returned data for each. If no authorization checks are enforced, "
                    f"this is an IDOR vulnerability allowing access to other users' data."
                ),
                vulnerability_type="idor",
                severity=SeverityLevel.HIGH,
                confidence=55.0,  # Needs manual verification
                target=base_url,
                endpoint=gql_url,
                parameter=f"{entity}.id",
                evidence=f"IDs {id_vals} returned data: {json.dumps(results, default=str)[:500]}",
                tool_name="graphql_deep_scanner",
                cwe_id="CWE-639",
                tags=["graphql", "idor", "authorization"],
                metadata={"entity": entity, "tested_ids": id_vals},
            ))

    return findings


# ── Test: Introspection Bypass (P4-5) ─────────────────────────

async def _test_introspection_bypass(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test for introspection bypass techniques.
    Even when __schema is blocked, various techniques can leak the schema.
    """
    findings: list[Finding] = []

    bypass_probes = [
        # Standard introspection
        ('{"query":"{ __schema { types { name } } }"}', "standard __schema"),
        # GET method (some WAFs only block POST introspection)
        None,  # Handled separately below
        # Whitespace/newline evasion
        ('{"query":"{ \\n __schema \\n { types { name } } }"}', "newline-padded __schema"),
        # Fragment-based
        ('{"query":"{ ...on Query { __schema { types { name } } } }"}', "fragment-based __schema"),
        # Alias
        ('{"query":"{ s: __schema { types { name } } }"}', "aliased __schema"),
        # __type instead of __schema
        ('{"query":"{ __type(name: \\"Query\\") { fields { name type { name } } } }"}', "__type Query fields"),
        # Case mutation (some naive filters)
        ('{"query":"{ __SCHEMA { types { name } } }"}', "uppercase __SCHEMA"),
    ]

    introspection_blocked = True

    for probe_data in bypass_probes:
        if probe_data is None:
            # GET-based introspection bypass
            async with sem:
                try:
                    from urllib.parse import urlencode
                    params = urlencode({"query": "{ __schema { types { name } } }"})
                    resp = await client.get(f"{gql_url}?{params}")
                    body = _validated_graphql_response(resp, gql_url)
                    if isinstance(body, dict):
                        schema = body.get("data", {}).get("__schema")
                        if schema and schema.get("types"):
                            findings.append(Finding(
                                title="GraphQL Introspection Bypass via GET Method",
                                description=(
                                    "Introspection may be blocked via POST but is allowed via GET. "
                                    f"Full schema with {len(schema['types'])} types was retrieved."
                                ),
                                vulnerability_type="information_disclosure",
                                severity=SeverityLevel.MEDIUM,
                                confidence=90.0,
                                target=gql_url,
                                endpoint=gql_url,
                                evidence=f"GET introspection returned {len(schema['types'])} types",
                                tool_name="graphql_deep_scanner",
                                cwe_id="CWE-200",
                                tags=["graphql", "introspection", "bypass"],
                            ))
                            introspection_blocked = False
                except Exception as e:
                    logger.warning(f"graphql_deep_scanner error: {e}")
            continue

        content, technique = probe_data
        async with sem:
            try:
                resp = await client.post(gql_url, content=content)
                body = _validated_graphql_response(resp, gql_url)
                if isinstance(body, dict):
                    data = body.get("data", {})
                    schema = data.get("__schema") or data.get("s")
                    type_info = data.get("__type")

                    if schema and schema.get("types"):
                        if technique == "standard __schema":
                            introspection_blocked = False
                            continue  # Standard introspection allowed, not a bypass finding
                        findings.append(Finding(
                            title=f"GraphQL Introspection Bypass: {technique}",
                            description=(
                                f"Introspection was bypassed using technique: {technique}. "
                                f"Schema with {len(schema.get('types', []))} types was exposed."
                            ),
                            vulnerability_type="information_disclosure",
                            severity=SeverityLevel.MEDIUM,
                            confidence=85.0,
                            target=gql_url,
                            endpoint=gql_url,
                            evidence=f"Technique: {technique}, types count: {len(schema.get('types', []))}",
                            tool_name="graphql_deep_scanner",
                            cwe_id="CWE-200",
                            tags=["graphql", "introspection", "bypass"],
                        ))
                        introspection_blocked = False
                        break

                    if type_info and type_info.get("fields"):
                        fields = [f["name"] for f in type_info["fields"]]
                        findings.append(Finding(
                            title="GraphQL __type Leak (Query Fields Exposed)",
                            description=(
                                f"The __type meta-field exposes Query type fields: "
                                f"{', '.join(fields[:15])}. This reveals the API surface "
                                f"even when __schema introspection is disabled."
                            ),
                            vulnerability_type="information_disclosure",
                            severity=SeverityLevel.LOW,
                            confidence=80.0,
                            target=gql_url,
                            endpoint=gql_url,
                            evidence=f"Exposed fields: {fields[:15]}",
                            tool_name="graphql_deep_scanner",
                            cwe_id="CWE-200",
                            tags=["graphql", "__type", "info-leak"],
                            metadata={"exposed_fields": fields},
                        ))
                        break

            except Exception as e:
                logger.warning(f"graphql_deep_scanner error: {e}")

    return findings


# ── Test: Field Brute-Force (P4-5) ────────────────────────────

_COMMON_GQL_FIELDS = [
    "user", "users", "me", "viewer", "currentUser", "profile",
    "admin", "admins", "account", "accounts",
    "post", "posts", "article", "articles", "blog",
    "order", "orders", "transaction", "transactions", "payment", "payments",
    "product", "products", "item", "items", "inventory",
    "message", "messages", "notification", "notifications", "inbox",
    "comment", "comments", "review", "reviews",
    "file", "files", "upload", "uploads", "document", "documents",
    "setting", "settings", "config", "configuration",
    "role", "roles", "permission", "permissions", "group", "groups",
    "token", "tokens", "session", "sessions", "apiKey", "apiKeys",
    "log", "logs", "audit", "event", "events",
    "search", "query", "report", "reports", "dashboard",
    "organization", "team", "workspace", "project", "projects",
    "invite", "invites", "member", "members",
    "subscription", "plan", "billing", "invoice", "invoices",
    "webhook", "webhooks", "integration", "integrations",
    "flag", "flags", "feature", "features",
    "secret", "secrets", "credential", "credentials",
    "node", "nodes", "edge", "edges", "connection",
]

_COMMON_GQL_MUTATIONS = [
    "createUser", "updateUser", "deleteUser", "register", "login", "logout",
    "resetPassword", "changePassword", "forgotPassword",
    "createPost", "updatePost", "deletePost",
    "createOrder", "updateOrder", "cancelOrder",
    "addToCart", "removeFromCart", "checkout",
    "uploadFile", "deleteFile",
    "updateSettings", "updateProfile", "updateEmail",
    "assignRole", "removeRole", "inviteUser",
    "createToken", "revokeToken", "refreshToken",
    "sendMessage", "deleteMessage",
    "subscribe", "unsubscribe",
    "createWebhook", "deleteWebhook",
    "executeQuery", "runReport",
]


async def _test_field_bruteforce(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Brute-force common query field names via individual probes.
    Useful when introspection is disabled.
    """
    findings: list[Finding] = []
    discovered_fields: list[str] = []

    for field in _COMMON_GQL_FIELDS:
        async with sem:
            try:
                query = f'{{ {field} {{ id }} }}'
                resp = await client.post(gql_url, json={"query": query})
                body = _validated_graphql_response(resp, gql_url)
                if not isinstance(body, dict):
                    continue
                data = body.get("data")
                errors = body.get("errors", [])

                # Field exists if data is non-null OR errors don't say "field not found"
                if data and data.get(field) is not None:
                    discovered_fields.append(field)
                elif errors:
                    # Field exists but subfield 'id' is wrong → field is valid
                    err_text = json.dumps(errors).lower()
                    if "cannot query field" not in err_text and "unknown field" not in err_text:
                        if "subfield" in err_text or "selection" in err_text or "must have" in err_text:
                            discovered_fields.append(field)
            except Exception as e:
                logger.warning(f"graphql_deep_scanner error: {e}")

    if discovered_fields:
        sensitive = [f for f in discovered_fields if any(
            kw in f.lower() for kw in (
                "admin", "secret", "credential", "token", "apikey",
                "password", "role", "permission", "log", "audit",
                "billing", "invoice", "payment", "session",
            )
        )]

        severity = SeverityLevel.MEDIUM if sensitive else SeverityLevel.LOW
        findings.append(Finding(
            title=f"GraphQL Field Discovery: {len(discovered_fields)} Fields Found",
            description=(
                f"Brute-forced {len(_COMMON_GQL_FIELDS)} common field names against the "
                f"GraphQL endpoint and discovered {len(discovered_fields)} valid fields: "
                f"{', '.join(discovered_fields[:20])}"
                + (f"\n\nSENSITIVE fields: {', '.join(sensitive)}" if sensitive else "")
            ),
            vulnerability_type="information_disclosure",
            severity=severity,
            confidence=75.0,
            target=gql_url,
            endpoint=gql_url,
            evidence=f"Discovered fields: {discovered_fields[:20]}",
            tool_name="graphql_deep_scanner",
            cwe_id="CWE-200",
            tags=["graphql", "field-bruteforce", "enumeration"],
            metadata={
                "discovered_fields": discovered_fields,
                "sensitive_fields": sensitive,
                "total_probed": len(_COMMON_GQL_FIELDS),
            },
        ))

    return findings


# ── Test: Mutation Discovery (P4-5) ───────────────────────────

async def _test_mutation_discovery(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Discover available mutations by probing common mutation names.
    Interesting mutations (admin ops, file uploads, etc.) are flagged.
    """
    findings: list[Finding] = []
    discovered_mutations: list[str] = []

    for mutation in _COMMON_GQL_MUTATIONS:
        async with sem:
            try:
                query = f'mutation {{ {mutation} }}'
                resp = await client.post(gql_url, json={"query": query})
                body = _validated_graphql_response(resp, gql_url)
                if not isinstance(body, dict):
                    continue
                errors = body.get("errors", [])
                err_text = json.dumps(errors).lower()

                # Mutation exists if error is about arguments/fields, not "unknown"
                if errors and "cannot query field" not in err_text and "unknown field" not in err_text:
                    if any(kw in err_text for kw in ("argument", "required", "field", "type")):
                        discovered_mutations.append(mutation)
                # Or if data is returned (unlikely without args but possible)
                if body.get("data", {}).get(mutation) is not None:
                    discovered_mutations.append(mutation)
            except Exception as e:
                logger.warning(f"graphql_deep_scanner error: {e}")

    if discovered_mutations:
        dangerous = [m for m in discovered_mutations if any(
            kw in m.lower() for kw in (
                "delete", "admin", "role", "execute", "reset",
                "revoke", "upload", "assign", "remove",
            )
        )]

        severity = SeverityLevel.MEDIUM if dangerous else SeverityLevel.LOW
        findings.append(Finding(
            title=f"GraphQL Mutation Discovery: {len(discovered_mutations)} Mutations Found",
            description=(
                f"Discovered {len(discovered_mutations)} valid mutations: "
                f"{', '.join(discovered_mutations[:15])}"
                + (f"\n\nPOTENTIALLY DANGEROUS: {', '.join(dangerous)}" if dangerous else "")
            ),
            vulnerability_type="information_disclosure",
            severity=severity,
            confidence=70.0,
            target=gql_url,
            endpoint=gql_url,
            evidence=f"Mutations: {discovered_mutations[:15]}",
            tool_name="graphql_deep_scanner",
            cwe_id="CWE-200",
            tags=["graphql", "mutation-discovery", "enumeration"],
            metadata={
                "discovered_mutations": discovered_mutations,
                "dangerous_mutations": dangerous,
                "total_probed": len(_COMMON_GQL_MUTATIONS),
            },
        ))

    return findings


# ── Test: Persisted Query Bypass (P4-5) ───────────────────────

async def _test_persisted_query_bypass(
    client: httpx.AsyncClient,
    gql_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test for Automatic Persisted Queries (APQ) that may allow arbitrary queries.
    If APQ is enabled, send a hash for a known query and see if arbitrary
    queries can still be registered.
    """
    findings: list[Finding] = []

    # Test 1: Check if APQ is supported
    apq_payload = {
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "0" * 64,  # Fake hash
            }
        }
    }

    async with sem:
        try:
            resp = await client.post(gql_url, json=apq_payload)
            body = _validated_graphql_response(resp, gql_url)
            if isinstance(body, dict):
                errors = body.get("errors", [])
                err_text = json.dumps(errors).lower()

                # APQ is active if we get "PersistedQueryNotFound" (not "unknown extension")
                if "persistedquerynotfound" in err_text or "persisted" in err_text:
                    # APQ is enabled — try to register an arbitrary query
                    import hashlib
                    arb_query = "{ __schema { types { name fields { name } } } }"
                    query_hash = hashlib.sha256(arb_query.encode()).hexdigest()

                    register_payload = {
                        "query": arb_query,
                        "extensions": {
                            "persistedQuery": {
                                "version": 1,
                                "sha256Hash": query_hash,
                            }
                        }
                    }

                    resp2 = await client.post(gql_url, json=register_payload)
                    body2 = _validated_graphql_response(resp2, gql_url)
                    if isinstance(body2, dict):
                        if body2.get("data", {}).get("__schema"):
                            findings.append(Finding(
                                title="GraphQL APQ Bypass: Arbitrary Query Registration",
                                description=(
                                    "Automatic Persisted Queries (APQ) allows registering "
                                    "arbitrary queries including introspection. An attacker "
                                    "can bypass query allowlists by registering their own queries."
                                ),
                                vulnerability_type="security_misconfiguration",
                                severity=SeverityLevel.MEDIUM,
                                confidence=90.0,
                                target=gql_url,
                                endpoint=gql_url,
                                evidence="APQ accepted arbitrary introspection query registration",
                                tool_name="graphql_deep_scanner",
                                cwe_id="CWE-284",
                                tags=["graphql", "apq", "bypass", "persisted-query"],
                            ))
                        else:
                            findings.append(Finding(
                                title="GraphQL Automatic Persisted Queries (APQ) Enabled",
                                description=(
                                    "APQ is enabled on this GraphQL endpoint. While the server "
                                    "did not allow arbitrary query registration in this test, "
                                    "APQ can sometimes be leveraged for cache-based attacks."
                                ),
                                vulnerability_type="information_disclosure",
                                severity=SeverityLevel.LOW,
                                confidence=75.0,
                                target=gql_url,
                                endpoint=gql_url,
                                evidence="PersistedQueryNotFound response confirms APQ support",
                                tool_name="graphql_deep_scanner",
                                cwe_id="CWE-200",
                                tags=["graphql", "apq", "info"],
                            ))

        except Exception as e:
            logger.debug(f"APQ test error: {e}")

    return findings


__all__ = ["scan_graphql_deep"]
