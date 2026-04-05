"""
WhiteHatHacker AI — Web Cache Poisoning Checker

Tests for web cache poisoning vulnerabilities by injecting unkeyed headers
and parameters, then checking if the poisoned response is cached and served
to subsequent requests.

Techniques tested:
- Unkeyed header injection (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL)
- Unkeyed parameter injection (utm_*, fbclid, etc.)
- Fat GET / body parameter override
- Host header poisoning via cache
- HTTP method-based cache key differences
- Cache deception (path confusion)

References:
- https://portswigger.net/research/practical-web-cache-poisoning
- https://portswigger.net/research/web-cache-entanglement
- CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data
"""

from __future__ import annotations

import asyncio
import random
import string
from urllib.parse import urlparse

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel

# ── Canary generation ─────────────────────────────────────────

_CANARY_PREFIX = "whai"


def _canary(length: int = 8) -> str:
    """Generate a unique canary string for cache buster and detection."""
    return _CANARY_PREFIX + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _cache_buster() -> str:
    """Generate a unique cache-busting query parameter value."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


# ── Unkeyed headers to test ───────────────────────────────────

_UNKEYED_HEADERS: list[tuple[str, str, str]] = [
    # (header_name, description, injection_type)
    ("X-Forwarded-Host", "X-Forwarded-Host header reflection", "host"),
    ("X-Host", "X-Host header reflection", "host"),
    ("X-Original-URL", "X-Original-URL path override", "path"),
    ("X-Rewrite-URL", "X-Rewrite-URL path override", "path"),
    ("X-Forwarded-Scheme", "X-Forwarded-Scheme downgrade", "scheme"),
    ("X-Forwarded-Proto", "X-Forwarded-Proto manipulation", "scheme"),
    ("X-Forwarded-Port", "X-Forwarded-Port injection", "port"),
    ("X-Original-Host", "X-Original-Host reflection", "host"),
    ("X-Forwarded-Server", "X-Forwarded-Server reflection", "host"),
    ("X-HTTP-Destinationheader", "X-HTTP-Destination override", "host"),
    ("X-Forwarded-For", "X-Forwarded-For in cached response", "ip"),
    ("True-Client-IP", "True-Client-IP in cached response", "ip"),
    ("CF-Connecting-IP", "CF-Connecting-IP bypass", "ip"),
]

# ── Unkeyed parameters ────────────────────────────────────────

_UNKEYED_PARAMS: list[str] = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "msclkid", "dclid", "mc_cid", "mc_eid",
    "_ga", "_gl", "ref", "source", "origin",
    "callback", "jsonp", "cb",
]

# ── Cache deception paths ─────────────────────────────────────

_DECEPTION_SUFFIXES: list[str] = [
    "/nonexistent.css",
    "/nonexistent.js",
    "/nonexistent.png",
    "/..%2fnonexistent.css",
    "/%2e%2e/nonexistent.js",
    "/whai.css",
    ";nonexistent.css",
    "%0d%0aX-Injected:true",
]


# ── Main checker ──────────────────────────────────────────────

async def check_cache_poisoning(
    target_urls: list[str],
    max_concurrent: int = 3,
    timeout: float = 10.0,
    verify_cached: bool = True,
    oob_domain: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """
    Test URLs for web cache poisoning vulnerabilities.

    Strategy:
    1. Send initial 'clean' request to get baseline response.
    2. Send poisoned request with unkeyed header + unique canary.
    3. Send 2nd clean request to see if the canary was cached.
    4. Same approach for unkeyed parameters and cache deception.

    Args:
        target_urls: URLs to test.
        max_concurrent: Concurrency limit.
        timeout: Per-request timeout in seconds.
        verify_cached: Whether to send a follow-up request to verify caching.
        oob_domain: Optional Interactsh OOB domain for blind verification.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)

    _headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WhiteHatHackerAI/2.1"}
    if extra_headers:
        _headers.update(extra_headers)
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,  # Don't follow — we want to see the raw response
        verify=False,
        headers=_headers,
    ) as client:
        tasks = []
        for url in target_urls:
            tasks.append(_test_url(client, url, sem, verify_cached, oob_domain))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug(f"Cache poisoning check error: {result}")

    logger.info(f"Cache poisoning check completed: {len(findings)} findings across {len(target_urls)} URLs")
    return findings


async def _test_url(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
    verify_cached: bool,
    oob_domain: str | None = None,
) -> list[Finding]:
    """Test a single URL for all cache poisoning vectors."""
    findings: list[Finding] = []

    # Phase 1: Unkeyed header poisoning
    findings.extend(await _test_unkeyed_headers(client, url, sem, verify_cached))

    # Phase 1b: OOB-based blind header poisoning (if OOB domain available)
    if oob_domain:
        findings.extend(await _test_unkeyed_headers_oob(client, url, sem, oob_domain))

    # Phase 2: Unkeyed parameter poisoning
    findings.extend(await _test_unkeyed_params(client, url, sem, verify_cached))

    # Phase 3: Cache deception
    findings.extend(await _test_cache_deception(client, url, sem))

    # Phase 4: Fat GET (body params override query params in cache)
    findings.extend(await _test_fat_get(client, url, sem))

    return findings


# ── Phase 1: Unkeyed Header Poisoning ─────────────────────────

async def _test_unkeyed_headers(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
    verify_cached: bool,
) -> list[Finding]:
    findings: list[Finding] = []

    for header_name, description, injection_type in _UNKEYED_HEADERS:
        async with sem:
            try:
                canary = _canary()
                cb = _cache_buster()
                test_url = _add_param(url, "cb", cb)

                # Determine payload based on injection type
                if injection_type == "host":
                    header_value = f"{canary}.evil.com"
                elif injection_type == "path":
                    header_value = f"/{canary}"
                elif injection_type == "scheme":
                    header_value = "http"  # Downgrade to HTTP
                elif injection_type == "port":
                    header_value = "1337"
                elif injection_type == "ip":
                    header_value = "127.0.0.1"
                else:
                    header_value = canary

                # Send poisoned request
                poisoned_resp = await client.get(
                    test_url,
                    headers={header_name: header_value},
                )

                # Check if canary appears in the response
                body = poisoned_resp.text
                resp_headers_str = str(dict(poisoned_resp.headers))

                reflected = canary in body or canary in resp_headers_str

                if not reflected:
                    continue

                # Reject WAF/CDN challenge pages that may echo request values
                _body_lower = body.lower()[:2000]
                _waf_sigs = (
                    "attention required", "cloudflare", "ray id:",
                    "access denied", "request blocked", "security check",
                    "captcha", "challenge-platform", "sucuri", "incapsula",
                    "akamai", "ddos protection",
                )
                if any(s in _body_lower for s in _waf_sigs):
                    continue

                # Verify: send clean request to see if poison is cached
                is_cached = False
                if verify_cached:
                    await asyncio.sleep(0.3)  # Small delay
                    clean_resp = await client.get(test_url)
                    is_cached = canary in clean_resp.text or canary in str(dict(clean_resp.headers))

                severity = SeverityLevel.HIGH if is_cached else SeverityLevel.MEDIUM
                confidence = 90.0 if is_cached else 60.0

                evidence_parts = [
                    f"Header: {header_name}: {header_value}",
                    f"Canary '{canary}' reflected in {'cached ' if is_cached else ''}response",
                    f"Status: {poisoned_resp.status_code}",
                ]

                cache_headers = _extract_cache_headers(poisoned_resp)
                if cache_headers:
                    evidence_parts.append(f"Cache headers: {cache_headers}")

                findings.append(Finding(
                    title=f"Web Cache Poisoning via {header_name}",
                    description=(
                        f"{description}. The header '{header_name}' is reflected in the response "
                        f"body/headers and {'IS CACHED (verified)' if is_cached else 'may be cached'}. "
                        f"An attacker can poison the cache to serve malicious content to other users."
                    ),
                    vulnerability_type="web_cache_poisoning",
                    severity=severity,
                    confidence=confidence,
                    target=url,
                    endpoint=test_url,
                    parameter=header_name,
                    payload=header_value,
                    evidence="\n".join(evidence_parts),
                    tool_name="cache_poisoning_checker",
                    cwe_id="CWE-349",
                    tags=["cache-poisoning", "unkeyed-header", header_name.lower()],
                    metadata={
                        "header": header_name,
                        "injection_type": injection_type,
                        "reflected": reflected,
                        "cached": is_cached,
                        "cache_headers": cache_headers,
                    },
                ))

            except httpx.HTTPError as e:
                logger.debug(f"Cache poison header test error [{header_name}] {url}: {e}")
            except Exception as e:
                logger.debug(f"Cache poison header test unexpected error: {e}")

    return findings


# ── Phase 1b: OOB-based Blind Header Poisoning ─────────────────

# Headers most likely to trigger blind interactions (resource loading)
_OOB_HEADERS = [
    ("X-Forwarded-Host", "host"),
    ("X-Original-URL", "path"),
    ("X-Forwarded-Scheme", "scheme"),
]


async def _test_unkeyed_headers_oob(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
    oob_domain: str,
) -> list[Finding]:
    """Test unkeyed headers with OOB domain for blind cache poisoning."""
    findings: list[Finding] = []

    for header_name, injection_type in _OOB_HEADERS:
        async with sem:
            try:
                cb = _cache_buster()
                test_url = _add_param(url, "cb", cb)
                tag = f"cp-{header_name.lower().replace('-', '')[:12]}"

                if injection_type == "host":
                    header_value = f"{tag}.{oob_domain}"
                elif injection_type == "path":
                    header_value = f"http://{tag}.{oob_domain}/x"
                elif injection_type == "scheme":
                    # Force scheme to HTTP with OOB host
                    header_value = f"http://{tag}.{oob_domain}"
                else:
                    header_value = f"{tag}.{oob_domain}"

                await client.get(
                    test_url,
                    headers={header_name: header_value},
                )
                # Don't create findings here — the OOB callback will be
                # correlated later by the CorrelationEngine. We just need
                # to send the poisoned request to trigger the callback.
                logger.debug(
                    f"Cache poison OOB probe sent: {header_name}={header_value} → {url}"
                )
            except httpx.HTTPError as exc:
                logger.debug(f"Cache poisoning OOB probe HTTP error: {exc}")
            except Exception as _exc:
                logger.debug(f"cache poisoning checker error: {_exc}")

    return findings


# ── Phase 2: Unkeyed Parameter Poisoning ──────────────────────

async def _test_unkeyed_params(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
    verify_cached: bool,
) -> list[Finding]:
    findings: list[Finding] = []

    for param in _UNKEYED_PARAMS:
        async with sem:
            try:
                canary = _canary()
                cb = _cache_buster()
                test_url = _add_param(url, "cb", cb)
                poisoned_url = _add_param(test_url, param, canary)

                resp = await client.get(poisoned_url)
                body = resp.text

                if canary not in body:
                    continue

                # Verify caching: request without the unkeyed param
                is_cached = False
                if verify_cached:
                    await asyncio.sleep(0.3)
                    clean_resp = await client.get(test_url)
                    is_cached = canary in clean_resp.text

                severity = SeverityLevel.MEDIUM if is_cached else SeverityLevel.LOW
                confidence = 80.0 if is_cached else 50.0

                findings.append(Finding(
                    title=f"Unkeyed Parameter Reflection: {param}",
                    description=(
                        f"The parameter '{param}' is reflected in the response but may not be part "
                        f"of the cache key. {'Verified: poisoned response IS cached.' if is_cached else 'Caching not confirmed.'}"
                    ),
                    vulnerability_type="web_cache_poisoning",
                    severity=severity,
                    confidence=confidence,
                    target=url,
                    endpoint=poisoned_url,
                    parameter=param,
                    payload=canary,
                    evidence=f"Parameter '{param}={canary}' reflected in response body (status {resp.status_code})",
                    tool_name="cache_poisoning_checker",
                    cwe_id="CWE-349",
                    tags=["cache-poisoning", "unkeyed-param", param],
                    metadata={"param": param, "cached": is_cached},
                ))

            except httpx.HTTPError as e:
                logger.debug(f"Cache poison param test error [{param}] {url}: {e}")
            except Exception as _exc:
                logger.debug(f"cache poisoning checker error: {_exc}")

    return findings


# ── Phase 3: Cache Deception ──────────────────────────────────

async def _test_cache_deception(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test for web cache deception.

    If url/profile is a dynamic authenticated page, appending .css or .js
    might cause a caching proxy to cache the personal content.
    """
    findings: list[Finding] = []
    parsed = urlparse(url)
    base_path = parsed.path.rstrip("/") or ""

    for suffix in _DECEPTION_SUFFIXES:
        async with sem:
            try:
                deception_path = (base_path if base_path else "") + suffix
                # Reconstruct URL properly instead of string replace to avoid
                # replacing '/' inside the scheme (https://)
                deception_url = parsed._replace(path=deception_path).geturl()

                resp = await client.get(deception_url)

                # If the dynamic page content is served despite static extension
                # AND a cache header indicates it was cached, that's deception.
                cache_headers = _extract_cache_headers(resp)
                is_cached = any(
                    v in cache_headers.lower()
                    for v in ("hit", "cached", "age:")
                ) if cache_headers else False

                content_type = resp.headers.get("content-type", "")
                serves_html = "text/html" in content_type

                if is_cached and serves_html and resp.status_code == 200:
                    findings.append(Finding(
                        title=f"Web Cache Deception: {suffix}",
                        description=(
                            f"Appending '{suffix}' to the URL path returns the same HTML content "
                            f"AND the response is cached. An attacker can trick a victim into visiting "
                            f"this URL to cache their private page content."
                        ),
                        vulnerability_type="web_cache_deception",
                        severity=SeverityLevel.HIGH,
                        confidence=75.0,
                        target=url,
                        endpoint=deception_url,
                        payload=suffix,
                        evidence=f"Status: {resp.status_code}, Content-Type: {content_type}, Cache: {cache_headers}",
                        tool_name="cache_poisoning_checker",
                        cwe_id="CWE-524",
                        tags=["cache-deception", "web-cache"],
                        metadata={"suffix": suffix, "cache_headers": cache_headers},
                    ))

            except httpx.HTTPError as exc:
                logger.debug(f"Cache poison OOB probe HTTP error: {exc}")
            except Exception as _exc:
                logger.debug(f"cache poisoning checker error: {_exc}")

    return findings


# ── Phase 4: Fat GET ──────────────────────────────────────────

async def _test_fat_get(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """
    Test for Fat GET cache poisoning.

    Some frameworks parse a request body on GET requests. If the cache
    key only uses query params, an attacker can override parameters via body.
    """
    findings: list[Finding] = []

    async with sem:
        try:
            canary = _canary()
            cb = _cache_buster()
            test_url = _add_param(url, "cb", cb)

            # Send GET with a body (Fat GET)
            resp = await client.request(
                "GET",
                test_url,
                content=f"cb={canary}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if canary in resp.text:
                # Check if it's cached
                await asyncio.sleep(0.3)
                clean_resp = await client.get(test_url)
                is_cached = canary in clean_resp.text

                if is_cached:
                    findings.append(Finding(
                        title="Fat GET Cache Poisoning",
                        description=(
                            "The server processes GET request body parameters AND the response "
                            "is cached based on query params only. An attacker can poison the "
                            "cache by sending a GET request with a malicious body."
                        ),
                        vulnerability_type="web_cache_poisoning",
                        severity=SeverityLevel.HIGH,
                        confidence=85.0,
                        target=url,
                        endpoint=test_url,
                        payload=f"GET body: cb={canary}",
                        evidence=f"Fat GET canary '{canary}' reflected and cached",
                        tool_name="cache_poisoning_checker",
                        cwe_id="CWE-349",
                        tags=["cache-poisoning", "fat-get"],
                        metadata={"canary": canary, "verified_cached": True},
                    ))

        except httpx.HTTPError as exc:
            logger.debug(f"Fat GET probe HTTP error: {exc}")
        except Exception as _exc:
            logger.debug(f"cache poisoning checker error: {_exc}")

    return findings


# ── Helper functions ──────────────────────────────────────────

def _add_param(url: str, param: str, value: str) -> str:
    """Add a query parameter to a URL."""
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{param}={value}"


def _extract_cache_headers(resp: httpx.Response) -> str:
    """Extract cache-related headers from a response."""
    cache_header_names = [
        "cache-control", "x-cache", "x-cache-hits", "cf-cache-status",
        "age", "x-varnish", "x-drupal-cache", "x-proxy-cache",
        "x-cdn-cache", "akamai-cache-status", "x-served-by",
        "x-cache-status", "x-fastly-request-id", "via",
    ]
    parts = []
    for name in cache_header_names:
        value = resp.headers.get(name)
        if value:
            parts.append(f"{name}: {value}")
    return " | ".join(parts)


__all__ = ["check_cache_poisoning"]
