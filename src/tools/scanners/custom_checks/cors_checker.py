"""
WhiteHatHacker AI — CORS Misconfiguration Checker

Tests for common CORS misconfigurations:
- Reflected Origin (arbitrary origin accepted)
- Null Origin accepted
- Wildcard with credentials
- Subdomain prefix/suffix bypass
- Pre-domain bypass (e.g. attacker-target.com)
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel
from src.utils.response_validator import ResponseValidator


def _get_test_origins(target_url: str) -> list[tuple[str, str, SeverityLevel]]:
    """Generate CORS test origins for a target URL.

    Returns list of (origin, description, severity) tuples.
    """
    parsed = urlparse(target_url)
    domain = parsed.hostname or ""
    scheme = parsed.scheme or "https"

    # Extract base domain (e.g. gravatar.com from api.gravatar.com)
    parts = domain.split(".")
    if len(parts) >= 2:
        base_domain = ".".join(parts[-2:])
    else:
        base_domain = domain

    return [
        # Reflected arbitrary origin (critical)
        ("https://evil.com", "Arbitrary origin reflected", SeverityLevel.HIGH),
        # Null origin
        ("null", "Null origin accepted", SeverityLevel.HIGH),
        # Attacker subdomain of target
        (f"{scheme}://evil.{base_domain}", "Subdomain injection accepted", SeverityLevel.HIGH),
        # Prefix match bypass (e.g. evilgravatar.com)
        (f"{scheme}://evil{base_domain}", "Pre-domain bypass accepted", SeverityLevel.MEDIUM),
        # Suffix match bypass (e.g. gravatar.com.evil.com)
        (f"{scheme}://{base_domain}.evil.com", "Post-domain bypass accepted", SeverityLevel.MEDIUM),
        # HTTP downgrade
        (f"http://{domain}", "HTTP downgrade origin accepted", SeverityLevel.LOW),
    ]


async def check_cors_misconfigurations(
    target_urls: list[str],
    max_concurrent: int = 3,
    timeout: float = 10.0,
) -> list[Finding]:
    """
    Test URLs for CORS misconfigurations.

    Args:
        target_urls: List of URLs to test
        max_concurrent: Maximum concurrent requests
        timeout: Per-request timeout

    Returns:
        List of Finding objects for discovered CORS issues
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)

    async def _test_cors(client: httpx.AsyncClient, url: str) -> list[Finding]:
        local_findings: list[Finding] = []
        test_origins = _get_test_origins(url)

        for origin, description, severity in test_origins:
            async with sem:
                try:
                    headers = {"Origin": origin}
                    resp = await client.get(url, headers=headers, follow_redirects=True)

                    # ── ResponseValidator: reject WAF blocks and error pages ──
                    # CORS headers on 403/WAF pages are meaningless
                    _rv = ResponseValidator()
                    vr = _rv.validate(
                        resp.status_code,
                        dict(resp.headers),
                        resp.text[:2000] if resp.text else "",
                        url=url,
                    )
                    if vr.is_waf_block or vr.is_error_page:
                        continue

                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "").lower()

                    if not acao:
                        continue

                    is_vuln = False
                    evidence_parts = []

                    # Check if our malicious origin is reflected
                    if origin != "null" and acao == origin:
                        is_vuln = True
                        evidence_parts.append(f"Origin '{origin}' reflected in ACAO")
                    elif origin == "null" and acao == "null":
                        is_vuln = True
                        evidence_parts.append("Null origin accepted")
                    elif acao == "*":
                        # Per Fetch spec (https://fetch.spec.whatwg.org/):
                        # When ACAO is "*", browsers IGNORE ACAC:true.
                        # Credentialed cross-origin requests are NOT possible
                        # with wildcard ACAO. This is NOT exploitable and NOT
                        # reportable for bug bounty programs.
                        pass  # Skip — ACAO:* is never a reportable finding

                    if is_vuln:
                        if acac == "true":
                            evidence_parts.append("ACAC: true (credentials allowed)")
                            # Credentials + reflected origin = exploitable (HIGH+)
                            if severity < SeverityLevel.HIGH:
                                severity = SeverityLevel.HIGH
                        else:
                            # ── P2-2: No credentials → NOT exploitable for data theft ──
                            # Origin reflected without ACAC:true means cross-origin
                            # requests can be made but browser won't attach cookies.
                            # Downgrade: HIGH→LOW, MEDIUM→LOW for non-credentialed.
                            evidence_parts.append(
                                "ACAC: false/absent (credentials NOT sent by browser — "
                                "limited impact without authenticated context)"
                            )
                            severity = SeverityLevel.LOW

                        evidence = " | ".join(evidence_parts)

                        local_findings.append(Finding(
                            title=f"CORS Misconfiguration: {description}",
                            description=(
                                f"URL {url} has a CORS misconfiguration. "
                                f"Tested Origin: {origin} → ACAO: {acao}, ACAC: {acac}. "
                                + (
                                    "This may allow cross-origin data theft."
                                    if acac == "true"
                                    else "Without credentials, impact is limited to reading public responses cross-origin."
                                )
                            ),
                            vulnerability_type="cors_misconfiguration",
                            severity=severity,
                            confidence=80.0 if acac == "true" else 40.0,
                            target=url,
                            endpoint=url,
                            evidence=evidence,
                            tool_name="cors_checker",
                        ))
                        # Stop testing this URL after first vuln found
                        break

                except (httpx.TimeoutException, httpx.ConnectError) as exc:
                    logger.debug(f"CORS test {url} origin={origin} connection error: {exc}")
                except Exception as e:
                    logger.debug(f"CORS test {url} origin={origin} error: {e}")

        return local_findings

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0",
        "Accept": "*/*",
    }

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        headers=headers,
        verify=False,
    ) as client:
        tasks = [_test_cors(client, url) for url in target_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

    if findings:
        logger.info(f"CORS checker: {len(findings)} findings from {len(target_urls)} URLs")

    return findings
