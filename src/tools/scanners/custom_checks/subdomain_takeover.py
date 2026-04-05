"""
WhiteHatHacker AI — Subdomain Takeover Checker

Checks for potential subdomain takeover conditions by analyzing
DNS records (CNAME pointing to unclaimed services) and HTTP responses
(service default/error pages indicating available claim).
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from loguru import logger
from src.tools.base import Finding
from src.utils.constants import SeverityLevel


# ── Known vulnerable CNAME targets ──────────────────────────────────────────

_TAKEOVER_FINGERPRINTS: dict[str, dict[str, Any]] = {
    # Service: {cname_pattern, response_fingerprints, severity}
    "github_pages": {
        "cname": r"\.github\.io\.?$",
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs"],
        "severity": SeverityLevel.HIGH,
    },
    "heroku": {
        "cname": r"\.herokuapp\.com\.?$|\.herokussl\.com\.?$",
        "fingerprints": ["No such app", "no-such-app", "herokucdn.com/error-pages"],
        "severity": SeverityLevel.HIGH,
    },
    "aws_s3": {
        "cname": r"\.s3\.amazonaws\.com\.?$|\.s3-website",
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": SeverityLevel.HIGH,
    },
    "aws_elastic_beanstalk": {
        "cname": r"\.elasticbeanstalk\.com\.?$",
        "fingerprints": [],
        "severity": SeverityLevel.MEDIUM,
    },
    "azure": {
        "cname": r"\.azurewebsites\.net\.?$|\.cloudapp\.azure\.com\.?$|\.trafficmanager\.net\.?$",
        "fingerprints": ["404 Web Site not found", "Azure Web App - Your web app is running"],
        "severity": SeverityLevel.HIGH,
    },
    "shopify": {
        "cname": r"\.myshopify\.com\.?$",
        "fingerprints": ["Sorry, this shop is currently unavailable"],
        "severity": SeverityLevel.MEDIUM,
    },
    "fastly": {
        "cname": r"\.fastly\.net\.?$",
        "fingerprints": ["Fastly error: unknown domain"],
        "severity": SeverityLevel.HIGH,
    },
    "pantheon": {
        "cname": r"\.pantheonsite\.io\.?$",
        "fingerprints": ["404 error unknown site", "The gods are wise"],
        "severity": SeverityLevel.MEDIUM,
    },
    "tumblr": {
        "cname": r"\.tumblr\.com\.?$",
        "fingerprints": ["There's nothing here", "Whatever you were looking for"],
        "severity": SeverityLevel.MEDIUM,
    },
    "wordpress_com": {
        "cname": r"\.wordpress\.com\.?$",
        "fingerprints": ["Do you want to register"],
        "severity": SeverityLevel.MEDIUM,
    },
    "ghost": {
        "cname": r"\.ghost\.io\.?$",
        "fingerprints": ["The thing you were looking for is no longer here"],
        "severity": SeverityLevel.MEDIUM,
    },
    "surge": {
        "cname": r"\.surge\.sh\.?$",
        "fingerprints": ["project not found"],
        "severity": SeverityLevel.MEDIUM,
    },
    "bitbucket": {
        "cname": r"\.bitbucket\.io\.?$",
        "fingerprints": ["Repository not found"],
        "severity": SeverityLevel.MEDIUM,
    },
    "zendesk": {
        "cname": r"\.zendesk\.com\.?$",
        "fingerprints": ["Help Center Closed", "Oops, this help center"],
        "severity": SeverityLevel.MEDIUM,
    },
    "readme_io": {
        "cname": r"\.readme\.io\.?$",
        "fingerprints": ["Project doesnt exist"],
        "severity": SeverityLevel.MEDIUM,
    },
    "cargo_collective": {
        "cname": r"\.cargocollective\.com\.?$",
        "fingerprints": ["404 Not Found"],
        "severity": SeverityLevel.LOW,
    },
    "unbounce": {
        "cname": r"\.unbouncepages\.com\.?$",
        "fingerprints": ["The requested URL was not found"],
        "severity": SeverityLevel.MEDIUM,
    },
}


async def check_subdomain_takeover(
    subdomains: list[str],
    max_concurrent: int = 5,
    timeout: int = 10,
) -> list[Finding]:
    """
    Check a list of subdomains for potential takeover conditions.

    Strategy:
    1. Resolve CNAME records
    2. Check if CNAME points to a known vulnerable service
    3. Optionally check HTTP response for service-specific fingerprints
    """
    findings: list[Finding] = []

    # Limit concurrency
    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_one(subdomain: str) -> Finding | None:
        async with semaphore:
            return await _check_single_subdomain(subdomain, timeout)

    tasks = [check_one(s) for s in subdomains[:100]]  # Limit to 100
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Finding):
            findings.append(r)
        elif isinstance(r, Exception):
            logger.debug(f"Subdomain takeover check error: {r}")

    logger.debug(f"Subdomain takeover checker: {len(findings)} potential findings from {len(subdomains)} subdomains")
    return findings


async def _check_single_subdomain(subdomain: str, timeout: int = 10) -> Finding | None:
    """Check a single subdomain for takeover conditions."""
    # Step 1: Get CNAME record
    cname = await _resolve_cname(subdomain, timeout)
    if not cname:
        return None  # No CNAME = likely not vulnerable to takeover

    # Step 2: Check CNAME against known patterns
    for service_name, config in _TAKEOVER_FINGERPRINTS.items():
        cname_pattern = config["cname"]
        if re.search(cname_pattern, cname, re.IGNORECASE):
            # Step 3: Optional HTTP fingerprint check
            fingerprints = config.get("fingerprints", [])
            http_confirmed = False

            if fingerprints:
                http_confirmed = await _check_http_fingerprint(
                    subdomain, fingerprints, timeout
                )

            severity = config["severity"]
            confidence = 85.0 if http_confirmed else 55.0

            # Without HTTP fingerprint confirmation the CNAME pattern
            # alone is too weak — active services legitimately use the
            # same CNAMEs, producing FPs on every well-hosted domain.
            if not http_confirmed:
                return None

            description = (
                f"Subdomain {subdomain} has a CNAME record pointing to "
                f"{cname} ({service_name})."
            )
            if http_confirmed:
                description += (
                    "\n\nHTTP response confirms the service is unclaimed. "
                    "This subdomain may be vulnerable to takeover."
                )
            else:
                description += (
                    "\n\nCNAME points to a service known for takeover "
                    "vulnerabilities. Verify manually if the service is unclaimed."
                )

            return Finding(
                title=f"Potential Subdomain Takeover: {subdomain} → {service_name}",
                description=description,
                vulnerability_type="subdomain_takeover",
                severity=severity,
                confidence=confidence,
                target=subdomain,
                endpoint=f"https://{subdomain}",
                tool_name="subdomain_takeover_checker",
                evidence=f"CNAME: {subdomain} → {cname}",
                tags=["subdomain_takeover", service_name, "cname"],
            )

    # Check for NXDOMAIN on CNAME target (dangling CNAME)
    nxdomain = await _check_nxdomain(cname, timeout)
    if nxdomain:
        # Only high confidence if CNAME target's registrable domain
        # matches a known takeover-vulnerable service pattern
        is_known_service = any(
            re.search(cfg["cname"], cname, re.IGNORECASE)
            for cfg in _TAKEOVER_FINGERPRINTS.values()
        )
        if is_known_service:
            confidence = 70.0
            severity = SeverityLevel.HIGH
        else:
            # Generic dangling CNAME — could be internal, retired, or
            # a service that doesn't allow arbitrary claims.
            confidence = 20.0
            severity = SeverityLevel.LOW

        return Finding(
            title=f"Dangling CNAME: {subdomain} → {cname} (NXDOMAIN)",
            description=(
                f"Subdomain {subdomain} has a CNAME pointing to {cname}, "
                f"but the CNAME target does not resolve (NXDOMAIN). "
                + (
                    "The target matches a known takeover-vulnerable service. "
                    "This is a strong indicator of a subdomain takeover opportunity."
                    if is_known_service else
                    "The target does NOT match any known takeover-vulnerable service. "
                    "Manual verification is required to confirm if this CNAME "
                    "target can be claimed by an attacker."
                )
            ),
            vulnerability_type="subdomain_takeover",
            severity=severity,
            confidence=confidence,
            target=subdomain,
            endpoint=f"https://{subdomain}",
            tool_name="subdomain_takeover_checker",
            evidence=f"CNAME: {subdomain} → {cname} (NXDOMAIN)",
            tags=["subdomain_takeover", "dangling_cname", "nxdomain"],
        )

    return None


async def _resolve_cname(domain: str, timeout: int = 10) -> str | None:
    """Resolve CNAME record for a domain using dig."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "CNAME", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace").strip()

        # dig returns CNAME target or empty
        if output and not output.startswith(";"):
            # Return first CNAME (in case of chain)
            for line in output.splitlines():
                line = line.strip().rstrip(".")
                if line and not line.startswith(";"):
                    return line
        return None
    except (asyncio.TimeoutError, Exception):
        return None


async def _check_nxdomain(domain: str, timeout: int = 10) -> bool:
    """Check if a domain resolves to NXDOMAIN (does not exist)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "A", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace").strip()

        # Empty output from +short means no A record
        if not output or output.startswith(";"):
            return True
        return False
    except (asyncio.TimeoutError, Exception):
        return False


async def _check_http_fingerprint(
    domain: str,
    fingerprints: list[str],
    timeout: int = 10,
) -> bool:
    """Check HTTP response body for takeover fingerprint strings."""
    try:
        # Use curl for simplicity and reliability
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sL", "-m", str(timeout), "--max-redirs", "3",
            "-o", "-", f"https://{domain}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        body = stdout.decode("utf-8", errors="replace")

        for fp in fingerprints:
            if fp.lower() in body.lower():
                return True
        return False
    except (asyncio.TimeoutError, Exception):
        return False


__all__ = ["check_subdomain_takeover"]
