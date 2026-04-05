"""
WhiteHatHacker AI — SPA Catch-All Route Detector

Detects Single-Page Applications that return the same HTML page for ALL
URL paths (catch-all / fallback routing).  This is the #1 source of false
positives for passive URL finders and endpoint checkers because tools like
gau, waybackurls and katana collect historical URLs that existed at some
point, but an SPA will serve its index.html shell for all of them.

Usage:
    from src.utils.spa_detector import is_spa_catchall

    is_spa, spa_hash = await is_spa_catchall("https://example.com", session)
    if is_spa:
        # Skip or lower confidence for sensitive-URL/rate-limit/info-disclosure checks
"""

from __future__ import annotations

import hashlib
import uuid

import aiohttp
from loguru import logger

# Number of random paths to probe (more = more reliable, but slower)
_PROBE_PATHS = [
    f"/definitely-not-a-real-page-{uuid.uuid4().hex[:8]}",
    f"/spa-check-{uuid.uuid4().hex[:8]}/nested",
    f"/api/v999/nonexistent-{uuid.uuid4().hex[:6]}",
]

# Minimum body length to consider (very short responses are error pages, not SPA)
_MIN_SPA_BODY_LENGTH = 500

# Similarity threshold: if probe responses are this similar to homepage, it's SPA
_SIMILARITY_THRESHOLD = 0.90


def _body_hash(content: bytes) -> str:
    """SHA-256 of response body, stripped of whitespace variance."""
    return hashlib.sha256(content.strip()).hexdigest()


def _similarity(a: bytes, b: bytes) -> float:
    """Quick similarity ratio based on length + shared prefix/suffix."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    # Length-based quick check
    len_ratio = min(len(a), len(b)) / max(len(a), len(b))
    if len_ratio < 0.7:
        return len_ratio
    # Content hash check
    if _body_hash(a) == _body_hash(b):
        return 1.0
    # Approximate: compare first and last 2KB
    chunk = 2048
    head_match = a[:chunk] == b[:chunk]
    tail_match = a[-chunk:] == b[-chunk:]
    if head_match and tail_match:
        return 0.95
    if head_match or tail_match:
        return 0.80
    return len_ratio * 0.5


async def is_spa_catchall(
    base_url: str,
    session: aiohttp.ClientSession | None = None,
    timeout: float = 10.0,
) -> tuple[bool, str]:
    """
    Detect if *base_url* is a Single-Page Application with catch-all routing.

    Returns:
        (is_spa: bool, homepage_hash: str)
        homepage_hash can be used later to verify individual URLs.
    """
    own_session = session is None
    if own_session:
        connector = aiohttp.TCPConnector(ssl=False, limit=5)
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout),
        )

    try:
        # Step 1: Fetch homepage
        try:
            async with session.get(base_url, allow_redirects=True) as resp:
                if resp.status != 200:
                    return False, ""
                home_body = await resp.read()
                home_ct = resp.headers.get("Content-Type", "")
        except Exception as e:
            logger.debug(f"SPA detector: homepage fetch failed: {e}")
            return False, ""

        # Only HTML responses can be SPA
        if "text/html" not in home_ct.lower():
            return False, ""

        # Too short → probably an error page, not an SPA
        if len(home_body) < _MIN_SPA_BODY_LENGTH:
            return False, ""

        home_hash = _body_hash(home_body)

        # Step 2: Probe random non-existent paths
        spa_matches = 0
        for probe_path in _PROBE_PATHS:
            probe_url = base_url.rstrip("/") + probe_path
            try:
                async with session.get(probe_url, allow_redirects=True) as resp:
                    if resp.status != 200:
                        # Real 404 → NOT a catch-all SPA
                        return False, home_hash
                    probe_body = await resp.read()
                    probe_ct = resp.headers.get("Content-Type", "")
            except Exception as _exc:
                logger.debug(f"spa detector error: {_exc}")
                continue

            if "text/html" not in probe_ct.lower():
                continue

            sim = _similarity(home_body, probe_body)
            if sim >= _SIMILARITY_THRESHOLD:
                spa_matches += 1

        # Need at least 2 out of 3 probes to match homepage
        is_spa = spa_matches >= 2
        if is_spa:
            logger.info(
                f"SPA catch-all detected for {base_url} "
                f"({spa_matches}/{len(_PROBE_PATHS)} probes returned homepage)"
            )
        return is_spa, home_hash

    finally:
        if own_session and session:
            await session.close()


async def is_real_endpoint(
    url: str,
    homepage_hash: str,
    session: aiohttp.ClientSession,
    timeout: float = 8.0,
) -> bool:
    """
    Check if *url* returns unique content (not same as SPA homepage).

    Use this after ``is_spa_catchall`` confirms the target is an SPA.
    Returns True if the endpoint serves distinct content (real endpoint).
    """
    try:
        async with session.get(
            url,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status in (404, 410):
                return False  # Explicit not-found
            if resp.status in (301, 302, 303, 307, 308):
                return True  # Redirect = real routing logic
            body = await resp.read()
            ct = resp.headers.get("Content-Type", "")

            # Non-HTML response on a URL that normally should be HTML → real endpoint
            if "text/html" not in ct.lower() and (
                "json" in ct.lower() or "xml" in ct.lower() or "text/plain" in ct.lower()
            ):
                return True

            # Compare with homepage
            if _body_hash(body) == homepage_hash:
                return False  # Same as homepage → SPA catch-all
            if _similarity(body, b"") == 0:
                return True  # Has content
            return True  # Different from homepage → real endpoint
    except Exception as _exc:
        return False  # Can't reach → not a real endpoint


__all__ = ["is_spa_catchall", "is_real_endpoint"]
