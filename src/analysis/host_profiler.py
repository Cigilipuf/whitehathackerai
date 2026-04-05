"""
WhiteHatHacker AI — Host Intelligence Profiler (v3.0 Phase 0)

Builds a HostIntelProfile for every live host BEFORE vulnerability scanning.
This profile drives all downstream decisions:
  - Which checkers to run (skip mass_assignment on static sites)
  - How to interpret responses (302 on AUTH_GATED is normal, not a finding)
  - How to score findings (lower confidence on CDN_ONLY hosts)
  - Where to focus deep testing (WEB_APP and API_SERVER hosts)

The profiler extends SPA detection with:
  - Static site detection (GET == POST, same content for all paths)
  - Auth-gated detection (all paths redirect to auth endpoint)
  - Redirect host detection (all paths redirect to another domain)
  - API server detection (JSON responses, API-style paths)
  - POST response comparison (does the host actually process POST data?)

Usage:
    from src.analysis.host_profiler import HostProfiler, HostIntelProfile, HostType

    profiler = HostProfiler()
    profiles = await profiler.profile_hosts(
        hosts=["https://example.com", "https://api.example.com"],
        timeout=15.0,
    )
    for host, profile in profiles.items():
        print(f"{host}: {profile.host_type.value}")
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import httpx
from loguru import logger


# ====================================================================
# Constants
# ====================================================================

# Random paths that should NOT exist on any real site
_RANDOM_PROBE_PATHS: list[str] = [
    f"/definitely-not-a-real-page-{uuid.uuid4().hex[:8]}",
    f"/hostprofile-check-{uuid.uuid4().hex[:8]}/nested/deep",
    f"/api/v999/nonexistent-endpoint-{uuid.uuid4().hex[:6]}",
]

# Minimum body length to consider a meaningful response (not error stub)
_MIN_MEANINGFUL_BODY = 200

# Similarity threshold for SPA/static detection
_SIMILARITY_THRESHOLD = 0.88

# Common auth redirect path patterns
_AUTH_REDIRECT_PATTERNS = re.compile(
    r"(?i)"
    r"/(?:login|signin|sign-in|sign_in|auth|authorize|oauth|sso|cas|saml"
    r"|accounts/login|users/sign_in|session/new|connect/authorize)"
)

# Known third-party/CDN script domains (not part of target)
THIRD_PARTY_DOMAINS = frozenset({
    "cloudflare.com",
    "cloudflareinsights.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googlesyndication.com",
    "gstatic.com",
    "facebook.net",
    "fbcdn.net",
    "twitter.com",
    "twimg.com",
    "hotjar.com",
    "newrelic.com",
    "nr-data.net",
    "sentry.io",
    "segment.com",
    "segment.io",
    "amplitude.com",
    "mixpanel.com",
    "intercom.io",
    "intercomcdn.com",
    "zendesk.com",
    "zdassets.com",
    "hcaptcha.com",
    "recaptcha.net",
    "gravatar.com",
    "wp.com",
    "jsdelivr.net",
    "datatables.net",
    "jquery.com",
    "bootstrapcdn.com",
    "fontawesome.com",
    "polyfill.io",
    "akamaihd.net",
    "akamaized.net",
    "fastly.net",
    "stackpath.bootstrapcdn.com",
})

# CDN IP ranges (CIDR blocks) — used for OOB callback validation
# Sources: https://www.cloudflare.com/ips/ https://ip-ranges.amazonaws.com
# Updated 2026-03 — these are the major blocks, not exhaustive
CLOUDFLARE_IPV4_RANGES: list[str] = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

CLOUDFRONT_IPV4_RANGES: list[str] = [
    "120.52.22.0/22",
    "205.251.0.0/16",
    "180.163.57.0/24",
    "204.246.168.0/22",
    "111.13.171.0/24",
    "18.160.0.0/15",
    "205.251.200.0/21",
    "54.182.0.0/16",
    "54.192.0.0/16",
    "54.230.0.0/16",
    "54.239.128.0/18",
    "52.46.0.0/18",
    "52.82.128.0/19",
    "52.84.0.0/15",
    "64.252.64.0/18",
    "64.252.128.0/18",
    "99.84.0.0/16",
    "99.86.0.0/16",
    "143.204.0.0/16",
    "13.32.0.0/15",
    "13.35.0.0/16",
    "13.224.0.0/14",
    "13.249.0.0/16",
    "130.176.0.0/18",
]

FASTLY_IPV4_RANGES: list[str] = [
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "140.248.64.0/18",
    "140.248.128.0/17",
    "146.75.0.0/17",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",
]

AKAMAI_IPV4_SAMPLE_RANGES: list[str] = [
    "23.0.0.0/12",
    "23.32.0.0/11",
    "23.64.0.0/14",
    "23.72.0.0/13",
    "104.64.0.0/10",
    "184.24.0.0/13",
    "184.50.0.0/15",
    "184.84.0.0/14",
    "2.16.0.0/13",
    "95.100.0.0/15",
]

# Combined dict for easy lookup
CDN_IP_RANGES: dict[str, list[str]] = {
    "cloudflare": CLOUDFLARE_IPV4_RANGES,
    "cloudfront": CLOUDFRONT_IPV4_RANGES,
    "fastly": FASTLY_IPV4_RANGES,
    "akamai": AKAMAI_IPV4_SAMPLE_RANGES,
}


# ====================================================================
# Enums & Data Model
# ====================================================================

class HostType(str, Enum):
    """Classification of a host based on its behavior."""

    WEB_APP = "web_app"               # Dynamic web application
    API_SERVER = "api_server"         # JSON/XML API endpoint
    SPA = "spa"                       # Single-Page Application (catch-all routing)
    STATIC_SITE = "static_site"       # Static content, GET == POST, no processing
    AUTH_GATED = "auth_gated"         # All paths redirect to auth endpoint
    REDIRECT_HOST = "redirect_host"   # All paths redirect to another domain
    CDN_ONLY = "cdn_only"             # CDN edge, origin not reachable
    UNKNOWN = "unknown"               # Could not determine


@dataclass
class ResponseBaseline:
    """Captured baseline response for a host."""

    status_code: int = 0
    body_hash: str = ""
    body_length: int = 0
    content_type: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    redirect_location: str = ""


@dataclass
class HostIntelProfile:
    """
    Intelligence profile for a single host.
    This is the PRIMARY data structure that drives all downstream scanning decisions.
    """

    host: str
    host_type: HostType = HostType.UNKNOWN

    # Infrastructure
    cdn_provider: str = ""            # cloudflare, akamai, fastly, etc.
    waf_detected: bool = False
    waf_name: str = ""

    # Behavior
    responds_to_post: bool = True     # Does POST return different content than GET?
    post_accepts_body: bool = False   # Does POST with JSON body get processed?
    auth_required: bool = False       # Does it require authentication?
    redirect_target: str = ""         # If it redirects, where to?
    content_similarity: float = 0.0   # How similar are responses across paths (0-1)

    # Technology
    technologies: list[str] = field(default_factory=list)
    server_header: str = ""
    powered_by: str = ""

    # Baselines
    homepage_baseline: ResponseBaseline = field(default_factory=ResponseBaseline)
    random_path_baselines: list[ResponseBaseline] = field(default_factory=list)
    post_baseline: ResponseBaseline | None = None

    # Scanning guidance
    skip_checkers: list[str] = field(default_factory=list)   # Checker names to skip
    confidence_modifier: float = 0.0   # Global adjustment (-0.3 to +0.1)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for checkpoint/metadata storage."""
        return {
            "host": self.host,
            "host_type": self.host_type.value,
            "cdn_provider": self.cdn_provider,
            "waf_detected": self.waf_detected,
            "waf_name": self.waf_name,
            "responds_to_post": self.responds_to_post,
            "post_accepts_body": self.post_accepts_body,
            "auth_required": self.auth_required,
            "redirect_target": self.redirect_target,
            "content_similarity": self.content_similarity,
            "technologies": list(self.technologies),
            "server_header": self.server_header,
            "powered_by": self.powered_by,
            "skip_checkers": list(self.skip_checkers),
            "confidence_modifier": self.confidence_modifier,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HostIntelProfile:
        """Reconstruct from dict (e.g., after checkpoint resume)."""
        ht = data.get("host_type", "unknown")
        try:
            host_type = HostType(ht)
        except ValueError:
            host_type = HostType.UNKNOWN
        return cls(
            host=data.get("host", ""),
            host_type=host_type,
            cdn_provider=data.get("cdn_provider", ""),
            waf_detected=data.get("waf_detected", False),
            waf_name=data.get("waf_name", ""),
            responds_to_post=data.get("responds_to_post", True),
            post_accepts_body=data.get("post_accepts_body", False),
            auth_required=data.get("auth_required", False),
            redirect_target=data.get("redirect_target", ""),
            content_similarity=data.get("content_similarity", 0.0),
            technologies=data.get("technologies", []),
            server_header=data.get("server_header", ""),
            powered_by=data.get("powered_by", ""),
            skip_checkers=data.get("skip_checkers", []),
            confidence_modifier=data.get("confidence_modifier", 0.0),
        )

    def should_skip_checker(self, checker_name: str) -> bool:
        """Check if a specific checker should be skipped for this host."""
        return checker_name in self.skip_checkers

    def is_testable(self) -> bool:
        """Check if this host is worth scanning at all."""
        return self.host_type in (
            HostType.WEB_APP,
            HostType.API_SERVER,
            HostType.SPA,
            HostType.UNKNOWN,    # Give unknown hosts a chance
        )


# ====================================================================
# Checker-HostType compatibility matrix
# ====================================================================

# Which checkers are INCOMPATIBLE with which host types
# checker_name → set of HostType values where it should be skipped
_CHECKER_SKIP_MAP: dict[str, set[HostType]] = {
    # Mass assignment requires POST processing — useless on static/auth-gated/redirect
    "mass_assignment_checker": {
        HostType.STATIC_SITE, HostType.AUTH_GATED, HostType.REDIRECT_HOST,
        HostType.CDN_ONLY, HostType.SPA,
    },
    # Deserialization needs actual server-side processing
    "deserialization_checker": {
        HostType.STATIC_SITE, HostType.CDN_ONLY, HostType.REDIRECT_HOST,
        HostType.SPA,
    },
    # Cloud/infra checks fail on auth-gated (all 302) and redirect hosts
    "cloud_checker": {
        HostType.AUTH_GATED, HostType.REDIRECT_HOST, HostType.CDN_ONLY,
    },
    # CI/CD paths don't exist on auth-gated or redirect hosts
    "cicd_checker": {
        HostType.AUTH_GATED, HostType.REDIRECT_HOST, HostType.CDN_ONLY,
        HostType.STATIC_SITE,
    },
    # DOM XSS needs JavaScript execution context — not on redirects or API
    "js_analyzer": {
        HostType.REDIRECT_HOST, HostType.CDN_ONLY, HostType.API_SERVER,
    },
    # Race conditions need server-side state
    "race_condition": {
        HostType.STATIC_SITE, HostType.CDN_ONLY, HostType.REDIRECT_HOST,
    },
    # Business logic needs dynamic application
    "business_logic": {
        HostType.STATIC_SITE, HostType.CDN_ONLY, HostType.REDIRECT_HOST,
    },
    # Prototype pollution needs JS on a web app
    "prototype_pollution_checker": {
        HostType.STATIC_SITE, HostType.CDN_ONLY, HostType.REDIRECT_HOST,
        HostType.AUTH_GATED,
    },
    # Cache poisoning needs cacheable dynamic content
    "cache_poisoning_checker": {
        HostType.STATIC_SITE, HostType.REDIRECT_HOST,
    },
    # BFLA/BOLA needs API with auth
    "bfla_bola_checker": {
        HostType.STATIC_SITE, HostType.CDN_ONLY, HostType.REDIRECT_HOST,
    },
    # HTTP smuggling needs a front-end proxy — pointless on CDN-only
    "http_smuggling_prober": {
        HostType.REDIRECT_HOST,
    },
    # WebSocket checks need WS upgrade support
    "websocket_checker": {
        HostType.STATIC_SITE, HostType.CDN_ONLY, HostType.REDIRECT_HOST,
    },
    # Subdomain takeover operates on DNS, not host type — no skip
    # Open redirect needs dynamic redirect logic
    "open_redirect_checker": {
        HostType.STATIC_SITE, HostType.CDN_ONLY,
    },
    # IDOR needs authenticated endpoints
    "idor_checker": {
        HostType.STATIC_SITE, HostType.CDN_ONLY, HostType.REDIRECT_HOST,
    },
    # GraphQL only on hosts that actually serve GraphQL
    "graphql_deep_scanner": {
        HostType.STATIC_SITE, HostType.CDN_ONLY, HostType.REDIRECT_HOST,
    },
    # CORS is relevant everywhere except redirect-only hosts
    "cors_checker": {
        HostType.REDIRECT_HOST,
    },
    # HTTP method testing
    "http_method_checker": {
        HostType.CDN_ONLY, HostType.REDIRECT_HOST,
    },
    # Info disclosure
    "info_disclosure_checker": {
        HostType.REDIRECT_HOST,
    },
    # Sensitive URL finder
    "sensitive_url_finder": {
        HostType.AUTH_GATED, HostType.REDIRECT_HOST, HostType.CDN_ONLY,
    },
    # API endpoint tester
    "api_endpoint_tester": {
        HostType.STATIC_SITE, HostType.REDIRECT_HOST, HostType.CDN_ONLY,
    },
    # 403/401 bypass
    "fourxx_bypass": {
        HostType.REDIRECT_HOST, HostType.CDN_ONLY,
    },
    # HTTP/2-3 checks
    "http2_http3_checker": {
        HostType.REDIRECT_HOST,
    },
}


# ====================================================================
# Helper functions
# ====================================================================

def _body_hash(content: bytes) -> str:
    """SHA-256 of response body, stripped of whitespace variance."""
    return hashlib.sha256(content.strip()).hexdigest()


def _similarity(a: bytes, b: bytes) -> float:
    """
    Quick similarity ratio between two response bodies.
    Returns 0.0 (completely different) to 1.0 (identical).
    """
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    # Length-based quick check
    len_a, len_b = len(a), len(b)
    len_ratio = min(len_a, len_b) / max(len_a, len_b) if max(len_a, len_b) > 0 else 0.0
    if len_ratio < 0.7:
        return len_ratio
    # Exact content hash
    if _body_hash(a) == _body_hash(b):
        return 1.0
    # Compare first and last 2KB chunks
    chunk = 2048
    head_match = a[:chunk] == b[:chunk]
    tail_match = a[-chunk:] == b[-chunk:]
    if head_match and tail_match:
        return 0.95
    if head_match or tail_match:
        return 0.80
    return len_ratio * 0.5


def _extract_redirect_target(headers: httpx.Headers, current_url: str) -> str:
    """Extract final redirect target from Location header."""
    location = headers.get("location", "")
    if not location:
        return ""
    # Relative URL → absolute
    if location.startswith("/"):
        parsed = urlparse(current_url)
        return f"{parsed.scheme}://{parsed.netloc}{location}"
    return location


def _detect_cdn_from_headers(headers: httpx.Headers) -> str:
    """Quick CDN detection from response headers."""
    h_lower = {k.lower(): v for k, v in headers.items()}

    if "cf-ray" in h_lower or "cf-cache-status" in h_lower:
        return "cloudflare"
    if "x-amz-cf-id" in h_lower or "x-amz-cf-pop" in h_lower:
        return "cloudfront"
    if "x-akamai-transformed" in h_lower:
        return "akamai"
    if "x-fastly-request-id" in h_lower:
        return "fastly"
    if "x-sucuri-id" in h_lower:
        return "sucuri"
    if "x-msedge-ref" in h_lower or "x-azure-ref" in h_lower:
        return "azure_cdn"
    # Server header fallback
    server = h_lower.get("server", "").lower()
    if "cloudflare" in server:
        return "cloudflare"
    if "cloudfront" in server:
        return "cloudfront"
    if "akamai" in server:
        return "akamai"
    return ""


def _detect_waf_from_headers(headers: httpx.Headers) -> tuple[bool, str]:
    """Quick WAF detection from response headers."""
    h_lower = {k.lower(): v for k, v in headers.items()}

    # Cloudflare WAF challenge indicators
    if "cf-mitigated" in h_lower or "cf-chl-bypass" in h_lower:
        return True, "cloudflare"

    server = h_lower.get("server", "").lower()
    if "cloudflare" in server:
        # Cloudflare is always WAF-capable even without explicit challenge headers
        return True, "cloudflare"

    if any(k in h_lower for k in ("x-sucuri-id", "x-sucuri-cache")):
        return True, "sucuri"
    if "x-cdn" in h_lower and "imperva" in h_lower.get("x-cdn", "").lower():
        return True, "imperva"
    if any(k in h_lower for k in ("x-powered-by-plesk",)):
        return False, ""

    return False, ""


def _extract_technologies(headers: httpx.Headers) -> tuple[list[str], str, str]:
    """Extract technology hints from response headers."""
    techs: list[str] = []
    h_lower = {k.lower(): v for k, v in headers.items()}

    server = h_lower.get("server", "")
    powered_by = h_lower.get("x-powered-by", "")

    if server:
        techs.append(f"server:{server}")
    if powered_by:
        techs.append(f"powered_by:{powered_by}")

    # Framework hints
    for key in ("x-aspnet-version", "x-aspnetmvc-version"):
        if key in h_lower:
            techs.append("asp.net")
    if "x-drupal-cache" in h_lower or "x-generator" in h_lower and "drupal" in h_lower.get("x-generator", "").lower():
        techs.append("drupal")
    if "x-powered-by" in h_lower:
        pb = h_lower["x-powered-by"].lower()
        if "php" in pb:
            techs.append("php")
        if "express" in pb:
            techs.append("express")
        if "asp.net" in pb:
            techs.append("asp.net")

    return techs, server, powered_by


def _is_auth_redirect(status_code: int, location: str) -> bool:
    """Check if a redirect points to an authentication endpoint."""
    if status_code not in (301, 302, 303, 307, 308):
        return False
    if not location:
        return False
    return bool(_AUTH_REDIRECT_PATTERNS.search(location))


def _capture_baseline(resp: httpx.Response, body: bytes) -> ResponseBaseline:
    """Capture a ResponseBaseline from an httpx response."""
    return ResponseBaseline(
        status_code=resp.status_code,
        body_hash=_body_hash(body),
        body_length=len(body),
        content_type=resp.headers.get("content-type", ""),
        headers={k.lower(): v for k, v in resp.headers.items()},
        redirect_location=resp.headers.get("location", ""),
    )


# ====================================================================
# IP range utilities (for OOB callback validation)
# ====================================================================

def _parse_cidr(cidr: str) -> tuple[int, int]:
    """Parse a CIDR block into (network_int, mask_int)."""
    parts = cidr.split("/")
    ip_parts = parts[0].split(".")
    prefix_len = int(parts[1])
    ip_int = (
        (int(ip_parts[0]) << 24)
        | (int(ip_parts[1]) << 16)
        | (int(ip_parts[2]) << 8)
        | int(ip_parts[3])
    )
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return ip_int & mask, mask


def _ip_to_int(ip: str) -> int:
    """Convert dotted-quad IP to integer."""
    parts = ip.split(".")
    if len(parts) != 4:
        return 0
    try:
        return (
            (int(parts[0]) << 24)
            | (int(parts[1]) << 16)
            | (int(parts[2]) << 8)
            | int(parts[3])
        )
    except (ValueError, IndexError):
        return 0


# Pre-parsed CIDR blocks for fast lookup
_PARSED_CDN_RANGES: dict[str, list[tuple[int, int]]] | None = None


def _get_parsed_cdn_ranges() -> dict[str, list[tuple[int, int]]]:
    """Lazy-initialize parsed CDN IP ranges."""
    global _PARSED_CDN_RANGES
    if _PARSED_CDN_RANGES is None:
        _PARSED_CDN_RANGES = {}
        for provider, cidrs in CDN_IP_RANGES.items():
            _PARSED_CDN_RANGES[provider] = [_parse_cidr(c) for c in cidrs]
    return _PARSED_CDN_RANGES


def is_cdn_ip(ip: str) -> tuple[bool, str]:
    """
    Check if an IP address belongs to a known CDN provider.

    Returns:
        (is_cdn: bool, provider_name: str)
    """
    ip_int = _ip_to_int(ip)
    if ip_int == 0:
        return False, ""

    for provider, ranges in _get_parsed_cdn_ranges().items():
        for net, mask in ranges:
            if (ip_int & mask) == net:
                return True, provider
    return False, ""


def get_all_cdn_ranges() -> dict[str, list[str]]:
    """Return the full CDN IP range database for external consumers."""
    return dict(CDN_IP_RANGES)


# ====================================================================
# Main Profiler Class
# ====================================================================

class HostProfiler:
    """
    Profiles hosts to determine their type and scanning strategy.
    Must be run BEFORE vulnerability scanning to avoid wasted effort.
    """

    def __init__(self, timeout: float = 12.0, max_concurrent: int = 10):
        self._timeout = timeout
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def profile_hosts(
        self,
        hosts: list[str],
        *,
        timeout: float | None = None,
    ) -> dict[str, HostIntelProfile]:
        """
        Profile multiple hosts concurrently.

        Args:
            hosts: List of base URLs (e.g., ["https://example.com"])
            timeout: Per-host timeout in seconds (default: self._timeout)

        Returns:
            dict mapping host URL → HostIntelProfile
        """
        effective_timeout = timeout or self._timeout
        profiles: dict[str, HostIntelProfile] = {}

        # Deduplicate hosts
        unique_hosts = list(dict.fromkeys(hosts))

        if not unique_hosts:
            return profiles

        logger.info(f"HostProfiler: profiling {len(unique_hosts)} hosts...")

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(effective_timeout, connect=8.0),
            follow_redirects=False,   # We handle redirects manually
            verify=False,
            limits=httpx.Limits(
                max_connections=self._max_concurrent,
                max_keepalive_connections=5,
            ),
        ) as client:
            tasks = [
                self._profile_single_host(client, host, effective_timeout)
                for host in unique_hosts
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for host, result in zip(unique_hosts, results):
            if isinstance(result, Exception):
                logger.warning(f"HostProfiler: failed to profile {host}: {result}")
                profiles[host] = HostIntelProfile(host=host, host_type=HostType.UNKNOWN)
            else:
                profiles[host] = result

        # Summary log
        type_counts: dict[str, int] = {}
        for p in profiles.values():
            type_counts[p.host_type.value] = type_counts.get(p.host_type.value, 0) + 1
        logger.info(f"HostProfiler: profiling complete — {type_counts}")

        return profiles

    async def _profile_single_host(
        self,
        client: httpx.AsyncClient,
        host: str,
        timeout: float,
    ) -> HostIntelProfile:
        """Profile a single host through multi-step analysis."""
        async with self._semaphore:
            profile = HostIntelProfile(host=host)

            # ────────────────────────────────────────
            # Step 1: Fetch homepage (GET)
            # ────────────────────────────────────────
            try:
                home_resp = await client.get(host, follow_redirects=False)
                home_body = home_resp.content
            except Exception as e:
                logger.debug(f"HostProfiler: {host} homepage fetch failed: {e}")
                return profile  # UNKNOWN

            home_baseline = _capture_baseline(home_resp, home_body)
            profile.homepage_baseline = home_baseline

            # Extract technology info from headers
            techs, server, powered_by = _extract_technologies(home_resp.headers)
            profile.technologies = techs
            profile.server_header = server
            profile.powered_by = powered_by

            # CDN detection
            cdn = _detect_cdn_from_headers(home_resp.headers)
            if cdn:
                profile.cdn_provider = cdn

            # WAF detection
            waf_detected, waf_name = _detect_waf_from_headers(home_resp.headers)
            profile.waf_detected = waf_detected
            profile.waf_name = waf_name

            # ────────────────────────────────────────
            # Step 2: Handle redirects
            # ────────────────────────────────────────
            if 300 <= home_resp.status_code < 400:
                location = _extract_redirect_target(home_resp.headers, host)
                profile.redirect_target = location

                if _is_auth_redirect(home_resp.status_code, location):
                    # Homepage redirects to auth → check if ALL paths do the same
                    all_redirect_to_auth = await self._check_all_paths_redirect(
                        client, host, location,
                    )
                    if all_redirect_to_auth:
                        profile.host_type = HostType.AUTH_GATED
                        profile.auth_required = True
                        profile.skip_checkers = self._compute_skip_list(HostType.AUTH_GATED)
                        profile.confidence_modifier = -0.15
                        logger.info(f"HostProfiler: {host} → AUTH_GATED (redirects to auth)")
                        return profile

                # Non-auth redirect → check if it's a wholesale redirect host
                parsed_host = urlparse(host).netloc.lower()
                parsed_loc = urlparse(location).netloc.lower() if location else ""
                if parsed_loc and parsed_loc != parsed_host:
                    # Redirects to different domain → check if all paths do the same
                    all_redirect = await self._check_all_paths_redirect(
                        client, host, location,
                    )
                    if all_redirect:
                        profile.host_type = HostType.REDIRECT_HOST
                        profile.skip_checkers = self._compute_skip_list(HostType.REDIRECT_HOST)
                        profile.confidence_modifier = -0.25
                        logger.info(f"HostProfiler: {host} → REDIRECT_HOST (all paths → {parsed_loc})")
                        return profile

                # Follow redirect to get actual content for further analysis
                try:
                    home_resp = await client.get(host, follow_redirects=True)
                    home_body = home_resp.content
                    home_baseline = _capture_baseline(home_resp, home_body)
                    profile.homepage_baseline = home_baseline
                except Exception:
                    pass  # Keep original baseline

            # ────────────────────────────────────────
            # Step 3: Probe random non-existent paths
            # ────────────────────────────────────────
            probe_bodies: list[bytes] = []
            probe_baselines: list[ResponseBaseline] = []
            auth_redirect_count = 0

            for probe_path in _RANDOM_PROBE_PATHS:
                probe_url = host.rstrip("/") + probe_path
                try:
                    probe_resp = await client.get(probe_url, follow_redirects=False)
                    probe_body = probe_resp.content
                    probe_bl = _capture_baseline(probe_resp, probe_body)
                    probe_baselines.append(probe_bl)
                    probe_bodies.append(probe_body)

                    # Check for auth redirect on random paths
                    if _is_auth_redirect(
                        probe_resp.status_code,
                        probe_resp.headers.get("location", ""),
                    ):
                        auth_redirect_count += 1
                except Exception as e:
                    logger.debug(f"HostProfiler: probe {probe_url} failed: {e}")

            profile.random_path_baselines = probe_baselines

            # If all probes redirect to auth → AUTH_GATED
            if auth_redirect_count >= 2:
                profile.host_type = HostType.AUTH_GATED
                profile.auth_required = True
                profile.skip_checkers = self._compute_skip_list(HostType.AUTH_GATED)
                profile.confidence_modifier = -0.15
                logger.info(f"HostProfiler: {host} → AUTH_GATED ({auth_redirect_count}/3 probes redirect to auth)")
                return profile

            # ────────────────────────────────────────
            # Step 4: API server detection (BEFORE SPA/static check)
            # ────────────────────────────────────────
            # API servers often return same JSON for all paths (404 JSON),
            # which would falsely trigger SPA/static detection.
            ct_lower = home_baseline.content_type.lower()
            if "application/json" in ct_lower or "application/xml" in ct_lower:
                profile.host_type = HostType.API_SERVER
                profile.skip_checkers = self._compute_skip_list(HostType.API_SERVER)
                profile.confidence_modifier = 0.0
                logger.info(f"HostProfiler: {host} → API_SERVER (content-type: {ct_lower})")
                return profile

            # ────────────────────────────────────────
            # Step 5: SPA / Static site detection
            # ────────────────────────────────────────
            if home_baseline.status_code == 200 and probe_bodies:
                similarities = [
                    _similarity(home_body, pb) for pb in probe_bodies if pb
                ]
                if similarities:
                    avg_sim = sum(similarities) / len(similarities)
                    profile.content_similarity = avg_sim

                    if avg_sim >= _SIMILARITY_THRESHOLD:
                        # High similarity → SPA or static site
                        # Distinguish: check Content-Type and JS presence
                        ct = home_baseline.content_type.lower()
                        has_js_framework = any(
                            marker in home_body.decode("utf-8", errors="replace").lower()
                            for marker in (
                                "react", "angular", "vue", "__next", "nuxt",
                                "svelte", "ember", "backbone", "webpack",
                                "bundle.js", "app.js", "main.js", "chunk",
                            )
                        )
                        if "text/html" in ct and has_js_framework:
                            profile.host_type = HostType.SPA
                            profile.skip_checkers = self._compute_skip_list(HostType.SPA)
                            profile.confidence_modifier = -0.10
                            logger.info(
                                f"HostProfiler: {host} → SPA "
                                f"(avg similarity {avg_sim:.2f}, JS framework detected)"
                            )
                        else:
                            # No JS framework → likely static site
                            profile.host_type = HostType.STATIC_SITE
                            profile.skip_checkers = self._compute_skip_list(HostType.STATIC_SITE)
                            profile.confidence_modifier = -0.20
                            logger.info(
                                f"HostProfiler: {host} → STATIC_SITE "
                                f"(avg similarity {avg_sim:.2f}, no JS framework)"
                            )
                            return profile

            # ────────────────────────────────────────
            # Step 5: POST comparison (does the host process POST?)
            # ────────────────────────────────────────
            try:
                post_resp = await client.post(
                    host,
                    content=b'{"test_field": "host_profile_check_value"}',
                    headers={"Content-Type": "application/json"},
                    follow_redirects=True,
                )
                post_body = post_resp.content
                post_bl = _capture_baseline(post_resp, post_body)
                profile.post_baseline = post_bl

                # Compare POST to GET
                get_post_sim = _similarity(home_body, post_body)
                if get_post_sim >= 0.95:
                    # POST returns same as GET → host doesn't process POST bodies
                    profile.responds_to_post = False
                    profile.post_accepts_body = False
                else:
                    profile.responds_to_post = True
                    # Check if our test value appears in response
                    if b"host_profile_check_value" in post_body:
                        profile.post_accepts_body = True

            except Exception as e:
                logger.debug(f"HostProfiler: POST test failed for {host}: {e}")
                # If POST fails, assume it doesn't process POST
                profile.responds_to_post = False

            # ────────────────────────────────────────
            # Step 7: CDN-only detection
            # ────────────────────────────────────────
            if profile.cdn_provider and not profile.responds_to_post:
                # CDN detected + doesn't process POST → might be CDN-only
                # Check if homepage looks like a CDN error page
                body_text = home_body.decode("utf-8", errors="replace").lower()
                cdn_error_signals = sum([
                    "error" in body_text and "1000" in body_text,   # CF error 1000
                    "403 forbidden" in body_text,
                    "access denied" in body_text,
                    len(home_body) < 1000 and home_baseline.status_code in (403, 503),
                ])
                if cdn_error_signals >= 1 and home_baseline.status_code in (403, 503):
                    profile.host_type = HostType.CDN_ONLY
                    profile.skip_checkers = self._compute_skip_list(HostType.CDN_ONLY)
                    profile.confidence_modifier = -0.30
                    logger.info(f"HostProfiler: {host} → CDN_ONLY (CDN error page detected)")
                    return profile

            # ────────────────────────────────────────
            # Step 8: Default → WEB_APP
            # ────────────────────────────────────────
            if profile.host_type in (HostType.UNKNOWN, HostType.SPA):
                # SPA that reached here is still testable, but normal web apps get WEB_APP
                if profile.host_type == HostType.UNKNOWN:
                    profile.host_type = HostType.WEB_APP
                    profile.skip_checkers = self._compute_skip_list(HostType.WEB_APP)
                    logger.info(f"HostProfiler: {host} → WEB_APP (default classification)")

            return profile

    async def _check_all_paths_redirect(
        self,
        client: httpx.AsyncClient,
        host: str,
        expected_location: str,
    ) -> bool:
        """Check if all random paths redirect similarly to the expected location."""
        redirect_count = 0
        expected_parsed = urlparse(expected_location)

        for probe_path in _RANDOM_PROBE_PATHS[:2]:  # Quick check — only 2 probes
            probe_url = host.rstrip("/") + probe_path
            try:
                resp = await client.get(probe_url, follow_redirects=False)
                if 300 <= resp.status_code < 400:
                    loc = resp.headers.get("location", "")
                    # Check if redirect target matches expected pattern
                    loc_parsed = urlparse(loc)
                    if (
                        loc_parsed.netloc == expected_parsed.netloc
                        or _AUTH_REDIRECT_PATTERNS.search(loc)
                    ):
                        redirect_count += 1
                    elif loc_parsed.path and expected_parsed.path:
                        # Same path prefix (e.g., both go to /login)
                        if loc_parsed.path.split("?")[0] == expected_parsed.path.split("?")[0]:
                            redirect_count += 1
            except Exception:
                pass

        return redirect_count >= 2

    @staticmethod
    def _compute_skip_list(host_type: HostType) -> list[str]:
        """Compute which checkers should be skipped for a given host type."""
        return [
            checker for checker, skip_types in _CHECKER_SKIP_MAP.items()
            if host_type in skip_types
        ]

    @staticmethod
    def get_skip_map() -> dict[str, set[HostType]]:
        """Return the checker-HostType skip map for testing/inspection."""
        return dict(_CHECKER_SKIP_MAP)


__all__ = [
    "HostProfiler",
    "HostIntelProfile",
    "HostType",
    "ResponseBaseline",
    "CDN_IP_RANGES",
    "THIRD_PARTY_DOMAINS",
    "is_cdn_ip",
    "get_all_cdn_ranges",
    "_CHECKER_SKIP_MAP",
]
