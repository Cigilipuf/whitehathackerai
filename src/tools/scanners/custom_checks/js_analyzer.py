"""
WhiteHatHacker AI — JavaScript Endpoint & Secret Analyzer

Fetches JavaScript files found during crawling and extracts:
  - API endpoints (relative/absolute paths)
  - Hardcoded secrets (API keys, tokens, passwords)
  - Cloud service URLs (AWS, GCP, Azure)
  - Sensitive configuration values
  - Hidden admin/debug endpoints
  - High-entropy strings that may be undiscovered secrets (P4-4)
  - DOM XSS sinks and sources (P4-4)
"""

from __future__ import annotations

import asyncio
import math
import re
from collections import Counter
from urllib.parse import urljoin, urlparse

from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel


# ── Compiled regex patterns for performance ──────────────────────

# API endpoints in JS
_ENDPOINT_PATTERNS: list[re.Pattern] = [
    # Relative API paths: "/api/v1/users", "/v2/auth/login"
    re.compile(r"""["'`](/(?:api|v[0-9]+|rest|graphql|auth|admin|internal|private|debug|health|status|config|webhook|callback|oauth|token|login|signup|register|reset|verify|upload|download|export|import)[/\w\-\.]*?)["'`]""", re.I),
    # Fetch/axios/XMLHttpRequest URL patterns
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch|XMLHttpRequest)\s*\(\s*["'`]((?:https?://)?[/\w\-\.]+?)["'`]""", re.I),
    # Assignment to URL/endpoint variables
    re.compile(r"""(?:url|endpoint|api_?url|base_?url|host|server|backend)\s*[:=]\s*["'`]((?:https?://)?[/\w\-\.:]+?)["'`]""", re.I),
    # Route definitions (React Router, Express, etc.)
    re.compile(r"""(?:path|route)\s*[:=]\s*["'`](/[\w\-\./:\*]+?)["'`]""", re.I),
]

# Secret/credential patterns
_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS Access Key", re.compile(r"""(?:AKIA[0-9A-Z]{16})"""), "high"),
    ("AWS Secret Key", re.compile(r"""(?:aws.{0,20}(?:secret|key).{0,20}['"][0-9a-zA-Z/+]{40}['"])""", re.I), "critical"),
    ("Google API Key", re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""), "high"),
    ("Google OAuth ID", re.compile(r"""[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"""), "medium"),
    ("GitHub Token", re.compile(r"""(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"""), "high"),
    ("Slack Token", re.compile(r"""xox[bpors]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}"""), "high"),
    ("Slack Webhook", re.compile(r"""https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"""), "medium"),
    ("Private Key", re.compile(r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"""), "critical"),
    ("JWT Token", re.compile(r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"""), "medium"),
    ("Generic API Key", re.compile(r"""(?:api[_-]?key|apikey|api_secret|app_secret|app_key)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']""", re.I), "medium"),
    ("Generic Token", re.compile(r"""(?:access_token|auth_token|bearer_token|secret_token)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{16,})["']""", re.I), "medium"),
    ("Generic Password", re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']""", re.I), "medium"),
    ("Firebase URL", re.compile(r"""https://[a-z0-9-]+\.firebaseio\.com"""), "medium"),
    ("Firebase API Key", re.compile(r"""(?:firebase.{0,20}api.{0,20}key.{0,20})["']([A-Za-z0-9_\-]{30,})["']""", re.I), "medium"),
    ("Stripe Key", re.compile(r"""(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}"""), "high"),
    ("Mailgun Key", re.compile(r"""key-[0-9a-zA-Z]{32}"""), "medium"),
    ("Twilio SID", re.compile(r"""AC[a-f0-9]{32}"""), "medium"),
    ("SendGrid Key", re.compile(r"""SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}"""), "high"),
    ("Heroku API", re.compile(r"""(?:heroku.{0,20}api.{0,20})["']([0-9a-f-]{36})["']""", re.I), "medium"),
    ("Internal IP", re.compile(r"""(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"""), "low"),
    # ── Additional provider keys (T3-1 enhancement) ──
    ("Cloudinary URL", re.compile(r"""cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z]+"""), "high"),
    ("Algolia API Key", re.compile(r"""(?:algolia.{0,20}(?:key|secret).{0,20})["']([a-f0-9]{32})["']""", re.I), "medium"),
    ("Mapbox Token", re.compile(r"""pk\.[a-zA-Z0-9]{60,}"""), "medium"),
    ("Square Token", re.compile(r"""sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}"""), "high"),
    ("Shopify Key", re.compile(r"""shpat_[a-fA-F0-9]{32}"""), "high"),
    ("DigitalOcean Token", re.compile(r"""dop_v1_[a-f0-9]{64}"""), "high"),
    ("Databricks Token", re.compile(r"""dapi[a-f0-9]{32}"""), "high"),
    ("npm Token", re.compile(r"""npm_[A-Za-z0-9]{36}"""), "high"),
    ("PyPI Token", re.compile(r"""pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}"""), "high"),
    ("Docker Hub Token", re.compile(r"""dckr_pat_[A-Za-z0-9\-_]{27,}"""), "high"),
    ("GitLab Token", re.compile(r"""glpat-[A-Za-z0-9\-_]{20}"""), "high"),
    ("Bitbucket App Password", re.compile(r"""ATBB[A-Za-z0-9]{32,}"""), "high"),
    ("Vault Token", re.compile(r"""hvs\.[a-zA-Z0-9_-]{24,}"""), "high"),
    ("Discord Bot Token", re.compile(r"""[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"""), "high"),
]

# Cloud service URLs
_CLOUD_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS S3 Bucket", re.compile(r"""(?:https?://)?(?:[a-z0-9.-]+\.)?s3[.-](?:us|eu|ap|sa|ca|me|af)[\w-]*\.amazonaws\.com|s3://[a-z0-9.-]+""", re.I)),
    ("Azure Blob", re.compile(r"""https?://[a-z0-9]+\.blob\.core\.windows\.net""", re.I)),
    ("GCP Storage", re.compile(r"""https?://storage\.googleapis\.com/[a-z0-9._-]+""", re.I)),
    ("CloudFront", re.compile(r"""https?://[a-z0-9]+\.cloudfront\.net""", re.I)),
]


# ── Third-party JS CDN filtering ──────────────────────────────────

# CDN domains and known third-party JS providers whose secrets are
# not relevant to the target (public keys, tracking IDs, etc.)
_THIRD_PARTY_JS_DOMAINS: tuple[str, ...] = (
    # CDN providers
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "ajax.googleapis.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "cdn.bootcss.com", "cdn.bootcdn.net",
    "fastly.jsdelivr.net", "cdn.staticfile.org",
    # Analytics / tracking
    "www.google-analytics.com", "www.googletagmanager.com",
    "connect.facebook.net", "platform.twitter.com",
    "cdn.segment.com", "cdn.amplitude.com", "cdn.mxpnl.com",
    "cdn.heapanalytics.com", "cdn.rudderlabs.com",
    "static.hotjar.com", "snap.licdn.com", "bat.bing.com",
    "analytics.tiktok.com", "sc-static.net",
    # Chat / support widgets
    "js.intercomcdn.com", "widget.intercom.io",
    "cdn.zendesk.com", "static.zdassets.com",
    "js.driftt.com", "cdn.livechatinc.com",
    # Payment (public JS is intentional)
    "js.stripe.com", "js.braintreegateway.com",
    "www.paypalobjects.com", "checkout.razorpay.com",
    # Ad tech
    "pagead2.googlesyndication.com", "securepubads.g.doubleclick.net",
    "cdn.taboola.com", "cdn.outbrain.com",
    # Social / embed
    "platform.instagram.com", "cdn.embedly.com",
    "player.vimeo.com", "www.youtube.com",
    # Fonts / icons
    "use.fontawesome.com", "use.typekit.net",
    "fonts.googleapis.com", "kit.fontawesome.com",
    # A/B testing / feature flags
    "cdn.optimizely.com", "cdn.launchdarkly.com",
    # ReCAPTCHA / bot protection
    "www.google.com/recaptcha", "www.gstatic.com/recaptcha",
    "challenges.cloudflare.com",
    # v4.0: Additional CDN/SaaS domains
    "static.cloudflareinsights.com", "cloudflare.com",
    "ajax.cloudflare.com", "beacon.cloudflare.com",
    "discord.com", "discordapp.com", "cdn.discordapp.com",
    # Error tracking
    "browser.sentry-cdn.com", "d2wy8f7a9ursnm.cloudfront.net",  # bugsnag
    "js.datadoghq.com",
    # Maps
    "maps.googleapis.com", "api.mapbox.com",
)

# URL path patterns that indicate third-party library code
_THIRD_PARTY_JS_PATH_PATTERNS: tuple[str, ...] = (
    "/jquery", "/react.", "/angular.", "/vue.", "/bootstrap",
    "/lodash", "/moment.", "/axios.", "/d3.", "/chart.",
    "/polyfill", "/modernizr", "/underscore", "/backbone",
    "/ember.", "/handlebars.", "/mustache.",
    "/gsap", "/three.", "/pixi.", "/phaser.",
    "/socket.io", "/sockjs", "/stomp.",
    "/highlight.", "/prism.", "/codemirror",
    "/tiny", "/ckeditor", "/quill",
)


def _is_third_party_js(url: str) -> bool:
    """Check if a JS URL belongs to a known third-party CDN or library."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path_lower = parsed.path.lower()

    # Check domain
    for domain in _THIRD_PARTY_JS_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return True

    # Check path patterns (on any domain — e.g. self-hosted vendor JS)
    for pattern in _THIRD_PARTY_JS_PATH_PATTERNS:
        if pattern in path_lower:
            return True

    return False


async def _fetch_js(url: str, timeout: float = 10.0) -> str | None:
    """Fetch JavaScript file content via curl, with HTTP status check."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sSL", "-m", str(int(timeout)),
            "-H", "User-Agent: Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)",
            "--max-filesize", "2097152",  # 2MB limit
            "-w", "\n%{http_code}",  # Append HTTP status code
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if proc.returncode != 0 or not stdout:
            return None
        raw = stdout.decode("utf-8", errors="replace")
        # Extract status code from the last line
        lines = raw.rsplit("\n", 1)
        if len(lines) == 2:
            body, status_str = lines
            try:
                status_code = int(status_str.strip())
            except ValueError:
                body = raw
                status_code = 0
        else:
            body = raw
            status_code = 0
        # Only analyze content from successful HTTP responses
        if status_code != 200:
            logger.debug(f"js_analyzer: skipping {url} (HTTP {status_code})")
            return None
        return body if body else None
    except Exception as _exc:
        logger.debug(f"js analyzer error: {_exc}")
    return None


def _extract_endpoints(js_content: str, base_url: str) -> list[dict[str, str]]:
    """Extract API endpoints from JS content."""
    endpoints: list[dict[str, str]] = []
    seen: set[str] = set()

    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_content):
            path = match.group(1) if match.lastindex else match.group(0)
            path = path.strip("\"'`")
            if not path or path in seen or len(path) < 3:
                continue
            # Skip common false positives
            if path in ("/", "//", "/.", "/#", "/index", "/favicon.ico"):
                continue
            if re.match(r"^/[a-z]+\.(css|png|jpg|gif|svg|ico|woff|ttf|eot)$", path, re.I):
                continue
            seen.add(path)
            full_url = urljoin(base_url, path) if path.startswith("/") else path
            endpoints.append({"path": path, "url": full_url})

    return endpoints[:50]  # Cap at 50 per JS file


def _detect_secrets(js_content: str, js_url: str) -> list[Finding]:
    """Detect hardcoded secrets in JS content."""
    findings: list[Finding] = []
    seen: set[str] = set()

    # ── Known-safe public frontend key patterns ──
    # These are intentionally exposed in client-side JS (by design)
    _PUBLIC_KEY_INDICATORS = (
        "amplitude", "contentful", "segment", "mixpanel", "intercom",
        "sentry", "bugsnag", "datadog", "newrelic", "googletagmanager",
        "gtm-", "analytics", "gtag", "pixel", "tracking",
        "cdn.contentful.com", "cdn.amplitude.com",
        # Maps & geocoding (public browser keys)
        "maps.googleapis.com", "maps/api", "geocode", "places/api",
        "mapbox", "mapkit",
        # reCAPTCHA (always public)
        "recaptcha", "sitekey", "captcha",
        # Public frontend identifiers
        "publishable", "public_key", "pk_test", "pk_live",
    )
    # Password context patterns that indicate form handling, NOT hardcoded creds
    _PASSWORD_FP_INDICATORS = (
        ".concat(", "encodeuri", "encodeuricomponent", "formdata",
        "input", "field", "form", "forgot_", "reset_", "change_",
        "new_password", "confirm_password", "password_confirm",
        ".password)", "e.password", "user.password", "data.password",
        "/forgot", "/reset", "/change", "/login", "/signup", "/register",
        "placeholder", "type=\"password", "autocomplete",
    )

    for name, pattern, severity_str in _SECRET_PATTERNS:
        for match in pattern.finditer(js_content):
            value = match.group(0)[:80]  # Truncate for display
            key = f"{name}:{value[:20]}"
            if key in seen:
                continue
            seen.add(key)

            # Get context (surrounding 100 chars)
            start = max(0, match.start() - 50)
            end = min(len(js_content), match.end() + 50)
            context = js_content[start:end].replace("\n", " ")
            context_lower = context.lower()

            # ── Context-aware false positive filtering ──
            is_fp = False

            # 1. Generic Password: skip form field handling code
            if name == "Generic Password":
                if any(ind in context_lower for ind in _PASSWORD_FP_INDICATORS):
                    is_fp = True
                # Also skip URL-path constants like "/forgot_password"
                matched_val = match.group(1) if match.lastindex else value
                if matched_val.startswith("/") or matched_val.startswith("http"):
                    is_fp = True

            # 2. Generic API Key / Token: skip known public frontend keys
            if name in ("Generic API Key", "Generic Token"):
                if any(ind in context_lower for ind in _PUBLIC_KEY_INDICATORS):
                    is_fp = True

            # 3. Stripe public keys (pk_test_, pk_live_) are intended for frontend
            if name == "Stripe Key" and value.startswith("pk_"):
                is_fp = True

            # 4. Discord Bot Token: validate base64 structure of user-ID segment
            if name == "Discord Bot Token" and not is_fp:
                token_val = match.group(0)
                first_seg = token_val.split(".")[0] if "." in token_val else ""
                try:
                    import base64
                    decoded = base64.b64decode(first_seg + "==").decode("utf-8")
                    # Discord user IDs are numeric snowflakes
                    if not decoded.isdigit():
                        is_fp = True
                except Exception:
                    is_fp = True

            # 5. Google API Key in Maps/reCAPTCHA context (public by design)
            if name == "Google API Key":
                maps_ctx = ("maps", "geocode", "places", "recaptcha",
                            "captcha", "sitekey", "directions", "elevation")
                if any(ind in context_lower for ind in maps_ctx):
                    is_fp = True

            # 6. Mapbox public tokens (pk.* are intentionally public)
            if name == "Mapbox Token":
                is_fp = True  # pk.* mapbox tokens are always public

            if is_fp:
                continue

            severity = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
            }.get(severity_str, SeverityLevel.MEDIUM)

            findings.append(Finding(
                title=f"Hardcoded {name} in JavaScript",
                description=(
                    f"Found potential {name} hardcoded in JavaScript file.\n"
                    f"File: {js_url}\n"
                    f"Context: ...{context}..."
                ),
                vulnerability_type="information_disclosure",
                severity=severity,
                confidence=70.0 if severity_str in ("critical", "high") else 55.0,
                target=urlparse(js_url).netloc,
                endpoint=js_url,
                tool_name="js_analyzer",
                tags=["javascript", "secrets", name.lower().replace(" ", "_")],
                evidence=f"Pattern: {name}\nMatch: {value}\nFile: {js_url}",
                cwe_id="CWE-798",
            ))

    return findings[:20]  # Cap findings per file


def _detect_cloud_urls(js_content: str, js_url: str) -> list[Finding]:
    """Detect cloud service URLs in JS content."""
    findings: list[Finding] = []
    seen: set[str] = set()

    for name, pattern in _CLOUD_PATTERNS:
        for match in pattern.finditer(js_content):
            url = match.group(0)
            if url in seen:
                continue
            seen.add(url)
            findings.append(Finding(
                title=f"Cloud Service URL ({name}) in JavaScript",
                description=(
                    f"Found {name} URL in JavaScript file.\n"
                    f"URL: {url}\nFile: {js_url}\n"
                    f"This may expose cloud infrastructure details."
                ),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.LOW,
                confidence=60.0,
                target=urlparse(js_url).netloc,
                endpoint=js_url,
                tool_name="js_analyzer",
                tags=["javascript", "cloud", name.lower().replace(" ", "_")],
                evidence=f"Cloud URL: {url}\nFile: {js_url}",
                cwe_id="CWE-200",
            ))

    return findings[:10]


# ── Source Map Detection (T3-1) ─────────────────────────────────

_SOURCEMAP_URL_RE = re.compile(r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)""")


async def _check_source_map(js_url: str, js_content: str, timeout: float = 8.0) -> list[Finding]:
    """Detect & probe source map files which can expose original source code."""
    findings: list[Finding] = []
    map_urls: list[str] = []

    # 1. Check inline sourceMappingURL comment
    m = _SOURCEMAP_URL_RE.search(js_content)
    if m:
        raw = m.group(1).strip()
        if not raw.startswith("data:"):  # skip inline base64 maps
            map_urls.append(urljoin(js_url, raw))

    # 2. Try conventional .map suffix
    if js_url.endswith((".js", ".mjs", ".jsx")):
        map_urls.append(js_url + ".map")

    seen: set[str] = set()
    for map_url in map_urls:
        if map_url in seen:
            continue
        seen.add(map_url)
        # v4.0: Skip third-party source maps (not our target's code)
        if _is_third_party_js(map_url):
            continue
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sSL", "-o", "/dev/null", "-w", "%{http_code}",
                "-m", str(int(timeout)),
                "-H", "User-Agent: Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)",
                "--max-filesize", "5242880",
                map_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
            status = stdout.decode().strip() if stdout else ""
            if status == "200":
                # Context-aware severity: marketing JS source maps are lower risk
                _MARKETING_JS = (
                    "analytics", "tracking", "gtm", "pixel", "segment",
                    "hotjar", "clarity", "tag-manager", "marketing",
                    "ads", "campaign", "cdn.segment", "cdn.mxpnl",
                )
                _map_lower = map_url.lower()
                _js_lower = js_url.lower()
                _is_marketing = any(
                    mk in _map_lower or mk in _js_lower
                    for mk in _MARKETING_JS
                )
                _sm_severity = SeverityLevel.LOW if _is_marketing else SeverityLevel.MEDIUM
                _sm_confidence = 55.0 if _is_marketing else 85.0
                findings.append(Finding(
                    title="JavaScript Source Map Exposed",
                    description=(
                        f"A JavaScript source map file is publicly accessible.\n"
                        f"Source map: {map_url}\n"
                        f"Original JS: {js_url}\n"
                        f"Source maps can expose original unminified source code, "
                        f"internal paths, component names, and developer comments."
                    ),
                    vulnerability_type="information_disclosure",
                    severity=_sm_severity,
                    confidence=_sm_confidence,
                    target=urlparse(js_url).netloc,
                    endpoint=map_url,
                    tool_name="js_analyzer",
                    tags=["javascript", "source_map", "information_disclosure"],
                    evidence=f"HTTP 200 for source map URL: {map_url}",
                    cwe_id="CWE-540",
                ))
        except Exception as _e:
            logger.debug(f"Source map probe failed for {map_url}: {_e}")

    return findings


# ── Environment Config & Webpack Detection (T3-1) ──────────────

_ENV_CONFIG_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Next.js Data", re.compile(r"""window\.__NEXT_DATA__\s*=\s*(\{.{20,}?\})""", re.S)),
    ("Runtime Config", re.compile(r"""window\.(?:__ENV__|__CONFIG__|__APP_CONFIG__|env|config)\s*=\s*(\{.{10,}?\})""", re.I | re.S)),
    ("Process Env Ref", re.compile(r"""process\.env\.([A-Z_]{3,40})""", re.I)),
]

_WEBPACK_CHUNK_RE = re.compile(r"""(?:webpackJsonp|__webpack_require__|__webpack_modules__)""")
_COMMENT_LEAK_RE = re.compile(
    r'(?://|/\*)\s*(?:TODO|FIXME|HACK|BUG|XXX|SECURITY|VULNERABLE|TEMP|DEBUG|WORKAROUND)'
    r'[:\s]+(.{10,100})',
    re.I,
)


def _detect_env_and_webpack(js_content: str, js_url: str) -> list[Finding]:
    """Detect exposed environment config, webpack internals, and dev comments."""
    findings: list[Finding] = []

    # Environment config leaks
    for name, pattern in _ENV_CONFIG_PATTERNS:
        for match in pattern.finditer(js_content):
            value = match.group(1) if match.lastindex else match.group(0)
            # Only report if it looks like config/env reference, not generic code
            if name == "Process Env Ref":
                env_var = value
                # Skip common build-time vars that are expected
                if env_var.upper() in ("NODE_ENV", "PUBLIC_URL", "BASE_URL"):
                    continue
                findings.append(Finding(
                    title=f"Environment Variable Reference in JavaScript ({env_var})",
                    description=(
                        f"Found reference to environment variable `{env_var}` in client-side JS.\n"
                        f"File: {js_url}\n"
                        f"If build process substitutes this, the value may be exposed."
                    ),
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.LOW,
                    confidence=40.0,
                    target=urlparse(js_url).netloc,
                    endpoint=js_url,
                    tool_name="js_analyzer",
                    tags=["javascript", "env_config"],
                    evidence=f"process.env.{env_var} in {js_url}",
                    cwe_id="CWE-200",
                ))
            else:
                truncated = value[:200] + "..." if len(value) > 200 else value
                findings.append(Finding(
                    title=f"Client-Side Configuration Leak ({name})",
                    description=(
                        f"Found {name} object injected into client-side JavaScript.\n"
                        f"File: {js_url}\n"
                        f"Preview: {truncated}\n"
                        f"This may contain API endpoints, feature flags, or internal config."
                    ),
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.LOW,
                    confidence=50.0,
                    target=urlparse(js_url).netloc,
                    endpoint=js_url,
                    tool_name="js_analyzer",
                    tags=["javascript", "env_config", name.lower().replace(" ", "_")],
                    evidence=f"{name}: {truncated}\nFile: {js_url}",
                    cwe_id="CWE-200",
                ))

    # Webpack chunk detection (indicates bundled app — potential for deeper analysis)
    if _WEBPACK_CHUNK_RE.search(js_content):
        # Only informational — helps prioritize this JS for deeper analysis
        logger.debug(f"js_analyzer: Webpack bundle detected in {js_url}")

    # Developer comment leaks
    for match in _COMMENT_LEAK_RE.finditer(js_content):
        comment = match.group(1).strip()
        # Only report comments that hint at security issues
        sec_keywords = ("password", "secret", "key", "token", "auth", "vuln",
                        "hack", "bypass", "insecure", "danger", "credential")
        if any(kw in comment.lower() for kw in sec_keywords):
            findings.append(Finding(
                title="Security-Relevant Developer Comment in JavaScript",
                description=(
                    f"Found a developer comment that may indicate a security concern.\n"
                    f"File: {js_url}\n"
                    f"Comment: {comment}"
                ),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.LOW,
                confidence=35.0,
                target=urlparse(js_url).netloc,
                endpoint=js_url,
                tool_name="js_analyzer",
                tags=["javascript", "developer_comment"],
                evidence=f"Comment: {comment}\nFile: {js_url}",
                cwe_id="CWE-615",
            ))

    return findings[:10]


# ── Entropy-Based Secret Detection (P4-4) ──────────────────────

# Regex to find assignment-style strings that could be secrets
_ENTROPY_CANDIDATE_RE = re.compile(
    r"""(?:['"]([A-Za-z0-9_\-/+=]{20,120})['"]\s*)"""
)

# Patterns to EXCLUDE from entropy analysis (known non-secret high-entropy)
_ENTROPY_EXCLUDES = (
    "data:image/", "data:application/", "sha256-", "sha384-", "sha512-",
    "integrity=", "sourceMappingURL", "webpack", "webpackChunk",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",  # alphabet runs
)

# Context keywords that indicate the string is a secret
_SECRET_CONTEXT_RE = re.compile(
    r"(?:key|token|secret|password|credential|auth|apikey|api_key|"
    r"access_key|private|signing|encryption|hmac|bearer)\s*[:=]",
    re.IGNORECASE,
)


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
        if c > 0
    )


def _detect_high_entropy_secrets(
    js_content: str,
    js_url: str,
) -> list[Finding]:
    """Find high-entropy strings that may be undiscovered API keys or tokens."""
    findings: list[Finding] = []
    seen: set[str] = set()

    for match in _ENTROPY_CANDIDATE_RE.finditer(js_content):
        value = match.group(1)
        if not value or len(value) < 20 or value in seen:
            continue

        # Skip known non-secret patterns
        if any(exc in value for exc in _ENTROPY_EXCLUDES):
            continue

        # Skip if mostly numeric (version numbers, timestamps, etc.)
        digit_ratio = sum(1 for c in value if c.isdigit()) / len(value)
        if digit_ratio > 0.8:
            continue

        entropy = _shannon_entropy(value)

        # High-entropy threshold: 4.5 bits/char for general, 4.0 with context
        start = max(0, match.start() - 80)
        end = min(len(js_content), match.end() + 30)
        context = js_content[start:end].replace("\n", " ")

        has_secret_context = bool(_SECRET_CONTEXT_RE.search(context))
        threshold = 4.0 if has_secret_context else 4.5

        if entropy >= threshold:
            seen.add(value)
            truncated = value[:40] + "..." if len(value) > 40 else value
            confidence = 55.0 if has_secret_context else 35.0
            severity = SeverityLevel.MEDIUM if has_secret_context else SeverityLevel.LOW

            findings.append(Finding(
                title="High-Entropy String in JavaScript (Potential Secret)",
                description=(
                    f"Found a high-entropy string that may be an undiscovered "
                    f"API key, token, or credential.\n"
                    f"File: {js_url}\n"
                    f"Entropy: {entropy:.2f} bits/char\n"
                    f"Value: {truncated}\n"
                    f"Context: ...{context.strip()[:150]}..."
                ),
                vulnerability_type="information_disclosure",
                severity=severity,
                confidence=confidence,
                target=urlparse(js_url).netloc,
                endpoint=js_url,
                tool_name="js_analyzer",
                tags=["javascript", "entropy", "potential_secret"],
                evidence=(
                    f"Entropy: {entropy:.2f} bits/char | "
                    f"Value: {truncated} | File: {js_url}"
                ),
                cwe_id="CWE-798",
            ))

    return findings[:8]  # Cap: high-entropy can be noisy


# ── DOM XSS Sink/Source Detection (P4-4) ────────────────────────

_DOM_SOURCES = [
    "document.URL", "document.documentURI", "document.referrer",
    "document.baseURI", "location.href", "location.search",
    "location.hash", "location.pathname", "window.name",
    "document.cookie", "postMessage",
]

_DOM_SINKS = [
    "document.write", "document.writeln",
    ".innerHTML", ".outerHTML", ".insertAdjacentHTML",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "execScript(", ".src=", ".href=", ".action=",
    "jQuery.html(", "$.html(", ".append(",
]


def _detect_dom_xss_patterns(
    js_content: str,
    js_url: str,
) -> list[Finding]:
    """Detect potential DOM XSS by finding source→sink data flows."""
    findings: list[Finding] = []
    content_lower = js_content.lower()

    found_sources: list[str] = [
        s for s in _DOM_SOURCES if s.lower() in content_lower
    ]
    found_sinks: list[str] = [
        s for s in _DOM_SINKS if s.lower() in content_lower
    ]

    if found_sources and found_sinks:
        # Check for proximity: source and sink within 500 chars
        for source in found_sources[:5]:
            source_positions = [
                m.start() for m in re.finditer(re.escape(source), js_content, re.I)
            ]
            for sink in found_sinks[:5]:
                sink_positions = [
                    m.start() for m in re.finditer(re.escape(sink), js_content, re.I)
                ]
                for sp in source_positions[:3]:
                    for sk in sink_positions[:3]:
                        dist = abs(sk - sp)
                        if dist < 500:
                            start = min(sp, sk)
                            end = max(sp, sk) + len(sink) + 20
                            snippet = js_content[start:min(end, start + 200)]
                            findings.append(Finding(
                                title=f"Potential DOM XSS: {source} → {sink}",
                                description=(
                                    f"JavaScript file contains a DOM XSS source "
                                    f"({source}) near a dangerous sink ({sink}).\n"
                                    f"File: {js_url}\n"
                                    f"Snippet: {snippet[:200]}\n"
                                    f"Manual verification required — this is a "
                                    f"static pattern match, not a confirmed flow."
                                ),
                                vulnerability_type="xss_dom",
                                severity=SeverityLevel.MEDIUM,
                                confidence=40.0,
                                target=urlparse(js_url).netloc,
                                endpoint=js_url,
                                tool_name="js_analyzer",
                                tags=["javascript", "dom_xss", "source_sink"],
                                evidence=(
                                    f"Source: {source} | Sink: {sink} | "
                                    f"Distance: {dist} chars | File: {js_url}"
                                ),
                                cwe_id="CWE-79",
                                needs_verification=True,
                            ))
                            if len(findings) >= 5:
                                return findings

    return findings


async def analyze_javascript_files(
    urls: list[str],
    max_concurrent: int = 5,
    max_files: int = 30,
    timeout: float = 10.0,
) -> tuple[list[Finding], list[dict[str, str]]]:
    """
    Analyze JavaScript files for secrets and endpoints.

    Args:
        urls: List of all collected URLs (JS files will be filtered)
        max_concurrent: Maximum concurrent HTTP requests
        max_files: Maximum JS files to analyze
        timeout: Per-file fetch timeout

    Returns:
        Tuple of (findings, discovered_endpoints)
    """
    # Filter JS file URLs
    js_urls: list[str] = []
    skipped_third_party = 0
    seen: set[str] = set()
    for url in urls:
        if not url or not isinstance(url, str):
            continue
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        if path_lower.endswith((".js", ".mjs", ".jsx")) and url not in seen:
            seen.add(url)
            if _is_third_party_js(url):
                skipped_third_party += 1
                continue
            js_urls.append(url)

    if skipped_third_party:
        logger.debug(f"js_analyzer: Skipped {skipped_third_party} third-party JS files")

    if not js_urls:
        logger.debug("js_analyzer: No JavaScript files found in URLs")
        return [], []

    # Prioritize interesting filenames
    priority_keywords = ["app", "main", "bundle", "vendor", "config", "auth",
                         "api", "admin", "login", "dashboard", "util", "service"]

    def sort_key(url: str) -> int:
        path = urlparse(url).path.lower()
        for i, kw in enumerate(priority_keywords):
            if kw in path:
                return i
        return len(priority_keywords)

    js_urls.sort(key=sort_key)
    js_urls = js_urls[:max_files]

    logger.info(f"js_analyzer: Analyzing {len(js_urls)} JavaScript files")

    all_findings: list[Finding] = []
    all_endpoints: list[dict[str, str]] = []
    sem = asyncio.Semaphore(max_concurrent)

    async def process_one(js_url: str) -> None:
        async with sem:
            content = await _fetch_js(js_url, timeout)
            if not content or len(content) < 50:
                return

            # Extract endpoints
            endpoints = _extract_endpoints(content, js_url)
            all_endpoints.extend(endpoints)

            # Detect secrets
            secret_findings = _detect_secrets(content, js_url)
            all_findings.extend(secret_findings)

            # Detect cloud URLs
            cloud_findings = _detect_cloud_urls(content, js_url)
            all_findings.extend(cloud_findings)

            # T3-1: Source map detection
            map_findings = await _check_source_map(js_url, content, timeout)
            all_findings.extend(map_findings)

            # T3-1: Environment config & webpack detection
            env_findings = _detect_env_and_webpack(content, js_url)
            all_findings.extend(env_findings)

            # P4-4: Entropy-based secret detection
            entropy_findings = _detect_high_entropy_secrets(content, js_url)
            all_findings.extend(entropy_findings)

            # P4-4: DOM XSS sink/source detection
            domxss_findings = _detect_dom_xss_patterns(content, js_url)
            all_findings.extend(domxss_findings)

            total = (len(secret_findings) + len(cloud_findings)
                     + len(map_findings) + len(env_findings)
                     + len(entropy_findings) + len(domxss_findings))
            if endpoints or total:
                logger.info(
                    f"js_analyzer: {js_url} → "
                    f"{len(endpoints)} endpoints, "
                    f"{total} findings"
                )

    tasks = [process_one(url) for url in js_urls]
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info(
        f"js_analyzer: Complete — "
        f"{len(all_findings)} findings, "
        f"{len(all_endpoints)} endpoints from {len(js_urls)} JS files"
    )

    return all_findings, all_endpoints


__all__ = ["analyze_javascript_files"]
