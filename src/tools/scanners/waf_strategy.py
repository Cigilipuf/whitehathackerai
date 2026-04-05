"""
WhiteHatHacker AI — WAF Fingerprinting & Adaptive Strategy Selection (V6-T2-1)

Detects WAFs from HTTP response signatures, then selects
appropriate bypass / evasion strategies for payload delivery.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from src.fp_engine.patterns.waf_artifacts import WAF_FINGERPRINTS


# ====================================================================
# Data model
# ====================================================================

@dataclass
class WAFResult:
    """Result of WAF fingerprinting for a host."""

    host: str
    detected: bool = False
    waf_name: str = ""
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    strategy: WAFStrategy | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict for checkpoint persistence."""
        return {
            "host": self.host,
            "detected": self.detected,
            "waf_name": self.waf_name,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "strategy": self.strategy.to_dict() if self.strategy else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WAFResult:
        """Reconstruct from dict (e.g., after checkpoint resume)."""
        strategy_data = data.get("strategy")
        strategy = WAFStrategy.from_dict(strategy_data) if isinstance(strategy_data, dict) else None
        return cls(
            host=data.get("host", ""),
            detected=data.get("detected", False),
            waf_name=data.get("waf_name", ""),
            confidence=data.get("confidence", 0.0),
            evidence=list(data.get("evidence", [])),
            strategy=strategy,
        )


@dataclass
class WAFStrategy:
    """Evasion strategy selected for a specific WAF."""

    waf_name: str
    encoding_chain: list[str] = field(default_factory=list)
    rate_adjustment: float = 1.0          # multiplier: <1 = slower
    header_tweaks: dict[str, str] = field(default_factory=dict)
    payload_transforms: list[str] = field(default_factory=list)
    nuclei_rate: int | None = None        # override nuclei -rl
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict for checkpoint persistence."""
        return {
            "waf_name": self.waf_name,
            "encoding_chain": list(self.encoding_chain),
            "rate_adjustment": self.rate_adjustment,
            "header_tweaks": dict(self.header_tweaks),
            "payload_transforms": list(self.payload_transforms),
            "nuclei_rate": self.nuclei_rate,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WAFStrategy:
        """Reconstruct from dict (e.g., after checkpoint resume)."""
        return cls(
            waf_name=data.get("waf_name", ""),
            encoding_chain=list(data.get("encoding_chain", [])),
            rate_adjustment=data.get("rate_adjustment", 1.0),
            header_tweaks=dict(data.get("header_tweaks", {})),
            payload_transforms=list(data.get("payload_transforms", [])),
            nuclei_rate=data.get("nuclei_rate"),
            notes=data.get("notes", ""),
        )


# ====================================================================
# Per-WAF strategy profiles (inline; could be YAML-ized later)
# ====================================================================

_STRATEGIES: dict[str, WAFStrategy] = {
    "cloudflare": WAFStrategy(
        waf_name="cloudflare",
        encoding_chain=["unicode_normalize", "chunked_transfer"],
        rate_adjustment=0.5,
        header_tweaks={
            "X-Forwarded-For": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
        },
        payload_transforms=[
            "unicode_normalization",    # Cf normalizes Unicode → use confusables
            "chunked_encoding",         # Split payload across chunks
            "case_randomize",           # ScRiPt vs SCRIPT
            "double_url_encode",        # %253C etc.
            "html_entity_mix",          # &#x3C; + literal
        ],
        nuclei_rate=15,
        notes="Cloudflare: slow rate + Unicode tricks + chunked TE",
    ),
    "akamai": WAFStrategy(
        waf_name="akamai",
        encoding_chain=["slow_rate", "session_rotate"],
        rate_adjustment=0.3,
        header_tweaks={
            "X-Forwarded-For": "127.0.0.1",
        },
        payload_transforms=[
            "slow_rate_delivery",
            "session_rotation",
            "comment_insertion",         # /**/
            "whitespace_variation",      # tab/newline between tokens
        ],
        nuclei_rate=10,
        notes="Akamai: very slow rate + rotate cookies/sessions",
    ),
    "aws_waf": WAFStrategy(
        waf_name="aws_waf",
        encoding_chain=["path_normalize", "url_encode"],
        rate_adjustment=0.6,
        header_tweaks={},
        payload_transforms=[
            "path_normalization",        # /./  /../  //
            "url_encode_selective",       # encode only trigger chars
            "case_randomize",
            "null_byte_insertion",        # %00 between keywords
        ],
        nuclei_rate=20,
        notes="AWS WAF: path normalization tricks + selective encoding",
    ),
    "modsecurity": WAFStrategy(
        waf_name="modsecurity",
        encoding_chain=["comment_inject", "case_mix"],
        rate_adjustment=0.7,
        header_tweaks={},
        payload_transforms=[
            "sql_comment_injection",     # /*!50000UNION*/
            "inline_comment",            # un/**/ion
            "case_randomize",
            "concat_bypass",             # CONCAT(0x..) vs literal
            "whitespace_variation",
        ],
        nuclei_rate=25,
        notes="ModSecurity: SQL inline comments + case mixing",
    ),
    "imperva_incapsula": WAFStrategy(
        waf_name="imperva_incapsula",
        encoding_chain=["session_cookie", "slow_rate"],
        rate_adjustment=0.4,
        header_tweaks={
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
        },
        payload_transforms=[
            "session_cookie_rotation",
            "unicode_normalization",
            "double_url_encode",
            "chunked_encoding",
        ],
        nuclei_rate=10,
        notes="Imperva: session rotation + double-encode + chunked",
    ),
    "f5_big_ip": WAFStrategy(
        waf_name="f5_big_ip",
        encoding_chain=["url_encode", "case_mix"],
        rate_adjustment=0.6,
        header_tweaks={},
        payload_transforms=[
            "url_encode_selective",
            "case_randomize",
            "whitespace_variation",
        ],
        nuclei_rate=20,
        notes="F5 BIG-IP: encoding + case variation",
    ),
    "sucuri": WAFStrategy(
        waf_name="sucuri",
        encoding_chain=["double_encode", "case_mix"],
        rate_adjustment=0.5,
        header_tweaks={},
        payload_transforms=[
            "double_url_encode",
            "case_randomize",
            "html_entity_mix",
            "comment_insertion",
        ],
        nuclei_rate=15,
        notes="Sucuri: double URL encoding + HTML entity mixing",
    ),
    "wordfence": WAFStrategy(
        waf_name="wordfence",
        encoding_chain=["slow_rate", "encoding_chain"],
        rate_adjustment=0.5,
        header_tweaks={},
        payload_transforms=[
            "url_encode_selective",
            "case_randomize",
            "null_byte_insertion",
        ],
        nuclei_rate=15,
        notes="Wordfence: slow + encoding tricks",
    ),
}

# Fallback for unknown WAFs
_DEFAULT_STRATEGY = WAFStrategy(
    waf_name="unknown",
    encoding_chain=["url_encode", "case_mix"],
    rate_adjustment=0.7,
    header_tweaks={},
    payload_transforms=[
        "url_encode_selective",
        "case_randomize",
        "whitespace_variation",
    ],
    nuclei_rate=20,
    notes="Unknown WAF: conservative default strategy",
)


# ====================================================================
# Fingerprinting engine
# ====================================================================

async def fingerprint_waf(
    host: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    body: str = "",
    status_code: int = 200,
) -> WAFResult:
    """Fingerprint WAF from a single HTTP response.

    Args:
        host: Target hostname.
        headers: Response headers (lowercase keys).
        cookies: Response cookies.
        body: Response body text.
        status_code: HTTP status code.

    Returns:
        WAFResult with detection info and selected strategy.
    """
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    cookies = cookies or {}
    body_lower = body.lower()

    best_match = ""
    best_score = 0.0
    best_evidence: list[str] = []

    for waf_name, sigs in WAF_FINGERPRINTS.items():
        score = 0.0
        evidence: list[str] = []

        # Header match
        for h in sigs.get("headers", []):
            h_lower = h.lower()
            if ":" in h_lower:
                key, val = h_lower.split(":", 1)
                if key.strip() in headers and val.strip() in headers[key.strip()].lower():
                    score += 25
                    evidence.append(f"header match: {h}")
            elif h_lower in headers:
                score += 20
                evidence.append(f"header present: {h}")

        # Cookie match
        for c in sigs.get("cookies", []):
            for cookie_name in cookies:
                if c.lower() in cookie_name.lower():
                    score += 15
                    evidence.append(f"cookie match: {c}")
                    break

        # Body pattern match
        for pat in sigs.get("body_patterns", []):
            if pat.lower() in body_lower:
                score += 20
                evidence.append(f"body pattern: {pat}")

        # Status code match
        if status_code in sigs.get("status_codes", []):
            score += 10
            evidence.append(f"status code {status_code} matches")

        # Block indicator match (strong signal)
        for ind in sigs.get("block_indicators", []):
            if ind.lower() in body_lower:
                score += 30
                evidence.append(f"block indicator: {ind}")

        if score > best_score:
            best_score = score
            best_match = waf_name
            best_evidence = evidence

    if best_score >= 20:
        confidence = min(best_score / 100, 1.0)
        strategy = _STRATEGIES.get(best_match, _DEFAULT_STRATEGY)
        result = WAFResult(
            host=host,
            detected=True,
            waf_name=best_match,
            confidence=confidence,
            evidence=best_evidence,
            strategy=strategy,
        )
        logger.info(
            "WAF detected: {} (confidence={:.0%}) on {}",
            best_match, confidence, host,
        )
        return result

    return WAFResult(host=host)


async def fingerprint_waf_wafw00f(host: str) -> WAFResult:
    """Run wafw00f external tool if available.

    Falls back to empty result if wafw00f is not installed.
    """
    if not shutil.which("wafw00f"):
        logger.debug("wafw00f not installed, skipping external WAF detection for {}", host)
        return WAFResult(host=host)

    try:
        url = host if host.startswith("http") else f"https://{host}"
        proc = await asyncio.create_subprocess_exec(
            "wafw00f", url, "-o", "-",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode(errors="replace")

        # Parse wafw00f output: looks for "is behind <WAF>" pattern
        m = re.search(r"is behind\s+(.+?)(?:\s+WAF)?$", output, re.MULTILINE | re.IGNORECASE)
        if m:
            waf_name_raw = m.group(1).strip().lower()
            # Map to our known names
            name_map = {
                "cloudflare": "cloudflare",
                "akamai": "akamai",
                "aws": "aws_waf",
                "amazon": "aws_waf",
                "imperva": "imperva_incapsula",
                "incapsula": "imperva_incapsula",
                "f5": "f5_big_ip",
                "big-ip": "f5_big_ip",
                "sucuri": "sucuri",
                "modsecurity": "modsecurity",
                "wordfence": "wordfence",
                "barracuda": "barracuda",
            }
            matched = ""
            for key, val in name_map.items():
                if key in waf_name_raw:
                    matched = val
                    break
            if matched:
                strategy = _STRATEGIES.get(matched, _DEFAULT_STRATEGY)
                return WAFResult(
                    host=host,
                    detected=True,
                    waf_name=matched,
                    confidence=0.85,
                    evidence=[f"wafw00f detected: {waf_name_raw}"],
                    strategy=strategy,
                )
    except (asyncio.TimeoutError, OSError) as exc:
        logger.debug("wafw00f failed for {}: {}", host, exc)

    return WAFResult(host=host)


async def detect_waf(
    host: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    body: str = "",
    status_code: int = 200,
    use_wafw00f: bool = True,
) -> WAFResult:
    """Combined WAF detection: response analysis + optional wafw00f.

    Merges results, picking the higher-confidence detection.
    """
    # Response-based detection
    response_result = await fingerprint_waf(host, headers, cookies, body, status_code)

    # Optionally run wafw00f
    wafw00f_result = WAFResult(host=host)
    if use_wafw00f and not response_result.detected:
        wafw00f_result = await fingerprint_waf_wafw00f(host)

    # Merge: pick highest confidence
    if wafw00f_result.detected and wafw00f_result.confidence > response_result.confidence:
        return wafw00f_result
    if response_result.detected:
        return response_result

    return WAFResult(host=host)


def get_strategy(waf_name: str) -> WAFStrategy:
    """Get bypass strategy for a known WAF name."""
    return _STRATEGIES.get(waf_name, _DEFAULT_STRATEGY)


def apply_rate_adjustment(base_rate: int, waf_result: WAFResult) -> int:
    """Adjust scan rate based on WAF detection.

    Returns adjusted rate (requests per second).
    """
    if not waf_result.detected or not waf_result.strategy:
        return base_rate
    adjusted = max(1, int(base_rate * waf_result.strategy.rate_adjustment))
    if waf_result.strategy.nuclei_rate:
        adjusted = min(adjusted, waf_result.strategy.nuclei_rate)
    return adjusted


# ====================================================================
# Payload transformation engine (P4-3: WAF Bypass Intelligence Loop)
# ====================================================================

import html
import urllib.parse


def _double_url_encode(payload: str) -> str:
    """Apply double URL encoding to special characters."""
    first = urllib.parse.quote(payload, safe="")
    return urllib.parse.quote(first, safe="")


def _case_randomize(payload: str) -> str:
    """Randomize case of alphabetic characters."""
    result: list[str] = []
    for i, ch in enumerate(payload):
        result.append(ch.upper() if i % 2 == 0 else ch.lower())
    return "".join(result)


def _unicode_normalize(payload: str) -> str:
    """Replace ASCII chars with Unicode confusables."""
    _CONFUSABLES = {
        "<": "\uff1c", ">": "\uff1e", "'": "\u2019", '"': "\u201c",
        "/": "\u2215", "(": "\uff08", ")": "\uff09",
    }
    return "".join(_CONFUSABLES.get(c, c) for c in payload)


def _html_entity_mix(payload: str) -> str:
    """Mix HTML entities with literal chars (encode every other special)."""
    specials = set("<>\"'&/")
    result: list[str] = []
    toggle = False
    for ch in payload:
        if ch in specials:
            toggle = not toggle
            result.append(f"&#{ord(ch)};" if toggle else ch)
        else:
            result.append(ch)
    return "".join(result)


def _url_encode_selective(payload: str) -> str:
    """URL-encode only SQL/XSS trigger characters."""
    triggers = set("<>'\"();/\\= ")
    return "".join(urllib.parse.quote(c) if c in triggers else c for c in payload)


def _sql_comment_injection(payload: str) -> str:
    """Insert SQL inline comments between keywords."""
    import re as _re
    keywords = ("SELECT", "UNION", "INSERT", "UPDATE", "DELETE",
                "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING")
    pattern = "|".join(keywords)
    return _re.sub(
        f"({pattern})",
        lambda m: f"/*!{m.group(1)}*/",
        payload,
        flags=_re.IGNORECASE,
    )


def _inline_comment(payload: str) -> str:
    """Break keywords with inline comments: union → un/**/ion."""
    import re as _re
    keywords = ["union", "select", "from", "where", "and", "or", "script", "alert", "onerror"]
    result = payload
    for kw in keywords:
        if len(kw) >= 4:
            mid = len(kw) // 2
            broken = kw[:mid] + "/**/" + kw[mid:]
            result = _re.sub(kw, broken, result, flags=_re.IGNORECASE, count=1)
    return result


def _null_byte_insertion(payload: str) -> str:
    """Insert %00 between trigger characters."""
    triggers = set("<>'\"();")
    result: list[str] = []
    for ch in payload:
        if ch in triggers:
            result.append("%00")
        result.append(ch)
    return "".join(result)


def _whitespace_variation(payload: str) -> str:
    """Replace spaces with alternative whitespace."""
    alternatives = ["\t", "\n", "\r\n", "/**/", "+", "%09", "%0a"]
    result = payload
    idx = 0
    while " " in result:
        result = result.replace(" ", alternatives[idx % len(alternatives)], 1)
        idx += 1
    return result


def _chunked_encoding(payload: str) -> str:
    """Simulate chunked transfer encoding split (for display/logging)."""
    if len(payload) <= 4:
        return payload
    mid = len(payload) // 2
    return payload[:mid] + "\\r\\n" + payload[mid:]


# Map transform name → function
_TRANSFORM_FUNCS: dict[str, Any] = {
    "double_url_encode": _double_url_encode,
    "case_randomize": _case_randomize,
    "unicode_normalization": _unicode_normalize,
    "unicode_normalize": _unicode_normalize,
    "html_entity_mix": _html_entity_mix,
    "url_encode_selective": _url_encode_selective,
    "sql_comment_injection": _sql_comment_injection,
    "inline_comment": _inline_comment,
    "null_byte_insertion": _null_byte_insertion,
    "whitespace_variation": _whitespace_variation,
    "chunked_encoding": _chunked_encoding,
    "comment_insertion": _inline_comment,
    "concat_bypass": _sql_comment_injection,
}


def transform_payload(payload: str, transform_name: str) -> str:
    """Apply a named payload transformation.

    Returns original payload if transform is unknown.
    """
    func = _TRANSFORM_FUNCS.get(transform_name)
    if func:
        try:
            return func(payload)
        except Exception as exc:
            logger.debug(f"Transform {transform_name} failed: {exc}")
    return payload


def generate_bypass_variants(
    payload: str,
    waf_result: WAFResult,
    max_variants: int = 5,
) -> list[str]:
    """Generate WAF bypass variants of a payload using the detected WAF's strategy.

    Args:
        payload: Original payload string.
        waf_result: WAF detection result with strategy.
        max_variants: Maximum variants to generate.

    Returns:
        List of transformed payloads (original NOT included).
    """
    if not waf_result.detected or not waf_result.strategy:
        return []

    transforms = waf_result.strategy.payload_transforms
    if not transforms:
        return []

    variants: list[str] = []
    seen: set[str] = {payload}

    # Single transforms
    for tname in transforms:
        if len(variants) >= max_variants:
            break
        variant = transform_payload(payload, tname)
        if variant not in seen:
            seen.add(variant)
            variants.append(variant)

    # Double transforms (combine pairs) if we still have room
    if len(variants) < max_variants and len(transforms) >= 2:
        for i in range(len(transforms)):
            if len(variants) >= max_variants:
                break
            for j in range(len(transforms)):
                if i == j or len(variants) >= max_variants:
                    continue
                v = transform_payload(payload, transforms[i])
                v = transform_payload(v, transforms[j])
                if v not in seen:
                    seen.add(v)
                    variants.append(v)

    logger.debug(
        f"Generated {len(variants)} bypass variants for "
        f"WAF={waf_result.waf_name}"
    )
    return variants


_BLOCK_STATUS_CODES = frozenset({403, 406, 429, 503})
_BLOCK_BODY_PATTERNS = [
    re.compile(r"access denied|blocked|forbidden|waf|firewall", re.I),
    re.compile(r"cloudflare|akamai|imperva|sucuri|wordfence", re.I),
    re.compile(r"security.check|captcha|challenge", re.I),
]


def is_waf_blocked(status_code: int, body: str = "") -> bool:
    """Heuristic check if a response looks like a WAF block."""
    if status_code in _BLOCK_STATUS_CODES:
        return True
    body_lower = body[:2000].lower()
    return any(p.search(body_lower) for p in _BLOCK_BODY_PATTERNS)
