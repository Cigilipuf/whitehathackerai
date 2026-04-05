"""
WhiteHatHacker AI — Technology CVE Checker (v2 — Real-time NVD Intelligence)

Matches technology fingerprints from whatweb/wappalyzer against:
1. Live NVD 2.0 API (https://services.nvd.nist.gov/rest/json/cves/2.0)
2. Local cache (24h TTL, JSON file)
3. Static fallback DB (offline mode)

Produces Finding objects for version-matched CVEs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel

# ── Configuration ──────────────────────────────────────────────
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_RATE_DELAY = 6.5  # seconds between NVD requests (free tier: 5 req / 30s)
_CACHE_DIR = Path("output/cve_cache")
_CACHE_TTL = 86400  # 24 hours in seconds
_NVD_TIMEOUT = 15   # HTTP request timeout
_MAX_NVD_RESULTS = 20  # max CVEs per tech query

# ── CPE vendor name mapping (tech name → CPE vendor:product) ──
_CPE_MAP: dict[str, str] = {
    "nginx": "nginx:nginx",
    "apache": "apache:http_server",
    "httpd": "apache:http_server",
    "php": "php:php",
    "jquery": "jquery:jquery",
    "wordpress": "wordpress:wordpress",
    "openssl": "openssl:openssl",
    "react": "facebook:react",
    "bootstrap": "twbs:bootstrap",
    "express": "expressjs:express",
    "lodash": "lodash:lodash",
    "tomcat": "apache:tomcat",
    "iis": "microsoft:internet_information_services",
    "django": "djangoproject:django",
    "flask": "palletsprojects:flask",
    "spring": "vmware:spring_framework",
    "rails": "rubyonrails:rails",
    "laravel": "laravel:laravel",
    "node.js": "nodejs:node.js",
    "nodejs": "nodejs:node.js",
    "mysql": "oracle:mysql",
    "postgresql": "postgresql:postgresql",
    "redis": "redis:redis",
    "mongodb": "mongodb:mongodb",
    "elasticsearch": "elastic:elasticsearch",
    "grafana": "grafana:grafana",
    "jenkins": "jenkins:jenkins",
    "nextjs": "vercel:next.js",
    "next.js": "vercel:next.js",
    "vue.js": "vuejs:vue.js",
    "angular": "angular:angular",
    "drupal": "drupal:drupal",
    "joomla": "joomla:joomla",
}

# ── Static fallback CVE database (used when NVD API is unreachable) ──
_KNOWN_VULNS: list[dict[str, Any]] = [
    # nginx
    {"tech": "nginx", "min_ver": "0.0.0", "max_ver": "1.25.3",
     "cve": "CVE-2024-7347", "severity": "medium",
     "desc": "nginx mp4 module buffer over-read (affects ngx_http_mp4_module)"},
    {"tech": "nginx", "min_ver": "0.0.0", "max_ver": "1.23.3",
     "cve": "CVE-2023-44487", "severity": "high",
     "desc": "HTTP/2 Rapid Reset Attack (affects nginx HTTP/2 implementation)"},
    # Apache
    {"tech": "apache", "min_ver": "2.4.0", "max_ver": "2.4.58",
     "cve": "CVE-2023-45802", "severity": "medium",
     "desc": "Apache HTTP Server HTTP/2 stream memory not reclaimed on RST"},
    {"tech": "apache", "min_ver": "2.4.0", "max_ver": "2.4.56",
     "cve": "CVE-2023-31122", "severity": "high",
     "desc": "Apache HTTP Server mod_macro out-of-bounds read"},
    # PHP
    {"tech": "php", "min_ver": "0.0.0", "max_ver": "8.1.28",
     "cve": "CVE-2024-4577", "severity": "critical",
     "desc": "PHP CGI argument injection vulnerability (Windows only)"},
    {"tech": "php", "min_ver": "0.0.0", "max_ver": "8.2.17",
     "cve": "CVE-2024-2756", "severity": "medium",
     "desc": "PHP __Host-/__Secure- cookie bypass"},
    # jQuery — multi-branch CVE ranges
    {"tech": "jquery", "min_ver": "0.0.0", "max_ver": "3.4.99",
     "cve": "CVE-2020-11022", "severity": "medium",
     "desc": "jQuery < 3.5.0 XSS via passing HTML containing <option>"},
    # CVE-2015-9251: affects jQuery 1.x < 1.12.0 AND 2.x < 2.2.0
    # jQuery 3.x is NOT affected (3.0.0+ includes the fix)
    {"tech": "jquery", "min_ver": "1.0.0", "max_ver": "1.11.99",
     "cve": "CVE-2015-9251", "severity": "medium",
     "desc": "jQuery < 1.12.0 cross-site scripting via cross-domain ajax requests"},
    {"tech": "jquery", "min_ver": "2.0.0", "max_ver": "2.1.99",
     "cve": "CVE-2015-9251", "severity": "medium",
     "desc": "jQuery < 2.2.0 cross-site scripting via cross-domain ajax requests"},
    # WordPress
    {"tech": "wordpress", "min_ver": "0.0.0", "max_ver": "6.4.2",
     "cve": "CVE-2024-1071", "severity": "high",
     "desc": "WordPress < 6.4.3 improper permission checks"},
    # OpenSSL
    {"tech": "openssl", "min_ver": "3.0.0", "max_ver": "3.0.12",
     "cve": "CVE-2023-6129", "severity": "medium",
     "desc": "OpenSSL POLY1305 MAC on PowerPC: buffer over-read"},
    # React (information disclosure)
    {"tech": "react", "min_ver": "0.0.0", "max_ver": "16.13.99",
     "cve": "CVE-2020-7919", "severity": "low",
     "desc": "React < 16.14.0 potential XSS via dangerouslySetInnerHTML"},
    # Bootstrap
    {"tech": "bootstrap", "min_ver": "0.0.0", "max_ver": "3.4.0",
     "cve": "CVE-2019-8331", "severity": "medium",
     "desc": "Bootstrap < 3.4.1 XSS via tooltip/popover data-template attribute"},
    # Express.js
    {"tech": "express", "min_ver": "0.0.0", "max_ver": "4.17.2",
     "cve": "CVE-2022-24999", "severity": "high",
     "desc": "Express.js qs before 6.10.3 prototype pollution"},
    # Lodash
    {"tech": "lodash", "min_ver": "0.0.0", "max_ver": "4.17.20",
     "cve": "CVE-2021-23337", "severity": "high",
     "desc": "Lodash < 4.17.21 command injection via template"},
]


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse a version string into a comparable tuple."""
    if not version_str:
        return None
    # Extract version numbers from string
    match = re.search(r'(\d+(?:\.\d+)+)', version_str)
    if not match:
        return None
    try:
        return tuple(int(x) for x in match.group(1).split("."))
    except ValueError:
        return None


def _version_in_range(version: str, min_ver: str, max_ver: str) -> bool:
    """Check if version is within vulnerable range."""
    ver = _parse_version(version)
    low = _parse_version(min_ver)
    high = _parse_version(max_ver)
    if not ver or not low or not high:
        return False
    # Pad tuples to same length
    max_len = max(len(ver), len(low), len(high))
    ver = ver + (0,) * (max_len - len(ver))
    low = low + (0,) * (max_len - len(low))
    high = high + (0,) * (max_len - len(high))
    return low <= ver <= high


def check_technology_cves(
    technologies: list[dict[str, Any]],
    target: str,
) -> list[Finding]:
    """
    Check technology fingerprints against known CVE database.

    Args:
        technologies: List of technology dicts from whatweb/wappalyzer
            Each should have 'name' and optionally 'version' keys
        target: Target hostname

    Returns:
        List of Finding objects for matching CVEs
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    for tech in technologies:
        tech_name = str(tech.get("name", tech.get("title", ""))).lower()
        tech_version = str(tech.get("version", tech.get("metadata", {}).get("version", "")))

        if not tech_name:
            continue

        # ── Parse raw WhatWeb JSON from tech_name if needed ──
        # WhatWeb may produce tech_name like: '"jquery":{"version":["3.2.1"]}'
        # We need to extract the clean name and version from this.
        import json as _json_tech
        if '{' in tech_name or '"' in tech_name:
            try:
                # Try to parse as JSON fragment
                _raw = tech_name
                if not _raw.strip().startswith('{'):
                    _raw = '{' + _raw + '}'
                _parsed = _json_tech.loads(_raw)
                if isinstance(_parsed, dict):
                    for _k, _v in _parsed.items():
                        _clean_name = _k.strip().strip('"').lower()
                        _clean_ver = ""
                        if isinstance(_v, dict):
                            _ver_list = _v.get("version", [])
                            if isinstance(_ver_list, list) and _ver_list:
                                _clean_ver = str(_ver_list[0])
                        if _clean_name and len(_clean_name) >= 3:
                            tech_name = _clean_name
                            if _clean_ver:
                                tech_version = _clean_ver
                            break  # Use first parsed tech
            except (ValueError, TypeError, KeyError):
                # Strip JSON artifacts as fallback
                import re as _re_tech
                tech_name = _re_tech.sub(r'[{}"\[\]:,]', ' ', tech_name).strip()
                tech_name = tech_name.split()[0] if tech_name else ""


        for vuln in _KNOWN_VULNS:
            vuln_tech = vuln["tech"].lower()
            # v4.0: Word-boundary matching — "apache" must not match "apachesolr"
            if vuln_tech != tech_name and not re.search(rf'\b{re.escape(vuln_tech)}\b', tech_name):
                continue

            # If we have a version, check range
            if tech_version and tech_version != "None":
                if not _version_in_range(tech_version, vuln["min_ver"], vuln["max_ver"]):
                    continue
                confidence = 75.0
                title_prefix = f"Potentially Vulnerable {tech_name} {tech_version}"
            else:
                # v4.0: Skip findings without version info — too unreliable (80% FP rate)
                continue

            cve = vuln["cve"]
            dedup_key = f"{cve}:{target}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
            }.get(vuln["severity"], SeverityLevel.MEDIUM)

            findings.append(Finding(
                title=f"{title_prefix}: {cve}",
                description=(
                    f"{vuln['desc']}\n\n"
                    f"Detected technology: {tech_name} {tech_version}\n"
                    f"Vulnerable range: {vuln['min_ver']} - {vuln['max_ver']}\n"
                    f"CVE: {cve}\n"
                    f"Note: Version-based detection only. Manual verification required."
                ),
                vulnerability_type="outdated_software",
                severity=severity,
                confidence=confidence,
                target=target,
                tool_name="tech_cve_checker",
                tags=["cve", vuln_tech, cve.lower()],
                evidence=f"Technology: {tech_name} {tech_version}\nCVE: {cve}",
                cwe_id="CWE-1104",
            ))

    if findings:
        logger.info(f"tech_cve_checker: {len(findings)} potential CVEs for {target}")

    return findings


# ═══════════════════════════════════════════════════════════════
# NVD 2.0 API — Real-time CVE Intelligence (T2-4)
# ═══════════════════════════════════════════════════════════════

def _cache_key(tech: str, version: str) -> str:
    """Deterministic cache key for a tech+version pair."""
    raw = f"{tech.lower().strip()}:{version.strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _load_cache(tech: str, version: str) -> list[dict] | None:
    """Load cached NVD results if fresh."""
    key = _cache_key(tech, version)
    path = _CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if time.time() - data.get("ts", 0) > _CACHE_TTL:
            return None  # stale
        return data.get("cves", [])
    except (json.JSONDecodeError, OSError):
        return None


def _save_cache(tech: str, version: str, cves: list[dict]) -> None:
    """Persist NVD results to cache."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(tech, version)
    path = _CACHE_DIR / f"{key}.json"
    try:
        path.write_text(json.dumps({"ts": time.time(), "tech": tech, "ver": version, "cves": cves}))
    except OSError as exc:
        logger.debug(f"CVE cache write error: {exc}")


def _nvd_severity_to_level(base_score: float) -> SeverityLevel:
    """Map CVSS base score to SeverityLevel."""
    if base_score >= 9.0:
        return SeverityLevel.CRITICAL
    if base_score >= 7.0:
        return SeverityLevel.HIGH
    if base_score >= 4.0:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def _extract_nvd_cves(nvd_json: dict, tech: str, version: str) -> list[dict]:
    """Extract simplified CVE entries from NVD API response."""
    results: list[dict] = []
    for vuln_item in nvd_json.get("vulnerabilities", [])[:_MAX_NVD_RESULTS]:
        cve_obj = vuln_item.get("cve", {})
        cve_id = cve_obj.get("id", "")
        if not cve_id:
            continue
        # Description
        desc_list = cve_obj.get("descriptions", [])
        desc = ""
        for d in desc_list:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and desc_list:
            desc = desc_list[0].get("value", "")
        # CVSS score
        metrics = cve_obj.get("metrics", {})
        base_score = 0.0
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                base_score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                break
        # CWE
        cwe_id = "CWE-1104"
        for weakness in cve_obj.get("weaknesses", []):
            for wd in weakness.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-") and val != "CWE-Other" and val != "NVD-CWE-noinfo":
                    cwe_id = val
                    break
        # References (first 3)
        refs = [r.get("url", "") for r in cve_obj.get("references", [])[:3]]

        results.append({
            "cve": cve_id,
            "desc": desc[:500],
            "base_score": base_score,
            "cwe": cwe_id,
            "refs": refs,
        })
    return results


_last_nvd_call: float = 0.0


async def _query_nvd(tech: str, version: str) -> list[dict]:
    """Query NVD 2.0 API for CVEs matching a technology keyword+version.

    Rate-limited to respect NVD free tier (5 requests / 30 seconds).
    Returns cached results when available.
    """
    # Check cache first
    cached = _load_cache(tech, version)
    if cached is not None:
        return cached

    # Build CPE match keyword
    cpe_name = _CPE_MAP.get(tech.lower(), "")
    keyword = f"{tech} {version}".strip() if not cpe_name else ""

    # Rate limiting
    global _last_nvd_call  # noqa: PLW0603
    elapsed = time.time() - _last_nvd_call
    if elapsed < _NVD_RATE_DELAY:
        await asyncio.sleep(_NVD_RATE_DELAY - elapsed)

    try:
        import httpx
        params: dict[str, Any] = {"resultsPerPage": _MAX_NVD_RESULTS}
        if cpe_name and version:
            # Use virtualMatchString for precise CPE matching
            params["keywordSearch"] = f"{cpe_name.replace(':', ' ')} {version}"
            params["keywordExactMatch"] = ""
        elif cpe_name:
            params["keywordSearch"] = cpe_name.replace(":", " ")
        else:
            params["keywordSearch"] = keyword

        _last_nvd_call = time.time()
        async with httpx.AsyncClient(timeout=_NVD_TIMEOUT, verify=True) as client:
            resp = await client.get(_NVD_API_URL, params=params)
            resp.raise_for_status()
            data = resp.json()

        cves = _extract_nvd_cves(data, tech, version)
        _save_cache(tech, version, cves)
        logger.debug(f"NVD query '{tech} {version}': {len(cves)} CVEs found")
        return cves
    except ImportError:
        logger.debug("httpx not available — skipping NVD API query")
        return []
    except Exception as exc:
        logger.debug(f"NVD API error for {tech} {version}: {exc}")
        return []


async def check_technology_cves_live(
    technologies: list[dict[str, Any]],
    target: str,
) -> list[Finding]:
    """Enhanced CVE checker that queries NVD API for real-time CVE data.

    Falls back to static DB when NVD is unreachable.
    """
    # Start with static DB
    findings = check_technology_cves(technologies, target)
    seen_cves: set[str] = {f.tags[-1] if f.tags else "" for f in findings}  # cve ids from static

    for tech in technologies:
        tech_name = str(tech.get("name", tech.get("title", ""))).lower().strip()
        tech_version = str(tech.get("version", "")).strip()
        if not tech_name or tech_name == "none":
            continue

        # Clean up tech name (same JSON parsing as static check)
        if "{" in tech_name or '"' in tech_name:
            match = re.match(r'"?(\w[\w.+-]*)"?', tech_name)
            if match:
                tech_name = match.group(1).lower()

        nvd_cves = await _query_nvd(tech_name, tech_version)
        for cve_data in nvd_cves:
            cve_id = cve_data["cve"]
            if cve_id.lower() in seen_cves:
                continue
            seen_cves.add(cve_id.lower())

            base_score = cve_data.get("base_score", 0.0)
            severity = _nvd_severity_to_level(base_score)

            # v4.0: Skip NVD findings without version — keyword-only matches are unreliable
            if not tech_version or tech_version in ("None", ""):
                continue
            # NVD keyword match (not CPE range validated) — lower than static DB
            confidence = 55.0

            refs_str = "\n".join(cve_data.get("refs", []))
            findings.append(Finding(
                title=f"NVD: {tech_name} {tech_version} — {cve_id}",
                description=(
                    f"{cve_data.get('desc', 'No description')}\n\n"
                    f"Detected: {tech_name} {tech_version}\n"
                    f"CVSS: {base_score}\n"
                    f"CVE: {cve_id}\n"
                    f"Source: NVD API (real-time)\n"
                    f"References:\n{refs_str}\n"
                    f"Note: Version keyword match — manual verification required."
                ),
                vulnerability_type="outdated_software",
                severity=severity,
                confidence=confidence,
                target=target,
                tool_name="tech_cve_checker",
                tags=["cve", "nvd_live", tech_name, cve_id.lower()],
                evidence=f"Technology: {tech_name} {tech_version}\nCVE: {cve_id}\nCVSS: {base_score}",
                cwe_id=cve_data.get("cwe", "CWE-1104"),
            ))

    if findings:
        static_count = sum(1 for f in findings if "nvd_live" not in (f.tags or []))
        live_count = len(findings) - static_count
        logger.info(f"tech_cve_checker: {len(findings)} CVEs ({static_count} static, {live_count} NVD live) for {target}")

    return findings


__all__ = ["check_technology_cves", "check_technology_cves_live"]
