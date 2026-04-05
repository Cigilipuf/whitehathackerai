"""
WhiteHatHacker AI — Dynamic Wordlist Generator (V7-T4-1)

Hedef-spesifik wordlist oluşturur:
  - CeWL benzeri web scraping (sayfadaki kelimelerden wordlist)
  - Subdomain pattern extraction (api-* → api-v2, api-staging, ...)
  - Endpoint path pattern extraction (/api/v1/* → /api/v2/*, /api/v3/*)
  - Teknoloji-spesifik augmentation (WordPress, Django, Spring, vb.)
  - Statik wordlist'lerle merge
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
from loguru import logger

# Technology → common paths mapping
_TECH_WORDLISTS: dict[str, list[str]] = {
    "wordpress": [
        "wp-admin", "wp-content", "wp-includes", "wp-login.php",
        "wp-json", "xmlrpc.php", "wp-cron.php", "wp-config.php.bak",
        "wp-content/uploads", "wp-content/plugins", "wp-content/themes",
        "wp-admin/admin-ajax.php", "readme.html", "license.txt",
    ],
    "django": [
        "admin", "api", "static", "media", "accounts", "__debug__",
        "sitemap.xml", "favicon.ico", ".env", "settings.py",
    ],
    "spring": [
        "actuator", "actuator/health", "actuator/info", "actuator/env",
        "actuator/beans", "actuator/mappings", "actuator/configprops",
        "swagger-ui.html", "v2/api-docs", "v3/api-docs",
        "api-docs", "swagger-resources",
    ],
    "laravel": [
        ".env", "storage", "public", "artisan", "telescope",
        "horizon", "nova", "_debugbar", "api",
    ],
    "express": [
        "api", "graphql", "socket.io", "health", "metrics",
        ".env", "package.json", "node_modules",
    ],
    "rails": [
        "rails/info", "rails/mailers", "sidekiq", "admin", "api",
        "assets", "cable", "packs", ".env",
    ],
}

# Version pattern for expansion
_VERSION_RE = re.compile(r"(v?)(\d+)")


class DynamicWordlistGenerator:
    """
    Generate target-specific wordlists by combining web scraping,
    pattern extraction from recon data, and technology-based augmentation.
    """

    def __init__(self) -> None:
        self._words: list[str] = []

    def generate(
        self,
        target: str,
        subdomains: list[str] | None = None,
        endpoints: list[str] | None = None,
        technologies: list[str] | None = None,
        static_wordlist: str | None = None,
    ) -> list[str]:
        """
        Build a merged, deduplicated wordlist.

        Args:
            target: base domain
            subdomains: discovered subdomains
            endpoints: discovered URL paths
            technologies: detected technology names
            static_wordlist: path to static base wordlist to merge
        """
        words: set[str] = set()

        # 1. Technology augmentation
        if technologies:
            for tech in technologies:
                tech_lower = tech.lower()
                for key, paths in _TECH_WORDLISTS.items():
                    if key in tech_lower:
                        words.update(paths)

        # 2. Subdomain pattern extraction
        if subdomains:
            words.update(self._extract_subdomain_patterns(subdomains, target))

        # 3. Endpoint path pattern extraction
        if endpoints:
            words.update(self._extract_endpoint_patterns(endpoints))

        # 4. Static wordlist merge
        if static_wordlist:
            path = Path(static_wordlist)
            if path.exists():
                for line in path.read_text().splitlines():
                    w = line.strip()
                    if w and not w.startswith("#"):
                        words.add(w)

        return sorted(words)

    async def scrape_words(
        self, url: str, min_length: int = 4, max_words: int = 500,
    ) -> list[str]:
        """
        CeWL-like: scrape a webpage and extract unique words from visible text.
        """
        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False,
            ) as client:
                resp = await client.get(url)
                text = _strip_html(resp.text)
                raw_words = re.findall(r"[a-zA-Z0-9_-]{%d,}" % min_length, text)
                counter = Counter(w.lower() for w in raw_words)
                return [w for w, _ in counter.most_common(max_words)]
        except Exception as exc:
            logger.warning(f"[wordlist] Scrape failed for {url}: {exc}")
            return []

    def _extract_subdomain_patterns(
        self, subdomains: list[str], target: str,
    ) -> set[str]:
        """Extract prefix patterns from subdomains and generate variations."""
        base = target.split("://")[-1].split("/")[0].split(":")[0]
        prefixes: set[str] = set()
        for sub in subdomains:
            sub_clean = sub.lower().strip(".")
            if sub_clean.endswith(base):
                prefix = sub_clean[: -(len(base) + 1)]
                if prefix:
                    prefixes.add(prefix)

        # Generate variations from observed prefixes
        expanded: set[str] = set(prefixes)
        for p in prefixes:
            # Version expansion: api-v1 → api-v2, api-v3
            m = _VERSION_RE.search(p)
            if m:
                vprefix = m.group(1)
                num = int(m.group(2))
                base_p = p[: m.start()] + vprefix
                for i in range(1, min(num + 3, 10)):
                    expanded.add(f"{base_p}{i}")
            # Common suffix variations
            for suffix in ("-dev", "-staging", "-test", "-internal", "-api", "-new", "-old"):
                expanded.add(p + suffix)

        return expanded

    def _extract_endpoint_patterns(self, endpoints: list[str]) -> set[str]:
        """Extract path components and generate variations."""
        segments: set[str] = set()
        for ep in endpoints:
            path = ep.split("?")[0].split("#")[0]
            path = path.split("://")[-1]  # remove scheme
            # Remove leading hostname
            if "/" in path:
                path = "/" + path.split("/", 1)[-1]
            for seg in path.strip("/").split("/"):
                if seg and len(seg) > 1 and not seg.startswith("{"):
                    segments.add(seg)

                    # Version expansion
                    m = _VERSION_RE.match(seg)
                    if m:
                        vprefix = m.group(1)
                        num = int(m.group(2))
                        for i in range(1, min(num + 3, 10)):
                            segments.add(f"{vprefix}{i}")

        return segments

    def save(self, words: list[str], output_path: str) -> int:
        """Save wordlist to file. Returns word count."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for w in words:
                f.write(w + "\n")
        return len(words)


def _strip_html(html: str) -> str:
    """Rough HTML tag removal for word extraction."""
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.S)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-zA-Z]+;", " ", text)
    return text
