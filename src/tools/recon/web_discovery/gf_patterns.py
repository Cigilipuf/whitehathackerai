"""
WhiteHatHacker AI — GF Pattern Engine (V7-T2-6)

URL listesini zafiyet türüne göre filtreler (tomnomnom/gf tarzı).
Regex tabanlı pattern eşleme: URL'leri XSS, SQLi, SSRF, LFI, RCE,
redirect, IDOR vb. kategorilere ayırarak hedefe özel tarama kuyruğu
oluşturur.

Harici gf binary'sine bağımlılık YOKTUR — pure Python implementasyon.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger


# ============================================================
# Pattern Definitions  (gf-patterns inspired)
# ============================================================

GF_PATTERNS: dict[str, dict[str, Any]] = {
    "xss": {
        "description": "Potential XSS injection points",
        "regex": re.compile(
            r"[?&](q|s|search|query|keyword|term|text|input|value|data|"
            r"content|message|comment|body|title|name|desc|redirect|url|"
            r"callback|cb|func|handler|return|next|ref|page|view|template|"
            r"html|id|lang)=",
            re.IGNORECASE,
        ),
    },
    "sqli": {
        "description": "Potential SQL injection points",
        "regex": re.compile(
            r"[?&](id|user|uid|page|cat|category|dir|order|sort|"
            r"table|column|field|row|num|number|count|offset|limit|"
            r"select|report|role|update|query|search|where|"
            r"filter|process|result|view|action|type)=",
            re.IGNORECASE,
        ),
    },
    "ssrf": {
        "description": "Potential SSRF injection points",
        "regex": re.compile(
            r"[?&](url|uri|src|source|href|link|dest|destination|"
            r"redirect|go|out|proxy|fetch|load|request|target|"
            r"path|file|page|feed|host|site|domain|callback|"
            r"return|next|data|reference|val|image|img)=",
            re.IGNORECASE,
        ),
    },
    "lfi": {
        "description": "Potential LFI/path traversal points",
        "regex": re.compile(
            r"[?&](file|path|folder|dir|document|root|template|"
            r"include|page|view|content|layout|mod|conf|"
            r"pg|style|pdf|display|category|log|read|download)=",
            re.IGNORECASE,
        ),
    },
    "rce": {
        "description": "Potential RCE/command injection points",
        "regex": re.compile(
            r"[?&](cmd|exec|command|execute|run|ping|query|jump|"
            r"code|reg|do|func|arg|option|load|process|step|"
            r"payload|read|feature|exe|module|action|shell|daemon)=",
            re.IGNORECASE,
        ),
    },
    "redirect": {
        "description": "Potential open redirect points",
        "regex": re.compile(
            r"[?&](url|redirect|redir|return|next|target|dest|"
            r"destination|rurl|forward|goto|out|view|to|"
            r"continue|link|ref|callback|path|data|site|"
            r"returnTo|returnUrl|redirect_uri|redirect_url)=",
            re.IGNORECASE,
        ),
    },
    "ssti": {
        "description": "Potential SSTI injection points",
        "regex": re.compile(
            r"[?&](template|page|content|preview|render|"
            r"view|layout|name|text|format|value|input|"
            r"msg|message|lang|locale|theme|skin)=",
            re.IGNORECASE,
        ),
    },
    "idor": {
        "description": "Potential IDOR points (numeric/UUID IDs)",
        "regex": re.compile(
            r"[?&](id|uid|user_id|account|profile|order|invoice|"
            r"ticket|doc|report|file|message|project|item|record|"
            r"token)=\d+",
            re.IGNORECASE,
        ),
    },
    "debug": {
        "description": "Debug/development endpoints",
        "regex": re.compile(
            r"(debug|test|dev|staging|phpinfo|trace|console|"
            r"status|health|info|metrics|env|config|actuator|"
            r"swagger|graphql|graphiql|altair)",
            re.IGNORECASE,
        ),
    },
    "secrets": {
        "description": "Potential secret/config file exposure",
        "regex": re.compile(
            r"\.(env|config|cfg|ini|yml|yaml|toml|json|xml|"
            r"bak|backup|old|orig|swp|log|sql|db|sqlite|"
            r"key|pem|p12|pfx|jks|keystore|htpasswd|htaccess|"
            r"git|svn|hg|DS_Store)",
            re.IGNORECASE,
        ),
    },
}


# ============================================================
# Engine
# ============================================================


class GFPatternEngine:
    """
    URL'leri zafiyet kategorilerine ayıran pattern engine.

    Kullanım:
        engine = GFPatternEngine()
        categorized = engine.classify(urls)
        # → {"xss": [...], "sqli": [...], ...}

        xss_urls = engine.filter(urls, "xss")
        interesting = engine.filter_interesting(urls)
    """

    def __init__(self, patterns: dict[str, dict[str, Any]] | None = None) -> None:
        self.patterns = patterns or GF_PATTERNS

    def classify(self, urls: list[str]) -> dict[str, list[str]]:
        """Tüm URL'leri kategorize et. Bir URL birden fazla kategoriye girebilir."""
        result: dict[str, list[str]] = {cat: [] for cat in self.patterns}
        result["unmatched"] = []

        for url in urls:
            matched = False
            for cat_name, cat_info in self.patterns.items():
                if cat_info["regex"].search(url):
                    result[cat_name].append(url)
                    matched = True
            if not matched:
                result["unmatched"].append(url)

        # Log summary
        summary = {k: len(v) for k, v in result.items() if v}
        logger.debug(f"GF classification: {summary}")
        return result

    def filter(self, urls: list[str], category: str) -> list[str]:
        """Sadece belirli kategoriye uyan URL'leri döndür."""
        pat = self.patterns.get(category)
        if pat is None:
            logger.warning(f"GF pattern category '{category}' not found")
            return []
        return [u for u in urls if pat["regex"].search(u)]

    def filter_interesting(self, urls: list[str]) -> list[str]:
        """Herhangi bir kategoriye uyan tüm 'ilginç' URL'leri döndür (deduplicated)."""
        seen: set[str] = set()
        interesting: list[str] = []
        for url in urls:
            if url in seen:
                continue
            for cat_info in self.patterns.values():
                if cat_info["regex"].search(url):
                    seen.add(url)
                    interesting.append(url)
                    break
        return interesting

    def categories(self) -> list[str]:
        return list(self.patterns.keys())

    def add_pattern(self, name: str, regex: str, description: str = "") -> None:
        """Dinamik olarak yeni pattern ekle."""
        self.patterns[name] = {
            "description": description,
            "regex": re.compile(regex, re.IGNORECASE),
        }
