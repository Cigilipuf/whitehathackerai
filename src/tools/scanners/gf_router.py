"""
WhiteHatHacker AI — GF → Scanner Auto-Routing (V7-T4-3)

GF pattern engine sonuçlarını ilgili scanner'lara otomatik yönlendirir.
Vulnerability scan aşamasında URL'leri kategorize eder ve
her kategori için uygun araçları çalıştırır.
"""

from __future__ import annotations

from typing import Any

from loguru import logger

# GF category → (scanner module path, scanner class name, extra options)
_ROUTING_TABLE: dict[str, list[dict[str, Any]]] = {
    "xss": [
        {"tool": "dalfox", "priority": 1},
        {"tool": "xsstrike", "priority": 2},
    ],
    "sqli": [
        {"tool": "sqlmap", "priority": 1},
    ],
    "ssrf": [
        {"tool": "ssrfmap", "priority": 1},
    ],
    "lfi": [
        {"tool": "nuclei", "priority": 1, "template_tags": ["lfi", "inclusion"]},
    ],
    "rce": [
        {"tool": "commix", "priority": 1},
        {"tool": "nuclei", "priority": 2, "template_tags": ["rce", "command-injection"]},
    ],
    "redirect": [
        {"tool": "openredirex", "priority": 1},
    ],
    "ssti": [
        {"tool": "tplmap", "priority": 1},
        {"tool": "nuclei", "priority": 2, "template_tags": ["ssti"]},
    ],
    "idor": [
        {"tool": "custom:idor_checker", "priority": 1},
    ],
    "debug": [
        {"tool": "nuclei", "priority": 1, "template_tags": ["exposure", "debug"]},
    ],
    "secrets": [
        {"tool": "nuclei", "priority": 1, "template_tags": ["exposure", "token"]},
    ],
}


def route_urls(
    classified_urls: dict[str, list[str]],
    max_urls_per_tool: int = 50,
) -> list[dict[str, Any]]:
    """
    Take GF-classified URLs and produce scan tasks for the pipeline.

    Args:
        classified_urls: output from GFPatternEngine.classify()
        max_urls_per_tool: cap per tool to avoid excessive scanning

    Returns:
        List of scan task dicts:
        [
            {
                "tool": "sqlmap",
                "urls": ["https://...?id=1", ...],
                "category": "sqli",
                "priority": 1,
                "options": {},
            },
            ...
        ]
    """
    tasks: list[dict[str, Any]] = []

    for category, urls in classified_urls.items():
        if category == "unmatched" or not urls:
            continue

        route_entries = _ROUTING_TABLE.get(category, [])
        if not route_entries:
            logger.debug(f"[gf_router] No scanner route for category: {category}")
            continue

        limited_urls = urls[:max_urls_per_tool]

        for entry in route_entries:
            task: dict[str, Any] = {
                "tool": entry["tool"],
                "urls": limited_urls,
                "category": category,
                "priority": entry.get("priority", 5),
                "options": {},
            }
            if "template_tags" in entry:
                task["options"]["template_tags"] = entry["template_tags"]

            tasks.append(task)

    # Sort by priority
    tasks.sort(key=lambda t: t["priority"])

    logger.info(
        f"[gf_router] Generated {len(tasks)} scan tasks from "
        f"{sum(len(u) for u in classified_urls.values() if u)} URLs"
    )
    return tasks


def get_routing_table() -> dict[str, list[dict[str, Any]]]:
    """Return the current routing table (for dry-run display)."""
    return dict(_ROUTING_TABLE)
