"""
WhiteHatHacker AI — Dry-Run Mode (V7-T4-4)

Pipeline'ı gerçekten çalıştırmadan hangi araçların hangi parametrelerle
çalıştırılacağını gösteren önizleme modu.

Kullanım:
    plan = dry_run_plan(target, profile, scope_config)
    print(format_dry_run(plan))
"""

from __future__ import annotations

from typing import Any

from src.utils.constants import ScanProfile

# Stage → tools mapping with descriptions
_PIPELINE_STAGES: list[dict[str, Any]] = [
    {
        "stage": "1. Scope Analysis",
        "tools": [
            {"name": "scope_validator", "desc": "Validate target scope", "risk": "safe"},
            {"name": "whois", "desc": "Domain registration info", "risk": "safe"},
        ],
    },
    {
        "stage": "2. Passive Recon",
        "tools": [
            {"name": "subfinder", "desc": "Fast subdomain discovery", "risk": "safe"},
            {"name": "amass (passive)", "desc": "Comprehensive passive enum", "risk": "safe"},
            {"name": "crt.sh", "desc": "Certificate transparency logs", "risk": "safe"},
            {"name": "assetfinder", "desc": "Asset discovery", "risk": "safe"},
            {"name": "theHarvester", "desc": "Email/subdomain OSINT", "risk": "safe"},
            {"name": "waybackurls", "desc": "Historical URLs", "risk": "safe"},
            {"name": "gau", "desc": "Known URLs from archives", "risk": "safe"},
            {"name": "github_secret_scanner", "desc": "GitHub secret search", "risk": "safe"},
            {"name": "cloud_storage_enum", "desc": "Cloud bucket discovery", "risk": "safe"},
            {"name": "email_security_checker", "desc": "SPF/DKIM/DMARC", "risk": "safe"},
            {"name": "reverse_ip_lookup", "desc": "Co-hosted domains", "risk": "safe"},
            {"name": "metadata_extractor", "desc": "Document metadata", "risk": "safe"},
        ],
    },
    {
        "stage": "3. Active Recon",
        "tools": [
            {"name": "httpx", "desc": "HTTP probing & live hosts", "risk": "low"},
            {"name": "rustscan/nmap", "desc": "Port scanning", "risk": "low"},
            {"name": "katana", "desc": "Web crawling", "risk": "low"},
            {"name": "gospider", "desc": "Web spider", "risk": "low"},
            {"name": "whatweb", "desc": "Technology detection", "risk": "safe"},
            {"name": "cdn_detector", "desc": "CDN detection", "risk": "safe"},
            {"name": "csp_subdomain_discovery", "desc": "CSP header analysis", "risk": "safe"},
            {"name": "favicon_hasher", "desc": "Favicon technology fingerprint", "risk": "safe"},
            {"name": "vhost_fuzzer", "desc": "Virtual host discovery", "risk": "low"},
            {"name": "ffuf", "desc": "Directory/file brute force", "risk": "low"},
        ],
    },
    {
        "stage": "4. Enumeration",
        "tools": [
            {"name": "arjun", "desc": "Hidden parameter discovery", "risk": "low"},
            {"name": "paramspider", "desc": "Parameter mining from archives", "risk": "safe"},
            {"name": "js_analyzer", "desc": "JavaScript endpoint extraction", "risk": "safe"},
            {"name": "sourcemap_extractor", "desc": "Source map analysis", "risk": "safe"},
            {"name": "gf_patterns", "desc": "URL pattern classification", "risk": "safe"},
            {"name": "swagger_parser", "desc": "API specification analysis", "risk": "safe"},
            {"name": "graphql_introspection", "desc": "GraphQL schema discovery", "risk": "low"},
        ],
    },
    {
        "stage": "5. Attack Surface Mapping",
        "tools": [
            {"name": "brain (LLM)", "desc": "AI-driven attack planning", "risk": "safe"},
            {"name": "threat_model", "desc": "Threat modeling", "risk": "safe"},
        ],
    },
    {
        "stage": "6. Vulnerability Scan",
        "tools": [
            {"name": "nuclei", "desc": "Template-based vulnerability scan", "risk": "medium"},
            {"name": "nikto", "desc": "Web server vulnerabilities", "risk": "medium"},
            {"name": "sqlmap", "desc": "SQL injection testing", "risk": "medium"},
            {"name": "dalfox", "desc": "XSS testing", "risk": "medium"},
            {"name": "commix", "desc": "Command injection testing", "risk": "medium"},
            {"name": "ssrfmap", "desc": "SSRF testing", "risk": "medium"},
            {"name": "tplmap", "desc": "Template injection testing", "risk": "medium"},
            {"name": "fourxx_bypass", "desc": "403/401 bypass testing", "risk": "low"},
            {"name": "jwt_checker", "desc": "JWT security testing", "risk": "low"},
            {"name": "cors_checker", "desc": "CORS misconfiguration", "risk": "low"},
            {"name": "idor_checker", "desc": "IDOR testing", "risk": "medium"},
            {"name": "gf_router", "desc": "Pattern-based scanner routing", "risk": "medium"},
        ],
    },
    {
        "stage": "7. FP Elimination",
        "tools": [
            {"name": "fp_detector (7-layer)", "desc": "Multi-layer false positive filtering", "risk": "low"},
            {"name": "brain (LLM)", "desc": "AI-driven verification", "risk": "safe"},
        ],
    },
    {
        "stage": "8. Reporting",
        "tools": [
            {"name": "report_generator", "desc": "Markdown/HTML/PDF reports", "risk": "safe"},
            {"name": "brain (LLM)", "desc": "AI-written professional reports", "risk": "safe"},
        ],
    },
]

_PROFILE_ADJUSTMENTS: dict[str, dict[str, Any]] = {
    "stealth": {
        "rate_limit": "1-3 req/s",
        "parallel_tools": 2,
        "nuclei_rate": 10,
        "scan_depth": "shallow",
        "notes": "Slow and quiet. Minimal fingerprint.",
    },
    "balanced": {
        "rate_limit": "5-10 req/s",
        "parallel_tools": 5,
        "nuclei_rate": 50,
        "scan_depth": "normal",
        "notes": "Default profile. Good balance of speed and stealth.",
    },
    "aggressive": {
        "rate_limit": "20-50 req/s",
        "parallel_tools": 10,
        "nuclei_rate": 150,
        "scan_depth": "deep",
        "notes": "Fast and thorough. May trigger WAF/IDS.",
    },
}


def dry_run_plan(
    target: str,
    profile: str = "balanced",
    scope_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Generate a dry-run plan showing what would be executed.

    Returns:
        {
            "target": "example.com",
            "profile": "balanced",
            "profile_settings": {...},
            "stages": [...],
            "total_tools": N,
        }
    """
    prof = _PROFILE_ADJUSTMENTS.get(profile, _PROFILE_ADJUSTMENTS["balanced"])

    total_tools = sum(len(s["tools"]) for s in _PIPELINE_STAGES)

    return {
        "target": target,
        "profile": profile,
        "profile_settings": prof,
        "stages": _PIPELINE_STAGES,
        "total_tools": total_tools,
        "scope": scope_config or {"target": target},
    }


def format_dry_run(plan: dict[str, Any]) -> str:
    """Format dry-run plan as readable text."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("  WhiteHatHacker AI — DRY RUN PLAN")
    lines.append("=" * 60)
    lines.append(f"  Target:  {plan['target']}")
    lines.append(f"  Profile: {plan['profile']}")

    prof = plan["profile_settings"]
    lines.append(f"  Rate:    {prof.get('rate_limit', '?')}")
    lines.append(f"  Parallel:{prof.get('parallel_tools', '?')}")
    lines.append(f"  Depth:   {prof.get('scan_depth', '?')}")
    lines.append(f"  Notes:   {prof.get('notes', '')}")
    lines.append("")

    for stage_info in plan["stages"]:
        lines.append(f"── {stage_info['stage']} ──")
        for tool in stage_info["tools"]:
            risk_tag = f"[{tool['risk'].upper()}]" if tool.get("risk") else ""
            lines.append(f"  • {tool['name']:30s} {risk_tag:10s} {tool['desc']}")
        lines.append("")

    lines.append(f"Total tools: {plan['total_tools']}")
    lines.append("=" * 60)
    lines.append("No requests will be sent in dry-run mode.")

    return "\n".join(lines)
