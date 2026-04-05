"""
WhiteHatHacker AI — Tool-Specific FP Quirks

Her güvenlik aracının bilinen yanlış pozitif davranışlarını,
sınırlılıklarını ve güvenilirlik kalıplarını tanımlayan modül.
"""

from __future__ import annotations

from typing import Any

from loguru import logger
from pydantic import BaseModel


# ============================================================
# Models
# ============================================================

class ToolQuirk(BaseModel):
    """Araç spesifik FP bilgisi."""

    tool_name: str
    vuln_type: str = "*"            # "*" = hepsi
    quirk_type: str = ""            # false_positive, unreliable, noisy, limitation
    description: str = ""
    confidence_modifier: int = 0    # -50 ile +20 arası
    requires_verification: bool = True
    verification_method: str = ""   # alternative tool or manual check
    regex_signature: str = ""       # bu desende matchlenirse aktif olur


# ============================================================
# TOOL QUIRKS DATABASE
# ============================================================

TOOL_QUIRKS: list[ToolQuirk] = [

    # ── sqlmap ──────────────────────────────────────────────

    ToolQuirk(
        tool_name="sqlmap",
        vuln_type="sql_injection",
        quirk_type="unreliable",
        description="sqlmap boolean-based blind detection can false positive on pages with naturally varying content (ads, timestamps, random elements)",
        confidence_modifier=-15,
        requires_verification=True,
        verification_method="Confirm with time-based or UNION test; check if page has dynamic content",
        regex_signature=r"boolean-based blind",
    ),
    ToolQuirk(
        tool_name="sqlmap",
        vuln_type="sql_injection",
        quirk_type="false_positive",
        description="sqlmap may report 'parameter appears to be injectable' with low confidence when WAF returns varied responses",
        confidence_modifier=-25,
        requires_verification=True,
        verification_method="Manual injection test with raw HTTP; check for WAF interference",
        regex_signature=r"appears to be.*injectable",
    ),
    ToolQuirk(
        tool_name="sqlmap",
        vuln_type="sql_injection",
        quirk_type="noisy",
        description="sqlmap --level=5 --risk=3 produces many potential FPs due to aggressive testing",
        confidence_modifier=-10,
        requires_verification=True,
        verification_method="Re-run with default level/risk and compare",
    ),

    # ── nikto ───────────────────────────────────────────────

    ToolQuirk(
        tool_name="nikto",
        vuln_type="*",
        quirk_type="noisy",
        description="nikto produces many informational findings that are not actual vulnerabilities (server headers, common files, etc.)",
        confidence_modifier=-20,
        requires_verification=True,
        verification_method="Filter informational findings; only escalate actual vulnerability indicators",
    ),
    ToolQuirk(
        tool_name="nikto",
        vuln_type="information_disclosure",
        quirk_type="false_positive",
        description="nikto flags standard server headers (Server, X-Powered-By) as information disclosure even when they're common/expected",
        confidence_modifier=-30,
        requires_verification=False,
        verification_method="Check if header reveals specific version with known CVEs",
        regex_signature=r"(Server header|X-Powered-By|retrieved)",
    ),
    ToolQuirk(
        tool_name="nikto",
        vuln_type="*",
        quirk_type="false_positive",
        description="nikto reports outdated findings from its database that may not apply to modern configs",
        confidence_modifier=-15,
        requires_verification=True,
        verification_method="Verify finding manually; check nikto database date",
        regex_signature=r"OSVDB-\d+",
    ),

    # ── nmap ────────────────────────────────────────────────

    ToolQuirk(
        tool_name="nmap",
        vuln_type="*",
        quirk_type="unreliable",
        description="nmap NSE vuln scripts may report 'LIKELY VULNERABLE' without definitive confirmation",
        confidence_modifier=-15,
        requires_verification=True,
        verification_method="Use specialized exploit tool to confirm; check CVE applicability",
        regex_signature=r"LIKELY VULNERABLE|POTENTIALLY VULNERABLE",
    ),
    ToolQuirk(
        tool_name="nmap",
        vuln_type="*",
        quirk_type="limitation",
        description="nmap service detection can misidentify services behind proxies or on non-standard ports",
        confidence_modifier=-10,
        requires_verification=True,
        verification_method="Banner grab and manual service identification",
    ),

    # ── wpscan ──────────────────────────────────────────────

    ToolQuirk(
        tool_name="wpscan",
        vuln_type="*",
        quirk_type="noisy",
        description="wpscan reports all known CVEs for detected plugin versions, even if the specific feature is not enabled",
        confidence_modifier=-10,
        requires_verification=True,
        verification_method="Verify vulnerable endpoint/feature is actually accessible",
    ),
    ToolQuirk(
        tool_name="wpscan",
        vuln_type="*",
        quirk_type="false_positive",
        description="wpscan version detection may be inaccurate if readme.html or meta generator tag is stripped",
        confidence_modifier=-20,
        requires_verification=True,
        verification_method="Try multiple version detection methods; check changelog endpoints",
        regex_signature=r"The version could not be determined",
    ),

    # ── ffuf / gobuster ─────────────────────────────────────

    ToolQuirk(
        tool_name="ffuf",
        vuln_type="information_disclosure",
        quirk_type="false_positive",
        description="ffuf may report false positives when custom 404 pages return 200 status with varying content length",
        confidence_modifier=-20,
        requires_verification=True,
        verification_method="Compare response body with known 404 signature; check for soft 404s",
        regex_signature=r"Status: 200.*Size: \d+",
    ),
    ToolQuirk(
        tool_name="gobuster",
        vuln_type="information_disclosure",
        quirk_type="false_positive",
        description="gobuster reports all 200/301/302 responses which may include wildcard DNS or catch-all routes",
        confidence_modifier=-15,
        requires_verification=True,
        verification_method="Check for wildcard responses; compare with random path baseline",
    ),

    # ── hydra ───────────────────────────────────────────────

    ToolQuirk(
        tool_name="hydra",
        vuln_type="authentication_bypass",
        quirk_type="false_positive",
        description="hydra http-post-form may false positive if success/failure conditions are not properly configured",
        confidence_modifier=-20,
        requires_verification=True,
        verification_method="Manually test the reported credentials; check login response differences",
        regex_signature=r"\[http-post-form\].*login:",
    ),
    ToolQuirk(
        tool_name="hydra",
        vuln_type="authentication_bypass",
        quirk_type="unreliable",
        description="hydra SSH/FTP brute force may falsely report success due to connection timeouts or rate limiting",
        confidence_modifier=-15,
        requires_verification=True,
        verification_method="Manually SSH/FTP with reported credentials",
    ),

    # ── commix ──────────────────────────────────────────────

    ToolQuirk(
        tool_name="commix",
        vuln_type="command_injection",
        quirk_type="false_positive",
        description="commix time-based detection may trigger false positives on naturally slow endpoints",
        confidence_modifier=-15,
        requires_verification=True,
        verification_method="Test with multiple delay values; compare baseline response time",
    ),

    # ── sslscan / sslyze ───────────────────────────────────

    ToolQuirk(
        tool_name="sslscan",
        vuln_type="ssl_tls_misconfiguration",
        quirk_type="noisy",
        description="sslscan reports all cipher suites including those that are weak but not directly exploitable",
        confidence_modifier=-10,
        requires_verification=False,
        verification_method="Focus on truly weak ciphers (RC4, DES, NULL); ignore medium-strength ones",
    ),
    ToolQuirk(
        tool_name="sslyze",
        vuln_type="ssl_tls_misconfiguration",
        quirk_type="false_positive",
        description="sslyze may report Heartbleed as 'could not determine' rather than confirmed, which gets misread as positive",
        confidence_modifier=-25,
        requires_verification=True,
        verification_method="Use nmap ssl-heartbleed script for confirmation",
        regex_signature=r"NOT_VULNERABLE|COULD NOT|unable to determine",
    ),

    # ── enum4linux / smbclient ──────────────────────────────

    ToolQuirk(
        tool_name="enum4linux",
        vuln_type="information_disclosure",
        quirk_type="noisy",
        description="enum4linux reports RPC/SMB enumeration results that are often expected behaviors, not vulnerabilities",
        confidence_modifier=-15,
        requires_verification=True,
        verification_method="Check if null session actually provides sensitive data; assess data sensitivity",
    ),

    # ── searchsploit ────────────────────────────────────────

    ToolQuirk(
        tool_name="searchsploit",
        vuln_type="*",
        quirk_type="noisy",
        description="searchsploit matches are based on version strings and may not be applicable to the target's specific configuration",
        confidence_modifier=-20,
        requires_verification=True,
        verification_method="Verify exact version and configuration; check if patch was applied",
    ),

    # ── whatweb ─────────────────────────────────────────────

    ToolQuirk(
        tool_name="whatweb",
        vuln_type="information_disclosure",
        quirk_type="limitation",
        description="whatweb technology detection is passive and may not accurately reflect the actual technology stack",
        confidence_modifier=-10,
        requires_verification=False,
        verification_method="Cross-reference with multiple detection methods",
    ),

    # ── wafw00f ─────────────────────────────────────────────

    ToolQuirk(
        tool_name="wafw00f",
        vuln_type="*",
        quirk_type="false_positive",
        description="wafw00f may misidentify CDN responses as WAF, or fail to detect certain WAFs behind CDN",
        confidence_modifier=-5,
        requires_verification=False,
        verification_method="Check response headers manually; test with known-blocked payloads",
    ),
]


# ============================================================
# Tool Quirk Checker
# ============================================================

class ToolQuirkChecker:
    """
    Araç spesifik FP kalıplarını kontrol eden motor.

    Usage:
        checker = ToolQuirkChecker()
        result = checker.check("sqlmap", finding)
        if result["has_quirks"]:
            confidence -= result["total_modifier"]
    """

    def __init__(self, extra_quirks: list[ToolQuirk] | None = None) -> None:
        self._quirks = list(TOOL_QUIRKS)
        if extra_quirks:
            self._quirks.extend(extra_quirks)

    def check(
        self, tool_name: str, finding: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Bir bulguyu araç spesifik FP kalıplarına karşı kontrol et.

        Returns:
            {
                "has_quirks": bool,
                "matching_quirks": [ToolQuirk, ...],
                "total_modifier": int,
                "needs_verification": bool,
                "verification_methods": [str, ...],
            }
        """
        vuln_type = finding.get("vuln_type", finding.get("type", "*"))
        evidence = str(finding.get("evidence", ""))

        matching: list[ToolQuirk] = []
        total_mod = 0
        needs_verify = False
        methods: list[str] = []

        for quirk in self._quirks:
            # Tool adı eşleşmesi
            if quirk.tool_name != tool_name:
                continue

            # Vuln type filtresi
            if quirk.vuln_type != "*" and quirk.vuln_type != vuln_type:
                continue

            # Regex signature eşleşmesi (varsa)
            if quirk.regex_signature:
                import re
                if not re.search(quirk.regex_signature, evidence, re.IGNORECASE):
                    continue

            matching.append(quirk)
            total_mod += quirk.confidence_modifier

            if quirk.requires_verification:
                needs_verify = True
                if quirk.verification_method:
                    methods.append(quirk.verification_method)

            logger.debug(
                f"Tool quirk matched | tool={tool_name} | "
                f"quirk={quirk.description[:60]} | "
                f"modifier={quirk.confidence_modifier}"
            )

        return {
            "has_quirks": bool(matching),
            "matching_quirks": matching,
            "total_modifier": total_mod,
            "needs_verification": needs_verify,
            "verification_methods": methods,
        }

    def get_tool_reliability(self, tool_name: str) -> dict[str, Any]:
        """Araç güvenilirlik profili."""
        tool_quirks = [q for q in self._quirks if q.tool_name == tool_name]

        if not tool_quirks:
            return {"tool": tool_name, "known_quirks": 0, "reliability": "unknown"}

        fp_count = sum(1 for q in tool_quirks if q.quirk_type == "false_positive")
        noisy_count = sum(1 for q in tool_quirks if q.quirk_type == "noisy")
        unreliable_count = sum(1 for q in tool_quirks if q.quirk_type == "unreliable")

        total_issues = fp_count + noisy_count + unreliable_count

        if total_issues >= 3:
            reliability = "low"
        elif total_issues >= 2:
            reliability = "medium"
        elif total_issues >= 1:
            reliability = "high"
        else:
            reliability = "very_high"

        return {
            "tool": tool_name,
            "known_quirks": len(tool_quirks),
            "false_positive_patterns": fp_count,
            "noisy_patterns": noisy_count,
            "unreliable_patterns": unreliable_count,
            "reliability": reliability,
        }

    def list_tools(self) -> list[str]:
        """Quirk veritabanındaki araç listesi."""
        return sorted({q.tool_name for q in self._quirks})


__all__ = [
    "ToolQuirkChecker",
    "ToolQuirk",
    "TOOL_QUIRKS",
]
