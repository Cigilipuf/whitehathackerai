"""
WhiteHatHacker AI — wafw00f Wrapper

Web Application Firewall (WAF) detection & fingerprinting.
Hedef sitenin önünde WAF olup olmadığını ve türünü saptar.
FP engine ve tarama stratejisi için kritik bilgi sağlar.
"""

from __future__ import annotations

import re
from typing import Any


from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class Wafw00fWrapper(SecurityTool):
    """
    wafw00f — WAF fingerprinting.

    Tespit edilen WAF bilgisi:
      - FP Engine'e iletilir (WAF kaynaklı FP'leri elemek için)
      - Tarama stratejisini etkiler (WAF bypass teknikleri)
    """

    name = "wafw00f"
    category = ToolCategory.RECON_TECH
    description = "Web Application Firewall detection and fingerprinting"
    binary_name = "wafw00f"
    requires_root = False
    risk_level = RiskLevel.SAFE

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=1200)
        # wafw00f writes progress/results to stderr
        combined = stdout + "\n" + stderr if stderr else stdout
        findings = self.parse_output(combined, target)

        return ToolResult(
            tool_name=self.name,
            success=(exit_code == 0 or len(findings) > 0),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            findings=findings,
            command=" ".join(command),
            target=target,
            metadata={"waf_detected": any("waf_detected" in f.tags for f in findings)},
        )

    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        options = options or {}
        url = target if target.startswith("http") else f"https://{target}"
        cmd = [self.binary_name, url]

        if options.get("all_wafs", False):
            cmd.append("-a")  # Tüm WAF testlerini çalıştır

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # wafw00f çıktı formatları:
        # [+] The site https://... is behind Cloudflare (Cloudflare Inc.)
        # [-] No WAF detected
        # [+] Generic detection results: ...

        waf_pattern = re.compile(
            r"\[\+\]\s+The site\s+(\S+)\s+is behind\s+(.+?)(?:\s*\((.+?)\))?$",
            re.MULTILINE
        )
        no_waf_pattern = re.compile(r"\[-\]\s+No WAF detected", re.IGNORECASE)

        for match in waf_pattern.finditer(raw_output):
            site = match.group(1)
            waf_name = match.group(2).strip()
            waf_vendor = match.group(3).strip() if match.group(3) else ""

            desc = f"WAF detected: {waf_name}"
            if waf_vendor:
                desc += f" by {waf_vendor}"

            findings.append(Finding(
                title=f"WAF Detected: {waf_name}",
                description=desc,
                vulnerability_type="waf_detection",
                severity=SeverityLevel.INFO,
                confidence=90.0,
                target=site or target,
                endpoint=site or target,
                tool_name=self.name,
                tags=["waf_detected", f"waf:{waf_name.lower()}", "security"],
                evidence=raw_output[:500],
                metadata={
                    "waf_name": waf_name,
                    "waf_vendor": waf_vendor,
                },
            ))

        if no_waf_pattern.search(raw_output):
            findings.append(Finding(
                title="No WAF Detected",
                description="No Web Application Firewall was detected in front of the target",
                vulnerability_type="waf_detection",
                severity=SeverityLevel.INFO,
                confidence=70.0,  # Düşük güven — bazı WAF'lar gizlenebilir
                target=target,
                tool_name=self.name,
                tags=["no_waf"],
            ))

        if not findings:
            findings.append(Finding(
                title="WAF Detection: Inconclusive",
                description="wafw00f could not determine WAF presence",
                vulnerability_type="waf_detection",
                severity=SeverityLevel.INFO,
                confidence=30.0,
                target=target,
                tool_name=self.name,
                tags=["waf_unknown"],
            ))

        return findings


__all__ = ["Wafw00fWrapper"]
