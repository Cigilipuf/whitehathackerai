"""
WhiteHatHacker AI — theHarvester Wrapper

OSINT aracı: e-posta, subdomain, host, isim keşfi.
Birden fazla arama motorunu ve veri kaynağını kullanır.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class TheHarvesterWrapper(SecurityTool):
    """
    theHarvester — OSINT emails, subdomains, hosts, names, ports.

    Kaynaklar: Bing, Google, Shodan, DNSdumpster, CRTsh, vb.
    """

    name = "theHarvester"
    category = ToolCategory.RECON_OSINT
    description = "OSINT tool for emails, subdomains, hosts from search engines"
    binary_name = "theHarvester"
    requires_root = False
    risk_level = RiskLevel.SAFE

    # Kaynak seçenekleri (bing removed — unsupported in theHarvester 4.9+)
    SOURCES = {
        ScanProfile.STEALTH: "crtsh,dnsdumpster,rapiddns",
        ScanProfile.BALANCED: "crtsh,dnsdumpster,rapiddns,urlscan,hackertarget,certspotter",
        ScanProfile.AGGRESSIVE: "crtsh,dnsdumpster,rapiddns,urlscan,hackertarget,certspotter,yahoo,baidu,duckduckgo,otx",
    }

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 600)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        # theHarvester writes info/results to stderr as well
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
        )

    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        options = options or {}
        cmd = [self.binary_name, "-d", target]

        sources = options.get("sources", self.SOURCES.get(profile, self.SOURCES[ScanProfile.BALANCED]))
        cmd.extend(["-b", sources])

        limit = options.get("limit", 200)
        cmd.extend(["-l", str(limit)])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        # E-posta adresleri
        email_section = False
        host_section = False

        for line in raw_output.splitlines():
            line = line.strip()

            if "Emails found" in line or "[*] Emails" in line:
                email_section = True
                host_section = False
                continue
            if "Hosts found" in line or "[*] Hosts" in line:
                host_section = True
                email_section = False
                continue
            if line.startswith("[*]") or line.startswith("---"):
                email_section = False
                host_section = False
                continue

            if email_section and "@" in line:
                email = line.strip()
                if email not in seen and re.match(r"^[\w.+-]+@[\w.-]+\.\w+$", email):
                    seen.add(email)
                    findings.append(Finding(
                        title=f"Email: {email}",
                        description=f"OSINT discovered email address: {email}",
                        vulnerability_type="information_disclosure",
                        severity=SeverityLevel.INFO,
                        confidence=80.0,
                        target=target,
                        evidence=email,
                        tool_name=self.name,
                        tags=["email", "osint"],
                    ))

            if host_section and line:
                parts = line.split(":")
                hostname = parts[0].strip()
                if hostname and hostname not in seen:
                    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}$", hostname):
                        seen.add(hostname)
                        ip = parts[1].strip() if len(parts) > 1 else ""
                        findings.append(Finding(
                            title=f"Host: {hostname}",
                            description=f"OSINT discovered host: {hostname}" + (f" ({ip})" if ip else ""),
                            vulnerability_type="subdomain_discovery",
                            severity=SeverityLevel.INFO,
                            confidence=75.0,
                            target=hostname,
                            endpoint=hostname,
                            tool_name=self.name,
                            tags=["host", "osint", "subdomain"],
                        ))

        # Regex fallback: raw çıktıda subdomain'leri ara
        domain_escaped = re.escape(target)
        subdomain_pattern = re.compile(rf"([\w\-]+\.)*{domain_escaped}", re.IGNORECASE)
        for match in subdomain_pattern.finditer(raw_output):
            sub = match.group(0).lower()
            if sub not in seen and sub != target:
                seen.add(sub)
                findings.append(Finding(
                    title=f"Subdomain: {sub}",
                    description=f"Discovered subdomain in theHarvester output: {sub}",
                    vulnerability_type="subdomain_discovery",
                    severity=SeverityLevel.INFO,
                    confidence=65.0,
                    target=sub,
                    tool_name=self.name,
                    tags=["subdomain", "osint"],
                ))

        logger.debug(f"theHarvester parsed {len(findings)} findings for {target}")
        return findings


__all__ = ["TheHarvesterWrapper"]
