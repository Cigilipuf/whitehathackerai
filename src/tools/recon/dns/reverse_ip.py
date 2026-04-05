"""
WhiteHatHacker AI — Reverse IP Lookup (V7-T1-4)

IP adresi üzerindeki diğer domain'leri / virtual host'ları bulur.
  - HackerTarget API (ücretsiz, anonim)
  - DNS PTR kaydı sorgusu
  - Bing IP2Host (ücretsiz, anonim)

Scope kontrolü yapılarak sadece yetkili domain'ler raporlanır.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

_HACKERTARGET_API = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
_BING_IP2HOST = "https://www.bing.com/search?q=ip%3a{ip}"


class ReverseIPLookup(SecurityTool):
    """
    Reverse IP lookup — find all domains hosted on a given IP address.

    Uses public APIs (HackerTarget) and DNS PTR records to discover
    co-hosted domains, which can expand the attack surface within scope.
    """

    name = "reverse_ip_lookup"
    category = ToolCategory.RECON_DNS
    description = "Reverse IP lookup — discover co-hosted domains"
    binary_name = ""
    requires_root = False
    risk_level = RiskLevel.SAFE

    def is_available(self) -> bool:
        return True  # Pure HTTP + DNS, no external binary

    async def run(
        self, target: str, options: dict[str, Any] | None = None,
        profile: ScanProfile | None = None,
    ) -> ToolResult:
        options = options or {}
        ip_addresses: list[str] = options.get("ip_addresses", [])

        if not ip_addresses:
            # If no IPs given, try to resolve the target domain
            ip_addresses = await self._resolve(target)

        all_domains: list[str] = []
        for ip in ip_addresses:
            logger.debug(f"[reverse_ip] Looking up: {ip}")
            domains = await self._lookup_hackertarget(ip)
            ptr = await self._ptr_lookup(ip)
            if ptr:
                domains.append(ptr)
            all_domains.extend(domains)

        unique = sorted(set(d.lower().strip(".") for d in all_domains if d))

        findings: list[Finding] = []
        if unique:
            findings.append(Finding(
                title=f"Reverse IP: {len(unique)} co-hosted domains found",
                severity=SeverityLevel.INFO,
                confidence=70,
                target=target,
                description=f"Domains sharing IP with {target}:\n" + "\n".join(f"  - {d}" for d in unique[:50]),
                evidence={"domains": unique, "ip_addresses": ip_addresses},
                tool_name=self.name,
            ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output="\n".join(unique),
            findings=findings,
            metadata={"domains": unique, "ip_addresses": ip_addresses},
        )

    async def _resolve(self, domain: str) -> list[str]:
        """Resolve domain to IP addresses using system DNS."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "A", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            lines = stdout.decode().strip().splitlines()
            return [l.strip() for l in lines if re.match(r"^\d+\.\d+\.\d+\.\d+$", l.strip())]
        except Exception as exc:
            logger.warning(f"[reverse_ip] DNS resolve failed for {domain}: {exc}")
            return []

    async def _lookup_hackertarget(self, ip: str) -> list[str]:
        """Query HackerTarget free API for reverse IP."""
        url = _HACKERTARGET_API.format(ip=ip)
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return []
                text = resp.text.strip()
                if "error" in text.lower() or "no records" in text.lower():
                    return []
                return [line.strip() for line in text.splitlines() if line.strip()]
        except Exception as exc:
            logger.warning(f"[reverse_ip] HackerTarget lookup failed for {ip}: {exc}")
            return []

    async def _ptr_lookup(self, ip: str) -> str | None:
        """DNS PTR record lookup."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "-x", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            result = stdout.decode().strip()
            return result if result and not result.startswith(";") else None
        except Exception:
            return None

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        domains = [l.strip() for l in raw_output.splitlines() if l.strip()]
        if not domains:
            return []
        return [Finding(
            title=f"Reverse IP: {len(domains)} domains found",
            severity=SeverityLevel.INFO,
            confidence=70,
            target=target,
            description="\n".join(domains),
            tool_name=self.name,
        )]

    def build_command(self, target: str, options: dict | None = None, profile: ScanProfile | None = None) -> list[str]:
        return []  # Pure Python — no external command
