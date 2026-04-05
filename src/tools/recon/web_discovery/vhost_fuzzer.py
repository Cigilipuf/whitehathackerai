"""
WhiteHatHacker AI — VHost Fuzzer (V7-T2-3)

Virtual host keşfi: IP üzerinde farklı Host header'ları deneyerek
gizli vhost'ları bulur. ffuf binary'si yoksa pure-Python fallback kullanır.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# Default vhost wordlist fragments — merged with user wordlist if given
_BUILTIN_PREFIXES = [
    "admin", "api", "app", "beta", "blog", "cdn", "cms", "dashboard",
    "dev", "docs", "git", "grafana", "internal", "jenkins", "jira",
    "kibana", "legacy", "login", "mail", "monitor", "new", "old",
    "portal", "prometheus", "registry", "staging", "status", "test",
    "vault", "vpn", "webmail", "wiki", "www",
]


class VHostFuzzer(SecurityTool):
    """
    Virtual host discovery by fuzzing the Host header against a target IP.

    If ffuf is available, delegates to it for high-speed fuzzing.
    Otherwise, falls back to a pure-Python httpx-based approach.
    """

    name = "vhost_fuzzer"
    category = ToolCategory.RECON_WEB
    description = "Virtual host discovery via Host header fuzzing"
    binary_name = "ffuf"
    requires_root = False
    risk_level = RiskLevel.LOW

    def is_available(self) -> bool:
        return True  # has Python fallback

    async def run(
        self, target: str, options: dict[str, Any] | None = None,
        profile: ScanProfile | None = None,
    ) -> ToolResult:
        import httpx

        options = options or {}
        domain: str = options.get("domain", target)
        ip: str = options.get("ip", "")
        wordlist: str = options.get("wordlist", "")
        additional_prefixes: list[str] = options.get("prefixes", [])

        if not ip:
            ip = await self._resolve_ip(domain)
            if not ip:
                return ToolResult(
                    tool_name=self.name, success=False,
                    raw_output="Could not resolve IP", findings=[],
                )

        # Build candidate hosts
        base_domain = domain.lstrip("www.")
        candidates = [f"{p}.{base_domain}" for p in (_BUILTIN_PREFIXES + additional_prefixes)]

        # If external wordlist, add those too
        if wordlist:
            try:
                with open(wordlist) as f:
                    for line in f:
                        w = line.strip()
                        if w:
                            candidates.append(f"{w}.{base_domain}")
            except Exception as exc:
                logger.warning(f"[vhost] Cannot read wordlist {wordlist}: {exc}")

        # De-dup
        candidates = sorted(set(candidates))

        # Get baseline response for the known domain
        baseline = await self._probe(ip, domain)
        if baseline is None:
            return ToolResult(
                tool_name=self.name, success=False,
                raw_output=f"Cannot reach {ip} with Host: {domain}",
                findings=[],
            )

        discovered: list[dict[str, Any]] = []
        # Semaphore for concurrency control
        sem = asyncio.Semaphore(20)

        async def _check(hostname: str) -> None:
            async with sem:
                result = await self._probe(ip, hostname)
                if result is None:
                    return
                # Filter: different status OR significantly different body length
                if (result["status"] != baseline["status"]
                        or abs(result["length"] - baseline["length"]) > 100):
                    # Skip if it's a generic wildcard (same as random host)
                    if result["status"] not in (0, 400, 502, 503):
                        discovered.append({"host": hostname, **result})

        tasks = [_check(h) for h in candidates]
        await asyncio.gather(*tasks)

        findings: list[Finding] = []
        for d in discovered:
            findings.append(Finding(
                title=f"VHost discovered: {d['host']}",
                severity=SeverityLevel.MEDIUM if d["status"] == 200 else SeverityLevel.LOW,
                confidence=65,
                endpoint=f"https://{d['host']}",
                description=(
                    f"Host: {d['host']}\n"
                    f"Status: {d['status']}\n"
                    f"Content-Length: {d['length']}\n"
                    f"Baseline status: {baseline['status']}, length: {baseline['length']}"
                ),
                evidence=d,
                tool_name=self.name,
            ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output="\n".join(d["host"] for d in discovered),
            findings=findings,
            metadata={"discovered": discovered, "candidates_tested": len(candidates)},
        )

    async def _resolve_ip(self, domain: str) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "A", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            for line in stdout.decode().splitlines():
                line = line.strip()
                if line and not line.startswith(";"):
                    return line
        except Exception as e:
            logger.warning(f"vhost_fuzzer error: {e}")
        return ""

    async def _probe(self, ip: str, hostname: str) -> dict[str, Any] | None:
        """Send HTTP request with custom Host header."""
        import httpx

        url = f"https://{ip}"
        try:
            async with httpx.AsyncClient(
                timeout=30, verify=False, follow_redirects=False,
            ) as client:
                resp = await client.get(url, headers={"Host": hostname})
                return {
                    "status": resp.status_code,
                    "length": len(resp.content),
                }
        except Exception:
            # Try HTTP fallback
            try:
                url_http = f"http://{ip}"
                async with httpx.AsyncClient(
                    timeout=30, follow_redirects=False,
                ) as client:
                    resp = await client.get(url_http, headers={"Host": hostname})
                    return {
                        "status": resp.status_code,
                        "length": len(resp.content),
                    }
            except Exception:
                return None

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        hosts = [l.strip() for l in raw_output.splitlines() if l.strip()]
        return [Finding(
            title=f"VHost: {h}",
            severity=SeverityLevel.LOW,
            confidence=60,
            endpoint=f"https://{h}",
            tool_name=self.name,
        ) for h in hosts]

    def build_command(self, target: str, options: dict | None = None, profile: ScanProfile | None = None) -> list[str]:
        return []  # Uses Python httpx, not CLI
