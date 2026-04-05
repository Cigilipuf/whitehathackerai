"""
WhiteHatHacker AI — Favicon Hash Technology Detection (V7-T4-2)

Favicon.ico hash (MurmurHash3) ile teknoloji/framework tanıma:
  - Favicon indir → mmh3 hash hesapla
  - Bilinen favicon hash veritabanı ile karşılaştır
  - Shodan favicon search uyumlu hash üret
"""

from __future__ import annotations

import base64
import struct
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# Known favicon hashes: hash → (technology, description)
# Sources: Shodan, OWASP favicon database, community contributions
_KNOWN_HASHES: dict[int, tuple[str, str]] = {
    -1137812357: ("Spring Boot", "Default Spring Boot favicon"),
    116323821: ("Jenkins", "Jenkins CI/CD"),
    -928028781: ("Grafana", "Grafana monitoring"),
    81586312: ("Apache Tomcat", "Default Tomcat favicon"),
    -266133133: ("Kubernetes Dashboard", "K8s dashboard"),
    1485257654: ("Jira", "Atlassian Jira"),
    -305179312: ("Confluence", "Atlassian Confluence"),
    988422585: ("GitLab", "GitLab self-hosted"),
    -1073467427: ("SonarQube", "SonarQube code analysis"),
    442749392: ("Kibana", "Elastic Kibana"),
    -218813164: ("Prometheus", "Prometheus monitoring"),
    1354567743: ("Minio", "MinIO object storage"),
    -1292735114: ("Portainer", "Portainer Docker management"),
    1279946647: ("RabbitMQ", "RabbitMQ management"),
    -335242539: ("Keycloak", "Keycloak IAM"),
    876876147: ("pgAdmin", "PostgreSQL admin"),
    -1337765292: ("Webmin", "Webmin server admin"),
    -1166198021: ("phpMyAdmin", "MySQL admin"),
    -820726651: ("Roundcube", "Roundcube webmail"),
    -1022954038: ("Nextcloud", "Nextcloud file sharing"),
    1457460880: ("Matomo", "Matomo analytics"),
    -1472836198: ("Zabbix", "Zabbix monitoring"),
    116323821: ("Jenkins", "Jenkins CI"),
    -2062162839: ("Hashicorp Vault", "HashiCorp Vault"),
    1697575664: ("Traefik", "Traefik proxy"),
}


def mmh3_hash32(data: bytes) -> int:
    """
    MurmurHash3 32-bit implementation (Shodan compatible).
    Computes hash on base64-encoded favicon data.
    """
    encoded = base64.b64encode(data).decode()

    # MurmurHash3 32-bit
    seed = 0
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(encoded)
    h1 = seed
    rounded_end = (length & 0xFFFFFFFC)

    for i in range(0, rounded_end, 4):
        k1 = (
            (ord(encoded[i]) & 0xFF)
            | ((ord(encoded[i + 1]) & 0xFF) << 8)
            | ((ord(encoded[i + 2]) & 0xFF) << 16)
            | ((ord(encoded[i + 3]) & 0xFF) << 24)
        )
        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = ((h1 * 5) + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (ord(encoded[rounded_end + 2]) & 0xFF) << 16
    if val in (2, 3):
        k1 |= (ord(encoded[rounded_end + 1]) & 0xFF) << 8
    if val in (1, 2, 3):
        k1 |= ord(encoded[rounded_end]) & 0xFF
        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # Convert to signed 32-bit
    return struct.unpack("i", struct.pack("I", h1))[0]


class FaviconHasher(SecurityTool):
    """
    Download favicon, compute MurmurHash3, and match against known
    technology fingerprints. Shodan-compatible hash format.
    """

    name = "favicon_hasher"
    category = ToolCategory.RECON_TECH
    description = "Favicon hash-based technology detection (Shodan compatible)"
    binary_name = ""
    requires_root = False
    risk_level = RiskLevel.SAFE

    def is_available(self) -> bool:
        return True

    async def run(
        self, target: str, options: dict[str, Any] | None = None,
        profile: ScanProfile | None = None,
    ) -> ToolResult:
        options = options or {}
        urls: list[str] = options.get("urls", [])
        if not urls:
            base = target if target.startswith("http") else f"https://{target}"
            urls = [f"{base}/favicon.ico"]

        results: list[dict[str, Any]] = []
        findings: list[Finding] = []

        for url in urls:
            data = await self._download_favicon(url)
            if not data:
                continue

            h = mmh3_hash32(data)
            match = _KNOWN_HASHES.get(h)
            result: dict[str, Any] = {
                "url": url,
                "hash": h,
                "shodan_query": f"http.favicon.hash:{h}",
                "size": len(data),
            }

            if match:
                tech, desc = match
                result["technology"] = tech
                result["description"] = desc
                findings.append(Finding(
                    title=f"Favicon hash: {tech} detected",
                    severity=SeverityLevel.INFO,
                    confidence=85,
                    endpoint=url,
                    description=f"Technology: {tech}\nDescription: {desc}\nHash: {h}\nShodan: http.favicon.hash:{h}",
                    evidence=result,
                    tool_name=self.name,
                ))
            else:
                result["technology"] = "unknown"
                findings.append(Finding(
                    title=f"Favicon hash: {h} (unrecognized)",
                    severity=SeverityLevel.INFO,
                    confidence=50,
                    endpoint=url,
                    description=f"Hash: {h}\nShodan query: http.favicon.hash:{h}\nNo known technology match.",
                    evidence=result,
                    tool_name=self.name,
                ))

            results.append(result)

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output=str(results),
            findings=findings,
            metadata={"results": results},
        )

    async def _download_favicon(self, url: str) -> bytes | None:
        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False,
            ) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.content) > 0:
                    return resp.content
        except Exception as exc:
            logger.debug(f"[favicon] Download failed for {url}: {exc}")
        return None

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []

    def build_command(self, target: str, options: dict | None = None, profile: ScanProfile | None = None) -> list[str]:
        return []
