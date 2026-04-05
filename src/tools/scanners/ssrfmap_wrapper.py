"""
WhiteHatHacker AI — SSRFMap Wrapper

SSRF exploitation framework — detection and exploitation of
Server-Side Request Forgery vulnerabilities with multiple modules.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# Available SSRFMap modules
_MODULES = {
    "readfiles": "Read local files via SSRF",
    "portscan": "Internal port scanning",
    "networkscan": "Internal network discovery",
    "aws": "AWS metadata exfiltration (169.254.169.254)",
    "gce": "GCE metadata exfiltration",
    "digitalocean": "DigitalOcean metadata exfiltration",
    "docker": "Docker API access",
    "github": "GitHub Enterprise metadata",
    "alibaba": "Alibaba Cloud metadata",
    "redis": "Redis interaction",
    "memcache": "Memcache interaction",
    "mysql": "MySQL interaction",
    "smtp": "SMTP interaction",
    "fastcgi": "FastCGI interaction",
    "custom": "Custom SSRF payload",
}

# Module risk classification
_HIGH_RISK_MODULES = {"aws", "gce", "digitalocean", "docker", "redis", "mysql", "fastcgi"}


class SsrfmapWrapper(SecurityTool):
    """
    SSRFMap — Automatic SSRF fuzzer and exploitation tool.

    Modules: readfiles, portscan, networkscan, aws/gce/digitalocean metadata,
    docker, redis, memcache, mysql, smtp, fastcgi.
    """

    name = "ssrfmap"
    category = ToolCategory.SCANNER
    description = "SSRF exploitation framework with cloud metadata and internal service modules"
    binary_name = "python3"
    requires_root = False
    risk_level = RiskLevel.HIGH

    # ── run ───────────────────────────────────────────────────
    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 300)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout + "\n" + stderr, target)

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

    # ── build_command ─────────────────────────────────────────
    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        options = options or {}

        cmd = [self.binary_name, "-m", "ssrfmap"]

        # Request file (required by SSRFMap)
        request_file = options.get("request_file", "")
        if request_file:
            cmd.extend(["-r", request_file])

        # Target parameter to inject into
        param = options.get("param", "")
        if param:
            cmd.extend(["-p", param])

        # Target URL (alternative to request file)
        if not request_file and target:
            cmd.extend(["--url", target])

        # Module selection based on profile
        module = options.get("module", "")
        if not module:
            match profile:
                case ScanProfile.STEALTH:
                    module = "readfiles"
                case ScanProfile.BALANCED:
                    module = "readfiles,portscan,aws"
                case ScanProfile.AGGRESSIVE:
                    module = ",".join([
                        "readfiles", "portscan", "networkscan",
                        "aws", "gce", "digitalocean", "docker",
                    ])

        if module:
            cmd.extend(["-m", module])

        # Timeout per request
        if options.get("rq_timeout"):
            cmd.extend(["--timeout", str(options["rq_timeout"])])

        # Proxy
        if options.get("proxy"):
            cmd.extend(["--proxy", options["proxy"]])

        # Custom headers
        for h in options.get("headers", []):
            cmd.extend(["--header", h])

        # Custom SSRF target (e.g. internal IP)
        if options.get("target_url"):
            cmd.extend(["--target-url", options["target_url"]])

        # Lhost for reverse connections
        if options.get("lhost"):
            cmd.extend(["--lhost", options["lhost"]])
        if options.get("lport"):
            cmd.extend(["--lport", str(options["lport"])])

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        # ---- Pattern 1: Successful SSRF access ----
        # "[+] URL accessible: http://169.254.169.254/..."
        accessible_re = re.compile(
            r"\[\+\]\s*(?:URL\s+)?accessible\s*[:\-]\s*(\S+)",
            re.IGNORECASE,
        )
        for match in accessible_re.finditer(raw_output):
            url = match.group(1).strip()
            severity = self._severity_for_url(url)
            findings.append(Finding(
                title="SSRF: Accessible internal resource",
                description=f"SSRFMap confirmed access to internal resource: {url}",
                vulnerability_type="ssrf",
                severity=severity,
                confidence=90.0,
                target=target,
                endpoint=url,
                tool_name=self.name,
                cwe_id="CWE-918",
                tags=["ssrf", "confirmed", self._classify_ssrf_target(url)],
                evidence=url,
                metadata={"accessible_url": url},
            ))

        # ---- Pattern 2: Cloud metadata extraction ----
        metadata_re = re.compile(
            r"(?:metadata|credentials?|iam|role|token|secret)\s*[:\-=]\s*(.+)",
            re.IGNORECASE,
        )
        for match in metadata_re.finditer(raw_output):
            data = match.group(1).strip()[:500]
            findings.append(Finding(
                title="SSRF: Cloud metadata/credentials exposed",
                description=(
                    "SSRFMap extracted cloud metadata or credentials via SSRF. "
                    "This may include IAM roles, tokens, or secrets."
                ),
                vulnerability_type="ssrf",
                severity=SeverityLevel.CRITICAL,
                confidence=95.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-918",
                tags=["ssrf", "cloud_metadata", "credential_leak"],
                evidence=data,
                metadata={"extracted_data": data},
            ))

        # ---- Pattern 3: File read results ----
        file_re = re.compile(
            r"\[\+\]\s*(?:File\s+)?(?:content|read)\s*[:\-]\s*(\S+)\s*\n([\s\S]{1,500}?)(?:\n\[|$)",
            re.IGNORECASE,
        )
        for match in file_re.finditer(raw_output):
            filepath = match.group(1).strip()
            content_snippet = match.group(2).strip()[:300]
            findings.append(Finding(
                title=f"SSRF: Local file read — {filepath}",
                description=f"SSRFMap read local file via SSRF: {filepath}",
                vulnerability_type="ssrf",
                severity=SeverityLevel.HIGH,
                confidence=90.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-918",
                tags=["ssrf", "lfi", "file_read"],
                evidence=content_snippet,
                metadata={"file_path": filepath},
            ))

        # ---- Pattern 4: Open port (internal) ----
        port_re = re.compile(
            r"\[\+\]\s*(?:Port|Service)\s+(\d+)\s+(?:is\s+)?(?:open|accessible)\s*(?:on\s+(\S+))?",
            re.IGNORECASE,
        )
        for match in port_re.finditer(raw_output):
            port = match.group(1)
            host = match.group(2) or "internal"
            findings.append(Finding(
                title=f"SSRF: Internal port {port} open on {host}",
                description=f"SSRFMap discovered internal port {port} open on {host} via SSRF.",
                vulnerability_type="ssrf",
                severity=SeverityLevel.MEDIUM,
                confidence=85.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-918",
                tags=["ssrf", "portscan", "internal"],
                metadata={"port": port, "host": host},
            ))

        # ---- Pattern 5: Internal service interaction ----
        service_re = re.compile(
            r"\[\+\]\s*(?:Redis|Memcache|MySQL|Docker|SMTP|FastCGI)\s+(?:interaction|response|data)\s*[:\-]\s*(.*)",
            re.IGNORECASE,
        )
        for match in service_re.finditer(raw_output):
            detail = match.group(1).strip()[:500]
            service = match.group(0).split("]")[1].strip().split()[0]
            findings.append(Finding(
                title=f"SSRF: Internal {service} access",
                description=f"SSRFMap interacted with internal {service} service via SSRF.",
                vulnerability_type="ssrf",
                severity=SeverityLevel.HIGH,
                confidence=90.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-918",
                tags=["ssrf", "internal_service", service.lower()],
                evidence=detail,
                metadata={"service": service, "response": detail},
            ))

        # ---- Pattern 6: General SSRF confirmed ----
        if not findings:
            ssrf_confirm_re = re.compile(
                r"\[\+\]\s*(?:SSRF|Server-Side Request Forgery)\s+(?:confirmed|detected|found)",
                re.IGNORECASE,
            )
            if ssrf_confirm_re.search(raw_output):
                findings.append(Finding(
                    title="SSRF Confirmed",
                    description="SSRFMap confirmed a Server-Side Request Forgery vulnerability.",
                    vulnerability_type="ssrf",
                    severity=SeverityLevel.HIGH,
                    confidence=55.0,
                    target=target,
                    tool_name=self.name,
                    cwe_id="CWE-918",
                    tags=["ssrf", "confirmed"],
                ))

        logger.debug(f"ssrfmap parsed {len(findings)} findings")
        return findings

    # ── helpers ────────────────────────────────────────────────
    @staticmethod
    def _severity_for_url(url: str) -> SeverityLevel:
        """Determine severity based on the accessed URL."""
        url_lower = url.lower()
        # Cloud metadata = critical
        if "169.254.169.254" in url_lower or "metadata" in url_lower:
            return SeverityLevel.CRITICAL
        # Internal services
        if any(s in url_lower for s in ("localhost", "127.0.0.1", "0.0.0.0", "internal", "10.", "172.16", "192.168")):
            return SeverityLevel.HIGH
        return SeverityLevel.MEDIUM

    @staticmethod
    def _classify_ssrf_target(url: str) -> str:
        """Classify the SSRF target for tagging."""
        url_lower = url.lower()
        if "169.254.169.254" in url_lower:
            return "cloud_metadata"
        if any(s in url_lower for s in ("localhost", "127.0.0.1")):
            return "localhost"
        if any(s in url_lower for s in ("10.", "172.16", "192.168")):
            return "internal_network"
        return "other"


__all__ = ["SsrfmapWrapper"]
