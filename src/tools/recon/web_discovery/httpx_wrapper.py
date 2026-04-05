"""
WhiteHatHacker AI — HTTPX Wrapper

Fast multi-purpose HTTP toolkit.
HTTP probing, teknoloji tespiti, durum kodu, başlık çıkarma.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


def _resolve_httpx_binary() -> str:
    """Resolve ProjectDiscovery httpx binary (NOT Python httpx)."""
    import os
    import shutil
    # Priority: ~/go/bin/httpx (Go ELF binary)
    go_httpx = os.path.expanduser("~/go/bin/httpx")
    if os.path.isfile(go_httpx):
        return go_httpx
    # Fallback: try system-wide (check it's ELF, not Python script)
    for p in ["/usr/local/bin/httpx", "/usr/bin/httpx"]:
        if os.path.isfile(p):
            with open(p, "rb") as f:
                magic = f.read(4)
            if magic == b"\x7fELF":
                return p
    # Last resort
    return shutil.which("httpx") or "httpx"


class HttpxWrapper(SecurityTool):
    """
    httpx — Fast HTTP probe & tech detection (ProjectDiscovery).

    Subdomain listesini canlılık kontrolünden geçirir,
    teknoloji ve CDN/WAF tespit eder.

    NOT: binary_name Python httpx (encode) ile çakışabilir.
    _resolve_httpx_binary() Go binary'sini açıkça bulur.
    """

    name = "httpx"
    category = ToolCategory.RECON_WEB
    description = "Fast HTTP/S probing, tech detect, status codes, titles"
    binary_name = "httpx"  # overridden in __init__
    requires_root = False
    risk_level = RiskLevel.SAFE

    def __init__(self) -> None:
        super().__init__()
        self.binary_name = _resolve_httpx_binary()
        self._binary_path = self.binary_name

    def is_available(self) -> bool:
        """Check Go httpx binary exists (not Python httpx)."""
        import os
        if os.path.isfile(self.binary_name):
            # Verify it's ELF (Go binary), not Python script
            try:
                with open(self.binary_name, "rb") as f:
                    magic = f.read(4)
                return magic == b"\x7fELF"
            except OSError:
                return False
        return False

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
        combined = stdout
        if stderr:
            combined = f"{stdout}\n{stderr}" if stdout else stderr
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

    async def run_batch(
        self,
        targets: list[str],
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        """
        Batch probe multiple targets at once using pipe-based input.

        Much more efficient than calling run() per host.
        httpx reads targets from stdin when no -u/-l is provided.
        """
        import tempfile
        import os

        options = options or {}

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="httpx_targets_"
        ) as tf:
            tf.write("\n".join(targets))
            tf.write("\n")
            targets_file = tf.name

        try:
            cmd = [self.binary_name, "-l", targets_file]

            # Standard output fields
            cmd.extend([
                "-status-code",
                "-title",
                "-tech-detect",
                "-content-length",
                "-web-server",
                "-follow-redirects",
                "-json",
            ])

            match profile:
                case ScanProfile.STEALTH:
                    cmd.extend(["-rate-limit", "2", "-timeout", "30", "-threads", "5"])
                case ScanProfile.BALANCED:
                    cmd.extend(["-rate-limit", "10", "-timeout", "15", "-threads", "25", "-retries", "2"])
                case ScanProfile.AGGRESSIVE:
                    cmd.extend(["-rate-limit", "50", "-timeout", "10", "-threads", "50"])

            timeout = options.get("timeout", 600)

            logger.info(f"httpx batch probe | targets={len(targets)} | profile={profile}")
            stdout, stderr, exit_code = await self.execute_command(cmd, timeout=timeout)
            combined = stdout
            if stderr:
                combined = f"{stdout}\n{stderr}" if stdout else stderr
            findings = self.parse_output(combined, ",".join(targets[:3]))

            return ToolResult(
                tool_name=self.name,
                success=(exit_code == 0 or len(findings) > 0),
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                findings=findings,
                command=" ".join(cmd),
                target=f"batch({len(targets)})",
            )
        finally:
            try:
                os.unlink(targets_file)
            except OSError:
                pass

    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        options = options or {}
        cmd = [self.binary_name]

        # Target: URL veya domain
        cmd.extend(["-u", target])

        # Standart output alanları
        cmd.extend([
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-web-server",
            "-follow-redirects",
            "-json",
        ])

        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["-rate-limit", "2", "-timeout", "30"])
            case ScanProfile.BALANCED:
                cmd.extend(["-rate-limit", "10", "-timeout", "15", "-retries", "2"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["-rate-limit", "50", "-timeout", "10", "-threads", "50"])

        if "ports" in options:
            cmd.extend(["-ports", options["ports"]])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # JSON satır parse
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # Plain text fallback
                if line.startswith("http"):
                    findings.append(Finding(
                        title=f"Live Host: {line}",
                        description=f"HTTP service detected at {line}",
                        vulnerability_type="live_host",
                        severity=SeverityLevel.INFO,
                        confidence=90.0,
                        target=line,
                        endpoint=line,
                        tool_name=self.name,
                        tags=["http", "alive"],
                    ))
                continue

            url = data.get("url", data.get("input", target))
            status = data.get("status_code", data.get("status-code", 0))
            title = data.get("title", "")
            tech = data.get("tech", [])
            server = data.get("webserver", data.get("web-server", ""))
            content_length = data.get("content_length", data.get("content-length", 0))

            desc_parts = [f"URL: {url}", f"Status: {status}"]
            if title:
                desc_parts.append(f"Title: {title}")
            if server:
                desc_parts.append(f"Server: {server}")
            if tech:
                desc_parts.append(f"Tech: {', '.join(tech)}")

            tags = ["http", "alive", f"status:{status}"]
            if tech:
                tags.extend([f"tech:{t.lower()}" for t in tech[:5]])

            findings.append(Finding(
                title=f"Live Host: {url} [{status}]",
                description=" | ".join(desc_parts),
                vulnerability_type="live_host",
                severity=SeverityLevel.INFO,
                confidence=95.0,
                target=url,
                endpoint=url,
                tool_name=self.name,
                tags=tags,
                metadata={
                    "status_code": status,
                    "title": title,
                    "technologies": tech,
                    "server": server,
                    "content_length": content_length,
                },
            ))

            # Güvenlik başlıkları eksikliği kontrol
            if status == 200 and server:
                self._check_security_headers(data, url, findings)

        logger.debug(f"httpx parsed {len(findings)} findings")
        return findings

    def _check_security_headers(
        self, data: dict, url: str, findings: list[Finding]
    ) -> None:
        """Eksik güvenlik başlıklarını tespit et."""
        # httpx JSON'da header verisi varsa kontrol et
        headers = data.get("header", {})
        if not headers:
            return

        header_checks = {
            "strict-transport-security": "Missing HSTS header",
            "x-content-type-options": "Missing X-Content-Type-Options",
            "x-frame-options": "Missing X-Frame-Options (clickjacking risk)",
            "content-security-policy": "Missing Content-Security-Policy",
        }

        for header, desc in header_checks.items():
            if header not in {k.lower() for k in headers}:
                findings.append(Finding(
                    title=f"Missing Header: {header} on {url}",
                    description=desc,
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.LOW,
                    confidence=85.0,
                    target=url,
                    endpoint=url,
                    tool_name=self.name,
                    tags=["header", "security", "misconfiguration"],
                ))


__all__ = ["HttpxWrapper"]
