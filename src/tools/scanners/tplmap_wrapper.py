"""
WhiteHatHacker AI — Tplmap Wrapper

Server-Side Template Injection (SSTI) detection and exploitation.
Supports Jinja2, Mako, Twig, Smarty, Freemarker, Velocity, Jade, and more.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# Known template engines Tplmap can detect
_TEMPLATE_ENGINES = {
    "jinja2", "mako", "twig", "smarty", "freemarker", "velocity",
    "jade", "pug", "dot", "marko", "nunjucks", "ejs", "slim",
    "erb", "tornado", "cheetah", "genshi", "chameleon",
}


class TplmapWrapper(SecurityTool):
    """
    Tplmap — Server-Side Template Injection detection and exploitation.

    Automatically detects SSTI in multiple template engines and can
    escalate to OS command execution, file read/write, and shell access.
    """

    name = "tplmap"
    category = ToolCategory.SCANNER
    description = "Server-Side Template Injection scanner and exploitation tool"
    binary_name = "tplmap"
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
        url = target if target.startswith("http") else f"http://{target}"

        cmd = [self.binary_name, "-u", url]

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["--level", "1"])
            case ScanProfile.BALANCED:
                cmd.extend(["--level", "3"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["--level", "5"])

        # Specific template engine to test
        if options.get("engine"):
            cmd.extend(["-e", options["engine"]])

        # POST data
        if options.get("data"):
            cmd.extend(["-d", options["data"]])

        # Cookie
        if options.get("cookie"):
            cmd.extend(["--cookie", options["cookie"]])

        # Custom headers
        for h in options.get("headers", []):
            cmd.extend(["--header", h])

        # Proxy
        if options.get("proxy"):
            cmd.extend(["--proxy", options["proxy"]])

        # OS shell (only if explicitly requested — high risk)
        if options.get("os_shell"):
            cmd.append("--os-shell")
        elif options.get("os_cmd"):
            cmd.extend(["--os-cmd", options["os_cmd"]])

        # File read (for PoC)
        if options.get("tpl_shell"):
            cmd.append("--tpl-shell")
        if options.get("tpl_code"):
            cmd.extend(["--tpl-code", options["tpl_code"]])

        # Bind/reverse shell
        if options.get("bind_shell"):
            cmd.extend(["--bind-shell", str(options["bind_shell"])])
        if options.get("reverse_shell"):
            cmd.extend(["--reverse-shell", options["reverse_shell"]])

        # Force overwrite (skip confirmation)
        cmd.append("--force-overwrite")

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        # ---- Pattern 1: Injection point found ----
        # "[+] Injection point found"  or  "Injection point detected"
        injection_re = re.compile(
            r"\[\+\]\s*(?:Injection\s+point|SSTI)\s+(?:found|detected|confirmed)\s*(?:in\s+parameter\s+'?(\S+?)'?)?",
            re.IGNORECASE,
        )
        for match in injection_re.finditer(raw_output):
            param = match.group(1) if match.group(1) else ""
            engine = self._extract_engine(raw_output)

            findings.append(Finding(
                title=f"SSTI: Injection point found{f' in {param!r}' if param else ''}",
                description=(
                    f"Tplmap confirmed Server-Side Template Injection. "
                    f"Engine: {engine or 'unknown'}. "
                    f"{'Parameter: ' + param + '.' if param else ''}"
                ),
                vulnerability_type="ssti",
                severity=SeverityLevel.CRITICAL,
                confidence=90.0,
                target=target,
                parameter=param,
                tool_name=self.name,
                cwe_id="CWE-1336",
                tags=["ssti", "template_injection", engine.lower() if engine else "unknown_engine"],
                metadata={"engine": engine, "parameter": param},
            ))

        # ---- Pattern 2: Template engine identified ----
        engine_re = re.compile(
            r"(?:Template\s+engine|Engine)\s*[:\-]\s*(\w+)",
            re.IGNORECASE,
        )
        for match in engine_re.finditer(raw_output):
            engine = match.group(1).strip()
            # Only add as a separate finding if no injection was found
            if not any(f.vulnerability_type == "ssti" for f in findings):
                findings.append(Finding(
                    title=f"Template Engine Identified: {engine}",
                    description=f"Tplmap identified the template engine as: {engine}",
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.INFO,
                    confidence=85.0,
                    target=target,
                    tool_name=self.name,
                    tags=["ssti", "engine_detect", engine.lower()],
                    metadata={"engine": engine},
                ))
            else:
                # Enrich existing SSTI findings with engine info
                for f in findings:
                    if f.vulnerability_type == "ssti" and not f.metadata.get("engine"):
                        f.metadata["engine"] = engine
                        f.tags.append(engine.lower())

        # ---- Pattern 3: OS shell / command execution ----
        shell_re = re.compile(
            r"\[\+\]\s*(?:OS\s+shell|OS\s+command\s+execution)\s+(?:available|confirmed|ready)",
            re.IGNORECASE,
        )
        if shell_re.search(raw_output):
            findings.append(Finding(
                title="SSTI: OS Command Execution Available",
                description=(
                    "Tplmap confirmed OS command execution is possible via SSTI. "
                    "This escalates template injection to full Remote Code Execution (RCE)."
                ),
                vulnerability_type="ssti",
                severity=SeverityLevel.CRITICAL,
                confidence=95.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-1336",
                tags=["ssti", "rce", "os_shell"],
            ))

        # ---- Pattern 4: File read confirmed ----
        file_re = re.compile(
            r"\[\+\]\s*(?:File\s+read|File\s+content)\s*[:\-]\s*(\S+)",
            re.IGNORECASE,
        )
        for match in file_re.finditer(raw_output):
            filepath = match.group(1).strip()
            findings.append(Finding(
                title=f"SSTI: File read — {filepath}",
                description=f"Tplmap read local file via SSTI: {filepath}",
                vulnerability_type="ssti",
                severity=SeverityLevel.HIGH,
                confidence=90.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-1336",
                tags=["ssti", "file_read", "lfi"],
                metadata={"file_path": filepath},
            ))

        # ---- Pattern 5: Blind injection confirmed ----
        blind_re = re.compile(
            r"\[\+\]\s*(?:Blind|Time-based)\s+(?:injection|SSTI)\s+(?:confirmed|detected)",
            re.IGNORECASE,
        )
        if blind_re.search(raw_output):
            findings.append(Finding(
                title="SSTI: Blind/Time-based Injection Confirmed",
                description="Tplmap confirmed blind/time-based Server-Side Template Injection.",
                vulnerability_type="ssti",
                severity=SeverityLevel.HIGH,
                confidence=60.0,  # blind/time-based SSTI — high FP risk
                target=target,
                tool_name=self.name,
                cwe_id="CWE-1336",
                tags=["ssti", "blind", "time_based"],
            ))

        # ---- Pattern 6: Not vulnerable ----
        if not findings and re.search(
            r"(?:not\s+(?:vulnerable|injectable)|no\s+(?:injection|SSTI)\s+(?:found|detected))",
            raw_output,
            re.IGNORECASE,
        ):
            findings.append(Finding(
                title="No SSTI Found",
                description="Tplmap did not detect Server-Side Template Injection in the target.",
                vulnerability_type="info",
                severity=SeverityLevel.INFO,
                confidence=60.0,
                target=target,
                tool_name=self.name,
                tags=["negative", "clean"],
            ))

        logger.debug(f"tplmap parsed {len(findings)} findings")
        return findings

    # ── helpers ────────────────────────────────────────────────
    @staticmethod
    def _extract_engine(raw_output: str) -> str:
        """Extract template engine name from output."""
        engine_re = re.compile(
            r"(?:Template\s+engine|Engine)\s*[:\-]\s*(\w+)",
            re.IGNORECASE,
        )
        m = engine_re.search(raw_output)
        if m:
            return m.group(1).strip()

        # Fallback: check for known engine names in output
        output_lower = raw_output.lower()
        for engine in _TEMPLATE_ENGINES:
            if engine in output_lower:
                return engine

        return ""


__all__ = ["TplmapWrapper"]
