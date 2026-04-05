"""
WhiteHatHacker AI — NoSQLMap Wrapper

NoSQL injection testing and exploitation for MongoDB, CouchDB, etc.
Since NoSQLMap is interactive, this wrapper automates common injection
payloads via command-line options and parses results.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# Common NoSQL injection payload patterns for detection
_NOSQL_INDICATORS = [
    "injection successful",
    "authentication bypass",
    "injection detected",
    "data extracted",
    "database enumerated",
    "collection found",
    "document found",
]


class NosqlmapWrapper(SecurityTool):
    """
    NoSQLMap — Automated NoSQL injection testing and exploitation.

    Tests for MongoDB, CouchDB, and other NoSQL database injection
    vulnerabilities including authentication bypass, data extraction,
    and database enumeration.
    """

    name = "nosqlmap"
    category = ToolCategory.SCANNER
    description = "NoSQL database injection detection and exploitation tool"
    binary_name = "nosqlmap"
    requires_root = False
    risk_level = RiskLevel.MEDIUM

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

        cmd = [self.binary_name]

        # Target URL
        if target:
            cmd.extend(["--url", target if target.startswith("http") else f"http://{target}"])

        # Attack type / options
        # NoSQLMap uses numeric menu items; for automated CLI use
        # we rely on available command-line flags.
        attack = options.get("attack", "")
        if attack:
            cmd.extend(["--attack", attack])

        # Target parameter
        if options.get("param"):
            cmd.extend(["--param", options["param"]])

        # POST data
        if options.get("data"):
            cmd.extend(["--data", options["data"]])

        # HTTP method
        if options.get("method"):
            cmd.extend(["--method", options["method"]])

        # Request headers
        for h in options.get("headers", []):
            cmd.extend(["--header", h])

        # Cookie
        if options.get("cookie"):
            cmd.extend(["--cookie", options["cookie"]])

        # Database platform hint
        if options.get("platform"):
            cmd.extend(["--platform", options["platform"]])  # mongodb, couchdb, etc.

        # Proxy
        if options.get("proxy"):
            cmd.extend(["--proxy", options["proxy"]])

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["--delay", "3", "--level", "1"])
                # Minimal payloads
                if not options.get("techniques"):
                    cmd.extend(["--techniques", "auth_bypass"])
            case ScanProfile.BALANCED:
                cmd.extend(["--delay", "1", "--level", "2"])
                if not options.get("techniques"):
                    cmd.extend(["--techniques", "auth_bypass,injection"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["--level", "3"])
                if not options.get("techniques"):
                    cmd.extend(["--techniques", "auth_bypass,injection,enum"])

        # Batch / non-interactive mode
        cmd.append("--batch")

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        output_lower = raw_output.lower()

        # ---- Pattern 1: Authentication bypass ----
        auth_bypass_re = re.compile(
            r"(?:authentication\s+bypass|auth\s+bypass)\s+(?:successful|confirmed|detected)\s*(?:on\s+parameter\s+'?(\S+?)'?)?",
            re.IGNORECASE,
        )
        for match in auth_bypass_re.finditer(raw_output):
            param = match.group(1) if match.group(1) else ""
            findings.append(Finding(
                title=f"NoSQL Auth Bypass{f': parameter {param!r}' if param else ''}",
                description=(
                    "NoSQLMap confirmed authentication bypass via NoSQL injection. "
                    "An attacker can bypass login mechanisms using crafted NoSQL payloads "
                    f"(e.g., {{\"$ne\": \"\"}} or {{\"$gt\": \"\"}})."
                    f"{f' Vulnerable parameter: {param}.' if param else ''}"
                ),
                vulnerability_type="nosql_injection",
                severity=SeverityLevel.CRITICAL,
                confidence=90.0,
                target=target,
                parameter=param,
                tool_name=self.name,
                cwe_id="CWE-943",
                tags=["nosql_injection", "auth_bypass", "mongodb"],
                metadata={"technique": "authentication_bypass", "parameter": param},
            ))

        # ---- Pattern 2: NoSQL injection detected ----
        injection_re = re.compile(
            r"(?:NoSQL\s+)?injection\s+(?:detected|confirmed|successful|found)\s*"
            r"(?:in\s+parameter\s+'?(\S+?)'?)?\s*"
            r"(?:using\s+(?:technique|method)\s+'?(\S+?)'?)?",
            re.IGNORECASE,
        )
        for match in injection_re.finditer(raw_output):
            param = match.group(1) if match.group(1) else ""
            technique = match.group(2) if match.group(2) else "unknown"

            # Avoid duplicates with auth bypass
            if any(f.metadata.get("technique") == "authentication_bypass" and f.parameter == param for f in findings):
                continue

            findings.append(Finding(
                title=f"NoSQL Injection{f' in {param!r}' if param else ''}",
                description=(
                    f"NoSQLMap detected NoSQL injection vulnerability. "
                    f"Technique: {technique}. "
                    f"{'Parameter: ' + param + '.' if param else ''}"
                ),
                vulnerability_type="nosql_injection",
                severity=SeverityLevel.HIGH,
                confidence=85.0,
                target=target,
                parameter=param,
                tool_name=self.name,
                cwe_id="CWE-943",
                tags=["nosql_injection", technique.lower()],
                metadata={"technique": technique, "parameter": param},
            ))

        # ---- Pattern 3: Database enumeration ----
        db_enum_re = re.compile(
            r"(?:database|collection|table)\s+(?:enumerated|found|discovered)\s*[:\-]\s*(.+)",
            re.IGNORECASE,
        )
        for match in db_enum_re.finditer(raw_output):
            items = match.group(1).strip()[:300]
            findings.append(Finding(
                title="NoSQL: Database enumeration successful",
                description=f"NoSQLMap enumerated database objects: {items}",
                vulnerability_type="nosql_injection",
                severity=SeverityLevel.HIGH,
                confidence=88.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-943",
                tags=["nosql_injection", "enumeration"],
                evidence=items,
                metadata={"enumerated": items},
            ))

        # ---- Pattern 4: Data extraction ----
        data_re = re.compile(
            r"(?:data\s+extracted|document\s+(?:found|extracted))\s*[:\-]\s*(.*)",
            re.IGNORECASE,
        )
        for match in data_re.finditer(raw_output):
            data = match.group(1).strip()[:500]
            findings.append(Finding(
                title="NoSQL: Data extraction confirmed",
                description=f"NoSQLMap extracted data via NoSQL injection: {data[:200]}",
                vulnerability_type="nosql_injection",
                severity=SeverityLevel.CRITICAL,
                confidence=92.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-943",
                tags=["nosql_injection", "data_extraction"],
                evidence=data,
            ))

        # ---- Pattern 5: Platform/DBMS detection ----
        platform_re = re.compile(
            r"(?:backend|database|DBMS|platform)\s+(?:is|detected|identified)\s*[:\-]?\s*(\S+)",
            re.IGNORECASE,
        )
        for match in platform_re.finditer(raw_output):
            platform = match.group(1).strip()
            findings.append(Finding(
                title=f"NoSQL Backend: {platform}",
                description=f"NoSQLMap identified the NoSQL backend: {platform}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=80.0,
                target=target,
                tool_name=self.name,
                tags=["nosql", "db_detect", platform.lower()],
                metadata={"platform": platform},
            ))

        # ---- Pattern 6: Payload information ----
        payload_re = re.compile(
            r"(?:Payload|Injected)\s*[:\-]\s*(.+)",
            re.IGNORECASE,
        )
        for match in payload_re.finditer(raw_output):
            payload = match.group(1).strip()[:300]
            # Attach to existing injection findings
            for f in findings:
                if f.vulnerability_type == "nosql_injection" and not f.payload:
                    f.payload = payload
                    break

        # ---- Pattern 7: Not vulnerable ----
        if not findings and any(
            neg in output_lower
            for neg in ("not vulnerable", "no injection", "not injectable", "no nosql injection")
        ):
            findings.append(Finding(
                title="No NoSQL Injection Found",
                description="NoSQLMap did not detect NoSQL injection in the target.",
                vulnerability_type="info",
                severity=SeverityLevel.INFO,
                confidence=60.0,
                target=target,
                tool_name=self.name,
                tags=["negative", "clean"],
            ))

        logger.debug(f"nosqlmap parsed {len(findings)} findings")
        return findings


__all__ = ["NosqlmapWrapper"]
