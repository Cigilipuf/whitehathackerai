"""
WhiteHatHacker AI — SQLMap Wrapper

Otomatik SQL injection tespiti ve exploitation.
Boolean-blind, time-blind, error-based, UNION, stacked queries destekli.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class SqlmapWrapper(SecurityTool):
    """
    SQLMap — Automatic SQL injection detection & exploitation.

    Desteklenen teknikler: B(oolean), E(rror), U(nion), S(tacked), T(ime-based)
    Desteklenen DBMS: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.
    """

    name = "sqlmap"
    category = ToolCategory.SCANNER
    description = "Automatic SQL injection and database takeover tool"
    binary_name = "sqlmap"
    requires_root = False
    risk_level = RiskLevel.MEDIUM
    default_timeout = 900  # 15min — deep injection testing

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", self.default_timeout)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        # sqlmap may have partial findings even on non-zero exit
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
        cmd = [self.binary_name]

        # Target: URL veya request file
        if "request_file" in options:
            cmd.extend(["-r", options["request_file"]])
        else:
            cmd.extend(["-u", target])

        # Parametreler
        if "param" in options:
            cmd.extend(["-p", options["param"]])
        if "data" in options:
            cmd.extend(["--data", options["data"]])
        if "cookie" in options:
            cmd.extend(["--cookie", options["cookie"]])
        if "headers" in options:
            for h in options["headers"]:
                cmd.extend(["--header", h])

        # Profil ayarları
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend([
                    "--level", "1",
                    "--risk", "1",
                    "--delay", "3",
                    "--random-agent",
                    "--technique", "BT",  # Sadece blind
                ])
            case ScanProfile.BALANCED:
                cmd.extend([
                    "--level", str(options.get("level", 3)),
                    "--risk", str(options.get("risk", 2)),
                    "--delay", "1",
                    "--random-agent",
                    "--technique", "BEUST",  # All techniques: Boolean/Error/Union/Stacked/Time
                    "--time-sec", "10",      # Time-based detection threshold
                ])
            case ScanProfile.AGGRESSIVE:
                cmd.extend([
                    "--level", "5",
                    "--risk", "3",
                    "--technique", "BEUST",
                    "--threads", "5",
                ])

        # DBMS hint
        if "dbms" in options:
            cmd.extend(["--dbms", options["dbms"]])

        # Enumeration düzeyi
        if options.get("enum_dbs"):
            cmd.append("--dbs")
        if options.get("enum_tables"):
            db = options.get("database", "")
            cmd.append("--tables")
            if db:
                cmd.extend(["-D", db])
        if options.get("current_user"):
            cmd.append("--current-user")

        # Güvenlik: sadece tespit, exploit etme (varsayılan)
        if not options.get("allow_exploit", False):
            # Explicitly prevent data extraction and OS shell
            cmd.extend(["--no-cast", "--no-escape"])
        else:
            logger.warning("sqlmap allow_exploit=True — data extraction enabled. Use responsibly.")

        # Batch mode — interaktif soru sormadan çalış
        cmd.extend(["--batch", "--flush-session"])

        # Çıktı formatı
        if options.get("output_dir"):
            cmd.extend(["--output-dir", options["output_dir"]])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # SQLMap önemli satırlar
        # [INFO] GET parameter 'id' is 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
        injectable_pattern = re.compile(
            r"\[INFO\]\s+(?:(?:GET|POST|Cookie|Header)\s+)?parameter\s+'(\S+)'\s+(?:appears to be|is)\s+'(.+?)'\s+injectable",
            re.IGNORECASE,
        )

        for match in injectable_pattern.finditer(raw_output):
            param = match.group(1)
            technique = match.group(2)

            _tech_class = self._classify_technique(technique)
            # Technique-aware confidence: blind techniques are FP-prone (v5.0-P3.3)
            _TECH_CONFIDENCE = {
                "boolean_based": 55.0,
                "time_based": 40.0,   # Very high FP risk — timing anomalies
                "error_based": 80.0,
                "union_based": 85.0,
                "stacked_queries": 85.0,
            }
            _sqli_conf = _TECH_CONFIDENCE.get(_tech_class, 70.0)
            findings.append(Finding(
                title=f"SQL Injection: parameter '{param}'",
                description=f"SQL injection found in '{param}' using technique: {technique}",
                vulnerability_type="sql_injection",
                severity=SeverityLevel.HIGH,
                confidence=_sqli_conf,
                target=target,
                parameter=param,
                tool_name=self.name,
                tags=["sqli", f"technique:{_tech_class}", "injection"],
                evidence=technique,
                cwe_id="CWE-89",
                metadata={"technique": technique, "parameter": param},
            ))

        # DBMS tespiti
        dbms_pattern = re.compile(
            r"\[INFO\]\s+the back-end DBMS is\s+(.+)",
            re.IGNORECASE,
        )
        for match in dbms_pattern.finditer(raw_output):
            dbms = match.group(1).strip()
            findings.append(Finding(
                title=f"Backend DBMS: {dbms}",
                description=f"Database management system identified: {dbms}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=90.0,
                target=target,
                tool_name=self.name,
                tags=["dbms", "info"],
                metadata={"dbms": dbms},
            ))

        # Payload bilgileri
        payload_pattern = re.compile(
            r"Payload:\s*(.+)",
            re.IGNORECASE,
        )
        for match in payload_pattern.finditer(raw_output):
            for f in findings:
                if f.vulnerability_type == "sql_injection":
                    f.payload = match.group(1).strip()
                    break

        # Veritabanları/kullanıcı bilgisi
        current_user_pattern = re.compile(r"current user:\s+'(\S+)'", re.IGNORECASE)
        cu_match = current_user_pattern.search(raw_output)
        if cu_match:
            findings.append(Finding(
                title=f"DB Current User: {cu_match.group(1)}",
                description=f"Current database user: {cu_match.group(1)}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.MEDIUM,
                confidence=95.0,
                target=target,
                tool_name=self.name,
                tags=["sqli", "db_user"],
            ))

        logger.debug(f"sqlmap parsed {len(findings)} findings")
        return findings

    @staticmethod
    def _classify_technique(technique: str) -> str:
        t = technique.lower()
        if "time" in t or "sleep" in t:
            return "time_based"
        if "boolean" in t:
            return "boolean_based"
        if "error" in t:
            return "error_based"
        if "union" in t:
            return "union_based"
        if "stacked" in t:
            return "stacked_queries"
        return "unknown"


__all__ = ["SqlmapWrapper"]
