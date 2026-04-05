"""
WhiteHatHacker AI — LDAP Search Wrapper

LDAP enumeration — directory structure, users, groups, ACLs.
"""

from __future__ import annotations

import re


from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class LdapsearchWrapper(SecurityTool):
    """
    ldapsearch — LDAP directory enumeration.

    Queries LDAP for: base DN, users, groups, computer objects,
    service principals, password policies, and misconfigurations.
    """

    name = "ldapsearch"
    category = ToolCategory.NETWORK
    description = "LDAP directory enumeration — users, groups, policies"
    binary_name = "ldapsearch"
    requires_root = False
    risk_level = RiskLevel.LOW

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        findings: list[Finding] = []
        stdout = ""
        stderr = ""
        exit_code = 1

        # Step 1: Try anonymous bind to get root DSE
        cmd_rootdse = [self.binary_name, "-x", "-H", f"ldap://{target}", "-s", "base", "-b", ""]
        stdout, stderr, exit_code = await self.execute_command(cmd_rootdse, timeout=1200)

        if exit_code == 0 and stdout.strip():
            findings.append(Finding(
                title="LDAP Anonymous Bind Allowed",
                description="Anonymous LDAP bind is permitted, allowing directory enumeration.",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=95.0, target=target, tool_name=self.name,
                cwe_id="CWE-287",
                tags=["ldap", "anonymous_bind"],
            ))

            # Extract base DN
            base_dn = self._extract_base_dn(stdout)
            if base_dn:
                findings.append(Finding(
                    title=f"LDAP Base DN: {base_dn}",
                    description=f"Base Distinguished Name: {base_dn}",
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.INFO,
                    confidence=90.0, target=target, tool_name=self.name,
                    tags=["ldap", "base_dn"],
                ))

                # Step 2: Enumerate users
                cmd_users = [
                    self.binary_name, "-x", "-H", f"ldap://{target}",
                    "-b", base_dn,
                    "(objectClass=person)",
                    "sAMAccountName", "mail", "memberOf",
                    "-LLL",
                ]
                u_stdout, _, u_exit = await self.execute_command(cmd_users, timeout=1200)
                if u_exit == 0:
                    findings.extend(self._parse_users(u_stdout, target))

                # Step 3: Enumerate groups
                cmd_groups = [
                    self.binary_name, "-x", "-H", f"ldap://{target}",
                    "-b", base_dn,
                    "(objectClass=group)",
                    "cn", "member",
                    "-LLL",
                ]
                g_stdout, _, g_exit = await self.execute_command(cmd_groups, timeout=1200)
                if g_exit == 0:
                    findings.extend(self._parse_groups(g_stdout, target))
        else:
            # Try with credentials
            if "username" in options and "password" in options:
                cmd_auth = self.build_command(target, options, profile)
                stdout, stderr, exit_code = await self.execute_command(cmd_auth, timeout=1200)
                findings.extend(self.parse_output(stdout, target))

        all_stdout = stdout
        all_stderr = stderr

        return ToolResult(
            tool_name=self.name, success=len(findings) > 0,
            exit_code=exit_code, stdout=all_stdout, stderr=all_stderr,
            findings=findings, command=f"ldapsearch {target}", target=target,
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        options = options or {}
        cmd = [self.binary_name, "-x", "-H", f"ldap://{target}"]

        if "username" in options:
            cmd.extend(["-D", options["username"]])
        if "password" in options:
            cmd.extend(["-w", options["password"]])
        if "base_dn" in options:
            cmd.extend(["-b", options["base_dn"]])
        if "filter" in options:
            cmd.append(options["filter"])
        else:
            cmd.append("(objectClass=*)")

        cmd.append("-LLL")
        return cmd

    def _extract_base_dn(self, rootdse_output: str) -> str:
        match = re.search(r"namingContexts:\s*(.+)", rootdse_output)
        if match:
            return match.group(1).strip()
        match = re.search(r"defaultNamingContext:\s*(.+)", rootdse_output)
        if match:
            return match.group(1).strip()
        # Try to build from rootDomainNamingContext
        match = re.search(r"rootDomainNamingContext:\s*(.+)", rootdse_output)
        if match:
            return match.group(1).strip()
        return ""

    def _parse_users(self, output: str, target: str) -> list[Finding]:
        findings = []
        user_pattern = re.compile(r"sAMAccountName:\s*(.+)", re.IGNORECASE)
        users = user_pattern.findall(output)

        if users:
            findings.append(Finding(
                title=f"LDAP Users: {len(users)} accounts",
                description=f"Users found: {', '.join(u.strip() for u in users[:30])}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.LOW,
                confidence=90.0, target=target, tool_name=self.name,
                tags=["ldap", "user_enum"],
                metadata={"users": [u.strip() for u in users]},
            ))

        # Check for admin accounts
        admin_users = [u for u in users if any(
            kw in u.lower() for kw in ("admin", "root", "superuser", "svc_", "service")
        )]
        if admin_users:
            findings.append(Finding(
                title=f"LDAP Privileged Accounts: {len(admin_users)}",
                description=f"Privileged accounts found: {', '.join(a.strip() for a in admin_users)}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.MEDIUM,
                confidence=75.0, target=target, tool_name=self.name,
                tags=["ldap", "privileged_accounts"],
            ))

        return findings

    def _parse_groups(self, output: str, target: str) -> list[Finding]:
        findings = []
        group_pattern = re.compile(r"cn:\s*(.+)", re.IGNORECASE)
        groups = group_pattern.findall(output)

        if groups:
            findings.append(Finding(
                title=f"LDAP Groups: {len(groups)}",
                description=f"Groups: {', '.join(g.strip() for g in groups[:30])}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=85.0, target=target, tool_name=self.name,
                tags=["ldap", "group_enum"],
                metadata={"groups": [g.strip() for g in groups]},
            ))

        return findings

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings = []
        users = self._parse_users(raw_output, target)
        groups = self._parse_groups(raw_output, target)
        findings.extend(users)
        findings.extend(groups)
        return findings


__all__ = ["LdapsearchWrapper"]
