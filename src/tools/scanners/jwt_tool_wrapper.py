"""
WhiteHatHacker AI — jwt_tool Wrapper

JWT (JSON Web Token) security testing tool.
Tests for algorithm confusion, key brute-force, claim tampering,
signature bypass, and other JWT vulnerabilities.
"""

from __future__ import annotations

import re
import shutil
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# JWT attack type → severity / confidence
_ATTACK_SEVERITY: dict[str, SeverityLevel] = {
    "alg_none": SeverityLevel.CRITICAL,
    "alg_confusion": SeverityLevel.CRITICAL,
    "kid_injection": SeverityLevel.HIGH,
    "jwks_spoof": SeverityLevel.HIGH,
    "jku_bypass": SeverityLevel.HIGH,
    "signature_bypass": SeverityLevel.CRITICAL,
    "claim_tamper": SeverityLevel.HIGH,
    "key_confusion": SeverityLevel.CRITICAL,
    "blank_password": SeverityLevel.HIGH,
    "weak_secret": SeverityLevel.HIGH,
    "expired_not_checked": SeverityLevel.MEDIUM,
    "null_signature": SeverityLevel.CRITICAL,
}

_ATTACK_CONFIDENCE: dict[str, float] = {
    "alg_none": 90.0,
    "alg_confusion": 85.0,
    "kid_injection": 80.0,
    "jwks_spoof": 80.0,
    "jku_bypass": 80.0,
    "signature_bypass": 90.0,
    "claim_tamper": 75.0,
    "key_confusion": 85.0,
    "blank_password": 85.0,
    "weak_secret": 80.0,
    "expired_not_checked": 70.0,
    "null_signature": 90.0,
}


class JwtToolWrapper(SecurityTool):
    """
    jwt_tool — JWT Security Testing Tool.

    Comprehensive JWT testing including algorithm confusion (none/HS↔RS),
    kid injection, JWKS spoofing, brute-force signing key, claim
    manipulation, and token replay.
    """

    name = "jwt_tool"
    category = ToolCategory.SCANNER
    description = "JWT (JSON Web Token) security testing tool"
    binary_name = "jwt_tool"
    requires_root = False
    risk_level = RiskLevel.MEDIUM

    # ── is_available ──────────────────────────────────────────
    def is_available(self) -> bool:
        """Check standalone jwt_tool binary or jwt_tool.py script."""
        path = shutil.which(self.binary_name)
        if path:
            self._binary_path = path
            return True

        # Fallback: python3 jwt_tool.py
        path = shutil.which("python3")
        if path:
            self._binary_path = path
            return True

        return False

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

        # Determine base command — standalone binary or python3 script
        jwt_binary = shutil.which("jwt_tool")
        if jwt_binary:
            cmd = [jwt_binary]
        else:
            script = options.get("script_path", "jwt_tool.py")
            cmd = ["python3", script]

        # JWT token (first positional argument)
        token = options.get("token", target)
        cmd.append(token)

        # Target URL for sending tampered tokens
        target_url = options.get("target_url")
        if target_url:
            cmd.extend(["-t", target_url])

        # Cookies
        if options.get("cookies"):
            cmd.extend(["-rc", options["cookies"]])

        # No proxy
        if options.get("no_proxy", False):
            cmd.append("-np")

        # Specific attack mode
        attack = options.get("attack")
        if attack:
            cmd.extend(["-X", attack])

        # Run all tests mode
        if options.get("all_tests", False):
            cmd.extend(["-M", "at"])

        # Custom signing key
        if options.get("sign_key"):
            cmd.extend(["-pk", options["sign_key"]])

        # Dictionary file for brute-force
        if options.get("dictionary"):
            cmd.extend(["-d", options["dictionary"]])

        # Claim injection
        if options.get("inject_claim"):
            cmd.extend(["-I", "-pc", options["inject_claim"]])

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                # Minimal tests — avoid aggressive scanning
                if not attack and not options.get("all_tests"):
                    cmd.extend(["-X", "a"])  # alg:none only
            case ScanProfile.BALANCED:
                # All tests if not specified
                if not attack and not options.get("all_tests"):
                    cmd.extend(["-M", "at"])
            case ScanProfile.AGGRESSIVE:
                # Full sweep — all tests + brute-force
                if not attack and not options.get("all_tests"):
                    cmd.extend(["-M", "at"])

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        seen: set[str] = set()

        # Define detection patterns
        patterns: list[tuple[re.Pattern[str], str, str]] = [
            (
                re.compile(r"alg(?:orithm)?\s*(?:=|:)?\s*none", re.IGNORECASE),
                "alg_none",
                "Algorithm 'none' accepted — unsigned tokens are valid",
            ),
            (
                re.compile(
                    r"(?:algorithm|alg)\s*confusion|(?:RS|ES)\d*\s*→?\s*HS\d*",
                    re.IGNORECASE,
                ),
                "alg_confusion",
                "Algorithm confusion vulnerability — RS→HS key confusion possible",
            ),
            (
                re.compile(r"key\s*confusion", re.IGNORECASE),
                "key_confusion",
                "Key confusion — public key used as HMAC secret",
            ),
            (
                re.compile(r"kid\s+(?:inject|sqli|path)", re.IGNORECASE),
                "kid_injection",
                "kid header parameter injection — SQL injection or path traversal",
            ),
            (
                re.compile(r"jwks?\s*(?:spoof|inject)", re.IGNORECASE),
                "jwks_spoof",
                "JWKS spoofing — attacker-controlled key set accepted",
            ),
            (
                re.compile(r"jku\s*(?:bypass|inject|spoof)", re.IGNORECASE),
                "jku_bypass",
                "jku header bypass — external JWKS URL accepted",
            ),
            (
                re.compile(
                    r"(?:signature|sig)\s*(?:bypass|stripped|removed|null|not\s*checked)",
                    re.IGNORECASE,
                ),
                "signature_bypass",
                "Signature validation bypass — token accepted without valid signature",
            ),
            (
                re.compile(r"(?:null|empty)\s+signature", re.IGNORECASE),
                "null_signature",
                "Null/empty signature accepted",
            ),
            (
                re.compile(r"(?:blank|empty)\s*password", re.IGNORECASE),
                "blank_password",
                "JWT signed with blank/empty password",
            ),
            (
                re.compile(r"weak\s*(?:secret|key|password)", re.IGNORECASE),
                "weak_secret",
                "JWT signed with a weak/guessable secret",
            ),
            (
                re.compile(r"tamper(?:ed|ing)?", re.IGNORECASE),
                "claim_tamper",
                "Token claim tampering accepted — modified claims are valid",
            ),
            (
                re.compile(
                    r"expir(?:ed|y|ation)\s*(?:not\s*)?(?:check|valid|enforc)",
                    re.IGNORECASE,
                ),
                "expired_not_checked",
                "Token expiration not properly checked",
            ),
        ]

        # Also look for generic VULNERABILITY / TAMPERED keywords
        generic_vuln_re = re.compile(
            r"\[?\+?\]?\s*(?:VULNERABILITY|VULN|EXPLOIT|TAMPERED|CRITICAL)\b",
            re.IGNORECASE,
        )

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            for pattern, attack_type, description in patterns:
                if pattern.search(line):
                    if attack_type in seen:
                        continue
                    seen.add(attack_type)

                    severity = _ATTACK_SEVERITY.get(
                        attack_type, SeverityLevel.HIGH
                    )
                    confidence = _ATTACK_CONFIDENCE.get(attack_type, 70.0)

                    findings.append(Finding(
                        title=f"JWT Vulnerability ({attack_type})",
                        description=(
                            f"jwt_tool detected: {description}. "
                            f"Target: {target}"
                        ),
                        vulnerability_type="jwt_vulnerability",
                        severity=severity,
                        confidence=confidence,
                        target=target,
                        evidence=line[:500],
                        tool_name=self.name,
                        cwe_id="CWE-345",
                        tags=["jwt", attack_type],
                        metadata={
                            "attack_type": attack_type,
                            "raw_line": line[:500],
                        },
                    ))
                    break  # one match per line

            # Catch generic vulnerability flags not matched above
            if generic_vuln_re.search(line) and not any(
                p.search(line) for p, _, _ in patterns
            ):
                dedup_key = f"generic:{line[:80]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(Finding(
                    title=f"JWT Issue Detected: {line[:80]}",
                    description=(
                        f"jwt_tool flagged a potential JWT issue: {line[:300]}"
                    ),
                    vulnerability_type="jwt_vulnerability",
                    severity=SeverityLevel.MEDIUM,
                    confidence=55.0,
                    target=target,
                    evidence=line[:500],
                    tool_name=self.name,
                    cwe_id="CWE-345",
                    tags=["jwt", "generic"],
                    metadata={"raw_line": line[:500]},
                ))

        logger.debug(f"jwt_tool parsed {len(findings)} findings")
        return findings


__all__ = ["JwtToolWrapper"]
