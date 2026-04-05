"""
WhiteHatHacker AI — Auto Report Draft Generator (P6-4)

Automatically generates individual HackerOne/Bugcrowd-style draft reports
for each verified HIGH/CRITICAL finding. Reports are saved as markdown files
in the output directory for human review before submission.

Key features:
- Per-finding draft (not whole-report): each finding gets its own report file
- Platform-aware formatting (HackerOne, Bugcrowd, generic)
- CVSS scoring with default vectors
- PoC code inclusion and evidence attachment
- Never auto-submits — all drafts require human review
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

# CVSS v3.1 default vectors for common vulnerability types
_CVSS_DEFAULTS: dict[str, tuple[str, float]] = {
    "xss": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "sqli": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "ssrf": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6),
    "rce": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "ssti": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "idor": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1),
    "lfi": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "xxe": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "csrf": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 6.5),
    "cors": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),
    "redirect": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "crlf": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", 4.7),
    "jwt": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "deserialization": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "http_smuggling": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", 8.1),
    "subdomain_takeover": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
    "info_disclosure": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
}

# CWE defaults for common vuln types
_CWE_DEFAULTS: dict[str, str] = {
    "xss": "CWE-79: Improper Neutralization of Input During Web Page Generation",
    "sqli": "CWE-89: Improper Neutralization of Special Elements in SQL Command",
    "ssrf": "CWE-918: Server-Side Request Forgery",
    "rce": "CWE-78: Improper Neutralization of Special Elements in OS Command",
    "ssti": "CWE-1336: Improper Neutralization of Special Elements in Template Engine",
    "idor": "CWE-639: Authorization Bypass Through User-Controlled Key",
    "lfi": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
    "xxe": "CWE-611: Improper Restriction of XML External Entity Reference",
    "csrf": "CWE-352: Cross-Site Request Forgery",
    "cors": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
    "redirect": "CWE-601: URL Redirection to Untrusted Site",
    "crlf": "CWE-93: Improper Neutralization of CRLF Sequences",
    "jwt": "CWE-347: Improper Verification of Cryptographic Signature",
    "deserialization": "CWE-502: Deserialization of Untrusted Data",
    "http_smuggling": "CWE-444: Inconsistent Interpretation of HTTP Requests",
    "subdomain_takeover": "CWE-284: Improper Access Control",
    "nosqli": "CWE-943: Improper Neutralization of Special Elements in Data Query Logic",
}


def _normalise_vuln_type(raw: str) -> str:
    """Collapse vuln type variants into canonical form for lookup."""
    v = raw.strip().lower().replace(" ", "_").replace("-", "_")
    # Simple aliases
    aliases = {
        "xss_reflected": "xss", "xss_stored": "xss", "xss_dom": "xss",
        "sql_injection": "sqli", "command_injection": "rce",
        "open_redirect": "redirect", "cors_misconfiguration": "cors",
    }
    return aliases.get(v, v)


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert *val* to float. Returns *default* on failure."""
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _coerce_str(val: Any) -> str:
    """Ensure *val* is a string; flatten list to first element."""
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        return str(val[0]) if val else ""
    if val is None:
        return ""
    return str(val)


class AutoDraftGenerator:
    """
    Generates per-finding draft reports for human review.

    Only processes findings meeting threshold:
    - severity >= HIGH, OR
    - severity == MEDIUM and confidence >= 80
    """

    def __init__(
        self,
        output_dir: str = "output/drafts",
        platform: str = "hackerone",
        target: str = "",
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.platform = platform.lower()
        self.target = target
        self._drafts_generated: list[Path] = []

    def should_draft(self, finding: dict[str, Any]) -> bool:
        """Check if a finding qualifies for auto-draft."""
        severity = _coerce_str(finding.get("severity") or "info").strip().lower()
        confidence = _safe_float(finding.get("confidence_score") or finding.get("confidence") or 0)

        if severity in ("critical", "high"):
            return True
        if severity == "medium" and confidence >= 80:
            return True
        return False

    def generate_draft(
        self,
        finding: dict[str, Any],
        scan_id: str = "",
    ) -> Path | None:
        """
        Generate a draft report markdown file for a single finding.

        Returns the path to the generated file, or None if skipped.
        """
        if not self.should_draft(finding):
            return None

        vuln_type = _normalise_vuln_type(
            _coerce_str(finding.get("vulnerability_type")
            or finding.get("type")
            or "unknown")
        )
        title = _coerce_str(finding.get("title") or "Unnamed Vulnerability")
        severity = _coerce_str(finding.get("severity") or "info").strip().upper()
        url = _coerce_str(finding.get("url") or finding.get("endpoint") or finding.get("target") or "")
        param = _coerce_str(finding.get("parameter") or "")
        payload = _coerce_str(finding.get("payload") or "")
        description = _coerce_str(finding.get("description") or "")
        evidence = _coerce_str(finding.get("evidence") or "")
        tool = _coerce_str(finding.get("tool") or finding.get("tool_name") or "")
        confidence = _safe_float(finding.get("confidence_score") or finding.get("confidence") or 0)
        cvss_vector, cvss_score = _CVSS_DEFAULTS.get(vuln_type, ("", 0.0))
        cwe = _CWE_DEFAULTS.get(vuln_type, "")

        # Override with finding-specific values if present
        if finding.get("cvss_score"):
            cvss_score = _safe_float(finding["cvss_score"], cvss_score)
        if finding.get("cvss_vector"):
            cvss_vector = _coerce_str(finding["cvss_vector"])
        if finding.get("cwe_id"):
            cwe = _coerce_str(finding["cwe_id"])

        # PoC code
        poc_code = finding.get("poc_code") or finding.get("poc") or ""
        http_request = finding.get("http_request") or ""
        http_response = finding.get("http_response") or ""

        # Build markdown
        md = self._render_template(
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe=cwe,
            url=url,
            param=param,
            payload=payload,
            description=description,
            evidence=evidence,
            poc_code=poc_code,
            http_request=http_request,
            http_response=http_response,
            tool=tool,
            confidence=confidence,
            scan_id=scan_id,
            vuln_type=vuln_type,
        )

        # Save to file
        safe_title = "".join(c if c.isalnum() or c in "- _" else "_" for c in title[:60])
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{severity}_{safe_title}.md"
        filepath = self.output_dir / filename
        filepath.write_text(md, encoding="utf-8")

        # ── V24: Append manual verification guide for mid-confidence findings ──
        if 30 <= confidence <= 75:
            try:
                from src.fp_engine.verification.manual_verify import (
                    ManualVerifyGuideGenerator,
                )
                _mvg = ManualVerifyGuideGenerator()
                _guide = _mvg.generate(
                    vuln_type=vuln_type,
                    url=url,
                    parameter=param,
                    payload=payload,
                    confidence=confidence,
                )
                if _guide:
                    _guide_md = _mvg.generate_markdown(_guide) if hasattr(_mvg, "generate_markdown") else ""
                    if not _guide_md and isinstance(_guide, dict):
                        # Fallback: render guide dict as markdown manually
                        _steps = _guide.get("steps", [])
                        if _steps:
                            _guide_md = "\n## Manual Verification Guide\n\n"
                            _guide_md += f"**Confidence:** {confidence:.0f}% — Manual verification recommended\n\n"
                            for _i, _s in enumerate(_steps, 1):
                                if isinstance(_s, dict):
                                    _guide_md += f"{_i}. **{_s.get('title', 'Step')}**: {_s.get('description', '')}\n"
                                else:
                                    _guide_md += f"{_i}. {_s}\n"
                    if _guide_md:
                        with filepath.open("a", encoding="utf-8") as _f:
                            _f.write("\n" + _guide_md + "\n")
            except ImportError:
                pass
            except Exception as _draft_err:
                logger.warning(f"Manual verification guide generation failed: {_draft_err}")

        self._drafts_generated.append(filepath)
        logger.info(f"Draft report generated: {filepath.name} ({severity} — {title[:50]})")
        return filepath

    def generate_batch(
        self,
        findings: list[dict[str, Any]],
        scan_id: str = "",
    ) -> list[Path]:
        """Generate drafts for all qualifying findings."""
        paths: list[Path] = []
        for f in findings:
            p = self.generate_draft(f, scan_id)
            if p:
                paths.append(p)
        if paths:
            logger.info(f"Generated {len(paths)} draft reports in {self.output_dir}")
        return paths

    @property
    def drafts_generated(self) -> list[Path]:
        return list(self._drafts_generated)

    def _render_template(self, **ctx: Any) -> str:
        """Render the platform-appropriate report template."""
        if self.platform == "bugcrowd":
            return self._render_bugcrowd(**ctx)
        return self._render_hackerone(**ctx)

    def _render_hackerone(self, **ctx: Any) -> str:
        """HackerOne report format."""
        lines = [
            f"# {ctx['title']}",
            "",
            "---",
            f"**Platform:** HackerOne  ",
            f"**Target:** {self.target}  ",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Scan ID:** {ctx.get('scan_id', 'N/A')}  ",
            f"**Tool:** {ctx.get('tool', 'N/A')}  ",
            f"**Confidence:** {ctx.get('confidence', 0):.0f}%  ",
            f"**Status:** ⚠️ DRAFT — Requires human review before submission",
            "",
            "---",
            "",
            "## Summary",
            "",
            ctx.get("description") or f"A {ctx['vuln_type']} vulnerability was identified at {ctx['url']}.",
            "",
            "## Severity",
            "",
            f"**CVSS Score:** {ctx['cvss_score']} ({ctx['severity']})",
        ]

        if ctx.get("cvss_vector"):
            lines.append(f"**Vector:** {ctx['cvss_vector']}")
        if ctx.get("cwe"):
            lines.append(f"**CWE:** {ctx['cwe']}")

        lines.extend([
            "",
            "## Steps to Reproduce",
            "",
            f"1. Navigate to `{ctx['url']}`",
        ])

        if ctx.get("param"):
            lines.append(f"2. Identify the `{ctx['param']}` parameter")
        if ctx.get("payload"):
            lines.append(f"3. Inject the following payload:")
            lines.append(f"   ```")
            lines.append(f"   {ctx['payload']}")
            lines.append(f"   ```")
        lines.append(f"4. Observe the vulnerability in the response")

        if ctx.get("http_request"):
            lines.extend([
                "",
                "## HTTP Request",
                "",
                "```http",
                ctx["http_request"][:2000],
                "```",
            ])

        if ctx.get("http_response"):
            lines.extend([
                "",
                "## HTTP Response",
                "",
                "```http",
                ctx["http_response"][:2000],
                "```",
            ])

        if ctx.get("poc_code"):
            lines.extend([
                "",
                "## Proof of Concept",
                "",
                "```python",
                ctx["poc_code"][:3000],
                "```",
            ])

        if ctx.get("evidence"):
            lines.extend([
                "",
                "## Evidence",
                "",
                ctx["evidence"][:2000],
            ])

        lines.extend([
            "",
            "## Impact",
            "",
            self._impact_text(ctx["vuln_type"], ctx["severity"]),
            "",
            "## Suggested Fix",
            "",
            self._remediation_text(ctx["vuln_type"]),
            "",
            "## References",
            "",
        ])

        if ctx.get("cwe"):
            cwe_id = ctx["cwe"].split(":")[0].replace("CWE-", "").strip()
            lines.append(f"- https://cwe.mitre.org/data/definitions/{cwe_id}.html")
        lines.append(f"- https://owasp.org/www-community/attacks/{ctx['vuln_type']}")

        return "\n".join(lines) + "\n"

    def _render_bugcrowd(self, **ctx: Any) -> str:
        """Bugcrowd report format (similar to HackerOne with rating taxonomy)."""
        # Bugcrowd uses VRT (Vulnerability Rating Taxonomy)
        lines = [
            f"# {ctx['title']}",
            "",
            "---",
            f"**Platform:** Bugcrowd  ",
            f"**Target:** {self.target}  ",
            f"**VRT Category:** {ctx['vuln_type']}  ",
            f"**Priority:** {self._bugcrowd_priority(ctx['severity'])}  ",
            f"**Status:** ⚠️ DRAFT — Requires human review",
            "",
            "---",
            "",
            "## Description",
            "",
            ctx.get("description") or f"{ctx['vuln_type']} vulnerability at {ctx['url']}.",
            "",
            "## URL / Location",
            "",
            f"`{ctx['url']}`",
            "",
        ]

        if ctx.get("param"):
            lines.extend([f"**Parameter:** `{ctx['param']}`", ""])
        if ctx.get("payload"):
            lines.extend(["**Payload:**", f"```\n{ctx['payload']}\n```", ""])

        lines.extend([
            "## Steps to Reproduce",
            "",
            f"1. Go to {ctx['url']}",
        ])
        if ctx.get("payload"):
            lines.append(f"2. Inject: `{ctx['payload'][:100]}`")
        lines.append("3. Observe the vulnerability")

        if ctx.get("evidence") or ctx.get("poc_code"):
            lines.extend(["", "## Proof of Concept", ""])
            if ctx.get("poc_code"):
                lines.extend(["```python", ctx["poc_code"][:3000], "```"])
            if ctx.get("evidence"):
                lines.extend(["", ctx["evidence"][:2000]])

        lines.extend([
            "",
            "## Impact",
            "",
            self._impact_text(ctx["vuln_type"], ctx["severity"]),
        ])

        return "\n".join(lines) + "\n"

    @staticmethod
    def _bugcrowd_priority(severity: str) -> str:
        if not isinstance(severity, str) or not severity:
            return "P5 (Informational)"
        return {
            "CRITICAL": "P1 (Critical)",
            "HIGH": "P2 (High)",
            "MEDIUM": "P3 (Medium)",
            "LOW": "P4 (Low)",
            "INFO": "P5 (Informational)",
        }.get(severity.upper(), "P5 (Informational)")

    @staticmethod
    def _impact_text(vuln_type: str, severity: str) -> str:
        impacts = {
            "xss": "An attacker could execute arbitrary JavaScript in the context of the victim's browser session, potentially stealing session tokens, credentials, or performing actions on behalf of the user.",
            "sqli": "An attacker could extract, modify, or delete data from the backend database. In severe cases, this could lead to full database compromise, authentication bypass, or remote code execution.",
            "ssrf": "An attacker could force the server to make requests to internal services, potentially accessing cloud metadata endpoints, internal APIs, or other backend systems not exposed to the internet.",
            "rce": "An attacker could execute arbitrary commands on the server, leading to full system compromise, data exfiltration, lateral movement, and persistent access.",
            "idor": "An attacker could access or modify other users' data by manipulating object references, potentially leading to unauthorized data disclosure or account takeover.",
            "lfi": "An attacker could read sensitive files from the server, potentially including configuration files, source code, credentials, or system files like /etc/passwd.",
            "jwt": "An attacker could forge or tamper with authentication tokens, potentially leading to authentication bypass, privilege escalation, or account takeover.",
        }
        return impacts.get(vuln_type, f"This {severity} severity vulnerability could impact the confidentiality, integrity, or availability of the application and its data.")

    @staticmethod
    def _remediation_text(vuln_type: str) -> str:
        remediations = {
            "xss": "Implement proper output encoding/escaping for all user-controlled data. Use Content-Security-Policy headers. Consider using a templating engine with auto-escaping enabled.",
            "sqli": "Use parameterized queries or prepared statements for all database interactions. Never concatenate user input into SQL queries. Implement input validation as a defense-in-depth measure.",
            "ssrf": "Validate and whitelist allowed destination URLs/IPs. Block requests to internal network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254). Use a request proxy with strict URL filtering.",
            "rce": "Never pass user-controlled input to system commands or shell functions. Use language-native libraries instead of shell commands. If unavoidable, use strict input validation and parameterization.",
            "idor": "Implement proper authorization checks on every object access. Use indirect references (UUIDs) instead of sequential IDs. Validate that the authenticated user has permission to access the requested resource.",
            "lfi": "Validate and sanitize file paths. Use a whitelist of allowed files. Avoid passing user input to file system functions. Implement chroot or similar filesystem isolation.",
            "jwt": "Use strong signing algorithms (RS256/ES256). Validate all JWT claims including exp, iss, aud. Never accept 'none' algorithm. Use sufficiently long and random secrets for HMAC-based algorithms.",
        }
        return remediations.get(vuln_type, "Review the vulnerability type and implement appropriate security controls following OWASP guidelines.")
