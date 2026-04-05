"""
WhiteHatHacker AI — Output Aggregator & Correlator

Collects, deduplicates, normalizes, and correlates findings
from all security tools. Creates a unified finding database
with cross-tool verification and enrichment.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from src.tools.base import Finding, ToolResult


class NormalizedFinding(BaseModel):
    """A finding normalized for cross-tool comparison."""

    finding_id: str = ""

    # Core identification
    title: str
    vuln_type: str = ""                   # Normalized type (sqli, xss, ssrf, etc.)
    target: str = ""                       # Normalized target (scheme://host:port)
    endpoint: str = ""                     # Normalized path
    parameter: str = ""

    # Evidence
    severity: str = "MEDIUM"
    confidence: float = 50.0               # 0-100
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    payloads: list[str] = Field(default_factory=list)

    # Source tracking
    source_tools: list[str] = Field(default_factory=list)     # Which tools reported this
    source_findings: list[str] = Field(default_factory=list)   # Original finding IDs
    verification_count: int = 0            # How many tools confirmed

    # Classification
    cwe: str = ""
    cve: list[str] = Field(default_factory=list)
    owasp: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""

    # Status
    is_verified: bool = False
    is_false_positive: bool = False
    fp_reason: str = ""

    # Metadata
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrelationResult(BaseModel):
    """Result of correlating findings across tools."""

    total_raw_findings: int = 0
    total_after_dedup: int = 0
    total_cross_verified: int = 0       # Found by 2+ tools
    total_high_confidence: int = 0      # Confidence >= 70

    by_severity: dict[str, int] = Field(default_factory=dict)
    by_vuln_type: dict[str, int] = Field(default_factory=dict)
    by_tool: dict[str, int] = Field(default_factory=dict)

    # Interesting correlations
    attack_chains: list[dict] = Field(default_factory=list)
    related_findings: list[list[str]] = Field(default_factory=list)


# ── Normalization Maps ─────────────────────────────────────────────

# Map various tool-specific vuln names to standard types
VULN_TYPE_NORMALIZER: dict[str, str] = {
    # SQL Injection
    "sql injection": "sqli",
    "sql_injection": "sqli",
    "sqli": "sqli",
    "blind sql injection": "sqli",
    "union sql injection": "sqli",
    "stacked sql injection": "sqli",
    "time-based blind": "sqli",
    "boolean-based blind": "sqli",
    "error-based": "sqli",
    # XSS
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "xss": "xss",
    "reflected xss": "xss_reflected",
    "stored xss": "xss_stored",
    "dom xss": "xss_dom",
    "dom-based xss": "xss_dom",
    # Command Injection
    "command injection": "cmdi",
    "os command injection": "cmdi",
    "rce": "cmdi",
    "remote code execution": "cmdi",
    # SSRF
    "server-side request forgery": "ssrf",
    "ssrf": "ssrf",
    # SSTI
    "server-side template injection": "ssti",
    "ssti": "ssti",
    "template injection": "ssti",
    # File
    "local file inclusion": "lfi",
    "lfi": "lfi",
    "remote file inclusion": "rfi",
    "rfi": "rfi",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "file upload": "file_upload",
    # Auth
    "authentication bypass": "auth_bypass",
    "broken authentication": "auth_bypass",
    "idor": "idor",
    "insecure direct object reference": "idor",
    "broken access control": "authz",
    "privilege escalation": "privesc",
    # Config
    "cors": "cors",
    "cors misconfiguration": "cors",
    "open redirect": "open_redirect",
    "http request smuggling": "http_smuggling",
    "crlf injection": "crlf",
    "clickjacking": "clickjacking",
    "security headers": "missing_headers",
    "missing security headers": "missing_headers",
    # Crypto
    "weak ssl": "ssl_weak",
    "ssl/tls": "ssl_weak",
    "weak cipher": "ssl_weak",
    "expired certificate": "ssl_cert",
    # Info
    "information disclosure": "info_disclosure",
    "directory listing": "dir_listing",
    "sensitive file": "sensitive_file",
    "source code disclosure": "source_disclosure",
    "stack trace": "stack_trace",
    "error message": "verbose_error",
    # Network
    "smb": "smb_issue",
    "null session": "null_session",
    "anonymous access": "anon_access",
    "default credentials": "default_creds",
    "weak credentials": "weak_creds",
    "brute force": "brute_force",
}

SEVERITY_NORMALIZER: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "none": "INFO",
}


class OutputAggregator:
    """
    Aggregates and correlates findings from multiple security tools.

    Pipeline:
    1. Ingest raw ToolResults from each tool execution
    2. Normalize each Finding (vuln type, severity, target format)
    3. Deduplicate (same vuln + same target + same param = same finding)
    4. Correlate (link findings from different tools to same issue)
    5. Enrich (add CWE/CVE, boost confidence for multi-tool finds)
    6. Rank (priority sort by severity × confidence)

    Used by the workflow orchestrator to build the unified findings database.
    """

    def __init__(self):
        self._findings: dict[str, NormalizedFinding] = {}  # finding_id → finding
        self._raw_count = 0
        self._tool_results: list[ToolResult] = []

    def ingest_tool_result(self, result: ToolResult, tool_name: str = "") -> int:
        """
        Ingest a ToolResult and add its findings to the store.

        Returns number of new (non-duplicate) findings added.
        """
        self._tool_results.append(result)

        new_count = 0
        for finding in result.findings:
            self._raw_count += 1
            normalized = self._normalize_finding(finding, tool_name or result.metadata.get("tool", "unknown"))

            # Check for duplicates
            dup_id = self._find_duplicate(normalized)
            if dup_id:
                self._merge_finding(dup_id, normalized)
            else:
                # New finding
                normalized.finding_id = self._generate_finding_id(normalized)
                self._findings[normalized.finding_id] = normalized
                new_count += 1

        logger.debug(
            f"[Aggregator] Ingested {len(result.findings)} findings from {tool_name}, "
            f"{new_count} new, {len(result.findings) - new_count} merged"
        )
        return new_count

    def correlate(self) -> CorrelationResult:
        """
        Run correlation analysis on all collected findings.

        Cross-references findings across tools, identifies
        attack chains, and boosts confidence for multi-tool findings.
        """
        result = CorrelationResult(
            total_raw_findings=self._raw_count,
            total_after_dedup=len(self._findings),
        )

        # Boost confidence for multi-tool verified findings
        for finding in self._findings.values():
            if finding.verification_count >= 2:
                finding.confidence = min(100, finding.confidence + 15 * (finding.verification_count - 1))
                finding.is_verified = True
                result.total_cross_verified += 1

            if finding.confidence >= 70:
                result.total_high_confidence += 1

        # Count by severity
        for f in self._findings.values():
            sev = f.severity
            result.by_severity[sev] = result.by_severity.get(sev, 0) + 1

        # Count by vuln type
        for f in self._findings.values():
            vt = f.vuln_type or "unknown"
            result.by_vuln_type[vt] = result.by_vuln_type.get(vt, 0) + 1

        # Count by tool
        for f in self._findings.values():
            for tool in f.source_tools:
                result.by_tool[tool] = result.by_tool.get(tool, 0) + 1

        # Identify potential attack chains
        result.attack_chains = self._find_attack_chains()

        # Identify related findings
        result.related_findings = self._find_related_findings()

        logger.info(
            f"[Aggregator] Correlation complete: {result.total_after_dedup} unique findings "
            f"({result.total_cross_verified} cross-verified, "
            f"{result.total_high_confidence} high-confidence)"
        )
        return result

    def get_findings(
        self,
        min_confidence: float = 0,
        severity: str | None = None,
        vuln_type: str | None = None,
        verified_only: bool = False,
        exclude_fp: bool = True,
    ) -> list[NormalizedFinding]:
        """Get findings with optional filters."""
        results = []
        for f in self._findings.values():
            if exclude_fp and f.is_false_positive:
                continue
            if f.confidence < min_confidence:
                continue
            if severity and f.severity != severity.upper():
                continue
            if vuln_type and f.vuln_type != vuln_type:
                continue
            if verified_only and not f.is_verified:
                continue
            results.append(f)

        # Sort by severity weight × confidence
        results.sort(key=lambda f: self._finding_priority(f), reverse=True)
        return results

    def get_findings_for_report(self) -> list[NormalizedFinding]:
        """Get findings suitable for inclusion in bug bounty report."""
        return self.get_findings(
            min_confidence=50,
            exclude_fp=True,
        )

    def mark_false_positive(self, finding_id: str, reason: str) -> None:
        """Mark a finding as false positive."""
        f = self._findings.get(finding_id)
        if f:
            f.is_false_positive = True
            f.fp_reason = reason
            logger.info(f"[Aggregator] Marked FP: {f.title} — {reason}")

    def get_stats(self) -> dict:
        """Get aggregation statistics."""
        findings = list(self._findings.values())
        active = [f for f in findings if not f.is_false_positive]

        return {
            "raw_findings": self._raw_count,
            "unique_findings": len(findings),
            "active_findings": len(active),
            "false_positives": len(findings) - len(active),
            "cross_verified": sum(1 for f in active if f.is_verified),
            "high_confidence": sum(1 for f in active if f.confidence >= 70),
            "by_severity": {
                sev: sum(1 for f in active if f.severity == sev)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
            "dedup_ratio": f"{(1 - len(findings) / max(1, self._raw_count)):.1%}",
        }

    # ── Normalization ──────────────────────────────────────────────

    def _normalize_finding(self, finding: Finding, tool_name: str) -> NormalizedFinding:
        """Normalize a raw Finding into standard format."""
        # Normalize vulnerability type
        vuln_type = self._normalize_vuln_type(finding.title, finding.description)

        # Normalize severity
        severity = SEVERITY_NORMALIZER.get(
            (finding.severity or "medium").lower(), "MEDIUM"
        )

        # Normalize target
        target = self._normalize_target(finding.target)

        return NormalizedFinding(
            title=finding.title,
            vuln_type=vuln_type,
            target=target,
            endpoint=finding.endpoint or "",
            parameter=finding.parameter or "",
            severity=severity,
            confidence=finding.confidence,
            description=finding.description or "",
            evidence=[finding.evidence] if finding.evidence else [],
            payloads=[finding.payload] if finding.payload else [],
            source_tools=[tool_name],
            source_findings=[f"{tool_name}:{finding.title[:50]}"],
            verification_count=1,
            cwe=getattr(finding, "cwe", None) or getattr(finding, "cwe_id", "") or "",
            cve=getattr(finding, "cve", None) or ([getattr(finding, "cve_id", "")] if getattr(finding, "cve_id", "") else []),
            tags=getattr(finding, "tags", []) or [],
            metadata=getattr(finding, "metadata", {}) or {},
        )

    def _normalize_vuln_type(self, title: str, description: str) -> str:
        """Normalize vulnerability type from title/description."""
        combined = f"{title} {description}".lower()

        for pattern, normalized in VULN_TYPE_NORMALIZER.items():
            if pattern in combined:
                return normalized

        return "unknown"

    def _normalize_target(self, target: str) -> str:
        """Normalize target URL/IP format."""
        if not target:
            return ""

        target = target.strip().rstrip("/")

        # Add scheme if missing
        if target and not target.startswith(("http://", "https://", "ftp://")):
            if ":" in target and not target.startswith("["):
                # IP:port or host:port
                pass
            else:
                target = f"https://{target}"

        return target

    # ── Deduplication ──────────────────────────────────────────────

    def _find_duplicate(self, finding: NormalizedFinding) -> str | None:
        """
        Check if a finding is a duplicate of an existing one.

        Dedup criteria: same vuln_type + same target + same endpoint + same parameter
        """
        for fid, existing in self._findings.items():
            if self._is_same_finding(existing, finding):
                return fid
        return None

    def _is_same_finding(self, a: NormalizedFinding, b: NormalizedFinding) -> bool:
        """Check if two findings represent the same vulnerability."""
        # Exact match on core fields
        if (
            a.vuln_type == b.vuln_type
            and a.vuln_type != "unknown"
            and self._normalize_url(a.target) == self._normalize_url(b.target)
            and a.endpoint == b.endpoint
            and a.parameter == b.parameter
        ):
            return True

        # Fuzzy match: same type and very similar titles
        if a.vuln_type == b.vuln_type and a.vuln_type != "unknown":
            title_sim = self._title_similarity(a.title, b.title)
            if title_sim > 0.8:
                return True

        return False

    def _merge_finding(self, existing_id: str, new: NormalizedFinding) -> None:
        """Merge a duplicate finding into existing, compiling evidence."""
        existing = self._findings[existing_id]

        # Boost confidence for cross-tool confirmation (check BEFORE append)
        _new_tool = new.source_tools[0] if new.source_tools else ""
        _is_new_tool = _new_tool and _new_tool not in existing.source_tools

        # Add source tool
        for tool in new.source_tools:
            if tool not in existing.source_tools:
                existing.source_tools.append(tool)
                existing.verification_count += 1

        # Merge evidence
        for ev in new.evidence:
            if ev and ev not in existing.evidence:
                existing.evidence.append(ev)

        # Merge payloads
        for p in new.payloads:
            if p and p not in existing.payloads:
                existing.payloads.append(p)

        # Take higher severity
        if self._severity_weight(new.severity) > self._severity_weight(existing.severity):
            existing.severity = new.severity

        # Apply cross-tool confidence boost
        if _is_new_tool:
            existing.confidence = min(100, existing.confidence + 10)

        # Merge CVE/CWE
        if new.cwe and not existing.cwe:
            existing.cwe = new.cwe
        for cve in new.cve:
            if cve not in existing.cve:
                existing.cve.append(cve)

        existing.last_seen = time.time()
        existing.source_findings.extend(new.source_findings)

    # ── Correlation ────────────────────────────────────────────────

    def _find_attack_chains(self) -> list[dict]:
        """
        Identify potential attack chains from findings.

        Example chains:
        - Info disclosure → credential leak → auth bypass
        - SQLi → data extraction → privilege escalation
        - SSRF → internal service access → further exploitation
        """
        chains = []
        findings = [f for f in self._findings.values() if not f.is_false_positive]

        # Chain: Info disclosure leading to further exploitation
        info_findings = [f for f in findings if f.vuln_type in ("info_disclosure", "sensitive_file", "dir_listing")]
        injection_findings = [f for f in findings if f.vuln_type in ("sqli", "cmdi", "xss", "ssti")]

        if info_findings and injection_findings:
            chains.append({
                "type": "info_to_injection",
                "description": "Information disclosure may enable targeted injection attacks",
                "steps": [
                    {"finding": f.title, "role": "reconnaissance"} for f in info_findings[:3]
                ] + [
                    {"finding": f.title, "role": "exploitation"} for f in injection_findings[:3]
                ],
                "severity": "HIGH",
            })

        # Chain: Auth issues + IDOR
        auth_issues = [f for f in findings if f.vuln_type in ("auth_bypass", "weak_creds", "default_creds")]
        idor_findings = [f for f in findings if f.vuln_type == "idor"]

        if auth_issues and idor_findings:
            chains.append({
                "type": "auth_plus_idor",
                "description": "Authentication weakness combined with IDOR enables account takeover",
                "steps": [
                    {"finding": f.title, "role": "auth_bypass"} for f in auth_issues[:3]
                ] + [
                    {"finding": f.title, "role": "data_access"} for f in idor_findings[:3]
                ],
                "severity": "CRITICAL",
            })

        # Chain: SSRF → internal access
        ssrf_findings = [f for f in findings if f.vuln_type == "ssrf"]
        if ssrf_findings:
            chains.append({
                "type": "ssrf_chain",
                "description": "SSRF may allow access to internal services and cloud metadata",
                "steps": [
                    {"finding": f.title, "role": "ssrf_entry"} for f in ssrf_findings[:3]
                ],
                "severity": "CRITICAL",
            })

        return chains

    def _find_related_findings(self) -> list[list[str]]:
        """Group related findings together."""
        groups: list[list[str]] = []
        used: set[str] = set()

        findings_list = list(self._findings.values())

        for i, f1 in enumerate(findings_list):
            if f1.finding_id in used:
                continue

            group = [f1.finding_id]

            for j, f2 in enumerate(findings_list[i+1:], i+1):
                if f2.finding_id in used:
                    continue

                # Same target + related vuln type
                if (
                    f1.target == f2.target
                    and f1.vuln_type != f2.vuln_type
                    and f1.endpoint == f2.endpoint
                ):
                    group.append(f2.finding_id)

            if len(group) > 1:
                groups.append(group)
                used.update(group)

        return groups

    # ── Utilities ──────────────────────────────────────────────────

    def _generate_finding_id(self, finding: NormalizedFinding) -> str:
        """Generate a deterministic ID for a finding."""
        raw = f"{finding.vuln_type}:{finding.target}:{finding.endpoint}:{finding.parameter}:{finding.title}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _severity_weight(severity: str) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(severity, 0)

    def _finding_priority(self, finding: NormalizedFinding) -> float:
        """Calculate priority score for sorting."""
        sev_weight = self._severity_weight(finding.severity)
        return sev_weight * 20 + finding.confidence

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Strip trailing slashes, normalize scheme."""
        return url.strip().rstrip("/").lower()

    @staticmethod
    def _title_similarity(a: str, b: str) -> float:
        """Simple word-overlap similarity for titles."""
        words_a = set(a.lower().split())
        words_b = set(b.lower().split())
        if not words_a or not words_b:
            return 0.0
        intersection = words_a & words_b
        return len(intersection) / max(len(words_a), len(words_b))

    def clear(self) -> None:
        """Clear all findings."""
        self._findings.clear()
        self._raw_count = 0
        self._tool_results.clear()


__all__ = [
    "OutputAggregator",
    "NormalizedFinding",
    "CorrelationResult",
]
