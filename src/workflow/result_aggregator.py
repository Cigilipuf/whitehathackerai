"""
WhiteHatHacker AI — Result Aggregator

Cross-tool result merging, deduplication, and correlation engine.

When multiple security tools scan the same target, they produce overlapping,
sometimes conflicting results. A professional bug bounty hunter synthesises
all tool outputs into a unified intelligence picture. This module automates
that synthesis:

1. **Merge**: Combine findings from different tools into a single dataset
2. **Deduplicate**: Identify and merge duplicate findings (same vuln, different tool)
3. **Correlate**: Find relationships between findings (e.g. subdomain → endpoint → vuln)
4. **Conflict Resolution**: When tools disagree, determine the most likely truth
5. **Source Tracking**: Always know which tool(s) contributed to each finding
6. **Confidence Boost**: Cross-tool confirmation increases confidence scores
"""

from __future__ import annotations

import hashlib
import time
import uuid
from enum import StrEnum
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ────────────────────────────────────────────────────────────
# Enumerations
# ────────────────────────────────────────────────────────────


class MergeStrategy(StrEnum):
    """How to merge duplicate findings."""

    HIGHEST_CONFIDENCE = "highest_confidence"  # Keep the finding with highest confidence
    MERGE_EVIDENCE = "merge_evidence"          # Combine evidence from all sources
    CONSENSUS = "consensus"                    # Require N tools to agree
    FIRST_FOUND = "first_found"                # Keep the first discovery


class ConflictResolution(StrEnum):
    """How to resolve conflicting tool results."""

    TRUST_PRIMARY = "trust_primary"        # Prefer primary/more reliable tool
    TRUST_MAJORITY = "trust_majority"      # Go with what most tools say
    TRUST_SPECIALIST = "trust_specialist"  # Prefer tool specialised for this vuln type
    ESCALATE = "escalate"                  # Flag for human review


class FindingRelation(StrEnum):
    """Types of relationships between findings."""

    DUPLICATE = "duplicate"            # Same finding from different tools
    RELATED = "related"                # Same target, different vulns
    CHAINED = "chained"                # Exploiting one enables the other
    PREREQUISITE = "prerequisite"      # Finding A is needed for finding B
    CONFLICTING = "conflicting"        # Tools disagree about this
    COMPLEMENTARY = "complementary"    # Different aspects of same issue


# ────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────


class ToolSource(BaseModel):
    """Attribution of a finding to a specific tool."""

    tool_name: str
    stage: str = ""
    confidence: float = 0.0         # Tool's own confidence (0-100)
    raw_output: str = ""            # Snippet of raw tool output
    timestamp: float = Field(default_factory=time.time)
    parameters_used: dict[str, Any] = Field(default_factory=dict)


class UnifiedFinding(BaseModel):
    """
    A single unified finding, potentially sourced from multiple tools.

    This is the canonical representation after aggregation.
    """

    finding_id: str = Field(
        default_factory=lambda: f"UF_{uuid.uuid4().hex[:10]}"
    )

    # What was found
    title: str
    vuln_type: str
    severity: str = "info"          # critical | high | medium | low | info
    description: str = ""

    # Where
    target: str = ""                # Host / domain
    endpoint: str = ""              # Specific URL / path
    parameter: str = ""             # Vulnerable parameter
    method: str = ""                # GET / POST / etc

    # Evidence
    evidence: list[str] = Field(default_factory=list)
    request_samples: list[str] = Field(default_factory=list)
    response_samples: list[str] = Field(default_factory=list)

    # Tool sourcing (which tools found this)
    sources: list[ToolSource] = Field(default_factory=list)
    source_count: int = 0           # How many tools confirmed this

    # Confidence
    confidence: float = 0.0         # Aggregated confidence (0-100)
    cross_tool_confirmed: bool = False  # Confirmed by ≥2 tools

    # Relations to other findings
    related_finding_ids: list[str] = Field(default_factory=list)
    relation_types: dict[str, str] = Field(default_factory=dict)  # finding_id → relation

    # Metadata
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    is_duplicate: bool = False
    duplicate_of: str = ""          # Primary finding ID

    # Dedup fingerprint
    fingerprint: str = ""

    def add_source(self, source: ToolSource) -> None:
        """Add a tool source, updating aggregated confidence."""
        self.sources.append(source)
        self.source_count = len(self.sources)
        self.last_seen = time.time()

        # Recalculate confidence
        self._recalculate_confidence()

    def _recalculate_confidence(self) -> None:
        """Recalculate aggregated confidence from sources."""
        if not self.sources:
            return

        # Base: highest individual confidence
        max_conf = max(s.confidence for s in self.sources)
        base = max_conf

        # Boost for cross-tool confirmation
        # Each additional tool boosts confidence by diminishing returns
        if len(self.sources) >= 2:
            self.cross_tool_confirmed = True
            boost = sum(
                s.confidence * (0.1 / i)
                for i, s in enumerate(
                    sorted(self.sources, key=lambda s: s.confidence, reverse=True)[1:],
                    start=1,
                )
            )
            base = min(100.0, base + boost)

        self.confidence = round(base, 1)


class AggregationResult(BaseModel):
    """Result of an aggregation operation."""

    total_input_findings: int = 0
    unique_findings: int = 0
    duplicates_merged: int = 0
    cross_tool_confirmed: int = 0
    conflicts_detected: int = 0
    relations_found: int = 0
    processing_time_ms: float = 0.0

    findings: list[UnifiedFinding] = Field(default_factory=list)
    conflicts: list[dict[str, Any]] = Field(default_factory=list)


# ────────────────────────────────────────────────────────────
# Tool Reliability Configuration
# ────────────────────────────────────────────────────────────

# Reliability scores (0-100) used for conflict resolution.
# More reliable tools are preferred when findings conflict.
TOOL_RELIABILITY: dict[str, float] = {
    # Primary scanners — highly reliable
    "sqlmap": 90,
    "nuclei": 85,
    "nmap": 95,

    # Specialised scanners
    "dalfox": 80,
    "xsstrike": 75,
    "ssrfmap": 78,
    "tplmap": 80,
    "commix": 82,
    "wpscan": 85,

    # Recon tools
    "subfinder": 90,
    "amass": 88,
    "httpx": 92,
    "katana": 80,

    # Fuzzing — moderate reliability (more FPs)
    "ffuf": 70,
    "feroxbuster": 68,
    "gobuster": 65,

    # Custom checks
    "custom_idor": 60,
    "custom_auth_bypass": 65,
    "custom_business_logic": 55,
}

# Which tool is the specialist for each vuln type
VULN_TYPE_SPECIALISTS: dict[str, list[str]] = {
    "sql_injection": ["sqlmap"],
    "xss_reflected": ["dalfox", "xsstrike"],
    "xss_stored": ["dalfox"],
    "xss_dom": ["dalfox"],
    "ssrf": ["ssrfmap"],
    "ssti": ["tplmap"],
    "command_injection": ["commix"],
    "lfi": ["ffuf", "nuclei"],
    "cors_misconfiguration": ["corsy"],
    "open_redirect": ["openredirex"],
    "jwt_vulnerability": ["jwt_tool"],
    "crlf_injection": ["crlfuzz"],
    "http_request_smuggling": ["smuggler"],
    "subdomain_takeover": ["nuclei", "subjack"],
}


# ────────────────────────────────────────────────────────────
# Result Aggregator
# ────────────────────────────────────────────────────────────


class ResultAggregator:
    """
    Cross-tool result merging and deduplication engine.

    Usage::

        aggregator = ResultAggregator()

        # Feed findings from different tools
        aggregator.add_findings_from_tool("sqlmap", "vuln_scan", sqlmap_findings)
        aggregator.add_findings_from_tool("nuclei", "vuln_scan", nuclei_findings)
        aggregator.add_findings_from_tool("dalfox", "vuln_scan", dalfox_findings)

        # Run aggregation
        result = aggregator.aggregate()

        # Get unified findings
        for finding in result.findings:
            print(f"{finding.title} — confidence={finding.confidence} "
                  f"— sources={finding.source_count}")
    """

    def __init__(
        self,
        merge_strategy: MergeStrategy = MergeStrategy.MERGE_EVIDENCE,
        conflict_resolution: ConflictResolution = ConflictResolution.TRUST_SPECIALIST,
        min_consensus: int = 2,
    ) -> None:
        self.merge_strategy = merge_strategy
        self.conflict_resolution = conflict_resolution
        self.min_consensus = min_consensus

        # Raw ingested findings (pre-aggregation)
        self._raw_buffer: list[tuple[str, str, dict[str, Any]]] = []

        # Aggregated output
        self._unified: dict[str, UnifiedFinding] = {}  # fingerprint → finding
        self._conflicts: list[dict[str, Any]] = []

        logger.info(
            f"ResultAggregator initialized | strategy={merge_strategy} | "
            f"conflict={conflict_resolution}"
        )

    # ─── Ingestion ───────────────────────────────────────────

    def add_findings_from_tool(
        self,
        tool_name: str,
        stage: str,
        findings: list[dict[str, Any]],
        tool_confidence: float = 50.0,
    ) -> int:
        """
        Ingest findings from a single tool execution.

        Args:
            tool_name: Name of the tool that produced these findings.
            stage: Pipeline stage (e.g., "vulnerability_scanning").
            findings: List of finding dicts from the tool.
            tool_confidence: Default confidence if not specified per-finding.

        Returns:
            Number of findings ingested.
        """
        count = 0
        for f in findings:
            self._raw_buffer.append((tool_name, stage, f))
            count += 1

        logger.debug(
            f"Ingested {count} findings from {tool_name} | stage={stage}"
        )
        return count

    def add_single_finding(
        self,
        tool_name: str,
        stage: str,
        finding: dict[str, Any],
    ) -> None:
        """Ingest a single finding from a tool."""
        self._raw_buffer.append((tool_name, stage, finding))

    # ─── Aggregation ─────────────────────────────────────────

    def aggregate(self) -> AggregationResult:
        """
        Run the full aggregation pipeline:
        1. Fingerprint all raw findings
        2. Group by fingerprint (deduplication)
        3. Merge duplicates
        4. Detect conflicts
        5. Correlate related findings
        6. Calculate final confidence scores
        """
        start = time.monotonic()
        total_input = len(self._raw_buffer)

        logger.info(f"Starting aggregation | input_findings={total_input}")

        # Step 1 & 2: Fingerprint and group
        groups: dict[str, list[tuple[str, str, dict]]] = {}
        for tool_name, stage, finding in self._raw_buffer:
            fp = self._fingerprint(finding)
            groups.setdefault(fp, []).append((tool_name, stage, finding))

        # Step 3: Merge duplicates within each group
        duplicates_merged = 0
        for fp, group in groups.items():
            if fp in self._unified:
                # Existing finding — add new sources
                existing = self._unified[fp]
                for tool_name, stage, finding in group:
                    source = ToolSource(
                        tool_name=tool_name,
                        stage=stage,
                        confidence=finding.get("confidence", 50.0),
                        raw_output=finding.get("raw_output", "")[:500],
                    )
                    existing.add_source(source)
                    duplicates_merged += 1
                    self._merge_evidence(existing, finding)
            else:
                # New finding
                primary_tool, primary_stage, primary = group[0]
                unified = self._create_unified(primary, primary_tool, primary_stage)
                unified.fingerprint = fp

                # Add remaining sources
                for tool_name, stage, finding in group[1:]:
                    source = ToolSource(
                        tool_name=tool_name,
                        stage=stage,
                        confidence=finding.get("confidence", 50.0),
                        raw_output=finding.get("raw_output", "")[:500],
                    )
                    unified.add_source(source)
                    self._merge_evidence(unified, finding)
                    duplicates_merged += 1

                self._unified[fp] = unified

        # Step 4: Detect conflicts
        self._detect_conflicts()

        # Step 5: Correlate related findings
        relations_found = self._correlate_findings()

        # Step 6: Sort by confidence
        findings = sorted(
            self._unified.values(),
            key=lambda f: f.confidence,
            reverse=True,
        )

        elapsed_ms = (time.monotonic() - start) * 1000

        cross_confirmed = sum(1 for f in findings if f.cross_tool_confirmed)

        result = AggregationResult(
            total_input_findings=total_input,
            unique_findings=len(findings),
            duplicates_merged=duplicates_merged,
            cross_tool_confirmed=cross_confirmed,
            conflicts_detected=len(self._conflicts),
            relations_found=relations_found,
            processing_time_ms=round(elapsed_ms, 2),
            findings=findings,
            conflicts=self._conflicts,
        )

        logger.info(
            f"Aggregation complete | input={total_input} → "
            f"unique={result.unique_findings} | "
            f"merged={duplicates_merged} | "
            f"confirmed={cross_confirmed} | "
            f"conflicts={len(self._conflicts)} | "
            f"time={elapsed_ms:.1f}ms"
        )

        # Clear raw buffer
        self._raw_buffer.clear()

        return result

    # ─── Queries ─────────────────────────────────────────────

    def get_findings(
        self,
        min_confidence: float = 0.0,
        vuln_type: str | None = None,
        cross_confirmed_only: bool = False,
        severity: str | None = None,
    ) -> list[UnifiedFinding]:
        """Query unified findings with filters."""
        results: list[UnifiedFinding] = []
        for f in self._unified.values():
            if f.confidence < min_confidence:
                continue
            if vuln_type and f.vuln_type != vuln_type:
                continue
            if cross_confirmed_only and not f.cross_tool_confirmed:
                continue
            if severity and f.severity != severity:
                continue
            results.append(f)

        return sorted(results, key=lambda f: f.confidence, reverse=True)

    def get_finding_by_id(self, finding_id: str) -> UnifiedFinding | None:
        """Look up a finding by its ID."""
        for f in self._unified.values():
            if f.finding_id == finding_id:
                return f
        return None

    def get_tool_contribution_stats(self) -> dict[str, dict[str, Any]]:
        """Statistics about each tool's contribution to findings."""
        stats: dict[str, dict[str, Any]] = {}

        for finding in self._unified.values():
            for source in finding.sources:
                name = source.tool_name
                if name not in stats:
                    stats[name] = {
                        "total_findings": 0,
                        "unique_findings": 0,
                        "cross_confirmed": 0,
                        "avg_confidence": 0.0,
                        "_confidence_sum": 0.0,
                    }
                stats[name]["total_findings"] += 1
                stats[name]["_confidence_sum"] += source.confidence

        # Calculate averages and unique counts
        for name, s in stats.items():
            if s["total_findings"] > 0:
                s["avg_confidence"] = round(
                    s["_confidence_sum"] / s["total_findings"], 1
                )
            del s["_confidence_sum"]

            # Count findings where this tool was the only source
            unique = sum(
                1 for f in self._unified.values()
                if len(f.sources) == 1 and f.sources[0].tool_name == name
            )
            s["unique_findings"] = unique

            # Count cross-confirmed findings that include this tool
            confirmed = sum(
                1 for f in self._unified.values()
                if f.cross_tool_confirmed
                and any(src.tool_name == name for src in f.sources)
            )
            s["cross_confirmed"] = confirmed

        return stats

    def get_summary(self) -> dict[str, Any]:
        """High-level aggregation summary."""
        findings = list(self._unified.values())
        severity_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}

        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            type_counts[f.vuln_type] = type_counts.get(f.vuln_type, 0) + 1

        return {
            "total_unified_findings": len(findings),
            "cross_tool_confirmed": sum(
                1 for f in findings if f.cross_tool_confirmed
            ),
            "average_confidence": round(
                sum(f.confidence for f in findings) / max(1, len(findings)), 1
            ),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "tools_contributing": len(
                {s.tool_name for f in findings for s in f.sources}
            ),
            "conflicts": len(self._conflicts),
        }

    # ─── Internal: Fingerprinting ────────────────────────────

    @staticmethod
    def _fingerprint(finding: dict[str, Any]) -> str:
        """
        Generate a deduplication fingerprint for a finding.

        Two findings from different tools are considered duplicates if they
        target the same endpoint + parameter + vulnerability type.
        """
        def _s(val: Any) -> str:
            if isinstance(val, str):
                return val
            if isinstance(val, list):
                return str(val[0]) if val else ""
            if val is None:
                return ""
            return str(val)

        components = [
            _s(finding.get("vuln_type", "unknown")).lower().strip(),
            _s(finding.get("target", "")).lower().strip(),
            _s(finding.get("endpoint", finding.get("url", ""))).lower().strip(),
            _s(finding.get("parameter", "")).lower().strip(),
            _s(finding.get("method", "")).upper().strip(),
        ]

        # Remove empty components to avoid false grouping
        key = "||".join(c for c in components if c)
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    # ─── Internal: Unified Finding Creation ──────────────────

    def _create_unified(
        self,
        raw: dict[str, Any],
        tool_name: str,
        stage: str,
    ) -> UnifiedFinding:
        """Create a UnifiedFinding from a raw tool finding."""
        source = ToolSource(
            tool_name=tool_name,
            stage=stage,
            confidence=raw.get("confidence", 50.0),
            raw_output=raw.get("raw_output", "")[:500],
        )

        evidence = raw.get("evidence", [])
        if isinstance(evidence, str):
            evidence = [evidence]

        return UnifiedFinding(
            title=raw.get("title", "Untitled Finding"),
            vuln_type=raw.get("vuln_type", "unknown"),
            severity=raw.get("severity", "info"),
            description=raw.get("description", ""),
            target=raw.get("target", ""),
            endpoint=raw.get("endpoint", raw.get("url", "")),
            parameter=raw.get("parameter", ""),
            method=raw.get("method", ""),
            evidence=evidence,
            request_samples=raw.get("request_samples", []),
            response_samples=raw.get("response_samples", []),
            sources=[source],
            source_count=1,
            confidence=raw.get("confidence", 50.0),
        )

    def _merge_evidence(
        self,
        unified: UnifiedFinding,
        raw: dict[str, Any],
    ) -> None:
        """Merge additional evidence from a raw finding into unified."""
        # Merge evidence strings
        new_evidence = raw.get("evidence", [])
        if isinstance(new_evidence, str):
            new_evidence = [new_evidence]
        for ev in new_evidence:
            if ev and ev not in unified.evidence:
                unified.evidence.append(ev)

        # Merge request/response samples
        for req in raw.get("request_samples", []):
            if req and req not in unified.request_samples:
                unified.request_samples.append(req)
        for resp in raw.get("response_samples", []):
            if resp and resp not in unified.response_samples:
                unified.response_samples.append(resp)

        # Update description if richer
        new_desc = raw.get("description", "")
        if len(new_desc) > len(unified.description):
            unified.description = new_desc

        # Update severity if higher
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        new_sev = raw.get("severity", "info")
        if severity_order.get(new_sev, 0) > severity_order.get(unified.severity, 0):
            unified.severity = new_sev

    # ─── Internal: Conflict Detection ────────────────────────

    def _detect_conflicts(self) -> None:
        """
        Detect conflicts between findings.

        E.g., Tool A says "SQL injection on /api/users?id=",
              Tool B tested the same endpoint and found nothing.
        """
        # Conflicts are primarily detected when:
        # 1. Same endpoint, same vuln type, but vastly different confidence
        # 2. This is complex — for now, flag findings where tools have
        #    confidence spread > 50 points
        for finding in self._unified.values():
            if len(finding.sources) < 2:
                continue

            confidences = [s.confidence for s in finding.sources]
            spread = max(confidences) - min(confidences)

            if spread > 50:
                self._conflicts.append({
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "spread": spread,
                    "sources": [
                        {"tool": s.tool_name, "confidence": s.confidence}
                        for s in finding.sources
                    ],
                    "resolution": self._resolve_conflict(finding),
                })

    def _resolve_conflict(self, finding: UnifiedFinding) -> dict[str, Any]:
        """Resolve a conflict using the configured strategy."""
        sources = finding.sources

        match self.conflict_resolution:
            case ConflictResolution.TRUST_PRIMARY:
                # Trust the tool with highest reliability score
                best = max(
                    sources,
                    key=lambda s: TOOL_RELIABILITY.get(s.tool_name, 50),
                )
                finding.confidence = best.confidence
                return {
                    "method": "trust_primary",
                    "trusted_tool": best.tool_name,
                    "new_confidence": best.confidence,
                }

            case ConflictResolution.TRUST_SPECIALIST:
                specialists = VULN_TYPE_SPECIALISTS.get(finding.vuln_type, [])
                specialist_sources = [
                    s for s in sources if s.tool_name in specialists
                ]
                if specialist_sources:
                    best = max(specialist_sources, key=lambda s: s.confidence)
                    finding.confidence = best.confidence
                    return {
                        "method": "trust_specialist",
                        "specialist_tool": best.tool_name,
                        "new_confidence": best.confidence,
                    }
                # Fall through to majority if no specialist
                return self._resolve_by_majority(finding)

            case ConflictResolution.TRUST_MAJORITY:
                return self._resolve_by_majority(finding)

            case ConflictResolution.ESCALATE:
                return {
                    "method": "escalate",
                    "reason": "Conflict requires human review",
                    "all_sources": [
                        {"tool": s.tool_name, "conf": s.confidence}
                        for s in sources
                    ],
                }

        return {"method": "unresolved"}

    @staticmethod
    def _resolve_by_majority(finding: UnifiedFinding) -> dict[str, Any]:
        """Resolve conflict by averaging confidence scores."""
        if not finding.sources:
            return {"method": "unresolved"}
        avg = sum(s.confidence for s in finding.sources) / len(finding.sources)
        finding.confidence = round(avg, 1)
        return {
            "method": "majority_average",
            "new_confidence": finding.confidence,
        }

    # ─── Internal: Finding Correlation ───────────────────────

    def _correlate_findings(self) -> int:
        """
        Find relationships between findings.

        - Same target, different vulns → RELATED
        - Same endpoint, different vuln types → COMPLEMENTARY
        - SSRF + LFI → possible CHAINED
        """
        relations_count = 0
        findings = list(self._unified.values())

        for i, f1 in enumerate(findings):
            for f2 in findings[i + 1 :]:
                relation = self._detect_relation(f1, f2)
                if relation is not None:
                    f1.related_finding_ids.append(f2.finding_id)
                    f1.relation_types[f2.finding_id] = relation
                    f2.related_finding_ids.append(f1.finding_id)
                    f2.relation_types[f1.finding_id] = relation
                    relations_count += 1

        return relations_count

    @staticmethod
    def _detect_relation(
        f1: UnifiedFinding,
        f2: UnifiedFinding,
    ) -> str | None:
        """Detect the relationship between two findings."""
        # Same exact fingerprint = duplicate (should not happen after dedup)
        if f1.fingerprint == f2.fingerprint:
            return FindingRelation.DUPLICATE

        same_target = f1.target == f2.target and f1.target != ""
        same_endpoint = (
            f1.endpoint == f2.endpoint
            and f1.endpoint != ""
        )
        same_vuln_type = f1.vuln_type == f2.vuln_type

        # Same endpoint, different vuln → complementary
        if same_endpoint and not same_vuln_type:
            return FindingRelation.COMPLEMENTARY

        # Same target, different endpoint → related
        if same_target and not same_endpoint:
            return FindingRelation.RELATED

        # Check for known chained attack patterns
        chain_pairs = {
            ("ssrf", "lfi"),
            ("ssrf", "rce"),
            ("sql_injection", "rce"),
            ("ssti", "rce"),
            ("file_upload", "rce"),
            ("idor", "information_disclosure"),
            ("authentication_bypass", "idor"),
            ("open_redirect", "ssrf"),
            ("xss_reflected", "csrf"),
        }

        types = {f1.vuln_type.lower(), f2.vuln_type.lower()}
        for pair in chain_pairs:
            if set(pair).issubset(types) or any(
                t in types for t in pair
            ):
                if set(pair) == types:
                    return FindingRelation.CHAINED

        return None

    # ─── Reset ───────────────────────────────────────────────

    def reset(self) -> None:
        """Clear all state for a new aggregation run."""
        self._raw_buffer.clear()
        self._unified.clear()
        self._conflicts.clear()
        logger.debug("ResultAggregator reset")


__all__ = [
    "ResultAggregator",
    "UnifiedFinding",
    "ToolSource",
    "AggregationResult",
    "MergeStrategy",
    "ConflictResolution",
    "FindingRelation",
    "TOOL_RELIABILITY",
    "VULN_TYPE_SPECIALISTS",
]
