"""
WhiteHatHacker AI — Knowledge Base

Long-term persistent memory that survives across scan sessions.
Stores learned patterns, target intelligence, tool effectiveness
metrics, and accumulated security knowledge.

Uses SQLite for persistence with async access.
"""

from __future__ import annotations

import asyncio
from collections import Counter
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ── Data Models ────────────────────────────────────────────────────

class TargetIntelligence(BaseModel):
    """Accumulated knowledge about a specific target."""

    domain: str
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    technologies: list[str] = Field(default_factory=list)
    waf_detected: str = ""
    cdn_detected: str = ""
    subdomains: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    services: dict[int, str] = Field(default_factory=dict)  # port: service
    known_vulns: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)  # FP patterns
    scan_count: int = 0
    notes: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolEffectiveness(BaseModel):
    """Track how effective each tool is over time."""

    tool_name: str
    total_runs: int = 0
    successful_runs: int = 0
    total_findings: int = 0
    confirmed_findings: int = 0
    false_positives: int = 0
    avg_execution_time: float = 0.0
    best_against: list[str] = Field(default_factory=list)      # Vuln types
    worst_against: list[str] = Field(default_factory=list)
    last_used: float = 0.0
    effectiveness_score: float = 0.5  # 0.0 = useless, 1.0 = perfect


class VulnPattern(BaseModel):
    """A learned vulnerability pattern."""

    pattern_id: str
    vuln_type: str
    description: str
    indicators: list[str] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)  # Where this pattern is common
    detection_tools: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    confidence_modifier: float = 0.0   # Adjust confidence when pattern matches
    times_seen: int = 0
    times_confirmed: int = 0
    false_positive_rate: float = 0.0
    created: float = Field(default_factory=time.time)
    updated: float = Field(default_factory=time.time)


class FalsePositivePattern(BaseModel):
    """A known false positive pattern learned from experience."""

    pattern_id: str = Field(default_factory=lambda: f"fp-{uuid.uuid4().hex[:12]}")
    tool_name: str
    vuln_type: str
    description: str
    indicators: list[str] = Field(default_factory=list)   # What makes this a FP
    context_clues: list[str] = Field(default_factory=list) # When it triggers
    waf_related: bool = False
    cdn_related: bool = False
    times_seen: int = 0
    confidence: float = 0.0  # How confident we are this is actually a FP pattern
    created: float = Field(default_factory=time.time)
    updated: float = Field(default_factory=time.time)


class AttackChainRecord(BaseModel):
    """A successful attack chain worth remembering."""

    chain_id: str
    target_type: str  # e.g., "wordpress", "api", "network"
    tech_stack: list[str] = Field(default_factory=list)
    steps: list[dict[str, str]] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    vuln_types_found: list[str] = Field(default_factory=list)
    total_findings: int = 0
    success_rate: float = 0.0
    notes: str = ""
    created: float = Field(default_factory=time.time)


# ── Knowledge Base Engine ──────────────────────────────────────────

class KnowledgeBase:
    """
    Persistent long-term memory using SQLite.

    Stores:
    - Target intelligence (tech stack, WAF, services, past findings)
    - Tool effectiveness metrics (success rates, FP rates, speed)
    - Vulnerability patterns (indicators, tech correlations)
    - False positive patterns (learned FP signatures)
    - Attack chain records (successful methodologies)
    - Scan history (session metadata)

    All data persists across sessions and is used to:
    1. Inform tool selection (pick tools with best track record)
    2. Improve FP detection (known FP patterns)
    3. Prioritize attack vectors (what works for this tech stack)
    4. Skip redundant work (already scanned, nothing changed)
    """

    DB_SCHEMA_VERSION = 1

    def __init__(self, db_path: str | Path = "output/knowledge.db"):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialized = False

    def initialize(self) -> None:
        """Create tables if they don't exist."""
        with self._get_conn() as conn:
            conn.executescript(self._get_schema())
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("schema_version", str(self.DB_SCHEMA_VERSION)),
            )
        self._initialized = True
        logger.info(f"Knowledge base initialized at {self._db_path}")

    @staticmethod
    def normalize_tech_stack(
        technologies: dict[str, list[str]] | list[str] | str | None,
    ) -> list[str]:
        """Normalize heterogeneous technology data into unique lowercase labels."""
        if not technologies:
            return []

        raw_values: list[str] = []
        if isinstance(technologies, dict):
            for values in technologies.values():
                if isinstance(values, list):
                    raw_values.extend(str(value) for value in values if str(value).strip())
                elif isinstance(values, str) and values.strip():
                    raw_values.append(values)
        elif isinstance(technologies, list):
            raw_values.extend(str(value) for value in technologies if str(value).strip())
        elif isinstance(technologies, str) and technologies.strip():
            raw_values.append(technologies)

        normalized: list[str] = []
        seen: set[str] = set()
        for raw_value in raw_values:
            cleaned = raw_value.replace(";", ",")
            for part in cleaned.split(","):
                tech = part.strip().lower()
                if not tech or tech in seen:
                    continue
                seen.add(tech)
                normalized.append(tech)
        return normalized

    @contextmanager
    def _get_conn(self):
        """Get a database connection with context management."""
        conn = sqlite3.connect(str(self._db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception as _exc:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Target Intelligence ────────────────────────────────────────

    def save_target_intel(self, intel: TargetIntelligence) -> None:
        """Save or update target intelligence."""
        with self._get_conn() as conn:
            existing = conn.execute(
                "SELECT data FROM target_intel WHERE domain = ?",
                (intel.domain,),
            ).fetchone()

            if existing:
                # Merge with existing data
                old = TargetIntelligence(**json.loads(existing["data"]))
                merged = self._merge_target_intel(old, intel)
                conn.execute(
                    "UPDATE target_intel SET data = ?, updated = ? WHERE domain = ?",
                    (merged.model_dump_json(), time.time(), intel.domain),
                )
            else:
                conn.execute(
                    "INSERT INTO target_intel (domain, data, created, updated) VALUES (?, ?, ?, ?)",
                    (intel.domain, intel.model_dump_json(), time.time(), time.time()),
                )
        logger.debug(f"Saved target intel for {intel.domain}")

    def get_target_intel(self, domain: str) -> TargetIntelligence | None:
        """Retrieve target intelligence."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT data FROM target_intel WHERE domain = ?", (domain,)
            ).fetchone()
            if row:
                return TargetIntelligence(**json.loads(row["data"]))
        return None

    def get_all_targets(self) -> list[TargetIntelligence]:
        """Get all known target intelligence."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT data FROM target_intel ORDER BY updated DESC").fetchall()
            return [TargetIntelligence(**json.loads(r["data"])) for r in rows]

    def _merge_target_intel(
        self, old: TargetIntelligence, new: TargetIntelligence
    ) -> TargetIntelligence:
        """Merge new intel with existing, preserving accumulated data."""
        return TargetIntelligence(
            domain=old.domain,
            first_seen=old.first_seen,
            last_seen=time.time(),
            technologies=list(set(old.technologies + new.technologies)),
            waf_detected=new.waf_detected or old.waf_detected,
            cdn_detected=new.cdn_detected or old.cdn_detected,
            subdomains=list(set(old.subdomains + new.subdomains)),
            open_ports=sorted(set(old.open_ports + new.open_ports)),
            services={**old.services, **new.services},
            known_vulns=list(set(old.known_vulns + new.known_vulns)),
            false_positives=list(set(old.false_positives + new.false_positives)),
            scan_count=old.scan_count + 1,
            notes=new.notes or old.notes,
            metadata={**old.metadata, **new.metadata},
        )

    # ── Tool Effectiveness ─────────────────────────────────────────

    def record_tool_run(
        self,
        tool_name: str,
        success: bool,
        findings: int = 0,
        confirmed: int = 0,
        false_positives: int = 0,
        execution_time: float = 0.0,
        vuln_types: list[str] | None = None,
    ) -> None:
        """Record a tool execution for effectiveness tracking."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT data FROM tool_effectiveness WHERE tool_name = ?",
                (tool_name,),
            ).fetchone()

            if row:
                eff = ToolEffectiveness(**json.loads(row["data"]))
                eff.total_runs += 1
                if success:
                    eff.successful_runs += 1
                eff.total_findings += findings
                eff.confirmed_findings += confirmed
                eff.false_positives += false_positives
                # Running average
                n = eff.total_runs
                eff.avg_execution_time = (eff.avg_execution_time * (n - 1) + execution_time) / n
                eff.last_used = time.time()
                if vuln_types:
                    eff.best_against = list(set(eff.best_against + vuln_types))
                eff.effectiveness_score = self._calculate_effectiveness(eff)

                conn.execute(
                    "UPDATE tool_effectiveness SET data = ?, updated = ? WHERE tool_name = ?",
                    (eff.model_dump_json(), time.time(), tool_name),
                )
            else:
                eff = ToolEffectiveness(
                    tool_name=tool_name,
                    total_runs=1,
                    successful_runs=1 if success else 0,
                    total_findings=findings,
                    confirmed_findings=confirmed,
                    false_positives=false_positives,
                    avg_execution_time=execution_time,
                    best_against=vuln_types or [],
                    last_used=time.time(),
                    effectiveness_score=0.5,
                )
                conn.execute(
                    "INSERT INTO tool_effectiveness (tool_name, data, created, updated) VALUES (?, ?, ?, ?)",
                    (tool_name, eff.model_dump_json(), time.time(), time.time()),
                )

    def get_tool_effectiveness(self, tool_name: str) -> ToolEffectiveness | None:
        """Get effectiveness data for a specific tool."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT data FROM tool_effectiveness WHERE tool_name = ?",
                (tool_name,),
            ).fetchone()
            if row:
                return ToolEffectiveness(**json.loads(row["data"]))
        return None

    def get_best_tools_for(self, vuln_type: str, top_n: int = 5) -> list[ToolEffectiveness]:
        """Get the most effective tools for a specific vulnerability type."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT data FROM tool_effectiveness").fetchall()

        tools = []
        for r in rows:
            eff = ToolEffectiveness(**json.loads(r["data"]))
            if vuln_type.lower() in [v.lower() for v in eff.best_against]:
                tools.append(eff)

        tools.sort(key=lambda t: t.effectiveness_score, reverse=True)
        return tools[:top_n]

    def get_all_tool_stats(self) -> list[ToolEffectiveness]:
        """Get all tool effectiveness data."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT data FROM tool_effectiveness ORDER BY updated DESC"
            ).fetchall()
            return [ToolEffectiveness(**json.loads(r["data"])) for r in rows]

    def _calculate_effectiveness(self, eff: ToolEffectiveness) -> float:
        """
        Calculate effectiveness score (0.0 - 1.0).

        Factors:
        - Success rate (weight: 0.25)
        - Confirmed vs total findings ratio (weight: 0.35)
        - Low FP rate (weight: 0.30)
        - Recency bonus (weight: 0.10)
        """
        if eff.total_runs == 0:
            return 0.5

        success_rate = eff.successful_runs / eff.total_runs

        if eff.total_findings > 0:
            confirm_rate = eff.confirmed_findings / eff.total_findings
            fp_rate = 1.0 - (eff.false_positives / eff.total_findings)
        else:
            confirm_rate = 0.0
            fp_rate = 1.0

        # Recency: higher if used recently
        days_since = (time.time() - eff.last_used) / 86400 if eff.last_used else 30
        recency = 1.0 / (1.0 + days_since / 7)

        score = (
            success_rate * 0.25
            + confirm_rate * 0.35
            + max(0, fp_rate) * 0.30
            + recency * 0.10
        )
        return round(min(1.0, max(0.0, score)), 3)

    # ── Vulnerability Patterns ─────────────────────────────────────

    def save_vuln_pattern(self, pattern: VulnPattern) -> None:
        """Save or update a vulnerability pattern."""
        with self._get_conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO vuln_patterns
                   (pattern_id, vuln_type, data, created, updated)
                   VALUES (?, ?, ?, ?, ?)""",
                (pattern.pattern_id, pattern.vuln_type,
                 pattern.model_dump_json(), pattern.created, time.time()),
            )

    def get_vuln_patterns(self, vuln_type: str | None = None) -> list[VulnPattern]:
        """Get vulnerability patterns, optionally filtered by type."""
        with self._get_conn() as conn:
            if vuln_type:
                rows = conn.execute(
                    "SELECT data FROM vuln_patterns WHERE vuln_type = ?",
                    (vuln_type,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT data FROM vuln_patterns").fetchall()
            return [VulnPattern(**json.loads(r["data"])) for r in rows]

    def increment_pattern_stats(
        self, pattern_id: str, confirmed: bool = True
    ) -> None:
        """Update pattern statistics after a sighting."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT data FROM vuln_patterns WHERE pattern_id = ?",
                (pattern_id,),
            ).fetchone()
            if row:
                p = VulnPattern(**json.loads(row["data"]))
                p.times_seen += 1
                if confirmed:
                    p.times_confirmed += 1
                if p.times_seen > 0:
                    p.false_positive_rate = 1.0 - (p.times_confirmed / p.times_seen)
                p.updated = time.time()
                conn.execute(
                    "UPDATE vuln_patterns SET data = ?, updated = ? WHERE pattern_id = ?",
                    (p.model_dump_json(), time.time(), pattern_id),
                )

    # ── False Positive Patterns ────────────────────────────────────

    def save_fp_pattern(self, pattern: FalsePositivePattern) -> None:
        """Save a learned false positive pattern (increment times_seen if exists)."""
        with self._get_conn() as conn:
            existing = conn.execute(
                "SELECT data FROM fp_patterns WHERE pattern_id = ?",
                (pattern.pattern_id,)
            ).fetchone()
            if existing:
                try:
                    old = FalsePositivePattern(**json.loads(existing["data"]))
                    pattern.times_seen = old.times_seen + 1
                    # Dynamic confidence: ramps 0.5 → 0.95 over repeated observations
                    pattern.confidence = min(0.95, 0.5 + pattern.times_seen * 0.1)
                except Exception as _fp_err:
                    logger.warning(f"FP pattern deserialization failed for {pattern.pattern_id}: {_fp_err}")
            conn.execute(
                """INSERT OR REPLACE INTO fp_patterns
                   (pattern_id, tool_name, vuln_type, data, created)
                   VALUES (?, ?, ?, ?, ?)""",
                (pattern.pattern_id, pattern.tool_name, pattern.vuln_type,
                 pattern.model_dump_json(), pattern.created),
            )
        logger.debug(f"Saved FP pattern: {pattern.pattern_id} (times_seen={pattern.times_seen})")

    def get_fp_patterns(
        self, tool_name: str | None = None, vuln_type: str | None = None
    ) -> list[FalsePositivePattern]:
        """Get FP patterns, optionally filtered."""
        with self._get_conn() as conn:
            query = "SELECT data FROM fp_patterns WHERE 1=1"
            params: list[str] = []
            if tool_name:
                query += " AND tool_name = ?"
                params.append(tool_name)
            if vuln_type:
                query += " AND vuln_type = ?"
                params.append(vuln_type)
            rows = conn.execute(query, params).fetchall()
            return [FalsePositivePattern(**json.loads(r["data"])) for r in rows]

    def check_known_fp(
        self, tool_name: str, vuln_type: str, indicators: list[str]
    ) -> tuple[bool, float]:
        """
        Check if a finding matches a known FP pattern.

        Returns (is_known_fp, confidence).
        """
        patterns = self.get_fp_patterns(tool_name=tool_name, vuln_type=vuln_type)

        best_match = 0.0
        best_pattern = None
        for pattern in patterns:
            if not pattern.indicators:
                continue
            # Calculate indicator overlap
            pattern_indicators = set(i.lower() for i in pattern.indicators)
            finding_indicators = set(i.lower() for i in indicators)
            overlap = pattern_indicators & finding_indicators

            if pattern_indicators:
                match_ratio = len(overlap) / len(pattern_indicators)
                if match_ratio > best_match:
                    best_match = match_ratio
                    best_pattern = pattern

        is_fp = best_match > 0.6
        return is_fp, best_match * best_pattern.confidence if best_pattern else 0.0

    # ── Attack Chains ──────────────────────────────────────────────

    def save_attack_chain(self, chain: AttackChainRecord) -> None:
        """Save a successful attack chain."""
        with self._get_conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO attack_chains
                   (chain_id, target_type, data, created)
                   VALUES (?, ?, ?, ?)""",
                (chain.chain_id, chain.target_type,
                 chain.model_dump_json(), chain.created),
            )

    def get_attack_chains(self, target_type: str | None = None) -> list[AttackChainRecord]:
        """Get attack chains, optionally filtered by target type."""
        with self._get_conn() as conn:
            if target_type:
                rows = conn.execute(
                    "SELECT data FROM attack_chains WHERE target_type = ?",
                    (target_type,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM attack_chains ORDER BY created DESC"
                ).fetchall()
            return [AttackChainRecord(**json.loads(r["data"])) for r in rows]

    def get_best_chain_for_stack(self, tech_stack: list[str]) -> AttackChainRecord | None:
        """Find the most relevant attack chain for a technology stack."""
        chains = self.get_attack_chains()

        best_chain = None
        best_overlap = 0

        for chain in chains:
            overlap = len(set(t.lower() for t in chain.tech_stack) &
                         set(t.lower() for t in tech_stack))
            if overlap > best_overlap:
                best_overlap = overlap
                best_chain = chain

        return best_chain

    # ── Scan History ───────────────────────────────────────────────

    def record_scan_session(
        self,
        session_id: str,
        target: str,
        profile: str,
        mode: str,
        findings_count: int,
        duration_seconds: float,
        tools_used: list[str],
        notes: str = "",
    ) -> None:
        """Record a completed scan session."""
        with self._get_conn() as conn:
            data = json.dumps({
                "session_id": session_id,
                "target": target,
                "profile": profile,
                "mode": mode,
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
                "tools_used": tools_used,
                "notes": notes,
            })
            conn.execute(
                """INSERT INTO scan_history
                   (session_id, target, data, created)
                   VALUES (?, ?, ?, ?)""",
                (session_id, target, data, time.time()),
            )

    def record_scan_learning(
        self,
        *,
        session_id: str,
        target: str,
        profile: str,
        mode: str,
        technologies: dict[str, list[str]] | list[str] | str | None,
        tools_used: list[str],
        raw_findings: list[dict[str, Any]],
        verified_findings: list[dict[str, Any]],
        false_positives: list[dict[str, Any]],
        duration_seconds: float,
    ) -> None:
        """Persist a completed scan as reusable cross-scan learning."""
        tech_stack = self.normalize_tech_stack(technologies)
        raw_findings = raw_findings or []
        verified_findings = verified_findings or []
        false_positives = false_positives or []

        raw_by_tool = Counter(
            self._extract_tool_name(finding)
            for finding in raw_findings
            if self._extract_tool_name(finding)
        )
        verified_by_tool = Counter(
            self._extract_tool_name(finding)
            for finding in verified_findings
            if self._extract_tool_name(finding)
        )
        fp_by_tool = Counter(
            self._extract_tool_name(finding)
            for finding in false_positives
            if self._extract_tool_name(finding)
        )

        vuln_types_by_tool: dict[str, set[str]] = {}
        for finding in verified_findings:
            tool_name = self._extract_tool_name(finding)
            vuln_type = self._extract_vuln_type(finding)
            if tool_name and vuln_type:
                vuln_types_by_tool.setdefault(tool_name, set()).add(vuln_type)

        tool_names = {
            tool.strip().lower()
            for tool in tools_used
            if str(tool).strip()
        }
        tool_names.update(raw_by_tool.keys())
        tool_names.update(verified_by_tool.keys())
        tool_names.update(fp_by_tool.keys())

        for tool_name in sorted(tool_names):
            findings_count = raw_by_tool.get(tool_name, 0)
            confirmed_count = verified_by_tool.get(tool_name, 0)
            fp_count = fp_by_tool.get(tool_name, 0)
            self.record_tool_run(
                tool_name=tool_name,
                success=(findings_count + confirmed_count + fp_count) > 0,
                findings=findings_count or (confirmed_count + fp_count),
                confirmed=confirmed_count,
                false_positives=fp_count,
                execution_time=0.0,
                vuln_types=sorted(vuln_types_by_tool.get(tool_name, set())),
            )

        verified_types = [
            vuln_type
            for vuln_type in (self._extract_vuln_type(finding) for finding in verified_findings)
            if vuln_type
        ]
        fp_types = [
            vuln_type
            for vuln_type in (self._extract_vuln_type(finding) for finding in false_positives)
            if vuln_type
        ]

        self.save_target_intel(
            TargetIntelligence(
                domain=target,
                technologies=tech_stack,
                known_vulns=sorted(set(verified_types)),
                false_positives=sorted(set(fp_types)),
                scan_count=1,
                metadata={
                    "productive_tools": sorted(
                        tool for tool, count in verified_by_tool.items() if count > 0
                    ),
                    "verified_findings": len(verified_findings),
                    "false_positive_count": len(false_positives),
                    "last_profile": profile,
                },
            )
        )

        for fp in false_positives:
            tool_name = self._extract_tool_name(fp)
            vuln_type = self._extract_vuln_type(fp)
            if not tool_name or not vuln_type:
                continue
            reason = str(fp.get("fp_reason") or fp.get("reason") or fp.get("description") or "").strip()
            pattern_basis = reason or f"{tool_name}:{vuln_type}"
            pattern_id = f"fp-{abs(hash(pattern_basis)) % 10**12:012d}"
            self.save_fp_pattern(
                FalsePositivePattern(
                    pattern_id=pattern_id,
                    tool_name=tool_name,
                    vuln_type=vuln_type,
                    description=reason or f"False positive seen for {tool_name}/{vuln_type}",
                    indicators=[
                        value for value in [
                            str(fp.get("title") or "").strip(),
                            str(fp.get("severity") or "").strip().lower(),
                            str(fp.get("target") or "").strip(),
                        ] if value
                    ],
                    context_clues=[
                        value for value in [
                            str(fp.get("waf") or "").strip().lower(),
                            str(fp.get("cdn") or "").strip().lower(),
                        ] if value
                    ],
                    waf_related=bool(fp.get("waf")),
                    cdn_related=bool(fp.get("cdn")),
                    times_seen=1,
                    confidence=0.5,  # starts at 0.5, ramps up with times_seen
                )
            )

        productive_tools = sorted(tool for tool, count in verified_by_tool.items() if count > 0)
        if tech_stack and productive_tools and verified_types:
            self.save_attack_chain(
                AttackChainRecord(
                    chain_id=session_id or f"chain-{uuid.uuid4().hex[:12]}",
                    target_type="web",
                    tech_stack=tech_stack,
                    steps=[
                        {
                            "stage": "vulnerability_scan",
                            "summary": f"Productive tools: {', '.join(productive_tools[:5])}",
                        },
                        {
                            "stage": "fp_elimination",
                            "summary": f"Confirmed {len(verified_findings)} findings after verification",
                        },
                    ],
                    tools_used=productive_tools,
                    vuln_types_found=sorted(set(verified_types)),
                    total_findings=len(verified_findings),
                    success_rate=round(
                        len(verified_findings) / max(1, len(raw_findings) or len(verified_findings)),
                        3,
                    ),
                    notes=f"target={target}",
                )
            )

        self.record_scan_session(
            session_id=session_id or f"scan-{uuid.uuid4().hex[:12]}",
            target=target,
            profile=profile,
            mode=mode,
            findings_count=len(verified_findings),
            duration_seconds=duration_seconds,
            tools_used=sorted(tool_names),
            notes=f"tech_stack={', '.join(tech_stack[:8])}",
        )

    def get_learning_snapshot(
        self,
        technologies: dict[str, list[str]] | list[str] | str | None,
        limit: int = 5,
    ) -> dict[str, Any]:
        """Return reusable historical guidance for a detected technology stack."""
        tech_stack = self.normalize_tech_stack(technologies)
        if not tech_stack:
            return {
                "tech_stack": [],
                "matched_chains": 0,
                "recommended_tools": [],
                "common_vuln_types": [],
                "best_attack_chain": None,
            }

        tech_set = set(tech_stack)
        tool_scores: Counter[str] = Counter()
        vuln_scores: Counter[str] = Counter()
        matched_chains = 0

        for chain in self.get_attack_chains():
            chain_stack = {tech.lower() for tech in chain.tech_stack}
            overlap = len(tech_set & chain_stack)
            if overlap == 0:
                continue
            matched_chains += 1
            weight = (overlap / max(1, len(chain_stack))) + max(chain.success_rate, 0.1)
            for index, tool_name in enumerate(chain.tools_used):
                tool_scores[tool_name] += weight + max(0.0, 0.15 - index * 0.01)
            for vuln_type in chain.vuln_types_found:
                vuln_scores[vuln_type] += weight

        for tool_stat in self.get_all_tool_stats():
            if tool_stat.effectiveness_score > 0:
                tool_scores[tool_stat.tool_name] += tool_stat.effectiveness_score * 0.25

        best_chain = self.get_best_chain_for_stack(tech_stack)
        best_chain_data = None
        if best_chain:
            best_chain_data = {
                "tools_used": best_chain.tools_used,
                "vuln_types_found": best_chain.vuln_types_found,
                "success_rate": best_chain.success_rate,
                "notes": best_chain.notes,
            }

        return {
            "tech_stack": tech_stack,
            "matched_chains": matched_chains,
            "recommended_tools": [
                tool_name for tool_name, _score in tool_scores.most_common(limit)
            ],
            "common_vuln_types": [
                vuln_type for vuln_type, _score in vuln_scores.most_common(limit)
            ],
            "best_attack_chain": best_chain_data,
        }

    def get_scan_history(self, target: str | None = None, limit: int = 20) -> list[dict]:
        """Get scan history."""
        with self._get_conn() as conn:
            if target:
                rows = conn.execute(
                    "SELECT data FROM scan_history WHERE target = ? ORDER BY created DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM scan_history ORDER BY created DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [json.loads(r["data"]) for r in rows]

    # ── Knowledge Summary ──────────────────────────────────────────

    def get_knowledge_summary(self) -> dict:
        """Get a summary of all stored knowledge."""
        with self._get_conn() as conn:
            targets = conn.execute("SELECT COUNT(*) as c FROM target_intel").fetchone()["c"]
            tools = conn.execute("SELECT COUNT(*) as c FROM tool_effectiveness").fetchone()["c"]
            vulns = conn.execute("SELECT COUNT(*) as c FROM vuln_patterns").fetchone()["c"]
            fps = conn.execute("SELECT COUNT(*) as c FROM fp_patterns").fetchone()["c"]
            chains = conn.execute("SELECT COUNT(*) as c FROM attack_chains").fetchone()["c"]
            scans = conn.execute("SELECT COUNT(*) as c FROM scan_history").fetchone()["c"]

        return {
            "targets_known": targets,
            "tools_tracked": tools,
            "vuln_patterns": vulns,
            "fp_patterns": fps,
            "attack_chains": chains,
            "scans_completed": scans,
            "db_path": str(self._db_path),
        }

    # ── Schema ─────────────────────────────────────────────────────

    def _get_schema(self) -> str:
        return """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS target_intel (
            domain TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            created REAL NOT NULL,
            updated REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tool_effectiveness (
            tool_name TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            created REAL NOT NULL,
            updated REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vuln_patterns (
            pattern_id TEXT PRIMARY KEY,
            vuln_type TEXT NOT NULL,
            data TEXT NOT NULL,
            created REAL NOT NULL,
            updated REAL NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_vuln_type ON vuln_patterns(vuln_type);

        CREATE TABLE IF NOT EXISTS fp_patterns (
            pattern_id TEXT PRIMARY KEY,
            tool_name TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            data TEXT NOT NULL,
            created REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_fp_tool ON fp_patterns(tool_name);
        CREATE INDEX IF NOT EXISTS idx_fp_vuln ON fp_patterns(vuln_type);

        CREATE TABLE IF NOT EXISTS attack_chains (
            chain_id TEXT PRIMARY KEY,
            target_type TEXT NOT NULL,
            data TEXT NOT NULL,
            created REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_chain_type ON attack_chains(target_type);

        CREATE TABLE IF NOT EXISTS scan_history (
            session_id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            data TEXT NOT NULL,
            created REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_history(target);
        """

    # ── Async Wrappers ─────────────────────────────────────────────
    # All synchronous SQLite methods above block, so these wrappers
    # offload them to a thread via asyncio.to_thread().

    async def async_initialize(self) -> None:
        await asyncio.to_thread(self.initialize)

    async def async_save_target_intel(self, intel: TargetIntelligence) -> None:
        await asyncio.to_thread(self.save_target_intel, intel)

    async def async_get_target_intel(self, domain: str) -> TargetIntelligence | None:
        return await asyncio.to_thread(self.get_target_intel, domain)

    async def async_update_tool_effectiveness(
        self, tool_name: str, **kwargs: Any
    ) -> None:
        await asyncio.to_thread(self.record_tool_run, tool_name, **kwargs)

    async def async_save_vuln_pattern(self, pattern: VulnPattern) -> None:
        await asyncio.to_thread(self.save_vuln_pattern, pattern)

    async def async_save_fp_pattern(self, pattern: FalsePositivePattern) -> None:
        await asyncio.to_thread(self.save_fp_pattern, pattern)

    async def async_get_fp_patterns(self) -> list[FalsePositivePattern]:
        return await asyncio.to_thread(self.get_fp_patterns)

    async def async_save_attack_chain(self, chain: AttackChainRecord) -> None:
        await asyncio.to_thread(self.save_attack_chain, chain)

    @staticmethod
    def _extract_tool_name(finding: dict[str, Any]) -> str:
        return str(finding.get("tool") or finding.get("source_tool") or "").strip().lower()

    @staticmethod
    def _extract_vuln_type(finding: dict[str, Any]) -> str:
        return str(
            finding.get("type")
            or finding.get("vuln_type")
            or finding.get("category")
            or ""
        ).strip().lower()


__all__ = [
    "KnowledgeBase",
    "TargetIntelligence",
    "ToolEffectiveness",
    "VulnPattern",
    "FalsePositivePattern",
    "AttackChainRecord",
]
