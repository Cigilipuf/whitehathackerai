"""
WhiteHatHacker AI — Correlation Engine

Farklı araçlardan gelen bulguları korelasyonlar,
duplicate'leri birleştirir, zincirleme saldırı yollarını tespit eder
ve genel risk haritası oluşturur.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from src.utils.constants import BrainType

try:
    from src.analysis.global_finding_store import _canonical_vuln_type
except ImportError:  # pragma: no cover
    def _canonical_vuln_type(raw: Any) -> str:
        return str(raw or "unknown").strip().lower().replace(" ", "_").replace("-", "_")


def _coerce_str(value: Any) -> str:
    """Normalize heterogeneous values to strings for comparisons."""
    if value is None:
        return ""
    if isinstance(value, list):
        value = value[0] if value else ""
    return value if isinstance(value, str) else str(value)


# ============================================================
# Models
# ============================================================

class CorrelatedFinding(BaseModel):
    """Korelasyon sonrası birleştirilmiş bulgu."""

    id: str = ""
    title: str = ""
    vuln_type: str = ""
    endpoint: str = ""
    parameter: str = ""
    severity: str = "medium"
    confidence: float = 0.0

    # Birden fazla araçtan gelen kanıtlar
    source_tools: list[str] = Field(default_factory=list)
    source_findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence_count: int = 0

    # Korelasyon bilgileri
    correlation_group: str = ""
    is_duplicate: bool = False
    merged_from: list[str] = Field(default_factory=list)

    # Zincir bilgisi
    chain_id: str = ""
    chain_position: int = 0
    chain_description: str = ""

    # OOB callback correlation
    oob_confirmed: bool = False
    oob_interactions: list[dict[str, Any]] = Field(default_factory=list)
    oob_payload_tag: str = ""


class AttackChain(BaseModel):
    """Zincirleme saldırı yolu."""

    id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "critical"
    findings: list[str] = Field(default_factory=list)  # Finding IDs
    steps: list[str] = Field(default_factory=list)
    impact: str = ""
    likelihood: str = "medium"


class CorrelationReport(BaseModel):
    """Korelasyon raporu."""

    generated_at: str = ""
    total_raw_findings: int = 0
    total_after_dedup: int = 0
    total_duplicates_removed: int = 0
    total_chains_found: int = 0

    correlated_findings: list[CorrelatedFinding] = Field(default_factory=list)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    host_risk_map: dict[str, float] = Field(default_factory=dict)

    statistics: dict[str, Any] = Field(default_factory=dict)


# ============================================================
# Bilinen saldırı zinciri tanımları
# ============================================================

KNOWN_CHAINS: list[dict[str, Any]] = [
    {
        "name": "SQLi → Auth Bypass → Data Exfiltration",
        "required": ["sql_injection"],
        "optional": ["authentication_bypass", "idor"],
        "description": "SQL injection used to bypass authentication and extract sensitive data",
        "severity": "critical",
        "impact": "Full database compromise with unauthorized access to admin functionality",
    },
    {
        "name": "SSRF → Cloud Metadata → Credential Theft",
        "required": ["ssrf"],
        "optional": ["information_disclosure"],
        "description": "SSRF to access cloud metadata endpoint (169.254.169.254) and steal IAM credentials",
        "severity": "critical",
        "impact": "Cloud infrastructure compromise via stolen temporary credentials",
    },
    {
        "name": "XSS → Session Hijacking → Account Takeover",
        "required": ["xss_stored"],
        "optional": ["xss_reflected", "cors_misconfiguration"],
        "description": "Stored XSS to steal session tokens, combined with weak CORS to exfiltrate data",
        "severity": "high",
        "impact": "Mass account takeover affecting all users viewing the compromised page",
    },
    {
        "name": "LFI → Source Code Disclosure → Credential Harvest",
        "required": ["local_file_inclusion"],
        "optional": ["information_disclosure"],
        "description": "Local file inclusion to read source code containing hardcoded credentials or API keys",
        "severity": "high",
        "impact": "Source code and credential exposure leading to deeper compromise",
    },
    {
        "name": "SSTI → RCE → Full Compromise",
        "required": ["ssti"],
        "optional": ["command_injection"],
        "description": "Server-Side Template Injection escalated to remote code execution",
        "severity": "critical",
        "impact": "Full server compromise with potential lateral movement",
    },
    {
        "name": "IDOR → Data Harvesting → PII Exposure",
        "required": ["idor"],
        "optional": ["rate_limit_bypass"],
        "description": "IDOR with rate limit bypass enables mass data harvesting of user PII",
        "severity": "high",
        "impact": "Large-scale unauthorized data access, potential GDPR/compliance violations",
    },
    {
        "name": "Open Redirect → OAuth Token Theft",
        "required": ["open_redirect"],
        "optional": ["authentication_bypass"],
        "description": "Open redirect in OAuth flow to steal authorization codes or tokens",
        "severity": "high",
        "impact": "OAuth token theft enabling account takeover",
    },
    {
        "name": "XXE → SSRF → Internal Network Access",
        "required": ["xxe"],
        "optional": ["ssrf"],
        "description": "XML External Entity leveraged for Server-Side Request Forgery against internal services",
        "severity": "critical",
        "impact": "Internal network reconnaissance and service exploitation",
    },
    {
        "name": "Deserialization → RCE → Persistence",
        "required": ["deserialization"],
        "optional": ["command_injection"],
        "description": "Insecure deserialization leading to arbitrary code execution",
        "severity": "critical",
        "impact": "Full server compromise with ability to install persistent backdoors",
    },
]


# ============================================================
# Correlation Engine
# ============================================================

class CorrelationEngine:
    """
    Bulgu korelasyon motoru.

    İşlevler:
    1. Duplicate tespiti ve birleştirme (aynı zafiyet, farklı araç)
    2. Yakınlık analizi (aynı endpoint farklı parametre)
    3. Zincirleme saldırı yolu tespiti
    4. Host bazlı risk haritası
    5. Genel istatistikler ve özet

    Usage:
        engine = CorrelationEngine()

        # Bulguları ekle
        for finding in all_findings:
            engine.add_finding(finding)

        # Korelasyonu çalıştır
        report = engine.correlate()
    """

    def __init__(self, similarity_threshold: float = 0.7, intelligence_engine: Any = None) -> None:
        self._raw_findings: list[dict[str, Any]] = []
        self._oob_interactions: list[dict[str, Any]] = []
        self._similarity_threshold = similarity_threshold
        self._intelligence_engine = intelligence_engine

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Ham bulgu ekle."""
        self._raw_findings.append(finding)

    def add_findings(self, findings: list[dict[str, Any]]) -> None:
        """Toplu bulgu ekle."""
        self._raw_findings.extend(findings)

    def add_oob_interactions(self, interactions: list[dict[str, Any]]) -> None:
        """Add Interactsh OOB interactions for correlation with findings."""
        self._oob_interactions.extend(interactions)

    def correlate(self) -> CorrelationReport:
        """
        Korelasyon sürecini çalıştır.

        Sıralama:
        1. Normalize et
        2. Grupla (duplicate tespiti)
        3. Birleştir
        4. Zincir tespit et
        5. Host risk haritası
        6. Rapor oluştur
        """
        if not self._raw_findings:
            return CorrelationReport(
                generated_at=datetime.now(timezone.utc).isoformat(),
                total_raw_findings=0,
            )

        # 1. Normalize
        normalized = [self._normalize(f) for f in self._raw_findings]

        # 2. Grupla — aynı endpoint+vuln_type → duplicate
        groups = self._group_findings(normalized)

        # 3. Birleştir
        merged = self._merge_groups(groups)

        # 3.5 OOB callback correlation
        if self._oob_interactions:
            self._correlate_oob(merged)

        # 4. Zincir tespiti
        chains = self._detect_chains(merged)

        # 5. Host risk haritası
        host_risk = self._build_host_risk_map(merged)

        # 6. İstatistikler
        stats = self._compute_statistics(merged, chains)

        duplicates_removed = len(self._raw_findings) - len(merged)

        report = CorrelationReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_raw_findings=len(self._raw_findings),
            total_after_dedup=len(merged),
            total_duplicates_removed=duplicates_removed,
            total_chains_found=len(chains),
            correlated_findings=merged,
            attack_chains=chains,
            host_risk_map=host_risk,
            statistics=stats,
        )

        logger.info(
            f"Correlation complete | raw={len(self._raw_findings)} | "
            f"deduped={len(merged)} | removed={duplicates_removed} | "
            f"chains={len(chains)}"
        )

        return report

    # ── Normalization ───────────────────────────────────────

    @staticmethod
    def _normalize(finding: dict[str, Any]) -> dict[str, Any]:
        """Bulguyu standart formata normalize et."""
        normalized = dict(finding)

        # URL normalizasyonu
        url = finding.get("url", finding.get("endpoint", ""))
        if url:
            # Trailing slash temizle, lowercase host
            url = url.rstrip("/")
            normalized["endpoint"] = url

        # Vuln type normalizasyonu — delegate to canonical form
        vtype = finding.get("vuln_type", finding.get("type", "unknown"))
        normalized["vuln_type"] = _canonical_vuln_type(vtype)

        # Severity normalizasyonu
        sev = str(finding.get("severity") or "medium").lower()
        sev_aliases = {"info": "informational", "informational": "informational",
                       "low": "low", "med": "medium", "medium": "medium",
                       "high": "high", "crit": "critical", "critical": "critical"}
        normalized["severity"] = sev_aliases.get(sev, "medium")

        return normalized

    # ── Grouping ────────────────────────────────────────────

    def _group_findings(
        self, findings: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Aynı endpoint+vuln_type+parameter bulgularını grupla."""
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for f in findings:
            # Gruplama anahtarı
            key_parts = [
                f.get("vuln_type", "unknown"),
                self._normalize_endpoint(f.get("endpoint", "")),
                f.get("parameter", ""),
            ]
            key = hashlib.sha256("|".join(key_parts).encode()).hexdigest()[:16]
            groups[key].append(f)

        return dict(groups)

    @staticmethod
    def _normalize_endpoint(endpoint: str) -> str:
        """Endpoint'i karşılaştırma için normalize et."""
        # Scheme / port varyasyonlarını kaldır
        ep = _coerce_str(endpoint).lower().rstrip("/")
        for prefix in ("https://", "http://"):
            if ep.startswith(prefix):
                ep = ep[len(prefix):]
        # Default port kaldır
        ep = ep.replace(":443", "").replace(":80", "")
        return ep

    # ── Merging ─────────────────────────────────────────────

    def _merge_groups(
        self, groups: dict[str, list[dict[str, Any]]]
    ) -> list[CorrelatedFinding]:
        """Grupları birleştirerek tekil bulgular oluştur."""
        merged: list[CorrelatedFinding] = []
        counter = 0

        for group_key, group_findings in groups.items():
            counter += 1

            # En yüksek güvenli bulguyu ana olarak seç
            primary = max(group_findings, key=lambda f: f.get("confidence", 0))

            # Araç listesi
            tools = list({
                f.get("tool", f.get("source_tool", "unknown"))
                for f in group_findings
            })

            # Güven skoru — birden fazla araç = daha yüksek güven
            base_conf = primary.get("confidence", 50.0)
            multi_tool_bonus = min(len(tools) - 1, 3) * 10  # +10 per extra tool, max +30
            confidence = min(100.0, base_conf + multi_tool_bonus)

            # Severity — en yüksek olanı al
            severity_order = ["info", "low", "medium", "high", "critical"]
            severities = [f.get("severity", "medium") for f in group_findings]
            max_sev = max(severities, key=lambda s: severity_order.index(s) if s in severity_order else 2)

            cf = CorrelatedFinding(
                id=f"CORR-{counter:04d}",
                title=primary.get("title", primary.get("name", "")),
                vuln_type=primary.get("vuln_type", "unknown"),
                endpoint=primary.get("endpoint", primary.get("url", "")),
                parameter=primary.get("parameter", ""),
                severity=max_sev,
                confidence=confidence,
                source_tools=tools,
                source_findings=group_findings,
                evidence_count=len(group_findings),
                correlation_group=group_key,
                is_duplicate=len(group_findings) > 1,
                merged_from=[
                    f.get("id", f.get("tool", "?")) for f in group_findings
                ],
            )
            merged.append(cf)

        # Severity + confidence'a göre sırala
        severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        merged.sort(
            key=lambda c: (severity_rank.get(c.severity, 0), c.confidence),
            reverse=True,
        )

        return merged

    # ── OOB Callback Correlation ──────────────────────────────

    # Vuln types that produce OOB callbacks
    _OOB_VULN_TYPES = frozenset({
        "ssrf", "xxe", "command_injection", "ssti",
        "remote_file_inclusion", "sql_injection",
    })

    def _correlate_oob(self, findings: list[CorrelatedFinding]) -> None:
        """Match Interactsh OOB interactions to findings by tag or vuln type."""
        if not self._oob_interactions:
            return

        oob_matched = 0

        for finding in findings:
            # Check each source finding for an oob_tag in metadata
            tags_to_check: list[str] = []
            for src in finding.source_findings:
                meta = src.get("metadata", {})
                if isinstance(meta, dict):
                    tag = meta.get("oob_tag", "")
                    if tag:
                        tags_to_check.append(_coerce_str(tag).lower())

            matched_interactions: list[dict[str, Any]] = []

            # Tag-based correlation: match tag substring in full-id/unique-id
            for interaction in self._oob_interactions:
                full_id = (
                    interaction.get("full-id", "")
                    + interaction.get("unique-id", "")
                ).lower()
                for tag in tags_to_check:
                    safe_tag = re.sub(r"[^a-z0-9-]", "", tag)
                    if safe_tag and safe_tag in full_id:
                        matched_interactions.append(interaction)
                        break

            # Type-based heuristic: if finding is blind-capable type and
            # there are unmatched OOB interactions of matching protocol
            # Limit to max 2 interactions to avoid over-broad false confirmations
            if (
                not matched_interactions
                and finding.vuln_type in self._OOB_VULN_TYPES
            ):
                _type_matches: list[dict[str, Any]] = []
                for interaction in self._oob_interactions:
                    proto = interaction.get("protocol", "").upper()
                    # DNS callbacks commonly confirm SSRF/XXE
                    if finding.vuln_type in ("ssrf", "xxe") and proto in (
                        "DNS", "HTTP",
                    ):
                        _type_matches.append(interaction)
                    elif finding.vuln_type == "command_injection" and proto in (
                        "DNS", "HTTP",
                    ):
                        _type_matches.append(interaction)
                    if len(_type_matches) >= 2:
                        break
                matched_interactions = _type_matches

            if matched_interactions:
                finding.oob_confirmed = True
                finding.oob_interactions = matched_interactions
                # OOB confirmation boosts confidence significantly
                finding.confidence = min(100.0, finding.confidence + 25)
                oob_matched += 1

        if oob_matched:
            logger.info(
                f"OOB correlation: {oob_matched} finding(s) confirmed via "
                f"{len(self._oob_interactions)} Interactsh interaction(s)"
            )

    # ── Chain detection ─────────────────────────────────────

    def _detect_chains(
        self, findings: list[CorrelatedFinding]
    ) -> list[AttackChain]:
        """Zincirleme saldırı yollarını tespit et."""
        chains: list[AttackChain] = []
        vuln_types = {f.vuln_type for f in findings}
        # Use defaultdict(list) to handle multiple findings of the same type
        finding_map: dict[str, list[CorrelatedFinding]] = defaultdict(list)
        for f in findings:
            finding_map[f.vuln_type].append(f)

        chain_counter = 0

        for chain_def in KNOWN_CHAINS:
            required = set(chain_def["required"])
            optional = set(chain_def.get("optional", []))

            # Zorunlu türler mevcut mu?
            if not required.issubset(vuln_types):
                continue

            # Eşleşen bulgular
            matched_types = required | (optional & vuln_types)
            matched_finding_ids = []
            for vt in matched_types:
                for f in finding_map.get(vt, []):
                    matched_finding_ids.append(f.id)

            chain_counter += 1

            chain = AttackChain(
                id=f"CHAIN-{chain_counter:03d}",
                name=chain_def["name"],
                description=chain_def["description"],
                severity=chain_def["severity"],
                findings=matched_finding_ids,
                steps=[
                    f"Step {i+1}: Exploit {vt.replace('_', ' ')}"
                    for i, vt in enumerate(matched_types)
                ],
                impact=chain_def["impact"],
                likelihood="high" if len(matched_types) > 1 else "medium",
            )
            chains.append(chain)

            # İlgili bulgulara zincir bilgisi ekle
            for i, vt in enumerate(matched_types):
                for f in finding_map.get(vt, []):
                    f.chain_id = chain.id
                    f.chain_position = i + 1
                    f.chain_description = chain.name

            logger.info(
                f"Attack chain detected: {chain.name} | "
                f"findings={matched_finding_ids} | severity={chain.severity}"
            )

        return chains

    async def detect_chains_llm(
        self, findings: list[CorrelatedFinding]
    ) -> list[AttackChain]:
        """V6-T0-3 + P3-3: LLM-powered cross-finding reasoning with technology-aware
        chain templates and attack narrative structure.

        Analyzes all findings together to identify attack chains that go
        beyond the hardcoded KNOWN_CHAINS patterns. Uses chain-specific
        prompt templates for common attack patterns.
        """
        if not self._intelligence_engine or not getattr(self._intelligence_engine, "is_available", False):
            return []

        if len(findings) < 2:
            return []

        # Build finding summary — include ALL findings (up to 50)
        summary_lines = []
        for f in findings[:50]:
            summary_lines.append(
                f"- [{f.severity.upper()}] {f.vuln_type} at {f.endpoint} "
                f"(confidence={f.confidence:.0f}%, tools={','.join(f.source_tools)})"
            )
        findings_text = "\n".join(summary_lines)

        # Collect technology hints from findings
        techs = set()
        for f in findings:
            for t in getattr(f, "technologies", []) or []:
                        techs.add(_coerce_str(t).lower())

        # Build chain-specific hint section based on observed vuln types
        vuln_types = {_canonical_vuln_type(f.vuln_type) for f in findings}
        chain_hints = self._build_chain_hints(vuln_types, techs)

        prompt = (
            "You are an expert bug bounty hunter analyzing correlated findings.\n"
            "Below are the deduplicated vulnerability findings from a scan:\n\n"
            f"{findings_text}\n\n"
            f"**Technologies detected:** {', '.join(techs) or 'unknown'}\n\n"
            "## Attack Chain Analysis\n\n"
            "Identify ATTACK CHAINS where multiple findings can be chained together "
            "for a more severe impact than each individual finding.\n\n"
            "For each chain, provide:\n"
            "1. **Attack Narrative**: A story describing how an attacker would chain these.\n"
            "2. **Steps**: Ordered exploitation steps with specific payloads/endpoints.\n"
            "3. **Impact**: Concrete business impact (data breach, account takeover, etc.).\n"
            "4. **Severity**: Re-assessed severity for the CHAIN (not individual findings).\n\n"
            f"{chain_hints}"
            "Return a JSON array of chain objects:\n"
            "```json\n"
            '[{"name": "Chain Name", "narrative": "Attacker first exploits X to gain Y, '
            'then uses Y to achieve Z...", "steps": ["Step 1: ...", "Step 2: ..."], '
            '"impact": "Business impact description", "severity": "critical|high|medium", '
            '"finding_types": ["vuln_type_1", "vuln_type_2"], '
            '"prerequisites": ["any preconditions"], "likelihood": "high|medium|low"}]\n'
            "```\n"
            "If no meaningful chains exist, return `[]`."
        )

        try:
            data = await self._intelligence_engine._brain_call_json(
                prompt=prompt,
                system_prompt=(
                    "You are a cybersecurity expert specializing in multi-stage attack analysis. "
                    "Focus on chains that amplify impact — don't force chains where none exist."
                ),
                brain=BrainType.PRIMARY,
                timeout=180,
            )
            if not data:
                return []

            # Handle both list and dict responses
            chain_list = data if isinstance(data, list) else data.get("chains", [])
            if not isinstance(chain_list, list):
                return []

            existing_count = len([f for f in findings if f.chain_id])
            chains: list[AttackChain] = []
            for i, chain_data in enumerate(chain_list):
                if not isinstance(chain_data, dict):
                    continue
                chain = AttackChain(
                    id=f"CHAIN-LLM-{existing_count + i + 1:03d}",
                    name=chain_data.get("name", "LLM-Detected Chain"),
                    description=chain_data.get("narrative", chain_data.get("impact", "")),
                    severity=chain_data.get("severity", "medium"),
                    findings=[],
                    steps=chain_data.get("steps", []),
                    impact=chain_data.get("impact", ""),
                    likelihood=chain_data.get("likelihood", "medium"),
                )

                chain_types = set(chain_data.get("finding_types", []))
                for f in findings:
                    if f.vuln_type in chain_types:
                        chain.findings.append(f.id)

                if chain.findings:
                    chains.append(chain)

            if chains:
                logger.info("LLM cross-finding reasoning: {} novel chain(s) detected", len(chains))

            return chains

        except Exception as exc:
            logger.debug("LLM chain detection failed: {}", exc)
            return []

    @staticmethod
    def _build_chain_hints(vuln_types: set[str], techs: set[str]) -> str:
        """Build technology-aware chain hint section for the LLM prompt."""
        hints = []

        # SSRF + cloud metadata → credential pivot
        if any("ssrf" in v for v in vuln_types):
            hints.append(
                "**SSRF Chain Hint:** If SSRF is found, consider chaining with cloud metadata "
                "endpoints (169.254.169.254, metadata.google.internal) to extract IAM credentials, "
                "or with internal services (Redis/Elasticsearch/K8s API) for lateral movement."
            )

        # XSS + CSRF/CORS → session hijack
        if any("xss" in v for v in vuln_types) and any(
            x in vuln_types for x in ("cors", "csrf", "cors_misconfiguration")
        ):
            hints.append(
                "**XSS + CORS/CSRF Chain Hint:** XSS combined with CORS misconfiguration or "
                "missing CSRF protection can enable full account takeover via session token theft."
            )

        # SQLi + auth bypass → data breach
        if any("sql" in v for v in vuln_types) and any("auth" in v or "idor" in v for v in vuln_types):
            hints.append(
                "**SQLi + Auth Chain Hint:** SQL injection combined with authentication bypass "
                "or IDOR can lead to unauthorized access to any user's data."
            )

        # Open redirect + OAuth → token theft
        if any("redirect" in v for v in vuln_types) and any("oauth" in t or "jwt" in t for t in techs):
            hints.append(
                "**Open Redirect + OAuth Chain Hint:** Open redirect on OAuth callback URL "
                "can redirect authorization codes to attacker-controlled domain."
            )

        # JWT + IDOR → privilege escalation
        if any("jwt" in v for v in vuln_types) and any("idor" in v or "bola" in v for v in vuln_types):
            hints.append(
                "**JWT + IDOR Chain Hint:** Weak JWT validation combined with IDOR "
                "can enable privilege escalation — modify JWT claims to access other users' resources."
            )

        if not hints:
            return ""
        return "### Technology-Specific Chain Hints\n" + "\n".join(hints) + "\n\n"

    # ── Host risk map ───────────────────────────────────────

    def _build_host_risk_map(
        self, findings: list[CorrelatedFinding]
    ) -> dict[str, float]:
        """Host bazlı toplam risk skoru."""
        host_scores: dict[str, list[float]] = defaultdict(list)

        severity_weight = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 2.0,
            "informational": 0.5,
        }

        for f in findings:
            # Host çıkar
            host = self._extract_host(f.endpoint)
            if not host:
                continue

            weight = severity_weight.get(f.severity, 3.0)
            score = weight * (f.confidence / 100.0)
            host_scores[host].append(score)

        # Toplam risk (sum — daha çok bulgu = daha yüksek risk)
        result = {}
        for host, scores in host_scores.items():
            result[host] = round(sum(scores), 1)

        return dict(sorted(result.items(), key=lambda x: -x[1]))

    @staticmethod
    def _extract_host(endpoint: str) -> str:
        """Endpoint'ten host çıkar."""
        ep = _coerce_str(endpoint).lower()
        for prefix in ("https://", "http://"):
            if ep.startswith(prefix):
                ep = ep[len(prefix):]
        # Port ve path kaldır
        ep = ep.split("/")[0].split(":")[0]
        return ep

    # ── Statistics ──────────────────────────────────────────

    def _compute_statistics(
        self,
        findings: list[CorrelatedFinding],
        chains: list[AttackChain],
    ) -> dict[str, Any]:
        """Genel istatistikler."""
        severity_dist: dict[str, int] = defaultdict(int)
        type_dist: dict[str, int] = defaultdict(int)
        tool_dist: dict[str, int] = defaultdict(int)

        for f in findings:
            severity_dist[f.severity] += 1
            type_dist[f.vuln_type] += 1
            for tool in f.source_tools:
                tool_dist[tool] += 1

        multi_tool = sum(1 for f in findings if len(f.source_tools) > 1)
        avg_confidence = (
            sum(f.confidence for f in findings) / len(findings)
            if findings else 0
        )

        return {
            "severity_distribution": dict(severity_dist),
            "vulnerability_type_distribution": dict(type_dist),
            "tool_distribution": dict(tool_dist),
            "multi_tool_confirmed": multi_tool,
            "single_tool_only": len(findings) - multi_tool,
            "average_confidence": round(avg_confidence, 1),
            "attack_chains_found": len(chains),
            "critical_chains": sum(1 for c in chains if c.severity == "critical"),
        }

    def to_markdown(self) -> str:
        """Korelasyon raporunu markdown string olarak döndür."""
        report = self.correlate()

        lines = ["# Correlation Report\n"]
        lines.append(f"**Generated**: {report.generated_at}")
        lines.append(f"**Raw findings**: {report.total_raw_findings}")
        lines.append(f"**After dedup**: {report.total_after_dedup}")
        lines.append(f"**Duplicates removed**: {report.total_duplicates_removed}")
        lines.append(f"**Attack chains**: {report.total_chains_found}\n")

        # Attack Chains
        if report.attack_chains:
            lines.append("## Attack Chains\n")
            for chain in report.attack_chains:
                lines.append(f"### {chain.id}: {chain.name}")
                lines.append(f"- **Severity**: {chain.severity.upper()}")
                lines.append(f"- **Impact**: {chain.impact}")
                for step in chain.steps:
                    lines.append(f"  - {step}")
                lines.append("")

        # Correlated Findings
        lines.append("## Correlated Findings\n")
        lines.append("| ID | Type | Severity | Endpoint | Tools | Confidence |")
        lines.append("|----|------|----------|----------|-------|------------|")
        for f in report.correlated_findings[:30]:
            tools = ", ".join(f.source_tools[:3])
            ep = f.endpoint[:50] + "..." if len(f.endpoint) > 50 else f.endpoint
            lines.append(
                f"| {f.id} | {f.vuln_type} | {f.severity} | "
                f"{ep} | {tools} | {f.confidence:.0f}% |"
            )

        # Host Risk Map
        if report.host_risk_map:
            lines.append("\n## Host Risk Map\n")
            lines.append("| Host | Risk Score |")
            lines.append("|------|-----------|")
            for host, score in list(report.host_risk_map.items())[:20]:
                lines.append(f"| {host} | {score:.1f} |")

        return "\n".join(lines)

    def reset(self) -> None:
        """Tüm verileri temizle."""
        self._raw_findings.clear()
        self._oob_interactions.clear()


__all__ = [
    "CorrelationEngine",
    "CorrelationReport",
    "CorrelatedFinding",
    "AttackChain",
]
