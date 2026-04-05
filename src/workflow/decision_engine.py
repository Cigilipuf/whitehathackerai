"""
WhiteHatHacker AI — Decision Engine

Workflow kararlarını veren akıllı karar motoru.
Brain modelleri, knowledge base, attack planner ve
self-reflection verilerini birleştirerek her aşamada
en optimal kararı verir.

Karar Türleri:
  - Hangi araçları çalıştırmalı?
  - Hangi sırada?
  - Bu bulgu gerçek mi?
  - Bir sonraki aşamaya geçmeli miyiz?
  - Taramayı durdurmalı mıyız?
  - İnsan onayı gerekli mi?
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from loguru import logger
from pydantic import BaseModel

from src.utils.constants import (
    BrainType,
    OperationMode,
    ScanProfile,
    WorkflowStage,
)


# ============================================================
# Karar Modelleri
# ============================================================

class Decision(BaseModel):
    """Tek bir karar."""

    decision_id: str = ""
    decision_type: str = ""        # tool_selection | stage_transition | finding_verdict | abort | escalate
    question: str = ""             # Sorulan soru
    answer: str = ""               # Verilen karar
    confidence: float = 0.0        # 0-1.0
    reasoning: str = ""            # Gerekçe

    # Bağlam
    stage: str = ""
    timestamp: float = 0.0
    brain_used: str = ""           # primary | secondary | both | rule_based

    # Sonuç
    actions: list[dict[str, Any]] = []  # Uygulanacak aksiyonlar
    alternatives: list[str] = []        # Alternatif kararlar

    @property
    def is_confident(self) -> bool:
        return self.confidence >= 0.7


class ToolSelectionResult(BaseModel):
    """Araç seçimi sonucu."""

    selected_tools: list[str]
    execution_order: str = "parallel"   # parallel | sequential | chain
    reasoning: str = ""
    options_per_tool: dict[str, dict[str, Any]] = {}


class StageTransitionResult(BaseModel):
    """Aşama geçiş kararı."""

    should_proceed: bool = True
    next_stage: str = ""
    skip_stages: list[str] = []
    reasoning: str = ""
    additional_work_needed: list[str] = []


# ============================================================
# Araç Seçim Matrisi
# ============================================================

# Her aşama + hedef türü kombinasyonu için araç grupları
STAGE_TOOL_MATRIX: dict[str, dict[str, list[str]]] = {
    "passive_recon": {
        "domain": ["amass", "theharvester", "whois", "shodan", "dnsrecon", "dig"],
        "ip": ["shodan", "whois", "dnsrecon"],
        "url": ["whois", "whatweb", "httpx"],
    },
    "active_recon": {
        "domain": [
            "httpx", "nmap", "whatweb", "wafw00f", "ffuf", "gobuster",
        ],
        "ip": ["nmap", "masscan"],
        "url": ["httpx", "whatweb", "wafw00f", "nikto", "ffuf"],
    },
    "enumeration": {
        "web": [
            "ffuf", "gobuster", "nikto", "whatweb",
        ],
        "network": [
            "nmap", "enum4linux", "smbclient", "snmpwalk",
            "ldapsearch", "ssh_audit",
        ],
        "api": ["httpx", "ffuf"],
    },
    "vulnerability_scanning": {
        "web": [
            "nuclei", "nikto", "sqlmap", "dalfox", "searchsploit",
            "commix", "wpscan", "sslscan", "sslyze", "corsy",
        ],
        "network": [
            "nmap", "searchsploit", "netexec", "ssh_audit",
        ],
        "custom": [
            "idor_checker", "auth_bypass_checker",
            "rate_limit_checker", "race_condition_checker",
            "business_logic_checker",
        ],
    },
}

# Profile bazlı araç limitleri
PROFILE_LIMITS: dict[str, dict[str, Any]] = {
    "stealth": {
        "max_parallel": 2,
        "max_tools_per_stage": 4,
        "skip_aggressive_tools": True,
        "aggressive_tools": ["masscan", "sqlmap", "commix", "hydra", "metasploit"],
        "rate_multiplier": 0.3,
    },
    "balanced": {
        "max_parallel": 4,
        "max_tools_per_stage": 8,
        "skip_aggressive_tools": False,
        "aggressive_tools": [],
        "rate_multiplier": 1.0,
    },
    "aggressive": {
        "max_parallel": 6,
        "max_tools_per_stage": 15,
        "skip_aggressive_tools": False,
        "aggressive_tools": [],
        "rate_multiplier": 2.0,
    },
}


class DecisionEngine:
    """
    Akıllı karar motoru.

    Brain modelleri, geçmiş bilgi, mevcut durum ve konfigürasyonu
    birleştirerek her aşamada en optimal kararı verir.

    Kullanım:
        engine = DecisionEngine(
            brain_engine=brain,
            knowledge_base=kb,
            mode=OperationMode.SEMI_AUTONOMOUS,
            profile=ScanProfile.BALANCED,
        )

        # Araç seçimi
        tools = await engine.select_tools(stage, target_type, context)

        # Aşama geçişi
        transition = await engine.should_transition(state, current_results)
    """

    def __init__(
        self,
        brain_engine: Any | None = None,
        knowledge_base: Any | None = None,
        attack_planner: Any | None = None,
        self_reflection: Any | None = None,
        registry: Any | None = None,
        mode: OperationMode = OperationMode.SEMI_AUTONOMOUS,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> None:
        self.brain = brain_engine
        self.kb = knowledge_base
        self.planner = attack_planner
        self.reflection = self_reflection
        self.registry = registry
        self.mode = mode
        self.profile = profile

        self._decision_log: list[Decision] = []
        self._counter = 0

        logger.info(
            f"DecisionEngine initialized | mode={mode} | profile={profile}"
        )

    # ── Araç Seçimi ───────────────────────────────────────────

    async def select_tools(
        self,
        stage: WorkflowStage,
        target_type: str = "domain",
        context: dict[str, Any] | None = None,
    ) -> ToolSelectionResult:
        """
        Mevcut aşama ve bağlam için en uygun araçları seç.

        Args:
            stage: Mevcut workflow aşaması
            target_type: domain | ip | url | web | network | api
            context: Ek bağlam bilgisi (technologies, previous_results, etc.)

        Returns:
            ToolSelectionResult
        """
        context = context or {}

        # 1. Rule-based selection (matris tabanlı)
        candidate_tools = self._get_matrix_tools(stage.value, target_type)

        # 2. Profile filtresi
        candidates = self._apply_profile_filter(candidate_tools)

        # 3. Availability filtresi
        available = self._filter_available(candidates)

        # 4. Knowledge base optimizasyonu (geçmiş verilerden öğrenme)
        if self.kb:
            available = await self._optimize_with_knowledge(available, target_type, context)

        # 5. Technology-specific eklemeler
        tech_extras = self._get_tech_specific_tools(context.get("technologies", {}))
        for tool in tech_extras:
            if tool not in available:
                available.append(tool)

        # 5b. Filter out tech-only tools that don't match the stack
        technologies = context.get("technologies", {})
        if technologies:
            available = self.filter_irrelevant_tools(available, technologies)

        # 6. Brain-guided prioritization (karmaşık durumlar için)
        if self.brain and context.get("use_brain", False):
            available = await self._brain_prioritize(available, stage, context)

        # 7. Profile limit
        limits = PROFILE_LIMITS.get(self.profile.value, PROFILE_LIMITS["balanced"])
        max_tools = limits["max_tools_per_stage"]
        final_tools = available[:max_tools]

        # 8. Minimum tool guarantee — never return empty for vuln scanning
        if not final_tools and stage.value == "vulnerability_scanning":
            fallback = ["nuclei"]
            if self.registry:
                fallback = [t for t in fallback if (self.registry.get(t) and self.registry.get(t).is_available())]
            if fallback:
                final_tools = fallback
                logger.warning(f"Tool selection empty for {stage.value}, using fallback: {fallback}")

        # Execution order
        exec_order = self._determine_execution_order(final_tools, stage)

        result = ToolSelectionResult(
            selected_tools=final_tools,
            execution_order=exec_order,
            reasoning=(
                f"Selected {len(final_tools)} tools for {stage.value} "
                f"(target_type={target_type}, profile={self.profile})"
            ),
        )

        # Log decision
        self._log_decision(
            decision_type="tool_selection",
            question=f"Which tools for {stage.value}/{target_type}?",
            answer=str(final_tools),
            confidence=0.8,
            reasoning=result.reasoning,
            stage=stage.value,
            brain_used="rule_based",
        )

        logger.info(
            f"Tools selected | stage={stage.value} | "
            f"count={len(final_tools)} | order={exec_order} | "
            f"tools={final_tools}"
        )

        return result

    def _get_matrix_tools(self, stage: str, target_type: str) -> list[str]:
        """Matris tabanlı araç seçimi."""
        stage_tools = STAGE_TOOL_MATRIX.get(stage, {})
        tools = stage_tools.get(target_type, [])

        if not tools:
            # Fuzzy match: domain → web, ip → network
            fallback_map = {
                "domain": "web",
                "ip": "network",
                "url": "web",
                "subnet": "network",
            }
            alt_type = fallback_map.get(target_type, "web")
            tools = stage_tools.get(alt_type, [])

        return list(tools)  # Copy

    def _apply_profile_filter(self, tools: list[str]) -> list[str]:
        """Profile'a göre araç filtrele."""
        limits = PROFILE_LIMITS.get(self.profile.value, PROFILE_LIMITS["balanced"])

        if limits.get("skip_aggressive_tools"):
            aggressive = set(limits.get("aggressive_tools", []))
            return [t for t in tools if t not in aggressive]

        return tools

    def _filter_available(self, tools: list[str]) -> list[str]:
        """Registry'den sadece mevcut araçları filtrele."""
        if not self.registry:
            return tools

        available = []
        for name in tools:
            tool = self.registry.get(name)
            if tool and tool.is_available():
                available.append(name)
            else:
                logger.debug(f"Tool not available, skipping: {name}")

        return available

    async def _optimize_with_knowledge(
        self,
        tools: list[str],
        target_type: str,
        context: dict[str, Any],
    ) -> list[str]:
        """Knowledge base'den alınmış past effectiveness verileriyle optimize et."""
        if not self.kb:
            return tools

        try:
            # Build a lookup of effectiveness scores from KB
            effectiveness = self.kb.get_best_tools_for(target_type)
            # Map tool_name → effectiveness_score (0.0–1.0)
            eff_scores: dict[str, float] = {}
            for t in effectiveness:
                name = t.get("name") if isinstance(t, dict) else getattr(t, "tool_name", "")
                score = (
                    t.get("effectiveness_score", 0.5)
                    if isinstance(t, dict)
                    else getattr(t, "effectiveness_score", 0.5)
                )
                if name:
                    eff_scores[name] = float(score)

            scored: list[tuple[str, float]] = []
            for tool_name in tools:
                if tool_name in eff_scores:
                    # Use actual recorded effectiveness (0.0–1.0)
                    scored.append((tool_name, eff_scores[tool_name]))
                else:
                    # Unknown tool — neutral score
                    scored.append((tool_name, 0.5))

            # Skora göre sırala
            scored.sort(key=lambda x: x[1], reverse=True)
            return [name for name, _ in scored]

        except Exception as e:
            logger.debug(f"Knowledge optimization failed: {e}")
            return tools

    # ── Technology → Tool Matrix ────────────────────────────────
    # Keys: lowercase substring or keyword matched against tech_set.
    # Values: list of tool names to ADD when the tech is detected.
    _TECH_TOOL_MAP: dict[str, list[str]] = {
        # CMS
        "wordpress": ["wpscan", "sqlmap", "nuclei"],
        "joomla": ["joomscan", "sqlmap", "nuclei"],
        "drupal": ["droopescan", "sqlmap", "nuclei"],
        "magento": ["magescan", "sqlmap", "nuclei"],
        # Languages / Runtimes
        "php": ["sqlmap", "commix", "tplmap"],
        "java": ["nuclei", "sqlmap", "deserialization_checker"],
        "asp.net": ["nuclei", "sqlmap"],
        ".net": ["nuclei", "sqlmap"],
        "python": ["sqlmap", "tplmap", "commix"],
        "ruby": ["sqlmap", "tplmap"],
        "node.js": ["nuclei", "prototype_pollution_checker"],
        "golang": ["nuclei"],
        # Frameworks
        "django": ["sqlmap", "tplmap", "nuclei"],
        "flask": ["sqlmap", "tplmap", "commix"],
        "spring boot": ["nuclei", "deserialization_checker"],
        "spring": ["nuclei", "deserialization_checker"],
        "laravel": ["sqlmap", "nuclei"],
        "rails": ["sqlmap", "tplmap", "nuclei"],
        "express": ["nuclei", "prototype_pollution_checker"],
        "fastapi": ["nuclei", "sqlmap"],
        "next.js": ["nuclei", "prototype_pollution_checker"],
        "react": ["js_analyzer"],
        "angular": ["js_analyzer"],
        "vue": ["js_analyzer"],
        # Servers
        "apache": ["nuclei", "nikto"],
        "nginx": ["nuclei", "nikto"],
        "iis": ["nuclei", "nikto", "davtest"],
        "tomcat": ["nuclei", "nikto", "metasploit_aux"],
        "weblogic": ["nuclei", "deserialization_checker"],
        "websphere": ["nuclei", "deserialization_checker"],
        "jboss": ["nuclei", "deserialization_checker"],
        "jetty": ["nuclei"],
        "caddy": ["nuclei"],
        # API
        "graphql": ["graphql_deep_scanner", "nuclei"],
        "swagger": ["swagger_parser", "api_fuzzer"],
        "openapi": ["swagger_parser", "api_fuzzer"],
        "rest": ["api_fuzzer", "nuclei"],
        "grpc": ["nuclei"],
        # Auth
        "jwt": ["jwt_checker", "jwt_tool"],
        "oauth": ["oauth_tester", "nuclei"],
        "saml": ["nuclei"],
        # Databases (exposed services)
        "mysql": ["sqlmap", "nuclei"],
        "postgresql": ["sqlmap", "nuclei"],
        "mongodb": ["nosqlmap", "nuclei"],
        "redis": ["nuclei"],
        "elasticsearch": ["nuclei"],
        "couchdb": ["nuclei"],
        # Infrastructure
        "docker": ["cloud_checker", "nuclei"],
        "kubernetes": ["cloud_checker", "nuclei"],
        "jenkins": ["nuclei", "cloud_checker"],
        "gitlab": ["nuclei"],
        "grafana": ["nuclei"],
        "prometheus": ["nuclei"],
        "kibana": ["nuclei"],
        "sonarqube": ["nuclei"],
        # Network
        "smb": ["enum4linux", "smbclient", "netexec"],
        "samba": ["enum4linux", "smbclient", "netexec"],
        "windows": ["enum4linux", "smbclient", "netexec"],
        "active directory": ["enum4linux", "ldapsearch", "netexec"],
        "ssh": ["ssh_audit"],
        "ftp": ["nmap", "nuclei"],
        "snmp": ["snmpwalk"],
        "ldap": ["ldapsearch", "nuclei"],
        # TLS
        "ssl": ["sslscan", "sslyze", "testssl"],
        "tls": ["sslscan", "sslyze", "testssl"],
        "https": ["sslscan", "sslyze"],
    }

    # Tools that are ONLY relevant when their target tech is detected.
    # If none of the tech triggers are found, these tools are skipped.
    _TECH_ONLY_TOOLS: dict[str, list[str]] = {
        "wpscan": ["wordpress"],
        "joomscan": ["joomla"],
        "droopescan": ["drupal"],
        "magescan": ["magento"],
        "enum4linux": ["smb", "samba", "windows", "active directory"],
        "smbclient": ["smb", "samba", "windows"],
        "netexec": ["smb", "samba", "windows", "active directory"],
        "snmpwalk": ["snmp"],
        "ldapsearch": ["ldap", "active directory"],
        "ssh_audit": ["ssh"],
        "nosqlmap": ["mongodb", "nosql", "couchdb"],
        "jwt_checker": ["jwt"],
        "jwt_tool": ["jwt"],
        "oauth_tester": ["oauth"],
        "graphql_deep_scanner": ["graphql"],
        "swagger_parser": ["swagger", "openapi"],
        "tplmap": ["python", "flask", "jinja", "django", "ruby", "rails", "php", "twig"],
        "deserialization_checker": ["java", "spring", "spring boot", "weblogic",
                                    "websphere", "jboss", ".net", "asp.net"],
    }

    def _get_tech_specific_tools(
        self,
        technologies: dict[str, list[str]],
    ) -> list[str]:
        """Return extra tools based on detected technology stack."""
        extras: list[str] = []
        seen: set[str] = set()

        tech_set: set[str] = set()
        for techs in technologies.values():
            tech_set.update(t.lower() for t in techs)

        for keyword, tools in self._TECH_TOOL_MAP.items():
            if any(keyword in t for t in tech_set):
                for tool in tools:
                    if tool not in seen:
                        seen.add(tool)
                        extras.append(tool)

        return extras

    def filter_irrelevant_tools(
        self,
        tools: list[str],
        technologies: dict[str, list[str]],
    ) -> list[str]:
        """Remove tools that require a specific tech stack not present."""
        tech_set: set[str] = set()
        for techs in technologies.values():
            tech_set.update(t.lower() for t in techs)

        filtered: list[str] = []
        for tool in tools:
            required_techs = self._TECH_ONLY_TOOLS.get(tool)
            if required_techs is None:
                # Not in tech-only list → always keep
                filtered.append(tool)
                continue
            # Check if ANY required tech keyword matches
            if any(kw in t for kw in required_techs for t in tech_set):
                filtered.append(tool)
            else:
                logger.debug(
                    f"Skipping {tool} — no matching tech "
                    f"(needs: {required_techs})"
                )
        return filtered

    async def _brain_prioritize(
        self,
        tools: list[str],
        stage: WorkflowStage,
        context: dict[str, Any],
    ) -> list[str]:
        """Brain modeliyle araç önceliklendir."""
        if not self.brain:
            return tools

        try:
            prompt = (
                f"You are a bug bounty expert. Given these available tools: {tools}\n"
                f"Current stage: {stage.value}\n"
                f"Context: {str(context)[:500]}\n\n"
                f"Return the tools sorted by priority (most important first) as a JSON list.\n"
                f'Example: ["nmap", "nikto", "sqlmap"]'
            )

            response = await asyncio.wait_for(
                self.brain.think(
                    prompt=prompt,
                    brain=BrainType.SECONDARY,
                    temperature=0.1,
                ),
                timeout=30.0,
            )

            import json
            try:
                prioritized = json.loads(response.text)
                if isinstance(prioritized, list):
                    # Brain'den gelen listedeki araçları filtrele (sadece mevcut olanlar)
                    valid = [t for t in prioritized if t in tools]
                    remaining = [t for t in tools if t not in valid]
                    return valid + remaining
            except json.JSONDecodeError:
                pass

        except asyncio.TimeoutError:
            logger.warning("Brain prioritization timed out (30s)")
        except Exception as e:
            logger.debug(f"Brain prioritization failed: {e}")

        return tools

    def _determine_execution_order(
        self,
        tools: list[str],
        stage: WorkflowStage,
    ) -> str:
        """Araç çalıştırma sırasını belirle."""
        # Bazı araçlar sıralı çalışmalı
        sequential_stages = {
            WorkflowStage.VULNERABILITY_SCAN,  # Bulguları sıralı analiz et
        }

        if stage in sequential_stages:
            return "sequential"

        # Bağımlılık zinciri olan araçlar
        chain_tools = {"sqlmap", "commix"}  # Nmap sonuçlarına bağlı
        if any(t in chain_tools for t in tools) and "nmap" in tools:
            return "chain"

        return "parallel"

    # ── Aşama Geçiş Kararı ───────────────────────────────────

    async def should_transition(
        self,
        current_stage: WorkflowStage,
        state: Any,
        current_results: dict[str, Any] | None = None,
    ) -> StageTransitionResult:
        """
        Bir sonraki aşamaya geçilmeli mi kararını ver.

        Args:
            current_stage: Mevcut aşama
            state: WorkflowState objesi
            current_results: Bu aşamanın sonuçları

        Returns:
            StageTransitionResult
        """
        results = current_results or {}

        # Temel kurallar
        findings_count = results.get("findings_count", 0)
        errors = results.get("errors", [])
        success = results.get("success", True)

        # Self-reflection check
        if self.reflection:
            try:
                critique = await self.reflection.critique_stage(
                    current_stage.value, str(results)
                )
                # Critique returns a Critique model, extract recommendations
                if critique.recommendations:
                    logger.info(
                        f"Self-reflection recommendations: "
                        f"{'; '.join(critique.recommendations)}"
                    )
                elif critique.reasoning:
                    pass
            except Exception as _exc:
                logger.debug(f"decision engine error: {_exc}")

        # Karar kuralları
        result = StageTransitionResult()

        # Ciddi hatalar → durdur
        if not success and len(errors) > 3:
            result.should_proceed = False
            result.reasoning = f"Too many errors ({len(errors)}) in stage {current_stage.value}"
            return result

        # Scope analysis başarısız → durdur
        if current_stage == WorkflowStage.SCOPE_ANALYSIS and not success:
            result.should_proceed = False
            result.reasoning = "Scope analysis failed — cannot proceed"
            return result

        # Passive recon sonuçsuz → active recon'u skip etme, yine de devam
        if current_stage == WorkflowStage.PASSIVE_RECON and findings_count == 0:
            result.should_proceed = True
            result.reasoning = "No passive results, but proceeding to active recon"

        # Vulnerability scan → FP elimination
        if current_stage == WorkflowStage.VULNERABILITY_SCAN:
            if findings_count == 0:
                result.skip_stages = [
                    WorkflowStage.FP_ELIMINATION.value,
                    WorkflowStage.REPORTING.value,
                    WorkflowStage.PLATFORM_SUBMIT.value,
                ]
                result.reasoning = "No findings to verify or report"

        # Reporting → Platform submit kararı
        if current_stage == WorkflowStage.REPORTING:
            verified = results.get("verified_count", 0)
            if verified == 0:
                result.skip_stages = [WorkflowStage.PLATFORM_SUBMIT.value]
                result.reasoning = "No verified findings to submit"

        # should_proceed defaults to True; earlier checks return early if False
        if not result.reasoning:
            result.reasoning = (
                f"Stage {current_stage.value} complete "
                f"(findings={findings_count}, errors={len(errors)})"
            )

        self._log_decision(
            decision_type="stage_transition",
            question=f"Proceed after {current_stage.value}?",
            answer=f"proceed={result.should_proceed}, skip={result.skip_stages}",
            confidence=0.85,
            reasoning=result.reasoning,
            stage=current_stage.value,
            brain_used="rule_based",
        )

        return result

    # ── Bulgu Değerlendirme ───────────────────────────────────

    async def evaluate_finding_priority(
        self,
        finding: Any,
        existing_findings: list[Any] | None = None,
    ) -> dict[str, Any]:
        """
        Bir bulgunun önemini ve önceliğini değerlendir.

        Returns:
            {"priority": "critical"|"high"|"medium"|"low"|"skip",
             "reasoning": str, "should_verify": bool}
        """
        vuln_type = finding.vulnerability_type.lower()
        severity = getattr(finding, "severity", "medium").lower()

        # Öncelik kuralları
        critical_vulns = {
            "sql_injection", "command_injection", "authentication_bypass",
            "remote_code_execution",
        }
        high_vulns = {
            "xss_stored", "ssrf", "ssti", "idor", "local_file_inclusion",
        }

        if vuln_type in critical_vulns or severity == "critical":
            priority = "critical"
            should_verify = True
        elif vuln_type in high_vulns or severity == "high":
            priority = "high"
            should_verify = True
        elif severity == "medium":
            priority = "medium"
            should_verify = True
        elif severity in ("low", "info"):
            priority = "low"
            should_verify = False
        else:
            priority = "medium"
            should_verify = True

        # Duplikat kontrolü
        if existing_findings:
            for ef in existing_findings:
                if (
                    ef.vulnerability_type == finding.vulnerability_type
                    and ef.url == finding.url
                    and ef.parameter == finding.parameter
                ):
                    priority = "skip"
                    should_verify = False
                    break

        return {
            "priority": priority,
            "reasoning": f"Vuln type={vuln_type}, severity={severity}",
            "should_verify": should_verify,
        }

    # ── Abort Kararı ──────────────────────────────────────────

    async def should_abort(
        self,
        state: Any,
        reason: str = "",
    ) -> tuple[bool, str]:
        """
        Taramayı durdurmalı mıyız?

        Returns:
            (should_abort, reason)
        """
        # Out-of-scope tespit edildi
        if reason == "out_of_scope":
            return True, "Target confirmed out of scope"

        # Çok fazla hata
        if hasattr(state, "stage_results"):
            error_count = sum(
                len(r.errors)
                for r in state.stage_results.values()
                if hasattr(r, "errors")
            )
            if error_count > 20:
                return True, f"Excessive errors: {error_count}"

        # Rate limit exhausted
        if reason == "rate_limited":
            return False, "Rate limited - will continue with backoff"

        return False, ""

    # ── Internal Helpers ──────────────────────────────────────

    def _log_decision(self, **kwargs: Any) -> None:
        """Kararı logla."""
        self._counter += 1
        decision = Decision(
            decision_id=f"d_{self._counter}",
            timestamp=time.time(),
            **kwargs,
        )
        self._decision_log.append(decision)

    def get_decision_log(self) -> list[Decision]:
        """Tüm kararları döndür."""
        return self._decision_log

    def get_stats(self) -> dict[str, Any]:
        """Karar engine istatistikleri."""
        return {
            "total_decisions": len(self._decision_log),
            "by_type": {},
            "avg_confidence": 0.0,
        }


__all__ = [
    "DecisionEngine",
    "Decision",
    "ToolSelectionResult",
    "StageTransitionResult",
    "STAGE_TOOL_MATRIX",
    "PROFILE_LIMITS",
]
