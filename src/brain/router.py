"""
WhiteHatHacker AI — Brain Router

Görev karmaşıklığına göre otomatik model seçimi yapar.
Basit/hızlı görevler → 20B (Secondary)
Karmaşık analiz → 32B (Primary)
Kritik kararlar → Her iki model (Ensemble)
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import Any

from loguru import logger

from src.utils.constants import BrainType


@dataclass
class RoutingRule:
    """Tek bir yönlendirme kuralı."""

    pattern: str                    # Regex pattern
    brain: BrainType                # Hedef model
    reason: str = ""                # Neden bu model
    priority: int = 0              # Öncelik (yüksek = daha önemli)

    def __post_init__(self) -> None:
        """Pre-compile regex pattern for performance."""
        self._compiled = re.compile(self.pattern, re.IGNORECASE)

    def matches(self, task_type: str) -> bool:
        """Görev türü ile eşleşiyor mu?"""
        return bool(self._compiled.search(task_type))


# ============================================================
# Varsayılan Yönlendirme Kuralları
# ============================================================

DEFAULT_ROUTING_RULES: list[RoutingRule] = [
    # ── Secondary Brain (20B) — Hızlı Görevler ──
    RoutingRule(
        pattern=r"recon|discover|enumerate_subdomain|dns_lookup",
        brain=BrainType.SECONDARY,
        reason="Hızlı keşif kararları, düşük latency",
        priority=10,
    ),
    RoutingRule(
        pattern=r"tool_select|tool_config|scan_config|parameter",
        brain=BrainType.SECONDARY,
        reason="Araç seçimi ve konfigürasyonu",
        priority=10,
    ),
    RoutingRule(
        pattern=r"triage|quick_assess|categorize|prioritize_targets",
        brain=BrainType.SECONDARY,
        reason="Hızlı triage ve önceliklendirme",
        priority=10,
    ),
    RoutingRule(
        pattern=r"scope_check|scope_analysis|validate_scope",
        brain=BrainType.SECONDARY,
        reason="Scope analizi — hızlı karar",
        priority=10,
    ),
    RoutingRule(
        pattern=r"parse_output|aggregate_results|merge_findings",
        brain=BrainType.SECONDARY,
        reason="Çıktı birleştirme ve parse",
        priority=10,
    ),

    # ── Primary Brain (32B) — Derin Analiz Görevleri ──
    RoutingRule(
        pattern=r"analyze_vuln|deep_analysis|vulnerability_analysis",
        brain=BrainType.PRIMARY,
        reason="Derin zafiyet analizi",
        priority=20,
    ),
    RoutingRule(
        pattern=r"exploit_strategy|attack_plan|exploitation",
        brain=BrainType.PRIMARY,
        reason="Exploit stratejisi planlama",
        priority=20,
    ),
    RoutingRule(
        pattern=r"fp_check|fp_eliminate|false_positive|verify_finding",
        brain=BrainType.PRIMARY,
        reason="False positive eleme — yüksek doğruluk gerekli",
        priority=25,
    ),
    RoutingRule(
        pattern=r"report_write|generate_report|write_report",
        brain=BrainType.PRIMARY,
        reason="Profesyonel rapor yazma",
        priority=20,
    ),
    RoutingRule(
        pattern=r"business_logic|idor_analysis|auth_bypass_analysis",
        brain=BrainType.PRIMARY,
        reason="İş mantığı zafiyetleri — derin reasoning",
        priority=25,
    ),
    RoutingRule(
        pattern=r"chain_of_thought|complex_reason|risk_assess",
        brain=BrainType.PRIMARY,
        reason="Karmaşık akıl yürütme",
        priority=20,
    ),
    RoutingRule(
        pattern=r"threat_model|attack_surface_analysis|impact_assess",
        brain=BrainType.PRIMARY,
        reason="Tehdit modelleme ve etki analizi",
        priority=20,
    ),
    RoutingRule(
        pattern=r"severity_calculate|cvss_score|impact_rating",
        brain=BrainType.PRIMARY,
        reason="CVSS hesaplama ve ciddiyet değerlendirme",
        priority=20,
    ),

    # ── Ensemble (Her iki model) — Kritik Kararlar ──
    RoutingRule(
        pattern=r"critical_decision|final_verify|submit_decision",
        brain=BrainType.BOTH,
        reason="Kritik karar — her iki modelin onayı gerekli",
        priority=30,
    ),
    RoutingRule(
        pattern=r"high_confidence_check|ensemble_verify",
        brain=BrainType.BOTH,
        reason="Yüksek güven doğrulaması",
        priority=30,
    ),

    # ── Agentic Pipeline Routing Rules ──
    RoutingRule(
        pattern=r"agent_decide|agent_think|next_action",
        brain=BrainType.SECONDARY,
        reason="Agentic loop: hızlı karar döngüsü (ReAct THINK aşaması)",
        priority=15,
    ),
    RoutingRule(
        pattern=r"agent_evaluate|evaluate_result|assess_outcome",
        brain=BrainType.PRIMARY,
        reason="Agentic loop: sonuç değerlendirme — derin analiz gerekli",
        priority=20,
    ),
    RoutingRule(
        pattern=r"stage_select|pick_stage|workflow_route",
        brain=BrainType.SECONDARY,
        reason="Agentic loop: aşama seçimi — hızlı karar",
        priority=10,
    ),
    RoutingRule(
        pattern=r"chain_attack|attack_chain|pivot_plan",
        brain=BrainType.PRIMARY,
        reason="Agentic loop: saldırı zinciri planlama — karmaşık reasoning",
        priority=25,
    ),
]


class BrainRouter:
    """
    Görev-Model eşleme motoru.

    Gelen görev türünü analiz eder ve en uygun brain modelini seçer.
    Kural bazlı yönlendirme + varsayılan fallback.

    Kullanım:
        router = BrainRouter()
        brain = router.route("fp_check")  # → BrainType.PRIMARY
        brain = router.route("triage")     # → BrainType.SECONDARY
    """

    def __init__(
        self,
        rules: list[RoutingRule] | None = None,
        default_brain: BrainType = BrainType.SECONDARY,
        fallback_brain: BrainType = BrainType.SECONDARY,
    ) -> None:
        self.rules = sorted(
            rules or DEFAULT_ROUTING_RULES,
            key=lambda r: r.priority,
            reverse=True,  # Yüksek öncelik önce
        )
        self.default_brain = default_brain
        self.fallback_brain = fallback_brain

        self._routing_history: deque[dict[str, Any]] = deque(maxlen=1000)

        logger.info(
            f"BrainRouter initialized | rules={len(self.rules)} | "
            f"default={default_brain} | fallback={fallback_brain}"
        )

    def route(self, task_type: str) -> BrainType:
        """
        Görev türüne göre brain model seç.

        Args:
            task_type: Görev türü tanımlayıcı string

        Returns:
            BrainType — kullanılacak model
        """
        for rule in self.rules:
            if rule.matches(task_type):
                logger.debug(
                    f"Brain routed | task={task_type} → {rule.brain} | "
                    f"reason='{rule.reason}'"
                )
                self._routing_history.append({
                    "task": task_type,
                    "brain": rule.brain,
                    "rule_pattern": rule.pattern,
                    "reason": rule.reason,
                })
                return rule.brain

        # Hiçbir kural eşleşmedi → default
        logger.debug(f"Brain routed (default) | task={task_type} → {self.default_brain}")
        self._routing_history.append({
            "task": task_type,
            "brain": self.default_brain,
            "rule_pattern": "default",
            "reason": "No matching rule",
        })
        return self.default_brain

    def route_with_override(
        self,
        task_type: str,
        override: BrainType | None = None,
    ) -> BrainType:
        """
        Manuel override ile route.
        Override verilmişse kural bazlı seçimi atlar.
        """
        if override is not None:
            logger.debug(f"Brain override | task={task_type} → {override} (manual)")
            return override
        return self.route(task_type)

    def add_rule(self, rule: RoutingRule) -> None:
        """Yeni routing kuralı ekle."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        logger.info(f"Routing rule added | pattern={rule.pattern} → {rule.brain}")

    def get_routing_history(self) -> list[dict[str, Any]]:
        """Yönlendirme geçmişini döndür."""
        return list(self._routing_history)

    def get_stats(self) -> dict[str, Any]:
        """Router istatistikleri."""
        brain_counts: dict[str, int] = {}
        for entry in self._routing_history:
            brain = str(entry["brain"])
            brain_counts[brain] = brain_counts.get(brain, 0) + 1

        return {
            "total_routes": len(self._routing_history),
            "routes_by_brain": brain_counts,
            "rules_count": len(self.rules),
        }


__all__ = ["BrainRouter", "RoutingRule", "DEFAULT_ROUTING_RULES"]
