"""
WhiteHatHacker AI — Self-Reflection & Self-Critique Engine

Bot'un kendi performansı üzerine düşünmesini, kritik yapmasını ve
bir sonraki hamlesini bu kritiklere göre seçmesini sağlar.

Meta-Cognitive Loop:
  Plan → Execute → Evaluate → Critique → Adapt → Plan (tekrar)

Bu modül:
  1. performans_tracker: Her aşamada metrikler toplar
  2. critique_engine: Sonuçları eleştirel olarak değerlendirir
  3. strategy_adapter: Kritiklere göre strateji değiştirir
  4. decision_journal: Tüm kararları ve sonuçlarını kaydeder
  5. reflection_prompts: Brain'e self-critique yaptıran prompt'lar

NOT: Brain Engine üzerinden LLM'ye "kendi çıktını değerlendir" sorularını sorar.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from src.utils.constants import BrainType


# ════════════════════════════════════════════════════════════
# Enums & Data Models
# ════════════════════════════════════════════════════════════

class ReflectionType(StrEnum):
    """Ne tür bir reflection yapılıyor?"""
    POST_STAGE = "post_stage"                # Aşama sonrası değerlendirme
    POST_TOOL = "post_tool"                  # Araç çalıştırma sonrası
    FINDING_QUALITY = "finding_quality"      # Bulgu kalitesi değerlendirme
    STRATEGY_REVIEW = "strategy_review"      # Strateji gözden geçirme
    COVERAGE_CHECK = "coverage_check"        # Kapsam kontrolü
    FP_RETROSPECTIVE = "fp_retrospective"    # FP elemeleri geri bakış
    MID_SCAN_PIVOT = "mid_scan_pivot"        # Tarama ortasında yön değiştirme
    FINAL_REVIEW = "final_review"            # Son genel değerlendirme


class CritiqueLevel(StrEnum):
    """Kritik şiddeti."""
    EXCELLENT = "excellent"    # Mükemmel sonuç
    GOOD = "good"             # İyi ama iyileştirilebilir
    ADEQUATE = "adequate"     # Yeterli ama eksiklikler var
    POOR = "poor"             # Zayıf — strateji değişikliği gerekli
    FAILED = "failed"         # Başarısız — tamamen farklı yaklaşım


class AdaptAction(StrEnum):
    """Eleştiri sonucunda alınacak aksiyon."""
    CONTINUE = "continue"           # Aynı stratejiyle devam et
    ADJUST_PARAMS = "adjust_params" # Parametreleri ayarla
    ADD_TOOLS = "add_tools"         # Ek araçlar kullan
    SKIP_STAGE = "skip_stage"       # Bu aşamayı atla
    RETRY = "retry"                 # Tekrar dene
    PIVOT = "pivot"                 # Tamamen farklı bir strateji
    DEEPEN = "deepen"               # Daha derinlemesine analiz
    BROADEN = "broaden"             # Kapsamı genişlet
    ESCALATE = "escalate"           # İnsan müdahalesi iste


@dataclass
class PerformanceMetric:
    """Tek bir performans ölçümü."""
    metric_name: str
    value: float
    unit: str = ""
    context: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class StagePerformance:
    """Bir iş akışı aşamasının performansı."""
    stage: str
    started_at: float = 0.0
    completed_at: float = 0.0
    tools_used: list[str] = field(default_factory=list)
    findings_count: int = 0
    fp_count: int = 0
    true_positive_count: int = 0
    errors: list[str] = field(default_factory=list)
    metrics: list[PerformanceMetric] = field(default_factory=list)
    coverage_score: float = 0.0    # 0-100 kapsam yüzdesi

    @property
    def duration(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return 0.0

    @property
    def fp_rate(self) -> float:
        total = self.findings_count
        if total == 0:
            return 0.0
        return (self.fp_count / total) * 100


class Critique(BaseModel):
    """Bir eleştiri kararı."""
    reflection_type: ReflectionType
    stage: str = ""
    level: CritiqueLevel = CritiqueLevel.ADEQUATE
    score: float = 50.0          # 0-100
    findings: list[str] = Field(default_factory=list)     # Eleştiri noktaları
    strengths: list[str] = Field(default_factory=list)    # Güçlü yanlar
    weaknesses: list[str] = Field(default_factory=list)   # Zayıf yanlar
    recommendations: list[str] = Field(default_factory=list)  # Öneriler
    adapt_action: AdaptAction = AdaptAction.CONTINUE
    adapt_details: dict[str, Any] = Field(default_factory=dict)  # Uyarlama detayları
    reasoning: str = ""          # Düşünce zinciri
    timestamp: float = 0.0


class DecisionEntry(BaseModel):
    """Karar günlüğü girdisi. Her önemli karar burada kayıt altına alınır."""
    decision_id: str
    stage: str
    question: str                 # Ne karar verildi?
    options_considered: list[str] = Field(default_factory=list)  # Değerlendirilen seçenekler
    chosen_option: str = ""       # Seçilen seçenek
    reasoning: str = ""           # Neden bu seçenek?
    outcome: str = ""             # Sonuç (post-hoc doldurulur)
    outcome_score: float = 0.0   # Sonuç skoru (0-100)
    was_correct: bool | None = None  # Doğru karar mıydı?
    timestamp: float = 0.0


# ════════════════════════════════════════════════════════════
# Self-Reflection Prompt Library
# ════════════════════════════════════════════════════════════

REFLECTION_PROMPTS = {
    ReflectionType.POST_STAGE: """You are a senior bug bounty hunter performing self-critique on your own work.

## Completed Stage: {stage}
## Performance Data:
- Duration: {duration:.1f}s
- Tools used: {tools_used}
- Raw findings: {findings_count}
- False positives identified: {fp_count}
- Errors encountered: {errors}

## Results Summary:
{results_summary}

## Your Task:
Critically evaluate your performance in this stage. Be BRUTALLY honest.

Respond in JSON:
{{
  "level": "excellent|good|adequate|poor|failed",
  "score": 0-100,
  "strengths": ["what went well"],
  "weaknesses": ["what went wrong or could be better"],
  "missed_opportunities": ["what you should have done but didn't"],
  "recommendations": ["specific actions for improvement"],
  "adapt_action": "continue|adjust_params|add_tools|retry|pivot|deepen|broaden|escalate",
  "adapt_details": {{}},
  "reasoning": "detailed chain of thought explaining your assessment"
}}""",

    ReflectionType.POST_TOOL: """You are reviewing the output of a security tool you just ran.

## Tool: {tool_name}
## Target: {target}
## Exit Code: {exit_code}
## Execution Time: {exec_time:.1f}s
## Findings Count: {findings_count}

## Raw Output (truncated):
{output_snippet}

## Your Task:
Was this tool run effective? Did you use the right parameters?
Should you run it again with different options or use a complementary tool?

Respond in JSON:
{{
  "effectiveness": 0-100,
  "output_quality": "high|medium|low|empty",
  "findings_relevance": "high|medium|low|none",
  "parameter_quality": "optimal|acceptable|suboptimal|wrong",
  "should_rerun": false,
  "rerun_reason": "",
  "complementary_tools": ["tool names that would complement this"],
  "missed_checks": ["things this tool didn't cover"],
  "reasoning": "your analysis"
}}""",

    ReflectionType.FINDING_QUALITY: """You are a quality assurance specialist reviewing security findings.

## Finding:
- Title: {finding_title}
- Type: {finding_type}
- Severity: {finding_severity}
- Confidence: {finding_confidence}%
- Tool: {tool_name}
- Evidence: {evidence}

## Your Task:
Assess the quality of this finding. Is it likely real or a false positive?
What additional verification would increase confidence?

Respond in JSON:
{{
  "quality_score": 0-100,
  "likely_real": true/false,
  "false_positive_indicators": ["list of FP red flags"],
  "true_positive_indicators": ["list of TP green flags"],
  "verification_needed": ["specific steps to verify"],
  "additional_tools": ["tools that could confirm or deny"],
  "confidence_after_review": 0-100,
  "reasoning": "detailed analysis"
}}""",

    ReflectionType.STRATEGY_REVIEW: """You are an expert penetration tester reviewing your overall attack strategy.

## Target: {target}
## Current Strategy: {current_strategy}
## Stages Completed: {stages_completed}
## Total Findings So Far: {total_findings}
## High-Confidence Findings: {high_confidence_findings}
## Time Elapsed: {time_elapsed}

## Attack Surface Summary:
{attack_surface_summary}

## Your Task:
Is the current strategy the best approach? What would a top-tier bug bounty hunter do differently?
Think about: coverage, efficiency, creativity, missed attack vectors.

Respond in JSON:
{{
  "strategy_effectiveness": 0-100,
  "coverage_assessment": "comprehensive|adequate|partial|minimal",
  "efficiency_rating": "high|medium|low",
  "missed_attack_vectors": ["vectors not yet explored"],
  "priority_adjustments": ["reorder priorities"],
  "new_hypotheses": ["new attack hypotheses to test"],
  "creative_approaches": ["unconventional ideas to try"],
  "should_pivot": false,
  "pivot_strategy": "",
  "reasoning": "your strategic analysis"
}}""",

    ReflectionType.COVERAGE_CHECK: """Evaluate the testing coverage for the target.

## Target: {target}
## Technologies Detected: {technologies}
## Endpoints Discovered: {endpoint_count}
## Tests Performed: {tests_performed}
## Vulnerability Categories Tested: {vuln_categories_tested}
## Vulnerability Categories NOT Tested: {vuln_categories_missing}

## Your Task:
Which areas haven't been tested yet? What's the coverage gap?

Respond in JSON:
{{
  "coverage_score": 0-100,
  "tested_categories": ["list"],
  "untested_categories": ["list"],
  "critical_gaps": ["gaps that MUST be addressed"],
  "recommended_next_tests": ["specific test actions"],
  "estimated_remaining_time": "hours:minutes",
  "reasoning": "analysis"
}}""",

    ReflectionType.FINAL_REVIEW: """You are performing a FINAL review before completing the assessment.

## Target: {target}
## Total Duration: {total_duration}
## Stages Completed: {stages_completed}
## Total Findings: {total_findings}
## Verified Vulnerabilities: {verified_vulns}
## Severity Breakdown: {severity_breakdown}

## Top Findings:
{top_findings_summary}

## Decision History (Last 10):
{decision_history}

## Your Task:
Give a final, comprehensive self-assessment. Were you thorough enough?
What would you do differently if you started over?

Respond in JSON:
{{
  "overall_score": 0-100,
  "thoroughness": "excellent|good|adequate|poor",
  "key_achievements": ["list"],
  "regrets": ["what you wish you'd done differently"],
  "lessons_learned": ["insights for future scans"],
  "confidence_in_results": 0-100,
  "missing_coverage": ["areas not covered"],
  "final_recommendation": "text summary",
  "reasoning": "comprehensive self-reflection"
}}""",

    ReflectionType.MID_SCAN_PIVOT: """You are mid-scan and considering whether to change your approach.

## Current Stage: {current_stage}
## Findings So Far: {findings_so_far}
## Time Spent: {time_spent}
## Recent Tool Results:
{recent_results}

## Anomalies Detected:
{anomalies}

## Your Task:
Based on what you've found (or haven't found), should you pivot?
Consider: diminishing returns, new attack vectors revealed, time budget.

Respond in JSON:
{{
  "should_pivot": false,
  "pivot_reasoning": "",
  "new_priority_targets": ["list of endpoints/params to focus on"],
  "drop_targets": ["list of low-value targets to deprioritize"],
  "new_tools_to_try": ["list"],
  "estimated_value_of_continuation": 0-100,
  "estimated_value_of_pivot": 0-100,
  "recommendation": "continue|pivot|adjust",
  "reasoning": "your analysis"
}}""",
}


# ════════════════════════════════════════════════════════════
# Self-Reflection Engine
# ════════════════════════════════════════════════════════════

class SelfReflectionEngine:
    """
    Bot'un kendi performansı üzerine düşünmesini ve kritik yapmasını sağlar.

    Meta-Cognitive Loop:
      1. PLAN:     Hedef ve strateji belirle
      2. EXECUTE:  Araçları çalıştır, veri topla
      3. EVALUATE: Sonuçları ölç (metrikler)
      4. CRITIQUE: AI ile sonuçları eleştirel değerlendir
      5. ADAPT:    Kritiklere göre stratejiyi uyarla
      6. → PLAN'a geri dön (yeni bilgilerle)

    Kullanım:
        engine = SelfReflectionEngine(brain_engine)

        # Aşama tamamlandığında
        engine.record_stage_start("passive_recon")
        # ... araçlar çalışır ...
        engine.record_stage_end("passive_recon", findings=[...])

        # Self-critique yap
        critique = await engine.critique_stage("passive_recon")

        # Stratejiye göre sonraki aşamayı belirle
        next_action = engine.get_next_action()
    """

    def __init__(self, brain_engine: Any = None) -> None:
        """
        Args:
            brain_engine: BrainEngine instance (self-critique prompt'ları için)
        """
        self.brain = brain_engine

        # Performans takibi
        self.stage_performances: dict[str, StagePerformance] = {}
        self.global_metrics: list[PerformanceMetric] = []

        # Karar günlüğü
        self.decision_journal: list[DecisionEntry] = []
        self._decision_counter = 0

        # Eleştiri geçmişi
        self.critique_history: list[Critique] = []

        # Oturum bilgisi
        self.session_start = time.time()
        self.total_findings: list[dict[str, Any]] = []
        self.verified_findings: list[dict[str, Any]] = []
        self.false_positives: list[dict[str, Any]] = []

        # Adaptasyon durumu
        self.current_strategy: str = "balanced"
        self.strategy_adjustments: list[dict[str, Any]] = []
        self.active_hypotheses: list[str] = []

        logger.info("SelfReflectionEngine initialized")

    # ─── Stage Performance Tracking ──────────────────────────

    def record_stage_start(self, stage: str) -> None:
        """Bir aşamanın başlangıcını kaydet."""
        self.stage_performances[stage] = StagePerformance(
            stage=stage,
            started_at=time.time(),
        )
        logger.info(f"[Reflection] Stage started: {stage}")

    def record_stage_end(
        self,
        stage: str,
        tools_used: list[str] | None = None,
        findings: list[dict[str, Any]] | None = None,
        errors: list[str] | None = None,
    ) -> None:
        """Bir aşamanın bitişini kaydet."""
        perf = self.stage_performances.get(stage)
        if perf is None:
            perf = StagePerformance(stage=stage, started_at=time.time())
            self.stage_performances[stage] = perf

        perf.completed_at = time.time()
        perf.tools_used = tools_used or []
        perf.findings_count = len(findings or [])
        perf.errors = errors or []

        if findings:
            self.total_findings.extend(findings)

        logger.info(
            f"[Reflection] Stage completed: {stage} | "
            f"duration={perf.duration:.1f}s | "
            f"findings={perf.findings_count} | "
            f"tools={len(perf.tools_used)} | "
            f"errors={len(perf.errors)}"
        )

    def record_tool_result(
        self,
        stage: str,
        tool_name: str,
        success: bool,
        findings_count: int,
        execution_time: float,
    ) -> None:
        """Araç çalıştırma sonucunu kaydet."""
        self.global_metrics.append(PerformanceMetric(
            metric_name=f"tool_{tool_name}",
            value=findings_count,
            unit="findings",
            context=f"stage={stage}, success={success}, time={execution_time:.1f}s",
        ))

    def record_finding_verification(
        self,
        finding: dict[str, Any],
        is_true_positive: bool,
    ) -> None:
        """Bulgu doğrulama sonucunu kaydet."""
        if is_true_positive:
            self.verified_findings.append(finding)
        else:
            self.false_positives.append(finding)

        # İlgili stage performansını güncelle
        stage = finding.get("stage", "")
        perf = self.stage_performances.get(stage)
        if perf:
            if is_true_positive:
                perf.true_positive_count += 1
            else:
                perf.fp_count += 1

    # ─── Decision Journal ────────────────────────────────────

    def record_decision(
        self,
        stage: str,
        question: str,
        options: list[str],
        chosen: str,
        reasoning: str,
    ) -> str:
        """Bir kararı günlüğe kaydet. decision_id döndürür."""
        self._decision_counter += 1
        entry = DecisionEntry(
            decision_id=f"D{self._decision_counter:04d}",
            stage=stage,
            question=question,
            options_considered=options,
            chosen_option=chosen,
            reasoning=reasoning,
            timestamp=time.time(),
        )
        self.decision_journal.append(entry)
        logger.debug(f"[Decision] {entry.decision_id}: {question} → {chosen}")
        return entry.decision_id

    def update_decision_outcome(
        self,
        decision_id: str,
        outcome: str,
        score: float,
        was_correct: bool | None = None,
    ) -> None:
        """Bir kararın sonucunu güncelle (geri bildirim)."""
        for entry in self.decision_journal:
            if entry.decision_id == decision_id:
                entry.outcome = outcome
                entry.outcome_score = score
                entry.was_correct = was_correct
                logger.debug(
                    f"[Decision Update] {decision_id}: "
                    f"outcome={outcome[:50]} | score={score} | correct={was_correct}"
                )
                return
        logger.warning(f"Decision not found: {decision_id}")

    # ─── Core Self-Critique (Brain-powered) ──────────────────

    async def critique_stage(
        self,
        stage: str,
        results_summary: str = "",
    ) -> Critique:
        """
        Tamamlanan bir aşamayı eleştirel olarak değerlendir.
        Brain Engine ile deep self-critique yapar.
        """
        perf = self.stage_performances.get(stage)
        if perf is None:
            logger.warning(f"No performance data for stage: {stage}")
            return Critique(
                reflection_type=ReflectionType.POST_STAGE,
                stage=stage,
                level=CritiqueLevel.ADEQUATE,
                reasoning="No performance data available",
            )

        # Skip brain critique if stage had 0 findings, 0 tools, and 0 errors —
        # brain always returns POOR/add_tools for empty stages, wasting 100-170s.
        if perf.findings_count == 0 and not perf.tools_used and not perf.errors:
            logger.info(
                f"[Reflection] Skipping brain critique for {stage} "
                f"(0 findings, 0 tools, 0 errors — would be uninformative)"
            )
            return Critique(
                reflection_type=ReflectionType.POST_STAGE,
                stage=stage,
                level=CritiqueLevel.ADEQUATE,
                reasoning="Stage had no findings/tools/errors — critique skipped to save time",
            )

        # Prompt oluştur
        prompt = REFLECTION_PROMPTS[ReflectionType.POST_STAGE].format(
            stage=stage,
            duration=perf.duration,
            tools_used=", ".join(perf.tools_used) or "none",
            findings_count=perf.findings_count,
            fp_count=perf.fp_count,
            errors=", ".join(perf.errors[:5]) or "none",
            results_summary=results_summary or "No summary provided",
        )

        critique = await self._run_brain_critique(prompt, ReflectionType.POST_STAGE, stage)
        self.critique_history.append(critique)

        # Auto-adapt
        if critique.level in (CritiqueLevel.POOR, CritiqueLevel.FAILED):
            logger.warning(
                f"[Reflection] POOR/FAILED critique for stage {stage} → "
                f"action={critique.adapt_action}"
            )
            self._apply_adaptation(critique)

        return critique

    async def critique_tool_result(
        self,
        tool_name: str,
        target: str,
        exit_code: int,
        exec_time: float,
        findings_count: int,
        output_snippet: str,
    ) -> Critique:
        """Tekil bir araç sonucunu eleştir."""
        prompt = REFLECTION_PROMPTS[ReflectionType.POST_TOOL].format(
            tool_name=tool_name,
            target=target,
            exit_code=exit_code,
            exec_time=exec_time,
            findings_count=findings_count,
            output_snippet=output_snippet[:2000],
        )

        critique = await self._run_brain_critique(prompt, ReflectionType.POST_TOOL, tool_name)
        self.critique_history.append(critique)
        return critique

    async def critique_finding(
        self,
        finding_title: str,
        finding_type: str,
        finding_severity: str,
        finding_confidence: float,
        tool_name: str,
        evidence: str,
    ) -> Critique:
        """Tekil bir bulguyu eleştir."""
        prompt = REFLECTION_PROMPTS[ReflectionType.FINDING_QUALITY].format(
            finding_title=finding_title,
            finding_type=finding_type,
            finding_severity=finding_severity,
            finding_confidence=finding_confidence,
            tool_name=tool_name,
            evidence=evidence[:1500],
        )

        critique = await self._run_brain_critique(prompt, ReflectionType.FINDING_QUALITY, finding_title)
        self.critique_history.append(critique)
        return critique

    async def review_strategy(
        self,
        target: str,
        attack_surface_summary: str = "",
    ) -> Critique:
        """Global strateji gözden geçirmesi."""
        completed = [s for s, p in self.stage_performances.items() if p.completed_at > 0]
        total_elapsed = time.time() - self.session_start

        prompt = REFLECTION_PROMPTS[ReflectionType.STRATEGY_REVIEW].format(
            target=target,
            current_strategy=self.current_strategy,
            stages_completed=", ".join(completed) or "none",
            total_findings=len(self.total_findings),
            high_confidence_findings=len(self.verified_findings),
            time_elapsed=f"{total_elapsed:.0f}s ({total_elapsed/60:.1f}m)",
            attack_surface_summary=attack_surface_summary or "Not yet mapped",
        )

        critique = await self._run_brain_critique(prompt, ReflectionType.STRATEGY_REVIEW)
        self.critique_history.append(critique)

        if critique.adapt_action == AdaptAction.PIVOT:
            logger.warning(f"[Reflection] STRATEGY PIVOT recommended: {critique.reasoning[:200]}")
            self.strategy_adjustments.append({
                "type": "pivot",
                "from": self.current_strategy,
                "to": critique.adapt_details.get("new_strategy", "adaptive"),
                "reason": critique.reasoning,
                "timestamp": time.time(),
            })

        return critique

    async def mid_scan_reflection(
        self,
        current_stage: str,
        recent_results: str,
        anomalies: str = "",
    ) -> Critique:
        """Tarama ortasında anlık değerlendirme — pivot gerekli mi?"""
        prompt = REFLECTION_PROMPTS[ReflectionType.MID_SCAN_PIVOT].format(
            current_stage=current_stage,
            findings_so_far=len(self.total_findings),
            time_spent=f"{time.time() - self.session_start:.0f}s",
            recent_results=recent_results[:2000],
            anomalies=anomalies or "none detected",
        )

        critique = await self._run_brain_critique(prompt, ReflectionType.MID_SCAN_PIVOT, current_stage)
        self.critique_history.append(critique)
        return critique

    async def final_review(self, target: str) -> Critique:
        """Son genel değerlendirme — tarama bittiğinde."""
        completed = [s for s, p in self.stage_performances.items() if p.completed_at > 0]
        total_elapsed = time.time() - self.session_start

        # Severity breakdown
        severity_counts: dict[str, int] = {}
        for f in self.verified_findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Top findings summary
        top_summaries = []
        for f in self.verified_findings[:10]:
            top_summaries.append(
                f"  - [{f.get('severity', 'info').upper()}] {f.get('title', 'N/A')} "
                f"(confidence={f.get('confidence', 0)}%)"
            )

        # Decision history
        recent_decisions = []
        for d in self.decision_journal[-10:]:
            recent_decisions.append(
                f"  - {d.decision_id}: {d.question[:80]} → {d.chosen_option} "
                f"(correct={d.was_correct})"
            )

        prompt = REFLECTION_PROMPTS[ReflectionType.FINAL_REVIEW].format(
            target=target,
            total_duration=f"{total_elapsed:.0f}s ({total_elapsed/60:.1f}m)",
            stages_completed=", ".join(completed),
            total_findings=len(self.total_findings),
            verified_vulns=len(self.verified_findings),
            severity_breakdown=json.dumps(severity_counts),
            top_findings_summary="\n".join(top_summaries) or "None",
            decision_history="\n".join(recent_decisions) or "None",
        )

        critique = await self._run_brain_critique(prompt, ReflectionType.FINAL_REVIEW)
        self.critique_history.append(critique)
        return critique

    # ─── Adaptation Logic ────────────────────────────────────

    def get_next_action(self) -> dict[str, Any]:
        """
        Son eleştirilere bakarak en uygun sonraki aksiyonu belirle.

        Returns:
            {
                "action": AdaptAction,
                "reason": str,
                "parameters": dict,
                "priority_targets": list,
            }
        """
        if not self.critique_history:
            return {
                "action": AdaptAction.CONTINUE,
                "reason": "No critiques yet — continue with plan",
                "parameters": {},
                "priority_targets": [],
            }

        last = self.critique_history[-1]

        # Eğer son 3 eleştiride POOR/FAILED varsa → PIVOT
        recent = self.critique_history[-3:]
        poor_count = sum(
            1 for c in recent
            if c.level in (CritiqueLevel.POOR, CritiqueLevel.FAILED)
        )
        if poor_count >= 2:
            return {
                "action": AdaptAction.PIVOT,
                "reason": f"{poor_count}/3 recent critiques were POOR/FAILED — strategy pivot needed",
                "parameters": last.adapt_details,
                "priority_targets": last.recommendations,
            }

        return {
            "action": last.adapt_action,
            "reason": last.reasoning[:300],
            "parameters": last.adapt_details,
            "priority_targets": last.recommendations[:5],
        }

    def _apply_adaptation(self, critique: Critique) -> None:
        """Eleştiri sonucuna göre internal durumu güncelle."""
        action = critique.adapt_action
        details = critique.adapt_details

        self.strategy_adjustments.append({
            "action": action,
            "from_stage": critique.stage,
            "details": details,
            "reason": critique.reasoning[:200],
            "timestamp": time.time(),
        })

        match action:
            case AdaptAction.ADJUST_PARAMS:
                logger.info(f"[Adapt] Adjusting parameters: {details}")
            case AdaptAction.ADD_TOOLS:
                new_tools = details.get("tools", [])
                logger.info(f"[Adapt] Adding complementary tools: {new_tools}")
            case AdaptAction.DEEPEN:
                logger.info("[Adapt] Deepening analysis on current targets")
            case AdaptAction.BROADEN:
                logger.info("[Adapt] Broadening scope to explore new attack vectors")
            case AdaptAction.PIVOT:
                new_strategy = details.get("new_strategy", "adaptive")
                logger.warning(f"[Adapt] PIVOTING strategy: {self.current_strategy} → {new_strategy}")
                self.current_strategy = new_strategy
            case AdaptAction.RETRY:
                logger.info(f"[Adapt] Will retry stage: {critique.stage}")
            case AdaptAction.ESCALATE:
                logger.warning("[Adapt] ESCALATING — human intervention requested")
            case _:
                logger.debug("[Adapt] Continuing with current strategy")

    # ─── Brain Communication ─────────────────────────────────

    async def _run_brain_critique(
        self,
        prompt: str,
        reflection_type: ReflectionType,
        context_label: str = "",
    ) -> Critique:
        """Brain Engine ile eleştiri yap. Brain yoksa rule-based fallback kullan."""

        if self.brain is not None:
            try:
                response = await asyncio.wait_for(
                    self.brain.think(
                        prompt=prompt,
                        brain=BrainType.PRIMARY,  # Self-critique daima 32B ile
                        system_prompt=(
                            "You are a self-reflective AI performing meta-cognitive evaluation. "
                            "Be brutally honest, analytical, and actionable. "
                            "Always respond in valid JSON."
                        ),
                        json_mode=True,
                        temperature=0.15,
                    ),
                    timeout=1200.0,
                )

                return self._parse_critique_response(
                    response.text, reflection_type, context_label
                )

            except asyncio.TimeoutError:
                logger.warning(f"Brain critique timed out (1200s) for {context_label}")
            except Exception as e:
                logger.warning(f"Brain critique failed, using rule-based fallback: {e}")

        # Fallback: rule-based assessment
        return self._rule_based_critique(reflection_type, context_label)

    def _parse_critique_response(
        self,
        text: str,
        reflection_type: ReflectionType,
        context_label: str,
    ) -> Critique:
        """Brain JSON yanıtını Critique'e parse et."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to parse critique JSON, using defaults")
            return Critique(
                reflection_type=reflection_type,
                stage=context_label,
                level=CritiqueLevel.ADEQUATE,
                reasoning=text[:500],
                timestamp=time.time(),
            )

        # Ensure parsed data is a dict (LLM may return a list)
        if not isinstance(data, dict):
            logger.warning(f"Critique JSON is not a dict (got {type(data).__name__}), using defaults")
            return Critique(
                reflection_type=reflection_type,
                stage=context_label,
                level=CritiqueLevel.ADEQUATE,
                reasoning=str(data)[:500],
                timestamp=time.time(),
            )

        # JSON → Critique mapping
        level_map = {
            "excellent": CritiqueLevel.EXCELLENT,
            "good": CritiqueLevel.GOOD,
            "adequate": CritiqueLevel.ADEQUATE,
            "poor": CritiqueLevel.POOR,
            "failed": CritiqueLevel.FAILED,
        }
        action_map = {
            "continue": AdaptAction.CONTINUE,
            "adjust_params": AdaptAction.ADJUST_PARAMS,
            "add_tools": AdaptAction.ADD_TOOLS,
            "skip_stage": AdaptAction.SKIP_STAGE,
            "retry": AdaptAction.RETRY,
            "pivot": AdaptAction.PIVOT,
            "deepen": AdaptAction.DEEPEN,
            "broaden": AdaptAction.BROADEN,
            "escalate": AdaptAction.ESCALATE,
        }

        def _sf(v: Any, d: float = 50.0) -> float:
            if v is None:
                return d
            try:
                return float(v)
            except (ValueError, TypeError):
                return d

        return Critique(
            reflection_type=reflection_type,
            stage=context_label,
            level=level_map.get(data.get("level", "adequate"), CritiqueLevel.ADEQUATE),
            score=_sf(data.get("score", data.get("overall_score", 50)), 50.0),
            strengths=data.get("strengths", data.get("key_achievements", [])),
            weaknesses=data.get("weaknesses", data.get("regrets", [])),
            findings=data.get("missed_opportunities", data.get("critical_gaps", [])),
            recommendations=data.get("recommendations", data.get("recommended_next_tests", [])),
            adapt_action=action_map.get(
                data.get("adapt_action", data.get("recommendation", "continue")),
                AdaptAction.CONTINUE,
            ),
            adapt_details=data.get("adapt_details", {}),
            reasoning=data.get("reasoning", data.get("final_recommendation", "")),
            timestamp=time.time(),
        )

    def _rule_based_critique(
        self,
        reflection_type: ReflectionType,
        context_label: str,
    ) -> Critique:
        """Brain olmadan basit kural-bazlı eleştiri."""
        perf = self.stage_performances.get(context_label)

        if perf is None:
            return Critique(
                reflection_type=reflection_type,
                stage=context_label,
                level=CritiqueLevel.ADEQUATE,
                score=50.0,
                reasoning="No performance data — rule-based default",
                adapt_action=AdaptAction.CONTINUE,
                timestamp=time.time(),
            )

        # Basit puanlama
        score = 50.0
        level = CritiqueLevel.ADEQUATE
        weaknesses: list[str] = []
        strengths: list[str] = []
        action = AdaptAction.CONTINUE

        # Stages where findings_count == 0 is NORMAL (they produce recon data, not vulns)
        _NON_VULN_STAGES = {
            "scope_analysis", "passive_recon", "active_recon",
            "enumeration", "attack_surface_mapping", "knowledge_update",
        }
        _is_vuln_stage = context_label not in _NON_VULN_STAGES

        if perf.findings_count > 0:
            score += 15
            strengths.append(f"Found {perf.findings_count} findings")
        elif _is_vuln_stage:
            # Only penalize 0 findings on stages that SHOULD produce findings
            score -= 20
            weaknesses.append("No findings discovered")
            action = AdaptAction.ADD_TOOLS
        else:
            # Non-vuln stage: 0 findings is expected — don't penalize
            score += 5
            strengths.append("Stage completed (recon/analysis stage — findings not expected)")

        if perf.fp_rate > 50:
            score -= 20
            weaknesses.append(f"High FP rate: {perf.fp_rate:.0f}%")
            action = AdaptAction.ADJUST_PARAMS
        elif perf.fp_rate < 20:
            score += 10
            strengths.append(f"Low FP rate: {perf.fp_rate:.0f}%")

        if len(perf.errors) > 3:
            score -= 15
            weaknesses.append(f"Multiple errors: {len(perf.errors)}")
        elif len(perf.errors) == 0:
            score += 5
            strengths.append("No errors")

        if perf.duration > 600:
            score -= 10
            weaknesses.append(f"Slow execution: {perf.duration:.0f}s")

        if len(perf.tools_used) < 2:
            score -= 10
            weaknesses.append("Only used 1 tool — consider additional tools")
            action = AdaptAction.ADD_TOOLS

        # Level determination
        score = max(0, min(100, score))
        if score >= 80:
            level = CritiqueLevel.EXCELLENT
        elif score >= 60:
            level = CritiqueLevel.GOOD
        elif score >= 40:
            level = CritiqueLevel.ADEQUATE
        elif score >= 20:
            level = CritiqueLevel.POOR
        else:
            level = CritiqueLevel.FAILED

        return Critique(
            reflection_type=reflection_type,
            stage=context_label,
            level=level,
            score=score,
            strengths=strengths,
            weaknesses=weaknesses,
            recommendations=["Consider adding more tools" if action == AdaptAction.ADD_TOOLS else "Continue"],
            adapt_action=action,
            reasoning=f"Rule-based assessment: score={score:.0f}, level={level}",
            timestamp=time.time(),
        )

    # ─── Analytics & Reporting ───────────────────────────────

    def get_performance_summary(self) -> dict[str, Any]:
        """Global performans özeti."""
        total_elapsed = time.time() - self.session_start
        completed_stages = [
            s for s, p in self.stage_performances.items()
            if p.completed_at > 0
        ]
        total_errors = sum(len(p.errors) for p in self.stage_performances.values())

        avg_critique_score = 0.0
        if self.critique_history:
            avg_critique_score = sum(c.score for c in self.critique_history) / len(self.critique_history)

        return {
            "session_duration": round(total_elapsed, 1),
            "stages_completed": completed_stages,
            "total_findings": len(self.total_findings),
            "verified_findings": len(self.verified_findings),
            "false_positives": len(self.false_positives),
            "fp_rate": round(
                len(self.false_positives) / max(1, len(self.total_findings)) * 100, 1
            ),
            "total_errors": total_errors,
            "decisions_made": len(self.decision_journal),
            "critiques_performed": len(self.critique_history),
            "avg_critique_score": round(avg_critique_score, 1),
            "strategy_pivots": len([
                a for a in self.strategy_adjustments
                if a.get("action") == AdaptAction.PIVOT
            ]),
            "current_strategy": self.current_strategy,
        }

    def get_decision_quality_report(self) -> dict[str, Any]:
        """Karar kalitesi raporu."""
        total = len(self.decision_journal)
        evaluated = [d for d in self.decision_journal if d.was_correct is not None]
        correct = sum(1 for d in evaluated if d.was_correct)
        avg_score = sum(d.outcome_score for d in evaluated) / max(1, len(evaluated))

        return {
            "total_decisions": total,
            "evaluated_decisions": len(evaluated),
            "correct_decisions": correct,
            "accuracy": round(correct / max(1, len(evaluated)) * 100, 1),
            "avg_outcome_score": round(avg_score, 1),
        }


__all__ = [
    "SelfReflectionEngine",
    "Critique",
    "CritiqueLevel",
    "AdaptAction",
    "ReflectionType",
    "DecisionEntry",
    "StagePerformance",
    "PerformanceMetric",
]
