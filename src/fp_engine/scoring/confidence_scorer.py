"""
WhiteHatHacker AI — Confidence Scorer

Bulgu güven puanı hesaplama motoru. Birden fazla sinyali
ağırlıklı olarak birleştirir ve 0-100 arası final skor üretir.
"""

from __future__ import annotations

from typing import Any

from loguru import logger
from pydantic import BaseModel


class ScoreBreakdown(BaseModel):
    """Detaylı skor çıktısı."""

    base_score: float = 50.0
    factors: list[dict[str, Any]] = []
    final_score: float = 50.0
    verdict: str = "needs_review"       # real | needs_review | likely_fp | false_positive
    tier: str = "medium"                # critical | high | medium | low | fp

    @property
    def is_reportable(self) -> bool:
        return self.verdict in ("real", "needs_review") and self.final_score >= 50.0


# ============================================================
# Ağırlık Tablosu
# ============================================================

# Vulnerability-type-aware base scores.
# High-impact vuln types start with a higher base to reflect
# that tools rarely false-positive on RCE/SQLi error-based,
# while info-disclosure/header findings are often noise.
VULN_TYPE_BASE_SCORES: dict[str, float] = {
    # Critical-impact types — tools are usually right
    "rce": 58.0,
    "command_injection": 58.0,
    "sqli": 55.0,
    "sqli_error": 58.0,
    "sqli_blind": 48.0,       # Blind detection is noisier
    "deserialization": 55.0,
    "lfi": 55.0,
    "ssti": 55.0,
    "auth_bypass": 55.0,
    "idor": 50.0,
    "privilege_escalation": 55.0,
    # High-impact types
    "ssrf": 52.0,
    "xxe": 55.0,
    "xss": 50.0,
    "xss_reflected": 50.0,
    "xss_stored": 52.0,
    "xss_dom": 48.0,
    # Medium-impact types
    "cors": 48.0,
    "open_redirect": 48.0,
    "crlf": 48.0,
    "header_injection": 45.0,
    "jwt": 50.0,
    "race_condition": 50.0,
    "cache_poisoning": 50.0,
    "prototype_pollution": 50.0,
    "http_smuggling": 52.0,
    "subdomain_takeover": 55.0,
    # Low-impact / high-noise types
    "information_disclosure": 42.0,
    "info_disclosure": 42.0,
    "missing_security_header": 65.0,  # Almost always true, just low severity
    "cookie_security": 60.0,          # Usually true
    "ssl_tls": 55.0,
    # Default for unknown types
    "_default": 50.0,
}

# Her faktörün ağırlığı
FACTOR_WEIGHTS = {
    # Pozitif faktörler
    "multi_tool_confirmed_3plus":  {"delta": +25, "desc": "3+ tools confirmed same finding"},
    "multi_tool_confirmed_2":      {"delta": +18, "desc": "2 tools confirmed same finding"},
    "payload_executed":            {"delta": +22, "desc": "Payload executed in target"},
    "payload_reflected_unencoded": {"delta": +18, "desc": "Payload reflected without encoding"},
    "time_based_confirmed":        {"delta": +20, "desc": "Time-based injection confirmed"},
    "oob_callback_received":       {"delta": +28, "desc": "Out-of-band callback received (legacy — use tiered)"},
    "oob_callback_high":           {"delta": +28, "desc": "OOB HTTP callback from non-infrastructure IP"},
    "oob_callback_medium":         {"delta": +15, "desc": "OOB DNS callback from non-infrastructure IP"},
    "oob_callback_low":            {"delta": +5,  "desc": "OOB callback from CDN/infrastructure IP"},
    "oob_callback_infrastructure": {"delta": 0,   "desc": "OOB DNS from public resolver — no evidence"},
    "data_extracted":              {"delta": +25, "desc": "Data successfully extracted"},
    "error_message_leaked":        {"delta": +12, "desc": "Error message leaked sensitive info"},
    "response_diff_significant":   {"delta": +10, "desc": "Significant response difference detected"},
    "brain_analysis_confirms":     {"delta": +15, "desc": "Brain AI analysis confirms finding"},
    "brain_both_confirm":          {"delta": +20, "desc": "Both brain models confirm finding"},
    "no_waf_interference":         {"delta": +5,  "desc": "No WAF/CDN detected"},
    "evidence_chain_complete":     {"delta": +10, "desc": "Complete evidence chain established"},
    "known_vuln_pattern_match":    {"delta": +8,  "desc": "Matches known vulnerability pattern"},
    "critical_severity":           {"delta": +5,  "desc": "Critical severity finding"},
    "auth_bypass_confirmed":       {"delta": +20, "desc": "Authentication bypass confirmed"},
    "privilege_escalation":        {"delta": +22, "desc": "Privilege escalation achieved"},

    # Negatif faktörler
    "single_tool_only":            {"delta": -15, "desc": "Only one tool reports this finding"},
    "waf_detected":                {"delta": -10, "desc": "WAF/CDN detected, may interfere"},
    "known_fp_pattern_match":      {"delta": -30, "desc": "Matches known false positive pattern"},
    "payload_reflected_encoded":   {"delta": -8,  "desc": "Payload reflected but encoded (safe)"},
    "inconsistent_results":        {"delta": -18, "desc": "Inconsistent results across tools"},
    "cdn_detected":                {"delta": -5,  "desc": "CDN detected, responses may be cached"},
    "generic_error_page":          {"delta": -12, "desc": "Generic error page (not vuln-specific)"},
    "no_payload_evidence":         {"delta": -10, "desc": "No payload or evidence provided"},
    "brain_analysis_denies":       {"delta": -15, "desc": "Brain AI analysis denies finding"},
    "brain_both_deny":             {"delta": -22, "desc": "Both brain models deny finding"},
    "timing_within_normal":        {"delta": -8,  "desc": "Response timing within normal range"},
    "info_only_finding":           {"delta": -20, "desc": "Informational finding, not a vulnerability"},
    "tool_known_fp_for_type":      {"delta": -12, "desc": "Tool known to produce FP for this type"},
    "stale_finding":               {"delta": -5,  "desc": "Finding may be stale/outdated"},
}


class ConfidenceScorer:
    """
    Güven puanı hesaplama motoru.

    Base skor 50'den başlar. Her faktör pozitif veya negatif
    delta uygular. Final skor 0-100 arası clamp edilir.

    Tier eşikleri:
      90-100 → "critical" (otomatik rapor)
      70-89  → "high" (minimal doğrulama)
      50-69  → "medium" (insan onayı gerekli)
      30-49  → "low" (derin analiz)
      0-29   → "fp" (büyük olasılıkla yanlış pozitif)

    Kullanım:
        scorer = ConfidenceScorer()
        breakdown = scorer.calculate(factors=["multi_tool_confirmed_2", "payload_executed"])
        print(breakdown.final_score, breakdown.verdict)
    """

    BASE_SCORE: float = 50.0

    # Tier thresholds
    TIER_CRITICAL = 90.0
    TIER_HIGH = 70.0
    TIER_MEDIUM = 50.0
    TIER_LOW = 30.0

    def __init__(
        self,
        custom_weights: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.weights = {**FACTOR_WEIGHTS}
        if custom_weights:
            self.weights.update(custom_weights)

    def calculate(
        self,
        factors: list[str] | None = None,
        raw_deltas: list[dict[str, Any]] | None = None,
        base_score: float | None = None,
    ) -> ScoreBreakdown:
        """
        Güven puanı hesapla.

        Args:
            factors: Faktör adları listesi (FACTOR_WEIGHTS'ten)
            raw_deltas: Özel delta listesi [{"name": ..., "delta": ..., "desc": ...}]
            base_score: Özel başlangıç skoru (default: 50)

        Returns:
            ScoreBreakdown
        """
        score = base_score if base_score is not None else self.BASE_SCORE
        applied_factors: list[dict[str, Any]] = []

        # Named factors
        if factors:
            for factor_name in factors:
                weight = self.weights.get(factor_name)
                if weight:
                    delta = weight["delta"]
                    score += delta
                    applied_factors.append({
                        "name": factor_name,
                        "delta": delta,
                        "description": weight["desc"],
                    })
                else:
                    logger.warning(f"Unknown confidence factor: {factor_name}")

        # Raw deltas
        if raw_deltas:
            for rd in raw_deltas:
                delta = rd.get("delta", 0)
                score += delta
                applied_factors.append({
                    "name": rd.get("name", "custom"),
                    "delta": delta,
                    "description": rd.get("desc", "Custom factor"),
                })

        # Clamp
        final_score = max(0.0, min(100.0, score))

        # Verdict & tier
        tier, verdict = self._classify(final_score)

        breakdown = ScoreBreakdown(
            base_score=base_score if base_score is not None else self.BASE_SCORE,
            factors=applied_factors,
            final_score=round(final_score, 1),
            verdict=verdict,
            tier=tier,
        )

        logger.debug(
            f"Confidence score: {final_score:.1f} | "
            f"tier={tier} | verdict={verdict} | "
            f"factors={len(applied_factors)}"
        )

        return breakdown

    def calculate_from_finding_context(
        self,
        vuln_type: str = "",
        multi_tool_count: int = 0,
        has_payload: bool = False,
        payload_reflected: bool = False,
        payload_encoded: bool = False,
        payload_executed: bool = False,
        time_based_confirmed: bool = False,
        oob_callback: bool = False,
        oob_callback_quality: str = "",
        data_extracted: bool = False,
        error_leaked: bool = False,
        response_diff_significant: bool = False,
        brain_primary_confirms: bool | None = None,
        brain_secondary_confirms: bool | None = None,
        waf_detected: bool = False,
        cdn_detected: bool = False,
        known_fp_match: bool = False,
        known_vuln_pattern: bool = False,
        tool_fp_tendency: bool = False,
        has_evidence: bool = False,
        is_info_only: bool = False,
    ) -> ScoreBreakdown:
        """
        Bulgu bağlamından otomatik faktör seçimi ve skor hesaplama.

        Bu method, FP Detector tarafından kullanılmak üzere tüm
        bağlam bilgilerini alıp uygun faktörleri otomatik seçer.
        """
        factors: list[str] = []

        # Determine base score from vulnerability type
        _vt = vuln_type.lower().replace("-", "_").replace(" ", "_") if vuln_type else ""
        type_base = VULN_TYPE_BASE_SCORES.get(_vt, VULN_TYPE_BASE_SCORES["_default"])

        # Multi-tool
        if multi_tool_count >= 3:
            factors.append("multi_tool_confirmed_3plus")
        elif multi_tool_count >= 2:
            factors.append("multi_tool_confirmed_2")
        elif multi_tool_count <= 1:
            factors.append("single_tool_only")

        # Payload execution
        # Note: time_based_confirmed and oob_callback ARE evidence —
        # do not penalise "no_payload_evidence" when either is present.
        _has_indirect_evidence = time_based_confirmed or oob_callback
        if payload_executed:
            factors.append("payload_executed")
        elif payload_reflected and not payload_encoded:
            factors.append("payload_reflected_unencoded")
        elif payload_reflected and payload_encoded:
            factors.append("payload_reflected_encoded")
        elif has_payload is False and not _has_indirect_evidence:
            factors.append("no_payload_evidence")

        # Special confirmations
        if time_based_confirmed:
            factors.append("time_based_confirmed")
        if oob_callback:
            # Use quality-tiered OOB factor when quality info is available
            _oob_q = oob_callback_quality.lower() if oob_callback_quality else ""
            if _oob_q == "high":
                factors.append("oob_callback_high")
            elif _oob_q == "medium":
                factors.append("oob_callback_medium")
            elif _oob_q == "low":
                factors.append("oob_callback_low")
            elif _oob_q == "infrastructure":
                factors.append("oob_callback_infrastructure")
            else:
                # Legacy path — no quality info, use old factor
                factors.append("oob_callback_received")
        if data_extracted:
            factors.append("data_extracted")
        if error_leaked:
            factors.append("error_message_leaked")

        # Response
        if response_diff_significant:
            factors.append("response_diff_significant")

        # Brain
        if brain_primary_confirms is not None and brain_secondary_confirms is not None:
            if brain_primary_confirms and brain_secondary_confirms:
                factors.append("brain_both_confirm")
            elif not brain_primary_confirms and not brain_secondary_confirms:
                factors.append("brain_both_deny")
            elif brain_primary_confirms or brain_secondary_confirms:
                factors.append("brain_analysis_confirms")
        elif brain_primary_confirms is True:
            factors.append("brain_analysis_confirms")
        elif brain_primary_confirms is False:
            factors.append("brain_analysis_denies")

        # WAF/CDN
        if waf_detected:
            factors.append("waf_detected")
        else:
            factors.append("no_waf_interference")
        if cdn_detected:
            factors.append("cdn_detected")

        # Pattern matching
        if known_fp_match:
            factors.append("known_fp_pattern_match")
        if known_vuln_pattern:
            factors.append("known_vuln_pattern_match")
        if tool_fp_tendency:
            factors.append("tool_known_fp_for_type")

        # Evidence
        if has_evidence:
            factors.append("evidence_chain_complete")

        # Info only
        if is_info_only:
            factors.append("info_only_finding")

        return self.calculate(factors=factors, base_score=type_base)

    def _classify(self, score: float) -> tuple[str, str]:
        """Skoru tier ve verdict'e dönüştür."""
        if score >= self.TIER_CRITICAL:
            return "critical", "real"
        elif score >= self.TIER_HIGH:
            return "high", "real"
        elif score >= self.TIER_MEDIUM:
            return "medium", "needs_review"
        elif score >= self.TIER_LOW:
            return "low", "likely_fp"
        else:
            return "fp", "false_positive"

    @staticmethod
    def list_factors() -> dict[str, dict[str, Any]]:
        """Tüm faktörleri listele."""
        return FACTOR_WEIGHTS.copy()


__all__ = ["ConfidenceScorer", "ScoreBreakdown", "FACTOR_WEIGHTS", "VULN_TYPE_BASE_SCORES"]
