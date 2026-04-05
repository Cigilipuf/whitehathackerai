"""WhiteHatHacker AI — Risk Assessment Module.

Combines threat probability, impact severity, and contextual factors to
produce a quantified risk score and prioritised action plan.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, ClassVar

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Risk taxonomy
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatLikelihood(str, Enum):
    CERTAIN = "certain"      # 0.95
    LIKELY = "likely"        # 0.75
    POSSIBLE = "possible"    # 0.50
    UNLIKELY = "unlikely"    # 0.25
    RARE = "rare"            # 0.10


LIKELIHOOD_SCORES: dict[ThreatLikelihood, float] = {
    ThreatLikelihood.CERTAIN: 0.95,
    ThreatLikelihood.LIKELY: 0.75,
    ThreatLikelihood.POSSIBLE: 0.50,
    ThreatLikelihood.UNLIKELY: 0.25,
    ThreatLikelihood.RARE: 0.10,
}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class RiskFactor(BaseModel):
    """Individual risk factor."""

    name: str
    weight: float = 1.0  # 0-1 relative importance
    score: float = 0.0   # 0-10
    description: str = ""


class RiskAssessment(BaseModel):
    """Complete risk assessment for a vulnerability or target."""

    target: str = ""
    vuln_type: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    risk_score: float = 0.0  # 0-100
    threat_likelihood: ThreatLikelihood = ThreatLikelihood.POSSIBLE
    impact_score: float = 0.0  # 0-10
    exploitability_score: float = 0.0  # 0-10
    factors: list[RiskFactor] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    reasoning: str = ""
    priority_rank: int = 0  # lower = higher priority


class AttackVectorRisk(BaseModel):
    """Risk assessment for an attack vector / surface."""

    vector_name: str
    endpoints: list[str] = Field(default_factory=list)
    vuln_types_applicable: list[str] = Field(default_factory=list)
    estimated_risk: RiskLevel = RiskLevel.INFO
    estimated_roi: float = 0.0  # expected bounty reward / effort ratio
    effort_hours: float = 0.0
    reasoning: str = ""


# ---------------------------------------------------------------------------
# Exploitability baselines per vuln type
# ---------------------------------------------------------------------------

EXPLOIT_DIFFICULTY: dict[str, float] = {
    "sqli": 7.0,           # Tools make it easy
    "xss": 8.0,            # Often trivial
    "ssrf": 6.0,           # Needs specific conditions
    "rce": 5.0,            # Varies widely
    "ssti": 6.5,           # Template-specific knowledge needed
    "idor": 8.5,           # Usually trivial once found
    "auth_bypass": 6.0,    # Case-specific
    "csrf": 7.0,           # Easy once no token found
    "open_redirect": 9.0,  # Trivial
    "cors_misconfig": 7.5, # Easy to exploit
    "lfi": 6.5,            # Filter bypass often needed
    "jwt_vuln": 5.5,       # Requires crypto knowledge
    "race_condition": 4.0, # Timing-dependent
    "business_logic": 3.5, # Deep understanding needed
    "command_injection": 6.0,
    "crlf_injection": 7.0,
    "http_smuggling": 3.0, # Requires deep protocol knowledge
}


# ---------------------------------------------------------------------------
# Risk Assessor
# ---------------------------------------------------------------------------

class RiskAssessor:
    """Quantifies risk by combining likelihood, impact, and context."""

    def __init__(self) -> None:
        self.exploit_difficulty = dict(EXPLOIT_DIFFICULTY)

    # ---- Single vulnerability risk ---------------------------------------

    def assess_vulnerability(
        self,
        vuln_type: str,
        target: str,
        impact_score: float,
        *,
        confidence: float = 50.0,
        context: dict[str, Any] | None = None,
    ) -> RiskAssessment:
        """Produce a RiskAssessment for a single vulnerability."""
        context = context or {}

        # Exploitability
        exploit_score = self.exploit_difficulty.get(vuln_type, 5.0)
        if context.get("public_exploit_available"):
            exploit_score = min(10.0, exploit_score + 2.0)
        if context.get("waf_present"):
            exploit_score = max(0.0, exploit_score - 1.5)

        # Likelihood
        likelihood = self._estimate_likelihood(exploit_score, confidence, context)

        # Risk factors
        factors = self._build_factors(vuln_type, impact_score, exploit_score, context)

        # Composite risk score (0–100)
        risk_score = self._calculate_risk_score(
            impact_score, exploit_score, LIKELIHOOD_SCORES[likelihood], factors
        )

        risk_level = self._score_to_level(risk_score)
        actions = self._recommend_actions(vuln_type, risk_level, context)
        mitigations = self._suggest_mitigations(vuln_type)

        assessment = RiskAssessment(
            target=target,
            vuln_type=vuln_type,
            risk_level=risk_level,
            risk_score=round(risk_score, 1),
            threat_likelihood=likelihood,
            impact_score=round(impact_score, 1),
            exploitability_score=round(exploit_score, 1),
            factors=factors,
            mitigations=mitigations,
            recommended_actions=actions,
            reasoning=self._build_reasoning(
                vuln_type, risk_score, impact_score, exploit_score, likelihood
            ),
        )

        logger.info(
            f"Risk assessment: {vuln_type}@{target} → {risk_level.value} "
            f"(score={risk_score:.1f})"
        )
        return assessment

    # ---- Batch + prioritisation ------------------------------------------

    _SEVERITY_IMPACT: ClassVar[dict[str, float]] = {
        "critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0,
    }

    def prioritise_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[RiskAssessment]:
        """Assess and rank a batch of findings by risk score (desc)."""
        assessments: list[RiskAssessment] = []
        for f in findings:
            # Resolve field keys robustly — findings use various key names
            _vtype = (
                f.get("vulnerability_type")
                or f.get("vuln_type")
                or f.get("finding_type")
                or "unknown"
            )
            _target = (
                f.get("url")
                or f.get("endpoint")
                or f.get("target")
                or ""
            )
            _sev = str(f.get("severity", "medium")).lower().strip()
            _impact = self._SEVERITY_IMPACT.get(_sev, 5.0)
            _conf_raw = f.get("confidence_score", f.get("confidence", 50.0))
            try:
                _conf = float(_conf_raw)
            except (TypeError, ValueError):
                _conf = 50.0

            a = self.assess_vulnerability(
                vuln_type=_vtype,
                target=_target,
                impact_score=_impact,
                confidence=_conf,
                context=f.get("context", {}),
            )
            assessments.append(a)

        # Sort by risk_score desc
        assessments.sort(key=lambda x: x.risk_score, reverse=True)
        for idx, a in enumerate(assessments, 1):
            a.priority_rank = idx
        return assessments

    # ---- Attack surface risk ---------------------------------------------

    def assess_attack_surface(
        self,
        endpoints: list[dict[str, Any]],
    ) -> list[AttackVectorRisk]:
        """Evaluate risk for a collection of endpoints / vectors."""
        vectors: list[AttackVectorRisk] = []
        # Group by likely vuln types
        type_endpoints: dict[str, list[str]] = {}
        for ep in endpoints:
            url = ep.get("url", "")
            for vtype in ep.get("potential_vulns", ["unknown"]):
                type_endpoints.setdefault(vtype, []).append(url)

        for vtype, urls in type_endpoints.items():
            exploit = self.exploit_difficulty.get(vtype, 5.0)
            effort = max(0.5, (10.0 - exploit) * 0.5)  # inverse relationship
            roi = exploit / max(effort, 0.1)

            vectors.append(AttackVectorRisk(
                vector_name=vtype,
                endpoints=urls[:20],
                vuln_types_applicable=[vtype],
                estimated_risk=self._score_to_level(exploit * 10),
                estimated_roi=round(roi, 2),
                effort_hours=round(effort, 1),
                reasoning=(
                    f"{len(urls)} endpoint(s) potentially vulnerable to {vtype}. "
                    f"Estimated exploitability={exploit}/10, effort={effort:.1f}h, ROI={roi:.2f}."
                ),
            ))

        vectors.sort(key=lambda v: v.estimated_roi, reverse=True)
        return vectors

    # ---- Internal helpers ------------------------------------------------

    @staticmethod
    def _estimate_likelihood(
        exploit_score: float, confidence: float, ctx: dict[str, Any]
    ) -> ThreatLikelihood:
        """Map exploit ease + confidence → likelihood."""
        combined = (exploit_score / 10.0 * 0.6) + (confidence / 100.0 * 0.4)
        if ctx.get("actively_exploited"):
            combined = min(1.0, combined + 0.2)
        if combined >= 0.85:
            return ThreatLikelihood.CERTAIN
        if combined >= 0.65:
            return ThreatLikelihood.LIKELY
        if combined >= 0.40:
            return ThreatLikelihood.POSSIBLE
        if combined >= 0.20:
            return ThreatLikelihood.UNLIKELY
        return ThreatLikelihood.RARE

    @staticmethod
    def _calculate_risk_score(
        impact: float, exploit: float, likelihood: float,
        factors: list[RiskFactor],
    ) -> float:
        """Weighted risk score (0-100)."""
        base = (impact * 0.4 + exploit * 0.3) * likelihood * 10

        # Factor adjustments
        factor_adj = sum(f.weight * f.score for f in factors) / max(len(factors), 1)
        return max(0.0, min(100.0, base + factor_adj))

    @staticmethod
    def _build_factors(
        vuln_type: str, impact: float, exploit: float,
        ctx: dict[str, Any],
    ) -> list[RiskFactor]:
        factors: list[RiskFactor] = [
            RiskFactor(
                name="impact", weight=0.4, score=impact,
                description=f"Impact score: {impact}/10",
            ),
            RiskFactor(
                name="exploitability", weight=0.3, score=exploit,
                description=f"Exploit difficulty: {exploit}/10",
            ),
        ]
        if ctx.get("internet_facing", True):
            factors.append(RiskFactor(
                name="exposure", weight=0.15, score=8.0,
                description="Internet-facing target",
            ))
        if ctx.get("handles_sensitive_data"):
            factors.append(RiskFactor(
                name="data_sensitivity", weight=0.15, score=9.0,
                description="Handles sensitive/regulated data",
            ))
        if ctx.get("high_traffic"):
            factors.append(RiskFactor(
                name="blast_radius", weight=0.1, score=7.0,
                description="High-traffic application",
            ))
        return factors

    @staticmethod
    def _score_to_level(score: float) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 35:
            return RiskLevel.MEDIUM
        if score >= 15:
            return RiskLevel.LOW
        return RiskLevel.INFO

    @staticmethod
    def _recommend_actions(
        vuln_type: str, risk_level: RiskLevel, ctx: dict[str, Any]
    ) -> list[str]:
        actions: list[str] = []
        if risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            actions.append(f"Immediately report {vuln_type} vulnerability")
            actions.append("Prepare detailed PoC with reproduction steps")
        if risk_level == RiskLevel.CRITICAL:
            actions.append("Consider responsible disclosure timeline urgency")
        if risk_level == RiskLevel.MEDIUM:
            actions.append("Verify with secondary tool before reporting")
            actions.append("Check for escalation potential (chain with other findings)")
        if risk_level == RiskLevel.LOW:
            actions.append("Document as informational / low severity")
            actions.append("Consider combining with other findings for higher impact")
        return actions

    @staticmethod
    def _suggest_mitigations(vuln_type: str) -> list[str]:
        mitigations_db: dict[str, list[str]] = {
            "sqli": ["Use parameterised queries / prepared statements",
                     "Implement input validation", "Apply least privilege on DB user"],
            "xss": ["Encode output contextually (HTML/JS/URL/CSS)",
                    "Implement Content-Security-Policy headers",
                    "Use HttpOnly + Secure cookie flags"],
            "ssrf": ["Whitelist allowed outbound destinations",
                     "Block requests to internal / metadata IPs",
                     "Validate and sanitise URL input"],
            "rce": ["Avoid system command execution with user input",
                    "Use sandboxed execution environments",
                    "Implement strict input validation"],
            "idor": ["Implement proper authorisation checks per resource",
                     "Use indirect object references (UUIDs)",
                     "Validate user ownership on every request"],
            "auth_bypass": ["Review authentication flow for logic flaws",
                           "Implement multi-factor authentication",
                           "Add security regression tests"],
        }
        return mitigations_db.get(vuln_type, [f"Remediate {vuln_type} per OWASP guidelines"])

    @staticmethod
    def _build_reasoning(
        vuln_type: str, risk_score: float, impact: float,
        exploit: float, likelihood: ThreatLikelihood,
    ) -> str:
        return (
            f"{vuln_type} vulnerability assessed at risk score {risk_score:.1f}/100. "
            f"Impact={impact:.1f}/10, exploitability={exploit:.1f}/10, "
            f"likelihood={likelihood.value}. "
            f"Risk = (impact×0.4 + exploitability×0.3) × likelihood × 10 + factor adjustments."
        )
