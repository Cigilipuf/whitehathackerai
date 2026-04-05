"""WhiteHatHacker AI — Impact Assessment Module.

Evaluates the real-world business / technical impact of a confirmed
vulnerability and produces a structured impact report.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Impact taxonomy
# ---------------------------------------------------------------------------

class ImpactCategory(str, Enum):
    """CIA triad + extras."""

    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    AUTHENTICATION = "authentication"
    AUTHORISATION = "authorisation"
    ACCOUNTABILITY = "accountability"
    FINANCIAL = "financial"
    REPUTATION = "reputation"
    COMPLIANCE = "compliance"


class ImpactLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"
    FINANCIAL = "financial"
    CREDENTIALS = "credentials"


# ---------------------------------------------------------------------------
# Impact models
# ---------------------------------------------------------------------------

class ImpactDimension(BaseModel):
    """Single dimension of impact."""

    category: ImpactCategory
    level: ImpactLevel = ImpactLevel.NONE
    description: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    data_at_risk: list[DataClassification] = Field(default_factory=list)


class ImpactReport(BaseModel):
    """Full impact assessment for a vulnerability."""

    vuln_type: str
    target: str
    overall_impact: ImpactLevel = ImpactLevel.NONE
    dimensions: list[ImpactDimension] = Field(default_factory=list)
    business_impact: str = ""
    technical_impact: str = ""
    affected_users: str = ""  # "all", "authenticated", "admin", "specific"
    affected_data: list[DataClassification] = Field(default_factory=list)
    exploitability: str = ""  # "trivial", "moderate", "complex"
    attack_prerequisites: list[str] = Field(default_factory=list)
    remediation_urgency: str = ""  # "immediate", "next-sprint", "planned"
    score: float = 0.0  # 0-10
    reasoning: str = ""


# ---------------------------------------------------------------------------
# Vuln-type → impact mapping
# ---------------------------------------------------------------------------

VULN_IMPACT_MAP: dict[str, dict[str, Any]] = {
    "sqli": {
        "dimensions": [
            {"category": "confidentiality", "level": "critical",
             "description": "Full database read access possible"},
            {"category": "integrity", "level": "high",
             "description": "Data modification / deletion via UNION or stacked queries"},
            {"category": "authentication", "level": "high",
             "description": "Auth bypass through injection"},
        ],
        "data_at_risk": ["credentials", "pii", "financial"],
        "exploitability": "moderate",
        "business_impact": "Complete database compromise, data breach, regulatory fines",
        "base_score": 8.5,
    },
    "xss": {
        "dimensions": [
            {"category": "confidentiality", "level": "medium",
             "description": "Session hijacking, cookie theft"},
            {"category": "integrity", "level": "medium",
             "description": "Page content manipulation, phishing"},
        ],
        "data_at_risk": ["credentials"],
        "exploitability": "trivial",
        "business_impact": "Account takeover via session hijacking, phishing attacks",
        "base_score": 6.0,
    },
    "ssrf": {
        "dimensions": [
            {"category": "confidentiality", "level": "high",
             "description": "Internal network / cloud metadata access"},
            {"category": "authorisation", "level": "high",
             "description": "Bypass network segmentation"},
        ],
        "data_at_risk": ["internal", "credentials"],
        "exploitability": "moderate",
        "business_impact": "Cloud credential theft (AWS/GCP metadata), internal service access",
        "base_score": 8.0,
    },
    "rce": {
        "dimensions": [
            {"category": "confidentiality", "level": "critical",
             "description": "Full server file-system read"},
            {"category": "integrity", "level": "critical",
             "description": "Arbitrary file write / code execution"},
            {"category": "availability", "level": "critical",
             "description": "Server shutdown or ransomware"},
        ],
        "data_at_risk": ["credentials", "pii", "financial", "restricted"],
        "exploitability": "moderate",
        "business_impact": "Complete server takeover, data exfiltration, lateral movement",
        "base_score": 10.0,
    },
    "ssti": {
        "dimensions": [
            {"category": "confidentiality", "level": "high",
             "description": "Server-side code execution, file read"},
            {"category": "integrity", "level": "high",
             "description": "Arbitrary code execution on server"},
        ],
        "data_at_risk": ["credentials", "internal"],
        "exploitability": "moderate",
        "business_impact": "Server compromise via template injection to RCE chain",
        "base_score": 8.5,
    },
    "idor": {
        "dimensions": [
            {"category": "authorisation", "level": "high",
             "description": "Access to other users' resources"},
            {"category": "confidentiality", "level": "high",
             "description": "Data leakage across accounts"},
        ],
        "data_at_risk": ["pii", "financial"],
        "exploitability": "trivial",
        "business_impact": "Mass data harvesting across user accounts",
        "base_score": 7.0,
    },
    "auth_bypass": {
        "dimensions": [
            {"category": "authentication", "level": "critical",
             "description": "Complete authentication bypass"},
            {"category": "authorisation", "level": "critical",
             "description": "Unauthorised access to protected resources"},
        ],
        "data_at_risk": ["credentials", "pii", "restricted"],
        "exploitability": "trivial",
        "business_impact": "Full account takeover, admin access without credentials",
        "base_score": 9.0,
    },
    "cors_misconfig": {
        "dimensions": [
            {"category": "confidentiality", "level": "medium",
             "description": "Cross-origin data theft"},
        ],
        "data_at_risk": ["pii"],
        "exploitability": "moderate",
        "business_impact": "Sensitive data theft via malicious website",
        "base_score": 5.5,
    },
    "open_redirect": {
        "dimensions": [
            {"category": "integrity", "level": "low",
             "description": "Redirect to malicious site for phishing"},
        ],
        "data_at_risk": [],
        "exploitability": "trivial",
        "business_impact": "Phishing attacks using trusted domain",
        "base_score": 3.5,
    },
    "lfi": {
        "dimensions": [
            {"category": "confidentiality", "level": "high",
             "description": "Server file read (/etc/passwd, config files)"},
        ],
        "data_at_risk": ["credentials", "internal"],
        "exploitability": "moderate",
        "business_impact": "Sensitive file disclosure, potential RCE via log poisoning",
        "base_score": 7.5,
    },
    "jwt_vuln": {
        "dimensions": [
            {"category": "authentication", "level": "high",
             "description": "Token forgery / algorithm confusion"},
            {"category": "authorisation", "level": "high",
             "description": "Privilege escalation via token manipulation"},
        ],
        "data_at_risk": ["credentials"],
        "exploitability": "moderate",
        "business_impact": "Account takeover via forged JWT tokens",
        "base_score": 8.0,
    },
}


# ---------------------------------------------------------------------------
# Assessor
# ---------------------------------------------------------------------------

class ImpactAssessor:
    """Evaluates the impact of a vulnerability."""

    def __init__(self) -> None:
        self.impact_map = dict(VULN_IMPACT_MAP)

    # ---- Main entry ------------------------------------------------------

    def assess(
        self,
        vuln_type: str,
        target: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> ImpactReport:
        """Produce an ImpactReport for the given vulnerability type."""
        context = context or {}
        template = self.impact_map.get(vuln_type, {})

        dimensions = [
            ImpactDimension(
                category=ImpactCategory(d["category"]),
                level=ImpactLevel(d["level"]),
                description=d.get("description", ""),
            )
            for d in template.get("dimensions", [])
        ]

        data_at_risk = [
            DataClassification(d) for d in template.get("data_at_risk", [])
        ]

        base_score = template.get("base_score", 5.0)
        exploitability = template.get("exploitability", "moderate")

        # Context adjustments
        adjusted_score = self._adjust_score(base_score, context)
        overall = self._score_to_level(adjusted_score)

        # Attack prerequisites
        prerequisites = self._determine_prerequisites(vuln_type, context)

        # Remediation urgency
        urgency = self._determine_urgency(adjusted_score)

        report = ImpactReport(
            vuln_type=vuln_type,
            target=target,
            overall_impact=overall,
            dimensions=dimensions,
            business_impact=template.get("business_impact", "Impact not categorised"),
            technical_impact=self._build_technical_impact(vuln_type, context),
            affected_users=context.get("affected_users", "unknown"),
            affected_data=data_at_risk,
            exploitability=exploitability,
            attack_prerequisites=prerequisites,
            remediation_urgency=urgency,
            score=round(adjusted_score, 1),
            reasoning=self._build_reasoning(vuln_type, adjusted_score, context),
        )

        logger.info(
            f"Impact assessment: {vuln_type} on {target} → "
            f"{overall.value} (score={adjusted_score:.1f})"
        )
        return report

    # ---- Batch -----------------------------------------------------------

    def assess_multiple(
        self,
        findings: list[dict[str, Any]],
    ) -> list[ImpactReport]:
        """Assess a batch of findings."""
        reports: list[ImpactReport] = []
        for f in findings:
            report = self.assess(
                vuln_type=f.get("vuln_type", "unknown"),
                target=f.get("target", ""),
                context=f.get("context", {}),
            )
            reports.append(report)
        return reports

    # ---- Score adjustments -----------------------------------------------

    @staticmethod
    def _adjust_score(base: float, ctx: dict[str, Any]) -> float:
        score = base

        # Internet-facing bumps score up
        if ctx.get("internet_facing", True):
            score += 0.5

        # Authentication required lowers exploitability
        if ctx.get("requires_auth", False):
            score -= 1.0

        # Sensitive data present raises impact
        if ctx.get("handles_sensitive_data", False):
            score += 1.0

        # WAF / protection reduces exploitability
        if ctx.get("waf_present", False):
            score -= 0.5

        # Production vs staging
        if ctx.get("environment") == "staging":
            score -= 1.5
        elif ctx.get("environment") == "development":
            score -= 2.5

        return max(0.0, min(10.0, score))

    @staticmethod
    def _score_to_level(score: float) -> ImpactLevel:
        if score >= 9.0:
            return ImpactLevel.CRITICAL
        if score >= 7.0:
            return ImpactLevel.HIGH
        if score >= 4.0:
            return ImpactLevel.MEDIUM
        if score >= 1.0:
            return ImpactLevel.LOW
        return ImpactLevel.NONE

    @staticmethod
    def _determine_prerequisites(vuln_type: str, ctx: dict[str, Any]) -> list[str]:
        prereqs: list[str] = []
        if ctx.get("requires_auth"):
            prereqs.append("Valid user credentials required")
        if vuln_type in ("xss",):
            prereqs.append("Victim must visit attacker-controlled URL")
        if vuln_type == "cors_misconfig":
            prereqs.append("Victim must visit attacker's page while authenticated")
        if ctx.get("requires_interaction"):
            prereqs.append("User interaction required")
        if not prereqs:
            prereqs.append("No special prerequisites — network access sufficient")
        return prereqs

    @staticmethod
    def _determine_urgency(score: float) -> str:
        if score >= 9.0:
            return "immediate"
        if score >= 7.0:
            return "next-sprint"
        return "planned"

    @staticmethod
    def _build_technical_impact(vuln_type: str, ctx: dict[str, Any]) -> str:
        impacts = {
            "sqli": "Arbitrary SQL execution against the backend database",
            "xss": "JavaScript execution in victim's browser context",
            "ssrf": "Server-side requests to internal/external services",
            "rce": "Arbitrary command execution on the web server",
            "ssti": "Template engine code execution leading to RCE",
            "idor": "Horizontal/vertical privilege escalation via direct object reference",
            "auth_bypass": "Authentication mechanism circumvention",
            "lfi": "Local file inclusion — arbitrary file read on server",
            "jwt_vuln": "JWT token forgery or algorithm confusion attack",
        }
        base = impacts.get(vuln_type, f"Exploitation of {vuln_type} vulnerability")
        if ctx.get("chained_with"):
            base += f" (chained with {ctx['chained_with']})"
        return base

    @staticmethod
    def _build_reasoning(vuln_type: str, score: float, ctx: dict[str, Any]) -> str:
        parts = [f"Vulnerability type: {vuln_type}, adjusted score: {score:.1f}/10."]
        if ctx.get("internet_facing", True):
            parts.append("Target is internet-facing (+0.5).")
        if ctx.get("requires_auth"):
            parts.append("Requires authentication (-1.0).")
        if ctx.get("handles_sensitive_data"):
            parts.append("Handles sensitive data (+1.0).")
        if ctx.get("waf_present"):
            parts.append("WAF detected (-0.5).")
        env = ctx.get("environment", "production")
        if env != "production":
            parts.append(f"Environment is {env} (penalty applied).")
        return " ".join(parts)
