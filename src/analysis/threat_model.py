"""
WhiteHatHacker AI — Threat Model Generator

STRIDE bazlı tehdit modelleme modülü.
Her endpoint ve servis için olası tehditleri tanımlar,
risk puanı atar ve önceliklendirme yapar.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Models
# ============================================================

class Threat(BaseModel):
    """Tek bir tanımlanmış tehdit."""

    id: str = ""
    name: str = ""
    category: str = ""          # STRIDE: S, T, R, I, D, E
    description: str = ""
    target: str = ""            # Etkilenen endpoint/servis
    attack_method: str = ""
    likelihood: str = "medium"  # very_low, low, medium, high, very_high
    impact: str = "medium"      # very_low, low, medium, high, very_high
    risk_score: float = 0.0     # 0-25 (likelihood × impact)
    mitigations: list[str] = Field(default_factory=list)
    tools_to_test: list[str] = Field(default_factory=list)


class ThreatModelReport(BaseModel):
    """Tam tehdit modeli raporu."""

    target: str = ""
    generated_at: str = ""
    total_threats: int = 0
    threats: list[Threat] = Field(default_factory=list)
    risk_summary: dict[str, int] = Field(default_factory=dict)  # category → count
    high_risk_threats: list[Threat] = Field(default_factory=list)


# ============================================================
# STRIDE Kategori Tanımları
# ============================================================

STRIDE_CATEGORIES = {
    "S": {
        "name": "Spoofing",
        "description": "Pretending to be someone or something else",
        "question": "Can an attacker pretend to be another user, system, or component?",
    },
    "T": {
        "name": "Tampering",
        "description": "Modifying data or code without authorization",
        "question": "Can an attacker modify data in transit, at rest, or in memory?",
    },
    "R": {
        "name": "Repudiation",
        "description": "Denying having performed an action",
        "question": "Can an attacker deny performing malicious actions?",
    },
    "I": {
        "name": "Information Disclosure",
        "description": "Exposing information to unauthorized parties",
        "question": "Can an attacker access data they shouldn't see?",
    },
    "D": {
        "name": "Denial of Service",
        "description": "Disrupting or degrading service availability",
        "question": "Can an attacker make the system unavailable?",
    },
    "E": {
        "name": "Elevation of Privilege",
        "description": "Gaining capabilities beyond authorized level",
        "question": "Can an attacker gain higher privileges than intended?",
    },
}


# ============================================================
# Servis/Teknoloji → Tehdit şablonları
# ============================================================

THREAT_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_application": [
        {"cat": "S", "name": "Session Hijacking", "method": "Steal session tokens via XSS, network sniffing, or session fixation",
         "tools": ["dalfox", "xsstrike", "mitmproxy"]},
        {"cat": "S", "name": "Credential Stuffing", "method": "Automated login attempts using leaked credential databases",
         "tools": ["hydra", "custom"]},
        {"cat": "T", "name": "SQL Injection Data Modification", "method": "Modify database records through SQL injection",
         "tools": ["sqlmap"]},
        {"cat": "T", "name": "Parameter Tampering", "method": "Modify hidden parameters, prices, roles, or quantities",
         "tools": ["mitmproxy", "custom"]},
        {"cat": "R", "name": "Insufficient Logging", "method": "Actions without audit trail due to missing/incomplete logging",
         "tools": ["manual"]},
        {"cat": "I", "name": "SQL Injection Data Exfiltration", "method": "Extract database contents via SQL injection",
         "tools": ["sqlmap"]},
        {"cat": "I", "name": "Directory Traversal", "method": "Access files outside web root via path traversal",
         "tools": ["ffuf", "nuclei"]},
        {"cat": "I", "name": "Verbose Error Messages", "method": "Extract stack traces, paths, and versions from error responses",
         "tools": ["nuclei", "nikto"]},
        {"cat": "D", "name": "Application Layer DoS", "method": "Resource-intensive requests, regex DoS, or XML bombs",
         "tools": ["manual"]},
        {"cat": "E", "name": "IDOR / Broken Access Control", "method": "Access other users' resources by manipulating IDs",
         "tools": ["custom_idor"]},
        {"cat": "E", "name": "Privilege Escalation via Business Logic", "method": "Exploit business logic flaws to gain admin access",
         "tools": ["manual", "mitmproxy"]},
    ],
    "api_rest": [
        {"cat": "S", "name": "JWT Token Forgery", "method": "Forge or tamper JWT tokens (none algorithm, weak secret)",
         "tools": ["jwt_tool"]},
        {"cat": "S", "name": "API Key Theft", "method": "Extract API keys from mobile apps, JavaScript, or git repos",
         "tools": ["manual", "nuclei"]},
        {"cat": "T", "name": "Mass Assignment", "method": "Modify protected fields by sending extra parameters",
         "tools": ["manual", "arjun"]},
        {"cat": "I", "name": "Excessive Data Exposure", "method": "API returns more data than necessary",
         "tools": ["manual"]},
        {"cat": "I", "name": "GraphQL Introspection", "method": "Schema discovery through introspection queries",
         "tools": ["nuclei"]},
        {"cat": "D", "name": "Rate Limit Bypass", "method": "Bypass rate limiting via header manipulation or IP rotation",
         "tools": ["custom"]},
        {"cat": "E", "name": "BOLA (Broken Object Level Authorization)", "method": "Access other users' objects via API",
         "tools": ["custom_idor"]},
    ],
    "authentication": [
        {"cat": "S", "name": "Brute Force Login", "method": "Automated password guessing",
         "tools": ["hydra"]},
        {"cat": "S", "name": "OAuth Misconfiguration", "method": "Token theft via redirect_uri manipulation",
         "tools": ["manual"]},
        {"cat": "T", "name": "Password Reset Poisoning", "method": "Manipulate password reset flow to hijack accounts",
         "tools": ["manual"]},
        {"cat": "I", "name": "User Enumeration", "method": "Determine valid usernames via differential responses",
         "tools": ["ffuf", "hydra"]},
        {"cat": "E", "name": "Authentication Bypass", "method": "Skip login via direct access, SQL injection, or logic flaws",
         "tools": ["sqlmap", "manual"]},
    ],
    "network_service": [
        {"cat": "S", "name": "ARP/DNS Spoofing", "method": "Redirect traffic via ARP poisoning or DNS spoofing",
         "tools": ["mitmproxy"]},
        {"cat": "T", "name": "Man-in-the-Middle", "method": "Intercept and modify network traffic",
         "tools": ["mitmproxy"]},
        {"cat": "I", "name": "SMB Null Session Enumeration", "method": "Extract user, share, and policy info via null session",
         "tools": ["enum4linux", "smbclient"]},
        {"cat": "I", "name": "SNMP Community String Guessing", "method": "Read device configuration via default community strings",
         "tools": ["snmpwalk"]},
        {"cat": "D", "name": "SYN Flood / Network DoS", "method": "Overwhelm service with connection requests",
         "tools": ["manual"]},
        {"cat": "E", "name": "Service Exploitation", "method": "Exploit known CVEs in exposed network services",
         "tools": ["searchsploit", "nmap"]},
    ],
    "ssl_tls": [
        {"cat": "I", "name": "Weak SSL/TLS Configuration", "method": "Downgrade attacks, weak ciphers, or protocol vulnerabilities",
         "tools": ["sslscan", "sslyze"]},
        {"cat": "T", "name": "SSL Stripping", "method": "Downgrade HTTPS to HTTP to intercept traffic",
         "tools": ["mitmproxy"]},
    ],
}

# Likelihood × Impact → Risk Score
RISK_MATRIX: dict[str, float] = {
    "very_low": 1.0,
    "low": 2.0,
    "medium": 3.0,
    "high": 4.0,
    "very_high": 5.0,
}


# ============================================================
# Threat Modeler
# ============================================================

class ThreatModeler:
    """
    STRIDE bazlı tehdit modelleme motoru.

    Hedef bilgilerini alıp servis türü, teknoloji stack ve
    attack surface bilgilerinden kapsamlı bir tehdit modeli oluşturur.

    Usage:
        modeler = ThreatModeler()
        report = modeler.model_threats(
            target="https://example.com",
            services=["web_application", "api_rest", "authentication"],
            technologies=["php", "mysql", "nginx"],
        )
    """

    def __init__(self) -> None:
        self._threats: list[Threat] = []
        self._threat_counter = 0

    def model_threats(
        self,
        target: str,
        services: list[str] | None = None,
        technologies: list[str] | None = None,
        open_ports: list[int] | None = None,
        custom_context: dict[str, Any] | None = None,
    ) -> ThreatModelReport:
        """
        Tam tehdit modeli oluştur.

        Args:
            target: Hedef tanımlayıcı
            services: Tespit edilen servis türleri
            technologies: Tespit edilen teknolojiler
            open_ports: Açık portlar
            custom_context: Ek bağlam bilgileri
        """
        self._threats.clear()
        self._threat_counter = 0

        svc_list = services or ["web_application"]
        tech_list = technologies or []
        ports = open_ports or []
        ctx = custom_context or {}

        # 1. Servis bazlı tehditler
        for svc in svc_list:
            templates = THREAT_TEMPLATES.get(svc, [])
            for tmpl in templates:
                threat = self._create_threat(target, svc, tmpl, tech_list, ctx)
                self._threats.append(threat)

        # 2. Port bazlı ek tehditler
        if ports:
            self._add_port_threats(target, ports)

        # 3. Teknoloji bazlı ek tehditler
        self._add_tech_threats(target, tech_list)

        # Risk'e göre sırala
        self._threats.sort(key=lambda t: t.risk_score, reverse=True)

        # Kategori dağılımı
        risk_summary: dict[str, int] = {}
        for t in self._threats:
            cat_name = STRIDE_CATEGORIES.get(t.category, {}).get("name", t.category)
            risk_summary[cat_name] = risk_summary.get(cat_name, 0) + 1

        high_risk = [t for t in self._threats if t.risk_score >= 12.0]

        report = ThreatModelReport(
            target=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_threats=len(self._threats),
            threats=self._threats,
            risk_summary=risk_summary,
            high_risk_threats=high_risk,
        )

        logger.info(
            f"Threat model generated | target={target} | "
            f"threats={report.total_threats} | high_risk={len(high_risk)}"
        )

        return report

    def _create_threat(
        self,
        target: str,
        service: str,
        template: dict[str, Any],
        technologies: list[str],
        context: dict[str, Any],
    ) -> Threat:
        """Şablondan tehdit oluştur."""
        self._threat_counter += 1

        # Likelihood/Impact tahmini
        likelihood = self._estimate_likelihood(template, technologies, context)
        impact = self._estimate_impact(template, context)
        risk_score = RISK_MATRIX[likelihood] * RISK_MATRIX[impact]

        return Threat(
            id=f"THREAT-{self._threat_counter:03d}",
            name=template["name"],
            category=template["cat"],
            description=f"{STRIDE_CATEGORIES[template['cat']]['name']}: {template['name']}",
            target=target,
            attack_method=template["method"],
            likelihood=likelihood,
            impact=impact,
            risk_score=risk_score,
            mitigations=self._suggest_mitigations(template["cat"], template["name"]),
            tools_to_test=template.get("tools", []),
        )

    def _estimate_likelihood(
        self,
        template: dict[str, Any],
        technologies: list[str],
        context: dict[str, Any],
    ) -> str:
        """Tehdit olasılığını tahmin et."""
        name = template["name"].lower()
        tech_str = " ".join(t.lower() for t in technologies)

        # Yüksek olasılık artıranlar
        if "brute force" in name and not context.get("rate_limiting"):
            return "high"
        if "sql injection" in name and any(t in tech_str for t in ["php", "asp", "legacy"]):
            return "high"
        if "xss" in name and "php" in tech_str:
            return "high"
        if "jwt" in name and "jwt" in tech_str:
            return "high"
        if "smb" in name or "snmp" in name:
            return "high"

        # WAF azaltır
        if context.get("waf_detected"):
            return "low"

        return "medium"

    def _estimate_impact(
        self, template: dict[str, Any], context: dict[str, Any]
    ) -> str:
        """Etki seviyesini tahmin et."""
        cat = template["cat"]
        name = template["name"].lower()

        # RCE → very_high
        if "rce" in name or "command" in name or "deserialization" in name:
            return "very_high"

        # Data exfiltration → high
        if "exfiltration" in name or "sql injection" in name:
            return "high"

        # Elevation of Privilege → high
        if cat == "E":
            return "high"

        # Information Disclosure → medium
        if cat == "I":
            return "medium"

        # DoS → medium (bug bounty context)
        if cat == "D":
            return "low"

        # Repudiation → low
        if cat == "R":
            return "low"

        return "medium"

    def _suggest_mitigations(self, category: str, name: str) -> list[str]:
        """Tehdit için mitigasyon önerileri."""
        mitigations: dict[str, list[str]] = {
            "S": [
                "Implement strong authentication (MFA)",
                "Use secure session management",
                "Implement account lockout policies",
            ],
            "T": [
                "Use input validation and parameterized queries",
                "Implement integrity checks (HMAC, digital signatures)",
                "Use HTTPS for all communications",
            ],
            "R": [
                "Implement comprehensive audit logging",
                "Use tamper-proof log storage",
                "Include timestamps and user identifiers in logs",
            ],
            "I": [
                "Implement proper access controls",
                "Encrypt sensitive data at rest and in transit",
                "Apply the principle of least privilege",
            ],
            "D": [
                "Implement rate limiting",
                "Use CDN/WAF for DDoS protection",
                "Design for graceful degradation",
            ],
            "E": [
                "Implement proper authorization checks",
                "Use role-based access control (RBAC)",
                "Validate authorization on every request",
            ],
        }
        return mitigations.get(category, ["Implement defense-in-depth measures"])

    def _add_port_threats(self, target: str, ports: list[int]) -> None:
        """Port bazlı ek tehditler."""
        risky_ports: dict[int, dict[str, str]] = {
            21: {"name": "FTP Anonymous Access", "cat": "I",
                 "method": "Attempt anonymous FTP login and file enumeration"},
            23: {"name": "Telnet Cleartext Protocol", "cat": "I",
                 "method": "Credentials transmitted in cleartext"},
            3389: {"name": "RDP Brute Force", "cat": "S",
                   "method": "Remote Desktop Protocol credential guessing"},
            5900: {"name": "VNC Unauthenticated Access", "cat": "E",
                   "method": "VNC without password or weak password"},
            6379: {"name": "Redis Unauthorized Access", "cat": "E",
                   "method": "Redis without authentication — command execution"},
            9200: {"name": "Elasticsearch Data Exposure", "cat": "I",
                   "method": "Unsecured Elasticsearch — data access"},
            27017: {"name": "MongoDB No Auth", "cat": "I",
                    "method": "MongoDB without authentication — full database access"},
        }

        for port in ports:
            if port in risky_ports:
                info = risky_ports[port]
                self._threat_counter += 1
                self._threats.append(Threat(
                    id=f"THREAT-{self._threat_counter:03d}",
                    name=info["name"],
                    category=info["cat"],
                    description=f"Port {port}: {info['name']}",
                    target=f"{target}:{port}",
                    attack_method=info["method"],
                    likelihood="high",
                    impact="high",
                    risk_score=RISK_MATRIX["high"] * RISK_MATRIX["high"],
                ))

    def _add_tech_threats(self, target: str, technologies: list[str]) -> None:
        """Teknoloji spesifik ek tehditler."""
        tech_str = " ".join(t.lower() for t in technologies)

        tech_threats = [
            ("wordpress", "WordPress Plugin Vulnerabilities", "E",
             "Exploit known vulnerabilities in WordPress plugins and themes",
             ["wpscan", "nuclei"]),
            ("phpmyadmin", "phpMyAdmin Default Credentials", "E",
             "Access phpMyAdmin with default or weak credentials",
             ["hydra", "nuclei"]),
            ("jenkins", "Jenkins Script Console RCE", "E",
             "Execute Groovy scripts via unauthenticated Jenkins console",
             ["nuclei", "manual"]),
            ("tomcat", "Tomcat Manager Default Credentials", "E",
             "Deploy malicious WAR file via Tomcat Manager with default credentials",
             ["nuclei", "hydra"]),
        ]

        for keyword, name, cat, method, tools in tech_threats:
            if keyword in tech_str:
                self._threat_counter += 1
                self._threats.append(Threat(
                    id=f"THREAT-{self._threat_counter:03d}",
                    name=name,
                    category=cat,
                    description=f"Technology-specific: {name}",
                    target=target,
                    attack_method=method,
                    likelihood="high",
                    impact="high",
                    risk_score=RISK_MATRIX["high"] * RISK_MATRIX["high"],
                    tools_to_test=tools,
                ))

    def to_markdown(self) -> str:
        """Tehdit modelini markdown string olarak döndür."""
        if not self._threats:
            return "# Threat Model\n\nNo threats modeled yet.\n"

        lines = ["# STRIDE Threat Model\n"]

        # Özet
        lines.append("## Summary\n")
        for cat_code, cat_info in STRIDE_CATEGORIES.items():
            count = sum(1 for t in self._threats if t.category == cat_code)
            if count:
                lines.append(f"- **{cat_info['name']}** ({cat_code}): {count} threats")

        # Yüksek riskli tehditler
        high = [t for t in self._threats if t.risk_score >= 12]
        if high:
            lines.append("\n## High-Risk Threats\n")
            lines.append("| ID | Threat | Category | Risk | Method |")
            lines.append("|----|--------|----------|------|--------|")
            for t in high:
                cat_name = STRIDE_CATEGORIES.get(t.category, {}).get("name", t.category)
                lines.append(f"| {t.id} | {t.name} | {cat_name} | {t.risk_score:.0f} | {t.attack_method[:60]} |")

        # Tüm tehditler
        lines.append("\n## All Threats\n")
        for t in self._threats:
            cat_name = STRIDE_CATEGORIES.get(t.category, {}).get("name", t.category)
            lines.append(f"### {t.id}: {t.name}")
            lines.append(f"- **Category**: {cat_name} ({t.category})")
            lines.append(f"- **Likelihood**: {t.likelihood}")
            lines.append(f"- **Impact**: {t.impact}")
            lines.append(f"- **Risk Score**: {t.risk_score:.0f}/25")
            lines.append(f"- **Method**: {t.attack_method}")
            if t.tools_to_test:
                lines.append(f"- **Tools**: {', '.join(t.tools_to_test)}")
            if t.mitigations:
                lines.append("- **Mitigations**:")
                for m in t.mitigations:
                    lines.append(f"  - {m}")
            lines.append("")

        return "\n".join(lines)


class ImpactAssessor:
    """
    İş etkisi değerlendiricisi.

    Zafiyet bulgularının iş etkisini; veri hassasiyeti,
    kullanıcı sayısı, yasal yükümlülükler ve marka etkisi
    perspektiflerinden analiz eder.
    """

    # Impact dimension weights
    DIMENSION_WEIGHTS = {
        "data_sensitivity": 0.30,
        "user_reach": 0.25,
        "financial": 0.20,
        "compliance": 0.15,
        "reputation": 0.10,
    }

    def assess(
        self,
        vuln_type: str,
        cvss_score: float,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        İş etkisi raporu üret.

        Returns:
            {
                "overall_impact": "critical|high|medium|low",
                "impact_score": float (0-100),
                "dimensions": {dimension: score},
                "narrative": str,
            }
        """
        ctx = context or {}

        dimensions = {
            "data_sensitivity": self._score_data_sensitivity(vuln_type, ctx),
            "user_reach": self._score_user_reach(vuln_type, ctx),
            "financial": self._score_financial(vuln_type, cvss_score, ctx),
            "compliance": self._score_compliance(vuln_type, ctx),
            "reputation": self._score_reputation(vuln_type, cvss_score),
        }

        # Ağırlıklı toplam
        total = sum(
            dimensions[dim] * weight
            for dim, weight in self.DIMENSION_WEIGHTS.items()
        )

        # Sınıflandırma
        if total >= 80:
            overall = "critical"
        elif total >= 60:
            overall = "high"
        elif total >= 35:
            overall = "medium"
        else:
            overall = "low"

        return {
            "overall_impact": overall,
            "impact_score": round(total, 1),
            "dimensions": dimensions,
            "narrative": self._generate_narrative(vuln_type, overall, dimensions),
        }

    @staticmethod
    def _score_data_sensitivity(vuln_type: str, ctx: dict) -> float:
        """Veri hassasiyeti skoru (0-100)."""
        high_data_vulns = {
            "sql_injection": 90, "command_injection": 80,
            "ssrf": 70, "local_file_inclusion": 75,
            "idor": 65, "xxe": 70, "deserialization": 85,
            "authentication_bypass": 80,
        }
        medium_data_vulns = {
            "xss_stored": 50, "xss_reflected": 30,
            "cors_misconfiguration": 40, "ssti": 80,
        }

        score = high_data_vulns.get(vuln_type, medium_data_vulns.get(vuln_type, 20))

        if ctx.get("pii_involved"):
            score = min(100, score + 15)
        if ctx.get("financial_data"):
            score = min(100, score + 20)

        return float(score)

    @staticmethod
    def _score_user_reach(vuln_type: str, ctx: dict) -> float:
        """Etkilenen kullanıcı kapsamı skoru (0-100)."""
        # Stored XSS tüm kullanıcıları etkiler
        if vuln_type == "xss_stored":
            return 90.0
        # Auth bypass / IDOR — potansiyel olarak tüm kullanıcılar
        if vuln_type in ("authentication_bypass", "idor"):
            return 75.0
        # Reflected XSS — hedefli
        if vuln_type in ("xss_reflected", "xss_dom"):
            return 30.0
        # Server-side — dolaylı
        if vuln_type in ("sql_injection", "command_injection", "ssti"):
            return 60.0

        return 40.0

    @staticmethod
    def _score_financial(vuln_type: str, cvss: float, ctx: dict) -> float:
        """Finansal etki skoru (0-100)."""
        # CVSS ile korelasyon
        base = cvss * 10

        if ctx.get("ecommerce"):
            base = min(100, base + 20)
        if ctx.get("payment_processing"):
            base = min(100, base + 30)

        return float(min(100, base))

    @staticmethod
    def _score_compliance(vuln_type: str, ctx: dict) -> float:
        """Uyumluluk etkisi skoru (0-100)."""
        if ctx.get("gdpr"):
            if vuln_type in ("sql_injection", "idor", "authentication_bypass"):
                return 90.0
            return 50.0
        if ctx.get("pci_dss"):
            if vuln_type in ("sql_injection", "xss_stored", "command_injection"):
                return 85.0
            return 40.0
        return 20.0

    @staticmethod
    def _score_reputation(vuln_type: str, cvss: float) -> float:
        """Marka/itibar etkisi skoru (0-100)."""
        if cvss >= 9.0:
            return 90.0
        if cvss >= 7.0:
            return 60.0
        if cvss >= 4.0:
            return 35.0
        return 15.0

    @staticmethod
    def _generate_narrative(
        vuln_type: str, overall: str, dimensions: dict[str, float]
    ) -> str:
        """İnsan okunabilir etki açıklaması."""
        highest_dim = max(dimensions, key=dimensions.get)  # type: ignore

        dim_descriptions = {
            "data_sensitivity": "sensitive data exposure",
            "user_reach": "broad user impact",
            "financial": "financial risk",
            "compliance": "regulatory compliance implications",
            "reputation": "brand reputation damage",
        }

        primary_concern = dim_descriptions.get(highest_dim, "security risk")

        return (
            f"This {vuln_type.replace('_', ' ')} vulnerability has an overall "
            f"{overall.upper()} business impact, primarily due to {primary_concern} "
            f"(score: {dimensions[highest_dim]:.0f}/100). "
            f"Immediate remediation is {'strongly recommended' if overall in ('critical', 'high') else 'recommended'}."
        )


__all__ = [
    "ThreatModeler",
    "ThreatModelReport",
    "Threat",
    "ImpactAssessor",
    "STRIDE_CATEGORIES",
]
