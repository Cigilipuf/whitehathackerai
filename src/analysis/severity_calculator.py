"""
WhiteHatHacker AI — CVSS v3.1 Severity Calculator

Zafiyet bulgularının CVSS v3.1 skorunu hesaplar.
Hem metrik bazlı hesaplama hem de zafiyet türü+bağlam
tabanlı akıllı tahmin destekler.
"""

from __future__ import annotations

import math
from typing import Any

from loguru import logger
from pydantic import BaseModel


# ============================================================
# CVSS v3.1 Metrik Tanımları
# ============================================================

class CVSSMetrics(BaseModel):
    """CVSS v3.1 Temel Metrikler."""

    # Attack Vector (AV)
    attack_vector: str = "N"      # N=Network, A=Adjacent, L=Local, P=Physical
    # Attack Complexity (AC)
    attack_complexity: str = "L"  # L=Low, H=High
    # Privileges Required (PR)
    privileges_required: str = "N"  # N=None, L=Low, H=High
    # User Interaction (UI)
    user_interaction: str = "N"   # N=None, R=Required
    # Scope (S)
    scope: str = "U"             # U=Unchanged, C=Changed
    # Confidentiality (C)
    confidentiality: str = "N"   # N=None, L=Low, H=High
    # Integrity (I)
    integrity: str = "N"         # N=None, L=Low, H=High
    # Availability (A)
    availability: str = "N"      # N=None, L=Low, H=High


class CVSSResult(BaseModel):
    """CVSS Hesaplama Sonucu."""

    score: float = 0.0
    severity: str = "none"       # none, low, medium, high, critical
    vector: str = ""
    metrics: CVSSMetrics = CVSSMetrics()


# ============================================================
# CVSS v3.1 Metrik Değerleri
# ============================================================

METRIC_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},  # Scope Unchanged
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},  # Scope Changed
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.00, "L": 0.22, "H": 0.56},
    "I": {"N": 0.00, "L": 0.22, "H": 0.56},
    "A": {"N": 0.00, "L": 0.22, "H": 0.56},
}


# ============================================================
# Zafiyet türü → CVSS metrik mapping (akıllı tahmin)
# ============================================================

VULN_TYPE_DEFAULTS: dict[str, dict[str, str]] = {
    "sql_injection": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "H", "A": "N",
    },
    "sql_injection_blind": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "N", "A": "N",
    },
    "command_injection": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "H", "A": "H",
    },
    "xss_reflected": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
        "C": "L", "I": "L", "A": "N",
    },
    "xss_stored": {
        "AV": "N", "AC": "L", "PR": "L", "UI": "R", "S": "C",
        "C": "L", "I": "L", "A": "N",
    },
    "xss_dom": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
        "C": "L", "I": "L", "A": "N",
    },
    "ssrf": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "N", "A": "N",
    },
    "ssrf_internal": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
        "C": "H", "I": "L", "A": "N",
    },
    "ssti": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "H", "A": "H",
    },
    "idor": {
        "AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U",
        "C": "H", "I": "N", "A": "N",
    },
    "idor_write": {
        "AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U",
        "C": "N", "I": "H", "A": "N",
    },
    "authentication_bypass": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "H", "A": "N",
    },
    "cors_misconfiguration": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U",
        "C": "H", "I": "N", "A": "N",
    },
    "open_redirect": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
        "C": "N", "I": "L", "A": "N",
    },
    "local_file_inclusion": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "N", "A": "N",
    },
    "remote_file_inclusion": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "H", "A": "H",
    },
    "ssl_tls_misconfiguration": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "N", "A": "N",
    },
    "information_disclosure": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "L", "I": "N", "A": "N",
    },
    "race_condition": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U",
        "C": "N", "I": "H", "A": "N",
    },
    "business_logic": {
        "AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U",
        "C": "N", "I": "H", "A": "N",
    },
    "rate_limit_bypass": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "N", "I": "L", "A": "N",
    },
    "xxe": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "N", "A": "N",
    },
    "deserialization": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "H", "A": "H",
    },
    "crlf_injection": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
        "C": "N", "I": "L", "A": "N",
    },
    "subdomain_takeover": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
        "C": "L", "I": "L", "A": "N",
    },
}


# ============================================================
# Calculator
# ============================================================

class SeverityCalculator:
    """
    CVSS v3.1 skor hesaplayıcı.

    İki mod destekler:
    1. Metrik bazlı: CVSSMetrics ile tam kontrol
    2. Akıllı tahmin: vuln_type + context ile otomatik

    Usage:
        calc = SeverityCalculator()

        # Mod 1: Manuel metrikler
        result = calc.calculate(CVSSMetrics(
            attack_vector="N", attack_complexity="L",
            confidentiality="H", integrity="H", availability="H",
        ))

        # Mod 2: Otomatik tahmin
        result = calc.estimate("sql_injection", context={
            "authenticated": False,
            "data_extracted": True,
        })
    """

    def calculate(self, metrics: CVSSMetrics) -> CVSSResult:
        """
        CVSS v3.1 skorunu metriklerden hesapla.

        Formül: NIST SP 800-126r3 standardına uygun.
        """
        # Validate metric values before lookup
        _valid = {
            "AV": set(METRIC_VALUES["AV"].keys()),
            "AC": set(METRIC_VALUES["AC"].keys()),
            "PR": set(METRIC_VALUES["PR"].get("U", {}).keys()),
            "UI": set(METRIC_VALUES["UI"].keys()),
            "S": set(METRIC_VALUES["PR"].keys()),
            "C": set(METRIC_VALUES["C"].keys()),
            "I": set(METRIC_VALUES["I"].keys()),
            "A": set(METRIC_VALUES["A"].keys()),
        }
        errors = []
        if metrics.attack_vector not in _valid["AV"]:
            errors.append(f"Invalid AV: {metrics.attack_vector}")
        if metrics.attack_complexity not in _valid["AC"]:
            errors.append(f"Invalid AC: {metrics.attack_complexity}")
        if metrics.scope not in _valid["S"]:
            errors.append(f"Invalid S: {metrics.scope}")
        if metrics.privileges_required not in _valid["PR"]:
            errors.append(f"Invalid PR: {metrics.privileges_required}")
        if metrics.user_interaction not in _valid["UI"]:
            errors.append(f"Invalid UI: {metrics.user_interaction}")
        if metrics.confidentiality not in _valid["C"]:
            errors.append(f"Invalid C: {metrics.confidentiality}")
        if metrics.integrity not in _valid["I"]:
            errors.append(f"Invalid I: {metrics.integrity}")
        if metrics.availability not in _valid["A"]:
            errors.append(f"Invalid A: {metrics.availability}")
        if errors:
            raise ValueError(f"Invalid CVSS metrics: {'; '.join(errors)}")

        # Metrik değerlerini al
        av = METRIC_VALUES["AV"][metrics.attack_vector]
        ac = METRIC_VALUES["AC"][metrics.attack_complexity]
        pr = METRIC_VALUES["PR"][metrics.scope][metrics.privileges_required]
        ui = METRIC_VALUES["UI"][metrics.user_interaction]

        c = METRIC_VALUES["C"][metrics.confidentiality]
        i = METRIC_VALUES["I"][metrics.integrity]
        a = METRIC_VALUES["A"][metrics.availability]

        # Impact Sub-Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Impact
        if metrics.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Base Score
        if impact <= 0:
            score = 0.0
        elif metrics.scope == "U":
            score = min(impact + exploitability, 10.0)
            score = math.ceil(score * 10) / 10
        else:
            score = min(1.08 * (impact + exploitability), 10.0)
            score = math.ceil(score * 10) / 10

        # Severity rating
        severity = self._score_to_severity(score)

        # Vector string
        vector = (
            f"CVSS:3.1/AV:{metrics.attack_vector}/AC:{metrics.attack_complexity}/"
            f"PR:{metrics.privileges_required}/UI:{metrics.user_interaction}/"
            f"S:{metrics.scope}/C:{metrics.confidentiality}/"
            f"I:{metrics.integrity}/A:{metrics.availability}"
        )

        return CVSSResult(
            score=score,
            severity=severity,
            vector=vector,
            metrics=metrics,
        )

    def estimate(
        self,
        vuln_type: str,
        context: dict[str, Any] | None = None,
    ) -> CVSSResult:
        """
        Zafiyet türü ve bağlam bilgisinden CVSS skoru tahmin et.

        Context parametreleri:
        - authenticated: bool — giriş gerekli mi
        - user_interaction: bool — kullanıcı etkileşimi gerekli mi
        - data_extracted: bool — veri çekilebilir mi
        - rce_possible: bool — uzaktan kod çalıştırma mümkün mü
        - scope_changed: bool — etki scope dışına taşıyor mu
        - internal_access: bool — iç ağ erişimi mümkün mü

        Returns:
            CVSSResult
        """
        ctx = context or {}

        # Varsayılan metrikleri al
        defaults = VULN_TYPE_DEFAULTS.get(vuln_type, {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
            "C": "L", "I": "N", "A": "N",
        })

        # Bağlam bazlı ayarlama
        metrics = CVSSMetrics(
            attack_vector=defaults["AV"],
            attack_complexity=defaults["AC"],
            privileges_required=defaults["PR"],
            user_interaction=defaults["UI"],
            scope=defaults["S"],
            confidentiality=defaults["C"],
            integrity=defaults["I"],
            availability=defaults["A"],
        )

        # Context overrides
        if ctx.get("authenticated"):
            metrics.privileges_required = "L"

        if ctx.get("user_interaction"):
            metrics.user_interaction = "R"

        if ctx.get("rce_possible"):
            metrics.confidentiality = "H"
            metrics.integrity = "H"
            metrics.availability = "H"

        if ctx.get("data_extracted"):
            metrics.confidentiality = "H"

        if ctx.get("scope_changed"):
            metrics.scope = "C"

        if ctx.get("internal_access"):
            if metrics.confidentiality != "H":
                metrics.confidentiality = "H"

        if ctx.get("local_only"):
            metrics.attack_vector = "L"

        result = self.calculate(metrics)

        logger.debug(
            f"CVSS estimated | type={vuln_type} | "
            f"score={result.score} | severity={result.severity} | "
            f"vector={result.vector}"
        )

        return result

    def parse_vector(self, vector_string: str) -> CVSSResult:
        """
        CVSS vector string'den hesapla.

        Örnek: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        """
        parts = vector_string.replace("CVSS:3.1/", "").split("/")

        metric_map = {}
        for part in parts:
            if ":" in part:
                key, val = part.split(":", 1)
                metric_map[key] = val

        metrics = CVSSMetrics(
            attack_vector=metric_map.get("AV", "N"),
            attack_complexity=metric_map.get("AC", "L"),
            privileges_required=metric_map.get("PR", "N"),
            user_interaction=metric_map.get("UI", "N"),
            scope=metric_map.get("S", "U"),
            confidentiality=metric_map.get("C", "N"),
            integrity=metric_map.get("I", "N"),
            availability=metric_map.get("A", "N"),
        )

        return self.calculate(metrics)

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """CVSS skoru → severity string."""
        if score == 0.0:
            return "none"
        elif score <= 3.9:
            return "low"
        elif score <= 6.9:
            return "medium"
        elif score <= 8.9:
            return "high"
        else:
            return "critical"


__all__ = [
    "SeverityCalculator",
    "CVSSMetrics",
    "CVSSResult",
    "VULN_TYPE_DEFAULTS",
]
