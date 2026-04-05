"""
WhiteHatHacker AI — Multi-Tool Cross-Verification

Çoklu araç doğrulama stratejisi. Aynı zafiyeti farklı araçlarla
tekrar test ederek false positive oranını düşürür.

Strateji: Bulgu türüne göre en uygun doğrulama araçlarını seç,
çalıştır ve sonuçları karşılaştır.
"""

from __future__ import annotations

import asyncio
from typing import Any

from loguru import logger
from pydantic import BaseModel

from src.tools.base import Finding, ToolResult


# ============================================================
# Doğrulama Sonucu
# ============================================================

class VerificationResult(BaseModel):
    """Tek bir doğrulama denemesinin sonucu."""

    tool_name: str
    confirmed: bool              # Araç da aynı bulguyu tespit etti mi?
    confidence_delta: float      # Güven skoru değişimi
    details: str = ""
    raw_output: str = ""
    error: str = ""


class CrossVerificationResult(BaseModel):
    """Çoklu araç doğrulama genel sonucu."""

    original_finding: Finding
    verifications: list[VerificationResult] = []
    total_confirmations: int = 0
    total_attempts: int = 0
    final_confidence_delta: float = 0.0
    verdict: str = "inconclusive"  # confirmed | denied | inconclusive

    @property
    def confirmation_ratio(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_confirmations / self.total_attempts


# ============================================================
# Zafiyet-Araç Doğrulama Matrisi
# ============================================================

# Her zafiyet türü için doğrulama araçları ve stratejileri
VERIFICATION_MATRIX: dict[str, list[dict[str, Any]]] = {
    # SQL Injection
    "sql_injection": [
        {
            "tool": "sqlmap",
            "strategy": "time_based_verify",
            "options": {"technique": "T", "level": 3, "risk": 2},
            "weight": 0.4,
        },
        {
            "tool": "commix",
            "strategy": "check_sqli_params",
            "options": {},
            "weight": 0.3,
        },
        {
            "tool": "nikto",
            "strategy": "passive_confirm",
            "options": {},
            "weight": 0.15,
        },
    ],
    # XSS (Reflected)
    "xss_reflected": [
        {
            "tool": "httpx",
            "strategy": "reflection_check",
            "options": {},
            "weight": 0.3,
        },
        {
            "tool": "nikto",
            "strategy": "passive_xss_check",
            "options": {},
            "weight": 0.2,
        },
    ],
    # XSS (Stored)
    "xss_stored": [
        {
            "tool": "nikto",
            "strategy": "passive_check",
            "options": {},
            "weight": 0.2,
        },
    ],
    # Command Injection
    "command_injection": [
        {
            "tool": "commix",
            "strategy": "full_scan",
            "options": {"level": 3},
            "weight": 0.4,
        },
    ],
    # SSRF
    "ssrf": [
        {
            "tool": "httpx",
            "strategy": "oob_callback_check",
            "options": {},
            "weight": 0.35,
        },
    ],
    # IDOR
    "idor": [
        {
            "tool": "idor_checker",
            "strategy": "sequential_id_test",
            "options": {},
            "weight": 0.4,
        },
    ],
    # CORS Misconfiguration
    "cors_misconfiguration": [
        {
            "tool": "nikto",
            "strategy": "cors_header_check",
            "options": {},
            "weight": 0.3,
        },
        {
            "tool": "httpx",
            "strategy": "cors_origin_test",
            "options": {},
            "weight": 0.3,
        },
    ],
    # SSL/TLS
    "ssl_tls_misconfiguration": [
        {
            "tool": "sslscan",
            "strategy": "full_ssl_check",
            "options": {},
            "weight": 0.35,
        },
        {
            "tool": "sslyze",
            "strategy": "cipher_analysis",
            "options": {},
            "weight": 0.35,
        },
    ],
    # Authentication Bypass
    "authentication_bypass": [
        {
            "tool": "auth_bypass_checker",
            "strategy": "full_check",
            "options": {},
            "weight": 0.4,
        },
    ],
    # Open Redirect
    "open_redirect": [
        {
            "tool": "httpx",
            "strategy": "redirect_follow",
            "options": {},
            "weight": 0.3,
        },
    ],
    # Information Disclosure
    "information_disclosure": [
        {
            "tool": "nikto",
            "strategy": "sensitive_file_check",
            "options": {},
            "weight": 0.25,
        },
        {
            "tool": "ffuf",
            "strategy": "verify_file_exists",
            "options": {},
            "weight": 0.25,
        },
    ],
}

# Varsayılan doğrulama stratejisi (matristeki tanımsız türler için)
DEFAULT_VERIFICATION = [
    {
        "tool": "httpx",
        "strategy": "response_verify",
        "options": {},
        "weight": 0.2,
    },
    {
        "tool": "nikto",
        "strategy": "generic_scan",
        "options": {},
        "weight": 0.2,
    },
]


class MultiToolVerifier:
    """
    Çoklu araç doğrulama motoru.

    Bir bulguyu farklı güvenlik araçlarıyla tekrar test ederek
    false positive olasılığını azaltır.

    Kullanım:
        verifier = MultiToolVerifier(tool_executor=executor)
        result = await verifier.verify(finding)

        if result.verdict == "confirmed":
            # Bulgu doğrulandı
    """

    def __init__(
        self,
        tool_executor: Any | None = None,  # ToolExecutor
        registry: Any | None = None,       # ToolRegistry
        max_verification_tools: int = 3,
        timeout_per_tool: float = 120.0,
    ) -> None:
        self.tool_executor = tool_executor
        self.registry = registry
        self.max_verification_tools = max_verification_tools
        self.timeout_per_tool = timeout_per_tool

        logger.info(
            f"MultiToolVerifier initialized | max_tools={max_verification_tools}"
        )

    async def verify(self, finding: Finding) -> CrossVerificationResult:
        """
        Bulguyu çoklu araçlarla doğrula.

        Args:
            finding: Doğrulanacak bulgu

        Returns:
            CrossVerificationResult
        """
        result = CrossVerificationResult(original_finding=finding)

        # Doğrulama araçlarını belirle
        vuln_type = finding.vulnerability_type.lower()
        verification_tools = self._get_verification_tools(vuln_type, finding)

        if not verification_tools:
            logger.warning(
                f"No verification tools available for: {vuln_type}"
            )
            result.verdict = "inconclusive"
            return result

        logger.info(
            f"Cross-verification starting | finding='{finding.title[:50]}' | "
            f"vuln_type={vuln_type} | tools={[v['tool'] for v in verification_tools]}"
        )

        # Her araçla doğrulama yap
        for vspec in verification_tools[:self.max_verification_tools]:
            vr = await self._run_verification(finding, vspec)
            result.verifications.append(vr)
            result.total_attempts += 1
            if vr.confirmed:
                result.total_confirmations += 1
                result.final_confidence_delta += vr.confidence_delta
            else:
                result.final_confidence_delta += vr.confidence_delta

        # Karar ver
        if result.total_attempts == 0:
            result.verdict = "inconclusive"
        elif result.confirmation_ratio >= 0.66:
            result.verdict = "confirmed"
        elif result.confirmation_ratio >= 0.33:
            result.verdict = "inconclusive"
        else:
            result.verdict = "denied"

        logger.info(
            f"Cross-verification complete | "
            f"confirmed={result.total_confirmations}/{result.total_attempts} | "
            f"verdict={result.verdict} | delta={result.final_confidence_delta:+.1f}"
        )

        return result

    def _get_verification_tools(
        self,
        vuln_type: str,
        finding: Finding,
    ) -> list[dict[str, Any]]:
        """
        Zafiyet türüne göre doğrulama araçlarını seç.
        Orijinal bulguyu bulan aracı hariç tut.
        """
        tools = VERIFICATION_MATRIX.get(vuln_type, DEFAULT_VERIFICATION)

        # Orijinal aracı hariç tut (aynı araçla doğrulama yapılmaz)
        filtered = [t for t in tools if t["tool"] != finding.tool_name]

        # Registry'den mevcut olanları filtrele
        if self.registry:
            available = []
            for t in filtered:
                tool_instance = self.registry.get(t["tool"])
                if tool_instance and tool_instance.is_available():
                    available.append(t)
            return available

        return filtered

    async def _run_verification(
        self,
        finding: Finding,
        vspec: dict[str, Any],
    ) -> VerificationResult:
        """Tek bir araçla doğrulama çalıştır."""
        tool_name = vspec["tool"]
        strategy = vspec["strategy"]
        options = vspec.get("options", {})
        weight = vspec.get("weight", 0.2)

        if not self.tool_executor:
            return VerificationResult(
                tool_name=tool_name,
                confirmed=False,
                confidence_delta=0.0,
                error="No tool executor available",
            )

        try:
            # Hedef URL'yi oluştur
            target = self._build_verification_target(finding)

            # Doğrulama opsiyonlarını hazırla
            verify_options = {
                **options,
                "verification_mode": True,
                "strategy": strategy,
                "original_finding": {
                    "title": finding.title,
                    "vuln_type": finding.vulnerability_type,
                    "endpoint": finding.endpoint,
                    "parameter": finding.parameter,
                    "payload": finding.payload,
                },
            }

            # Aracı çalıştır
            result: ToolResult = await asyncio.wait_for(
                self.tool_executor.run_tool(tool_name, target, verify_options),
                timeout=self.timeout_per_tool,
            )

            if not result.success:
                return VerificationResult(
                    tool_name=tool_name,
                    confirmed=False,
                    confidence_delta=-5.0 * weight,
                    error=result.error_message or "Tool execution failed",
                )

            # Sonuçları analiz et — aynı zafiyet bulundu mu?
            confirmed = self._check_confirmation(finding, result)

            if confirmed:
                delta = 15.0 * weight  # Doğrulama başarılı → skor artışı
                details = (
                    f"{tool_name} confirmed the finding with "
                    f"{len(result.findings)} matching results"
                )
            else:
                delta = -8.0 * weight  # Doğrulama başarısız → hafif düşüş
                details = f"{tool_name} did not confirm the finding"

            return VerificationResult(
                tool_name=tool_name,
                confirmed=confirmed,
                confidence_delta=delta,
                details=details,
                raw_output=result.raw_output[:500] if result.raw_output else "",
            )

        except asyncio.TimeoutError:
            logger.warning(f"Verification timeout | tool={tool_name}")
            return VerificationResult(
                tool_name=tool_name,
                confirmed=False,
                confidence_delta=0.0,
                error=f"Timeout after {self.timeout_per_tool}s",
            )
        except Exception as e:
            logger.error(f"Verification error | tool={tool_name} | error={e}")
            return VerificationResult(
                tool_name=tool_name,
                confirmed=False,
                confidence_delta=0.0,
                error=str(e),
            )

    def _build_verification_target(self, finding: Finding) -> str:
        """Bulgudan doğrulama hedef URL'si oluştur."""
        if finding.endpoint:
            return finding.endpoint
        return finding.target

    def _check_confirmation(
        self,
        original: Finding,
        result: ToolResult,
    ) -> bool:
        """
        Doğrulama aracının çıktısında orijinal bulguyu destekleyen
        kanıt var mı kontrol et.
        """
        if not result.findings:
            return False

        original_type = original.vulnerability_type.lower()
        original_endpoint = (original.endpoint or original.target or "").lower()
        original_param = (original.parameter or "").lower()

        for f in result.findings:
            f_type = f.vulnerability_type.lower()
            f_endpoint = (f.endpoint or f.target or "").lower()
            f_param = (f.parameter or "").lower()

            # Aynı zafiyet türü
            type_match = (
                f_type == original_type
                or f_type in original_type
                or original_type in f_type
            )

            # Aynı endpoint
            endpoint_match = (
                f_endpoint == original_endpoint
                or (original_endpoint and original_endpoint in f_endpoint)
                or (f_endpoint and f_endpoint in original_endpoint)
            )

            # Aynı parametre (varsa)
            param_match = (
                not original_param  # Parametre yoksa sadece tür+endpoint yeterli
                or f_param == original_param
                or original_param in f_param
            )

            if type_match and (endpoint_match or param_match):
                return True

        # Raw output'ta vuln type geçiyor mu? (loose match)
        if result.raw_output:
            raw_lower = result.raw_output.lower()
            vuln_keywords = self._get_vuln_keywords(original_type)
            if any(kw in raw_lower for kw in vuln_keywords):
                return True

        return False

    @staticmethod
    def _get_vuln_keywords(vuln_type: str) -> list[str]:
        """Zafiyet türüne ait anahtar kelimeler."""
        KEYWORDS: dict[str, list[str]] = {
            "sql_injection": ["sql injection", "sqli", "sql error", "mysql", "syntax error"],
            "xss_reflected": ["xss", "cross-site scripting", "script injection", "reflected"],
            "xss_stored": ["stored xss", "persistent xss", "cross-site"],
            "command_injection": ["command injection", "os injection", "rce", "remote code"],
            "ssrf": ["ssrf", "server-side request", "internal service"],
            "ssti": ["template injection", "ssti", "server-side template"],
            "idor": ["idor", "insecure direct object", "authorization bypass"],
            "cors_misconfiguration": ["cors", "access-control-allow-origin", "cross-origin"],
            "open_redirect": ["open redirect", "url redirect", "unvalidated redirect"],
            "authentication_bypass": ["auth bypass", "authentication", "unauthorized access"],
            "information_disclosure": ["information disclosure", "sensitive", "exposed", "leak"],
            "ssl_tls_misconfiguration": ["ssl", "tls", "certificate", "cipher"],
        }
        return KEYWORDS.get(vuln_type, [vuln_type.replace("_", " ")])


__all__ = [
    "MultiToolVerifier",
    "CrossVerificationResult",
    "VerificationResult",
    "VERIFICATION_MATRIX",
]
