"""
WhiteHatHacker AI — Payload Confirmation Engine

Bulguya ait payload'ın gerçekten çalışıp çalışmadığını doğrular.
Blind injection'lar için time-based ve OOB doğrulama yapar.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import aiohttp
from loguru import logger
from pydantic import BaseModel

from src.utils.constants import DEFAULT_USER_AGENT


class PayloadConfirmResult(BaseModel):
    """Payload doğrulama sonucu."""

    confirmed: bool = False
    confidence_delta: float = 0.0
    method: str = ""                # direct | time_based | error_based | oob | manual
    details: str = ""
    response_status: int = 0
    response_body_excerpt: str = ""
    response_time: float = 0.0
    error: str = ""


class PayloadConfirmer:
    """
    Payload doğrulama motoru.

    Bir zafiyetin gerçek olduğunu kanıtlamak için payload'ı
    farklı yöntemlerle tekrar test eder.

    Doğrulama Stratejileri:
    1. Direct reflection: Payload'ı gönder, response'da ara
    2. Time-based: Zaman gecikmesi ile doğrula (SQLi, CMDi)
    3. Error-based: Hata mesajı ile doğrula
    4. Payload variation: Farklı payload varyasyonları ile test

    Kullanım:
        confirmer = PayloadConfirmer()
        result = await confirmer.confirm(finding)
    """

    # Time-based doğrulama payload'ları
    TIME_BASED_PAYLOADS: dict[str, list[dict[str, Any]]] = {
        "sql_injection": [
            {"payload": "' OR SLEEP(5)-- -", "expected_delay": 5.0},
            {"payload": "'; WAITFOR DELAY '0:0:5'-- -", "expected_delay": 5.0},
            {"payload": "' OR pg_sleep(5)-- -", "expected_delay": 5.0},
            {"payload": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -", "expected_delay": 5.0},
        ],
        "command_injection": [
            {"payload": "; sleep 5", "expected_delay": 5.0},
            {"payload": "| sleep 5", "expected_delay": 5.0},
            {"payload": "`sleep 5`", "expected_delay": 5.0},
            {"payload": "$(sleep 5)", "expected_delay": 5.0},
        ],
        "ssti": [
            {"payload": "{{7*7}}", "expected_output": "49"},
            {"payload": "${7*7}", "expected_output": "49"},
            {"payload": "#{7*7}", "expected_output": "49"},
            {"payload": "<%= 7*7 %>", "expected_output": "49"},
        ],
    }

    # XSS doğrulama payload varyasyonları
    XSS_VERIFY_PAYLOADS = [
        '<img src=x onerror=alert(1)>',
        '"><svg/onload=alert(1)>',
        "'-alert(1)-'",
        '<details/open/ontoggle=alert(1)>',
        'javascript:alert(1)//',
    ]

    # Error-based doğrulama pattern'leri
    ERROR_PATTERNS: dict[str, list[str]] = {
        "sql_injection": [
            r"you have an error in your sql syntax",
            r"unclosed quotation mark",
            r"syntax error at or near",
            r"warning:\s+mysql",
            r"pg_query\(\).*failed",
            r"ORA-\d{5}",
            r"Microsoft SQL Native Client error",
            r"SQLite3::SQLException",
        ],
        "command_injection": [
            r"uid=\d+\(\w+\)",
            r"root:x:0:0",
            r"\/bin\/(?:ba)?sh",
            r"Permission denied",
        ],
        "local_file_inclusion": [
            r"root:x:0:0",
            r"\[boot loader\]",
            r"\\WINDOWS\\",
            r"No such file or directory",
        ],
    }

    def __init__(
        self,
        timeout: float = 15.0,
        max_retries: int = 2,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_ssl: bool = False,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl

    async def confirm(
        self,
        finding: Any,  # Finding object
        strategy: str = "auto",
    ) -> PayloadConfirmResult:
        """
        Bulgunun payload'ını doğrula.

        Args:
            finding: Doğrulanacak bulgu (Finding objesi)
            strategy: auto | direct | time_based | error_based | variation

        Returns:
            PayloadConfirmResult
        """
        vuln_type = finding.vulnerability_type.lower()

        if strategy == "auto":
            strategy = self._select_strategy(vuln_type, finding)

        logger.info(
            f"Payload confirmation | strategy={strategy} | "
            f"vuln={vuln_type} | target={finding.endpoint or finding.target}"
        )

        try:
            if strategy == "direct":
                return await self._direct_confirm(finding)
            elif strategy == "time_based":
                return await self._time_based_confirm(finding, vuln_type)
            elif strategy == "error_based":
                return await self._error_based_confirm(finding, vuln_type)
            elif strategy == "variation":
                return await self._variation_confirm(finding, vuln_type)
            else:
                return PayloadConfirmResult(
                    confirmed=False,
                    method="unknown",
                    error=f"Unknown strategy: {strategy}",
                )
        except Exception as e:
            logger.error(f"Payload confirmation failed: {e}")
            return PayloadConfirmResult(
                confirmed=False,
                method=strategy,
                error=str(e),
            )

    def _select_strategy(self, vuln_type: str, finding: Any) -> str:
        """Zafiyet türüne göre en uygun doğrulama stratejisini seç."""
        if vuln_type in ("sql_injection", "command_injection"):
            return "time_based"
        elif vuln_type in ("xss_reflected", "xss_stored", "xss_dom"):
            return "direct"
        elif vuln_type in ("ssti", "local_file_inclusion"):
            return "error_based"
        elif vuln_type in ("ssrf",):
            return "direct"
        else:
            return "direct"

    async def _direct_confirm(self, finding: Any) -> PayloadConfirmResult:
        """Direct reflection doğrulama — payload'ı gönder ve response'da ara."""
        if not finding.payload or not (finding.endpoint or finding.target):
            return PayloadConfirmResult(
                confirmed=False,
                method="direct",
                error="No payload or target URL",
            )

        target = finding.endpoint or finding.target

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"User-Agent": self.user_agent}

                start = time.monotonic()
                async with session.get(
                    target,
                    headers=headers,
                    ssl=self.verify_ssl,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    elapsed = time.monotonic() - start
                    body = await resp.text()

                    # Payload body'de var mı?
                    reflected = finding.payload in body

                    # Encoded versiyonlar kontrolü
                    encoded = False
                    if not reflected:
                        encoded_variants = [
                            finding.payload.replace("<", "&lt;").replace(">", "&gt;"),
                            finding.payload.replace("<", "%3C").replace(">", "%3E"),
                        ]
                        encoded = any(ev in body for ev in encoded_variants)

                    confirmed = reflected and not encoded

                    return PayloadConfirmResult(
                        confirmed=confirmed,
                        confidence_delta=15.0 if confirmed else (-5.0 if encoded else -8.0),
                        method="direct",
                        details=(
                            "Payload reflected unencoded"
                            if confirmed
                            else ("Payload reflected but encoded" if encoded else "Payload not reflected")
                        ),
                        response_status=resp.status,
                        response_body_excerpt=body[:500],
                        response_time=elapsed,
                    )
        except Exception as e:
            return PayloadConfirmResult(
                confirmed=False,
                method="direct",
                error=str(e),
            )

    async def _time_based_confirm(
        self,
        finding: Any,
        vuln_type: str,
    ) -> PayloadConfirmResult:
        """
        Time-based doğrulama.

        Önce normal istek gönderilir (baseline), sonra
        time-delay payload'ı gönderilir. Gecikme farkı
        beklenen_gecikme * 0.8'den büyükse doğrulanmış sayılır.
        """
        payloads = self.TIME_BASED_PAYLOADS.get(vuln_type, [])
        if not payloads:
            return PayloadConfirmResult(
                confirmed=False,
                method="time_based",
                error=f"No time-based payloads for {vuln_type}",
            )

        target = finding.endpoint or finding.target
        if not target:
            return PayloadConfirmResult(
                confirmed=False,
                method="time_based",
                error="No target URL",
            )

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"User-Agent": self.user_agent}

                # Baseline: normal istek süresi
                start = time.monotonic()
                async with session.get(
                    target,
                    headers=headers,
                    ssl=self.verify_ssl,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    baseline_time = time.monotonic() - start
                    await resp.text()

                # Her payload'ı dene
                for p_spec in payloads[:2]:  # Max 2 tane dene
                    payload = p_spec["payload"]
                    expected_delay = p_spec.get("expected_delay", 5.0)

                    # Payload'ı parametreye ekle
                    param = finding.parameter or "id"
                    test_url = self._inject_payload(target, param, payload)

                    start = time.monotonic()
                    try:
                        async with session.get(
                            test_url,
                            headers=headers,
                            ssl=self.verify_ssl,
                            timeout=aiohttp.ClientTimeout(total=expected_delay + 10),
                        ) as resp:
                            elapsed = time.monotonic() - start
                            await resp.text()

                        actual_delay = elapsed - baseline_time

                        if actual_delay >= expected_delay * 0.8:
                            return PayloadConfirmResult(
                                confirmed=True,
                                confidence_delta=20.0,
                                method="time_based",
                                details=(
                                    f"Time-based confirmed: baseline={baseline_time:.2f}s, "
                                    f"payload={elapsed:.2f}s, delay={actual_delay:.2f}s "
                                    f"(expected={expected_delay}s)"
                                ),
                                response_status=resp.status,
                                response_time=elapsed,
                            )
                    except asyncio.TimeoutError:
                        # Timeout bile delayın çalıştığını gösterebilir
                        elapsed = time.monotonic() - start
                        if elapsed >= expected_delay * 0.8:
                            return PayloadConfirmResult(
                                confirmed=True,
                                confidence_delta=15.0,
                                method="time_based",
                                details=f"Request timed out after {elapsed:.2f}s (likely delay executed)",
                                response_time=elapsed,
                            )

                return PayloadConfirmResult(
                    confirmed=False,
                    confidence_delta=-5.0,
                    method="time_based",
                    details="No time-based payload caused expected delay",
                )

        except Exception as e:
            return PayloadConfirmResult(
                confirmed=False,
                method="time_based",
                error=str(e),
            )

    async def _error_based_confirm(
        self,
        finding: Any,
        vuln_type: str,
    ) -> PayloadConfirmResult:
        """Error-based doğrulama — hata mesajı pattern'leri ara."""
        patterns = self.ERROR_PATTERNS.get(vuln_type, [])
        if not patterns:
            return PayloadConfirmResult(
                confirmed=False,
                method="error_based",
                error=f"No error patterns for {vuln_type}",
            )

        target = finding.endpoint or finding.target
        if not target:
            return PayloadConfirmResult(
                confirmed=False,
                method="error_based",
                error="No target URL",
            )

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"User-Agent": self.user_agent}

                # Orijinal payload ile istek
                test_url = target
                if finding.parameter and finding.payload:
                    test_url = self._inject_payload(
                        target, finding.parameter, finding.payload
                    )

                start = time.monotonic()
                async with session.get(
                    test_url,
                    headers=headers,
                    ssl=self.verify_ssl,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    elapsed = time.monotonic() - start
                    body = await resp.text()
                    body_lower = body.lower()

                    for pattern in patterns:
                        match = re.search(pattern, body_lower)
                        if match:
                            return PayloadConfirmResult(
                                confirmed=True,
                                confidence_delta=12.0,
                                method="error_based",
                                details=f"Error pattern matched: {match.group()[:100]}",
                                response_status=resp.status,
                                response_body_excerpt=body[:500],
                                response_time=elapsed,
                            )

                    return PayloadConfirmResult(
                        confirmed=False,
                        confidence_delta=-3.0,
                        method="error_based",
                        details="No error patterns found in response",
                        response_status=resp.status,
                        response_time=elapsed,
                    )

        except Exception as e:
            return PayloadConfirmResult(
                confirmed=False,
                method="error_based",
                error=str(e),
            )

    async def _variation_confirm(
        self,
        finding: Any,
        vuln_type: str,
    ) -> PayloadConfirmResult:
        """Farklı payload varyasyonları ile doğrulama."""
        if vuln_type not in ("xss_reflected", "xss_stored", "xss_dom"):
            return PayloadConfirmResult(
                confirmed=False,
                method="variation",
                error=f"Variation confirm not supported for {vuln_type}",
            )

        target = finding.endpoint or finding.target
        param = finding.parameter
        if not target or not param:
            return PayloadConfirmResult(
                confirmed=False,
                method="variation",
                error="No target URL or parameter",
            )

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"User-Agent": self.user_agent}

                for payload in self.XSS_VERIFY_PAYLOADS[:3]:
                    test_url = self._inject_payload(target, param, payload)

                    start = time.monotonic()
                    async with session.get(
                        test_url,
                        headers=headers,
                        ssl=self.verify_ssl,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ) as resp:
                        elapsed = time.monotonic() - start
                        body = await resp.text()

                        if payload in body:
                            return PayloadConfirmResult(
                                confirmed=True,
                                confidence_delta=18.0,
                                method="variation",
                                details=(
                                    f"XSS confirmed with variant payload: {payload[:50]}"
                                ),
                                response_status=resp.status,
                                response_body_excerpt=body[:500],
                                response_time=elapsed,
                            )

                return PayloadConfirmResult(
                    confirmed=False,
                    confidence_delta=-5.0,
                    method="variation",
                    details="No XSS variant payloads reflected",
                )

        except Exception as e:
            return PayloadConfirmResult(
                confirmed=False,
                method="variation",
                error=str(e),
            )

    @staticmethod
    def _inject_payload(url: str, param: str, payload: str) -> str:
        """URL'ye parametre ve payload ekle."""
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]

        # Rebuild
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))


__all__ = ["PayloadConfirmer", "PayloadConfirmResult"]
