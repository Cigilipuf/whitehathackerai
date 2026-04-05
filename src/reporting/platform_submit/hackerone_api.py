"""
WhiteHatHacker AI — HackerOne API Integration

HackerOne platformuna rapor gönderimi, draft yönetimi ve
program bilgisi çekme.
"""

from __future__ import annotations

import json
import time
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Models
# ============================================================

class HackerOneReport(BaseModel):
    """HackerOne rapor modeli."""

    title: str = ""
    vulnerability_information: str = ""    # Markdown report body
    impact: str = ""
    severity_rating: str = ""              # critical, high, medium, low, none
    weakness_id: int = 0                   # CWE mapped to H1 weakness
    structured_scope_id: str = ""          # Asset ID

    # CVSS
    cvss_vector: str = ""

    # Metadata
    report_id: str = ""
    state: str = "new"
    created_at: str = ""

    # Gönderim durumu
    submitted: bool = False
    submission_response: dict[str, Any] = Field(default_factory=dict)


class HackerOneProgram(BaseModel):
    """Program bilgileri."""

    handle: str = ""
    name: str = ""
    url: str = ""
    offers_bounties: bool = True
    policy: str = ""
    scopes: list[dict[str, Any]] = Field(default_factory=list)


# ============================================================
# Weakness Mapping
# ============================================================

# CWE → HackerOne Weakness ID eşleme (yaygın olanlar)
CWE_TO_H1_WEAKNESS: dict[str, int] = {
    "CWE-79": 60,      # XSS
    "CWE-89": 67,      # SQL Injection
    "CWE-78": 58,      # OS Command Injection
    "CWE-918": 68,     # SSRF
    "CWE-352": 45,     # CSRF
    "CWE-287": 27,     # Authentication Issues
    "CWE-639": 55,     # IDOR
    "CWE-22": 19,      # Path Traversal
    "CWE-611": 86,     # XXE
    "CWE-502": 48,     # Deserialization
    "CWE-94": 70,      # Code Injection
    "CWE-601": 53,     # Open Redirect
    "CWE-434": 51,     # Unrestricted Upload
    "CWE-200": 18,     # Information Disclosure
    "CWE-284": 26,     # Improper Access Control
    "CWE-312": 2,      # Cleartext Storage
    "CWE-319": 1,      # Cleartext Transmission
    "CWE-295": 28,     # Certificate Validation
    "CWE-326": 32,     # Inadequate Encryption
    "CWE-613": 49,     # Insufficient Session Expiration
    "CWE-942": 44,     # CORS Misconfiguration
    "CWE-113": 8,      # CRLF Injection
    "CWE-1236": 88,    # CSV Injection
}


# ============================================================
# HackerOne API Client
# ============================================================

class HackerOneAPI:
    """
    HackerOne v1 API istemcisi.

    API dokümantasyonu: https://api.hackerone.com/

    Usage:
        api = HackerOneAPI(
            api_token="your-token",
            api_identifier="your-identifier",
        )

        # Draft rapor oluştur
        report = api.prepare_report(
            program_handle="example",
            title="SQL Injection in /api/search",
            body="## Summary\\n...",
            severity="high",
            cvss_vector="CVSS:3.1/AV:N/AC:L/...",
        )

        # Gönder
        result = await api.submit_report(report)
    """

    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(
        self,
        api_token: str = "",
        api_identifier: str = "",
    ) -> None:
        self.api_token = api_token
        self.api_identifier = api_identifier
        self._session = None

    @property
    def _auth(self) -> tuple[str, str]:
        return (self.api_identifier, self.api_token)

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def is_configured(self) -> bool:
        return bool(self.api_token and self.api_identifier)

    # --------- Report Preparation ---------

    def prepare_report(
        self,
        program_handle: str,
        title: str,
        body: str,
        severity: str = "medium",
        impact: str = "",
        cvss_vector: str = "",
        cwe_id: str = "",
        scope_asset: str = "",
    ) -> HackerOneReport:
        """Rapor hazırla (henüz gönderme)."""
        weakness_id = 0
        if cwe_id:
            weakness_id = CWE_TO_H1_WEAKNESS.get(cwe_id, 0)

        report = HackerOneReport(
            title=title,
            vulnerability_information=body,
            impact=impact or self._default_impact(severity),
            severity_rating=str(severity or "medium").lower(),
            weakness_id=weakness_id,
            cvss_vector=cvss_vector,
        )

        logger.info(
            f"Report prepared for HackerOne | program={program_handle} | "
            f"title={title[:50]}... | severity={severity}"
        )

        return report

    @staticmethod
    def _default_impact(severity: str) -> str:
        impacts = {
            "critical": "This vulnerability allows an attacker to fully compromise the application and its data.",
            "high": "This vulnerability could lead to significant data exposure or unauthorized access.",
            "medium": "This vulnerability presents a moderate security risk that should be addressed.",
            "low": "This vulnerability presents a minor security risk with limited impact.",
        }
        return impacts.get(str(severity or "high").lower(), "Security impact to be determined.")

    # --------- API Calls ---------

    async def submit_report(
        self,
        report: HackerOneReport,
        program_handle: str = "",
        human_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Raporu HackerOne'a gönder.

        SAFETY: Bu metod ASLA otomatik olarak çağrılmamalıdır.
        human_confirmed=True parametresi, kullanıcının açıkça rapor
        gönderimini onayladığını doğrular. Bu parametre olmadan
        gönderim reddedilir.
        """
        # ── HARD SAFETY LOCK ──
        # Rapor gönderimi SADECE insan onayı ile yapılabilir.
        # Bu kilit, kodun hiçbir yerinden otomatik olarak atlanamaz.
        if not human_confirmed:
            logger.warning(
                "SUBMIT BLOCKED — human_confirmed=False | "
                "Rapor gönderimi insan onayı gerektirir. "
                "Draft olarak kaydediliyor."
            )
            draft_path = self.save_draft(report)
            return {
                "status": "blocked",
                "reason": "Human confirmation required — auto-submit is permanently disabled",
                "draft_path": draft_path,
            }

        if not self.is_configured():
            logger.warning("HackerOne API not configured — saving as draft only")
            return {"status": "draft", "reason": "API credentials not configured"}

        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": program_handle,
                    "title": report.title,
                    "vulnerability_information": report.vulnerability_information,
                    "impact": report.impact,
                    "severity_rating": report.severity_rating,
                },
            }
        }

        if report.weakness_id:
            payload["data"]["relationships"] = {
                "weakness": {
                    "data": {
                        "type": "weakness",
                        "id": report.weakness_id,
                    }
                }
            }

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.BASE_URL}/reporters/reports",
                    json=payload,
                    auth=aiohttp.BasicAuth(*self._auth),
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    response_data = await resp.json()

                    if resp.status == 201:
                        report.submitted = True
                        report.report_id = response_data.get("data", {}).get("id", "")
                        report.submission_response = response_data
                        logger.info(
                            f"Report submitted to HackerOne | id={report.report_id}"
                        )
                        return {"status": "submitted", "report_id": report.report_id}
                    else:
                        logger.error(
                            f"HackerOne submission failed | status={resp.status} | "
                            f"response={json.dumps(response_data)[:500]}"
                        )
                        return {
                            "status": "error",
                            "http_status": resp.status,
                            "errors": response_data.get("errors", []),
                        }

        except ImportError:
            return {"status": "error", "reason": "aiohttp not installed"}
        except Exception as e:
            logger.error(f"HackerOne API error: {e}")
            return {"status": "error", "reason": str(e)}

    async def get_program(self, handle: str) -> HackerOneProgram | None:
        """Program bilgilerini çek."""
        if not self.is_configured():
            return None

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.BASE_URL}/programs/{handle}",
                    auth=aiohttp.BasicAuth(*self._auth),
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attrs = data.get("data", {}).get("attributes", {})
                        return HackerOneProgram(
                            handle=handle,
                            name=attrs.get("name", ""),
                            url=f"https://hackerone.com/{handle}",
                            offers_bounties=attrs.get("offers_bounties", True),
                            policy=attrs.get("policy", ""),
                        )
        except Exception as e:
            logger.warning(f"Failed to fetch H1 program info: {e}")

        return None

    def save_draft(
        self,
        report: HackerOneReport,
        output_dir: str = "output/reports",
    ) -> str:
        """Raporu draft olarak kaydet."""
        from pathlib import Path

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        filename = f"h1_draft_{int(time.time())}_{report.title[:30].replace(' ', '_')}.json"
        filepath = out / filename

        filepath.write_text(
            json.dumps(report.model_dump(), indent=2, ensure_ascii=False)
        )

        logger.info(f"H1 draft saved: {filepath}")
        return str(filepath)


__all__ = [
    "HackerOneAPI",
    "HackerOneReport",
    "HackerOneProgram",
    "CWE_TO_H1_WEAKNESS",
]
