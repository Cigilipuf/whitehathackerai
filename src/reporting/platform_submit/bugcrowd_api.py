"""
WhiteHatHacker AI — Bugcrowd API Integration

Bugcrowd platformuna rapor gönderimi ve program yönetimi.
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

class BugcrowdSubmission(BaseModel):
    """Bugcrowd rapor modeli."""

    title: str = ""
    description: str = ""          # Markdown body
    severity: int = 3              # 1=Critical, 2=Severe(High), 3=Moderate, 4=Minor, 5=Trivial
    vrt_id: str = ""               # Vulnerability Rating Taxonomy ID

    # Hedef
    bug_url: str = ""              # Zafiyet URL'i
    extra_info: str = ""           # Ek bilgi

    # CVSS
    cvss_vector: str = ""

    # Durum
    submission_id: str = ""
    state: str = "new"
    submitted: bool = False
    submission_response: dict[str, Any] = Field(default_factory=dict)


class BugcrowdProgram(BaseModel):
    """Bugcrowd program bilgileri."""

    code: str = ""
    name: str = ""
    url: str = ""
    max_payout: float = 0.0
    target_groups: list[dict[str, Any]] = Field(default_factory=list)


# ============================================================
# SAFETY: Auto-Submit Hard Lock
# Rapor gönderimi SADECE insan onayı ile yapılabilir.
# Bu değişken hiçbir config dosyası tarafından override edilemez.
# ============================================================
_AUTO_SUBMIT_PERMANENTLY_DISABLED = True


# ============================================================
# Severity Mapping
# ============================================================

SEVERITY_TO_BUGCROWD: dict[str, int] = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
    "informational": 5,
}

# VRT (Vulnerability Rating Taxonomy) Mapping
# Ref: https://bugcrowd.com/vulnerability-rating-taxonomy
VRT_MAPPING: dict[str, str] = {
    "sql_injection": "server_security_misconfiguration.dbms.sql_injection",
    "xss_reflected": "cross_site_scripting_xss.reflected",
    "xss_stored": "cross_site_scripting_xss.stored",
    "xss_dom": "cross_site_scripting_xss.dom_based",
    "ssrf": "server_side_request_forgery",
    "command_injection": "server_security_misconfiguration.rce",
    "ssti": "server_security_misconfiguration.rce.ssti",
    "idor": "broken_access_control.idor",
    "authentication_bypass": "broken_authentication.auth_bypass",
    "cors_misconfiguration": "server_security_misconfiguration.cors",
    "open_redirect": "unvalidated_redirects_and_forwards.open_redirect",
    "local_file_inclusion": "server_security_misconfiguration.lfi",
    "xxe": "server_security_misconfiguration.xxe",
    "csrf": "cross_site_request_forgery",
    "deserialization": "server_security_misconfiguration.deserialization",
    "information_disclosure": "sensitive_data_exposure",
    "rate_limit_bypass": "broken_access_control.rate_limiting",
    "subdomain_takeover": "server_security_misconfiguration.subdomain_takeover",
    "crlf_injection": "server_security_misconfiguration.crlf_injection",
}


# ============================================================
# Bugcrowd API Client
# ============================================================

class BugcrowdAPI:
    """
    Bugcrowd API istemcisi.

    API Docs: https://docs.bugcrowd.com/customers/api/

    Usage:
        api = BugcrowdAPI(api_token="your-token")

        submission = api.prepare_submission(
            program_code="example_program",
            title="SQL Injection in search API",
            body="## Description\\n...",
            severity="high",
            vuln_type="sql_injection",
            bug_url="https://example.com/api/search?q=test",
        )

        result = await api.submit(submission, program_code="example_program")
    """

    BASE_URL = "https://api.bugcrowd.com"

    def __init__(self, api_token: str = "") -> None:
        self.api_token = api_token

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self.api_token}",
            "Content-Type": "application/vnd.bugcrowd+json",
            "Accept": "application/vnd.bugcrowd+json",
        }

    def is_configured(self) -> bool:
        return bool(self.api_token)

    # --------- Submission Preparation ---------

    def prepare_submission(
        self,
        program_code: str,
        title: str,
        body: str,
        severity: str = "medium",
        vuln_type: str = "",
        bug_url: str = "",
        cvss_vector: str = "",
        extra_info: str = "",
    ) -> BugcrowdSubmission:
        """Gönderim hazırla."""
        bc_severity = SEVERITY_TO_BUGCROWD.get(str(severity or "medium").lower(), 3)
        vrt_id = VRT_MAPPING.get(vuln_type, "")

        submission = BugcrowdSubmission(
            title=title,
            description=body,
            severity=bc_severity,
            vrt_id=vrt_id,
            bug_url=bug_url,
            cvss_vector=cvss_vector,
            extra_info=extra_info,
        )

        logger.info(
            f"Bugcrowd submission prepared | program={program_code} | "
            f"severity={severity}→P{bc_severity} | vrt={vrt_id}"
        )

        return submission

    # --------- API Calls ---------

    async def submit(
        self,
        submission: BugcrowdSubmission,
        program_code: str = "",
        human_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Bugcrowd'a rapor gönder.

        SAFETY: Bu metod ASLA otomatik olarak çağrılmamalıdır.
        human_confirmed=True parametresi zorunludur.
        """
        # ── HARD SAFETY LOCK ──
        if not human_confirmed:
            logger.warning(
                "SUBMIT BLOCKED — human_confirmed=False | "
                "Draft olarak kaydediliyor."
            )
            draft_path = self.save_draft(submission)
            return {
                "status": "blocked",
                "reason": "Human confirmation required — auto-submit is permanently disabled",
                "draft_path": draft_path,
            }

        if not self.is_configured():
            logger.warning("Bugcrowd API not configured — saving as draft")
            return {"status": "draft", "reason": "API token not configured"}

        payload = {
            "data": {
                "type": "submission",
                "attributes": {
                    "title": submission.title,
                    "description": submission.description,
                    "severity": submission.severity,
                    "bug_url": submission.bug_url,
                    "extra_info": submission.extra_info,
                },
                "relationships": {},
            }
        }

        if submission.vrt_id:
            payload["data"]["attributes"]["vrt_id"] = submission.vrt_id

        try:
            import aiohttp

            url = f"{self.BASE_URL}/programs/{program_code}/submissions"

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    response_data = await resp.json()

                    if resp.status in (200, 201):
                        submission.submitted = True
                        submission.submission_id = (
                            response_data.get("data", {}).get("id", "")
                        )
                        submission.submission_response = response_data
                        logger.info(
                            f"Submitted to Bugcrowd | id={submission.submission_id}"
                        )
                        return {
                            "status": "submitted",
                            "submission_id": submission.submission_id,
                        }
                    else:
                        logger.error(
                            f"Bugcrowd submission failed | status={resp.status}"
                        )
                        return {
                            "status": "error",
                            "http_status": resp.status,
                            "errors": response_data.get("errors", []),
                        }

        except ImportError:
            return {"status": "error", "reason": "aiohttp not installed"}
        except Exception as e:
            logger.error(f"Bugcrowd API error: {e}")
            return {"status": "error", "reason": str(e)}

    async def get_program(self, program_code: str) -> BugcrowdProgram | None:
        """Program bilgisi çek."""
        if not self.is_configured():
            return None

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.BASE_URL}/programs/{program_code}",
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attrs = data.get("data", {}).get("attributes", {})
                        return BugcrowdProgram(
                            code=program_code,
                            name=attrs.get("name", ""),
                            url=f"https://bugcrowd.com/{program_code}",
                        )
        except Exception as e:
            logger.warning(f"Failed to fetch Bugcrowd program: {e}")

        return None

    def save_draft(
        self,
        submission: BugcrowdSubmission,
        output_dir: str = "output/reports",
    ) -> str:
        """Draft olarak kaydet."""
        from pathlib import Path

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        filename = (
            f"bc_draft_{int(time.time())}_"
            f"{submission.title[:30].replace(' ', '_')}.json"
        )
        filepath = out / filename

        filepath.write_text(
            json.dumps(submission.model_dump(), indent=2, ensure_ascii=False)
        )

        logger.info(f"Bugcrowd draft saved: {filepath}")
        return str(filepath)


__all__ = [
    "BugcrowdAPI",
    "BugcrowdSubmission",
    "BugcrowdProgram",
    "VRT_MAPPING",
    "SEVERITY_TO_BUGCROWD",
]
