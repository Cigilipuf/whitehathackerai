"""
WhiteHatHacker AI — Generic Platform API

Platform-bağımsız rapor gönderim adaptörü.
Özel platformlar veya webhook entegrasyonları için kullanılır.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Models
# ============================================================

# ============================================================
# SAFETY: Auto-Submit Hard Lock
# Rapor gönderimi SADECE insan onayı ile yapılabilir.
# Bu değişken hiçbir config dosyası tarafından override edilemez.
# ============================================================
_AUTO_SUBMIT_PERMANENTLY_DISABLED = True


class GenericSubmission(BaseModel):
    """Platform-bağımsız rapor modeli."""

    title: str = ""
    description: str = ""          # Markdown body
    severity: str = "medium"       # critical/high/medium/low/info
    cvss_score: float = 0.0
    cvss_vector: str = ""
    vuln_type: str = ""
    cwe: str = ""

    # Target
    target_url: str = ""
    parameter: str = ""
    payload: str = ""

    # Reproduction
    steps_to_reproduce: list[str] = Field(default_factory=list)

    # Evidence
    http_requests: list[dict[str, Any]] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)
    poc_code: str = ""

    # Impact & Fix
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    # Meta
    submission_id: str = ""
    submitted: bool = False
    submitted_at: str = ""
    platform: str = "generic"


# ============================================================
# Generic API
# ============================================================

class GenericPlatformAPI:
    """
    Generic rapor gönderim API'si.

    - Webhook endpoint'lerine HTTP POST
    - Dosya sistemi draft kaydı
    - Özel API entegrasyonu desteği

    Usage:
        api = GenericPlatformAPI(webhook_url="https://hooks.example.com/vuln")
        sub = api.prepare_submission(title="SQLi in /api", body="...", severity="high")
        result = await api.submit(sub)
    """

    def __init__(
        self,
        webhook_url: str = "",
        api_url: str = "",
        api_token: str = "",
        platform_name: str = "generic",
        custom_headers: dict[str, str] | None = None,
    ) -> None:
        self.webhook_url = webhook_url
        self.api_url = api_url
        self.api_token = api_token
        self.platform_name = platform_name
        self.custom_headers = custom_headers or {}

    @property
    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "WhiteHatHackerAI/2.0",
        }
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        headers.update(self.custom_headers)
        return headers

    def is_configured(self) -> bool:
        return bool(self.webhook_url or self.api_url)

    # --------- Preparation ---------

    def prepare_submission(
        self,
        title: str,
        body: str,
        severity: str = "medium",
        vuln_type: str = "",
        target_url: str = "",
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        cwe: str = "",
        steps: list[str] | None = None,
        impact: str = "",
        remediation: str = "",
        poc_code: str = "",
        http_requests: list[dict] | None = None,
        screenshots: list[str] | None = None,
        references: list[str] | None = None,
    ) -> GenericSubmission:
        """Rapor hazırla."""
        sub = GenericSubmission(
            title=title,
            description=body,
            severity=str(severity or "medium").lower(),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            vuln_type=vuln_type,
            cwe=cwe,
            target_url=target_url,
            steps_to_reproduce=steps or [],
            impact=impact,
            remediation=remediation,
            poc_code=poc_code,
            http_requests=http_requests or [],
            screenshots=screenshots or [],
            references=references or [],
            platform=self.platform_name,
        )

        logger.info(
            f"Generic submission prepared | severity={severity} | "
            f"type={vuln_type} | target={target_url[:60]}"
        )

        return sub

    # --------- Submit ---------

    async def submit(
        self,
        submission: GenericSubmission,
        human_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Webhook / API endpoint'ine gönder.

        SAFETY: human_confirmed=True zorunludur.
        Otomatik gönderim kalıcı olarak devre dışıdır.
        """
        # ── HARD SAFETY LOCK ──
        if not human_confirmed:
            logger.warning(
                "SUBMIT BLOCKED — human_confirmed=False | "
                "Draft olarak kaydediliyor."
            )
            path = self.save_draft(submission)
            return {
                "status": "blocked",
                "reason": "Human confirmation required — auto-submit is permanently disabled",
                "draft_path": path,
            }

        if not self.is_configured():
            logger.warning("Generic API not configured — saving as draft")
            path = self.save_draft(submission)
            return {"status": "draft", "path": path}

        url = self.webhook_url or self.api_url
        payload = submission.model_dump()

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    try:
                        response_data = await resp.json()
                    except Exception as _exc:
                        response_data = {"raw": await resp.text()}

                    if resp.status in (200, 201, 202, 204):
                        submission.submitted = True
                        submission.submitted_at = time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        )

                        sid = response_data.get("id", response_data.get("submission_id", ""))
                        submission.submission_id = str(sid) if sid else ""

                        logger.info(
                            f"Submitted to {self.platform_name} | "
                            f"status={resp.status}"
                        )
                        return {
                            "status": "submitted",
                            "http_status": resp.status,
                            "response": response_data,
                        }
                    else:
                        logger.error(
                            f"Generic submission failed | "
                            f"status={resp.status} | url={url}"
                        )
                        return {
                            "status": "error",
                            "http_status": resp.status,
                            "response": response_data,
                        }

        except ImportError:
            return {"status": "error", "reason": "aiohttp not installed"}
        except Exception as e:
            logger.error(f"Generic API error: {e}")
            return {"status": "error", "reason": str(e)}

    async def submit_batch(
        self,
        submissions: list[GenericSubmission],
        delay: float = 2.0,
        human_confirmed: bool = False,
    ) -> list[dict[str, Any]]:
        """Toplu gönderim (rate limited). human_confirmed zorunlu."""
        import asyncio

        if not human_confirmed:
            logger.warning("BATCH SUBMIT BLOCKED — human_confirmed=False")
            results: list[dict[str, Any]] = []
            for sub in submissions:
                path = self.save_draft(sub)
                results.append({"status": "blocked", "draft_path": path})
            return results

        results = []
        for i, sub in enumerate(submissions):
            result = await self.submit(sub, human_confirmed=True)
            results.append(result)

            # Rate limiting arası
            if i < len(submissions) - 1:
                await asyncio.sleep(delay)

        successes = sum(1 for r in results if r.get("status") == "submitted")
        logger.info(
            f"Batch submit: {successes}/{len(submissions)} successful"
        )
        return results

    # --------- Draft ---------

    def save_draft(
        self,
        submission: GenericSubmission,
        output_dir: str = "output/reports",
    ) -> str:
        """Draft kaydet."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        safe_title = submission.title[:30].replace(" ", "_").replace("/", "-")
        filename = f"draft_{self.platform_name}_{int(time.time())}_{safe_title}.json"
        filepath = out / filename

        filepath.write_text(
            json.dumps(submission.model_dump(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"Draft saved: {filepath}")
        return str(filepath)

    def load_draft(self, filepath: str) -> GenericSubmission:
        """Draft'tan yükle."""
        data = json.loads(Path(filepath).read_text(encoding="utf-8"))
        return GenericSubmission(**data)


__all__ = [
    "GenericPlatformAPI",
    "GenericSubmission",
]
