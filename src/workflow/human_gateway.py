"""
WhiteHatHacker AI — Human Gateway (Onay Mekanizması)

Yarı-otonom modda kritik kararlar için insan onayı ister.
Tam otonom modda otomatik onay verir.
Bildirim kanalları: terminal, Slack, Telegram.
"""

from __future__ import annotations

import asyncio
import time
from enum import StrEnum
from typing import Any, Callable, Awaitable

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Enums & Models
# ============================================================

class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    AUTO_APPROVED = "auto_approved"


class RiskLevel(StrEnum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalRequest(BaseModel):
    """Onay talebi."""

    request_id: str = ""
    action: str = ""
    description: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    details: dict[str, Any] = Field(default_factory=dict)

    # Bağlam
    stage: str = ""
    target: str = ""
    tool: str = ""

    # Durum
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: float = Field(default_factory=time.time)
    responded_at: float = 0.0
    response_reason: str = ""


# Import canonical OperationMode from constants (avoid duplicate enum)
from src.utils.constants import OperationMode  # noqa: E402


# ============================================================
# Auto-Approval Rules
# ============================================================

# Tam otonom modda bile onay gerektiren eylemler
ALWAYS_REQUIRE_HUMAN = {
    "delete_data",
    "modify_production",
    "exceed_rate_limit",
}

# Yarı-otonom modda otomatik onaylanan eylemler
SEMI_AUTO_APPROVE = {
    "passive_recon",
    "dns_query",
    "whois_lookup",
    "certificate_check",
    "technology_detection",
    "wayback_lookup",
    "google_dorking",
    "github_dorking",
}

# Risk seviyesine göre auto-approve eşikleri
RISK_AUTO_APPROVE = {
    OperationMode.AUTONOMOUS: {
        RiskLevel.SAFE: True,
        RiskLevel.LOW: True,
        RiskLevel.MEDIUM: True,
        RiskLevel.HIGH: True,
        RiskLevel.CRITICAL: False,  # Kritik bile olsa otomanomda onay gerekebilir
    },
    OperationMode.SEMI_AUTONOMOUS: {
        RiskLevel.SAFE: True,
        RiskLevel.LOW: True,
        RiskLevel.MEDIUM: False,
        RiskLevel.HIGH: False,
        RiskLevel.CRITICAL: False,
    },
}


# ============================================================
# Notification Adapters
# ============================================================

class NotificationAdapter:
    """Bildirim adaptörü temel sınıfı."""

    async def send_approval_request(self, request: ApprovalRequest) -> None:
        raise NotImplementedError

    async def send_notification(self, message: str) -> None:
        raise NotImplementedError


class TerminalNotifier(NotificationAdapter):
    """Terminal/CLI üzerinden onay iste."""

    async def send_approval_request(self, request: ApprovalRequest) -> None:
        logger.info(
            f"\n{'='*60}\n"
            f"🔔 APPROVAL REQUIRED\n"
            f"{'='*60}\n"
            f"Action:  {request.action}\n"
            f"Target:  {request.target}\n"
            f"Risk:    {request.risk_level.upper()}\n"
            f"Stage:   {request.stage}\n"
            f"Tool:    {request.tool}\n"
            f"Details: {request.description}\n"
            f"{'='*60}"
        )

    async def send_notification(self, message: str) -> None:
        logger.info(f"📋 {message}")


class SlackNotifier(NotificationAdapter):
    """Slack webhook üzerinden bildirim."""

    def __init__(self, webhook_url: str = "") -> None:
        self.webhook_url = webhook_url

    async def send_approval_request(self, request: ApprovalRequest) -> None:
        if not self.webhook_url:
            return

        try:
            import aiohttp
            payload = {
                "text": (
                    f"🔔 *Approval Required*\n"
                    f"*Action:* {request.action}\n"
                    f"*Target:* {request.target}\n"
                    f"*Risk:* {request.risk_level}\n"
                    f"*Description:* {request.description}"
                )
            }
            async with aiohttp.ClientSession() as session:
                await session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                )
        except Exception as e:
            logger.warning(f"Slack notification failed: {e}")

    async def send_notification(self, message: str) -> None:
        if not self.webhook_url:
            return
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                await session.post(
                    self.webhook_url,
                    json={"text": message},
                    timeout=aiohttp.ClientTimeout(total=10),
                )
        except Exception as e:
            logger.warning(f"Slack notification failed: {e}")


class TelegramNotifier(NotificationAdapter):
    """Telegram bot üzerinden bildirim."""

    def __init__(self, bot_token: str = "", chat_id: str = "") -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id

    async def send_approval_request(self, request: ApprovalRequest) -> None:
        await self._send(
            f"🔔 *Approval Required*\n\n"
            f"*Action:* {request.action}\n"
            f"*Target:* {request.target}\n"
            f"*Risk:* {request.risk_level}\n"
            f"*Description:* {request.description}"
        )

    async def send_notification(self, message: str) -> None:
        await self._send(message)

    async def _send(self, text: str) -> None:
        if not self.bot_token or not self.chat_id:
            return
        try:
            import aiohttp
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            async with aiohttp.ClientSession() as session:
                await session.post(
                    url,
                    json={
                        "chat_id": self.chat_id,
                        "text": text,
                        "parse_mode": "Markdown",
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                )
        except Exception as e:
            logger.warning(f"Telegram notification failed: {e}")


# ============================================================
# Human Gateway
# ============================================================

class HumanGateway:
    """
    İnsan onay geçidi.

    Mod bazlı otomatik/manuel onay yönetimi:
    - autonomous: Çoğu aksiyon için otomatik onay
    - semi-autonomous: Riskli aksiyonlar için insan onayı

    Usage:
        gateway = HumanGateway(mode="semi-autonomous")
        gateway.add_notifier(TerminalNotifier())

        approval = await gateway.request_approval(
            action="run_sqlmap",
            target="example.com",
            risk_level="high",
            description="SQL injection test on login endpoint",
        )

        if approval.status == ApprovalStatus.APPROVED:
            # proceed
        else:
            # skip action
    """

    def __init__(
        self,
        mode: str = "semi-autonomous",
        default_timeout: int = 300,
        approval_callback: Callable[[ApprovalRequest], Awaitable[bool]] | None = None,
    ) -> None:
        self.mode = OperationMode(mode) if mode in OperationMode.__members__.values() else OperationMode.SEMI_AUTONOMOUS
        self.default_timeout = default_timeout
        self._approval_callback = approval_callback
        self._notifiers: list[NotificationAdapter] = []
        self._history: list[ApprovalRequest] = []
        self._counter = 0

    def add_notifier(self, notifier: NotificationAdapter) -> None:
        """Bildirim adaptörü ekle."""
        self._notifiers.append(notifier)

    def set_mode(self, mode: str) -> None:
        """Çalışma modunu değiştir."""
        self.mode = OperationMode(mode)
        logger.info(f"Human gateway mode changed to: {self.mode}")

    async def request_approval(
        self,
        action: str,
        target: str = "",
        risk_level: str = "low",
        description: str = "",
        stage: str = "",
        tool: str = "",
        details: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> ApprovalRequest:
        """
        Onay talep et.

        Returns:
            ApprovalRequest with status set to outcome
        """
        self._counter += 1

        risk = RiskLevel(risk_level) if risk_level in RiskLevel.__members__.values() else RiskLevel.MEDIUM

        request = ApprovalRequest(
            request_id=f"APR-{self._counter:05d}",
            action=action,
            description=description,
            risk_level=risk,
            details=details or {},
            stage=stage,
            target=target,
            tool=tool,
        )

        # Auto-approve kontrolü
        if self._should_auto_approve(request):
            request.status = ApprovalStatus.AUTO_APPROVED
            request.responded_at = time.time()
            request.response_reason = "Auto-approved by policy"
            self._history.append(request)
            logger.debug(
                f"Auto-approved: {action} | risk={risk_level} | mode={self.mode}"
            )
            return request

        # İnsan onayı gerekli
        logger.info(
            f"Awaiting human approval: {action} | risk={risk_level} | "
            f"target={target}"
        )

        # Bildirimleri gönder
        for notifier in self._notifiers:
            try:
                await notifier.send_approval_request(request)
            except Exception as e:
                logger.warning(f"Notification failed: {e}")

        # Onay bekle
        actual_timeout = timeout or self.default_timeout

        if self._approval_callback:
            try:
                approved = await asyncio.wait_for(
                    self._approval_callback(request),
                    timeout=actual_timeout,
                )
                request.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
                request.response_reason = "Human decision via callback"
            except asyncio.TimeoutError:
                request.status = ApprovalStatus.TIMEOUT
                request.response_reason = f"Timeout after {actual_timeout}s"
        else:
            # Callback yoksa terminal input (senkron fallback)
            request.status = await self._terminal_approval(request, actual_timeout)

        request.responded_at = time.time()
        self._history.append(request)

        logger.info(
            f"Approval result: {request.status} | action={action} | "
            f"reason={request.response_reason}"
        )

        return request

    def _should_auto_approve(self, request: ApprovalRequest) -> bool:
        """Otomatik onay verilmeli mi?"""
        # Her zaman insan gerektiren eylemler
        if request.action in ALWAYS_REQUIRE_HUMAN:
            return False

        # Tam otonom modda risk bazlı karar
        risk_rules = RISK_AUTO_APPROVE.get(self.mode, {})

        # Yarı otonom modda bazı eylemler her zaman otomatik
        if self.mode == OperationMode.SEMI_AUTONOMOUS:
            if request.action in SEMI_AUTO_APPROVE:
                return True

        return risk_rules.get(request.risk_level, False)

    async def _terminal_approval(
        self,
        request: ApprovalRequest,
        timeout: int,
    ) -> ApprovalStatus:
        """Terminal üzerinden onay iste (asyncio.to_thread ile)."""
        try:
            def _blocking_input() -> str:
                return input(
                    f"\n⚡ Approve '{request.action}' on {request.target}? "
                    f"[risk: {request.risk_level}] (y/n): "
                ).strip().lower()

            response = await asyncio.wait_for(
                asyncio.to_thread(_blocking_input),
                timeout=timeout,
            )

            if response in ("y", "yes", "evet", "e"):
                request.response_reason = "Approved by operator (terminal)"
                return ApprovalStatus.APPROVED
            else:
                request.response_reason = "Rejected by operator (terminal)"
                return ApprovalStatus.REJECTED

        except asyncio.TimeoutError:
            request.response_reason = f"No response within {timeout}s"
            return ApprovalStatus.TIMEOUT
        except EOFError:
            # Non-interactive terminal
            request.response_reason = "Non-interactive terminal — auto-rejected"
            return ApprovalStatus.REJECTED

    async def notify(self, message: str) -> None:
        """Tüm kanallara bildirim gönder."""
        for notifier in self._notifiers:
            try:
                await notifier.send_notification(message)
            except Exception as e:
                logger.warning(f"Notification failed: {e}")

    def get_history(self) -> list[ApprovalRequest]:
        """Onay geçmişi."""
        return list(self._history)

    def get_statistics(self) -> dict[str, Any]:
        """Onay istatistikleri."""
        total = len(self._history)
        if not total:
            return {"total": 0}

        status_counts = {}
        for r in self._history:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1

        avg_response = 0.0
        responded = [r for r in self._history if r.responded_at > 0]
        if responded:
            avg_response = sum(
                r.responded_at - r.requested_at for r in responded
            ) / len(responded)

        return {
            "total": total,
            "status_breakdown": status_counts,
            "avg_response_time_s": round(avg_response, 2),
            "auto_approved_pct": round(
                status_counts.get(ApprovalStatus.AUTO_APPROVED, 0) / total * 100, 1
            ),
        }

    def is_approved(self, request: ApprovalRequest) -> bool:
        """Shortcut — onaylanmış mı?"""
        return request.status in (
            ApprovalStatus.APPROVED,
            ApprovalStatus.AUTO_APPROVED,
        )


__all__ = [
    "HumanGateway",
    "ApprovalRequest",
    "ApprovalStatus",
    "RiskLevel",
    "OperationMode",
    "NotificationAdapter",
    "TerminalNotifier",
    "SlackNotifier",
    "TelegramNotifier",
]
