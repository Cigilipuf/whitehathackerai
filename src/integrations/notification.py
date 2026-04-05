"""
WhiteHatHacker AI — Notification System

Slack, Telegram ve terminal üzerinden bildirim gönderme.
Kritik bulgular, tarama durumu ve onay talepleri için.
"""

from __future__ import annotations

from pathlib import Path
from enum import StrEnum
from typing import Any

import yaml
from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Models
# ============================================================

class NotificationLevel(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    SUCCESS = "success"


class NotificationMessage(BaseModel):
    """Bildirim mesajı."""

    title: str = ""
    body: str = ""
    level: NotificationLevel = NotificationLevel.INFO
    channel: str = ""       # slack, telegram, terminal, all
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def formatted(self) -> str:
        icon = {
            NotificationLevel.INFO: "ℹ️",
            NotificationLevel.WARNING: "⚠️",
            NotificationLevel.CRITICAL: "🚨",
            NotificationLevel.SUCCESS: "✅",
        }.get(self.level, "📋")
        return f"{icon} *{self.title}*\n{self.body}"


# ============================================================
# Channel Adapters
# ============================================================

class NotificationChannel:
    """Bildirim kanalı temel sınıfı."""

    name: str = "base"

    async def send(self, message: NotificationMessage) -> bool:
        raise NotImplementedError


class TerminalChannel(NotificationChannel):
    """Terminal/loguru ile bildirim."""

    name = "terminal"

    async def send(self, message: NotificationMessage) -> bool:
        level_map = {
            NotificationLevel.INFO: "info",
            NotificationLevel.WARNING: "warning",
            NotificationLevel.CRITICAL: "critical",
            NotificationLevel.SUCCESS: "success",
        }
        log_level = level_map.get(message.level, "info")
        getattr(logger, log_level, logger.info)(message.formatted)
        return True


def _validate_webhook_url(url: str) -> str:
    """Validate that webhook URL uses https scheme. Returns empty string on invalid."""
    if not url:
        return ""
    url = url.strip()
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        logger.warning(f"Webhook URL rejected: unsupported scheme '{parsed.scheme}'")
        return ""
    if not parsed.hostname:
        logger.warning("Webhook URL rejected: no hostname")
        return ""
    return url


class SlackChannel(NotificationChannel):
    """Slack webhook kanalı."""

    name = "slack"

    def __init__(self, webhook_url: str = "") -> None:
        self.webhook_url = _validate_webhook_url(webhook_url)

    async def send(self, message: NotificationMessage) -> bool:
        if not self.webhook_url:
            return False

        try:
            import aiohttp

            color = {
                NotificationLevel.INFO: "#36a64f",
                NotificationLevel.WARNING: "#ff9900",
                NotificationLevel.CRITICAL: "#ff0000",
                NotificationLevel.SUCCESS: "#2eb886",
            }.get(message.level, "#cccccc")

            payload = {
                "attachments": [{
                    "color": color,
                    "title": message.title,
                    "text": message.body,
                    "footer": "WhiteHatHacker AI",
                }]
            }

            async with aiohttp.ClientSession() as session:
                resp = await session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                )
                return resp.status == 200

        except Exception as e:
            logger.warning(f"Slack send failed: {e}")
            return False


class TelegramChannel(NotificationChannel):
    """Telegram bot kanalı."""

    name = "telegram"

    def __init__(self, bot_token: str = "", chat_id: str = "") -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id

    async def send(self, message: NotificationMessage) -> bool:
        if not self.bot_token or not self.chat_id:
            return False

        try:
            import aiohttp

            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            payload = {
                "chat_id": self.chat_id,
                "text": message.formatted,
                "parse_mode": "Markdown",
            }

            async with aiohttp.ClientSession() as session:
                resp = await session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                )
                return resp.status == 200

        except Exception as e:
            logger.warning(f"Telegram send failed: {e}")
            return False


class DiscordChannel(NotificationChannel):
    """Discord webhook kanalı."""

    name = "discord"

    def __init__(self, webhook_url: str = "") -> None:
        self.webhook_url = _validate_webhook_url(webhook_url)

    async def send(self, message: NotificationMessage) -> bool:
        if not self.webhook_url:
            return False

        try:
            import aiohttp

            color = {
                NotificationLevel.INFO: 0x36A64F,
                NotificationLevel.WARNING: 0xFF9900,
                NotificationLevel.CRITICAL: 0xFF0000,
                NotificationLevel.SUCCESS: 0x2EB886,
            }.get(message.level, 0xCCCCCC)

            payload = {
                "embeds": [
                    {
                        "title": message.title,
                        "description": message.body[:4096],
                        "color": color,
                        "footer": {"text": "WhiteHatHacker AI"},
                    }
                ]
            }

            async with aiohttp.ClientSession() as session:
                resp = await session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                )
                return resp.status in (200, 204)

        except Exception as e:
            logger.warning(f"Discord send failed: {e}")
            return False


# ============================================================
# Notification Manager
# ============================================================

class NotificationManager:
    """
    Merkezi bildirim yöneticisi.

    Usage:
        mgr = NotificationManager()
        mgr.add_channel(TerminalChannel())
        mgr.add_channel(SlackChannel(webhook_url="https://..."))

        await mgr.notify(
            title="Critical Finding!",
            body="SQL Injection in login endpoint",
            level="critical",
        )
    """

    def __init__(self) -> None:
        self._channels: dict[str, NotificationChannel] = {}
        self._min_level = NotificationLevel.INFO

    def add_channel(self, channel: NotificationChannel) -> None:
        self._channels[channel.name] = channel
        logger.debug(f"Notification channel added: {channel.name}")

    def remove_channel(self, name: str) -> None:
        self._channels.pop(name, None)

    def set_min_level(self, level: str) -> None:
        """Minimum bildirim seviyesi."""
        self._min_level = NotificationLevel(level)

    async def notify(
        self,
        title: str,
        body: str,
        level: str = "info",
        channel: str = "all",
        **metadata: Any,
    ) -> dict[str, bool]:
        """
        Bildirim gönder.

        Args:
            title: Bildirim başlığı
            body: Bildirim içeriği
            level: info/warning/critical/success
            channel: Hedef kanal (all = hepsine)
            **metadata: Ek bilgiler

        Returns:
            Kanal başına gönderim sonuçları
        """
        msg = NotificationMessage(
            title=title,
            body=body,
            level=NotificationLevel(level),
            channel=channel,
            metadata=metadata,
        )

        # Seviye filtresi
        level_order = list(NotificationLevel)
        if level_order.index(msg.level) < level_order.index(self._min_level):
            return {}

        results: dict[str, bool] = {}

        if channel == "all":
            for ch_name, ch in self._channels.items():
                results[ch_name] = await ch.send(msg)
        elif channel in self._channels:
            results[channel] = await self._channels[channel].send(msg)

        return results

    async def notify_finding(
        self,
        vuln_type: str,
        severity: str,
        target: str,
        confidence: int = 0,
    ) -> None:
        """Zafiyet bulgusu bildirimi."""
        level = {
            "critical": "critical",
            "high": "critical",
            "medium": "warning",
            "low": "info",
            "info": "info",
        }.get(severity, "info")

        await self.notify(
            title=f"[{severity.upper()}] {vuln_type}",
            body=f"Target: {target}\nConfidence: {confidence}%",
            level=level,
        )

    async def notify_scan_complete(
        self,
        target: str,
        findings_count: int,
        duration: str = "",
    ) -> None:
        """Tarama tamamlanma bildirimi."""
        await self.notify(
            title="Scan Complete",
            body=(
                f"Target: {target}\n"
                f"Findings: {findings_count}\n"
                f"Duration: {duration}"
            ),
            level="success",
        )

    async def notify_error(self, error: str, context: str = "") -> None:
        """Hata bildirimi."""
        await self.notify(
            title="Error",
            body=f"{context}\n{error}" if context else error,
            level="warning",
        )


def _expand_env_vars(obj: Any) -> Any:
    """Expand ${VAR:-default} placeholders inside notification config values."""
    import os
    import re

    if isinstance(obj, str):
        pattern = re.compile(r"\$\{([^}:]+)(?::-(.*?))?\}")

        def _replace(match: re.Match[str]) -> str:
            var_name = match.group(1)
            default = match.group(2) if match.group(2) is not None else ""
            return os.environ.get(var_name, default)

        return pattern.sub(_replace, obj)
    if isinstance(obj, dict):
        return {k: _expand_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_vars(item) for item in obj]
    return obj


def load_notification_config(config_path: str = "config/settings.yaml") -> dict[str, Any]:
    """Load notification settings without pulling in the entire app bootstrap."""
    path = Path(config_path)
    if not path.exists():
        logger.debug(f"Notification config not found: {config_path}")
        return {}

    try:
        with path.open(encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
    except Exception as exc:
        logger.warning(f"Notification config load failed: {exc}")
        return {}

    return _expand_env_vars(config if isinstance(config, dict) else {})


def build_notification_manager(
    config: dict[str, Any] | None = None,
    *,
    config_path: str = "config/settings.yaml",
) -> NotificationManager:
    """Create a NotificationManager from settings.yaml notification channels."""
    manager = NotificationManager()

    if config is None:
        config = load_notification_config(config_path)

    notify_cfg = config.get("notifications", {}) if isinstance(config, dict) else {}
    if not notify_cfg.get("enabled", False):
        return manager

    channels_cfg = notify_cfg.get("channels", {}) if isinstance(notify_cfg, dict) else {}
    if channels_cfg.get("terminal", True):
        manager.add_channel(TerminalChannel())

    slack_cfg = channels_cfg.get("slack", {})
    if isinstance(slack_cfg, dict) and slack_cfg.get("enabled") and slack_cfg.get("webhook_url"):
        manager.add_channel(SlackChannel(webhook_url=slack_cfg["webhook_url"]))

    telegram_cfg = channels_cfg.get("telegram", {})
    if (
        isinstance(telegram_cfg, dict)
        and telegram_cfg.get("enabled")
        and telegram_cfg.get("bot_token")
        and telegram_cfg.get("chat_id")
    ):
        manager.add_channel(
            TelegramChannel(
                bot_token=telegram_cfg["bot_token"],
                chat_id=telegram_cfg["chat_id"],
            )
        )

    discord_cfg = channels_cfg.get("discord", {})
    if isinstance(discord_cfg, dict) and discord_cfg.get("enabled") and discord_cfg.get("webhook_url"):
        manager.add_channel(DiscordChannel(webhook_url=discord_cfg["webhook_url"]))

    min_level = notify_cfg.get("min_level")
    if min_level:
        try:
            manager.set_min_level(str(min_level))
        except Exception as exc:
            logger.debug(f"Invalid notification min_level '{min_level}': {exc}")

    return manager


__all__ = [
    "NotificationManager",
    "NotificationMessage",
    "NotificationLevel",
    "NotificationChannel",
    "TerminalChannel",
    "SlackChannel",
    "TelegramChannel",
    "DiscordChannel",
    "build_notification_manager",
    "load_notification_config",
]
