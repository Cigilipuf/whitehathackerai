"""Regression tests for notification wiring into diff alerts."""

from __future__ import annotations

from src.integrations.notification import build_notification_manager


def test_build_notification_manager_adds_enabled_channels():
    config = {
        "notifications": {
            "enabled": True,
            "min_level": "warning",
            "channels": {
                "terminal": True,
                "slack": {
                    "enabled": True,
                    "webhook_url": "https://hooks.slack.test/123",
                },
                "telegram": {
                    "enabled": True,
                    "bot_token": "bot-token",
                    "chat_id": "chat-id",
                },
                "discord": {
                    "enabled": True,
                    "webhook_url": "https://discord.test/webhook",
                },
            },
        },
    }

    manager = build_notification_manager(config)

    assert set(manager._channels) == {"terminal", "slack", "telegram", "discord"}
    assert manager._min_level.value == "warning"


def test_build_notification_manager_respects_disabled_notifications():
    manager = build_notification_manager({"notifications": {"enabled": False}})
    assert manager._channels == {}


def test_full_scan_uses_notification_builder_for_diff_alerts():
    from pathlib import Path

    source = Path("src/workflow/pipelines/full_scan.py").read_text(encoding="utf-8")
    assert "build_notification_manager" in source
    assert "NotificationManager()" not in source.split("# Send alerts via notification system", 1)[1][:300]
