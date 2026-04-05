"""
WhiteHatHacker AI — Diff-Based Notification Alerts (V7-T3-3)

Diff engine sonuçlarına göre bildirim gönderir:
  - Yeni CRITICAL/HIGH finding → acil bildirim
  - Yeni subdomain → bilgi bildirimi
  - Scan tamamlandı → özet
  
Mevcut NotificationManager ile entegre çalışır.
"""

from __future__ import annotations

from typing import Any

from loguru import logger

from src.analysis.diff_engine import ScanDiffReport


async def send_diff_alerts(
    report: ScanDiffReport,
    notify_fn: Any = None,
) -> int:
    """
    Analyze a ScanDiffReport and send appropriate notifications.

    Args:
        report: result from DiffEngine.diff()
        notify_fn: async callable(title, body, level) — typically NotificationManager.notify

    Returns:
        Number of alerts sent.
    """
    if notify_fn is None:
        logger.debug("[diff_alerts] No notify_fn provided, skipping alerts")
        return 0

    sent = 0

    # 1. New CRITICAL/HIGH findings — urgent
    critical_findings = [
        f for f in report.new_findings
        if str(f.get("severity") or "").upper() in ("CRITICAL", "HIGH")
    ]
    if critical_findings:
        body_lines = []
        for f in critical_findings[:10]:
            sev = str(f.get("severity") or "?").upper()
            title_f = f.get("title", f.get("vuln_type", "Unknown"))
            asset = f.get("asset_value", "")
            body_lines.append(f"  [{sev}] {title_f} — {asset}")

        await notify_fn(
            title=f"🚨 {len(critical_findings)} Critical/High findings — {report.program_id}",
            body="\n".join(body_lines),
            level="critical",
        )
        sent += 1

    # 2. New assets — informational
    ad = report.asset_diff
    if ad and ad.new_assets:
        body_lines = [f"  + {a.value} ({a.asset_type})" for a in ad.new_assets[:15]]
        if len(ad.new_assets) > 15:
            body_lines.append(f"  ... and {len(ad.new_assets) - 15} more")

        await notify_fn(
            title=f"📡 {len(ad.new_assets)} new assets — {report.program_id}",
            body="\n".join(body_lines),
            level="info",
        )
        sent += 1

    # 3. Disappeared assets — warning
    if ad and ad.disappeared_assets:
        body_lines = [f"  - {a.value}" for a in ad.disappeared_assets[:10]]
        await notify_fn(
            title=f"⚠️ {len(ad.disappeared_assets)} assets disappeared — {report.program_id}",
            body="\n".join(body_lines),
            level="warning",
        )
        sent += 1

    # 4. Resolved findings — success
    if report.resolved_findings:
        await notify_fn(
            title=f"✅ {len(report.resolved_findings)} findings resolved — {report.program_id}",
            body="Previously reported issues appear to be fixed.",
            level="success",
        )
        sent += 1

    # 5. Scan complete summary — always
    new_count = len(report.new_findings)
    resolved_count = len(report.resolved_findings)
    new_assets = len(ad.new_assets) if ad else 0
    gone_assets = len(ad.disappeared_assets) if ad else 0

    await notify_fn(
        title=f"📊 Scan diff complete — {report.program_id}",
        body=(
            f"New findings: {new_count}\n"
            f"Resolved: {resolved_count}\n"
            f"New assets: {new_assets}\n"
            f"Disappeared assets: {gone_assets}"
        ),
        level="info",
    )
    sent += 1

    return sent
