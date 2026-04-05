"""
WhiteHatHacker AI — Pipeline ↔ AssetDB Integration (V7-T0-3)

full_scan pipeline'ından AssetDB'ye veri kaydeden yardımcı
fonksiyonlar.  Her stage handler'ın sonunda çağrılır.
Non-critical: herhangi bir hata scan'i durdurmaz.
"""

from __future__ import annotations

import time
from typing import Any

from loguru import logger

_DB_INSTANCE: Any = None


def _get_db() -> Any:
    """Lazy-init singleton AssetDB."""
    global _DB_INSTANCE  # noqa: PLW0603
    if _DB_INSTANCE is None:
        try:
            from src.integrations.asset_db import AssetDB

            _DB_INSTANCE = AssetDB()
        except Exception as exc:
            logger.debug(f"AssetDB unavailable: {exc}")
            return None
    return _DB_INSTANCE


def _program_name(state: Any) -> str:
    """scope_config'den program adını çıkar."""
    if hasattr(state, "scope_config") and state.scope_config:
        return state.scope_config.get("program_name", "") or state.target
    return getattr(state, "target", "unknown")


# ============================================================
# Hook Functions  — her biri non-critical, try/except ile sarılı
# ============================================================


def record_scan_start(state: Any) -> int | None:
    """Pipeline başlarken scan_run kaydı oluşturur.  scan_id döner."""
    db = _get_db()
    if db is None:
        return None
    try:
        program = _program_name(state)
        scan_id = getattr(state, "session_id", "") or "unknown"
        profile = str(getattr(state, "profile", "balanced"))
        db.ensure_program(program, name=program)
        db.record_scan_start(scan_id=scan_id, program_id=program, profile=profile)
        logger.debug(f"AssetDB scan_start recorded | scan_id={scan_id}")
        return scan_id
    except Exception as exc:
        logger.debug(f"AssetDB record_scan_start failed: {exc}")
        return None


def save_subdomains(state: Any) -> None:
    """Passive recon sonrası subdomain'leri asset olarak kaydet."""
    db = _get_db()
    if db is None:
        return
    try:
        program = _program_name(state)
        scan_id = getattr(state, "session_id", "") or "unknown"
        db.ensure_program(program, name=program)

        from src.integrations.asset_db import Asset

        assets = [
            Asset(asset_type="subdomain", value=sub, first_seen=time.time())
            for sub in getattr(state, "subdomains", [])
        ]
        if assets:
            db.upsert_assets(program, scan_id, assets)
            logger.debug(
                f"AssetDB saved {len(assets)} subdomain assets for {program}"
            )
    except Exception as exc:
        logger.debug(f"AssetDB save_subdomains failed: {exc}")


def save_live_hosts(state: Any) -> None:
    """Active recon sonrası live_hosts, ports, technologies kaydet."""
    db = _get_db()
    if db is None:
        return
    try:
        program = _program_name(state)
        scan_id = getattr(state, "session_id", "") or "unknown"
        db.ensure_program(program, name=program)

        from src.integrations.asset_db import Asset

        assets: list[Asset] = []
        now = time.time()

        for host in getattr(state, "live_hosts", []):
            ports = getattr(state, "open_ports", {}).get(host, [])
            techs = getattr(state, "technologies", {}).get(host, [])
            assets.append(
                Asset(
                    asset_type="host",
                    value=host,
                    first_seen=now,
                    metadata={
                        "ports": ports,
                        "technologies": techs,
                    },
                )
            )

        if assets:
            db.upsert_assets(program, scan_id, assets)
            logger.debug(
                f"AssetDB saved {len(assets)} host assets for {program}"
            )
    except Exception as exc:
        logger.debug(f"AssetDB save_live_hosts failed: {exc}")


def save_endpoints(state: Any) -> None:
    """Enumeration sonrası endpoint'leri kaydet."""
    db = _get_db()
    if db is None:
        return
    try:
        program = _program_name(state)
        scan_id = getattr(state, "session_id", "") or "unknown"
        db.ensure_program(program, name=program)

        from src.integrations.asset_db import Asset

        now = time.time()
        assets = [
            Asset(asset_type="endpoint", value=ep, first_seen=now)
            for ep in getattr(state, "endpoints", [])
        ]
        if assets:
            db.upsert_assets(program, scan_id, assets)
            logger.debug(
                f"AssetDB saved {len(assets)} endpoint assets for {program}"
            )
    except Exception as exc:
        logger.debug(f"AssetDB save_endpoints failed: {exc}")


def save_verified_findings(state: Any) -> None:
    """FP elimination sonrası doğrulanmış bulguları kaydet."""
    db = _get_db()
    if db is None:
        return
    try:
        program = _program_name(state)
        scan_id = getattr(state, "session_id", "") or "unknown"
        db.ensure_program(program, name=program)
        for f in getattr(state, "verified_findings", []):
            try:
                db.save_finding(
                    program_id=program,
                    scan_id=scan_id,
                    vuln_type=f.get("type", "unknown"),
                    severity=f.get("severity", "info"),
                    title=f.get("title", ""),
                    asset_value=f.get("target", "") or f.get("url", ""),
                    confidence=f.get("confidence", 50.0),
                    details=f,
                )
            except Exception as e:
                logger.warning(f"asset_db_hooks error: {e}")
        logger.debug(
            f"AssetDB saved {len(getattr(state, 'verified_findings', []))} findings for {program}"
        )
    except Exception as exc:
        logger.debug(f"AssetDB save_verified_findings failed: {exc}")


def record_scan_finish(state: Any, scan_id: int | None) -> None:
    """Pipeline bitişinde scan kaydını tamamla."""
    if scan_id is None:
        return
    db = _get_db()
    if db is None:
        return
    try:
        findings_count = len(getattr(state, "verified_findings", []))
        db.record_scan_finish(
            scan_id=str(scan_id),
            status="completed",
            stats={"findings_count": findings_count},
        )
        logger.debug(f"AssetDB scan_finish recorded | scan_id={scan_id}")
    except Exception as exc:
        logger.debug(f"AssetDB record_scan_finish failed: {exc}")
