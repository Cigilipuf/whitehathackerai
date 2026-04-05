"""
WhiteHatHacker AI — Incremental Scan Mode (V7-T3-2)

full_scan pipeline'ı için incremental scan desteği:
  - Sadece yeni/değişen asset'leri tarar
  - Önceki scan ile karşılaştırarak delta hesaplar
  - Scan sonrası diff raporu oluşturur

Bağımlılık: Asset DB (V7-T0-2), Diff Engine (V7-T3-1)
"""

from __future__ import annotations

from typing import Any

from loguru import logger

from src.integrations.asset_db import Asset, AssetDB


def compute_incremental_targets(
    db: AssetDB,
    program_id: str,
    current_subdomains: list[str],
    current_endpoints: list[str],
) -> dict[str, list[str]]:
    """
    Compare current recon results with the asset DB to find
    only new or changed targets.

    Returns:
        {
            "new_subdomains": [...],
            "new_endpoints": [...],
            "all_subdomains": [...],  # for reference
        }
    """
    # Get known alive subdomains from DB
    known_assets = db.get_assets(program_id, asset_type="subdomain", alive_only=True)
    known_values = {a.value for a in known_assets}

    # Get known endpoints
    known_eps = db.get_assets(program_id, asset_type="endpoint", alive_only=True)
    known_ep_values = {a.value for a in known_eps}

    new_subs = [s for s in current_subdomains if s.lower() not in known_values]
    new_eps = [e for e in current_endpoints if e not in known_ep_values]

    logger.info(
        f"[incremental] Subdomains: {len(current_subdomains)} total, "
        f"{len(new_subs)} new. Endpoints: {len(current_endpoints)} total, "
        f"{len(new_eps)} new."
    )

    return {
        "new_subdomains": new_subs,
        "new_endpoints": new_eps,
        "all_subdomains": current_subdomains,
    }


def get_last_scan_id(db: AssetDB, program_id: str) -> str | None:
    """Get the most recent completed scan ID for a program."""
    runs = db.get_scan_runs(program_id, limit=1)
    for run in runs:
        if run.get("status") == "completed":
            return run.get("id")
    return None


def should_rescan_endpoint(
    endpoint: str,
    last_scan_findings: list[dict[str, Any]],
) -> bool:
    """
    Decide if an endpoint needs rescanning based on previous findings.
    Endpoints with unresolved findings should always be rescanned.
    """
    for f in last_scan_findings:
        if f.get("asset_value", "") == endpoint and f.get("status") != "fixed":
            return True
    return False
