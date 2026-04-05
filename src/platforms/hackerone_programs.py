"""
WhiteHatHacker AI — HackerOne Program Fetcher

Fetches publicly listed bug bounty programs from the HackerOne
Hacker API (v1).  Results are returned as a list of normalised
``BountyProgram`` objects that the GUI can display.

HackerOne API Reference:
    GET /v1/hackers/programs
    https://api.hackerone.com/customer-resources/#programs

Authentication:
    HTTP Basic — (api_identifier, api_token)
    Credentials come from env vars HACKERONE_API_USERNAME / HACKERONE_API_TOKEN.

Rate Limits:
    ~600 requests / 5 min.  We paginate at 100 results/page with a
    conservative sleep between pages.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import aiohttp
from loguru import logger
from pydantic import BaseModel, Field


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Convert value to float, returning *default* on failure."""
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


# ────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────


class H1Scope(BaseModel):
    """A single asset in a HackerOne program's scope."""

    asset_type: str = ""
    asset_identifier: str = ""
    eligible_for_bounty: bool = False
    eligible_for_submission: bool = True
    instruction: str | None = ""
    max_severity: str = ""


class H1Program(BaseModel):
    """Normalised HackerOne program."""

    id: str = ""
    handle: str = ""
    name: str = ""
    url: str = ""
    state: str = ""                        # "open_for_submission" etc.
    offers_bounties: bool = False
    response_efficiency_pct: float = 0.0
    bounty_table: list[dict[str, Any]] = Field(default_factory=list)
    scopes: list[H1Scope] = Field(default_factory=list)
    policy_html: str = ""
    started_accepting_at: str = ""
    last_updated: str = ""

    # Filtering helpers
    min_bounty: float = 0.0
    max_bounty: float = 0.0
    asset_count: int = 0


# ────────────────────────────────────────────────────────────
# Fetcher
# ────────────────────────────────────────────────────────────


class HackerOneProgramFetcher:
    """
    Fetches bug bounty programs from the HackerOne Hacker API.

    Usage::

        fetcher = HackerOneProgramFetcher()
        programs = await fetcher.fetch_programs()
        print(f"Fetched {len(programs)} programs")
    """

    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(
        self,
        api_identifier: str = "",
        api_token: str = "",
    ) -> None:
        self.api_identifier = api_identifier or os.getenv("HACKERONE_API_USERNAME", "")
        self.api_token = api_token or os.getenv("HACKERONE_API_TOKEN", "")

    @property
    def is_configured(self) -> bool:
        return bool(self.api_identifier and self.api_token)

    async def fetch_programs(
        self,
        max_pages: int = 50,
        page_size: int = 100,
    ) -> list[H1Program]:
        """
        Fetch all available bug bounty programs.

        Paginates through the Hacker API endpoint.
        Returns normalised H1Program objects.
        """
        if not self.is_configured:
            logger.warning(
                "HackerOne API credentials not configured — "
                "set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN"
            )
            return []

        programs: list[H1Program] = []
        page = 1

        try:
            auth = aiohttp.BasicAuth(self.api_identifier, self.api_token)
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(auth=auth, timeout=timeout) as session:
                while page <= max_pages:
                    url = (
                        f"{self.BASE_URL}/hackers/programs"
                        f"?page[size]={page_size}&page[number]={page}"
                    )

                    async with session.get(
                        url,
                        headers={"Accept": "application/json"},
                    ) as resp:
                        if resp.status == 401:
                            logger.error("HackerOne API: 401 Unauthorized — check credentials")
                            break
                        if resp.status == 429:
                            retry_after = int(resp.headers.get("Retry-After", "60"))
                            logger.warning(f"HackerOne rate-limited, sleeping {retry_after}s")
                            await asyncio.sleep(retry_after)
                            continue
                        if resp.status != 200:
                            logger.error(f"HackerOne API {resp.status}: {await resp.text()}")
                            break

                        data = await resp.json()
                        items = data.get("data", [])
                        if not items:
                            break

                        for item in items:
                            program = self._parse_program(item)
                            if program:
                                programs.append(program)

                        # Check for next page
                        links = data.get("links", {})
                        if not links.get("next"):
                            break

                        page += 1
                        await asyncio.sleep(0.5)  # Be respectful

            logger.info(f"HackerOne: fetched {len(programs)} programs ({page} pages)")

        except aiohttp.ClientError as e:
            logger.error(f"HackerOne fetch error: {e}")
        except Exception as e:
            logger.error(f"HackerOne unexpected error: {e}")

        return programs

    async def fetch_program_scopes(self, handle: str) -> list[H1Scope]:
        """Fetch detailed scope for a single program."""
        if not self.is_configured:
            return []

        scopes: list[H1Scope] = []
        try:
            auth = aiohttp.BasicAuth(self.api_identifier, self.api_token)
            timeout = aiohttp.ClientTimeout(total=15)

            async with aiohttp.ClientSession(auth=auth, timeout=timeout) as session:
                url = (
                    f"{self.BASE_URL}/hackers/programs/{handle}"
                    f"/structured_scopes?page[size]=100"
                )
                async with session.get(
                    url,
                    headers={"Accept": "application/json"},
                ) as resp:
                    if resp.status != 200:
                        return scopes

                    data = await resp.json()
                    for item in data.get("data", []):
                        attrs = item.get("attributes", {})
                        try:
                            scopes.append(H1Scope(
                                asset_type=attrs.get("asset_type", ""),
                                asset_identifier=attrs.get("asset_identifier", ""),
                                eligible_for_bounty=attrs.get("eligible_for_bounty", False),
                                eligible_for_submission=attrs.get("eligible_for_submission", True),
                                instruction=attrs.get("instruction") or "",
                                max_severity=attrs.get("max_severity") or "",
                            ))
                        except Exception as e:
                            logger.debug(f"Skipping malformed scope in {handle}: {e}")

        except Exception as e:
            logger.warning(f"Failed to fetch scopes for {handle}: {e}")

        return scopes

    # ─── Parsing ─────────────────────────────────────────

    def _parse_program(self, raw: dict[str, Any]) -> H1Program | None:
        """Parse a raw API program object into H1Program."""
        try:
            attrs = raw.get("attributes", {})
            program_id = raw.get("id", "")

            handle = attrs.get("handle", "")
            if not handle:
                return None

            # Parse bounty table for min/max bounty
            bounty_table: list[dict[str, Any]] = []
            min_bounty = 0.0
            max_bounty = 0.0

            rels = raw.get("relationships", {})
            bounty_data = rels.get("bounty_table", {}).get("data", [])
            if isinstance(bounty_data, list):
                for bt in bounty_data:
                    bt_attrs = bt.get("attributes", {})
                    try:
                        low = float(bt_attrs.get("low", 0))
                    except (TypeError, ValueError):
                        low = 0.0
                    try:
                        high = float(bt_attrs.get("high", 0))
                    except (TypeError, ValueError):
                        high = 0.0
                    bounty_table.append({"low": low, "high": high})
                    if low < min_bounty or min_bounty == 0:
                        min_bounty = low
                    if high > max_bounty:
                        max_bounty = high

            # Parse scopes from relationships if present
            scopes: list[H1Scope] = []
            scope_data = rels.get("structured_scopes", {}).get("data", [])
            if isinstance(scope_data, list):
                for sd in scope_data:
                    sd_attrs = sd.get("attributes", {})
                    if not sd_attrs:
                        continue
                    try:
                        scopes.append(H1Scope(
                            asset_type=sd_attrs.get("asset_type", ""),
                            asset_identifier=sd_attrs.get("asset_identifier", ""),
                            eligible_for_bounty=sd_attrs.get("eligible_for_bounty", False),
                            eligible_for_submission=sd_attrs.get("eligible_for_submission", True),
                            instruction=sd_attrs.get("instruction") or "",
                            max_severity=sd_attrs.get("max_severity") or "",
                        ))
                    except Exception:
                        pass

            return H1Program(
                id=str(program_id),
                handle=handle,
                name=attrs.get("name", handle),
                url=f"https://hackerone.com/{handle}",
                state=attrs.get("submission_state", attrs.get("state", "")),
                offers_bounties=attrs.get("offers_bounties", False),
                response_efficiency_pct=_safe_float(attrs.get("response_efficiency_percentage", 0)),
                bounty_table=bounty_table,
                scopes=scopes,
                started_accepting_at=attrs.get("started_accepting_at", ""),
                min_bounty=min_bounty,
                max_bounty=max_bounty,
                asset_count=len(scopes),
            )

        except Exception as e:
            logger.debug(f"Failed to parse H1 program: {e}")
            return None


__all__ = [
    "HackerOneProgramFetcher",
    "H1Program",
    "H1Scope",
]
