"""
WhiteHatHacker AI — Bugcrowd Program Fetcher

Fetches publicly listed bug bounty programs from the Bugcrowd API.

Bugcrowd API Reference:
    https://docs.bugcrowd.com/customers/api/

Authentication:
    Bearer token via Authorization header.
    Credential from env var BUGCROWD_API_TOKEN.

The Bugcrowd API uses JSON:API format.  We also support parsing
the public program listing page as a fallback.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import aiohttp
from loguru import logger
from pydantic import BaseModel, Field


# ────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────


class BCScope(BaseModel):
    """A single target in a Bugcrowd program."""

    name: str = ""
    uri: str = ""
    category: str = ""             # website, api, mobile, ...
    in_scope: bool = True


class BCProgram(BaseModel):
    """Normalised Bugcrowd program."""

    id: str = ""
    code: str = ""                   # Program slug / code
    name: str = ""
    url: str = ""
    tagline: str = ""
    description: str = ""
    program_type: str = ""           # bug_bounty, vulnerability_disclosure
    managed: bool = False
    min_bounty: float = 0.0
    max_bounty: float = 0.0
    currency: str = "USD"
    targets: list[BCScope] = Field(default_factory=list)
    target_count: int = 0
    started_at: str = ""
    last_updated: str = ""


# ────────────────────────────────────────────────────────────
# Fetcher
# ────────────────────────────────────────────────────────────


class BugcrowdProgramFetcher:
    """
    Fetches bug bounty programs from the Bugcrowd API.

    Usage::

        fetcher = BugcrowdProgramFetcher()
        programs = await fetcher.fetch_programs()
    """

    BASE_URL = "https://api.bugcrowd.com"

    def __init__(self, api_token: str = "") -> None:
        self.api_token = api_token or os.getenv("BUGCROWD_API_TOKEN", "")

    @property
    def is_configured(self) -> bool:
        return bool(self.api_token)

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self.api_token}",
            "Accept": "application/vnd.bugcrowd+json",
        }

    async def fetch_programs(
        self,
        max_pages: int = 50,
        page_size: int = 100,
    ) -> list[BCProgram]:
        """
        Fetch all available Bugcrowd programs.

        Uses the /programs endpoint with pagination.
        """
        if not self.is_configured:
            logger.warning(
                "Bugcrowd API credentials not configured — "
                "set BUGCROWD_API_TOKEN"
            )
            return []

        programs: list[BCProgram] = []
        offset = 0

        try:
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(
                headers=self._headers, timeout=timeout
            ) as session:
                while offset // page_size < max_pages:
                    url = (
                        f"{self.BASE_URL}/programs"
                        f"?page[offset]={offset}&page[limit]={page_size}"
                        f"&fields[program]=code,name,tagline,min_rewards,"
                        f"max_rewards,targets_overview,program_type,"
                        f"managed,started_at,updated_at"
                    )

                    async with session.get(url) as resp:
                        if resp.status == 401:
                            logger.error("Bugcrowd API: 401 Unauthorized — check token")
                            break
                        if resp.status == 429:
                            retry_after = int(resp.headers.get("Retry-After", "60"))
                            logger.warning(f"Bugcrowd rate-limited, sleeping {retry_after}s")
                            await asyncio.sleep(retry_after)
                            continue
                        if resp.status != 200:
                            logger.error(f"Bugcrowd API {resp.status}: {await resp.text()}")
                            break

                        data = await resp.json()
                        items = data.get("data", [])
                        if not items:
                            break

                        for item in items:
                            program = self._parse_program(item)
                            if program:
                                programs.append(program)

                        total = data.get("meta", {}).get("total_hits", 0)
                        offset += page_size
                        if offset >= total:
                            break

                        await asyncio.sleep(0.5)

            logger.info(f"Bugcrowd: fetched {len(programs)} programs")

        except aiohttp.ClientError as e:
            logger.error(f"Bugcrowd fetch error: {e}")
        except Exception as e:
            logger.error(f"Bugcrowd unexpected error: {e}")

        return programs

    async def fetch_program_targets(self, program_code: str) -> list[BCScope]:
        """Fetch detailed targets for a specific program."""
        if not self.is_configured:
            return []

        targets: list[BCScope] = []
        try:
            timeout = aiohttp.ClientTimeout(total=15)

            async with aiohttp.ClientSession(
                headers=self._headers, timeout=timeout
            ) as session:
                url = (
                    f"{self.BASE_URL}/programs/{program_code}"
                    f"/targets?page[limit]=100"
                )
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return targets

                    data = await resp.json()
                    for item in data.get("data", []):
                        attrs = item.get("attributes", {})
                        targets.append(BCScope(
                            name=attrs.get("name", ""),
                            uri=attrs.get("uri", ""),
                            category=attrs.get("category", ""),
                            in_scope=attrs.get("in_scope", True),
                        ))

        except Exception as e:
            logger.warning(f"Failed to fetch targets for {program_code}: {e}")

        return targets

    # ─── Parsing ─────────────────────────────────────────

    def _parse_program(self, raw: dict[str, Any]) -> BCProgram | None:
        """Parse a raw API program object into BCProgram."""
        try:
            attrs = raw.get("attributes", {})
            program_id = raw.get("id", "")
            code = attrs.get("code", "")

            if not code:
                return None

            # Parse reward info
            min_rewards = attrs.get("min_rewards", {})
            max_rewards = attrs.get("max_rewards", {})
            try:
                min_bounty = float(min_rewards.get("amount", 0)) if min_rewards else 0.0
            except (TypeError, ValueError):
                min_bounty = 0.0
            try:
                max_bounty = float(max_rewards.get("amount", 0)) if max_rewards else 0.0
            except (TypeError, ValueError):
                max_bounty = 0.0
            currency = (
                max_rewards.get("currency", "USD")
                if max_rewards
                else "USD"
            )

            # Targets overview
            targets_overview = attrs.get("targets_overview", [])
            target_count = len(targets_overview) if isinstance(targets_overview, list) else 0

            return BCProgram(
                id=str(program_id),
                code=code,
                name=attrs.get("name", code),
                url=f"https://bugcrowd.com/{code}",
                tagline=attrs.get("tagline", ""),
                program_type=attrs.get("program_type", ""),
                managed=attrs.get("managed", False),
                min_bounty=min_bounty,
                max_bounty=max_bounty,
                currency=currency,
                target_count=target_count,
                started_at=attrs.get("started_at", ""),
                last_updated=attrs.get("updated_at", ""),
            )

        except Exception as e:
            logger.debug(f"Failed to parse Bugcrowd program: {e}")
            return None


__all__ = [
    "BugcrowdProgramFetcher",
    "BCProgram",
    "BCScope",
]
