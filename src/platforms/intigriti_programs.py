"""
WhiteHatHacker AI — Intigriti Program Fetcher

Fetches publicly listed bug bounty programs from the Intigriti
External API (v2).

Intigriti API Reference:
    GET /external/researcher/v2/programs
    https://app.intigriti.com/api-docs

Authentication:
    Bearer token via Authorization header.
    Credential from env var INTIGRITI_API_TOKEN.

    Alternatively, an API key + secret pair can be provided via
    INTIGRITI_CLIENT_ID / INTIGRITI_CLIENT_SECRET for OAuth2
    client-credentials flow.

Rate Limits:
    Varies — we paginate at 25 results/page with a conservative
    sleep between pages.
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


class IntiScope(BaseModel):
    """A single in-scope target on Intigriti."""

    endpoint: str = ""          # e.g. *.example.com
    type: str = ""              # domain, url, api, ip_range, mobile, ...
    description: str = ""
    tier: str = ""              # tier1, tier2, tier3 — severity tiers
    in_scope: bool = True


class IntiProgram(BaseModel):
    """Normalised Intigriti program."""

    id: str = ""
    company_handle: str = ""        # Company slug
    handle: str = ""                # Program slug
    name: str = ""
    url: str = ""
    description: str = ""

    # Bounty information
    min_bounty: float = 0.0
    max_bounty: float = 0.0
    currency: str = "EUR"
    program_type: str = ""          # bug_bounty, vdp
    confidentiality_level: str = "" # public, private, invite_only

    # Scope
    domains: list[IntiScope] = Field(default_factory=list)
    domain_count: int = 0

    # Metadata
    status: str = ""                # open, closed, suspended
    started_at: str = ""
    last_updated: str = ""


# ────────────────────────────────────────────────────────────
# Fetcher
# ────────────────────────────────────────────────────────────


class IntigritiFetcher:
    """
    Fetches bug bounty programs from the Intigriti API.

    Supports two authentication methods:
    1. Direct bearer token (INTIGRITI_API_TOKEN)
    2. OAuth2 client credentials (INTIGRITI_CLIENT_ID + INTIGRITI_CLIENT_SECRET)

    Usage::

        fetcher = IntigritiFetcher()
        programs = await fetcher.fetch_programs()
        print(f"Fetched {len(programs)} programs")
    """

    BASE_URL = "https://app.intigriti.com/api"
    AUTH_URL = "https://login.intigriti.com/connect/token"

    def __init__(
        self,
        api_token: str = "",
        client_id: str = "",
        client_secret: str = "",
    ) -> None:
        self.api_token = api_token or os.getenv("INTIGRITI_API_TOKEN", "")
        self.client_id = client_id or os.getenv("INTIGRITI_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("INTIGRITI_CLIENT_SECRET", "")
        self._oauth_token: str = ""

    @property
    def is_configured(self) -> bool:
        """Check if at least one auth method is available."""
        return bool(
            self.api_token or (self.client_id and self.client_secret)
        )

    async def _get_token(self, session: aiohttp.ClientSession) -> str:
        """
        Obtain a bearer token.

        If a direct API token is set, return it.
        Otherwise, use OAuth2 client credentials flow.
        """
        if self.api_token:
            return self.api_token

        if self._oauth_token:
            return self._oauth_token

        if not (self.client_id and self.client_secret):
            return ""

        try:
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
            async with session.post(self.AUTH_URL, data=data) as resp:
                if resp.status != 200:
                    logger.error(
                        f"Intigriti OAuth2 failed: {resp.status} "
                        f"{await resp.text()}"
                    )
                    return ""

                body = await resp.json()
                self._oauth_token = body.get("access_token", "")
                logger.debug("Intigriti OAuth2 token acquired")
                return self._oauth_token

        except Exception as e:
            logger.error(f"Intigriti OAuth2 error: {e}")
            return ""

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    # ─── Program List ────────────────────────────────────

    async def fetch_programs(
        self,
        max_pages: int = 50,
        page_size: int = 25,
    ) -> list[IntiProgram]:
        """
        Fetch all available Intigriti programs.

        Uses /external/researcher/v2/programs with offset pagination.
        Falls back to the public program listing endpoint if the
        researcher endpoint is unavailable.
        """
        if not self.is_configured:
            logger.warning(
                "Intigriti API credentials not configured — "
                "set INTIGRITI_API_TOKEN or "
                "INTIGRITI_CLIENT_ID + INTIGRITI_CLIENT_SECRET"
            )
            return []

        programs: list[IntiProgram] = []

        try:
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                token = await self._get_token(session)
                if not token:
                    logger.error("Intigriti: could not obtain API token")
                    return []

                headers = self._auth_headers(token)
                page = 0

                while page < max_pages:
                    # Primary: researcher v2 endpoint
                    url = (
                        f"{self.BASE_URL}/external/researcher/v2/programs"
                        f"?offset={page * page_size}&limit={page_size}"
                    )

                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 401:
                            logger.error(
                                "Intigriti API: 401 Unauthorized — "
                                "check token / credentials"
                            )
                            break
                        if resp.status == 429:
                            retry = int(resp.headers.get("Retry-After", "60"))
                            logger.warning(
                                f"Intigriti rate-limited, sleeping {retry}s"
                            )
                            await asyncio.sleep(retry)
                            continue
                        if resp.status == 404:
                            # Try fallback endpoint
                            programs = await self._fetch_public_listing(
                                session, headers, max_pages, page_size
                            )
                            return programs
                        if resp.status != 200:
                            body = await resp.text()
                            logger.error(
                                f"Intigriti API {resp.status}: {body[:300]}"
                            )
                            break

                        data = await resp.json()
                        # Response may be a dict with 'records' or a flat list
                        items = (
                            data.get("records", data)
                            if isinstance(data, dict)
                            else data
                        )
                        if not isinstance(items, list) or not items:
                            break

                        for item in items:
                            program = self._parse_program(item)
                            if program:
                                programs.append(program)

                        # Pagination check
                        total = (
                            data.get("totalRecordCount", 0)
                            if isinstance(data, dict)
                            else 0
                        )
                        page += 1
                        if total and (page * page_size) >= total:
                            break
                        if len(items) < page_size:
                            break

                        await asyncio.sleep(0.5)

            logger.info(f"Intigriti: fetched {len(programs)} programs")

        except aiohttp.ClientError as e:
            logger.error(f"Intigriti fetch error: {e}")
        except Exception as e:
            logger.error(f"Intigriti unexpected error: {e}")

        return programs

    async def _fetch_public_listing(
        self,
        session: aiohttp.ClientSession,
        headers: dict[str, str],
        max_pages: int,
        page_size: int,
    ) -> list[IntiProgram]:
        """
        Fallback: try the /core/researcher/programs endpoint.

        Some API versions use a different path.
        """
        programs: list[IntiProgram] = []
        page = 0

        try:
            while page < max_pages:
                url = (
                    f"{self.BASE_URL}/core/researcher/programs"
                    f"?offset={page * page_size}&limit={page_size}"
                )
                async with session.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        break
                    data = await resp.json()
                    items = (
                        data.get("records", data)
                        if isinstance(data, dict)
                        else data
                    )
                    if not isinstance(items, list) or not items:
                        break

                    for item in items:
                        program = self._parse_program(item)
                        if program:
                            programs.append(program)

                    if len(items) < page_size:
                        break
                    page += 1
                    await asyncio.sleep(0.5)

        except Exception as e:
            logger.warning(f"Intigriti public listing fallback error: {e}")

        return programs

    # ─── Program Detail ──────────────────────────────────

    async def fetch_program_domains(
        self,
        company_handle: str,
        program_handle: str,
    ) -> list[IntiScope]:
        """Fetch detailed in-scope domains for a specific program."""
        if not self.is_configured:
            return []

        domains: list[IntiScope] = []
        try:
            timeout = aiohttp.ClientTimeout(total=15)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                token = await self._get_token(session)
                if not token:
                    return []

                headers = self._auth_headers(token)
                url = (
                    f"{self.BASE_URL}/external/researcher/v2/programs"
                    f"/{company_handle}/{program_handle}"
                )

                async with session.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        return domains

                    data = await resp.json()
                    raw_domains = data.get("domains", [])

                    for d in raw_domains:
                        domain = self._parse_domain(d)
                        if domain:
                            domains.append(domain)

        except Exception as e:
            logger.warning(
                f"Failed to fetch domains for "
                f"{company_handle}/{program_handle}: {e}"
            )

        return domains

    # ─── Parsing ─────────────────────────────────────────

    def _parse_program(self, raw: dict[str, Any]) -> IntiProgram | None:
        """Parse a raw API program object into IntiProgram."""
        try:
            program_id = raw.get("programId", raw.get("id", ""))
            company_handle = raw.get("companyHandle", "")
            handle = raw.get("handle", raw.get("programHandle", ""))

            if not handle:
                return None

            name = raw.get("name", handle)

            # Bounty range
            try:
                min_bounty = float(raw.get("minBounty", 0) or 0)
            except (TypeError, ValueError):
                min_bounty = 0.0
            try:
                max_bounty = float(raw.get("maxBounty", 0) or 0)
            except (TypeError, ValueError):
                max_bounty = 0.0

            # Fallback: bounty table / reward range
            if max_bounty == 0:
                reward_range = raw.get("rewardRange", {})
                if reward_range:
                    try:
                        min_bounty = float(reward_range.get("min", 0) or 0)
                    except (TypeError, ValueError):
                        min_bounty = 0.0
                    try:
                        max_bounty = float(reward_range.get("max", 0) or 0)
                    except (TypeError, ValueError):
                        max_bounty = 0.0

            currency = raw.get("currency", "EUR") or "EUR"

            # Confidentiality
            conf_level = raw.get("confidentialityLevel", {})
            if isinstance(conf_level, dict):
                conf_str = conf_level.get("value", "public")
            else:
                conf_str = str(conf_level) if conf_level else "public"

            # Status
            status_raw = raw.get("status", {})
            if isinstance(status_raw, dict):
                status = status_raw.get("value", "open")
            else:
                status = str(status_raw) if status_raw else "open"

            # Type
            type_raw = raw.get("type", {})
            if isinstance(type_raw, dict):
                program_type = type_raw.get("value", "bug_bounty")
            else:
                program_type = str(type_raw) if type_raw else "bug_bounty"

            # Domains
            raw_domains = raw.get("domains", [])
            domains: list[IntiScope] = []
            for d in raw_domains if isinstance(raw_domains, list) else []:
                domain = self._parse_domain(d)
                if domain:
                    domains.append(domain)

            url = (
                f"https://app.intigriti.com/researcher/programs"
                f"/{company_handle}/{handle}/detail"
                if company_handle
                else f"https://app.intigriti.com/researcher/programs/{handle}"
            )

            return IntiProgram(
                id=str(program_id),
                company_handle=company_handle,
                handle=handle,
                name=name,
                url=url,
                description=raw.get("description", ""),
                min_bounty=min_bounty,
                max_bounty=max_bounty,
                currency=currency,
                program_type=program_type,
                confidentiality_level=conf_str,
                domains=domains,
                domain_count=len(domains) or raw.get("domainCount", 0),
                status=status,
                started_at=raw.get("startDate", ""),
                last_updated=raw.get("lastUpdated", ""),
            )

        except Exception as e:
            logger.debug(f"Failed to parse Intigriti program: {e}")
            return None

    def _parse_domain(self, raw: dict[str, Any]) -> IntiScope | None:
        """Parse a raw domain/target into IntiScope."""
        try:
            # Intigriti API uses 'endpoint' for the target URL/domain
            endpoint = raw.get("endpoint", raw.get("content", ""))
            if not endpoint:
                return None

            # Type mapping
            type_raw = raw.get("type", {})
            if isinstance(type_raw, dict):
                scope_type = type_raw.get("value", "domain")
            else:
                scope_type = str(type_raw) if type_raw else "domain"

            # Tier
            tier_raw = raw.get("tier", {})
            if isinstance(tier_raw, dict):
                tier = tier_raw.get("value", "")
            else:
                tier = str(tier_raw) if tier_raw else ""

            return IntiScope(
                endpoint=endpoint,
                type=scope_type,
                description=raw.get("description", ""),
                tier=tier,
                in_scope=True,
            )

        except Exception as e:
            logger.debug(f"Failed to parse Intigriti domain: {e}")
            return None


__all__ = [
    "IntigritiFetcher",
    "IntiProgram",
    "IntiScope",
]
