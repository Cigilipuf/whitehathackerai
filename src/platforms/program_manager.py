"""
WhiteHatHacker AI — Program Manager

Central management layer for bug bounty programs from all
platforms. Handles:

- Fetching from HackerOne + Bugcrowd APIs
- Local JSON cache with daily refresh (24-hour TTL)
- Unified BountyProgram model for GUI consumption
- Search / filter / sort helpers
- Scope extraction for bot's scope_validator

File structure::

    output/programs/
    ├── hackerone_programs.json     # Cached H1 programs
    ├── bugcrowd_programs.json     # Cached BC programs
    └── cache_meta.json            # Last update timestamps
"""

from __future__ import annotations

import json
import time
from enum import StrEnum
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, Field


# ────────────────────────────────────────────────────────────
# Enumerations
# ────────────────────────────────────────────────────────────


class PlatformSource(StrEnum):
    """Bug bounty platform."""

    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"


# ────────────────────────────────────────────────────────────
# Unified Data Models
# ────────────────────────────────────────────────────────────


class ProgramScope(BaseModel):
    """A single in-scope asset, normalised across platforms."""

    asset_type: str = ""          # domain, url, api, cidr, mobile, ...
    identifier: str = ""          # *.example.com,  10.0.0.0/24, etc.
    eligible_for_bounty: bool = False
    notes: str = ""


class BountyProgram(BaseModel):
    """
    Unified bug bounty program model — works for both H1 and BC.

    This is what the GUI displays and the bot works with.
    """

    id: str = ""
    platform: PlatformSource = PlatformSource.HACKERONE
    handle: str = ""               # Unique program slug
    name: str = ""
    url: str = ""                  # Platform URL
    description: str = ""

    # Bounty information
    offers_bounties: bool = False
    min_bounty: float = 0.0
    max_bounty: float = 0.0
    currency: str = "USD"

    # Scope
    scopes: list[ProgramScope] = Field(default_factory=list)
    scope_count: int = 0

    # Program metadata
    program_type: str = ""         # bug_bounty, vdp
    state: str = ""                # open, paused
    response_efficiency: float = 0.0
    started_at: str = ""

    # Local metadata
    last_fetched: float = 0.0
    favourite: bool = False
    notes: str = ""
    tags: list[str] = Field(default_factory=list)


# ────────────────────────────────────────────────────────────
# Cache Metadata
# ────────────────────────────────────────────────────────────

CACHE_TTL_SECONDS = 86400  # 24 hours


class CacheMeta(BaseModel):
    """Tracks cache freshness per platform."""

    hackerone_last_update: float = 0.0
    bugcrowd_last_update: float = 0.0
    intigriti_last_update: float = 0.0
    hackerone_count: int = 0
    bugcrowd_count: int = 0
    intigriti_count: int = 0

    def is_stale(self, platform: PlatformSource) -> bool:
        ts_map = {
            PlatformSource.HACKERONE: self.hackerone_last_update,
            PlatformSource.BUGCROWD: self.bugcrowd_last_update,
            PlatformSource.INTIGRITI: self.intigriti_last_update,
        }
        ts = ts_map.get(platform, 0.0)
        return (time.time() - ts) > CACHE_TTL_SECONDS


# ────────────────────────────────────────────────────────────
# Program Manager
# ────────────────────────────────────────────────────────────


class ProgramManager:
    """
    Central manager for bug bounty programs.

    Fetches from platform APIs, caches locally, provides search/filter,
    and refreshes daily.

    Usage::

        pm = ProgramManager()
        await pm.refresh()                     # Fetch from APIs
        programs = pm.search("shopify")        # Search
        bounty = pm.filter(min_bounty=500)     # Filter
        program = pm.get("hackerone", "github") # Get specific
    """

    def __init__(self, cache_dir: str = "output/programs") -> None:
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        self._programs: dict[str, BountyProgram] = {}   # key = "platform:handle"
        self._cache_meta = CacheMeta()
        self._favourites: set[str] = set()

        # Load cached data on init
        self._load_cache()

        logger.info(
            f"ProgramManager initialized | cached={len(self._programs)} | "
            f"cache_dir={self._cache_dir}"
        )

    # ─── Refresh / Fetch ─────────────────────────────────

    async def refresh(
        self,
        force: bool = False,
        platforms: list[PlatformSource] | None = None,
    ) -> dict[str, int]:
        """
        Refresh programs from APIs.

        Respects 24-hour cache TTL unless force=True.
        Returns dict of counts per platform.
        """
        platforms = platforms or [
            PlatformSource.HACKERONE,
            PlatformSource.BUGCROWD,
            PlatformSource.INTIGRITI,
        ]
        counts: dict[str, int] = {}

        for platform in platforms:
            if not force and not self._cache_meta.is_stale(platform):
                counts[platform] = self._count_for_platform(platform)
                logger.debug(f"{platform}: cache is fresh, skipping fetch")
                continue

            try:
                if platform == PlatformSource.HACKERONE:
                    n = await self._fetch_hackerone()
                elif platform == PlatformSource.BUGCROWD:
                    n = await self._fetch_bugcrowd()
                elif platform == PlatformSource.INTIGRITI:
                    n = await self._fetch_intigriti()
                else:
                    n = 0
                counts[platform] = n
            except Exception as e:
                logger.error(f"Failed to refresh {platform}: {e}")
                counts[platform] = self._count_for_platform(platform)

        self._save_cache()
        return counts

    async def _fetch_hackerone(self) -> int:
        """Fetch from HackerOne API."""
        from src.platforms.hackerone_programs import HackerOneProgramFetcher

        fetcher = HackerOneProgramFetcher()
        if not fetcher.is_configured:
            logger.info("HackerOne: no credentials, skipping")
            return self._count_for_platform(PlatformSource.HACKERONE)

        h1_programs = await fetcher.fetch_programs()

        for h1 in h1_programs:
            # Convert scopes
            scopes = [
                ProgramScope(
                    asset_type=s.asset_type,
                    identifier=s.asset_identifier,
                    eligible_for_bounty=s.eligible_for_bounty,
                    notes=s.instruction,
                )
                for s in h1.scopes
            ]

            key = f"hackerone:{h1.handle}"
            existing = self._programs.get(key)

            self._programs[key] = BountyProgram(
                id=h1.id,
                platform=PlatformSource.HACKERONE,
                handle=h1.handle,
                name=h1.name,
                url=h1.url,
                offers_bounties=h1.offers_bounties,
                min_bounty=h1.min_bounty,
                max_bounty=h1.max_bounty,
                scopes=scopes,
                scope_count=len(scopes) or h1.asset_count,
                state=h1.state,
                response_efficiency=h1.response_efficiency_pct,
                started_at=h1.started_accepting_at,
                last_fetched=time.time(),
                favourite=existing.favourite if existing else False,
                notes=existing.notes if existing else "",
                tags=existing.tags if existing else [],
            )

        self._cache_meta.hackerone_last_update = time.time()
        self._cache_meta.hackerone_count = len(h1_programs)
        count = len(h1_programs)
        logger.info(f"HackerOne: refreshed {count} programs")
        return count

    async def _fetch_bugcrowd(self) -> int:
        """Fetch from Bugcrowd API."""
        from src.platforms.bugcrowd_programs import BugcrowdProgramFetcher

        fetcher = BugcrowdProgramFetcher()
        if not fetcher.is_configured:
            logger.info("Bugcrowd: no credentials, skipping")
            return self._count_for_platform(PlatformSource.BUGCROWD)

        bc_programs = await fetcher.fetch_programs()

        for bc in bc_programs:
            targets = [
                ProgramScope(
                    asset_type=t.category,
                    identifier=t.uri or t.name,
                    eligible_for_bounty=True,
                    notes="",
                )
                for t in bc.targets
            ]

            key = f"bugcrowd:{bc.code}"
            existing = self._programs.get(key)

            self._programs[key] = BountyProgram(
                id=bc.id,
                platform=PlatformSource.BUGCROWD,
                handle=bc.code,
                name=bc.name,
                url=bc.url,
                description=bc.tagline,
                offers_bounties=bc.max_bounty > 0,
                min_bounty=bc.min_bounty,
                max_bounty=bc.max_bounty,
                currency=bc.currency,
                scopes=targets,
                scope_count=len(targets) or bc.target_count,
                program_type=bc.program_type,
                started_at=bc.started_at,
                last_fetched=time.time(),
                favourite=existing.favourite if existing else False,
                notes=existing.notes if existing else "",
                tags=existing.tags if existing else [],
            )

        self._cache_meta.bugcrowd_last_update = time.time()
        self._cache_meta.bugcrowd_count = len(bc_programs)
        count = len(bc_programs)
        logger.info(f"Bugcrowd: refreshed {count} programs")
        return count

    async def _fetch_intigriti(self) -> int:
        """Fetch from Intigriti API."""
        from src.platforms.intigriti_programs import IntigritiFetcher

        fetcher = IntigritiFetcher()
        if not fetcher.is_configured:
            logger.info("Intigriti: no credentials, skipping")
            return self._count_for_platform(PlatformSource.INTIGRITI)

        inti_programs = await fetcher.fetch_programs()

        for ip in inti_programs:
            scopes = [
                ProgramScope(
                    asset_type=d.type,
                    identifier=d.endpoint,
                    eligible_for_bounty=d.in_scope,
                    notes=d.description,
                )
                for d in ip.domains
            ]

            key = f"intigriti:{ip.handle}"
            existing = self._programs.get(key)

            self._programs[key] = BountyProgram(
                id=ip.id,
                platform=PlatformSource.INTIGRITI,
                handle=ip.handle,
                name=ip.name,
                url=ip.url,
                description=ip.description,
                offers_bounties=ip.max_bounty > 0,
                min_bounty=ip.min_bounty,
                max_bounty=ip.max_bounty,
                currency=ip.currency,
                scopes=scopes,
                scope_count=len(scopes) or ip.domain_count,
                program_type=ip.program_type,
                state=ip.status,
                started_at=ip.started_at,
                last_fetched=time.time(),
                favourite=existing.favourite if existing else False,
                notes=existing.notes if existing else "",
                tags=existing.tags if existing else [],
            )

        self._cache_meta.intigriti_last_update = time.time()
        self._cache_meta.intigriti_count = len(inti_programs)
        count = len(inti_programs)
        logger.info(f"Intigriti: refreshed {count} programs")
        return count

    # ─── Queries ─────────────────────────────────────────

    def get_all(
        self,
        platform: PlatformSource | None = None,
    ) -> list[BountyProgram]:
        """Get all programs, optionally filtered by platform."""
        programs = list(self._programs.values())
        if platform:
            programs = [p for p in programs if p.platform == platform]
        return programs

    def get(self, platform: str, handle: str) -> BountyProgram | None:
        """Get a specific program by platform and handle."""
        key = f"{platform}:{handle}"
        return self._programs.get(key)

    def search(
        self,
        query: str,
        platform: PlatformSource | None = None,
    ) -> list[BountyProgram]:
        """
        Search programs by name, handle, or description.
        Case-insensitive substring match.
        """
        q = query.lower()
        results: list[BountyProgram] = []

        for p in self._programs.values():
            if platform and p.platform != platform:
                continue

            searchable = f"{p.name} {p.handle} {p.description}".lower()
            scope_ids = " ".join(s.identifier for s in p.scopes).lower()

            if q in searchable or q in scope_ids:
                results.append(p)

        return results

    def filter(
        self,
        platform: PlatformSource | None = None,
        min_bounty: float = 0.0,
        offers_bounties: bool | None = None,
        favourites_only: bool = False,
        has_scope: bool = False,
    ) -> list[BountyProgram]:
        """Filter programs by criteria."""
        results: list[BountyProgram] = []

        for p in self._programs.values():
            if platform and p.platform != platform:
                continue
            if min_bounty > 0 and p.max_bounty < min_bounty:
                continue
            if offers_bounties is not None and p.offers_bounties != offers_bounties:
                continue
            if favourites_only and not p.favourite:
                continue
            if has_scope and p.scope_count == 0:
                continue
            results.append(p)

        return results

    def toggle_favourite(self, platform: str, handle: str) -> bool:
        """Toggle favourite status. Returns new state."""
        key = f"{platform}:{handle}"
        program = self._programs.get(key)
        if program:
            program.favourite = not program.favourite
            self._save_cache()
            return program.favourite
        return False

    def set_notes(self, platform: str, handle: str, notes: str) -> None:
        """Set notes for a program."""
        key = f"{platform}:{handle}"
        program = self._programs.get(key)
        if program:
            program.notes = notes
            self._save_cache()

    async def fetch_and_update_scopes(
        self, platform: str, handle: str,
    ) -> list[ProgramScope]:
        """
        Lazy-fetch scope details for a program whose scopes are empty.

        Calls the platform-specific scope API, updates the in-memory
        program object, and persists the cache so subsequent loads see
        the scopes immediately.

        Returns the fetched ``ProgramScope`` list (empty on failure).
        """
        key = f"{platform}:{handle}"
        program = self._programs.get(key)

        if platform in ("hackerone", PlatformSource.HACKERONE):
            from src.platforms.hackerone_programs import HackerOneProgramFetcher

            fetcher = HackerOneProgramFetcher()
            if not fetcher.is_configured:
                logger.warning("HackerOne API credentials not configured")
                return []

            h1_scopes = await fetcher.fetch_program_scopes(handle)
            scopes = [
                ProgramScope(
                    asset_type=s.asset_type,
                    identifier=s.asset_identifier,
                    eligible_for_bounty=s.eligible_for_bounty,
                    notes=s.instruction,
                )
                for s in h1_scopes
            ]
        else:
            logger.debug(f"Scope lazy-fetch not supported for platform={platform}")
            return []

        if program and scopes:
            program.scopes = scopes
            program.scope_count = len(scopes)
            self._save_cache()
            logger.info(
                f"Lazy-fetched {len(scopes)} scopes for {platform}:{handle}"
            )

        return scopes

    def get_scope_domains(self, platform: str, handle: str) -> list[str]:
        """
        Extract in-scope domain identifiers for the bot's scope validator.

        Returns list of strings like "*.example.com", "api.example.com", etc.
        """
        program = self.get(platform, handle)
        if not program:
            return []

        return [
            s.identifier
            for s in program.scopes
            if s.identifier and s.eligible_for_bounty
        ]

    @property
    def total_count(self) -> int:
        return len(self._programs)

    @property
    def cache_meta(self) -> CacheMeta:
        return self._cache_meta

    # ─── Cache I/O ───────────────────────────────────────

    def _load_cache(self) -> None:
        """Load cached programs from disk."""
        meta_path = self._cache_dir / "cache_meta.json"
        if meta_path.exists():
            try:
                self._cache_meta = CacheMeta.model_validate_json(
                    meta_path.read_text()
                )
            except Exception as e:
                logger.warning(f"Failed to load cache meta: {e}")

        for platform in PlatformSource:
            cache_file = self._cache_dir / f"{platform}_programs.json"
            if not cache_file.exists():
                continue
            try:
                data = json.loads(cache_file.read_text())
                for item in data:
                    program = BountyProgram.model_validate(item)
                    key = f"{program.platform}:{program.handle}"
                    self._programs[key] = program
            except Exception as e:
                logger.warning(f"Failed to load {platform} cache: {e}")

        if self._programs:
            logger.debug(f"Loaded {len(self._programs)} programs from cache")

    def _save_cache(self) -> None:
        """Persist current programs to disk."""
        try:
            # Save per-platform files
            for platform in PlatformSource:
                programs = [
                    p.model_dump()
                    for p in self._programs.values()
                    if p.platform == platform
                ]
                cache_file = self._cache_dir / f"{platform}_programs.json"
                cache_file.write_text(
                    json.dumps(programs, indent=2, ensure_ascii=False)
                )

            # Save meta
            meta_path = self._cache_dir / "cache_meta.json"
            meta_path.write_text(self._cache_meta.model_dump_json(indent=2))

        except Exception as e:
            logger.error(f"Failed to save program cache: {e}")

    def _count_for_platform(self, platform: PlatformSource) -> int:
        return sum(
            1 for p in self._programs.values() if p.platform == platform
        )


__all__ = [
    "ProgramManager",
    "BountyProgram",
    "ProgramScope",
    "PlatformSource",
    "CacheMeta",
    "CACHE_TTL_SECONDS",
]
