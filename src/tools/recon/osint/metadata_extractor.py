"""
WhiteHatHacker AI — Metadata Extractor (V7-T1-5)

Hedef sitedeki dokümanlardan (PDF, DOC, XLS, PPT, vb.) metadata çıkarır:
  - Creator/Author isimleri (internal kullanıcı keşfi)
  - Software bilgisi (versiyon tespiti)
  - Internal path sızıntıları
  - Email adresleri

İki aşama:
  1. Google dorking ile doküman URL'leri keşfet
  2. exiftool ile metadata parse et
"""

from __future__ import annotations

import asyncio
import json
import re
import tempfile
from pathlib import Path
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

_DOC_EXTENSIONS = ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods")
_MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024  # 10 MB
_INTERESTING_TAGS = (
    "Author", "Creator", "Producer", "Company", "Manager",
    "Last Modified By", "Software", "Application",
    "Template", "Directory",
)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_INTERNAL_PATH_RE = re.compile(
    r"(?:[A-Z]:\\|/home/|/Users/|/var/|/opt/|/etc/|/tmp/|\\\\)[^\s\"'<>]{5,}",
)


class MetadataExtractor(SecurityTool):
    """
    Download public documents from a target domain and extract metadata
    using exiftool. Reports author names, software versions, internal
    paths, and email addresses that may leak sensitive information.
    """

    name = "metadata_extractor"
    category = ToolCategory.RECON_OSINT
    description = "Document metadata extractor (exiftool-based)"
    binary_name = "exiftool"
    requires_root = False
    risk_level = RiskLevel.SAFE

    def is_available(self) -> bool:
        import shutil
        return shutil.which("exiftool") is not None

    async def run(
        self, target: str, options: dict[str, Any] | None = None,
        profile: ScanProfile | None = None,
    ) -> ToolResult:
        options = options or {}
        doc_urls: list[str] = options.get("document_urls", [])
        max_files: int = options.get("max_files", 20)

        if not doc_urls:
            doc_urls = await self._discover_documents(target, max_files)

        all_meta: list[dict[str, Any]] = []
        findings: list[Finding] = []

        for url in doc_urls[:max_files]:
            meta = await self._extract_metadata(url)
            if meta:
                all_meta.append({"url": url, **meta})

        # Aggregate interesting leaks
        authors: set[str] = set()
        software: set[str] = set()
        emails: set[str] = set()
        internal_paths: set[str] = set()

        for entry in all_meta:
            for tag in _INTERESTING_TAGS:
                val = entry.get(tag, "")
                if not val:
                    continue
                if tag in ("Author", "Creator", "Last Modified By", "Company", "Manager"):
                    authors.add(val)
                if tag in ("Software", "Producer", "Application"):
                    software.add(val)

            raw_str = json.dumps(entry)
            emails.update(_EMAIL_RE.findall(raw_str))
            internal_paths.update(_INTERNAL_PATH_RE.findall(raw_str))

        if authors:
            findings.append(Finding(
                title=f"Metadata: {len(authors)} author/creator names leaked",
                severity=SeverityLevel.LOW,
                confidence=80,
                target=target,
                description="Author names found in document metadata:\n" + "\n".join(f"  - {a}" for a in sorted(authors)),
                evidence={"authors": sorted(authors)},
                tool_name=self.name,
            ))

        if internal_paths:
            findings.append(Finding(
                title=f"Metadata: {len(internal_paths)} internal paths leaked",
                severity=SeverityLevel.LOW,
                confidence=75,
                target=target,
                description="Internal paths found in metadata:\n" + "\n".join(f"  - {p}" for p in sorted(internal_paths)),
                evidence={"paths": sorted(internal_paths)},
                tool_name=self.name,
            ))

        if emails:
            findings.append(Finding(
                title=f"Metadata: {len(emails)} email addresses found",
                severity=SeverityLevel.INFO,
                confidence=85,
                target=target,
                description="Emails:\n" + "\n".join(f"  - {e}" for e in sorted(emails)),
                evidence={"emails": sorted(emails)},
                tool_name=self.name,
            ))

        if software:
            findings.append(Finding(
                title=f"Metadata: {len(software)} software versions identified",
                severity=SeverityLevel.INFO,
                confidence=70,
                target=target,
                description="Software:\n" + "\n".join(f"  - {s}" for s in sorted(software)),
                evidence={"software": sorted(software)},
                tool_name=self.name,
            ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output=json.dumps(all_meta, indent=2, default=str),
            findings=findings,
            metadata={
                "documents_processed": len(all_meta),
                "authors": sorted(authors),
                "emails": sorted(emails),
                "paths": sorted(internal_paths),
                "software": sorted(software),
            },
        )

    async def _discover_documents(self, domain: str, limit: int) -> list[str]:
        """Use search engine dorking to discover document URLs."""
        filetypes = " OR ".join(f"filetype:{ext}" for ext in _DOC_EXTENSIONS)
        query = f"site:{domain} ({filetypes})"
        logger.debug(f"[metadata] Doc discovery query: {query}")

        # Use httpx to query DuckDuckGo lite (no API key needed)
        urls: list[str] = []
        try:
            params = {"q": query}
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get("https://lite.duckduckgo.com/lite/", params=params)
                if resp.status_code == 200:
                    # Extract URLs with doc extensions
                    for match in re.finditer(r'https?://[^\s"\'<>]+', resp.text):
                        url = match.group(0)
                        if any(url.lower().endswith(f".{ext}") for ext in _DOC_EXTENSIONS):
                            if domain.lower() in url.lower():
                                urls.append(url)
        except Exception as exc:
            logger.warning(f"[metadata] Document discovery failed: {exc}")

        return urls[:limit]

    async def _extract_metadata(self, url: str) -> dict[str, Any] | None:
        """Download file and run exiftool on it."""
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return None
                if len(resp.content) > _MAX_DOWNLOAD_SIZE:
                    logger.debug(f"[metadata] Skipping {url}: too large")
                    return None

            with tempfile.NamedTemporaryFile(suffix=Path(url).suffix, delete=True) as tmp:
                tmp.write(resp.content)
                tmp.flush()

                proc = await asyncio.create_subprocess_exec(
                    "exiftool", "-json", tmp.name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                data = json.loads(stdout.decode())
                return data[0] if data else None

        except Exception as exc:
            logger.debug(f"[metadata] Failed to extract from {url}: {exc}")
            return None

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        try:
            data = json.loads(raw_output)
        except (json.JSONDecodeError, TypeError):
            return []
        return [Finding(
            title=f"Metadata extracted from {len(data)} documents",
            severity=SeverityLevel.INFO,
            confidence=60,
            target=target,
            description=raw_output[:2000],
            tool_name=self.name,
        )] if data else []

    def build_command(self, target: str, options: dict | None = None, profile: ScanProfile | None = None) -> list[str]:
        return []  # Async Python — no single command
