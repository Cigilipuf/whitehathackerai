"""
WhiteHatHacker AI — Output Organizer

Hierarchical file organization system that ensures every scan's
output is cleanly separated by platform, program, scan session,
and internal stage.

Directory layout::

    output/
    ├── programs/                              # Program cache (ProgramManager)
    ├── scans/
    │   └── {platform}_{program_handle}/       # e.g. hackerone_github
    │       ├── program_info.json
    │       └── {YYYY-MM-DD}_{session_id}/     # e.g. 2026-02-28_a1b2c3d4
    │           ├── session.json
    │           ├── config.json
    │           ├── 01_recon/
    │           │   ├── subdomains/
    │           │   ├── ports/
    │           │   ├── web_discovery/
    │           │   ├── dns/
    │           │   ├── osint/
    │           │   └── tech_detect/
    │           ├── 02_enumeration/
    │           │   ├── parameters/
    │           │   ├── endpoints/
    │           │   ├── js_analysis/
    │           │   └── api_specs/
    │           ├── 03_scanning/
    │           │   ├── nuclei/
    │           │   ├── sqlmap/
    │           │   ├── xss/
    │           │   ├── ssrf/
    │           │   ├── ssti/
    │           │   └── custom/
    │           ├── 04_findings/
    │           │   ├── raw/
    │           │   ├── verified/
    │           │   └── false_positives/
    │           ├── 05_reports/
    │           │   ├── markdown/
    │           │   ├── html/
    │           │   └── json/
    │           ├── 06_evidence/
    │           │   ├── screenshots/
    │           │   ├── http_logs/
    │           │   └── poc/
    │           └── logs/
    │               ├── scan.log
    │               ├── brain.log
    │               └── tool_outputs/
    └── global_logs/
        └── {YYYY-MM-DD}.log
"""

from __future__ import annotations

import json
import re
import secrets
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────

_SCAN_SUBDIRS: dict[str, list[str]] = {
    "01_recon": [
        "subdomains",
        "ports",
        "web_discovery",
        "dns",
        "osint",
        "tech_detect",
    ],
    "02_enumeration": [
        "parameters",
        "endpoints",
        "js_analysis",
        "api_specs",
    ],
    "03_scanning": [
        "nuclei",
        "sqlmap",
        "xss",
        "ssrf",
        "ssti",
        "custom",
    ],
    "04_findings": [
        "raw",
        "verified",
        "false_positives",
    ],
    "05_reports": [
        "markdown",
        "html",
        "json",
    ],
    "06_evidence": [
        "screenshots",
        "http_logs",
        "poc",
    ],
    "logs": [
        "tool_outputs",
    ],
}

# Map tool names → subdirectory under the stage folder
_TOOL_DIR_MAP: dict[str, str] = {
    # Recon / subdomains
    "subfinder": "01_recon/subdomains",
    "amass": "01_recon/subdomains",
    "assetfinder": "01_recon/subdomains",
    "findomain": "01_recon/subdomains",
    "crt_sh": "01_recon/subdomains",
    "knockpy": "01_recon/subdomains",
    # Recon / ports
    "nmap": "01_recon/ports",
    "masscan": "01_recon/ports",
    "rustscan": "01_recon/ports",
    # Recon / web discovery
    "httpx": "01_recon/web_discovery",
    "katana": "01_recon/web_discovery",
    "gospider": "01_recon/web_discovery",
    "hakrawler": "01_recon/web_discovery",
    "waybackurls": "01_recon/web_discovery",
    "gau": "01_recon/web_discovery",
    "aquatone": "01_recon/web_discovery",
    "eyewitness": "01_recon/web_discovery",
    # Recon / DNS
    "dnsrecon": "01_recon/dns",
    "dnsx": "01_recon/dns",
    "dig": "01_recon/dns",
    # Recon / OSINT
    "theHarvester": "01_recon/osint",
    "shodan": "01_recon/osint",
    "censys": "01_recon/osint",
    "whois": "01_recon/osint",
    "google_dorking": "01_recon/osint",
    "github_dorking": "01_recon/osint",
    # Recon / tech
    "whatweb": "01_recon/tech_detect",
    "wappalyzer": "01_recon/tech_detect",
    "builtwith": "01_recon/tech_detect",
    # Enumeration
    "arjun": "02_enumeration/parameters",
    "paramspider": "02_enumeration/parameters",
    "ffuf": "02_enumeration/endpoints",
    "feroxbuster": "02_enumeration/endpoints",
    "gobuster": "02_enumeration/endpoints",
    "dirb": "02_enumeration/endpoints",
    "swagger_parser": "02_enumeration/api_specs",
    "graphql_introspection": "02_enumeration/api_specs",
    # Scanners
    "nuclei": "03_scanning/nuclei",
    "nikto": "03_scanning/nikto",
    "wpscan": "03_scanning/nuclei",
    "sqlmap": "03_scanning/sqlmap",
    "nosqlmap": "03_scanning/sqlmap",
    "dalfox": "03_scanning/xss",
    "xsstrike": "03_scanning/xss",
    "ssrfmap": "03_scanning/ssrf",
    "tplmap": "03_scanning/ssti",
    "commix": "03_scanning/custom",
    "crlfuzz": "03_scanning/custom",
    "corsy": "03_scanning/custom",
    "smuggler": "03_scanning/custom",
    "jwt_tool": "03_scanning/custom",
    "openredirex": "03_scanning/custom",
}


# ────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────


class ScanWorkspaceInfo(BaseModel):
    """Metadata about a scan workspace."""

    session_id: str = ""
    platform: str = ""
    program_handle: str = ""
    scan_date: str = ""
    root_path: str = ""
    created_at: float = 0.0
    config: dict[str, Any] = Field(default_factory=dict)


class ScanWorkspace:
    """
    Manages the directory workspace for a single scan session.

    Provides typed accessors for every sub-directory and helpers
    to write files into the correct location.

    Usage::

        ws = ScanWorkspace.create(
            base_dir="output/scans",
            platform="hackerone",
            program_handle="github",
        )

        # Write tool output
        ws.write_tool_output("subfinder", data, ext="txt")
        ws.write_tool_output("nmap", xml_data, ext="xml")

        # Write finding
        ws.write_finding(finding_dict, category="verified", severity="high")

        # Write report
        ws.write_report("sqli_in_search", md_content, fmt="markdown")

        # Get log path for a tool
        log_path = ws.tool_log_path("sqlmap")
    """

    def __init__(self, root: Path, info: ScanWorkspaceInfo) -> None:
        self._root = root
        self.info = info

    @classmethod
    def create(
        cls,
        base_dir: str,
        platform: str,
        program_handle: str,
        session_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> ScanWorkspace:
        """Create a new scan workspace with full directory tree."""
        safe_handle = re.sub(r"[^a-zA-Z0-9_\-]", "_", program_handle)
        program_dir = f"{platform}_{safe_handle}"

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")
        sid = session_id or secrets.token_hex(4)
        scan_dir = f"{date_str}_{sid}"

        root = Path(base_dir) / program_dir / scan_dir
        root.mkdir(parents=True, exist_ok=True)

        # Create all subdirectories
        for stage_dir, subdirs in _SCAN_SUBDIRS.items():
            stage_path = root / stage_dir
            stage_path.mkdir(exist_ok=True)
            for sub in subdirs:
                (stage_path / sub).mkdir(exist_ok=True)

        info = ScanWorkspaceInfo(
            session_id=sid,
            platform=platform,
            program_handle=program_handle,
            scan_date=date_str,
            root_path=str(root),
            created_at=time.time(),
            config=config or {},
        )

        # Write session info
        (root / "session.json").write_text(
            json.dumps(info.model_dump(), indent=2, ensure_ascii=False),
        )
        if config:
            (root / "config.json").write_text(
                json.dumps(config, indent=2, ensure_ascii=False),
            )

        logger.info(f"Scan workspace created: {root}")
        return cls(root, info)

    @classmethod
    def open_existing(cls, root_path: str) -> ScanWorkspace | None:
        """Open an existing workspace from disk."""
        root = Path(root_path)
        session_file = root / "session.json"
        if not session_file.exists():
            logger.warning(f"No session.json found in {root}")
            return None

        try:
            info = ScanWorkspaceInfo.model_validate_json(
                session_file.read_text()
            )
            return cls(root, info)
        except Exception as e:
            logger.error(f"Failed to open workspace {root}: {e}")
            return None

    # ─── Path Accessors ──────────────────────────────────

    @property
    def root(self) -> Path:
        return self._root

    def stage_dir(self, stage: str) -> Path:
        """Get path for a numbered stage dir, e.g. '01_recon'."""
        p = self._root / stage
        p.mkdir(parents=True, exist_ok=True)
        return p

    def tool_dir(self, tool_name: str) -> Path:
        """Get the correct output directory for a specific tool."""
        rel = _TOOL_DIR_MAP.get(tool_name.lower())
        if rel:
            p = self._root / rel
        else:
            p = self._root / "03_scanning" / "custom"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def findings_dir(self, category: str = "raw") -> Path:
        """Get findings directory. category: raw | verified | false_positives"""
        p = self._root / "04_findings" / category
        p.mkdir(parents=True, exist_ok=True)
        return p

    def reports_dir(self, fmt: str = "markdown") -> Path:
        """Get reports directory. fmt: markdown | html | json"""
        p = self._root / "05_reports" / fmt
        p.mkdir(parents=True, exist_ok=True)
        return p

    def evidence_dir(self, etype: str = "screenshots") -> Path:
        """Get evidence directory. etype: screenshots | http_logs | poc"""
        p = self._root / "06_evidence" / etype
        p.mkdir(parents=True, exist_ok=True)
        return p

    def log_dir(self) -> Path:
        p = self._root / "logs"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def tool_log_path(self, tool_name: str) -> Path:
        """Path for a tool's log file."""
        d = self._root / "logs" / "tool_outputs"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{tool_name.lower()}.log"

    # ─── Write Helpers ───────────────────────────────────

    def write_tool_output(
        self,
        tool_name: str,
        data: str | bytes | dict | list,
        ext: str = "txt",
        suffix: str = "",
    ) -> Path:
        """
        Write tool output to the correct directory.

        Automatically routes the file to the right stage subdir
        based on the tool name.
        """
        d = self.tool_dir(tool_name)
        fname = f"{tool_name.lower()}"
        if suffix:
            fname += f"_{suffix}"
        fname += f".{ext}"
        path = d / fname

        if isinstance(data, bytes):
            path.write_bytes(data)
        elif isinstance(data, (dict, list)):
            path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False)
            )
        else:
            path.write_text(str(data))

        logger.debug(f"Tool output written: {path}")
        return path

    def write_finding(
        self,
        finding: dict[str, Any],
        category: str = "raw",
        severity: str = "",
        finding_id: str = "",
    ) -> Path:
        """Write a finding JSON to the correct findings directory."""
        d = self.findings_dir(category)
        fid = finding_id or secrets.token_hex(4)
        tool = finding.get("tool_name", "unknown")

        if severity:
            fname = f"{severity}_{tool}_{fid}.json"
        else:
            fname = f"{tool}_{fid}.json"

        path = d / fname
        path.write_text(
            json.dumps(finding, indent=2, ensure_ascii=False)
        )
        logger.debug(f"Finding written: {path}")
        return path

    def write_report(
        self,
        title: str,
        content: str,
        fmt: str = "markdown",
    ) -> Path:
        """Write a report file."""
        d = self.reports_dir(fmt)
        safe_title = re.sub(r"[^a-zA-Z0-9_\-]", "_", title)[:80]
        ext = {"markdown": "md", "html": "html", "json": "json"}.get(fmt, "txt")
        path = d / f"{safe_title}.{ext}"
        path.write_text(content)
        logger.debug(f"Report written: {path}")
        return path

    def write_evidence(
        self,
        name: str,
        data: bytes | str,
        etype: str = "screenshots",
        ext: str = "png",
    ) -> Path:
        """Write evidence (screenshot, HTTP log, PoC)."""
        d = self.evidence_dir(etype)
        path = d / f"{name}.{ext}"
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(str(data))
        return path

    def append_log(self, log_name: str, content: str) -> None:
        """Append content to a log file."""
        path = self.log_dir() / log_name
        with open(path, "a") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")

    # ─── Listing ─────────────────────────────────────────

    def list_findings(self, category: str = "verified") -> list[Path]:
        d = self.findings_dir(category)
        return sorted(d.glob("*.json"))

    def list_reports(self, fmt: str = "markdown") -> list[Path]:
        d = self.reports_dir(fmt)
        return sorted(d.glob("*"))

    def disk_usage_bytes(self) -> int:
        total = 0
        for f in self._root.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
        return total

    def summary(self) -> dict[str, Any]:
        """Get a summary of workspace contents."""
        return {
            "session_id": self.info.session_id,
            "platform": self.info.platform,
            "program": self.info.program_handle,
            "date": self.info.scan_date,
            "raw_findings": len(self.list_findings("raw")),
            "verified_findings": len(self.list_findings("verified")),
            "false_positives": len(self.list_findings("false_positives")),
            "reports": len(self.list_reports("markdown")),
            "disk_usage_mb": round(self.disk_usage_bytes() / (1024 * 1024), 2),
        }


# ────────────────────────────────────────────────────────────
# Output Organizer (top-level manager)
# ────────────────────────────────────────────────────────────


class OutputOrganizer:
    """
    Top-level output organiser.

    Manages the ``output/scans/`` hierarchy and provides helpers
    to list past scans, create new workspaces, and clean up.

    Usage::

        organizer = OutputOrganizer()

        # Create workspace for new scan
        ws = organizer.create_workspace("hackerone", "github")

        # List previous scans for a program
        prev = organizer.list_scans("hackerone", "github")

        # Get latest scan
        latest = organizer.latest_scan("hackerone", "github")
    """

    def __init__(self, base_dir: str = "output") -> None:
        self._base = Path(base_dir)
        self._scans_dir = self._base / "scans"
        self._scans_dir.mkdir(parents=True, exist_ok=True)

        # Global logs
        self._global_logs = self._base / "global_logs"
        self._global_logs.mkdir(parents=True, exist_ok=True)

        logger.debug(f"OutputOrganizer initialized: {self._base}")

    def create_workspace(
        self,
        platform: str,
        program_handle: str,
        session_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> ScanWorkspace:
        """Create a new scan workspace for a program."""
        return ScanWorkspace.create(
            base_dir=str(self._scans_dir),
            platform=platform,
            program_handle=program_handle,
            session_id=session_id,
            config=config,
        )

    def list_programs(self) -> list[dict[str, str]]:
        """
        List all programs that have at least one scan.

        Returns list of {platform, handle, path} dicts.
        """
        results: list[dict[str, str]] = []
        if not self._scans_dir.exists():
            return results

        for d in sorted(self._scans_dir.iterdir()):
            if d.is_dir() and "_" in d.name:
                parts = d.name.split("_", 1)
                results.append({
                    "platform": parts[0],
                    "handle": parts[1],
                    "path": str(d),
                })
        return results

    def list_scans(
        self,
        platform: str,
        program_handle: str,
    ) -> list[ScanWorkspaceInfo]:
        """List all scan sessions for a program, newest first."""
        safe_handle = re.sub(r"[^a-zA-Z0-9_\-]", "_", program_handle)
        program_dir = self._scans_dir / f"{platform}_{safe_handle}"

        if not program_dir.exists():
            return []

        infos: list[ScanWorkspaceInfo] = []
        for d in sorted(program_dir.iterdir(), reverse=True):
            session_file = d / "session.json"
            if session_file.exists():
                try:
                    info = ScanWorkspaceInfo.model_validate_json(
                        session_file.read_text()
                    )
                    infos.append(info)
                except Exception as _exc:
                    logger.debug(f"output organizer error: {_exc}")
        return infos

    def latest_scan(
        self,
        platform: str,
        program_handle: str,
    ) -> ScanWorkspace | None:
        """Open the most recent scan workspace for a program."""
        scans = self.list_scans(platform, program_handle)
        if not scans:
            return None
        return ScanWorkspace.open_existing(scans[0].root_path)

    def open_scan(self, root_path: str) -> ScanWorkspace | None:
        """Open a scan workspace by its root path."""
        return ScanWorkspace.open_existing(root_path)

    def global_log_path(self) -> Path:
        """Get today's global log file path."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._global_logs / f"{today}.log"

    def cleanup_old_scans(
        self,
        platform: str,
        program_handle: str,
        keep_last: int = 10,
    ) -> int:
        """
        Remove old scan directories, keeping only the N most recent.

        Returns the number of directories removed.
        """
        scans = self.list_scans(platform, program_handle)
        if len(scans) <= keep_last:
            return 0

        to_remove = scans[keep_last:]
        removed = 0
        for info in to_remove:
            try:
                shutil.rmtree(info.root_path)
                removed += 1
            except Exception as e:
                logger.warning(f"Failed to remove {info.root_path}: {e}")

        if removed:
            logger.info(
                f"Cleaned up {removed} old scans for "
                f"{platform}/{program_handle}"
            )
        return removed

    def disk_usage(self) -> dict[str, Any]:
        """Get disk usage summary for the entire output directory."""
        total = 0
        per_program: dict[str, int] = {}

        for f in self._scans_dir.rglob("*"):
            if f.is_file():
                size = f.stat().st_size
                total += size

                # Attribute to program
                rel = f.relative_to(self._scans_dir)
                program_key = str(rel.parts[0]) if rel.parts else "unknown"
                per_program[program_key] = per_program.get(program_key, 0) + size

        return {
            "total_mb": round(total / (1024 * 1024), 2),
            "per_program_mb": {
                k: round(v / (1024 * 1024), 2)
                for k, v in sorted(
                    per_program.items(), key=lambda x: x[1], reverse=True
                )
            },
        }


__all__ = [
    "OutputOrganizer",
    "ScanWorkspace",
    "ScanWorkspaceInfo",
]
