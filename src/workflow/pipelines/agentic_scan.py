"""
WhiteHatHacker AI — Agentic Scan Pipeline Builder

Converts the 60+ SecurityTool wrappers into ToolUnits, registers them
with a ToolUnitRegistry, and wires a fully-functional AgentOrchestrator.

Usage::

    orchestrator = build_agentic_pipeline(
        brain_engine=brain,
        tool_executor=executor,
        fp_detector=fp,
        mode=mode,
        profile=profile,
        session_manager=sm,
        brain_router=router,
    )
    state = await orchestrator.run(state)
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from loguru import logger

from src.tools.base import SecurityTool, ToolResult
from src.tools.registry import ToolRegistry, tool_registry
from src.utils.constants import (
    OperationMode,
    RiskLevel,
    ScanProfile,
    SeverityLevel,
    WorkflowStage,
)
from src.workflow.tool_unit import (
    PREREQ_AUTH_HEADERS,
    PREREQ_ENDPOINTS,
    PREREQ_FINDINGS,
    PREREQ_LIVE_HOSTS,
    PREREQ_OPEN_PORTS,
    PREREQ_SCOPE,
    PREREQ_SUBDOMAINS,
    PREREQ_TECHNOLOGIES,
    ToolUnit,
    ToolUnitRegistry,
    ToolUnitResult,
    UnitCategory,
)

if TYPE_CHECKING:
    from src.brain.engine import BrainEngine
    from src.brain.router import BrainRouter
    from src.fp_engine.fp_detector import FPDetector
    from src.tools.executor import ToolExecutor
    from src.workflow.orchestrator import WorkflowState
    from src.workflow.session_manager import SessionManager


# ══════════════════════════════════════════════════════════════
#  Generic ToolUnit — wraps any SecurityTool
# ══════════════════════════════════════════════════════════════

class GenericToolUnit(ToolUnit):
    """
    A ToolUnit that wraps a single SecurityTool from the ToolRegistry.

    Instead of implementing 60+ concrete subclasses, this generic wrapper
    extracts targets from WorkflowState based on ``target_source`` and
    delegates execution to the underlying SecurityTool.
    """

    def __init__(
        self,
        *,
        unit_id: str,
        tool_name: str,
        stage: WorkflowStage,
        category: UnitCategory,
        requires: list[str] | None = None,
        provides: list[str] | None = None,
        estimated_duration: int = 120,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        concurrency: int = 3,
        per_target_timeout: float = 300.0,
        target_source: str = "live_hosts",
        max_targets: int = 20,
        tool_options: dict[str, Any] | None = None,
        registry: ToolRegistry | None = None,
    ) -> None:
        self.unit_id = unit_id
        self.stage = stage
        self.category = category
        self.requires = requires or []
        self.provides = provides or []
        self.tools = [tool_name]
        self.estimated_duration = estimated_duration
        self.risk_level = risk_level
        self.concurrency = concurrency
        self.per_target_timeout = per_target_timeout

        self._tool_name = tool_name
        self._target_source = target_source
        self._max_targets = max_targets
        self._tool_options = tool_options or {}
        self._registry = registry or tool_registry

    def _get_tool(self) -> SecurityTool | None:
        return self._registry.get(self._tool_name)

    def _extract_targets(self, state: WorkflowState) -> list[str]:
        """Extract targets from WorkflowState based on target_source."""
        source = self._target_source

        if source == "domain":
            target = getattr(state, "target", "")
            return [target] if target else []

        if source == "subdomains":
            subs = getattr(state, "subdomains", []) or []
            return list(subs)[: self._max_targets]

        if source == "live_hosts":
            hosts = getattr(state, "live_hosts", []) or []
            return list(hosts)[: self._max_targets]

        if source == "endpoints":
            eps = getattr(state, "endpoints", []) or []
            return list(eps)[: self._max_targets]

        if source == "param_urls":
            eps = getattr(state, "endpoints", []) or []
            return [u for u in eps if "?" in str(u)][: self._max_targets]

        if source == "open_ports":
            ports = getattr(state, "open_ports", []) or []
            return list(ports)[: self._max_targets]

        # Fallback: target domain
        target = getattr(state, "target", "")
        return [target] if target else []

    async def _execute(
        self,
        state: WorkflowState,
        context: Any = None,
    ) -> ToolUnitResult:
        tool = self._get_tool()
        if tool is None or not tool.is_available():
            return ToolUnitResult(
                unit_id=self.unit_id,
                success=False,
                errors=[f"Tool {self._tool_name} not available"],
            )

        targets = self._extract_targets(state)
        if not targets:
            return ToolUnitResult(
                unit_id=self.unit_id,
                success=True,
                observations=f"{self.unit_id}: no targets available — skipped.",
            )

        profile = getattr(state, "scan_profile", None) or ScanProfile.BALANCED
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        tools_run: list[str] = [self._tool_name]
        context_updates: dict[str, Any] = {}

        sem = asyncio.Semaphore(self.concurrency)
        timeout = self.effective_timeout(profile)

        async def _run_one(t: str) -> ToolResult | None:
            async with sem:
                try:
                    return await asyncio.wait_for(
                        tool.run(t, options=self._tool_options, profile=profile),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    errors.append(f"{self._tool_name} timeout on {t}")
                    logger.warning(
                        f"GenericToolUnit {self.unit_id}: timeout on {t}"
                    )
                    return None
                except Exception as exc:
                    errors.append(f"{self._tool_name} error on {t}: {exc!r}")
                    logger.warning(
                        f"GenericToolUnit {self.unit_id}: error on {t}: {exc}"
                    )
                    return None

        results = await asyncio.gather(
            *[_run_one(t) for t in targets], return_exceptions=True
        )

        for res in results:
            if isinstance(res, Exception):
                errors.append(f"{self._tool_name}: {res!r}")
                continue
            if res is None or not isinstance(res, ToolResult):
                continue
            for f in res.findings:
                findings.append(_finding_to_dict(f))

            # Extract context updates from tool metadata
            if res.metadata:
                for key in ("subdomains", "endpoints", "technologies", "live_hosts"):
                    val = res.metadata.get(key)
                    if val and isinstance(val, list):
                        existing = context_updates.get(key, [])
                        context_updates[key] = existing + val

        return ToolUnitResult(
            unit_id=self.unit_id,
            success=len(errors) == 0 or len(findings) > 0,
            tools_run=tools_run,
            findings=findings,
            context_updates=context_updates,
            errors=errors,
        )


# ══════════════════════════════════════════════════════════════
#  FunctionToolUnit — wraps a standalone async function
# ══════════════════════════════════════════════════════════════

class FunctionToolUnit(ToolUnit):
    """
    A ToolUnit that wraps a standalone async function (not a SecurityTool).

    Some custom checkers (cors_checker, jwt_checker, cicd_checker, etc.) are
    implemented as plain async functions rather than SecurityTool subclasses.
    This wrapper lets them participate in the agentic pipeline.
    """

    def __init__(
        self,
        *,
        unit_id: str,
        func: Any,                          # Callable[..., Awaitable[list[Finding]]]
        stage: WorkflowStage,
        category: UnitCategory,
        requires: list[str] | None = None,
        provides: list[str] | None = None,
        estimated_duration: int = 120,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        target_source: str = "endpoints",
        max_targets: int = 30,
    ) -> None:
        self.unit_id = unit_id
        self.stage = stage
        self.category = category
        self.requires = requires or []
        self.provides = provides or []
        self.tools = [unit_id]
        self.estimated_duration = estimated_duration
        self.risk_level = risk_level
        self.concurrency = 3
        self.per_target_timeout = float(estimated_duration)

        self._func = func
        self._target_source = target_source
        self._max_targets = max_targets

    def _extract_targets(self, state: WorkflowState) -> list[str]:
        src = self._target_source
        if src == "subdomains":
            return list(getattr(state, "subdomains", []) or [])[:self._max_targets]
        if src == "live_hosts":
            return list(getattr(state, "live_hosts", []) or [])[:self._max_targets]
        if src == "endpoints":
            return list(getattr(state, "endpoints", []) or [])[:self._max_targets]
        target = getattr(state, "target", "")
        return [target] if target else []

    async def _execute(
        self,
        state: WorkflowState,
        context: Any = None,
    ) -> ToolUnitResult:
        targets = self._extract_targets(state)
        if not targets:
            return ToolUnitResult(
                unit_id=self.unit_id,
                success=True,
                observations=f"{self.unit_id}: no targets — skipped.",
            )

        auth = getattr(state, "auth_headers", None) or {}
        try:
            raw_findings = await self._func(
                targets,
                max_targets=min(len(targets), self._max_targets),
                extra_headers=auth if auth else None,
            )
        except TypeError:
            # Some functions have different signatures — fall back
            try:
                raw_findings = await self._func(targets)
            except Exception as exc:
                return ToolUnitResult(
                    unit_id=self.unit_id,
                    success=False,
                    errors=[str(exc)],
                    observations=f"{self.unit_id}: error — {exc}",
                )
        except Exception as exc:
            return ToolUnitResult(
                unit_id=self.unit_id,
                success=False,
                errors=[str(exc)],
                observations=f"{self.unit_id}: error — {exc}",
            )

        findings: list[dict[str, Any]] = []
        for f in raw_findings or []:
            if hasattr(f, "model_dump"):
                findings.append(f.model_dump())
            elif hasattr(f, "dict"):
                findings.append(f.dict())
            elif isinstance(f, dict):
                findings.append(f)

        return ToolUnitResult(
            unit_id=self.unit_id,
            success=True,
            tools_run=[self.unit_id],
            findings=findings,
            observations=(
                f"{self.unit_id}: tested {len(targets)} targets, "
                f"found {len(findings)} issues"
            ),
        )


# ══════════════════════════════════════════════════════════════
#  Composite ToolUnits (multi-tool operations)
# ══════════════════════════════════════════════════════════════

class SubdomainAggregateUnit(ToolUnit):
    """Runs multiple subdomain discovery tools and merges results."""

    unit_id = "subdomain_aggregate"
    stage = WorkflowStage.PASSIVE_RECON
    category = UnitCategory.RECON
    requires = [PREREQ_SCOPE]
    provides = [PREREQ_SUBDOMAINS]
    tools = ["subfinder", "amass", "crt_sh", "assetfinder", "fierce"]
    estimated_duration = 300
    risk_level = RiskLevel.SAFE
    concurrency = 5
    per_target_timeout = 300.0

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self._registry = registry or tool_registry

    async def _execute(self, state: WorkflowState, context: Any = None) -> ToolUnitResult:
        target = getattr(state, "target", "")
        if not target:
            return ToolUnitResult(unit_id=self.unit_id, success=False, errors=["No target"])

        profile = getattr(state, "scan_profile", None) or ScanProfile.BALANCED
        all_subdomains: set[str] = set()
        tools_run: list[str] = []
        errors: list[str] = []

        for tool_name in self.tools:
            tool = self._registry.get(tool_name)
            if not tool or not tool.is_available():
                continue
            try:
                result = await asyncio.wait_for(
                    tool.run(target, profile=profile),
                    timeout=self.effective_timeout(profile),
                )
                tools_run.append(tool_name)
                # Subdomain tools typically produce findings with target=subdomain
                for f in result.findings:
                    sd = getattr(f, "target", "") or getattr(f, "endpoint", "")
                    if sd:
                        all_subdomains.add(sd)
                # Also check metadata
                if result.metadata and "subdomains" in result.metadata:
                    for sd in result.metadata["subdomains"]:
                        all_subdomains.add(str(sd))
                # And stdout lines as subdomain candidates
                if result.stdout:
                    for line in result.stdout.strip().splitlines():
                        line = line.strip()
                        if line and "." in line and " " not in line:
                            all_subdomains.add(line)
            except Exception as exc:
                errors.append(f"{tool_name}: {exc!r}")
                logger.warning(f"SubdomainAggregate: {tool_name} failed: {exc}")

        subs_list = sorted(all_subdomains)
        return ToolUnitResult(
            unit_id=self.unit_id,
            success=True,
            tools_run=tools_run,
            context_updates={"subdomains": subs_list},
            observations=(
                f"subdomain_aggregate completed. "
                f"Tools: {', '.join(tools_run)}. "
                f"Discovered {len(subs_list)} unique subdomains."
            ),
            errors=errors,
        )


class LiveHostProbeUnit(ToolUnit):
    """Runs httpx against discovered subdomains to find live hosts."""

    unit_id = "live_host_probe"
    stage = WorkflowStage.ACTIVE_RECON
    category = UnitCategory.RECON
    requires = [PREREQ_SUBDOMAINS]
    provides = [PREREQ_LIVE_HOSTS]
    tools = ["httpx"]
    estimated_duration = 180
    risk_level = RiskLevel.LOW
    per_target_timeout = 300.0

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self._registry = registry or tool_registry

    async def _execute(self, state: WorkflowState, context: Any = None) -> ToolUnitResult:
        tool = self._registry.get("httpx")
        if not tool or not tool.is_available():
            return ToolUnitResult(unit_id=self.unit_id, success=False, errors=["httpx not available"])

        subs = getattr(state, "subdomains", []) or []
        target = getattr(state, "target", "")
        # Include the root target too
        targets = list(set(list(subs) + ([target] if target else [])))
        if not targets:
            return ToolUnitResult(unit_id=self.unit_id, success=True, observations="No subdomains to probe.")

        profile = getattr(state, "scan_profile", None) or ScanProfile.BALANCED
        live_hosts: list[str] = []
        technologies: dict[str, list[str]] = {}

        # httpx can usually take a file or stdin-separated list
        # Run per-target to collect results
        sem = asyncio.Semaphore(10)

        async def _probe(t: str) -> ToolResult | None:
            async with sem:
                try:
                    return await asyncio.wait_for(
                        tool.run(t, profile=profile),
                        timeout=60.0,
                    )
                except Exception:
                    return None

        results = await asyncio.gather(*[_probe(t) for t in targets[:200]])
        for res in results:
            if res and isinstance(res, ToolResult) and res.success:
                if res.stdout:
                    for line in res.stdout.strip().splitlines():
                        line = line.strip()
                        if line.startswith("http"):
                            live_hosts.append(line)
                if res.metadata:
                    for host, techs in res.metadata.get("technologies", {}).items():
                        technologies[host] = techs

        live_hosts = sorted(set(live_hosts))
        return ToolUnitResult(
            unit_id=self.unit_id,
            success=True,
            tools_run=["httpx"],
            context_updates={
                "live_hosts": live_hosts,
                "technologies": technologies,
            },
            observations=(
                f"live_host_probe: {len(live_hosts)} live hosts from "
                f"{len(targets)} subdomains. "
                f"Tech stacks detected for {len(technologies)} hosts."
            ),
        )


class EndpointCrawlUnit(ToolUnit):
    """Runs katana + gospider + gau/waybackurls to discover endpoints."""

    unit_id = "endpoint_crawl"
    stage = WorkflowStage.ENUMERATION
    category = UnitCategory.RECON
    requires = [PREREQ_LIVE_HOSTS]
    provides = [PREREQ_ENDPOINTS]
    tools = ["katana", "gospider", "gau", "waybackurls"]
    estimated_duration = 600
    risk_level = RiskLevel.LOW
    concurrency = 3
    per_target_timeout = 300.0

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self._registry = registry or tool_registry

    async def _execute(self, state: WorkflowState, context: Any = None) -> ToolUnitResult:
        hosts = (getattr(state, "live_hosts", []) or [])[:30]
        if not hosts:
            return ToolUnitResult(unit_id=self.unit_id, success=True, observations="No live hosts.")

        profile = getattr(state, "scan_profile", None) or ScanProfile.BALANCED
        all_eps: set[str] = set()
        tools_run: list[str] = []
        errors: list[str] = []

        for tool_name in self.tools:
            tool = self._registry.get(tool_name)
            if not tool or not tool.is_available():
                continue
            tools_run.append(tool_name)

            sem = asyncio.Semaphore(3)

            async def _crawl(host: str, _tn: str = tool_name) -> None:
                async with sem:
                    try:
                        t = self._registry.get(_tn)
                        if not t:
                            return
                        res = await asyncio.wait_for(
                            t.run(host, profile=profile),
                            timeout=self.effective_timeout(profile),
                        )
                        if res and res.stdout:
                            for line in res.stdout.strip().splitlines():
                                line = line.strip()
                                if line.startswith("http"):
                                    all_eps.add(line)
                        if res and res.metadata and "endpoints" in res.metadata:
                            for ep in res.metadata["endpoints"]:
                                all_eps.add(str(ep))
                    except Exception as exc:
                        errors.append(f"{_tn} on {host}: {exc!r}")

            await asyncio.gather(*[_crawl(h) for h in hosts])

        eps_list = sorted(all_eps)
        return ToolUnitResult(
            unit_id=self.unit_id,
            success=True,
            tools_run=tools_run,
            context_updates={"endpoints": eps_list},
            observations=(
                f"endpoint_crawl: {len(eps_list)} endpoints from "
                f"{len(hosts)} hosts. Tools: {', '.join(tools_run)}."
            ),
            errors=errors,
        )


# ══════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════

def _finding_to_dict(finding: Any) -> dict[str, Any]:
    """Convert a Finding (or dict) to a normalised dict."""
    if isinstance(finding, dict):
        return finding
    try:
        return finding.model_dump()
    except AttributeError:
        pass
    d: dict[str, Any] = {}
    for attr in (
        "title", "description", "vulnerability_type", "severity",
        "confidence", "target", "endpoint", "parameter", "payload",
        "evidence", "http_request", "http_response", "tool_name",
        "cvss_score", "cwe_id", "cve_id", "remediation", "references",
        "tags", "metadata",
    ):
        val = getattr(finding, attr, None)
        if val is not None:
            # Coerce enums to string
            if hasattr(val, "value"):
                val = val.value
            d[attr] = val
    return d


# ══════════════════════════════════════════════════════════════
#  Unit Registration
# ══════════════════════════════════════════════════════════════

def register_all_tool_units(
    registry: ToolUnitRegistry,
    tool_reg: ToolRegistry | None = None,
) -> ToolUnitRegistry:
    """
    Create and register all ToolUnits that correspond to the current
    SecurityTool catalogue.

    Composite units (subdomain aggregate, live host probe, endpoint crawl)
    are registered first, followed by individual tool wrappers grouped
    by workflow stage.
    """
    tr = tool_reg or tool_registry

    # ── Composite units ─────────────────────────────────────
    registry.register(SubdomainAggregateUnit(registry=tr))
    registry.register(LiveHostProbeUnit(registry=tr))
    registry.register(EndpointCrawlUnit(registry=tr))

    # ── Passive Recon ───────────────────────────────────────
    _passive_recon = [
        ("osint_theharvester", "theharvester", RiskLevel.SAFE, 300, "domain"),
        ("osint_shodan", "shodan", RiskLevel.SAFE, 180, "domain"),
        ("osint_censys", "censys", RiskLevel.SAFE, 180, "domain"),
        ("osint_whois", "whois", RiskLevel.SAFE, 60, "domain"),
        ("osint_google_dorking", "google_dorking", RiskLevel.SAFE, 120, "domain"),
        ("osint_github_dorking", "github_dorking", RiskLevel.SAFE, 120, "domain"),
        ("osint_github_secrets", "github_secret_scanner", RiskLevel.SAFE, 180, "domain"),
        ("dns_dnsrecon", "dnsrecon", RiskLevel.SAFE, 120, "domain"),
        ("dns_dnsx", "dnsx", RiskLevel.SAFE, 90, "subdomains"),
        ("dns_dig", "dig", RiskLevel.SAFE, 60, "domain"),
        ("dns_mail_security", "mail_security", RiskLevel.SAFE, 60, "domain"),
        ("recon_waybackurls", "waybackurls", RiskLevel.SAFE, 180, "domain"),
        ("recon_gau", "gau", RiskLevel.SAFE, 180, "domain"),
    ]
    for uid, tname, risk, est, src in _passive_recon:
        registry.register(GenericToolUnit(
            unit_id=uid,
            tool_name=tname,
            stage=WorkflowStage.PASSIVE_RECON,
            category=UnitCategory.RECON,
            requires=[PREREQ_SCOPE],
            provides=[PREREQ_SUBDOMAINS],
            estimated_duration=est,
            risk_level=risk,
            target_source=src,
            registry=tr,
        ))

    # ── Active Recon ────────────────────────────────────────
    _active_recon = [
        ("recon_whatweb", "whatweb", RiskLevel.LOW, 120, "live_hosts", [PREREQ_TECHNOLOGIES]),
        ("recon_wafw00f", "wafw00f", RiskLevel.LOW, 90, "live_hosts", []),
        ("recon_cdn_detector", "cdn_detector", RiskLevel.SAFE, 60, "live_hosts", []),
        ("recon_reverse_ip", "reverse_ip", RiskLevel.SAFE, 120, "live_hosts", []),
        ("recon_favicon_hash", "favicon_hasher", RiskLevel.SAFE, 60, "live_hosts", [PREREQ_TECHNOLOGIES]),
    ]
    for uid, tname, risk, est, src, provides in _active_recon:
        registry.register(GenericToolUnit(
            unit_id=uid,
            tool_name=tname,
            stage=WorkflowStage.ACTIVE_RECON,
            category=UnitCategory.RECON,
            requires=[PREREQ_LIVE_HOSTS],
            provides=provides or [],
            estimated_duration=est,
            risk_level=risk,
            target_source=src,
            registry=tr,
        ))

    # Port scanning
    registry.register(GenericToolUnit(
        unit_id="port_scan_nmap",
        tool_name="nmap",
        stage=WorkflowStage.ACTIVE_RECON,
        category=UnitCategory.RECON,
        requires=[PREREQ_LIVE_HOSTS],
        provides=[PREREQ_OPEN_PORTS],
        estimated_duration=600,
        risk_level=RiskLevel.LOW,
        target_source="live_hosts",
        max_targets=10,
        per_target_timeout=600.0,
        registry=tr,
    ))
    registry.register(GenericToolUnit(
        unit_id="port_scan_masscan",
        tool_name="masscan",
        stage=WorkflowStage.ACTIVE_RECON,
        category=UnitCategory.RECON,
        requires=[PREREQ_LIVE_HOSTS],
        provides=[PREREQ_OPEN_PORTS],
        estimated_duration=300,
        risk_level=RiskLevel.MEDIUM,
        target_source="live_hosts",
        max_targets=10,
        registry=tr,
    ))

    # ── Enumeration ─────────────────────────────────────────
    _enum_tools = [
        ("enum_ffuf", "ffuf", RiskLevel.LOW, 300, "live_hosts"),
        ("enum_gobuster", "gobuster", RiskLevel.LOW, 300, "live_hosts"),
        ("enum_feroxbuster", "feroxbuster", RiskLevel.LOW, 600, "live_hosts"),
        ("enum_dirb", "dirb", RiskLevel.LOW, 300, "live_hosts"),
        ("enum_wfuzz", "wfuzz", RiskLevel.LOW, 300, "live_hosts"),
        ("enum_arjun", "arjun", RiskLevel.LOW, 300, "endpoints"),
        ("enum_paramspider", "paramspider", RiskLevel.SAFE, 180, "domain"),
        ("enum_vhost_fuzzer", "vhost_fuzzer", RiskLevel.LOW, 180, "live_hosts"),
        ("enum_cloud_enum", "cloud_enum", RiskLevel.SAFE, 180, "domain"),
        ("enum_metadata_extractor", "metadata_extractor", RiskLevel.SAFE, 120, "domain"),
        ("enum_csp_discovery", "csp_discovery", RiskLevel.SAFE, 60, "live_hosts"),
        ("enum_sourcemap", "sourcemap_extractor", RiskLevel.SAFE, 120, "live_hosts"),
        ("enum_swagger_parser", "swagger_parser", RiskLevel.SAFE, 120, "live_hosts"),
        ("enum_graphql_introspection", "graphql_introspection", RiskLevel.SAFE, 120, "live_hosts"),
    ]
    for uid, tname, risk, est, src in _enum_tools:
        registry.register(GenericToolUnit(
            unit_id=uid,
            tool_name=tname,
            stage=WorkflowStage.ENUMERATION,
            category=UnitCategory.RECON,
            requires=[PREREQ_LIVE_HOSTS],
            provides=[PREREQ_ENDPOINTS],
            estimated_duration=est,
            risk_level=risk,
            target_source=src,
            registry=tr,
        ))

    # ── Vulnerability Scanning ──────────────────────────────
    _vuln_tools = [
        ("vuln_nuclei", "nuclei", RiskLevel.MEDIUM, 600, "live_hosts", 25),
        ("vuln_nikto", "nikto", RiskLevel.MEDIUM, 300, "live_hosts", 10),
        ("vuln_wpscan", "wpscan", RiskLevel.MEDIUM, 300, "live_hosts", 5),
        ("vuln_sqlmap", "sqlmap", RiskLevel.HIGH, 900, "param_urls", 40),
        ("vuln_dalfox", "dalfox", RiskLevel.MEDIUM, 300, "param_urls", 50),
        ("vuln_xsstrike", "xsstrike", RiskLevel.MEDIUM, 300, "param_urls", 30),
        ("vuln_commix", "commix", RiskLevel.HIGH, 300, "param_urls", 20),
        ("vuln_ssrfmap", "ssrfmap", RiskLevel.HIGH, 300, "param_urls", 15),
        ("vuln_tplmap", "tplmap", RiskLevel.HIGH, 300, "param_urls", 15),
        ("vuln_nosqlmap", "nosqlmap", RiskLevel.HIGH, 300, "param_urls", 15),
        ("vuln_crlfuzz", "crlfuzz", RiskLevel.MEDIUM, 180, "live_hosts", 20),
        ("vuln_corsy", "corsy", RiskLevel.LOW, 120, "live_hosts", 20),
        ("vuln_openredirex", "openredirex", RiskLevel.MEDIUM, 180, "param_urls", 20),
        ("vuln_smuggler", "smuggler", RiskLevel.MEDIUM, 180, "live_hosts", 10),
        ("vuln_jwt_tool", "jwt_tool", RiskLevel.MEDIUM, 180, "live_hosts", 5),
        ("vuln_interactsh", "interactsh", RiskLevel.MEDIUM, 180, "live_hosts", 5),
    ]
    for uid, tname, risk, est, src, max_t in _vuln_tools:
        registry.register(GenericToolUnit(
            unit_id=uid,
            tool_name=tname,
            stage=WorkflowStage.VULNERABILITY_SCAN,
            category=UnitCategory.SCAN,
            requires=[PREREQ_LIVE_HOSTS, PREREQ_ENDPOINTS],
            provides=[PREREQ_FINDINGS],
            estimated_duration=est,
            risk_level=risk,
            target_source=src,
            max_targets=max_t,
            registry=tr,
        ))

    # ── Custom Checks ───────────────────────────────────────
    _custom_checks = [
        ("check_idor", "idor_checker", RiskLevel.MEDIUM, 300),
        ("check_auth_bypass", "auth_bypass", RiskLevel.MEDIUM, 300),
        ("check_race_condition", "race_condition", RiskLevel.MEDIUM, 180),
        ("check_rate_limit", "rate_limit_checker", RiskLevel.LOW, 180),
        ("check_business_logic", "business_logic", RiskLevel.MEDIUM, 300),
        ("check_mass_assignment", "mass_assignment_checker", RiskLevel.MEDIUM, 180),
        ("check_deserialization", "deserialization_checker", RiskLevel.HIGH, 180),
        ("check_bfla_bola", "bfla_bola_checker", RiskLevel.MEDIUM, 300),
        ("check_fourxx_bypass", "fourxx_bypass", RiskLevel.LOW, 180),
    ]
    for uid, tname, risk, est in _custom_checks:
        registry.register(GenericToolUnit(
            unit_id=uid,
            tool_name=tname,
            stage=WorkflowStage.VULNERABILITY_SCAN,
            category=UnitCategory.CUSTOM_CHECK,
            requires=[PREREQ_LIVE_HOSTS, PREREQ_ENDPOINTS],
            provides=[PREREQ_FINDINGS],
            estimated_duration=est,
            risk_level=risk,
            target_source="endpoints",
            max_targets=30,
            registry=tr,
        ))

    # ── Function-based Custom Checks (no SecurityTool class) ─
    _func_checkers: list[tuple[str, Any, RiskLevel, int, str]] = []
    try:
        from src.tools.scanners.custom_checks.cors_checker import (
            check_cors_misconfigurations,
        )
        _func_checkers.append(
            ("check_cors", check_cors_misconfigurations, RiskLevel.LOW, 120, "endpoints")
        )
    except ImportError:
        logger.warning("cors_checker not importable — skipped in agentic pipeline")

    try:
        from src.tools.scanners.custom_checks.subdomain_takeover import (
            check_subdomain_takeover,
        )
        _func_checkers.append(
            ("check_subdomain_takeover", check_subdomain_takeover, RiskLevel.MEDIUM, 180, "subdomains")
        )
    except ImportError:
        logger.warning("subdomain_takeover not importable — skipped in agentic pipeline")

    try:
        from src.tools.scanners.custom_checks.jwt_checker import (
            check_jwt_security,
        )
        # jwt_checker has a different signature (endpoint, jwt_token) so it
        # needs special handling.  We wrap it in a thin adapter.
        async def _jwt_adapter(
            targets: list[str], **_kw: Any,
        ) -> list:
            from src.tools.base import Finding
            all_findings: list[Finding] = []
            for ep in targets[:5]:
                # JWT checker requires a token — skip if none in state
                # (the function will return [] if token is invalid)
                try:
                    fds = await check_jwt_security(ep, jwt_token="", timeout=15)
                    all_findings.extend(fds)
                except Exception:
                    pass
            return all_findings

        _func_checkers.append(
            ("check_jwt_deep", _jwt_adapter, RiskLevel.MEDIUM, 180, "endpoints")
        )
    except ImportError:
        logger.warning("jwt_checker not importable — skipped in agentic pipeline")

    try:
        from src.tools.scanners.custom_checks.cicd_checker import (
            check_cicd_security,
        )
        _func_checkers.append(
            ("check_cicd", check_cicd_security, RiskLevel.LOW, 180, "live_hosts")
        )
    except ImportError:
        logger.warning("cicd_checker not importable — skipped in agentic pipeline")

    try:
        from src.tools.scanners.custom_checks.http2_http3_checker import (
            check_http2_http3_security,
        )
        _func_checkers.append(
            ("check_http2_http3", check_http2_http3_security, RiskLevel.LOW, 120, "live_hosts")
        )
    except ImportError:
        logger.warning("http2_http3_checker not importable — skipped in agentic pipeline")

    for uid, func, risk, est, src in _func_checkers:
        registry.register(FunctionToolUnit(
            unit_id=uid,
            func=func,
            stage=WorkflowStage.VULNERABILITY_SCAN,
            category=UnitCategory.CUSTOM_CHECK,
            requires=[PREREQ_LIVE_HOSTS, PREREQ_ENDPOINTS],
            provides=[PREREQ_FINDINGS],
            estimated_duration=est,
            risk_level=risk,
            target_source=src,
            max_targets=30,
        ))

    # ── Exploit / CVE Tools ─────────────────────────────────
    _exploit_tools = [
        ("exploit_searchsploit", "searchsploit", RiskLevel.SAFE, 120, "domain"),
        ("exploit_metasploit", "metasploit", RiskLevel.HIGH, 600, "live_hosts"),
        ("exploit_hydra", "hydra", RiskLevel.HIGH, 300, "live_hosts"),
    ]
    for uid, tname, risk, est, src in _exploit_tools:
        registry.register(GenericToolUnit(
            unit_id=uid,
            tool_name=tname,
            stage=WorkflowStage.VULNERABILITY_SCAN,
            category=UnitCategory.EXPLOIT,
            requires=[PREREQ_LIVE_HOSTS, PREREQ_TECHNOLOGIES],
            provides=[PREREQ_FINDINGS],
            estimated_duration=est,
            risk_level=risk,
            target_source=src,
            max_targets=10,
            registry=tr,
        ))

    # ── Network Tools ───────────────────────────────────────
    _network_tools = [
        ("network_enum4linux", "enum4linux", RiskLevel.MEDIUM, 300, "live_hosts"),
        ("network_smbclient", "smbclient", RiskLevel.MEDIUM, 180, "live_hosts"),
        ("network_snmpwalk", "snmpwalk", RiskLevel.MEDIUM, 180, "live_hosts"),
        ("network_ldapsearch", "ldapsearch", RiskLevel.MEDIUM, 180, "live_hosts"),
        ("network_ssh_audit", "ssh_audit", RiskLevel.LOW, 120, "live_hosts"),
    ]
    for uid, tname, risk, est, src in _network_tools:
        registry.register(GenericToolUnit(
            unit_id=uid,
            tool_name=tname,
            stage=WorkflowStage.ACTIVE_RECON,
            category=UnitCategory.SCAN,
            requires=[PREREQ_LIVE_HOSTS, PREREQ_OPEN_PORTS],
            provides=[PREREQ_FINDINGS],
            estimated_duration=est,
            risk_level=risk,
            target_source=src,
            max_targets=5,
            registry=tr,
        ))

    # ── Crypto / TLS ────────────────────────────────────────
    _crypto_tools = [
        ("crypto_sslscan", "sslscan", RiskLevel.SAFE, 120, "live_hosts"),
        ("crypto_sslyze", "sslyze", RiskLevel.SAFE, 120, "live_hosts"),
    ]
    for uid, tname, risk, est, src in _crypto_tools:
        registry.register(GenericToolUnit(
            unit_id=uid,
            tool_name=tname,
            stage=WorkflowStage.ACTIVE_RECON,
            category=UnitCategory.SCAN,
            requires=[PREREQ_LIVE_HOSTS],
            provides=[PREREQ_FINDINGS],
            estimated_duration=est,
            risk_level=risk,
            target_source=src,
            max_targets=10,
            registry=tr,
        ))

    count = len(registry)
    logger.info(f"ToolUnitRegistry populated: {count} units registered")
    return registry


# ══════════════════════════════════════════════════════════════
#  Pipeline Builder
# ══════════════════════════════════════════════════════════════

def build_agentic_pipeline(
    *,
    brain_engine: BrainEngine,
    tool_executor: ToolExecutor,
    fp_detector: FPDetector,
    mode: OperationMode = OperationMode.AUTONOMOUS,
    profile: ScanProfile = ScanProfile.BALANCED,
    session_manager: SessionManager | None = None,
    brain_router: BrainRouter | None = None,
    max_iterations: int | None = None,
    time_budget_seconds: int | None = None,
) -> Any:
    """
    Build a fully wired AgentOrchestrator ready to run an agentic scan.

    This is the ``build_*_pipeline()`` counterpart for the agentic mode,
    sitting alongside ``build_full_scan_pipeline()`` etc.

    Returns an AgentOrchestrator instance.
    """
    from src.brain.intelligence import IntelligenceEngine
    from src.brain.memory.working_memory import WorkingMemory
    from src.brain.reasoning.self_reflection import SelfReflectionEngine
    from src.workflow.adaptive_strategy import AdaptiveStrategyEngine
    from src.workflow.agent_orchestrator import AgentOrchestrator
    from src.workflow.decision_engine import DecisionEngine

    # ── Intelligence Engine (brain wrapper) ──────────────────
    intel = IntelligenceEngine(
        brain_engine=brain_engine,
        brain_router=brain_router,
    )

    # ── Working Memory ───────────────────────────────────────
    working_memory = WorkingMemory()

    # ── ToolUnit Registry ────────────────────────────────────
    unit_registry = ToolUnitRegistry()
    register_all_tool_units(unit_registry)

    # ── Auxiliary engines ────────────────────────────────────
    adaptive = AdaptiveStrategyEngine(profile=profile)
    reflection = SelfReflectionEngine(brain_engine=brain_engine)
    decision = DecisionEngine(profile=profile)

    # ── Orchestrator ─────────────────────────────────────────
    orchestrator = AgentOrchestrator(
        brain_engine=brain_engine,
        intelligence_engine=intel,
        tool_executor=tool_executor,
        fp_detector=fp_detector,
        adaptive_strategy=adaptive,
        self_reflection=reflection,
        decision_engine=decision,
        session_manager=session_manager,
        working_memory=working_memory,
        tool_unit_registry=unit_registry,
        mode=mode,
        profile=profile,
        max_iterations_override=max_iterations,
        time_budget_seconds_override=time_budget_seconds,
    )

    logger.info(
        f"Agentic pipeline built | units={len(unit_registry)} | "
        f"mode={mode} | profile={profile}"
    )

    return orchestrator


__all__ = [
    "build_agentic_pipeline",
    "register_all_tool_units",
    "GenericToolUnit",
    "SubdomainAggregateUnit",
    "LiveHostProbeUnit",
    "EndpointCrawlUnit",
]
