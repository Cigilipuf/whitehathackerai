"""
WhiteHatHacker AI — Web Application Pipeline

Web uygulamalarına özelleştirilmiş tarama pipeline'ı.
Full scan'in web-odaklı, optimize edilmiş hali.
"""

from __future__ import annotations

import asyncio
from typing import Any

from loguru import logger

from src.utils.constants import (
    OperationMode,
    ScanProfile,
    WorkflowStage,
)
from src.workflow.orchestrator import (
    StageResult,
    WorkflowOrchestrator,
    WorkflowState,
)
from src.workflow.pipelines.full_scan import (
    handle_scope_analysis,
    handle_fp_elimination,
    handle_reporting,
    handle_knowledge_update,
    _get_scan_options,
)


async def _execute_tool(
    executor: Any,
    tool: Any,
    target: str,
    options: dict[str, Any] | None = None,
    *,
    timeout: float,
) -> Any:
    """Apply a pipeline-level timeout around executor calls."""
    return await asyncio.wait_for(
        executor.execute(tool, target, options or {}),
        timeout=timeout,
    )


async def handle_web_recon(state: WorkflowState) -> StageResult:
    """
    Web Recon: Pasif + aktif keşif birleşik.

    Subdomain → HTTP probe → technology detect → crawl
    """
    result = StageResult(stage=WorkflowStage.PASSIVE_RECON)

    try:
        target = state.target
        logger.info(f"Web recon started | target={target}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        collected: dict[str, Any] = {
            "live_hosts": [],
            "technologies": {},
            "urls": [],
            "endpoints": [],
        }

        # ── Subdomain keşfi ──
        subdomains = [target]
        for tool_name in ["amass", "subfinder"]:
            tool = tool_registry.get(tool_name)
            if tool and tool.is_available():
                try:
                    r = await _execute_tool(
                        executor, tool, target, {"mode": "passive"}, timeout=1200.0
                    )
                    if r and r.findings:
                        for f in r.findings:
                            sd = getattr(f, "target", "")
                            if sd and sd not in subdomains:
                                subdomains.append(sd)
                except Exception as e:
                    logger.warning(f"Subdomain {tool_name}: {e}")
                break  # İlk çalışan yeterli

        # ── HTTP Probe ──
        httpx_tool = tool_registry.get("httpx")
        if httpx_tool and httpx_tool.is_available():
            for host in subdomains[:30]:
                try:
                    r = await _execute_tool(executor, httpx_tool, host, {}, timeout=1200.0)
                    if r and r.success:
                        collected["live_hosts"].append(host)
                except Exception as _exc:
                    logger.warning(f"web app error: {_exc}")
        else:
            collected["live_hosts"] = subdomains[:30]

        # ── Teknoloji tespiti ──
        whatweb = tool_registry.get("whatweb")
        if whatweb and whatweb.is_available():
            for host in collected["live_hosts"][:15]:
                try:
                    r = await _execute_tool(executor, whatweb, host, {}, timeout=1200.0)
                    if r and r.raw_output:
                        collected["technologies"][host] = r.raw_output[:300]
                except Exception as _exc:
                    logger.warning(f"web app error: {_exc}")

        # ── Web crawling (waybackurls, gau benzeri URL koleksiyonu) ──
        for tool_name in ["katana", "gospider", "hakrawler"]:
            tool = tool_registry.get(tool_name)
            if tool and tool.is_available():
                for host in collected["live_hosts"][:10]:
                    try:
                        r = await _execute_tool(
                            executor, tool, host, {"depth": 2}, timeout=1200.0
                        )
                        if r and r.findings:
                            for f in r.findings:
                                url = getattr(f, "url", "")
                                if url and url not in collected["urls"]:
                                    collected["urls"].append(url)
                    except Exception as _exc:
                        logger.warning(f"web app error: {_exc}")
                break

        state.subdomains = subdomains
        state.live_hosts = collected["live_hosts"]
        state.technologies = collected["technologies"]
        state.endpoints = collected["urls"]

        result.data = collected
        result.findings_count = len(collected["live_hosts"])
        result.success = True

        logger.info(
            f"Web recon complete | live={len(collected['live_hosts'])} | "
            f"urls={len(collected['urls'])}"
        )

    except Exception as e:
        logger.error(f"Web recon failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_web_enumeration(state: WorkflowState) -> StageResult:
    """
    Web Enumeration: Directory fuzzing + parameter discovery.
    """
    result = StageResult(stage=WorkflowStage.ENUMERATION)

    try:
        live_hosts = state.live_hosts or [state.target]
        logger.info(f"Web enumeration started | hosts={len(live_hosts)}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        endpoints: list[str] = list(state.endpoints)
        params: list[dict] = []

        # ── Directory Fuzzing ──
        for tool_name in ["ffuf", "gobuster", "feroxbuster"]:
            tool = tool_registry.get(tool_name)
            if tool and tool.is_available():
                for host in live_hosts[:10]:
                    try:
                        opts = _get_scan_options(state.profile, "fuzzing")
                        r = await _execute_tool(executor, tool, host, opts, timeout=1200.0)
                        if r and r.findings:
                            for f in r.findings:
                                url = getattr(f, "url", "")
                                if url and url not in endpoints:
                                    endpoints.append(url)
                    except Exception as e:
                        logger.warning(f"Fuzzing {tool_name}@{host}: {e}")
                break

        state.endpoints = endpoints

        result.data = {
            "endpoints": len(endpoints),
            "parameters": len(params),
        }
        result.findings_count = len(endpoints)
        result.success = True

        logger.info(f"Web enumeration complete | endpoints={len(endpoints)}")

    except Exception as e:
        logger.error(f"Web enumeration failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_web_vuln_scan(state: WorkflowState) -> StageResult:
    """
    Web-odaklı zafiyet taraması.

    XSS, SQLi, SSRF, SSTI, CORS, Open Redirect gibi
    web-specific zafiyetlere odaklanır.
    """
    result = StageResult(stage=WorkflowStage.VULNERABILITY_SCAN)

    try:
        targets = state.live_hosts or [state.target]
        endpoints = state.endpoints or []

        logger.info(
            f"Web vuln scan started | targets={len(targets)} | "
            f"endpoints={len(endpoints)}"
        )

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        all_findings: list[dict[str, Any]] = []

        # ── Nuclei (web templates) ──
        nuclei = tool_registry.get("nuclei")
        if nuclei and nuclei.is_available():
            for target in targets[:15]:
                try:
                    r = await _execute_tool(
                        executor,
                        nuclei,
                        target,
                        {"tags": "web,cve,xss,sqli,ssrf,lfi,rce"},
                        timeout=1200.0,
                    )
                    if r and r.findings:
                        for f in r.findings:
                            all_findings.append(_finding_to_dict(f, "nuclei", target))
                except Exception as e:
                    logger.warning(f"Nuclei@{target}: {e}")

        # ── SQLMap ──
        sqlmap = tool_registry.get("sqlmap")
        if sqlmap and sqlmap.is_available():
            for ep in endpoints[:20]:
                try:
                    opts = _get_scan_options(state.profile, "injection")
                    r = await _execute_tool(executor, sqlmap, ep, opts, timeout=1200.0)
                    if r and r.findings:
                        for f in r.findings:
                            all_findings.append(_finding_to_dict(f, "sqlmap", ep))
                except Exception as e:
                    logger.warning(f"SQLMap@{ep}: {e}")

        # ── Nikto ──
        nikto = tool_registry.get("nikto")
        if nikto and nikto.is_available():
            for target in targets[:10]:
                try:
                    r = await _execute_tool(executor, nikto, target, {}, timeout=1200.0)
                    if r and r.findings:
                        for f in r.findings:
                            all_findings.append(_finding_to_dict(f, "nikto", target))
                except Exception as e:
                    logger.warning(f"Nikto@{target}: {e}")

        # ── WPScan (WordPress ise) ──
        wpscan = tool_registry.get("wpscan")
        if wpscan and wpscan.is_available():
            for host in targets[:5]:
                tech = str(state.technologies.get(host, "")).lower()
                if "wordpress" in tech or "wp-" in tech:
                    try:
                        r = await _execute_tool(executor, wpscan, host, {}, timeout=1200.0)
                        if r and r.findings:
                            for f in r.findings:
                                all_findings.append(_finding_to_dict(f, "wpscan", host))
                    except Exception as _exc:
                        logger.warning(f"web app error: {_exc}")

        # ── SSL/TLS ──
        for tool_name in ["sslscan", "sslyze"]:
            tool = tool_registry.get(tool_name)
            if tool and tool.is_available():
                for target in targets[:5]:
                    try:
                        r = await _execute_tool(executor, tool, target, {}, timeout=1200.0)
                        if r and r.findings:
                            for f in r.findings:
                                d = _finding_to_dict(f, tool_name, target)
                                d["vulnerability_type"] = "ssl_tls_misconfiguration"
                                all_findings.append(d)
                    except Exception as _exc:
                        logger.warning(f"web app error: {_exc}")
                break

        # ── Custom Web Checks ──
        for tool_name in ["idor_checker", "cors_checker", "auth_bypass_checker"]:
            tool = tool_registry.get(tool_name)
            if tool and tool.is_available():
                for ep in endpoints[:10]:
                    try:
                        r = await _execute_tool(executor, tool, ep, {}, timeout=1200.0)
                        if r and r.findings:
                            for f in r.findings:
                                all_findings.append(_finding_to_dict(f, tool_name, ep))
                    except Exception as _exc:
                        logger.warning(f"web app error: {_exc}")

        state.raw_findings = all_findings

        result.data = {"total_findings": len(all_findings)}
        result.findings_count = len(all_findings)
        result.success = True

        logger.info(f"Web vuln scan complete | findings={len(all_findings)}")

    except Exception as e:
        logger.error(f"Web vuln scan failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


# ============================================================
# Pipeline Builder
# ============================================================

def build_web_app_pipeline(
    brain_engine: Any | None = None,
    tool_executor: Any | None = None,
    fp_detector: Any | None = None,
    mode: OperationMode = OperationMode.SEMI_AUTONOMOUS,
    profile: ScanProfile = ScanProfile.BALANCED,
    human_callback: Any = None,
    session_manager: Any | None = None,
    brain_router: Any | None = None,
) -> WorkflowOrchestrator:
    """
    Web uygulama tarama pipeline'ı kur.

    Optimize edilmiş 7 aşamalı web-focused pipeline:
    Scope → WebRecon → WebEnum → VulnScan → FPElim → Report → KBUpdate
    """
    orchestrator = WorkflowOrchestrator(
        brain_engine=brain_engine,
        tool_executor=tool_executor,
        fp_detector=fp_detector,
        mode=mode,
        profile=profile,
        human_approval_callback=human_callback,
        session_manager=session_manager,
        brain_router=brain_router,
    )

    orchestrator.register_handler(WorkflowStage.SCOPE_ANALYSIS, handle_scope_analysis)
    orchestrator.register_handler(WorkflowStage.PASSIVE_RECON, handle_web_recon)
    orchestrator.register_handler(WorkflowStage.ENUMERATION, handle_web_enumeration)
    orchestrator.register_handler(WorkflowStage.VULNERABILITY_SCAN, handle_web_vuln_scan)
    orchestrator.register_handler(WorkflowStage.FP_ELIMINATION, handle_fp_elimination)
    orchestrator.register_handler(WorkflowStage.REPORTING, handle_reporting)
    orchestrator.register_handler(WorkflowStage.KNOWLEDGE_UPDATE, handle_knowledge_update)

    logger.info(f"Web app pipeline built | mode={mode} | profile={profile}")

    return orchestrator


# ============================================================
# Yardımcı
# ============================================================

def _finding_to_dict(finding: Any, tool_name: str, target: str) -> dict[str, Any]:
    """Finding nesnesini dict'e dönüştür."""
    url_val = getattr(finding, "endpoint", None) or getattr(finding, "url", None) or target
    if isinstance(url_val, list):
        url_val = url_val[0] if url_val else target
    if not isinstance(url_val, str):
        url_val = str(url_val)
    data = {
        "title": getattr(finding, "title", "") or "",
        "vulnerability_type": getattr(finding, "vulnerability_type", "") or "",
        "url": url_val,
        "endpoint": url_val,
        "target": target,
        "parameter": getattr(finding, "parameter", "") or "",
        "payload": getattr(finding, "payload", "") or "",
        "severity": getattr(finding, "severity", "medium") or "medium",
        "confidence": getattr(finding, "confidence", 50.0),
        "confidence_score": getattr(finding, "confidence_score", None) or getattr(finding, "confidence", 50.0),
        "tool": tool_name,
        "description": getattr(finding, "description", "") or "",
        "evidence": getattr(finding, "evidence", "") or "",
        "cve_id": getattr(finding, "cve_id", "") or "",
        "cwe_id": getattr(finding, "cwe_id", "") or "",
        "http_request": getattr(finding, "http_request", "") or "",
        "http_response": getattr(finding, "http_response", "") or "",
        "impact": getattr(finding, "impact", "") or "",
        "remediation": getattr(finding, "remediation", "") or "",
        "cvss_score": getattr(finding, "cvss_score", None),
        "cvss_vector": getattr(finding, "cvss_vector", "") or "",
    }

    for extra_key in (
        "references", "tags",
        "interactsh_callback", "oob_domain", "oob_protocol",
        "blind_verification", "interaction_type",
        "metadata", "poc_code", "poc_confirmed",
    ):
        val = getattr(finding, extra_key, None)
        if val is not None and val != "" and val != []:
            data[extra_key] = val

    return data


__all__ = ["build_web_app_pipeline"]
