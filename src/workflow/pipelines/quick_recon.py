"""
WhiteHatHacker AI — Quick Recon Pipeline

Hızlı keşif pipeline'ı. Detaylı tarama yapmadan
hedef hakkında maksimum bilgi toplar.

Kullanım Senaryoları:
- İlk değerlendirme
- Scope geniş olduğunda ön tarama
- Hızlı saldırı yüzeyi tahmini
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
    handle_knowledge_update,
    _detect_target_type,
)


async def _execute_tool(
    executor: Any,
    tool: Any,
    target: str,
    options: dict[str, Any] | None = None,
    *,
    timeout: float,
) -> Any:
    """Apply a pipeline-level timeout around quick recon tool calls."""
    return await asyncio.wait_for(
        executor.execute(tool, target, options or {}),
        timeout=timeout,
    )


async def handle_quick_passive(state: WorkflowState) -> StageResult:
    """Hızlı pasif keşif — sadece temel araçlar."""
    result = StageResult(stage=WorkflowStage.PASSIVE_RECON)

    try:
        target = state.target
        logger.info(f"Quick passive recon | target={target}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        collected: dict[str, Any] = {
            "subdomains": [],
            "dns_info": "",
            "whois_info": "",
            "tech_info": "",
        }

        # ── DNS (hızlı) ──
        dig_tool = tool_registry.get("dig")
        if dig_tool and dig_tool.is_available():
            try:
                r = await _execute_tool(executor, dig_tool, target, {"timeout": 10}, timeout=1200.0)
                if r and r.raw_output:
                    collected["dns_info"] = r.raw_output[:1000]
            except asyncio.TimeoutError:
                logger.warning(f"DNS lookup timed out for {target}")
            except Exception as exc:
                logger.warning(f"DNS lookup failed for {target}: {exc}")

        # ── WHOIS ──
        whois_tool = tool_registry.get("whois")
        if whois_tool and whois_tool.is_available():
            try:
                r = await _execute_tool(executor, whois_tool, target, {"timeout": 10}, timeout=1200.0)
                if r and r.raw_output:
                    collected["whois_info"] = r.raw_output[:1000]
            except asyncio.TimeoutError:
                logger.warning(f"WHOIS lookup timed out for {target}")
            except Exception as exc:
                logger.warning(f"WHOIS lookup failed for {target}: {exc}")

        # ── Subdomain (en hızlı araç) ──
        for tool_name in ["subfinder", "amass", "assetfinder"]:
            tool = tool_registry.get(tool_name)
            if tool and tool.is_available():
                try:
                    r = await _execute_tool(executor, tool, target, {"timeout": 60}, timeout=1200.0)
                    if r and r.findings:
                        for f in r.findings:
                            sd = getattr(f, "target", "")
                            if sd and sd not in collected["subdomains"]:
                                collected["subdomains"].append(sd)
                except asyncio.TimeoutError:
                    logger.warning(f"Subdomain enum ({tool_name}) timed out for {target}")
                except Exception as exc:
                    logger.warning(f"Subdomain enum ({tool_name}) failed for {target}: {exc}")
                break  # Sadece bir araç

        state.subdomains = collected["subdomains"]

        result.data = collected
        result.findings_count = len(collected["subdomains"])
        result.success = True

        logger.info(f"Quick passive done | subdomains={len(collected['subdomains'])}")

    except Exception as e:
        logger.error(f"Quick passive failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_quick_active(state: WorkflowState) -> StageResult:
    """Hızlı aktif keşif — port scan + HTTP probe."""
    result = StageResult(stage=WorkflowStage.ACTIVE_RECON)

    try:
        hosts = state.subdomains or [state.target]
        logger.info(f"Quick active recon | hosts={len(hosts)}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        live_hosts: list[str] = []
        ports: dict[str, list[int]] = {}
        tech: dict[str, str] = {}

        # ── HTTP Probe ──
        httpx = tool_registry.get("httpx")
        if httpx and httpx.is_available():
            for host in hosts[:20]:
                try:
                    r = await _execute_tool(executor, httpx, host, {"timeout": 5}, timeout=1200.0)
                    if r and r.success:
                        live_hosts.append(host)
                except asyncio.TimeoutError:
                    logger.warning(f"HTTP probe timed out for {host}")
                except Exception as exc:
                    logger.warning(f"HTTP probe failed for {host}: {exc}")
        else:
            live_hosts = hosts[:20]

        # ── Quick Port Scan (top 100 only) ──
        nmap = tool_registry.get("nmap")
        if nmap and nmap.is_available():
            for host in live_hosts[:10]:
                try:
                    r = await _execute_tool(
                        executor,
                        nmap,
                        host,
                        {
                            "ports": "21,22,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017",
                            "timeout": 30,
                        },
                        timeout=1200.0,
                    )
                    if r and r.findings:
                        host_ports = []
                        for f in r.findings:
                            p = getattr(f, "port", None)
                            if p:
                                host_ports.append(p)
                        ports[host] = host_ports
                except asyncio.TimeoutError:
                    logger.warning(f"Port scan timed out for {host}")
                except Exception as exc:
                    logger.warning(f"Port scan failed for {host}: {exc}")

        # ── Tech Detect ──
        whatweb = tool_registry.get("whatweb")
        if whatweb and whatweb.is_available():
            for host in live_hosts[:10]:
                try:
                    r = await _execute_tool(executor, whatweb, host, {"timeout": 10}, timeout=1200.0)
                    if r and r.raw_output:
                        tech[host] = r.raw_output[:300]
                except asyncio.TimeoutError:
                    logger.warning(f"Tech detect timed out for {host}")
                except Exception as exc:
                    logger.warning(f"Tech detect failed for {host}: {exc}")

        state.live_hosts = live_hosts
        state.open_ports = ports
        state.technologies = tech

        result.data = {
            "live_hosts": len(live_hosts),
            "ports_scanned": len(ports),
            "tech_detected": len(tech),
        }
        result.findings_count = len(live_hosts)
        result.success = True

        logger.info(
            f"Quick active done | live={len(live_hosts)} | "
            f"ports={sum(len(v) for v in ports.values())}"
        )

    except Exception as e:
        logger.error(f"Quick active failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_quick_summary(state: WorkflowState) -> StageResult:
    """Hızlı değerlendirme özeti oluştur."""
    result = StageResult(stage=WorkflowStage.REPORTING)

    try:
        from pathlib import Path
        import time
        import json

        summary: dict[str, Any] = {
            "target": state.target,
            "target_type": _detect_target_type(state.target),
            "session_id": state.session_id,
            "scan_time": state.elapsed_time,
            "subdomains": len(state.subdomains),
            "live_hosts": len(state.live_hosts),
            "total_open_ports": sum(len(v) for v in state.open_ports.values()),
            "technologies": state.technologies,
            "attack_surface_estimate": _estimate_attack_surface(state),
            "recommended_next": _recommend_next_phase(state),
        }

        # Kaydet
        output_dir = Path(f"output/reports/{state.session_id}")
        output_dir.mkdir(parents=True, exist_ok=True)

        # JSON
        json_path = output_dir / "quick_recon_summary.json"
        json_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

        # Markdown
        md_lines = [
            f"# Quick Recon Summary: {state.target}",
            f"\n**Date:** {time.strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Duration:** {state.elapsed_time:.0f}s",
            "\n## Findings Overview",
            f"- **Subdomains:** {len(state.subdomains)}",
            f"- **Live Hosts:** {len(state.live_hosts)}",
            f"- **Open Ports:** {summary['total_open_ports']}",
            "\n## Technologies Detected",
        ]

        for host, tech in state.technologies.items():
            md_lines.append(f"- **{host}:** {tech[:100]}")

        md_lines.append("\n## Attack Surface Estimate")
        md_lines.append(f"**Score:** {summary['attack_surface_estimate']['score']}/100")
        md_lines.append(f"**Assessment:** {summary['attack_surface_estimate']['assessment']}")

        md_lines.append("\n## Recommended Next Steps")
        for rec in summary["recommended_next"]:
            md_lines.append(f"- {rec}")

        md_lines.append(
            "\n---\n*Quick recon by WhiteHatHacker AI v2.1*"
        )

        md_path = output_dir / "quick_recon_summary.md"
        md_path.write_text("\n".join(md_lines), encoding="utf-8")

        state.reports_generated = [str(md_path), str(json_path)]

        result.data = summary
        result.success = True

        logger.info(f"Quick summary generated | output={output_dir}")

    except Exception as e:
        logger.error(f"Quick summary failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


def _estimate_attack_surface(state: WorkflowState) -> dict[str, Any]:
    """Saldırı yüzeyi tahmini."""
    score = 0

    # Subdomain zenginliği
    sd_count = len(state.subdomains)
    if sd_count > 50:
        score += 25
    elif sd_count > 20:
        score += 15
    elif sd_count > 5:
        score += 10
    elif sd_count > 0:
        score += 5

    # Açık port çeşitliliği
    all_ports = set()
    for ports in state.open_ports.values():
        all_ports.update(ports)

    score += min(len(all_ports) * 3, 30)

    # Web presence
    web_hosts = sum(1 for h in state.live_hosts if any(
        p in state.open_ports.get(h, []) for p in [80, 443, 8080, 8443]
    ))
    score += min(web_hosts * 5, 25)

    # Risky sevices
    risky = {21, 23, 445, 1433, 3306, 5432, 6379, 27017}
    risky_found = len(all_ports & risky)
    score += risky_found * 5

    score = min(score, 100)

    if score >= 70:
        assessment = "Large attack surface — extensive testing recommended"
    elif score >= 40:
        assessment = "Moderate attack surface — targeted testing recommended"
    elif score >= 15:
        assessment = "Small attack surface — focused testing sufficient"
    else:
        assessment = "Minimal attack surface detected"

    return {"score": score, "assessment": assessment}


def _recommend_next_phase(state: WorkflowState) -> list[str]:
    """Sonraki aşama önerileri."""
    recs: list[str] = []

    if state.live_hosts:
        recs.append(f"Run full web application scan on {len(state.live_hosts)} live hosts")

    all_ports = set()
    for ports in state.open_ports.values():
        all_ports.update(ports)

    if {80, 443, 8080, 8443} & all_ports:
        recs.append("Run web vulnerability scanner (nuclei, nikto)")

    if {445, 139} & all_ports:
        recs.append("Run SMB enumeration (enum4linux)")

    if {3306, 5432, 1433} & all_ports:
        recs.append("Check for exposed database services — potential critical finding")

    if {6379} & all_ports:
        recs.append("Check Redis for unauthenticated access — potential critical finding")

    if len(state.subdomains) > 20:
        recs.append("Subdomain takeover check recommended")

    if not recs:
        recs.append("Limited attack surface — consider expanding scope or manual testing")

    return recs


# ============================================================
# Pipeline Builder
# ============================================================

def build_quick_recon_pipeline(
    brain_engine: Any | None = None,
    tool_executor: Any | None = None,
    fp_detector: Any | None = None,
    mode: OperationMode = OperationMode.AUTONOMOUS,
    profile: ScanProfile = ScanProfile.STEALTH,
    human_callback: Any = None,
    session_manager: Any | None = None,
    brain_router: Any | None = None,
) -> WorkflowOrchestrator:
    """
    Hızlı keşif pipeline'ı kur.

    4 aşamalı hafif pipeline:
    Scope → QuickPassive → QuickActive → Summary
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
    orchestrator.register_handler(WorkflowStage.PASSIVE_RECON, handle_quick_passive)
    orchestrator.register_handler(WorkflowStage.ACTIVE_RECON, handle_quick_active)
    orchestrator.register_handler(WorkflowStage.REPORTING, handle_quick_summary)
    orchestrator.register_handler(WorkflowStage.KNOWLEDGE_UPDATE, handle_knowledge_update)

    logger.info(f"Quick recon pipeline built | mode={mode}")

    return orchestrator


__all__ = ["build_quick_recon_pipeline"]
