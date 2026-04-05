"""
WhiteHatHacker AI — Network Scan Pipeline

Ağ altyapısına odaklı tarama pipeline'ı.
Port scan, servis keşfi, SMB/LDAP/SNMP enum, ağ servisleri.
"""

from __future__ import annotations

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
)


async def handle_network_recon(state: WorkflowState) -> StageResult:
    """
    Ağ keşfi: DNS + kapsamlı port tarama.
    """
    result = StageResult(stage=WorkflowStage.ACTIVE_RECON)

    try:
        target = state.target
        logger.info(f"Network recon started | target={target}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        collected: dict[str, Any] = {
            "hosts": [],
            "ports": {},
            "services": {},
        }

        # Hedef tipi: IP/CIDR → doğrudan, domain → resolve et
        import re
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", target):
            collected["hosts"] = [target]
        else:
            # DNS resolve (non-blocking)
            try:
                import asyncio, socket
                loop = asyncio.get_running_loop()
                addrs = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
                ip = addrs[0][4][0] if addrs else target
                collected["hosts"] = [target, ip]
            except Exception as _exc:
                collected["hosts"] = [target]

        # ── Port Scan (kapsamlı) ──
        nmap = tool_registry.get("nmap")
        masscan = tool_registry.get("masscan")

        # Önce masscan (hızlı), sonra nmap (detaylı)
        if masscan and masscan.is_available():
            for host in collected["hosts"]:
                try:
                    r = await executor.execute(masscan, host, {
                        "ports": "1-65535",
                        "rate": 1000,
                    })
                    if r and r.findings:
                        ports = []
                        for f in r.findings:
                            p = getattr(f, "port", None)
                            if p:
                                ports.append(p)
                        collected["ports"][host] = ports
                except Exception as e:
                    logger.warning(f"Masscan@{host}: {e}")

        if nmap and nmap.is_available():
            for host in collected["hosts"]:
                existing_ports = collected["ports"].get(host, [])
                port_str = ",".join(str(p) for p in existing_ports) if existing_ports else "1-10000"

                try:
                    r = await executor.execute(nmap, host, {
                        "ports": port_str,
                        "service_detect": True,
                        "scripts": "default,vuln",
                    })
                    if r and r.findings:
                        services = {}
                        ports = []
                        for f in r.findings:
                            p = getattr(f, "port", None)
                            svc = getattr(f, "service", "")
                            if p:
                                ports.append(p)
                                if svc:
                                    services[str(p)] = svc
                        collected["ports"][host] = list(set(
                            collected["ports"].get(host, []) + ports
                        ))
                        collected["services"][host] = services
                except Exception as e:
                    logger.warning(f"Nmap@{host}: {e}")

        state.live_hosts = collected["hosts"]
        state.open_ports = collected["ports"]

        result.data = collected
        result.findings_count = sum(len(v) for v in collected["ports"].values())
        result.success = True

        logger.info(
            f"Network recon complete | hosts={len(collected['hosts'])} | "
            f"total_ports={result.findings_count}"
        )

    except Exception as e:
        logger.error(f"Network recon failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_network_enum(state: WorkflowState) -> StageResult:
    """
    Ağ servis enumeration: SMB, SNMP, LDAP, SSH audit.
    """
    result = StageResult(stage=WorkflowStage.ENUMERATION)

    try:
        hosts = state.live_hosts or [state.target]
        logger.info(f"Network enumeration started | hosts={len(hosts)}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        all_findings: list[dict[str, Any]] = []

        for host in hosts:
            ports = state.open_ports.get(host, [])

            # ── SMB (445) ──
            if 445 in ports or 139 in ports:
                enum4linux = tool_registry.get("enum4linux")
                if enum4linux and enum4linux.is_available():
                    try:
                        r = await executor.execute(enum4linux, host, {})
                        if r and r.findings:
                            for f in r.findings:
                                all_findings.append({
                                    "title": getattr(f, "title", "SMB Finding"),
                                    "vulnerability_type": getattr(f, "vulnerability_type", "information_disclosure"),
                                    "url": host,
                                    "tool": "enum4linux",
                                    "description": getattr(f, "description", ""),
                                    "severity": getattr(f, "severity", "medium"),
                                })
                    except Exception as e:
                        logger.warning(f"enum4linux@{host}: {e}")

                smbclient = tool_registry.get("smbclient")
                if smbclient and smbclient.is_available():
                    try:
                        r = await executor.execute(smbclient, host, {"anonymous": True})
                        if r and r.findings:
                            for f in r.findings:
                                all_findings.append({
                                    "title": getattr(f, "title", "SMB Share Finding"),
                                    "vulnerability_type": "information_disclosure",
                                    "url": host,
                                    "tool": "smbclient",
                                    "description": getattr(f, "description", ""),
                                    "severity": "medium",
                                })
                    except Exception as _exc:
                        logger.debug(f"network scan error: {_exc}")

            # ── SNMP (161) ──
            if 161 in ports:
                snmpwalk = tool_registry.get("snmpwalk")
                if snmpwalk and snmpwalk.is_available():
                    try:
                        r = await executor.execute(snmpwalk, host, {"community": "public"})
                        if r and r.findings:
                            for f in r.findings:
                                all_findings.append({
                                    "title": getattr(f, "title", "SNMP Finding"),
                                    "vulnerability_type": "information_disclosure",
                                    "url": host,
                                    "tool": "snmpwalk",
                                    "description": getattr(f, "description", ""),
                                    "severity": "medium",
                                })
                    except Exception as _exc:
                        logger.debug(f"network scan error: {_exc}")

            # ── LDAP (389, 636) ──
            if 389 in ports or 636 in ports:
                ldap = tool_registry.get("ldapsearch")
                if ldap and ldap.is_available():
                    try:
                        r = await executor.execute(ldap, host, {"anonymous": True})
                        if r and r.findings:
                            for f in r.findings:
                                all_findings.append({
                                    "title": getattr(f, "title", "LDAP Finding"),
                                    "vulnerability_type": "information_disclosure",
                                    "url": host,
                                    "tool": "ldapsearch",
                                    "description": getattr(f, "description", ""),
                                    "severity": "medium",
                                })
                    except Exception as _exc:
                        logger.debug(f"network scan error: {_exc}")

            # ── SSH (22) ──
            if 22 in ports:
                ssh_audit = tool_registry.get("ssh_audit")
                if ssh_audit and ssh_audit.is_available():
                    try:
                        r = await executor.execute(ssh_audit, host, {})
                        if r and r.findings:
                            for f in r.findings:
                                all_findings.append({
                                    "title": getattr(f, "title", "SSH Finding"),
                                    "vulnerability_type": "ssl_tls_misconfiguration",
                                    "url": host,
                                    "tool": "ssh_audit",
                                    "description": getattr(f, "description", ""),
                                    "severity": getattr(f, "severity", "low"),
                                })
                    except Exception as _exc:
                        logger.debug(f"network scan error: {_exc}")

        state.raw_findings = all_findings

        result.data = {"network_findings": len(all_findings)}
        result.findings_count = len(all_findings)
        result.success = True

        logger.info(f"Network enumeration complete | findings={len(all_findings)}")

    except Exception as e:
        logger.error(f"Network enumeration failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


# ============================================================
# Pipeline Builder
# ============================================================

def build_network_scan_pipeline(
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
    Ağ tarama pipeline'ı kur.

    6 aşamalı ağ-odaklı pipeline:
    Scope → NetworkRecon → NetworkEnum → FPElim → Report → KBUpdate
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
    orchestrator.register_handler(WorkflowStage.ACTIVE_RECON, handle_network_recon)
    orchestrator.register_handler(WorkflowStage.ENUMERATION, handle_network_enum)
    orchestrator.register_handler(WorkflowStage.FP_ELIMINATION, handle_fp_elimination)
    orchestrator.register_handler(WorkflowStage.REPORTING, handle_reporting)
    orchestrator.register_handler(WorkflowStage.KNOWLEDGE_UPDATE, handle_knowledge_update)

    logger.info(f"Network scan pipeline built | mode={mode}")

    return orchestrator


__all__ = ["build_network_scan_pipeline"]
