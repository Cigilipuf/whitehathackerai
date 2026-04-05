"""
WhiteHatHacker AI — Tool Registration

Central registration of ALL security tool wrappers.
Called at application startup to populate the ToolRegistry.
"""

from __future__ import annotations

from loguru import logger

from src.tools.registry import ToolRegistry, tool_registry


def register_all_tools(registry: ToolRegistry | None = None) -> ToolRegistry:
    """
    Register all available security tool wrappers in the registry.

    This imports and registers every tool wrapper class so they
    are available for discovery, selection, and execution by the
    workflow orchestrator and attack planner.

    Args:
        registry: Optional registry instance. Uses global if not provided.

    Returns:
        The populated ToolRegistry.
    """
    reg = registry or tool_registry

    tool_classes = []
    failed_imports = []

    # ── Recon: Port Scanning ───────────────────────────────────────
    try:
        from src.tools.recon.port_scan.nmap_wrapper import NmapWrapper
        tool_classes.append(NmapWrapper)
    except Exception as e:
        failed_imports.append(("NmapWrapper", str(e)))

    try:
        from src.tools.recon.port_scan.masscan_wrapper import MasscanWrapper
        tool_classes.append(MasscanWrapper)
    except Exception as e:
        failed_imports.append(("MasscanWrapper", str(e)))

    # ── Recon: Subdomain Discovery ─────────────────────────────────
    try:
        from src.tools.recon.subdomain.amass_wrapper import AmassWrapper
        tool_classes.append(AmassWrapper)
    except Exception as e:
        failed_imports.append(("AmassWrapper", str(e)))

    try:
        from src.tools.recon.subdomain.subfinder_wrapper import SubfinderWrapper
        tool_classes.append(SubfinderWrapper)
    except Exception as e:
        failed_imports.append(("SubfinderWrapper", str(e)))

    try:
        from src.tools.recon.subdomain.assetfinder_wrapper import AssetfinderWrapper
        tool_classes.append(AssetfinderWrapper)
    except Exception as e:
        failed_imports.append(("AssetfinderWrapper", str(e)))

    try:
        from src.tools.recon.subdomain.crt_sh_wrapper import CrtShWrapper
        tool_classes.append(CrtShWrapper)
    except Exception as e:
        failed_imports.append(("CrtShWrapper", str(e)))

    try:
        from src.tools.recon.subdomain.fierce_wrapper import FierceWrapper
        tool_classes.append(FierceWrapper)
    except Exception as e:
        failed_imports.append(("FierceWrapper", str(e)))

    # ── Recon: OSINT ───────────────────────────────────────────────
    try:
        from src.tools.recon.osint.theharvester_wrapper import TheHarvesterWrapper
        tool_classes.append(TheHarvesterWrapper)
    except Exception as e:
        failed_imports.append(("TheHarvesterWrapper", str(e)))

    try:
        from src.tools.recon.osint.shodan_wrapper import ShodanWrapper
        tool_classes.append(ShodanWrapper)
    except Exception as e:
        failed_imports.append(("ShodanWrapper", str(e)))

    try:
        from src.tools.recon.osint.whois_wrapper import WhoisWrapper
        tool_classes.append(WhoisWrapper)
    except Exception as e:
        failed_imports.append(("WhoisWrapper", str(e)))

    try:
        from src.tools.recon.osint.censys_wrapper import CensysWrapper
        tool_classes.append(CensysWrapper)
    except Exception as e:
        failed_imports.append(("CensysWrapper", str(e)))

    try:
        from src.tools.recon.osint.google_dorking import GoogleDorkingWrapper
        tool_classes.append(GoogleDorkingWrapper)
    except Exception as e:
        failed_imports.append(("GoogleDorkingWrapper", str(e)))

    try:
        from src.tools.recon.osint.github_dorking import GitHubDorkingWrapper
        tool_classes.append(GitHubDorkingWrapper)
    except Exception as e:
        failed_imports.append(("GitHubDorkingWrapper", str(e)))

    # ── Recon: Web Discovery ───────────────────────────────────────
    try:
        from src.tools.recon.web_discovery.httpx_wrapper import HttpxWrapper
        tool_classes.append(HttpxWrapper)
    except Exception as e:
        failed_imports.append(("HttpxWrapper", str(e)))

    try:
        from src.tools.recon.web_discovery.katana_wrapper import KatanaWrapper
        tool_classes.append(KatanaWrapper)
    except Exception as e:
        failed_imports.append(("KatanaWrapper", str(e)))

    try:
        from src.tools.recon.web_discovery.gospider_wrapper import GoSpiderWrapper
        tool_classes.append(GoSpiderWrapper)
    except Exception as e:
        failed_imports.append(("GoSpiderWrapper", str(e)))

    try:
        from src.tools.recon.web_discovery.gau_wrapper import GauWrapper
        tool_classes.append(GauWrapper)
    except Exception as e:
        failed_imports.append(("GauWrapper", str(e)))

    try:
        from src.tools.recon.web_discovery.waybackurls_wrapper import WaybackurlsWrapper
        tool_classes.append(WaybackurlsWrapper)
    except Exception as e:
        failed_imports.append(("WaybackurlsWrapper", str(e)))

    # ── Recon: Technology Detection ────────────────────────────────
    try:
        from src.tools.recon.tech_detect.whatweb_wrapper import WhatWebWrapper
        tool_classes.append(WhatWebWrapper)
    except Exception as e:
        failed_imports.append(("WhatWebWrapper", str(e)))

    try:
        from src.tools.recon.tech_detect.wafw00f_wrapper import Wafw00fWrapper
        tool_classes.append(Wafw00fWrapper)
    except Exception as e:
        failed_imports.append(("Wafw00fWrapper", str(e)))

    # ── Recon: DNS ─────────────────────────────────────────────────
    try:
        from src.tools.recon.dns.dnsrecon_wrapper import DnsReconWrapper
        tool_classes.append(DnsReconWrapper)
    except Exception as e:
        failed_imports.append(("DnsReconWrapper", str(e)))

    try:
        from src.tools.recon.dns.dig_wrapper import DigWrapper
        tool_classes.append(DigWrapper)
    except Exception as e:
        failed_imports.append(("DigWrapper", str(e)))

    try:
        from src.tools.recon.dns.dnsx_wrapper import DnsxWrapper
        tool_classes.append(DnsxWrapper)
    except Exception as e:
        failed_imports.append(("DnsxWrapper", str(e)))

    # ── Scanners ───────────────────────────────────────────────────
    try:
        from src.tools.scanners.nikto_wrapper import NiktoWrapper
        tool_classes.append(NiktoWrapper)
    except Exception as e:
        failed_imports.append(("NiktoWrapper", str(e)))

    try:
        from src.tools.scanners.sqlmap_wrapper import SqlmapWrapper
        tool_classes.append(SqlmapWrapper)
    except Exception as e:
        failed_imports.append(("SqlmapWrapper", str(e)))

    try:
        from src.tools.scanners.wpscan_wrapper import WpscanWrapper
        tool_classes.append(WpscanWrapper)
    except Exception as e:
        failed_imports.append(("WpscanWrapper", str(e)))

    try:
        from src.tools.scanners.commix_wrapper import CommixWrapper
        tool_classes.append(CommixWrapper)
    except Exception as e:
        failed_imports.append(("CommixWrapper", str(e)))

    try:
        from src.tools.scanners.nuclei_wrapper import NucleiWrapper
        tool_classes.append(NucleiWrapper)
    except Exception as e:
        failed_imports.append(("NucleiWrapper", str(e)))

    try:
        from src.tools.scanners.dalfox_wrapper import DalfoxWrapper
        tool_classes.append(DalfoxWrapper)
    except Exception as e:
        failed_imports.append(("DalfoxWrapper", str(e)))

    try:
        from src.tools.scanners.xsstrike_wrapper import XsstrikeWrapper
        tool_classes.append(XsstrikeWrapper)
    except Exception as e:
        failed_imports.append(("XsstrikeWrapper", str(e)))

    try:
        from src.tools.scanners.ssrfmap_wrapper import SsrfmapWrapper
        tool_classes.append(SsrfmapWrapper)
    except Exception as e:
        failed_imports.append(("SsrfmapWrapper", str(e)))

    try:
        from src.tools.scanners.tplmap_wrapper import TplmapWrapper
        tool_classes.append(TplmapWrapper)
    except Exception as e:
        failed_imports.append(("TplmapWrapper", str(e)))

    try:
        from src.tools.scanners.nosqlmap_wrapper import NosqlmapWrapper
        tool_classes.append(NosqlmapWrapper)
    except Exception as e:
        failed_imports.append(("NosqlmapWrapper", str(e)))

    try:
        from src.tools.scanners.arjun_wrapper import ArjunWrapper
        tool_classes.append(ArjunWrapper)
    except Exception as e:
        failed_imports.append(("ArjunWrapper", str(e)))

    try:
        from src.tools.scanners.paramspider_wrapper import ParamspiderWrapper
        tool_classes.append(ParamspiderWrapper)
    except Exception as e:
        failed_imports.append(("ParamspiderWrapper", str(e)))

    try:
        from src.tools.scanners.crlfuzz_wrapper import CrlfuzzWrapper
        tool_classes.append(CrlfuzzWrapper)
    except Exception as e:
        failed_imports.append(("CrlfuzzWrapper", str(e)))

    try:
        from src.tools.scanners.corsy_wrapper import CorsyWrapper
        tool_classes.append(CorsyWrapper)
    except Exception as e:
        failed_imports.append(("CorsyWrapper", str(e)))

    try:
        from src.tools.scanners.openredirex_wrapper import OpenredirexWrapper
        tool_classes.append(OpenredirexWrapper)
    except Exception as e:
        failed_imports.append(("OpenredirexWrapper", str(e)))

    try:
        from src.tools.scanners.smuggler_wrapper import SmugglerWrapper
        tool_classes.append(SmugglerWrapper)
    except Exception as e:
        failed_imports.append(("SmugglerWrapper", str(e)))

    try:
        from src.tools.scanners.jwt_tool_wrapper import JwtToolWrapper
        tool_classes.append(JwtToolWrapper)
    except Exception as e:
        failed_imports.append(("JwtToolWrapper", str(e)))

    try:
        from src.tools.scanners.interactsh_wrapper import InteractshWrapper
        tool_classes.append(InteractshWrapper)
    except Exception as e:
        failed_imports.append(("InteractshWrapper", str(e)))

    # ── Scanners: Custom Checks ────────────────────────────────────
    try:
        from src.tools.scanners.custom_checks.idor_checker import IDORChecker
        tool_classes.append(IDORChecker)
    except Exception as e:
        failed_imports.append(("IDORChecker", str(e)))

    try:
        from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
        tool_classes.append(AuthBypassChecker)
    except Exception as e:
        failed_imports.append(("AuthBypassChecker", str(e)))

    try:
        from src.tools.scanners.custom_checks.race_condition import RaceConditionChecker
        tool_classes.append(RaceConditionChecker)
    except Exception as e:
        failed_imports.append(("RaceConditionChecker", str(e)))

    try:
        from src.tools.scanners.custom_checks.rate_limit_checker import RateLimitChecker
        tool_classes.append(RateLimitChecker)
    except Exception as e:
        failed_imports.append(("RateLimitChecker", str(e)))

    try:
        from src.tools.scanners.custom_checks.business_logic import BusinessLogicChecker
        tool_classes.append(BusinessLogicChecker)
    except Exception as e:
        failed_imports.append(("BusinessLogicChecker", str(e)))

    # ── Fuzzing ────────────────────────────────────────────────────
    try:
        from src.tools.fuzzing.ffuf_wrapper import FfufWrapper
        tool_classes.append(FfufWrapper)
    except Exception as e:
        failed_imports.append(("FfufWrapper", str(e)))

    try:
        from src.tools.fuzzing.gobuster_wrapper import GobusterWrapper
        tool_classes.append(GobusterWrapper)
    except Exception as e:
        failed_imports.append(("GobusterWrapper", str(e)))

    try:
        from src.tools.fuzzing.dirb_wrapper import DirbWrapper
        tool_classes.append(DirbWrapper)
    except Exception as e:
        failed_imports.append(("DirbWrapper", str(e)))

    try:
        from src.tools.fuzzing.feroxbuster_wrapper import FeroxbusterWrapper
        tool_classes.append(FeroxbusterWrapper)
    except Exception as e:
        failed_imports.append(("FeroxbusterWrapper", str(e)))

    try:
        from src.tools.fuzzing.wfuzz_wrapper import WfuzzWrapper
        tool_classes.append(WfuzzWrapper)
    except Exception as e:
        failed_imports.append(("WfuzzWrapper", str(e)))

    # ── Network ────────────────────────────────────────────────────
    try:
        from src.tools.network.enum4linux_wrapper import Enum4linuxWrapper
        tool_classes.append(Enum4linuxWrapper)
    except Exception as e:
        failed_imports.append(("Enum4linuxWrapper", str(e)))

    try:
        from src.tools.network.smbclient_wrapper import SmbclientWrapper
        tool_classes.append(SmbclientWrapper)
    except Exception as e:
        failed_imports.append(("SmbclientWrapper", str(e)))

    try:
        from src.tools.network.snmpwalk_wrapper import SnmpwalkWrapper
        tool_classes.append(SnmpwalkWrapper)
    except Exception as e:
        failed_imports.append(("SnmpwalkWrapper", str(e)))

    try:
        from src.tools.network.ldapsearch_wrapper import LdapsearchWrapper
        tool_classes.append(LdapsearchWrapper)
    except Exception as e:
        failed_imports.append(("LdapsearchWrapper", str(e)))

    try:
        from src.tools.network.netexec_wrapper import NetexecWrapper
        tool_classes.append(NetexecWrapper)
    except Exception as e:
        failed_imports.append(("NetexecWrapper", str(e)))

    try:
        from src.tools.network.tshark_wrapper import TsharkWrapper
        tool_classes.append(TsharkWrapper)
    except Exception as e:
        failed_imports.append(("TsharkWrapper", str(e)))

    try:
        from src.tools.network.ssh_audit_wrapper import SshAuditWrapper
        tool_classes.append(SshAuditWrapper)
    except Exception as e:
        failed_imports.append(("SshAuditWrapper", str(e)))

    # ── Exploit ────────────────────────────────────────────────────
    try:
        from src.tools.exploit.searchsploit_wrapper import SearchsploitWrapper
        tool_classes.append(SearchsploitWrapper)
    except Exception as e:
        failed_imports.append(("SearchsploitWrapper", str(e)))

    try:
        from src.tools.exploit.hydra_wrapper import HydraWrapper
        tool_classes.append(HydraWrapper)
    except Exception as e:
        failed_imports.append(("HydraWrapper", str(e)))

    try:
        from src.tools.exploit.metasploit_wrapper import MetasploitWrapper
        tool_classes.append(MetasploitWrapper)
    except Exception as e:
        failed_imports.append(("MetasploitWrapper", str(e)))

    try:
        from src.tools.exploit.impacket_wrapper import ImpacketWrapper
        tool_classes.append(ImpacketWrapper)
    except Exception as e:
        failed_imports.append(("ImpacketWrapper", str(e)))

    # ── Crypto ─────────────────────────────────────────────────────
    try:
        from src.tools.crypto.sslscan_wrapper import SslscanWrapper
        tool_classes.append(SslscanWrapper)
    except Exception as e:
        failed_imports.append(("SslscanWrapper", str(e)))

    try:
        from src.tools.crypto.sslyze_wrapper import SslyzeWrapper
        tool_classes.append(SslyzeWrapper)
    except Exception as e:
        failed_imports.append(("SslyzeWrapper", str(e)))

    # ── Proxy ──────────────────────────────────────────────────────
    try:
        from src.tools.proxy.mitmproxy_wrapper import MitmproxyWrapper
        tool_classes.append(MitmproxyWrapper)
    except Exception as e:
        failed_imports.append(("MitmproxyWrapper", str(e)))

    try:
        from src.tools.proxy.zaproxy_wrapper import ZAProxyWrapper
        tool_classes.append(ZAProxyWrapper)
    except Exception as e:
        failed_imports.append(("ZAProxyWrapper", str(e)))

    # ── API Tools ──────────────────────────────────────────────
    try:
        from src.tools.api_tools.swagger_parser import SwaggerParserWrapper
        tool_classes.append(SwaggerParserWrapper)
    except Exception as e:
        failed_imports.append(("SwaggerParserWrapper", str(e)))

    try:
        from src.tools.api_tools.graphql_introspection import GraphQLIntrospectionWrapper
        tool_classes.append(GraphQLIntrospectionWrapper)
    except Exception as e:
        failed_imports.append(("GraphQLIntrospectionWrapper", str(e)))

    # ── Recon: Web Discovery (V23 registration) ───────────────────
    try:
        from src.tools.recon.web_discovery.csp_discovery import CSPSubdomainDiscovery
        tool_classes.append(CSPSubdomainDiscovery)
    except Exception as e:
        failed_imports.append(("CSPSubdomainDiscovery", str(e)))

    try:
        from src.tools.recon.web_discovery.sourcemap_extractor import SourceMapExtractor
        tool_classes.append(SourceMapExtractor)
    except Exception as e:
        failed_imports.append(("SourceMapExtractor", str(e)))

    try:
        from src.tools.recon.web_discovery.vhost_fuzzer import VHostFuzzer
        tool_classes.append(VHostFuzzer)
    except Exception as e:
        failed_imports.append(("VHostFuzzer", str(e)))

    # ── Recon: Tech Detection (V23 registration) ──────────────────
    try:
        from src.tools.recon.tech_detect.cdn_detector import CDNDetector
        tool_classes.append(CDNDetector)
    except Exception as e:
        failed_imports.append(("CDNDetector", str(e)))

    try:
        from src.tools.recon.tech_detect.favicon_hasher import FaviconHasher
        tool_classes.append(FaviconHasher)
    except Exception as e:
        failed_imports.append(("FaviconHasher", str(e)))

    # ── Recon: DNS (V23 registration) ─────────────────────────────
    try:
        from src.tools.recon.dns.mail_security import EmailSecurityChecker
        tool_classes.append(EmailSecurityChecker)
    except Exception as e:
        failed_imports.append(("EmailSecurityChecker", str(e)))

    try:
        from src.tools.recon.dns.reverse_ip import ReverseIPLookup
        tool_classes.append(ReverseIPLookup)
    except Exception as e:
        failed_imports.append(("ReverseIPLookup", str(e)))

    # ── Recon: OSINT (V23 registration) ───────────────────────────
    try:
        from src.tools.recon.osint.github_secret_scanner import GitHubSecretScanner
        tool_classes.append(GitHubSecretScanner)
    except Exception as e:
        failed_imports.append(("GitHubSecretScanner", str(e)))

    try:
        from src.tools.recon.osint.cloud_enum import CloudStorageEnumerator
        tool_classes.append(CloudStorageEnumerator)
    except Exception as e:
        failed_imports.append(("CloudStorageEnumerator", str(e)))

    try:
        from src.tools.recon.osint.metadata_extractor import MetadataExtractor
        tool_classes.append(MetadataExtractor)
    except Exception as e:
        failed_imports.append(("MetadataExtractor", str(e)))

    # ── V23 batch 2: Custom security checkers ──────────────────────
    try:
        from src.tools.scanners.custom_checks.mass_assignment_checker import MassAssignmentChecker
        tool_classes.append(MassAssignmentChecker)
    except Exception as e:
        failed_imports.append(("MassAssignmentChecker", str(e)))

    try:
        from src.tools.scanners.custom_checks.deserialization_checker import DeserializationChecker
        tool_classes.append(DeserializationChecker)
    except Exception as e:
        failed_imports.append(("DeserializationChecker", str(e)))

    try:
        from src.tools.scanners.custom_checks.bfla_bola_checker import BFLABOLAChecker
        tool_classes.append(BFLABOLAChecker)
    except Exception as e:
        failed_imports.append(("BFLABOLAChecker", str(e)))

    try:
        from src.tools.scanners.custom_checks.fourxx_bypass import FourXXBypassChecker
        tool_classes.append(FourXXBypassChecker)
    except Exception as e:
        failed_imports.append(("FourXXBypassChecker", str(e)))

    # ── Register all ───────────────────────────────────────────────
    reg.register_many(tool_classes)

    # Report
    # Critical tools whose failure significantly impacts scan coverage
    _CRITICAL_TOOLS = {
        "NucleiWrapper", "NmapWrapper", "HttpxWrapper", "SubfinderWrapper",
        "SqlmapWrapper", "DalfoxWrapper", "NiktoWrapper", "KatanaWrapper",
        "FfufWrapper", "SearchsploitWrapper",
    }
    if failed_imports:
        for name, err in failed_imports:
            if name in _CRITICAL_TOOLS:
                logger.error(f"CRITICAL tool import failed: {name} — {err}")
            else:
                logger.warning(f"Failed to import {name}: {err}")

    logger.info(
        f"Tool registration complete: {len(tool_classes)} tools registered, "
        f"{len(failed_imports)} failed imports"
    )

    return reg


__all__ = ["register_all_tools"]
