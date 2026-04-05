"""
WhiteHatHacker AI — Otomatik Araç Keşif Motoru

Sisteme kurulu olan TÜM siber güvenlik araçlarını otomatik keşfeder,
versiyonlarını kontrol eder, yeteneklerini haritalar ve ToolRegistry'ye kaydeder.

Bu modül:
  1. Bilinen araçların yüklü olup olmadığını kontrol eder
  2. Binary yollarını ve versiyonlarını saptar
  3. Her aracın yeteneklerini (capabilities) belirler
  4. Wordlist ve template dizinlerini tarar
  5. Araç bağımlılıklarını ve gruplarını çıkarır
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

from src.utils.constants import RiskLevel, ToolCategory


# ────────────────────────────────────────────────────────────
# Veri Modelleri
# ────────────────────────────────────────────────────────────

@dataclass
class ToolCapability:
    """Bir aracın belirli bir yeteneği."""
    name: str               # Yetenek adı (örn. "syn_scan", "version_detect")
    description: str = ""   # Açıklama
    requires_root: bool = False

@dataclass
class DiscoveredTool:
    """Sistemde keşfedilen bir güvenlik aracı."""
    name: str
    binary_name: str
    binary_path: str | None = None
    version: str = "unknown"
    installed: bool = False
    category: ToolCategory = ToolCategory.SCANNER
    risk_level: RiskLevel = RiskLevel.SAFE
    description: str = ""
    capabilities: list[ToolCapability] = field(default_factory=list)
    install_command: str = ""  # Kurulu değilse nasıl kurulur
    tags: list[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────
# Araç Katalogu — Bu bilgisayardaki tüm bilinen araçlar
# ────────────────────────────────────────────────────────────

TOOL_CATALOG: list[dict[str, Any]] = [
    # ═══════════════ RECON — Subdomain ═══════════════════
    {
        "name": "amass",
        "binary_name": "amass",
        "category": ToolCategory.RECON_SUBDOMAIN,
        "risk_level": RiskLevel.SAFE,
        "description": "In-depth attack surface mapping and asset discovery",
        "version_cmd": ["amass", "-version"],
        "capabilities": [
            ToolCapability("passive_enum", "Passive subdomain enumeration"),
            ToolCapability("active_enum", "Active DNS brute-force", True),
            ToolCapability("intel", "Intelligence gathering from OSINT"),
        ],
        "tags": ["subdomain", "recon", "dns", "osint"],
        "install_command": "apt install amass",
    },
    {
        "name": "theHarvester",
        "binary_name": "theHarvester",
        "category": ToolCategory.RECON_OSINT,
        "risk_level": RiskLevel.SAFE,
        "description": "OSINT tool for emails, subdomains, hosts, names, ports",
        "version_cmd": ["theHarvester", "--help"],
        "capabilities": [
            ToolCapability("email_harvest", "Email address harvesting"),
            ToolCapability("subdomain_harvest", "Subdomain discovery via search engines"),
            ToolCapability("host_harvest", "Virtual host enumeration"),
        ],
        "tags": ["osint", "email", "subdomain", "recon"],
        "install_command": "apt install theharvester",
    },
    # ═══════════════ RECON — Port Scan ═══════════════════
    {
        "name": "nmap",
        "binary_name": "nmap",
        "category": ToolCategory.RECON_PORT,
        "risk_level": RiskLevel.LOW,
        "description": "Network exploration and security auditing tool",
        "version_cmd": ["nmap", "--version"],
        "capabilities": [
            ToolCapability("syn_scan", "TCP SYN stealth scan", True),
            ToolCapability("connect_scan", "TCP connect scan"),
            ToolCapability("udp_scan", "UDP port scan", True),
            ToolCapability("version_detect", "Service version detection"),
            ToolCapability("os_detect", "OS fingerprinting", True),
            ToolCapability("script_engine", "NSE script execution"),
            ToolCapability("vuln_scan", "Vulnerability scanning via NSE scripts"),
        ],
        "tags": ["port", "scan", "service", "network", "nse"],
        "install_command": "apt install nmap",
    },
    {
        "name": "masscan",
        "binary_name": "masscan",
        "category": ToolCategory.RECON_PORT,
        "risk_level": RiskLevel.MEDIUM,
        "description": "Mass IP port scanner — fastest internet port scanner",
        "version_cmd": ["masscan", "--version"],
        "capabilities": [
            ToolCapability("mass_scan", "Ultra-fast port scanning", True),
            ToolCapability("banner_grab", "Banner grabbing"),
        ],
        "tags": ["port", "scan", "fast", "mass"],
        "install_command": "apt install masscan",
    },
    # ═══════════════ RECON — Web Discovery ═══════════════
    {
        "name": "httpx",
        "binary_name": "httpx",
        "category": ToolCategory.RECON_WEB,
        "risk_level": RiskLevel.SAFE,
        "description": "Fast and multi-purpose HTTP toolkit — probing, tech detect",
        "version_cmd": ["httpx", "-version"],
        "capabilities": [
            ToolCapability("http_probe", "HTTP/HTTPS probing and alive check"),
            ToolCapability("tech_detect", "Technology detection"),
            ToolCapability("status_codes", "Status code extraction"),
            ToolCapability("title_extract", "Page title extraction"),
            ToolCapability("cdn_detect", "CDN/WAF detection"),
        ],
        "tags": ["http", "probe", "web", "tech"],
        "install_command": "apt install httpx-toolkit",
    },
    {
        "name": "gobuster",
        "binary_name": "gobuster",
        "category": ToolCategory.FUZZING,
        "risk_level": RiskLevel.LOW,
        "description": "Directory/file & DNS busting tool written in Go",
        "version_cmd": ["gobuster", "version"],
        "capabilities": [
            ToolCapability("dir_brute", "Directory brute-force"),
            ToolCapability("dns_brute", "DNS subdomain brute-force"),
            ToolCapability("vhost_brute", "Virtual host brute-force"),
            ToolCapability("s3_brute", "S3 bucket enumeration"),
            ToolCapability("fuzz", "Fuzzing mode"),
        ],
        "tags": ["directory", "brute", "fuzzing", "dns"],
        "install_command": "apt install gobuster",
    },
    {
        "name": "ffuf",
        "binary_name": "ffuf",
        "category": ToolCategory.FUZZING,
        "risk_level": RiskLevel.LOW,
        "description": "Fast web fuzzer written in Go",
        "version_cmd": ["ffuf", "-V"],
        "capabilities": [
            ToolCapability("dir_fuzz", "Directory/path fuzzing"),
            ToolCapability("param_fuzz", "Parameter fuzzing"),
            ToolCapability("header_fuzz", "Header fuzzing"),
            ToolCapability("vhost_fuzz", "Virtual host fuzzing"),
            ToolCapability("post_fuzz", "POST data fuzzing"),
        ],
        "tags": ["fuzzing", "directory", "parameter", "fast"],
        "install_command": "apt install ffuf",
    },
    {
        "name": "dirb",
        "binary_name": "dirb",
        "category": ToolCategory.FUZZING,
        "risk_level": RiskLevel.LOW,
        "description": "Web content scanner / directory brute-forcer",
        "version_cmd": ["dirb"],
        "capabilities": [
            ToolCapability("dir_scan", "Directory scanning with wordlists"),
        ],
        "tags": ["directory", "brute", "web"],
        "install_command": "apt install dirb",
    },
    {
        "name": "wfuzz",
        "binary_name": "wfuzz",
        "category": ToolCategory.FUZZING,
        "risk_level": RiskLevel.LOW,
        "description": "Web application bruteforcer (Python)",
        "version_cmd": ["wfuzz", "--version"],
        "capabilities": [
            ToolCapability("dir_fuzz", "Directory fuzzing"),
            ToolCapability("param_fuzz", "Parameter fuzzing"),
            ToolCapability("header_fuzz", "Header fuzzing"),
            ToolCapability("auth_brute", "Authentication brute-force"),
            ToolCapability("payload_fuzz", "Custom payload fuzzing"),
        ],
        "tags": ["fuzzing", "web", "brute", "payload"],
        "install_command": "apt install wfuzz",
    },
    # ═══════════════ RECON — DNS ═════════════════════════
    {
        "name": "dnsrecon",
        "binary_name": "dnsrecon",
        "category": ToolCategory.RECON_DNS,
        "risk_level": RiskLevel.SAFE,
        "description": "DNS enumeration and reconnaissance",
        "version_cmd": ["dnsrecon", "--help"],
        "capabilities": [
            ToolCapability("std_enum", "Standard DNS record enumeration"),
            ToolCapability("zone_transfer", "Zone transfer attempt"),
            ToolCapability("brute_force", "Subdomain brute-force"),
            ToolCapability("reverse_lookup", "Reverse DNS lookups"),
            ToolCapability("srv_enum", "SRV record enumeration"),
            ToolCapability("cache_snoop", "DNS cache snooping"),
        ],
        "tags": ["dns", "recon", "zone_transfer", "enum"],
        "install_command": "apt install dnsrecon",
    },
    {
        "name": "fierce",
        "binary_name": "fierce",
        "category": ToolCategory.RECON_DNS,
        "risk_level": RiskLevel.SAFE,
        "description": "DNS reconnaissance tool for locating non-contiguous IP space",
        "version_cmd": ["fierce", "--help"],
        "capabilities": [
            ToolCapability("dns_scan", "DNS brute-force and zone walking"),
        ],
        "tags": ["dns", "recon", "brute"],
        "install_command": "apt install fierce",
    },
    {
        "name": "dnsmap",
        "binary_name": "dnsmap",
        "category": ToolCategory.RECON_DNS,
        "risk_level": RiskLevel.SAFE,
        "description": "Passive DNS network mapper",
        "version_cmd": ["dnsmap"],
        "capabilities": [
            ToolCapability("subdomain_brute", "Subdomain brute-force via DNS"),
        ],
        "tags": ["dns", "subdomain", "passive"],
        "install_command": "apt install dnsmap",
    },
    {
        "name": "dig",
        "binary_name": "dig",
        "category": ToolCategory.RECON_DNS,
        "risk_level": RiskLevel.SAFE,
        "description": "DNS lookup utility (bind-utils)",
        "version_cmd": ["dig", "-v"],
        "capabilities": [
            ToolCapability("dns_query", "DNS record queries (A, AAAA, MX, TXT, NS, SOA, CNAME)"),
            ToolCapability("reverse_dns", "Reverse DNS lookups"),
            ToolCapability("axfr", "Zone transfer attempts"),
        ],
        "tags": ["dns", "query", "standard"],
        "install_command": "apt install dnsutils",
    },
    # ═══════════════ VULN SCANNERS ═══════════════════════
    {
        "name": "nikto",
        "binary_name": "nikto",
        "category": ToolCategory.SCANNER,
        "risk_level": RiskLevel.LOW,
        "description": "Web server scanner for dangerous files, outdated versions",
        "version_cmd": ["nikto", "-Version"],
        "capabilities": [
            ToolCapability("webserver_scan", "Web server vulnerability scanning"),
            ToolCapability("outdated_check", "Outdated software detection"),
            ToolCapability("misconfig_check", "Misconfiguration detection"),
            ToolCapability("dangerous_files", "Dangerous file/CGI discovery"),
        ],
        "tags": ["web", "scanner", "vuln", "server"],
        "install_command": "apt install nikto",
    },
    {
        "name": "wpscan",
        "binary_name": "wpscan",
        "category": ToolCategory.SCANNER,
        "risk_level": RiskLevel.LOW,
        "description": "WordPress vulnerability scanner",
        "version_cmd": ["wpscan", "--version"],
        "capabilities": [
            ToolCapability("wp_enum_plugins", "WordPress plugin enumeration"),
            ToolCapability("wp_enum_themes", "WordPress theme enumeration"),
            ToolCapability("wp_enum_users", "WordPress user enumeration"),
            ToolCapability("wp_vuln_scan", "WordPress vulnerability scanning"),
            ToolCapability("wp_password_brute", "WordPress password brute-force"),
        ],
        "tags": ["wordpress", "cms", "vuln", "web"],
        "install_command": "apt install wpscan",
    },
    {
        "name": "sqlmap",
        "binary_name": "sqlmap",
        "category": ToolCategory.SCANNER,
        "risk_level": RiskLevel.MEDIUM,
        "description": "Automatic SQL injection and database takeover tool",
        "version_cmd": ["sqlmap", "--version"],
        "capabilities": [
            ToolCapability("sqli_detect", "SQL injection detection"),
            ToolCapability("sqli_exploit", "SQL injection exploitation"),
            ToolCapability("db_enum", "Database enumeration"),
            ToolCapability("os_shell", "Operating system shell access"),
            ToolCapability("file_read", "File system access"),
            ToolCapability("boolean_blind", "Boolean-based blind SQLi"),
            ToolCapability("time_blind", "Time-based blind SQLi"),
            ToolCapability("error_based", "Error-based SQLi"),
            ToolCapability("union_based", "UNION-based SQLi"),
            ToolCapability("stacked_queries", "Stacked queries SQLi"),
        ],
        "tags": ["sqli", "database", "injection", "exploit"],
        "install_command": "apt install sqlmap",
    },
    {
        "name": "commix",
        "binary_name": "commix",
        "category": ToolCategory.SCANNER,
        "risk_level": RiskLevel.HIGH,
        "description": "Automated command injection exploitation tool",
        "version_cmd": ["commix", "--version"],
        "capabilities": [
            ToolCapability("cmd_inject_detect", "Command injection detection"),
            ToolCapability("cmd_inject_exploit", "Command injection exploitation"),
            ToolCapability("reverse_shell", "Reverse shell generation"),
        ],
        "tags": ["command_injection", "exploit", "rce"],
        "install_command": "apt install commix",
    },
    # ═══════════════ EXPLOIT ═════════════════════════════
    {
        "name": "metasploit",
        "binary_name": "msfconsole",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.CRITICAL,
        "description": "Penetration testing framework — exploit development and execution",
        "version_cmd": ["msfconsole", "-v"],
        "capabilities": [
            ToolCapability("exploit_exec", "Exploit execution", True),
            ToolCapability("payload_gen", "Payload generation"),
            ToolCapability("aux_scan", "Auxiliary module scanning"),
            ToolCapability("post_exploit", "Post-exploitation modules", True),
        ],
        "tags": ["exploit", "framework", "payload", "post_exploit"],
        "install_command": "apt install metasploit-framework",
    },
    {
        "name": "searchsploit",
        "binary_name": "searchsploit",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.SAFE,
        "description": "Exploit-DB search tool — offline exploit database",
        "version_cmd": ["searchsploit", "--help"],
        "capabilities": [
            ToolCapability("exploit_search", "Search exploit database"),
            ToolCapability("exploit_mirror", "Mirror/copy exploits"),
            ToolCapability("nmap_xml_parse", "Parse nmap XML for known vulns"),
        ],
        "tags": ["exploit", "search", "database", "cve"],
        "install_command": "apt install exploitdb",
    },
    # ═══════════════ NETWORK ═════════════════════════════
    {
        "name": "tshark",
        "binary_name": "tshark",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.LOW,
        "description": "Terminal-based network protocol analyzer (Wireshark CLI)",
        "version_cmd": ["tshark", "--version"],
        "capabilities": [
            ToolCapability("packet_capture", "Network packet capture", True),
            ToolCapability("pcap_analysis", "PCAP file analysis"),
            ToolCapability("protocol_decode", "Protocol decoding"),
            ToolCapability("traffic_filter", "Traffic filtering with display filters"),
        ],
        "tags": ["network", "packet", "capture", "analysis"],
        "install_command": "apt install wireshark",
    },
    {
        "name": "netcat",
        "binary_name": "netcat",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.LOW,
        "description": "TCP/UDP networking utility (swiss army knife)",
        "version_cmd": ["netcat", "-h"],
        "capabilities": [
            ToolCapability("port_scan", "Basic port scanning"),
            ToolCapability("banner_grab", "Service banner grabbing"),
            ToolCapability("reverse_shell", "Reverse/bind shell"),
            ToolCapability("file_transfer", "File transfer"),
        ],
        "tags": ["network", "tcp", "udp", "utility"],
        "install_command": "apt install netcat-openbsd",
    },
    {
        "name": "enum4linux",
        "binary_name": "enum4linux",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.LOW,
        "description": "Windows/Samba enumeration tool",
        "version_cmd": ["enum4linux"],
        "capabilities": [
            ToolCapability("smb_enum", "SMB share enumeration"),
            ToolCapability("user_enum", "Windows user enumeration"),
            ToolCapability("group_enum", "Windows group enumeration"),
            ToolCapability("policy_enum", "Password policy enumeration"),
            ToolCapability("os_info", "OS information gathering"),
        ],
        "tags": ["smb", "windows", "enum", "ldap"],
        "install_command": "apt install enum4linux",
    },
    {
        "name": "smbclient",
        "binary_name": "smbclient",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.LOW,
        "description": "SMB/CIFS access utility — file sharing client",
        "version_cmd": ["smbclient", "--version"],
        "capabilities": [
            ToolCapability("share_list", "List available SMB shares"),
            ToolCapability("file_access", "Access SMB file shares"),
        ],
        "tags": ["smb", "file_share", "windows"],
        "install_command": "apt install smbclient",
    },
    {
        "name": "snmpwalk",
        "binary_name": "snmpwalk",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.LOW,
        "description": "SNMP MIB object tree walker",
        "version_cmd": ["snmpwalk", "--version"],
        "capabilities": [
            ToolCapability("snmp_walk", "SNMP MIB tree walking"),
            ToolCapability("community_test", "SNMP community string testing"),
        ],
        "tags": ["snmp", "network", "enum"],
        "install_command": "apt install snmp",
    },
    {
        "name": "ldapsearch",
        "binary_name": "ldapsearch",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.LOW,
        "description": "LDAP search tool for querying directory services",
        "version_cmd": ["ldapsearch", "-VV"],
        "capabilities": [
            ToolCapability("ldap_query", "LDAP directory queries"),
            ToolCapability("user_enum", "LDAP user enumeration"),
            ToolCapability("anon_bind", "Anonymous bind testing"),
        ],
        "tags": ["ldap", "directory", "enum", "ad"],
        "install_command": "apt install ldap-utils",
    },
    {
        "name": "netexec",
        "binary_name": "nxc",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.MEDIUM,
        "description": "Network execution tool (CrackMapExec successor) — SMB/WinRM/SSH/LDAP/MSSQL",
        "version_cmd": ["nxc", "--version"],
        "capabilities": [
            ToolCapability("smb_auth", "SMB authentication testing"),
            ToolCapability("winrm_auth", "WinRM authentication testing"),
            ToolCapability("ssh_auth", "SSH authentication testing"),
            ToolCapability("ldap_auth", "LDAP authentication testing"),
            ToolCapability("mssql_auth", "MSSQL authentication testing"),
            ToolCapability("pass_spray", "Password spraying"),
            ToolCapability("network_enum", "Network service enumeration"),
        ],
        "tags": ["ad", "smb", "winrm", "ssh", "ldap", "mssql", "spray"],
        "install_command": "apt install netexec",
    },
    {
        "name": "evil-winrm",
        "binary_name": "evil-winrm",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.HIGH,
        "description": "WinRM shell for pentesting — PowerShell remote",
        "version_cmd": ["evil-winrm", "--version"],
        "capabilities": [
            ToolCapability("winrm_shell", "WinRM interactive shell"),
            ToolCapability("file_upload", "File upload to target"),
            ToolCapability("file_download", "File download from target"),
        ],
        "tags": ["winrm", "windows", "shell", "post_exploit"],
        "install_command": "apt install evil-winrm",
    },
    # ═══════════════ CRYPTO / SSL ════════════════════════
    {
        "name": "sslscan",
        "binary_name": "sslscan",
        "category": ToolCategory.CRYPTO,
        "risk_level": RiskLevel.SAFE,
        "description": "SSL/TLS cipher suite and certificate scanner",
        "version_cmd": ["sslscan", "--version"],
        "capabilities": [
            ToolCapability("cipher_enum", "SSL/TLS cipher suite enumeration"),
            ToolCapability("cert_check", "Certificate validity checking"),
            ToolCapability("protocol_check", "SSL/TLS protocol version testing"),
            ToolCapability("heartbleed_check", "Heartbleed vulnerability check"),
        ],
        "tags": ["ssl", "tls", "crypto", "cert"],
        "install_command": "apt install sslscan",
    },
    {
        "name": "sslyze",
        "binary_name": "sslyze",
        "category": ToolCategory.CRYPTO,
        "risk_level": RiskLevel.SAFE,
        "description": "Fast and powerful SSL/TLS scanning library and CLI tool",
        "version_cmd": ["sslyze", "--version"],
        "capabilities": [
            ToolCapability("cipher_enum", "Cipher suite enumeration"),
            ToolCapability("cert_info", "Certificate information extraction"),
            ToolCapability("vuln_check", "SSL vulnerability checks (ROBOT, Heartbleed)"),
            ToolCapability("hsts_check", "HSTS and HPKP policy checking"),
        ],
        "tags": ["ssl", "tls", "crypto", "vuln"],
        "install_command": "pip install sslyze",
    },
    {
        "name": "hashcat",
        "binary_name": "hashcat",
        "category": ToolCategory.CRYPTO,
        "risk_level": RiskLevel.SAFE,
        "description": "Advanced password recovery (GPU-accelerated hash cracking)",
        "version_cmd": ["hashcat", "--version"],
        "capabilities": [
            ToolCapability("hash_crack", "Password hash cracking (GPU)"),
            ToolCapability("hash_identify", "Hash type identification"),
            ToolCapability("rule_attack", "Rule-based attack"),
            ToolCapability("mask_attack", "Mask/brute-force attack"),
        ],
        "tags": ["password", "hash", "crack", "gpu"],
        "install_command": "apt install hashcat",
    },
    {
        "name": "john",
        "binary_name": "john",
        "category": ToolCategory.CRYPTO,
        "risk_level": RiskLevel.SAFE,
        "description": "John the Ripper — password cracker",
        "version_cmd": ["john", "--list=build-info"],
        "capabilities": [
            ToolCapability("hash_crack", "Password hash cracking"),
            ToolCapability("wordlist_attack", "Wordlist-based cracking"),
            ToolCapability("incremental", "Incremental mode brute-force"),
        ],
        "tags": ["password", "hash", "crack"],
        "install_command": "apt install john",
    },
    # ═══════════════ PROXY ═══════════════════════════════
    {
        "name": "mitmproxy",
        "binary_name": "mitmproxy",
        "category": ToolCategory.PROXY,
        "risk_level": RiskLevel.LOW,
        "description": "Interactive TLS-capable intercepting HTTP proxy",
        "version_cmd": ["mitmproxy", "--version"],
        "capabilities": [
            ToolCapability("http_intercept", "HTTP/HTTPS traffic interception"),
            ToolCapability("request_modify", "Request/response modification"),
            ToolCapability("traffic_replay", "Traffic replay"),
            ToolCapability("script_addon", "Python scripting support"),
        ],
        "tags": ["proxy", "http", "intercept", "mitm"],
        "install_command": "pip install mitmproxy",
    },
    {
        "name": "mitmdump",
        "binary_name": "mitmdump",
        "category": ToolCategory.PROXY,
        "risk_level": RiskLevel.LOW,
        "description": "Command-line version of mitmproxy (scriptable)",
        "version_cmd": ["mitmdump", "--version"],
        "capabilities": [
            ToolCapability("traffic_dump", "HTTP traffic dumping"),
            ToolCapability("script_filter", "Scriptable traffic filtering"),
        ],
        "tags": ["proxy", "dump", "script"],
        "install_command": "pip install mitmproxy",
    },
    # ═══════════════ OSINT ═══════════════════════════════
    {
        "name": "shodan",
        "binary_name": "shodan",
        "category": ToolCategory.RECON_OSINT,
        "risk_level": RiskLevel.SAFE,
        "description": "Shodan CLI — search engine for internet-connected devices",
        "version_cmd": ["shodan", "version"],
        "capabilities": [
            ToolCapability("host_search", "Search hosts by IP"),
            ToolCapability("query_search", "Search by query string"),
            ToolCapability("port_search", "Search by open ports"),
            ToolCapability("vuln_search", "Search by vulnerabilities"),
        ],
        "tags": ["osint", "iot", "search", "internet"],
        "install_command": "pip install shodan",
    },
    {
        "name": "censys",
        "binary_name": "censys",
        "category": ToolCategory.RECON_OSINT,
        "risk_level": RiskLevel.SAFE,
        "description": "Censys CLI — internet-wide scan data search",
        "version_cmd": ["censys", "--version"],
        "capabilities": [
            ToolCapability("host_search", "Search hosts"),
            ToolCapability("cert_search", "Search certificates"),
        ],
        "tags": ["osint", "cert", "search"],
        "install_command": "pip install censys",
    },
    {
        "name": "whois",
        "binary_name": "whois",
        "category": ToolCategory.RECON_OSINT,
        "risk_level": RiskLevel.SAFE,
        "description": "WHOIS domain registration lookup",
        "version_cmd": ["whois", "--version"],
        "capabilities": [
            ToolCapability("domain_lookup", "Domain registration lookup"),
            ToolCapability("ip_lookup", "IP WHOIS lookup"),
        ],
        "tags": ["osint", "domain", "registration"],
        "install_command": "apt install whois",
    },
    {
        "name": "recon-ng",
        "binary_name": "recon-ng",
        "category": ToolCategory.RECON_OSINT,
        "risk_level": RiskLevel.SAFE,
        "description": "Web reconnaissance framework (modular)",
        "version_cmd": ["recon-ng", "--version"],
        "capabilities": [
            ToolCapability("module_recon", "Modular OSINT reconnaissance"),
            ToolCapability("domain_intel", "Domain intelligence gathering"),
        ],
        "tags": ["osint", "framework", "recon"],
        "install_command": "apt install recon-ng",
    },
    {
        "name": "spiderfoot",
        "binary_name": "spiderfoot",
        "category": ToolCategory.RECON_OSINT,
        "risk_level": RiskLevel.SAFE,
        "description": "OSINT automation tool — footprinting and intelligence",
        "version_cmd": ["spiderfoot", "--help"],
        "capabilities": [
            ToolCapability("auto_osint", "Automated OSINT gathering"),
            ToolCapability("threat_intel", "Threat intelligence correlation"),
        ],
        "tags": ["osint", "automated", "footprint"],
        "install_command": "apt install spiderfoot",
    },
    # ═══════════════ TECH DETECT ═════════════════════════
    {
        "name": "whatweb",
        "binary_name": "whatweb",
        "category": ToolCategory.RECON_TECH,
        "risk_level": RiskLevel.SAFE,
        "description": "Web technology fingerprinter — CMS, framework, library detection",
        "version_cmd": ["whatweb", "--version"],
        "capabilities": [
            ToolCapability("cms_detect", "CMS detection (WordPress, Joomla, Drupal)"),
            ToolCapability("framework_detect", "Web framework detection"),
            ToolCapability("server_detect", "Web server detection"),
            ToolCapability("plugin_detect", "Plugin/extension detection"),
        ],
        "tags": ["tech", "fingerprint", "cms", "web"],
        "install_command": "apt install whatweb",
    },
    {
        "name": "wafw00f",
        "binary_name": "wafw00f",
        "category": ToolCategory.RECON_TECH,
        "risk_level": RiskLevel.SAFE,
        "description": "Web Application Firewall fingerprinting tool",
        "version_cmd": ["wafw00f", "--version"],
        "capabilities": [
            ToolCapability("waf_detect", "WAF detection and identification"),
            ToolCapability("waf_fingerprint", "WAF fingerprinting"),
        ],
        "tags": ["waf", "firewall", "fingerprint", "detect"],
        "install_command": "apt install wafw00f",
    },
    # ═══════════════ PASSWORD ════════════════════════════
    {
        "name": "hydra",
        "binary_name": "hydra",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.MEDIUM,
        "description": "Network logon cracker — brute-force authentication",
        "version_cmd": ["hydra", "-V"],
        "capabilities": [
            ToolCapability("ssh_brute", "SSH brute-force"),
            ToolCapability("ftp_brute", "FTP brute-force"),
            ToolCapability("http_brute", "HTTP form brute-force"),
            ToolCapability("smb_brute", "SMB brute-force"),
            ToolCapability("rdp_brute", "RDP brute-force"),
            ToolCapability("multi_protocol", "50+ protocol support"),
        ],
        "tags": ["brute", "password", "auth", "login"],
        "install_command": "apt install hydra",
    },
    {
        "name": "medusa",
        "binary_name": "medusa",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.MEDIUM,
        "description": "Parallel network login auditor (brute-force)",
        "version_cmd": ["medusa", "-V"],
        "capabilities": [
            ToolCapability("parallel_brute", "Parallel authentication brute-force"),
        ],
        "tags": ["brute", "password", "parallel"],
        "install_command": "apt install medusa",
    },
    {
        "name": "cewl",
        "binary_name": "cewl",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.SAFE,
        "description": "Custom wordlist generator from target website",
        "version_cmd": ["cewl", "--help"],
        "capabilities": [
            ToolCapability("wordlist_gen", "Generate wordlist by spidering target"),
            ToolCapability("email_extract", "Extract emails during crawl"),
        ],
        "tags": ["wordlist", "password", "crawl"],
        "install_command": "apt install cewl",
    },
    {
        "name": "crunch",
        "binary_name": "crunch",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.SAFE,
        "description": "Wordlist generator based on character sets and patterns",
        "version_cmd": ["crunch"],
        "capabilities": [
            ToolCapability("charset_gen", "Character set based wordlist generation"),
            ToolCapability("pattern_gen", "Pattern-based wordlist generation"),
        ],
        "tags": ["wordlist", "generator", "brute"],
        "install_command": "apt install crunch",
    },
    # ═══════════════ NETWORK ATTACKS ═════════════════════
    {
        "name": "responder",
        "binary_name": "responder",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.HIGH,
        "description": "LLMNR/NBNS/MDNS poisoner — credential capture",
        "version_cmd": ["responder", "--version"],
        "capabilities": [
            ToolCapability("llmnr_poison", "LLMNR poisoning", True),
            ToolCapability("nbns_poison", "NBNS poisoning", True),
            ToolCapability("ntlm_capture", "NTLM hash capture", True),
        ],
        "tags": ["network", "poison", "ntlm", "credential"],
        "install_command": "apt install responder",
    },
    {
        "name": "ettercap",
        "binary_name": "ettercap",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.HIGH,
        "description": "Network sniffer/interceptor — MITM attacks",
        "version_cmd": ["ettercap", "--version"],
        "capabilities": [
            ToolCapability("arp_spoof", "ARP spoofing", True),
            ToolCapability("mitm", "Man-in-the-middle attacks", True),
            ToolCapability("traffic_sniff", "Network traffic sniffing", True),
        ],
        "tags": ["network", "mitm", "arp", "sniff"],
        "install_command": "apt install ettercap-text-only",
    },
    {
        "name": "arpspoof",
        "binary_name": "arpspoof",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.HIGH,
        "description": "ARP spoofing tool from dsniff suite",
        "version_cmd": ["arpspoof"],
        "capabilities": [
            ToolCapability("arp_spoof", "ARP cache poisoning", True),
        ],
        "tags": ["network", "arp", "spoof"],
        "install_command": "apt install dsniff",
    },
    {
        "name": "netdiscover",
        "binary_name": "netdiscover",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.LOW,
        "description": "Active/passive ARP reconnaissance tool",
        "version_cmd": ["netdiscover", "-help"],
        "capabilities": [
            ToolCapability("arp_scan", "ARP-based host discovery"),
            ToolCapability("passive_scan", "Passive ARP monitoring"),
        ],
        "tags": ["network", "arp", "discovery"],
        "install_command": "apt install netdiscover",
    },
    # ═══════════════ WIRELESS ════════════════════════════
    {
        "name": "aircrack-ng",
        "binary_name": "aircrack-ng",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.MEDIUM,
        "description": "WiFi security auditing tool suite",
        "version_cmd": ["aircrack-ng", "--help"],
        "capabilities": [
            ToolCapability("wep_crack", "WEP key cracking"),
            ToolCapability("wpa_crack", "WPA/WPA2 handshake cracking"),
            ToolCapability("packet_inject", "Wireless packet injection"),
        ],
        "tags": ["wireless", "wifi", "crack"],
        "install_command": "apt install aircrack-ng",
    },
    # ═══════════════ IMPACKET SUITE ═════════════════════
    {
        "name": "impacket-psexec",
        "binary_name": "impacket-psexec",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.HIGH,
        "description": "Impacket PSExec — remote command execution via SMB",
        "version_cmd": ["impacket-psexec", "--help"],
        "capabilities": [
            ToolCapability("remote_exec", "Remote command execution", True),
        ],
        "tags": ["smb", "remote", "exec", "windows"],
        "install_command": "apt install impacket-scripts",
    },
    {
        "name": "impacket-smbexec",
        "binary_name": "impacket-smbexec",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.HIGH,
        "description": "Impacket SMBExec — semi-interactive shell via SMB",
        "version_cmd": ["impacket-smbexec", "--help"],
        "capabilities": [
            ToolCapability("smb_shell", "Semi-interactive SMB shell"),
        ],
        "tags": ["smb", "shell", "windows"],
        "install_command": "apt install impacket-scripts",
    },
    {
        "name": "impacket-wmiexec",
        "binary_name": "impacket-wmiexec",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.HIGH,
        "description": "Impacket WMIExec — semi-interactive shell via WMI",
        "version_cmd": ["impacket-wmiexec", "--help"],
        "capabilities": [
            ToolCapability("wmi_shell", "Semi-interactive WMI shell"),
        ],
        "tags": ["wmi", "shell", "windows"],
        "install_command": "apt install impacket-scripts",
    },
    {
        "name": "impacket-secretsdump",
        "binary_name": "impacket-secretsdump",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.CRITICAL,
        "description": "Impacket secretsdump — extract credentials from SAM/NTDS/LSA",
        "version_cmd": ["impacket-secretsdump", "--help"],
        "capabilities": [
            ToolCapability("sam_dump", "SAM database dumping"),
            ToolCapability("ntds_dump", "NTDS.dit extraction"),
            ToolCapability("lsa_dump", "LSA secrets dumping"),
            ToolCapability("dcsync", "DCSync replication attack"),
        ],
        "tags": ["credential", "dump", "windows", "ad"],
        "install_command": "apt install impacket-scripts",
    },
    {
        "name": "impacket-GetNPUsers",
        "binary_name": "impacket-GetNPUsers",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.LOW,
        "description": "Impacket — AS-REP Roasting (no pre-auth required users)",
        "version_cmd": ["impacket-GetNPUsers", "--help"],
        "capabilities": [
            ToolCapability("asrep_roast", "AS-REP Roasting attack"),
        ],
        "tags": ["ad", "kerberos", "roast"],
        "install_command": "apt install impacket-scripts",
    },
    {
        "name": "impacket-GetUserSPNs",
        "binary_name": "impacket-GetUserSPNs",
        "category": ToolCategory.EXPLOIT,
        "risk_level": RiskLevel.LOW,
        "description": "Impacket — Kerberoasting (SPN service ticket extraction)",
        "version_cmd": ["impacket-GetUserSPNs", "--help"],
        "capabilities": [
            ToolCapability("kerberoast", "Kerberoasting attack"),
        ],
        "tags": ["ad", "kerberos", "roast", "spn"],
        "install_command": "apt install impacket-scripts",
    },
    # ═══════════════ UTILITY ═════════════════════════════
    {
        "name": "curl",
        "binary_name": "curl",
        "category": ToolCategory.RECON_WEB,
        "risk_level": RiskLevel.SAFE,
        "description": "Command-line HTTP/S client",
        "version_cmd": ["curl", "--version"],
        "capabilities": [
            ToolCapability("http_request", "Custom HTTP requests"),
            ToolCapability("header_check", "Response header inspection"),
            ToolCapability("redirect_follow", "Redirect chain following"),
        ],
        "tags": ["http", "utility", "request"],
        "install_command": "apt install curl",
    },
    {
        "name": "socat",
        "binary_name": "socat",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.LOW,
        "description": "Multipurpose relay for bidirectional data transfer",
        "version_cmd": ["socat", "-V"],
        "capabilities": [
            ToolCapability("port_forward", "Port forwarding"),
            ToolCapability("tunnel", "Encrypted tunneling"),
        ],
        "tags": ["network", "relay", "tunnel"],
        "install_command": "apt install socat",
    },
    {
        "name": "proxychains",
        "binary_name": "proxychains4",
        "category": ToolCategory.PROXY,
        "risk_level": RiskLevel.SAFE,
        "description": "Redirect connections through proxy servers (Tor/SOCKS)",
        "version_cmd": ["proxychains4", "--help"],
        "capabilities": [
            ToolCapability("proxy_chain", "Route traffic through proxy chain"),
            ToolCapability("tor_routing", "Route through Tor network"),
        ],
        "tags": ["proxy", "tor", "anonymity"],
        "install_command": "apt install proxychains4",
    },
    {
        "name": "macchanger",
        "binary_name": "macchanger",
        "category": ToolCategory.NETWORK,
        "risk_level": RiskLevel.LOW,
        "description": "MAC address spoofing utility",
        "version_cmd": ["macchanger", "--version"],
        "capabilities": [
            ToolCapability("mac_spoof", "MAC address changing"),
        ],
        "tags": ["network", "mac", "spoof"],
        "install_command": "apt install macchanger",
    },
]


# ────────────────────────────────────────────────────────────
# Wordlist & Resource Paths
# ────────────────────────────────────────────────────────────

WORDLIST_PATHS = {
    "rockyou": "/usr/share/wordlists/rockyou.txt",
    "rockyou_gz": "/usr/share/wordlists/rockyou.txt.gz",
    "dirb_common": "/usr/share/dirb/wordlists/common.txt",
    "dirb_big": "/usr/share/dirb/wordlists/big.txt",
    "dirbuster_medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "dirbuster_small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "wfuzz_general": "/usr/share/wfuzz/wordlist/general/common.txt",
    "nmap_lst": "/usr/share/wordlists/nmap.lst",
    "fasttrack": "/usr/share/wordlists/fasttrack.txt",
    "metasploit": "/usr/share/wordlists/metasploit/",
    "amass": "/usr/share/wordlists/amass/",
    "fern_wifi": "/usr/share/wordlists/fern-wifi/",
}

NMAP_SCRIPTS_DIR = Path("/usr/share/nmap/scripts")
METASPLOIT_DIR = Path("/usr/share/metasploit-framework")


# ────────────────────────────────────────────────────────────
# Tool Discovery Engine
# ────────────────────────────────────────────────────────────

class ToolDiscoveryEngine:
    """
    Sistemdeki tüm güvenlik araçlarını otomatik keşfeder.
    Versiyon bilgisi çeker, wordlist'leri haritalar.
    """

    def __init__(self) -> None:
        self.discovered_tools: dict[str, DiscoveredTool] = {}
        self.available_wordlists: dict[str, str] = {}
        self.nmap_script_count: int = 0

    async def discover_all(self) -> dict[str, DiscoveredTool]:
        """Tüm bilinen araçları tara ve durumlarını belirle."""
        logger.info("Starting tool discovery...")
        tasks = [self._check_tool(entry) for entry in TOOL_CATALOG]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, DiscoveredTool):
                self.discovered_tools[result.name] = result

        # Wordlist tarama
        self._scan_wordlists()

        # Nmap scripts
        if NMAP_SCRIPTS_DIR.exists():
            self.nmap_script_count = len(list(NMAP_SCRIPTS_DIR.glob("*.nse")))

        installed = sum(1 for t in self.discovered_tools.values() if t.installed)
        total = len(self.discovered_tools)
        logger.info(
            f"Tool discovery complete | installed={installed}/{total} | "
            f"wordlists={len(self.available_wordlists)} | "
            f"nmap_scripts={self.nmap_script_count}"
        )

        return self.discovered_tools

    async def _check_tool(self, entry: dict[str, Any]) -> DiscoveredTool:
        """Tek bir aracı kontrol et."""
        name = entry["name"]
        binary = entry["binary_name"]
        path = shutil.which(binary)

        tool = DiscoveredTool(
            name=name,
            binary_name=binary,
            binary_path=path,
            installed=path is not None,
            category=entry.get("category", ToolCategory.SCANNER),
            risk_level=entry.get("risk_level", RiskLevel.SAFE),
            description=entry.get("description", ""),
            capabilities=entry.get("capabilities", []),
            install_command=entry.get("install_command", ""),
            tags=entry.get("tags", []),
        )

        # Versiyon çek (kuruluysa)
        if tool.installed:
            version_cmd = entry.get("version_cmd")
            if version_cmd:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *version_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                    output = (stdout or stderr or b"").decode("utf-8", errors="replace").strip()
                    if output:
                        tool.version = output.split("\n")[0][:120]
                except Exception as _exc:
                    tool.version = "installed (version unknown)"

            logger.debug(f"Tool found: {name} @ {path} | version={tool.version[:60]}")

        return tool

    def _scan_wordlists(self) -> None:
        """Mevcut wordlist'leri tara."""
        for key, path in WORDLIST_PATHS.items():
            p = Path(path)
            if p.exists():
                self.available_wordlists[key] = str(p)

    def get_installed_tools(self) -> list[DiscoveredTool]:
        """Sadece kurulu araçları döndür."""
        return [t for t in self.discovered_tools.values() if t.installed]

    def get_missing_tools(self) -> list[DiscoveredTool]:
        """Kurulu olmayan araçları döndür."""
        return [t for t in self.discovered_tools.values() if not t.installed]

    def get_tools_by_category(self, category: ToolCategory) -> list[DiscoveredTool]:
        """Kategoriye göre araçları döndür."""
        return [t for t in self.discovered_tools.values()
                if t.installed and t.category == category]

    def get_tools_by_capability(self, capability_name: str) -> list[DiscoveredTool]:
        """Belirli bir yeteneğe sahip araçları döndür."""
        return [
            t for t in self.discovered_tools.values()
            if t.installed and any(c.name == capability_name for c in t.capabilities)
        ]

    def get_best_wordlist(self, purpose: str = "directory") -> str | None:
        """Amaca göre en iyi wordlist'i döndür."""
        priority_map = {
            "directory": ["dirb_common", "dirb_big", "dirbuster_medium"],
            "subdomain": ["amass"],
            "password": ["rockyou", "rockyou_gz", "fasttrack"],
            "general": ["wfuzz_general", "dirb_common"],
        }
        for key in priority_map.get(purpose, ["dirb_common"]):
            if key in self.available_wordlists:
                return self.available_wordlists[key]
        return None

    def generate_report(self) -> str:
        """İnsan okunabilir keşif raporu oluştur."""
        lines = ["=" * 60, "  TOOL DISCOVERY REPORT", "=" * 60, ""]

        # Kategoriye göre grupla
        by_category: dict[str, list[DiscoveredTool]] = {}
        for tool in self.discovered_tools.values():
            cat = tool.category.value
            by_category.setdefault(cat, []).append(tool)

        for cat, tools in sorted(by_category.items()):
            lines.append(f"\n── {cat.upper()} ──")
            for t in sorted(tools, key=lambda x: x.name):
                status = "✓" if t.installed else "✗"
                caps = ", ".join(c.name for c in t.capabilities[:3])
                lines.append(f"  [{status}] {t.name:25s} | {t.description[:50]}")
                if caps:
                    lines.append(f"      capabilities: {caps}")

        lines.append("\n── WORDLISTS ──")
        for key, path in sorted(self.available_wordlists.items()):
            lines.append(f"  {key:25s} → {path}")

        lines.append("\n── SUMMARY ──")
        installed = sum(1 for t in self.discovered_tools.values() if t.installed)
        total = len(self.discovered_tools)
        lines.append(f"  Tools: {installed}/{total} installed")
        lines.append(f"  Nmap scripts: {self.nmap_script_count}")
        lines.append(f"  Wordlists: {len(self.available_wordlists)}")

        return "\n".join(lines)


__all__ = [
    "ToolDiscoveryEngine",
    "DiscoveredTool",
    "ToolCapability",
    "TOOL_CATALOG",
    "WORDLIST_PATHS",
]
