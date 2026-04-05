# Tool Catalog — WhiteHatHacker AI v2.0

Complete catalog of security tools integrated into the bot, organized by category.

---

## Recon — Subdomain Discovery

| Tool | Wrapper | Binary | Type | Description |
|------|---------|--------|------|-------------|
| Amass | `AmassWrapper` | `amass` | Active/Passive | Comprehensive subdomain enumeration |
| Subfinder | `SubfinderWrapper` | `subfinder` | Passive | Fast passive subdomain discovery (Go) |
| Assetfinder | `AssetfinderWrapper` | `assetfinder` | Passive | Find related domains and subdomains |
| Findomain | `FindomainWrapper` | `findomain` | Passive | Cross-platform subdomain finder |
| crt.sh | `CrtShWrapper` | (API) | Passive | Certificate transparency log search |
| KnockPy | `KnockPyWrapper` | `knockpy` | Active | Subdomain bruteforce |

**Aggregator:** `SubdomainAggregator` — Merges and deduplicates results from all subdomain tools.

---

## Recon — Port Scanning

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| Nmap | `NmapWrapper` | `nmap` | Full-featured port scanner with service/version detection |
| Masscan | `MasscanWrapper` | `masscan` | Ultra-fast SYN port scanner |
| RustScan | `RustScanWrapper` | `rustscan` | Fast port scanner with Nmap integration |

---

## Recon — Web Discovery

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| HTTPX | `HttpxWrapper` | `httpx` | HTTP toolkit — probing, tech detect, status codes |
| Katana | `KatanaWrapper` | `katana` | Next-gen web crawler (Go) |
| GoSpider | `GoSpiderWrapper` | `gospider` | Fast web spider |
| Hakrawler | `HakrawlerWrapper` | `hakrawler` | Simple web crawler |
| GAU | `GauWrapper` | `gau` | Fetch known URLs (Wayback, Common Crawl, etc.) |
| Waybackurls | `WaybackurlsWrapper` | `waybackurls` | Wayback Machine URL fetcher |

---

## Recon — DNS

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| DNSRecon | `DnsReconWrapper` | `dnsrecon` | DNS enumeration and zone transfer |
| DNSx | `DnsxWrapper` | `dnsx` | Fast DNS resolver/prober (Go) |
| Dig | `DigWrapper` | `dig` | DNS query utility |
| Zone Transfer | `ZoneTransferChecker` | (builtin) | AXFR zone transfer testing |

---

## Recon — OSINT

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| theHarvester | `TheHarvesterWrapper` | `theHarvester` | Email, subdomain, host discovery |
| Shodan | `ShodanWrapper` | `shodan` | Internet-connected device search (API) |
| Censys | `CensysWrapper` | (API) | Certificate and host intelligence |
| Whois | `WhoisWrapper` | `whois` | Domain registration info |
| Google Dorking | `GoogleDorkWrapper` | (builtin) | Search engine dorking |
| GitHub Dorking | `GitHubDorkWrapper` | (API) | Source code leak detection |

---

## Recon — Technology Detection

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| WhatWeb | `WhatWebWrapper` | `whatweb` | Web technology fingerprinting |
| Wafw00f | `Wafw00fWrapper` | `wafw00f` | WAF detection and fingerprinting |
| Wappalyzer | `WappalyzerWrapper` | (builtin) | Technology stack identification |

---

## Vulnerability Scanners

| Tool | Wrapper | Binary | Vuln Types |
|------|---------|--------|------------|
| Nuclei | `NucleiWrapper` | `nuclei` | Template-based multi-vuln scanner |
| Nikto | `NiktoWrapper` | `nikto` | Web server misconfigurations |
| WPScan | `WpScanWrapper` | `wpscan` | WordPress vulnerabilities |
| SQLMap | `SqlmapWrapper` | `sqlmap` | SQL injection (all techniques) |
| Dalfox | `DalfoxWrapper` | `dalfox` | XSS (DOM, reflected, stored) |
| XSStrike | `XsStrikeWrapper` | `xsstrike` | Advanced XSS detection |
| Commix | `CommixWrapper` | `commix` | Command injection |
| SSRFMap | `SsrfmapWrapper` | `ssrfmap` | SSRF detection and exploitation |
| tplmap | `TplmapWrapper` | `tplmap` | Server-side template injection |
| jwt_tool | `JwtToolWrapper` | `jwt_tool` | JWT vulnerability testing |
| NoSQLMap | `NosqlmapWrapper` | `nosqlmap` | NoSQL injection |
| CRLFuzz | `CrlfuzzWrapper` | `crlfuzz` | CRLF injection |
| Corsy | `CorsyWrapper` | `corsy` | CORS misconfiguration |
| OpenRedirex | `OpenRedirexWrapper` | `openredirex` | Open redirect |
| Smuggler | `SmugglerWrapper` | `smuggler` | HTTP request smuggling |
| Arjun | `ArjunWrapper` | `arjun` | Hidden parameter discovery |
| ParamSpider | `ParamSpiderWrapper` | `paramspider` | Parameter mining from archives |

---

## Custom Checks (`scanners/custom_checks/`)

| Check | Class | Description |
|-------|-------|-------------|
| IDOR | `IdorChecker` | Insecure direct object reference testing |
| Auth Bypass | `AuthBypassChecker` | Authentication bypass techniques |
| Business Logic | `BusinessLogicChecker` | Business logic flaw detection |
| Race Condition | `RaceConditionChecker` | Race condition / TOCTOU testing |
| Rate Limit | `RateLimitChecker` | Rate limiting bypass testing |

---

## Exploit Tools

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| Metasploit | `MetasploitWrapper` | `msfconsole` | Exploitation framework (read-only search) |
| SearchSploit | `SearchSploitWrapper` | `searchsploit` | Exploit database search |
| Payload Generator | `PayloadGenerator` | (builtin) | Custom payload crafting |
| PoC Generator | `PocGenerator` | (builtin) | Proof-of-concept script generation |

---

## Fuzzing Tools

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| FFuf | `FfufWrapper` | `ffuf` | Fast web fuzzer |
| Gobuster | `GobusterWrapper` | `gobuster` | Directory/DNS/vhost brute force |
| Feroxbuster | `FeroxbusterWrapper` | `feroxbuster` | Recursive content discovery |
| Wfuzz | `WfuzzWrapper` | `wfuzz` | Web application fuzzer |
| Dirb | `DirbWrapper` | `dirb` | Web content scanner |

---

## Network Tools

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| Enum4linux | `Enum4linuxWrapper` | `enum4linux` | SMB/Samba enumeration |
| SMBClient | `SmbclientWrapper` | `smbclient` | SMB share access |
| SNMPWalk | `SnmpwalkWrapper` | `snmpwalk` | SNMP enumeration |
| LDAP Search | `LdapSearchWrapper` | `ldapsearch` | LDAP directory queries |
| SSH Audit | `SshAuditWrapper` | `ssh-audit` | SSH configuration audit |
| Netcat | `NetcatWrapper` | `nc` | Network utility (banner grab, etc.) |
| Wireshark | `WiresharkWrapper` | `tshark` | Packet capture and analysis |

---

## Crypto / SSL

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| SSLScan | `SslscanWrapper` | `sslscan` | SSL/TLS configuration testing |
| SSLyze | `SslyzeWrapper` | `sslyze` | SSL/TLS analysis |
| TestSSL | `TestSslWrapper` | `testssl.sh` | Comprehensive TLS testing |

---

## Proxy / Intercept

| Tool | Wrapper | Binary | Description |
|------|---------|--------|-------------|
| mitmproxy | `MitmproxyWrapper` | `mitmdump` | HTTP/S intercepting proxy |
| ZAProxy | `ZaproxyWrapper` | `zaproxy` | OWASP ZAP scanner |
| Burp API | `BurpApiWrapper` | (API) | Burp Suite integration |

---

## API Security

| Tool | Wrapper | Description |
|------|---------|-------------|
| Swagger Parser | `SwaggerParser` | OpenAPI/Swagger spec analysis |
| GraphQL Introspection | `GraphqlIntrospection` | GraphQL schema discovery |
| JWT Analyzer | `JwtAnalyzer` | JWT token security analysis |
| OAuth Tester | `OAuthTester` | OAuth flow testing |
| API Fuzzer | `ApiFuzzer` | API endpoint fuzzing |
| REST Analyzer | `RestAnalyzer` | REST API security checks |

---

## Tool Availability By Platform

| Tool | Kali (apt) | Go Install | Python/pip | Notes |
|------|:----------:|:----------:|:----------:|-------|
| nmap | ✅ | — | — | Core tool |
| nuclei | — | ✅ | — | Requires Go |
| sqlmap | ✅ | — | — | Pre-installed on Kali |
| subfinder | — | ✅ | — | Requires Go |
| httpx | — | ✅ | ✅ (different) | Go version preferred |
| mitmproxy | ✅ | — | ✅ | pip or apt |

Run `scripts/health_check.sh` to see which tools are available on your system.
