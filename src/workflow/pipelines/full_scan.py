"""
WhiteHatHacker AI — Full Scan Pipeline

Tam kapsamlı güvenlik taraması pipeline'ı.
10 aşamanın tümünü çalıştırır ve her aşama için
concrete stage handler fonksiyonları sağlar.
"""

from __future__ import annotations

import asyncio
import json
import re as _re
import time
from collections import defaultdict
from typing import Any

import httpx
from loguru import logger

from src.tools.scanners.waf_strategy import detect_waf, apply_rate_adjustment, WAFResult
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
from src.workflow.pipelines import asset_db_hooks as _adb


def _get_executor(state: WorkflowState):
    """Return state.tool_executor, or create a fallback with scope_validator wired."""
    if state.tool_executor:
        return state.tool_executor
    from src.tools.registry import tool_registry
    from src.tools.executor import ToolExecutor
    logger.warning("state.tool_executor is None — creating fallback ToolExecutor")
    executor = ToolExecutor(registry=tool_registry)
    # Propagate scope_validator from state if available
    if state.scope_config:
        try:
            from src.utils.scope_validator import ScopeValidator
            executor.scope_validator = ScopeValidator.from_dict(state.scope_config)
            logger.info("Fallback ToolExecutor: scope_validator wired from state.scope_config")
        except Exception as e:
            logger.warning(f"Fallback ToolExecutor: could not wire scope_validator: {e}")
    return executor


# ============================================================
# Stage Handlers
# ============================================================

async def handle_scope_analysis(state: WorkflowState) -> StageResult:
    """
    Aşama 1: Scope Analizi

    - Hedef domain/IP doğrulama
    - Scope sınırlarını belirleme
    - Tarama stratejisi önerme
    """
    from src.utils.scope_validator import ScopeValidator

    result = StageResult(stage=WorkflowStage.SCOPE_ANALYSIS)

    try:
        target = state.target
        logger.info(f"Scope analysis started | target={target}")

        # Record scan start time for benchmark (V8-T0-1)
        import time as _scope_time
        state.metadata = state.metadata or {}
        state.metadata["scan_start_time"] = _scope_time.time()

        # ── ScanProfiler: create at pipeline START (P2-1) ──
        try:
            from src.analysis.scan_profiler import ScanProfiler
            _profiler = ScanProfiler()
            _profiler.start_scan()
            state.metadata["scan_profiler"] = _profiler
            # Wire profiler into tool executor for per-tool timing (P2-2)
            if state.tool_executor is not None:
                state.tool_executor.perf_profiler = _profiler
            logger.info("ScanProfiler created at pipeline start")
        except Exception as _prof_init_err:
            logger.warning(f"ScanProfiler init skipped: {_prof_init_err}")

        # ── P4-2: Pre-scan tool availability check ──
        try:
            from src.tools.registry import tool_registry as _pre_reg
            _unavailable: list[str] = []
            for _tname, _tinst in _pre_reg.get_all().items():
                try:
                    if not _tinst.is_available():
                        _unavailable.append(_tname)
                except Exception as _tool_avail_err:
                    _unavailable.append(_tname)
                    logger.debug(f"Tool {_tname} availability check error: {_tool_avail_err}")
            if _unavailable:
                logger.warning(
                    f"Pre-scan check: {len(_unavailable)} tools unavailable: "
                    f"{', '.join(sorted(_unavailable)[:20])}"
                )
            state.metadata["unavailable_tools"] = sorted(_unavailable)
        except Exception as _avail_err:
            logger.warning(f"Tool availability check skipped: {_avail_err}")

        # DNS/WHOIS bilgisi topla
        scope_data: dict[str, Any] = {
            "target": target,
            "type": _detect_target_type(target),
            "scope_valid": True,
        }

        # Scope validator ile doğrula (scope tanımı varsa)
        try:
            from src.utils.scope_validator import ScopeDefinition, ScopeTarget
            if state.scope_config:
                # Use full scope config from YAML file
                validator = ScopeValidator.from_dict(state.scope_config)
                scope_data["program_name"] = state.scope_config.get("program_name", "")
                scope_data["excluded_count"] = len(validator.scope.excluded_targets)
            else:
                # Create ad-hoc validator for basic target validation
                default_scope = ScopeDefinition(
                    program_name="ad-hoc",
                    targets=[ScopeTarget(value=target, target_type=_detect_target_type(target))],
                )
                validator = ScopeValidator(scope=default_scope)
            scope_data["scope_valid"] = validator.is_in_scope(target)

            # ── Wire scope validator to tool executor (critical for tool execution) ──
            if state.tool_executor and not getattr(state.tool_executor, "scope_validator", None):
                state.tool_executor.scope_validator = validator
                logger.info("ScopeValidator wired to ToolExecutor from scope_analysis stage")
        except Exception as e:
            logger.warning(f"ScopeValidator setup failed — proceeding without scope enforcement: {e}")
            scope_data["scope_valid"] = True  # Default: valid (no scope config avail)

        if not scope_data["scope_valid"]:
            result.success = False
            result.errors.append(f"Target {target} is out of scope")
            return result

        # Tarama stratejisi belirle
        scope_data["recommended_profile"] = state.profile.value
        scope_data["target_class"] = scope_data["type"]

        result.data = scope_data
        result.success = True

        # AssetDB: scan başlangıcını kaydet
        scan_id = _adb.record_scan_start(state)
        state.metadata["asset_db_scan_id"] = scan_id

        logger.info(
            f"Scope analysis complete | type={scope_data['type']} | "
            f"valid={scope_data['scope_valid']}"
        )

    except Exception as e:
        logger.error(f"Scope analysis failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_passive_recon(state: WorkflowState) -> StageResult:
    """
    Aşama 2: Pasif Keşif

    - Subdomain enumeration
    - OSINT toplama
    - DNS analizi
    - Wayback/archive URL toplama
    """
    result = StageResult(stage=WorkflowStage.PASSIVE_RECON)

    try:
        target = state.target
        logger.info(f"Passive recon started | target={target}")

        from src.tools.registry import tool_registry
        executor = _get_executor(state)
        collected: dict[str, Any] = {
            "subdomains": [],
            "emails": [],
            "dns_records": [],
            "urls": [],
            "technologies": [],
        }

        # ── Maximum collected items — scaled by profile ──
        from src.utils.constants import ScanProfile as _SP
        _profile_val = state.profile.value if state.profile else "balanced"
        _LIMITS = {
            _SP.STEALTH: (300, 2000),
            _SP.BALANCED: (500, 5000),
            _SP.AGGRESSIVE: (2000, 20000),
        }
        MAX_SUBDOMAINS, MAX_URLS = _LIMITS.get(state.profile, (500, 5000))
        # Persist limits into state.metadata so downstream stages can use them
        state.metadata = state.metadata or {}
        state.metadata["max_subdomains"] = MAX_SUBDOMAINS
        state.metadata["max_urls"] = MAX_URLS

        # ── Helper: run a tool group in parallel ──
        async def _run_tool_group(
            tool_names: list[str],
            target: str,
            options: dict[str, Any] | None = None,
            group_name: str = "",
        ) -> list:
            """Run multiple tools in parallel. Returns list of (tool_name, ToolResult) tuples."""
            opts = options or {}
            results = []
            available_tools = []
            for name in tool_names:
                t = tool_registry.get(name)
                if t and t.is_available():
                    available_tools.append((name, t))

            if not available_tools:
                return results

            async def _run_single(name: str, tool):
                try:
                    r = await executor.execute(tool, target, opts)
                    return (name, r)
                except Exception as e:
                    logger.warning(f"{group_name} tool {name} failed: {e}")
                    return (name, None)

            tasks = [_run_single(n, t) for n, t in available_tools]
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for item in completed:
                if isinstance(item, Exception):
                    logger.warning(f"{group_name} parallel task error: {item}")
                elif item:
                    results.append(item)
            return results

        # ── Subdomain Enumeration (parallel) ──
        logger.info("Running subdomain enumeration tools in parallel...")
        subdomain_results = await _run_tool_group(
            ["amass", "subfinder", "assetfinder", "findomain"],
            target, {"mode": "passive"}, "Subdomain"
        )
        for tool_name, tool_result in subdomain_results:
            if tool_result and tool_result.findings:
                for f in tool_result.findings:
                    subdomain = getattr(f, "target", "")
                    if subdomain and subdomain not in collected["subdomains"]:
                        collected["subdomains"].append(subdomain)
                        if len(collected["subdomains"]) >= MAX_SUBDOMAINS:
                            break

        # ── OSINT (parallel) ──
        logger.info("Running OSINT tools in parallel...")
        osint_results = await _run_tool_group(
            ["theHarvester", "whois", "shodan"],
            target, {}, "OSINT"
        )
        for tool_name, tool_result in osint_results:
            if tool_result and tool_result.raw_output:
                collected["osint_" + tool_name] = tool_result.raw_output[:2000]

        # ── DNS (parallel) ──
        logger.info("Running DNS tools in parallel...")
        dns_results = await _run_tool_group(
            ["dnsrecon", "dig"],
            target, {}, "DNS"
        )
        for tool_name, tool_result in dns_results:
            if tool_result and tool_result.findings:
                for f in tool_result.findings:
                    collected["dns_records"].append(
                        getattr(f, "description", str(f))
                    )

        # ── Wayback / GAU (parallel URL toplama) ──
        logger.info("Running URL collection tools in parallel...")
        url_results = await _run_tool_group(
            ["gau", "waybackurls"],
            target, {}, "URL"
        )
        for tool_name, tool_result in url_results:
            if tool_result and tool_result.findings:
                for f in tool_result.findings:
                    url = getattr(f, "endpoint", "") or getattr(f, "target", "")
                    if url and url not in collected["urls"]:
                        collected["urls"].append(url)
                        if len(collected["urls"]) >= MAX_URLS:
                            break
                logger.info(f"{tool_name} collected {len(tool_result.findings)} URLs")

        if collected["urls"]:
            logger.info(f"Total passive URLs collected: {len(collected['urls'])}")

        # ── GitHub Secret Scanner (V9-T1-1) — Search for leaked secrets in GitHub ──
        try:
            from src.tools.recon.osint.github_secret_scanner import GitHubSecretScanner
            _gh_scanner = GitHubSecretScanner()
            if _gh_scanner.is_available():
                _gh_result = await asyncio.wait_for(
                    _gh_scanner.run(target, {}),
                    timeout=1200.0,
                )
                if _gh_result and _gh_result.findings:
                    collected["github_secrets"] = [
                        _finding_to_dict(f, "github_secret_scanner")
                        for f in _gh_result.findings
                    ]
                    logger.info(f"GitHub secret scanner: {len(_gh_result.findings)} findings")
        except asyncio.TimeoutError:
            logger.warning("GitHub secret scanner timed out")
        except ImportError:
            logger.debug("GitHub secret scanner module not available")
        except Exception as _gh_exc:
            logger.warning(f"GitHub secret scanner error: {_gh_exc}")

        # ── Email Security Checker (V9-T1-2) — SPF/DKIM/DMARC analysis ──
        try:
            from src.tools.recon.dns.mail_security import EmailSecurityChecker
            _mail_checker = EmailSecurityChecker()
            if _mail_checker.is_available():
                _mail_result = await asyncio.wait_for(
                    _mail_checker.run(target, {}),
                    timeout=1200.0,
                )
                if _mail_result and _mail_result.findings:
                    collected["mail_security"] = [
                        _finding_to_dict(f, "mail_security_checker")
                        for f in _mail_result.findings
                    ]
                    logger.info(f"Email security checker: {len(_mail_result.findings)} findings")
        except asyncio.TimeoutError:
            logger.warning("Email security checker timed out")
        except ImportError:
            logger.debug("Email security checker module not available")
        except Exception as _mail_exc:
            logger.warning(f"Email security checker error: {_mail_exc}")

        # State güncelle
        state.subdomains = collected["subdomains"]

        # AssetDB: subdomain'leri kaydet
        _adb.save_subdomains(state)

        result.data = collected
        result.findings_count = len(collected["subdomains"])
        result.success = True

        logger.info(
            f"Passive recon complete | subdomains={len(collected['subdomains'])} | "
            f"dns_records={len(collected['dns_records'])}"
        )

    except Exception as e:
        logger.error(f"Passive recon failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_active_recon(state: WorkflowState) -> StageResult:
    """
    Aşama 3: Aktif Keşif

    - HTTP probe (canlılık kontrolü)
    - Port tarama
    - Web crawling
    - Teknoloji tespiti
    """
    result = StageResult(stage=WorkflowStage.ACTIVE_RECON)

    try:
        target = state.target
        hosts = state.subdomains or [target]

        logger.info(f"Active recon started | hosts={len(hosts)}")

        # Smart deduplication — CDN/cache kopyalarını azalt
        hosts = _deduplicate_hosts(hosts, base_domain=target, max_per_group=2, max_total=40)
        logger.info(f"After dedup | hosts={len(hosts)}")

        from src.tools.registry import tool_registry
        executor = _get_executor(state)
        collected: dict[str, Any] = {
            "live_hosts": [],
            "ports": {},
            "services": {},
            "technologies": {},
        }

        # ── Extract auth headers for authenticated crawling (V11-T2-2) ──
        _recon_auth_headers: dict[str, str] = (
            state.auth_headers
            or (state.metadata.get("auth_headers", {}) if state.metadata else {})
        )

        # ── HTTP Probe (httpx) — batch mode for performance ──
        httpx_tool = tool_registry.get("httpx")
        if httpx_tool and httpx_tool.is_available():
            try:
                # Use batch probing if wrapper supports it
                probe_hosts = hosts[:50]
                if hasattr(httpx_tool, "run_batch"):
                    tool_result = await httpx_tool.run_batch(
                        probe_hosts, {}, state.profile
                    )
                    if tool_result and tool_result.findings:
                        for f in tool_result.findings:
                            url = getattr(f, "target", "") or getattr(f, "endpoint", "")
                            if url:
                                # Extract hostname from URL
                                from urllib.parse import urlparse
                                parsed = urlparse(url)
                                hostname = parsed.hostname or url
                                if hostname not in collected["live_hosts"]:
                                    collected["live_hosts"].append(hostname)
                                # Collect technology info from metadata
                                meta = getattr(f, "metadata", {}) or {}
                                techs = meta.get("technologies", [])
                                server = meta.get("server", "")
                                if techs or server:
                                    tech_info = ", ".join(techs)
                                    if server:
                                        tech_info = f"{server}; {tech_info}" if tech_info else server
                                    collected["technologies"][hostname] = tech_info
                    logger.info(
                        f"httpx batch probe | input={len(probe_hosts)} | "
                        f"live={len(collected['live_hosts'])}"
                    )
                else:
                    # Fallback: probe one by one
                    for host in probe_hosts:
                        try:
                            tool_result = await executor.execute(httpx_tool, host, {})
                            if tool_result and tool_result.success and tool_result.findings:
                                collected["live_hosts"].append(host)
                        except Exception as exc:
                            logger.warning(f"httpx probe {host} failed: {exc}")
            except Exception as e:
                logger.warning(f"httpx batch probe failed: {e}")
                # Fallback: assume all hosts are live
                collected["live_hosts"] = hosts[:50]
        else:
            # HTTP probe olmadan tüm hostları canlı kabul et
            collected["live_hosts"] = hosts[:50]

        # ── Port Scan (nmap) — parallel, limit to unique hosts, skip CDN dupes ──
        nmap_tool = tool_registry.get("nmap")
        if nmap_tool and nmap_tool.is_available():
            # Detect CDN-fronted hosts from httpx technology info — skip nmap for them
            _CDN_SIGNATURES = {"cloudflare", "akamai", "fastly", "cloudfront", "sucuri", "incapsula", "stackpath", "cdn"}
            _cdn_hosts = set()
            for h, tech in collected["technologies"].items():
                if any(sig in tech.lower() for sig in _CDN_SIGNATURES):
                    _cdn_hosts.add(h)
            if _cdn_hosts:
                logger.info(f"CDN-fronted hosts detected (skipping nmap): {', '.join(list(_cdn_hosts)[:5])}")

            # Only scan interesting hosts (not cache/web CDN nodes, not CDN-fronted) — cap at 3
            nmap_hosts = [h for h in collected["live_hosts"][:10]
                         if not _re.match(r"^(web|cache|node|lb|edge)\d+\.", h)
                         and h not in _cdn_hosts][:3]
            if not nmap_hosts:
                # All hosts are CDN-fronted — skip nmap entirely
                logger.info("All live hosts are CDN-fronted, skipping port scan")
            else:
                logger.info(f"Port scanning {len(nmap_hosts)} non-CDN hosts in parallel")
                nmap_sem = asyncio.Semaphore(2)  # Max 2 concurrent nmap scans
                _nmap_per_host_timeout = 600.0   # 10 min per host
                _NMAP_TOTAL_BUDGET = 600.0       # 10 min total for all nmap
                import time as _nmap_time
                _nmap_budget_start = _nmap_time.monotonic()

                async def _nmap_host(host: str) -> tuple[str, list[int]]:
                    elapsed = _nmap_time.monotonic() - _nmap_budget_start
                    remaining = _NMAP_TOTAL_BUDGET - elapsed
                    if remaining < 30:
                        logger.info(f"Nmap total budget exhausted, skipping {host}")
                        return host, []
                    async with nmap_sem:
                        try:
                            scan_opts = _get_scan_options(state.profile, "port_scan")
                            _timeout = min(_nmap_per_host_timeout, remaining)
                            tool_result = await asyncio.wait_for(
                                executor.execute(nmap_tool, host, scan_opts),
                                timeout=_timeout,
                            )
                            if tool_result and tool_result.findings:
                                ports: list[int] = []
                                for f in tool_result.findings:
                                    for tag in getattr(f, "tags", []):
                                        if tag.startswith("port:"):
                                            try:
                                                ports.append(int(tag.split(":")[1]))
                                            except (ValueError, IndexError):
                                                pass
                                    if not ports:
                                        ep = getattr(f, "endpoint", "")
                                        if ":" in ep:
                                            try:
                                                ports.append(int(ep.rsplit(":", 1)[1]))
                                            except (ValueError, IndexError):
                                                pass
                                return host, list(set(ports))
                        except asyncio.TimeoutError:
                            logger.warning(f"Port scan {host} timed out ({_timeout:.0f}s)")
                        except Exception as e:
                            logger.warning(f"Port scan {host} failed: {e}")
                        return host, []

                nmap_results = await asyncio.gather(
                    *[_nmap_host(h) for h in nmap_hosts],
                    return_exceptions=True,
                )
                for nr in nmap_results:
                    if isinstance(nr, tuple) and nr[1]:
                        collected["ports"][nr[0]] = nr[1]

        # ── Technology Detection (whatweb) — parallel on top priority hosts ──
        whatweb_tool = tool_registry.get("whatweb")
        if whatweb_tool and whatweb_tool.is_available():
            whatweb_hosts = collected["live_hosts"][:10]
            ww_semaphore = asyncio.Semaphore(4)  # Max 4 concurrent whatweb scans

            async def _whatweb_host(host: str) -> tuple[str, str]:
                async with ww_semaphore:
                    try:
                        tool_result = await executor.execute(whatweb_tool, host, {})
                        if tool_result and tool_result.raw_output:
                            return host, tool_result.raw_output[:500]
                    except Exception as exc:
                        logger.warning(f"whatweb {host} failed: {exc}")
                    return host, ""

            ww_results = await asyncio.gather(
                *[_whatweb_host(h) for h in whatweb_hosts],
                return_exceptions=True,
            )
            for res in ww_results:
                if isinstance(res, Exception):
                    continue
                host, tech_info = res
                if tech_info:
                    collected["technologies"][host] = tech_info

        # ── Favicon Hash Technology Detection (V8-T0-4) ──
        try:
            from src.tools.recon.tech_detect.favicon_hasher import FaviconHasher as _FaviconHasher
            _fav_hasher = _FaviconHasher()
            if _fav_hasher.is_available() and collected["live_hosts"]:
                _fav_hosts = collected["live_hosts"][:10]
                _fav_tasks = [_fav_hasher.run(h) for h in _fav_hosts]
                _fav_results = await asyncio.gather(*_fav_tasks, return_exceptions=True)
                _fav_techs: list[str] = []
                for _fr in _fav_results:
                    if isinstance(_fr, Exception):
                        continue
                    if _fr and _fr.findings:
                        for _ff in _fr.findings:
                            if "unknown" not in (_ff.title or "").lower():
                                _fav_techs.append(_ff.title)
                            # Merge favicon tech into collected technologies
                            _fav_url = getattr(_ff, "url", "") or ""
                            if _fav_url and _ff.evidence and isinstance(_ff.evidence, dict):
                                _tech_name = _ff.evidence.get("technology", "")
                                if _tech_name and _tech_name != "unknown":
                                    for _fh in _fav_hosts:
                                        if _fh in _fav_url:
                                            _existing = collected["technologies"].get(_fh, "")
                                            if _tech_name.lower() not in _existing.lower():
                                                collected["technologies"][_fh] = (
                                                    f"{_existing}, {_tech_name}" if _existing else _tech_name
                                                )
                                            break
                if _fav_techs:
                    logger.info(f"Favicon hash detected: {', '.join(_fav_techs[:5])}")
        except Exception as _fav_exc:
            logger.warning(f"Favicon hash detection failed: {_fav_exc}")

        # ── CDN Detector (V9-T1-3) — Identify CDN/proxy in front of targets ──
        try:
            from src.tools.recon.tech_detect.cdn_detector import CDNDetector
            _cdn_det = CDNDetector()
            if _cdn_det.is_available() and collected["live_hosts"]:
                _cdn_result = await asyncio.wait_for(
                    _cdn_det.run(target, {}),
                    timeout=1200.0,
                )
                if _cdn_result and _cdn_result.findings:
                    _cdn_names = [getattr(f, "title", "") for f in _cdn_result.findings]
                    collected["cdn_info"] = _cdn_names
                    logger.info(f"CDN detector: {', '.join(_cdn_names[:3])}")
        except asyncio.TimeoutError:
            logger.warning("CDN detector timed out")
        except ImportError:
            logger.debug("CDN detector module not available")
        except Exception as _cdn_exc:
            logger.warning(f"CDN detection failed: {_cdn_exc}")

        # ── Reverse IP Lookup (V9-T1-4) — Discover co-hosted domains ──
        try:
            from src.tools.recon.dns.reverse_ip import ReverseIPLookup
            _rip = ReverseIPLookup()
            if _rip.is_available():
                _rip_result = await asyncio.wait_for(
                    _rip.run(target, {}),
                    timeout=1200.0,
                )
                if _rip_result and _rip_result.findings:
                    _cohosted = [
                        getattr(f, "target", "") or getattr(f, "endpoint", "")
                        for f in _rip_result.findings
                    ]
                    _cohosted = [d for d in _cohosted if d]
                    collected["cohosted_domains"] = _cohosted[:50]
                    logger.info(f"Reverse IP lookup: {len(_cohosted)} co-hosted domains")
        except asyncio.TimeoutError:
            logger.warning("Reverse IP lookup timed out")
        except ImportError:
            logger.debug("Reverse IP lookup module not available")
        except Exception as _rip_exc:
            logger.warning(f"Reverse IP lookup error: {_rip_exc}")

        # ── Web Crawling (katana) — discover endpoints on live hosts ──
        katana_tool = tool_registry.get("katana")
        crawled_urls: list[str] = []
        if katana_tool and katana_tool.is_available():
            # Crawl top priority hosts for endpoint discovery — PARALLEL
            crawl_hosts = collected["live_hosts"][:8]
            crawl_semaphore = asyncio.Semaphore(3)  # Max 3 concurrent crawls

            async def _crawl_host(host: str) -> list[str]:
                """Crawl a single host under semaphore."""
                async with crawl_semaphore:
                    try:
                        target_url = f"https://{host}" if not host.startswith("http") else host
                        _katana_opts: dict[str, Any] = {"depth": 2, "timeout": 120}
                        if _recon_auth_headers:
                            _katana_opts["headers"] = _recon_auth_headers
                        tool_result = await executor.execute(
                            katana_tool, target_url, _katana_opts
                        )
                        urls: list[str] = []
                        if tool_result and tool_result.findings:
                            for f in tool_result.findings:
                                url = getattr(f, "endpoint", "") or getattr(f, "target", "")
                                if url:
                                    urls.append(url)
                        return urls
                    except Exception as e:
                        logger.warning(f"Katana crawl {host} failed: {e}")
                        return []

            host_results = await asyncio.gather(
                *[_crawl_host(h) for h in crawl_hosts],
                return_exceptions=True,
            )
            seen_urls: set[str] = set()
            for res in host_results:
                if isinstance(res, Exception):
                    logger.warning(f"Katana parallel crawl error: {res}")
                    continue
                for url in res:
                    if url not in seen_urls:
                        seen_urls.add(url)
                        crawled_urls.append(url)
            if crawled_urls:
                logger.info(f"Katana crawled {len(crawled_urls)} unique URLs (parallel)")

        # ── Spider (gospider) — secondary crawling ──
        gospider_tool = tool_registry.get("gospider")
        if gospider_tool and gospider_tool.is_available() and len(crawled_urls) < 50:
            # Use gospider on top hosts if katana found few URLs
            spider_hosts = collected["live_hosts"][:5]
            for host in spider_hosts:
                try:
                    target_url = f"https://{host}" if not host.startswith("http") else host
                    _gospider_opts: dict[str, Any] = {"depth": 2, "timeout": 180}
                    if _recon_auth_headers:
                        _gospider_opts["headers"] = _recon_auth_headers
                    tool_result = await executor.execute(
                        gospider_tool, target_url, _gospider_opts
                    )
                    if tool_result and tool_result.findings:
                        for f in tool_result.findings:
                            url = getattr(f, "endpoint", "") or getattr(f, "target", "")
                            if url and url not in crawled_urls:
                                crawled_urls.append(url)
                except Exception as e:
                    logger.warning(f"GoSpider {host} failed: {e}")
            if crawled_urls:
                logger.info(f"Total crawled URLs after GoSpider: {len(crawled_urls)}")

        # Add crawled URLs to collected data
        # Clean crawler output prefixes (e.g. gospider's "[code-200] - ")
        import re as _re_clean
        def _clean_crawled_url(url: str) -> str:
            url = url.strip()
            if url.startswith("["):
                m = _re_clean.match(r'\[code-\d+\]\s*-\s*', url)
                if m:
                    url = url[m.end():].strip()
            return url
        crawled_urls = [_clean_crawled_url(u) for u in crawled_urls if u]
        crawled_urls = [u for u in crawled_urls if u and u.startswith("http")]
        collected["crawled_urls"] = crawled_urls

        # State güncelle
        state.live_hosts = collected["live_hosts"]
        state.open_ports = collected["ports"]
        state.technologies = collected["technologies"]

        # Seed state.endpoints with crawled URLs so downstream stages
        # have data even if enumeration times out
        if crawled_urls:
            _max_urls = (state.metadata or {}).get("max_urls", 5000)
            state.endpoints = crawled_urls[:_max_urls]  # Respect profile-scaled limit
            logger.info(f"Seeded state.endpoints with {len(state.endpoints)} crawled URLs")

        # ── Host Intelligence Profiling (Phase 0.3) ──
        # Profile each live host BEFORE any vulnerability scanning to determine
        # host type (SPA, API, static, CDN-only, auth-gated, etc.) and compute
        # per-host checker skip lists.  This eliminates irrelevant tests and
        # reduces false positives from the very start.
        try:
            from src.analysis.host_profiler import HostProfiler

            _hp = HostProfiler()
            _hp_hosts: list[str] = []
            for _h in collected["live_hosts"]:
                if isinstance(_h, str) and _h:
                    _hp_hosts.append(
                        _h if _h.startswith("http") else f"https://{_h}"
                    )
            if _hp_hosts:
                _hp_timeout = 8.0  # per-host budget (fast, non-blocking)
                _hp_profiles = await _hp.profile_hosts(_hp_hosts, timeout=_hp_timeout)
                # Persist as serializable dicts so checkpoint/resume works
                state.metadata["host_profiles"] = {
                    h: p.to_dict() for h, p in _hp_profiles.items()
                }
                _hp_types = {}
                for _p in _hp_profiles.values():
                    _hp_types[_p.host_type.value] = _hp_types.get(_p.host_type.value, 0) + 1
                logger.info(
                    f"🔬 Host profiling complete | {len(_hp_profiles)} hosts | "
                    f"types: {_hp_types}"
                )
            else:
                state.metadata["host_profiles"] = {}
        except Exception as _hp_err:
            logger.warning(f"Host profiling failed (non-fatal): {_hp_err}")
            state.metadata["host_profiles"] = {}

        # ── Screenshot Capture — visual evidence of live hosts ──
        try:
            from src.reporting.evidence.screenshot import ScreenshotCapture, ScreenshotConfig

            ss_config = ScreenshotConfig(
                output_dir=f"output/screenshots/{state.session_id}",
                timeout_seconds=20,
                delay_ms=1500,
            )
            ss_capture = ScreenshotCapture(config=ss_config)
            if ss_capture.is_available:
                # Screenshot top live hosts (max 10, respect scan time budget)
                ss_hosts = collected["live_hosts"][:10]
                ss_urls = [
                    f"https://{h}" if not h.startswith("http") else h
                    for h in ss_hosts
                ]
                ss_results = await ss_capture.capture_multiple(
                    ss_urls, max_concurrent=3,
                )
                captured = [r for r in ss_results if r.success]
                collected["screenshots"] = [
                    ScreenshotCapture.create_evidence_entry(r) for r in captured
                ]
                if captured:
                    logger.info(
                        f"📸 Screenshots captured: {len(captured)}/{len(ss_urls)} hosts"
                    )
            else:
                logger.debug("Screenshot backend not available — skipping visual evidence")
        except Exception as ss_err:
            logger.debug(f"Screenshot capture skipped: {ss_err}")

        result.data = collected
        result.findings_count = len(collected["live_hosts"])
        result.success = True

        # AssetDB: live host'ları kaydet
        _adb.save_live_hosts(state)

        logger.info(
            f"Active recon complete | live={len(collected['live_hosts'])} | "
            f"ports_scanned={len(collected['ports'])}"
        )

    except Exception as e:
        logger.error(f"Active recon failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_enumeration(state: WorkflowState) -> StageResult:
    """
    Aşama 4: Derinlemesine Enumeration

    - Parameter keşfi
    - Directory/file brute force
    - API endpoint keşfi
    - Authentication analizi
    """
    result = StageResult(stage=WorkflowStage.ENUMERATION)

    # Resolve scan profile for profile-aware scaling decisions
    _scan_profile = getattr(state, "profile", None)
    if _scan_profile:
        _scan_profile = getattr(_scan_profile, "value", str(_scan_profile)).lower()
    else:
        _scan_profile = "balanced"

    # Define collected outside try so finally block can access it
    collected: dict[str, Any] = {
        "endpoints": [],
        "parameters": [],
        "directories": [],
    }

    try:
        live_hosts = state.live_hosts or [state.target]
        logger.info(f"Enumeration started | hosts={len(live_hosts)}")

        from src.tools.registry import tool_registry
        executor = _get_executor(state)

        # ── Collect URLs from previous stages ──
        # Pull crawled URLs from active_recon
        active_sr = state.stage_results.get("active_recon")
        if active_sr and active_sr.data:
            crawled = active_sr.data.get("crawled_urls", [])
            for url in crawled:
                if url not in collected["endpoints"]:
                    collected["endpoints"].append(url)
            logger.info(f"Carried over {len(crawled)} crawled URLs from active recon")

        # Pull passive URLs from passive_recon
        passive_sr = state.stage_results.get("passive_recon")
        if passive_sr and passive_sr.data:
            passive_urls = passive_sr.data.get("urls", [])
            for url in passive_urls[:200]:  # Limit to 200 passive URLs
                if url not in collected["endpoints"]:
                    collected["endpoints"].append(url)
            if passive_urls:
                logger.info(f"Carried over {min(len(passive_urls), 200)} passive URLs")

        # Seed state.endpoints early so even if this stage times out,
        # downstream stages have data from previous stages
        if collected["endpoints"]:
            state.endpoints = list(collected["endpoints"])
            logger.info(f"Seeded state.endpoints with {len(state.endpoints)} carried-over URLs")

        # ── Incremental Mode: filter to only new/changed assets (V8-T1-2) ──
        _is_incremental = (state.metadata or {}).get("incremental", False)
        if _is_incremental:
            try:
                from src.workflow.pipelines.incremental import compute_incremental_targets
                from src.integrations.asset_db import AssetDB
                _inc_db = AssetDB()
                _program_id = state.target or "unknown"
                _inc_result = compute_incremental_targets(
                    db=_inc_db,
                    program_id=_program_id,
                    current_subdomains=list(state.subdomains or []),
                    current_endpoints=list(state.endpoints or []),
                )
                _new_subs = _inc_result.get("new_subdomains", [])
                _new_eps = _inc_result.get("new_endpoints", [])
                if _new_subs or _new_eps:
                    logger.info(
                        f"[incremental] Filtering to {len(_new_subs)} new subdomains, "
                        f"{len(_new_eps)} new endpoints"
                    )
                    if _new_subs:
                        state.subdomains = _new_subs
                        state.live_hosts = [h for h in (state.live_hosts or []) if h in set(_new_subs)]
                        live_hosts = state.live_hosts or [state.target]
                    if _new_eps:
                        state.endpoints = _new_eps
                        collected["endpoints"] = list(_new_eps)
                else:
                    logger.info("[incremental] No new assets found — scan will proceed with all assets")
            except Exception as _inc_exc:
                logger.warning(f"[incremental] Filtering failed, scanning all: {_inc_exc}")

        # ── Directory Brute Force (ffuf, gobuster) — parallel per host ──
        for tool_name in ["ffuf", "gobuster"]:
            tool = tool_registry.get(tool_name)
            if tool and tool.is_available():
                fuzz_semaphore = asyncio.Semaphore(3)  # Max 3 concurrent fuzzing

                async def _fuzz_host(host: str) -> list[str]:
                    async with fuzz_semaphore:
                        try:
                            opts = _get_scan_options(state.profile, "fuzzing")
                            target_url = f"https://{host}" if not host.startswith("http") else host
                            tool_result = await executor.execute(tool, target_url, opts)
                            eps: list[str] = []
                            if tool_result and tool_result.findings:
                                for f in tool_result.findings:
                                    ep = getattr(f, "endpoint", "") or getattr(f, "target", "")
                                    if ep:
                                        eps.append(ep)
                                logger.info(f"{tool_name}@{host}: {len(tool_result.findings)} endpoints")
                            return eps
                        except Exception as e:
                            logger.warning(f"Enumeration {tool_name}@{host} failed: {e}")
                            return []

                # Dynamic dir fuzzing target scaling
                _fuzz_count = max(8, len(live_hosts) // 3)
                if _scan_profile == "aggressive":
                    _fuzz_count = max(12, len(live_hosts) // 2)
                elif _scan_profile == "stealth":
                    _fuzz_count = max(4, len(live_hosts) // 4)
                fuzz_results = await asyncio.gather(
                    *[_fuzz_host(h) for h in live_hosts[:_fuzz_count]],
                    return_exceptions=True,
                )
                for res in fuzz_results:
                    if isinstance(res, Exception):
                        continue
                    for ep in res:
                        if ep not in collected["endpoints"]:
                            collected["endpoints"].append(ep)
                break  # Bir araç yeterli

        # ── Parameter Discovery (arjun) — DISABLED: crashes on Python 3.13+ and
        # times out (300s) for most hosts, wasting ~10 min with zero results.
        # TODO: revisit when arjun fixes Python 3.13 compatibility.
        # arjun_tool = tool_registry.get("arjun")

        # ── VHost Fuzzer (V9-T1-5) — Discover hidden virtual hosts ──
        try:
            from src.tools.recon.web_discovery.vhost_fuzzer import VHostFuzzer
            _vhost = VHostFuzzer()
            if _vhost.is_available():
                _vhost_result = await asyncio.wait_for(
                    _vhost.run(state.target, {"domain": state.target}),
                    timeout=1200.0,
                )
                if _vhost_result and _vhost_result.findings:
                    for f in _vhost_result.findings:
                        ep = getattr(f, "endpoint", "") or getattr(f, "target", "")
                        if ep and ep not in collected["endpoints"]:
                            collected["endpoints"].append(ep)
                    logger.info(f"VHost fuzzer: {len(_vhost_result.findings)} hidden hosts")
        except asyncio.TimeoutError:
            logger.warning("VHost fuzzer timed out")
        except ImportError:
            logger.debug("VHost fuzzer module not available")
        except Exception as _vhost_exc:
            logger.warning(f"VHost fuzzer error: {_vhost_exc}")

        # ── CSP Subdomain Discovery — Extract domains from Content-Security-Policy ──
        try:
            from src.tools.recon.web_discovery.csp_discovery import CSPSubdomainDiscovery
            _csp_disc = CSPSubdomainDiscovery()
            if _csp_disc.is_available():
                _csp_hosts = state.metadata.get("live_hosts", [state.target])[:5]
                for _csp_host in _csp_hosts:
                    _csp_result = await asyncio.wait_for(
                        _csp_disc.run(_csp_host),
                        timeout=60.0,
                    )
                    if _csp_result and _csp_result.findings:
                        for f in _csp_result.findings:
                            _sd = getattr(f, "endpoint", "") or getattr(f, "target", "")
                            if _sd and _sd not in collected.get("subdomains", []):
                                collected.setdefault("subdomains", []).append(_sd)
                        logger.info(f"CSP discovery ({_csp_host}): {len(_csp_result.findings)} domains")
        except asyncio.TimeoutError:
            logger.warning("CSP subdomain discovery timed out")
        except ImportError:
            logger.debug("CSP discovery module not available")
        except Exception as _csp_exc:
            logger.warning(f"CSP discovery error: {_csp_exc}")

        # ── Cloud Storage Enumerator (V9-T1-6) — S3/Azure/GCS bucket discovery ──
        try:
            from src.tools.recon.osint.cloud_enum import CloudStorageEnumerator
            _cloud_enum = CloudStorageEnumerator()
            if _cloud_enum.is_available():
                _cloud_result = await asyncio.wait_for(
                    _cloud_enum.run(state.target, {}),
                    timeout=1200.0,
                )
                if _cloud_result and _cloud_result.findings:
                    collected["cloud_buckets"] = [
                        _finding_to_dict(f, "cloud_enum")
                        for f in _cloud_result.findings
                    ]
                    logger.info(f"Cloud enum: {len(_cloud_result.findings)} exposed buckets")
        except asyncio.TimeoutError:
            logger.warning("Cloud enum timed out")
        except ImportError:
            logger.debug("Cloud enum module not available")
        except Exception as _cloud_exc:
            logger.warning(f"Cloud enum error: {_cloud_exc}")

        # ── Metadata Extractor (V9-T1-7) — Document metadata for info leaks ──
        try:
            from src.tools.recon.osint.metadata_extractor import MetadataExtractor
            _meta_ext = MetadataExtractor()
            if _meta_ext.is_available():
                _meta_result = await asyncio.wait_for(
                    _meta_ext.run(state.target, {}),
                    timeout=1200.0,
                )
                if _meta_result and _meta_result.findings:
                    collected["metadata_findings"] = [
                        _finding_to_dict(f, "metadata_extractor")
                        for f in _meta_result.findings
                    ]
                    logger.info(f"Metadata extractor: {len(_meta_result.findings)} leaks")
        except asyncio.TimeoutError:
            logger.warning("Metadata extractor timed out")
        except ImportError:
            logger.debug("Metadata extractor module not available")
        except Exception as _meta_exc:
            logger.warning(f"Metadata extractor error: {_meta_exc}")

        # ── Dynamic Wordlist Generator (V9-T1-8) — Enhance fuzzing with target-specific words ──
        try:
            from src.tools.fuzzing.dynamic_wordlist import DynamicWordlistGenerator
            _dwg = DynamicWordlistGenerator()
            _tech_list = []
            for _tv in (state.technologies or {}).values():
                if isinstance(_tv, list):
                    _tech_list.extend([str(t).lower() for t in _tv])
                elif isinstance(_tv, str):
                    _tech_list.append(_tv.lower())
            _dynamic_words = _dwg.generate(
                target=state.target,
                subdomains=list(state.subdomains or [])[:50],
                endpoints=collected["endpoints"][:200],
                technologies=_tech_list[:20],
            )
            if _dynamic_words:
                # Save to temp wordlist for downstream fuzzing usage
                from pathlib import Path as _DWPath
                _dw_dir = _DWPath(f"output/scans/{state.session_id}")
                _dw_dir.mkdir(parents=True, exist_ok=True)
                _dw_path = str(_dw_dir / "dynamic_wordlist.txt")
                _saved = _dwg.save(_dynamic_words, _dw_path)
                collected["dynamic_wordlist_path"] = _dw_path
                # M4 fix: persist to state.metadata for downstream use
                state.metadata = state.metadata or {}
                state.metadata["dynamic_wordlist_path"] = _dw_path
                logger.info(f"Dynamic wordlist: {_saved} target-specific words generated")
        except ImportError:
            logger.debug("Dynamic wordlist generator module not available")
        except Exception as _dwg_exc:
            logger.warning(f"Dynamic wordlist generation error: {_dwg_exc}")

        # -- Subdomain Takeover Check --
        try:
            from src.tools.scanners.custom_checks.subdomain_takeover import check_subdomain_takeover
            all_subs = list(state.subdomains or [])
            if all_subs:
                takeover_findings = await check_subdomain_takeover(all_subs, max_concurrent=5, timeout=60)
                for f in takeover_findings:
                    collected["endpoints"].append(f.endpoint or f.target)
                if takeover_findings:
                    # Store takeover findings for vuln scan stage
                    collected["takeover_findings"] = [
                        _finding_to_dict(f, "subdomain_takeover_checker")
                        for f in takeover_findings
                    ]
                    logger.info(f"Subdomain takeover check: {len(takeover_findings)} potential findings from {len(all_subs)} subdomains")
        except ImportError:
            logger.debug("Subdomain takeover checker module not available")
        except Exception as e:
            logger.warning(f"Subdomain takeover check error: {e}")

        # ── GraphQL Endpoint Discovery & Introspection ──
        # Scan live hosts and previously discovered /graphql endpoints
        try:
            gql_tool = tool_registry.get("graphql_introspection")
            if gql_tool and gql_tool.is_available():
                # Collect candidate targets: live hosts + any endpoint with 'graphql' in path
                gql_candidates: list[str] = []
                for ep in collected["endpoints"]:
                    if "graphql" in ep.lower() or "gql" in ep.lower():
                        gql_candidates.append(ep)
                # Also probe top live hosts for graphql endpoints
                for host in live_hosts[:max(8, len(live_hosts) // 3)]:
                    base = f"https://{host}" if not host.startswith("http") else host
                    if base not in gql_candidates:
                        gql_candidates.append(base)

                gql_sem = asyncio.Semaphore(3)

                async def _gql_probe(target_url: str) -> list[str]:
                    async with gql_sem:
                        try:
                            gql_result = await asyncio.wait_for(
                                executor.execute(gql_tool, target_url, {"timeout": 20}),
                                timeout=1200.0,
                            )
                            eps: list[str] = []
                            if gql_result and gql_result.findings:
                                for f in gql_result.findings:
                                    ep = getattr(f, "endpoint", "") or ""
                                    if ep and ep not in collected["endpoints"]:
                                        eps.append(ep)
                                logger.info(
                                    f"GraphQL@{target_url}: {len(gql_result.findings)} findings"
                                )
                                # Store GraphQL findings for vuln scan
                                if "graphql_findings" not in collected:
                                    collected["graphql_findings"] = []
                                collected["graphql_findings"].extend(
                                    [_finding_to_dict(f, "graphql_introspection")
                                     for f in gql_result.findings]
                                )
                            return eps
                        except (asyncio.TimeoutError, Exception) as e:
                            logger.debug(f"GraphQL probe@{target_url}: {e}")
                            return []

                gql_results = await asyncio.gather(
                    *[_gql_probe(c) for c in gql_candidates[:8]],
                    return_exceptions=True,
                )
                gql_eps_found = 0
                for res in gql_results:
                    if isinstance(res, list):
                        for ep in res:
                            if ep not in collected["endpoints"]:
                                collected["endpoints"].append(ep)
                                gql_eps_found += 1
                if gql_eps_found:
                    logger.info(f"GraphQL discovery: {gql_eps_found} new endpoints")
            else:
                logger.debug("GraphQL introspection tool not available")
        except Exception as e:
            logger.warning(f"GraphQL discovery error: {e}")

        state.endpoints = collected["endpoints"]

        # AssetDB: endpoint'leri kaydet
        _adb.save_endpoints(state)

        # ── v5.0-P0.3: SPA Baseline Capture ──
        # Fetch homepage + a random nonexistent path for each live host and
        # register as baseline with ResponseValidator.  This enables SPA
        # catch-all detection during vulnerability scanning.
        try:
            import httpx as _bl_httpx
            import secrets as _bl_secrets
            from src.utils.response_validator import ResponseValidator as _BaselineRV

            _baseline_rv = _BaselineRV()
            _bl_hosts = list(live_hosts[:10]) if live_hosts else [state.target]
            _bl_timeout = _bl_httpx.Timeout(15.0, connect=10.0)
            _bl_captured = 0

            async with _bl_httpx.AsyncClient(
                timeout=_bl_timeout, verify=False, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"},
            ) as _bl_client:
                for _bl_host in _bl_hosts:
                    try:
                        _bl_base = f"https://{_bl_host}" if not _bl_host.startswith("http") else _bl_host
                        # Fetch a random nonexistent path — SPA apps return the
                        # same HTML shell for all routes.
                        _bl_rand = _bl_secrets.token_hex(8)
                        _bl_resp = await _bl_client.get(f"{_bl_base}/whai-baseline-{_bl_rand}")
                        if _bl_resp.status_code == 200 and len(_bl_resp.text) > 50:
                            _baseline_rv.set_baseline(_bl_host, _bl_resp.text)
                            _bl_captured += 1
                            # Store baseline body for pre-flight SPA detection later
                            if "_spa_baselines" not in state.metadata:
                                state.metadata["_spa_baselines"] = {}
                            state.metadata["_spa_baselines"][_bl_host] = _bl_resp.text[:4096]
                    except Exception:
                        pass  # Non-critical — best-effort baseline

            if _bl_captured:
                logger.info(f"SPA baseline captured for {_bl_captured}/{len(_bl_hosts)} hosts")
                state.metadata["spa_baseline_captured"] = _bl_captured
        except Exception as _bl_exc:
            logger.debug(f"SPA baseline capture skipped: {_bl_exc}")

        # ── V23: Post-Enumeration Targeted Fuzzing with Dynamic Wordlist ──
        # The dynamic wordlist is target-specific (from crawled words, subdomain
        # patterns, tech-specific paths). Run a focused ffuf pass if available.
        _dw_path_for_fuzz = (state.metadata or {}).get("dynamic_wordlist_path")
        if _dw_path_for_fuzz:
            try:
                import os as _dw_os
                if _dw_os.path.isfile(_dw_path_for_fuzz) and _dw_os.path.getsize(_dw_path_for_fuzz) > 50:
                    _ffuf_tool = tool_registry.get("ffuf")
                    if _ffuf_tool and _ffuf_tool.is_available():
                        _dw_fuzz_targets = list(live_hosts[:3]) if live_hosts else targets[:3]
                        _dw_sem = asyncio.Semaphore(2)

                        async def _dw_fuzz(host: str) -> list[str]:
                            async with _dw_sem:
                                try:
                                    _fuzz_url = f"https://{host}" if not host.startswith("http") else host
                                    _fuzz_opts = _get_scan_options(state.profile, "fuzzing")
                                    _fuzz_opts["wordlist"] = _dw_path_for_fuzz
                                    _fuzz_opts["timeout"] = min(_fuzz_opts.get("timeout", 180), 180)
                                    _fuzz_result = await asyncio.wait_for(
                                        executor.execute(_ffuf_tool, _fuzz_url, _fuzz_opts),
                                        timeout=1200.0,
                                    )
                                    eps: list[str] = []
                                    if _fuzz_result and _fuzz_result.findings:
                                        for f in _fuzz_result.findings:
                                            ep = getattr(f, "endpoint", "") or getattr(f, "target", "")
                                            if ep and ep not in collected["endpoints"]:
                                                eps.append(ep)
                                                collected["endpoints"].append(ep)
                                    return eps
                                except Exception as _fuzz_err:
                                    logger.warning(f"Dynamic wordlist ffuf {host} failed: {_fuzz_err}")
                                return []

                        _dw_results = await asyncio.gather(
                            *[_dw_fuzz(h) for h in _dw_fuzz_targets],
                            return_exceptions=True,
                        )
                        _dw_new_eps = sum(
                            len(r) for r in _dw_results if isinstance(r, list)
                        )
                        if _dw_new_eps:
                            logger.info(
                                f"Dynamic wordlist fuzzing: discovered {_dw_new_eps} "
                                f"new endpoints from target-specific wordlist"
                            )
            except Exception as _dw_fuzz_exc:
                logger.warning(f"Dynamic wordlist fuzzing error: {_dw_fuzz_exc}")

        result.data = collected
        result.findings_count = len(collected["endpoints"]) + len(collected["parameters"])
        result.success = True

        logger.info(
            f"Enumeration complete | endpoints={len(collected['endpoints'])} | "
            f"params={len(collected['parameters'])}"
        )

    except Exception as e:
        logger.error(f"Enumeration failed: {e}")
        result.success = False
        result.errors.append(str(e))
    finally:
        # ── Preserve endpoints on CancelledError (stage timeout) ──
        # CancelledError is a BaseException that skips `except Exception`.
        try:
            if collected.get("endpoints"):
                state.endpoints = collected["endpoints"]
                logger.debug(
                    f"Enumeration finally: preserved {len(collected['endpoints'])} endpoints"
                )
        except Exception as exc:
            logger.debug(f"Enumeration finally block error: {exc}")

    return result


async def handle_attack_surface_map(state: WorkflowState) -> StageResult:
    """
    Aşama 5: Saldırı Yüzeyi Haritalama (LLM-Powered)

    Brain 32B ile tüm keşif verileri analiz edilip
    stratejik saldırı planı oluşturulur.
    """
    result = StageResult(stage=WorkflowStage.ATTACK_SURFACE_MAP)

    try:
        logger.info("Attack surface mapping started")

        attack_surface: dict[str, Any] = {
            "total_hosts": len(state.live_hosts),
            "total_endpoints": len(state.endpoints),
            "total_subdomains": len(state.subdomains),
            "port_map": state.open_ports,
            "attack_vectors": [],
            "priority_targets": [],
            "intelligence_plan": None,
            "waf_detection": None,
            "historical_learning": None,
        }

        # ── WAF Fingerprinting (V6-T2-1) ──
        try:
            primary_host = state.target
            waf_result = await detect_waf(primary_host, use_wafw00f=True)
            if waf_result.detected:
                attack_surface["waf_detection"] = {
                    "waf_name": waf_result.waf_name,
                    "confidence": waf_result.confidence,
                    "evidence": waf_result.evidence,
                    "strategy_notes": waf_result.strategy.notes if waf_result.strategy else "",
                    "payload_transforms": waf_result.strategy.payload_transforms if waf_result.strategy else [],
                }
                logger.info(
                    "WAF detected: {} (confidence={:.0%}) — strategy: {}",
                    waf_result.waf_name, waf_result.confidence,
                    waf_result.strategy.notes if waf_result.strategy else "none",
                )
            else:
                logger.info("No WAF detected for {}", primary_host)
            state.metadata = state.metadata or {}
            state.metadata["waf_result"] = waf_result
        except Exception as exc:
            logger.warning("WAF fingerprinting failed: {}", exc)

        # Hedefleri önceliklendir (static analysis)
        for host in state.live_hosts:
            ports = state.open_ports.get(host, [])
            priority = _calculate_host_priority(host, ports, state.technologies.get(host, ""))
            attack_surface["priority_targets"].append({
                "host": host,
                "priority": priority,
                "ports": ports,
                "tech": state.technologies.get(host, ""),
            })

        # Static saldırı vektörleri
        attack_surface["attack_vectors"] = _identify_attack_vectors(state)

        # ── LLM-Powered Strategic Analysis ──
        intel = state.intelligence_engine
        if intel and intel.is_available:
            logger.info("🧠 Running LLM-powered attack planning...")
            _asm_budget = 480  # 8 min total budget for all LLM calls
            _asm_start = time.time()

            def _asm_remaining() -> float:
                return max(0.0, _asm_budget - (time.time() - _asm_start))

            try:
                # Gather recon data for the LLM
                passive_sr = state.stage_results.get("passive_recon")
                dns_records = []
                osint_data = {}
                if passive_sr and passive_sr.data:
                    dns_records = passive_sr.data.get("dns_records", [])
                    # Collect OSINT data
                    for key, val in passive_sr.data.items():
                        if key.startswith("osint_"):
                            osint_data[key] = val

                # Build technology dict for LLM
                tech_dict: dict[str, list[str]] = {}
                for host, tech in state.technologies.items():
                    if isinstance(tech, str):
                        tech_dict[host] = [t.strip() for t in tech.replace(";", ",").split(",") if t.strip()]
                    elif isinstance(tech, list):
                        tech_dict[host] = tech

                try:
                    from src.brain.memory.knowledge_base import KnowledgeBase

                    kb = KnowledgeBase()
                    kb.initialize()
                    historical_learning = kb.get_learning_snapshot(tech_dict)
                    if historical_learning.get("matched_chains") or historical_learning.get("recommended_tools"):
                        attack_surface["historical_learning"] = historical_learning
                        state.metadata = state.metadata or {}
                        state.metadata["historical_learning"] = historical_learning
                        logger.info(
                            "Loaded historical learning | matched_chains={} | recommended_tools={}",
                            historical_learning.get("matched_chains", 0),
                            ", ".join(historical_learning.get("recommended_tools", [])[:6]) or "none",
                        )
                except Exception as exc:
                    logger.warning(f"Historical learning lookup failed: {exc}")

                plan = await asyncio.wait_for(
                    intel.analyze_recon_and_plan(
                        target=state.target,
                        subdomains=state.subdomains,
                        live_hosts=state.live_hosts,
                        technologies=tech_dict,
                        open_ports=state.open_ports,
                        dns_records=[{"record": r} if isinstance(r, str) else r for r in dns_records],
                        urls=state.endpoints[:200],
                        osint_data=osint_data,
                    ),
                    timeout=min(1200, _asm_remaining()),
                )
                logger.info("🧠 analyze_recon_and_plan completed in {:.0f}s (budget remaining: {:.0f}s)",
                            time.time() - _asm_start, _asm_remaining())

                if plan.attack_vectors:
                    intel_plan_data = {
                        "summary": plan.summary,
                        "vectors": [v.model_dump() for v in plan.attack_vectors],
                        "custom_templates_needed": plan.custom_templates_needed,
                        "high_value_endpoints": plan.high_value_endpoints,
                        "technologies_of_interest": plan.technologies_of_interest,
                        "waf_bypass_strategies": plan.waf_bypass_strategies,
                    }
                    attack_surface["intelligence_plan"] = intel_plan_data

                    # Persist to state.metadata so vuln_scan can recover
                    # brain vectors even if this stage times out
                    state.metadata = state.metadata or {}
                    state.metadata["intelligence_plan"] = intel_plan_data

                    logger.info(
                        f"🧠 Intelligence plan ready | "
                        f"vectors={len(plan.attack_vectors)} | "
                        f"custom_templates={len(plan.custom_templates_needed)} | "
                        f"high_value_eps={len(plan.high_value_endpoints)}"
                    )

                    # Log top attack vectors
                    for i, v in enumerate(plan.attack_vectors[:5]):
                        logger.info(
                            f"  🎯 Vector #{i+1}: [{v.priority}] {v.vuln_type} at "
                            f"{v.endpoint} — {v.reasoning[:80]}"
                        )

                    # Add high-value endpoints to state.endpoints if not already present
                    # D1: Scope-validate brain-generated endpoints to prevent LLM hallucination
                    _scope_validator = None
                    if state.scope_config:
                        try:
                            from src.utils.scope_validator import ScopeValidator as _SV
                            _scope_validator = _SV.from_dict(state.scope_config)
                        except Exception as exc:
                            logger.warning(f"ScopeValidator init failed: {exc}")

                    for ep in plan.high_value_endpoints:
                        if ep not in state.endpoints:
                            # P6-1: Auto-prefix target hostname on bare paths
                            if ep.startswith("/"):
                                from urllib.parse import urlparse as _up_fix
                                _parsed_target = _up_fix(state.target)
                                _scheme = _parsed_target.scheme or "https"
                                _host_part = _parsed_target.netloc or _parsed_target.path.split("/")[0] or state.target
                                ep = f"{_scheme}://{_host_part}{ep}"

                            # Scope check — brain may hallucinate out-of-scope URLs
                            if _scope_validator:
                                try:
                                    from urllib.parse import urlparse as _up
                                    _host = _up(ep).hostname or ""
                                    if _host and not _scope_validator.is_in_scope(_host):
                                        logger.debug(f"Brain endpoint out of scope, skipping: {ep}")
                                        continue
                                except Exception as _exc:
                                    pass  # Keep if can't parse
                            state.endpoints.append(ep)

                    # ── Generate Custom Nuclei Templates (budget-limited) ──
                    if plan.custom_templates_needed and _asm_remaining() > 60:
                        _max_templates = 2  # Cap at 2 to save time
                        logger.info(f"🧠 Generating up to {_max_templates} custom nuclei templates (budget: {_asm_remaining():.0f}s)...")
                        templates_dir = "data/nuclei_templates/custom"
                        import os
                        os.makedirs(templates_dir, exist_ok=True)

                        for tmpl_req in plan.custom_templates_needed[:_max_templates]:
                            if _asm_remaining() < 30:
                                logger.info("🧠 Template generation stopped — time budget low ({:.0f}s)", _asm_remaining())
                                break
                            try:
                                tmpl = await asyncio.wait_for(
                                    intel.generate_nuclei_template(
                                        tech=tmpl_req.get("tech", "unknown"),
                                        version=tmpl_req.get("version", ""),
                                        check_description=tmpl_req.get("check_description", ""),
                                        known_cve=tmpl_req.get("cve", ""),
                                    ),
                                    timeout=min(1200, _asm_remaining()),
                                )
                                if tmpl and tmpl.yaml_content:
                                    tmpl_path = os.path.join(
                                        templates_dir,
                                        f"{tmpl.template_id}.yaml"
                                    )
                                    with open(tmpl_path, "w") as f:
                                        f.write(tmpl.yaml_content)
                                    # Validate with nuclei -validate
                                    import shutil
                                    if shutil.which("nuclei"):
                                        proc = await asyncio.create_subprocess_exec(
                                            "nuclei", "-validate", "-t", tmpl_path,
                                            stdout=asyncio.subprocess.PIPE,
                                            stderr=asyncio.subprocess.PIPE,
                                        )
                                        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
                                        if proc.returncode != 0:
                                            logger.warning(
                                                f"  ❌ Invalid nuclei template {tmpl_path} — removing "
                                                f"(nuclei: {stderr.decode(errors='replace')[:200]})"
                                            )
                                            os.remove(tmpl_path)
                                            continue
                                    logger.info(f"  📝 Custom template saved & validated: {tmpl_path}")
                            except Exception as e:
                                logger.warning(f"Template generation failed: {e}")
                else:
                    logger.info("🧠 LLM analysis returned no specific attack vectors")

                # ── V6-T0-2: Creative Attack Narratives (Pre-Hoc Strategist) ──
                if _asm_remaining() > 30:
                    try:
                        narratives = await asyncio.wait_for(
                            intel.generate_creative_attack_narratives(
                                target=state.target,
                                technologies=tech_dict,
                                endpoints=state.endpoints[:100],
                            ),
                            timeout=min(1200, _asm_remaining()),
                        )
                        if narratives:
                            attack_surface["creative_narratives"] = narratives
                            _narr_targets = list(state.live_hosts or []) or [state.target]
                            # Convert high-severity narratives into additional attack vectors
                            for n in narratives:
                                sev = (n.get("severity_estimate") or "medium").lower()
                                if sev in ("critical", "high") and n.get("target_endpoint"):
                                    _raw_ep = n["target_endpoint"]
                                    _resolved_ep = _resolve_brain_endpoint(
                                        _raw_ep, _narr_targets, state.target
                                    ) or _raw_ep
                                    attack_surface["priority_targets"].append({
                                        "target": _resolved_ep,
                                        "priority": 9 if sev == "critical" else 7,
                                        "source": "creative_strategist",
                                        "vuln_class": n.get("vuln_class", "unknown"),
                                        "narrative": n.get("narrative", "")[:200],
                                    })
                    except Exception as e:
                        logger.warning(f"Creative attack narratives failed (non-critical): {e}")
                else:
                    logger.debug("🧠 Skipping creative narratives — budget exhausted ({:.0f}s)", _asm_remaining())

                # ── V6-T0-4: Dynamic Test Case Generation (budget-limited) ──
                if _asm_remaining() > 30:
                    try:
                        for checker_type in ("idor", "business_logic", "race_condition"):
                            if _asm_remaining() < 20:
                                logger.info("🧠 Dynamic test generation stopped — budget low ({:.0f}s)", _asm_remaining())
                                break
                            cases = await asyncio.wait_for(
                                intel.generate_dynamic_test_cases(
                                    target=state.target,
                                    endpoints=state.endpoints[:100],
                                    technologies=tech_dict,
                                    checker_type=checker_type,
                                ),
                                timeout=min(1200, _asm_remaining()),
                            )
                            if cases:
                                key = f"dynamic_{checker_type}_test_cases"
                                attack_surface[key] = cases
                                logger.info(f"🧠 {len(cases)} dynamic {checker_type} test cases generated")
                            else:
                                logger.warning(f"🧠 Dynamic {checker_type} test cases: LLM returned empty/unparseable")
                    except Exception as e:
                        logger.warning(f"Dynamic test case generation failed: {e}")
                else:
                    logger.warning("🧠 Skipping dynamic test cases — budget exhausted ({:.0f}s remaining)", _asm_remaining())

                logger.info("🧠 Attack surface LLM analysis completed in {:.0f}s", time.time() - _asm_start)

            except Exception as e:
                logger.warning(f"LLM attack planning failed (non-critical): {e}")
        else:
            logger.info("No brain available — using static attack surface analysis only")

        # Önceliğe göre sırala
        attack_surface["priority_targets"].sort(
            key=lambda x: x["priority"], reverse=True
        )

        result.data = attack_surface
        result.success = True

        logger.info(
            f"Attack surface mapped | targets={len(attack_surface['priority_targets'])} | "
            f"vectors={len(attack_surface['attack_vectors'])}"
        )

    except Exception as e:
        logger.error(f"Attack surface mapping failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


def _generate_synthetic_vectors(
    targets: list[str],
    endpoints: list[str],
    state: Any,
) -> list[dict[str, str]]:
    """Generate synthetic probe vectors from discovered endpoints when
    the brain attack surface mapping returns no vectors.

    Scans endpoints for high-value patterns (GraphQL, API, admin, auth,
    actuator, config, upload, etc.) and produces vector dicts compatible
    with the deep probe pipeline.
    """
    import re as _re
    from urllib.parse import urlparse

    # Pattern → (vuln_type, parameter_hint, priority)
    HIGH_VALUE_PATTERNS: list[tuple[str, str, str, str]] = [
        # pattern (regex), vuln_type, param hint, priority
        (r"/graphql", "graphql_injection", "query", "high"),
        (r"/api/v\d", "api_abuse", "", "high"),
        (r"/api/", "idor", "id", "high"),
        (r"/admin", "auth_bypass", "", "critical"),
        (r"/login|/signin|/auth", "auth_bypass", "username", "high"),
        (r"/register|/signup", "mass_assignment", "", "medium"),
        (r"/upload|/file|/import", "file_upload", "file", "high"),
        (r"/search|/query|\?q=", "xss", "q", "high"),
        (r"/redirect|/goto|/url=|/next=|/return", "open_redirect", "url", "medium"),
        (r"/callback|/webhook|/notify", "ssrf", "url", "high"),
        (r"/actuator|/env|/health|/info|/metrics", "info_disclosure", "", "critical"),
        (r"/config|/settings|\.env|\.yaml|\.json", "info_disclosure", "", "high"),
        (r"/swagger|/openapi|/api-docs", "info_disclosure", "", "medium"),
        (r"/reset|/password|/forgot", "auth_bypass", "email", "high"),
        (r"/token|/oauth|/authorize", "oauth_misconfiguration", "", "high"),
        (r"/debug|/trace|/phpinfo|/server-status", "info_disclosure", "", "critical"),
        (r"/ws|/websocket|/socket\.io", "websocket_hijacking", "", "medium"),
        (r"/export|/download|/backup", "path_traversal", "file", "high"),
        (r"\?.*id=|\?.*user=|\?.*account=", "idor", "id", "high"),
        (r"\?.*url=|\?.*path=|\?.*file=|\?.*src=", "ssrf", "url", "high"),
        (r"\?.*redirect|return|next|continue", "open_redirect", "redirect", "medium"),
        (r"\?.*template|page|view|lang", "ssti", "template", "high"),
        (r"\?.*cmd|exec|command|run", "command_injection", "cmd", "critical"),
    ]

    vectors: list[dict[str, str]] = []
    seen_keys: set[str] = set()  # dedup

    # Combine all URL sources
    all_urls = list(endpoints or [])
    # Also check state endpoints if available
    if hasattr(state, "endpoints") and state.endpoints:
        for ep in state.endpoints:
            if isinstance(ep, str) and ep not in all_urls:
                all_urls.append(ep)

    for url in all_urls:
        url_lower = url.lower()
        for pattern, vuln_type, param_hint, priority in HIGH_VALUE_PATTERNS:
            if _re.search(pattern, url_lower):
                # Dedup key: endpoint base + vuln_type
                try:
                    parsed = urlparse(url)
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                except Exception as _exc:
                    base = url
                dedup_key = f"{base}:{vuln_type}"
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                vectors.append({
                    "endpoint": url,
                    "vuln_type": vuln_type,
                    "parameter": param_hint,
                    "priority": priority,
                })

    # If still nothing, create generic vectors from targets
    if not vectors and targets:
        for target in targets[:3]:
            scheme = "https" if not target.startswith("http") else ""
            base_url = f"{scheme}://{target}" if scheme else target
            vectors.extend([
                {
                    "endpoint": base_url,
                    "vuln_type": "xss",
                    "parameter": "",
                    "priority": "medium",
                },
                {
                    "endpoint": base_url,
                    "vuln_type": "info_disclosure",
                    "parameter": "",
                    "priority": "medium",
                },
            ])

    # Sort by priority (critical > high > medium > low)
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vectors.sort(key=lambda v: priority_order.get(v.get("priority", "low"), 3))

    return vectors


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert a value to float, returning default on failure.

    Brain/LLM-generated findings may produce non-numeric strings
    (e.g. 'high', '', None) for confidence/score fields.
    """
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _coerce_to_str(val: Any) -> str:
    """Coerce a value to string, handling list/None/non-string types."""
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0] if val else ""
        # Recurse once for nested lists
        if isinstance(val, list):
            val = val[0] if val else ""
    return str(val) if not isinstance(val, str) else val


def _get_waf_result(state: Any) -> WAFResult | None:
    """Safely retrieve WAFResult from state metadata.

    After checkpoint resume, waf_result is a dict (from to_dict()),
    not a WAFResult object. This helper handles both forms.
    """
    val = (state.metadata or {}).get("waf_result")
    if val is None:
        return None
    if isinstance(val, WAFResult):
        return val
    if isinstance(val, dict):
        try:
            return WAFResult.from_dict(val)
        except Exception:
            return None
    return None  # str or other unrecoverable form


def _finding_to_dict(
    f: Any,
    tool_name: str,
    *,
    fallback_url: str = "",
    vuln_type_override: str = "",
) -> dict[str, Any]:
    """Convert a Finding object to the standard dict used in raw_findings.

    Works with both direct attributes (Finding model) and arbitrary objects
    (uses getattr with defaults for safety).

    Args:
        f: Finding-like object with title, vulnerability_type, endpoint, etc.
        tool_name: Name of the tool that produced this finding.
        fallback_url: Default URL if finding has no endpoint/target.
        vuln_type_override: Override vulnerability_type if needed.
    """
    url = getattr(f, "endpoint", "") or getattr(f, "target", "") or fallback_url
    if isinstance(url, list):
        url = url[0] if url else ""
    if not isinstance(url, str):
        url = str(url)
    d: dict[str, Any] = {
        "title": getattr(f, "title", ""),
        "vulnerability_type": vuln_type_override or getattr(f, "vulnerability_type", ""),
        "url": url,
        "parameter": _coerce_to_str(getattr(f, "parameter", "")),
        "payload": _coerce_to_str(getattr(f, "payload", "")),
        "severity": str(getattr(f, "severity", "medium")),
        "tool": tool_name,
        "description": _coerce_to_str(getattr(f, "description", "")),
        "evidence": _coerce_to_str(getattr(f, "evidence", "")),
    }
    # Preserve rich fields used by FP engine and report generator
    for extra_key in (
        "http_request", "http_response", "cvss_score",
        "confidence", "confidence_score", "cve_id", "cwe_id",
        "references", "tags",
        # OOB / Interactsh metadata
        "interactsh_callback", "oob_domain", "oob_protocol",
        "blind_verification", "interaction_type",
    ):
        val = getattr(f, extra_key, None)
        if val is not None and val != "" and val != []:
            d[extra_key] = val
    # Map Finding.confidence → confidence_score for unified downstream access
    # Keep BOTH keys so consumers reading either "confidence" or "confidence_score" work.
    if "confidence_score" not in d and "confidence" in d:
        d["confidence_score"] = d["confidence"]
    elif "confidence_score" in d and "confidence" not in d:
        d["confidence"] = d["confidence_score"]
    # Propagate template_id from Finding.metadata for ExploitVerifier nuclei strategy
    _f_meta = getattr(f, "metadata", None)
    if isinstance(_f_meta, dict) and _f_meta.get("template_id"):
        d["template_id"] = _f_meta["template_id"]
    return d


def _resolve_brain_endpoint(ep: str, targets: list[str], default_target: str = "") -> str:
    """Resolve a brain vector endpoint (path like /api/v1/users) into a full URL.

    Brain vectors may contain:
    - Full URL: https://api.vimeo.com/api/v1/users → use as-is
    - Path only: /api/v1/users → prepend best matching target
    - Relative path: api/v1/users → prepend best matching target with /

    Returns empty string if cannot resolve.
    """
    if not ep:
        return ""
    # Already a full URL
    if ep.startswith("http://") or ep.startswith("https://"):
        return ep

    # Determine base host — prefer first target, fallback to default_target
    base_host = ""
    if targets:
        # Check if any target contains the ep path hint
        for t in targets:
            host = t if t.startswith("http") else f"https://{t}"
            if "api" in ep.lower() and "api" in host.lower():
                base_host = host.rstrip("/")
                break
        if not base_host:
            t = targets[0]
            base_host = (t if t.startswith("http") else f"https://{t}").rstrip("/")
    elif default_target:
        base_host = (default_target if default_target.startswith("http") else f"https://{default_target}").rstrip("/")

    if not base_host:
        return ""

    # Ensure path starts with /
    path = ep if ep.startswith("/") else f"/{ep}"
    return f"{base_host}{path}"


# ── Brain option sanitization tables ──────────────────────────────
# Keys the brain must NEVER inject (proxies, output paths, scope-breaking flags)
_BRAIN_DENY_KEYS: set[str] = {
    "tor", "proxy", "proxy_chain_file", "proxy-chain-file",
    "random_agent", "random-agent",
    "output_dir", "output", "output_file",
    "batch", "flush_session", "flush-session",
    "scope_constraints", "waf_evasion",  # hallucinated non-existent keys
    "cookiejar", "skip_plugins", "skip-plugins",
    "payload_encoding", "payload-encoding",
    "scope", "crawl", "crawl_depth", "crawl-depth",
}

# Per-tool whitelist of valid option keys the brain may set.
# Tools not in this dict accept any key that passes the deny filter.
_BRAIN_OPTION_WHITELIST: dict[str, set[str]] = {
    "sqlmap": {"timeout", "param", "data", "cookie", "headers", "level",
               "risk", "dbms", "tamper", "technique"},
    "commix": {"timeout", "data", "cookie", "parameter", "headers", "os"},
    "dalfox": {"timeout", "headers", "cookie", "data", "custom_payload",
               "blind", "mining_dict", "mining_dom"},
    "xsstrike": {"timeout", "headers", "cookie", "data", "params"},
    "tplmap": {"timeout", "data", "cookie", "headers"},
    "nosqlmap": {"timeout", "data", "cookie", "headers"},
}

# For these numeric keys, brain must not go BELOW the base value.
_BRAIN_PROTECTED_MIN_KEYS: set[str] = {"level", "risk"}


def _sanitize_brain_options(
    tool_name: str,
    suggested: dict[str, Any],
    base_opts: dict[str, Any],
) -> dict[str, Any]:
    """Strip hallucinated, dangerous, or invalid options from brain suggestions."""
    cleaned: dict[str, Any] = {}
    stripped: list[str] = []
    whitelist = _BRAIN_OPTION_WHITELIST.get(tool_name)

    for key, val in suggested.items():
        # 1. Deny-list check (normalise hyphens to underscores)
        norm_key = key.replace("-", "_")
        if key in _BRAIN_DENY_KEYS or norm_key in _BRAIN_DENY_KEYS:
            stripped.append(f"{key}(denied)")
            continue
        # 2. Per-tool whitelist check
        if whitelist and key not in whitelist and norm_key not in whitelist:
            stripped.append(f"{key}(unknown)")
            continue
        # 3. Protected-min: brain cannot lower below base
        if key in _BRAIN_PROTECTED_MIN_KEYS or norm_key in _BRAIN_PROTECTED_MIN_KEYS:
            base_val = base_opts.get(key, base_opts.get(norm_key))
            if base_val is not None:
                try:
                    if float(val) < float(base_val):
                        stripped.append(f"{key}({val}<base:{base_val})")
                        continue
                except (TypeError, ValueError):
                    stripped.append(f"{key}(bad-type)")
                    continue
        cleaned[key] = val

    if stripped:
        logger.info(f"🧹 Brain config sanitized for {tool_name}: stripped {stripped}")
    return cleaned


async def _brain_enhanced_options(
    state: WorkflowState,
    tool_name: str,
    target: str,
    base_opts: dict[str, Any],
) -> dict[str, Any]:
    """Ask the intelligence engine for optimal tool config, merge with base."""
    intel = state.intelligence_engine
    if not intel or not intel.is_available:
        return base_opts

    try:
        context: dict[str, Any] = {
            "technologies": state.technologies or {},
            "profile": str(state.profile) if state.profile else "balanced",
            "endpoints_count": len(state.endpoints or []),
            "live_hosts_count": len(state.live_hosts or []),
        }
        suggested = await asyncio.wait_for(
            intel.suggest_tool_config(tool_name, target, context),
            timeout=60.0,
        )
        if suggested and isinstance(suggested, dict):
            # ── Sanitize brain output before merging ──
            suggested = _sanitize_brain_options(tool_name, suggested, base_opts)
            if not suggested:
                return base_opts

            merged = {**base_opts, **suggested}

            # ── Safety floor: prevent brain from setting dangerously low timeouts ──
            _ABSOLUTE_MIN_TIMEOUT = 30
            _base_timeout = base_opts.get("timeout", 60)
            _proportional_min = max(_ABSOLUTE_MIN_TIMEOUT, int(_base_timeout * 0.5))
            if "timeout" in merged and isinstance(merged["timeout"], (int, float)):
                if merged["timeout"] < _proportional_min:
                    merged["timeout"] = _proportional_min

            logger.info(
                f"🧠 Brain-enhanced {tool_name} config: "
                f"+{len(suggested)} suggestions → {merged}"
            )
            return merged
    except asyncio.TimeoutError:
        logger.warning(f"suggest_tool_config timed out for {tool_name}")
    except Exception as exc:
        logger.warning(f"suggest_tool_config failed for {tool_name}: {exc}")

    return base_opts


async def handle_vulnerability_scan(state: WorkflowState) -> StageResult:
    """
    Aşama 6: Zafiyet Taraması

    Otomatik ve özel zafiyet testleri çalıştırır.
    """
    result = StageResult(stage=WorkflowStage.VULNERABILITY_SCAN)

    # ── Define all_findings and _sync_findings OUTSIDE try so they are
    #    always accessible in the finally block.  When asyncio.wait_for()
    #    cancels this coroutine on stage timeout, CancelledError (a
    #    BaseException) skips `except Exception`.  The finally block
    #    guarantees one last sync to state.raw_findings.
    from src.tools.registry import tool_registry
    executor = _get_executor(state)
    all_findings: list[dict[str, Any]] = []
    _failed_tools: list[str] = []  # Track failed tools for adaptive re-scan
    _all_tools_run: list[str] = []  # Track ALL tools executed (for report)

    # Resolve scan profile for profile-aware scaling decisions
    _scan_profile = getattr(state, "profile", None)
    if _scan_profile:
        _scan_profile = getattr(_scan_profile, "value", str(_scan_profile)).lower()
    else:
        _scan_profile = "balanced"

    # v5.0: Early brain availability check — skip brain-only phases to avoid timeout waits
    intel = state.intelligence_engine
    _brain_available = bool(intel and intel.is_available)
    if not _brain_available:
        logger.info("v5.0: Brain unavailable — skipping brain-only phases (HUNTER A/B, creative narratives, dynamic tests)")

    def _sync_findings() -> None:
        """Push current findings to state so they survive stage timeouts."""
        state.raw_findings = list(all_findings)
        logger.debug(f"_sync_findings: {len(all_findings)} findings synced to state")

    # ── Initialize cleanup variables OUTSIDE try block so finally can
    #    always access them, even if an exception occurs before the
    #    Interactsh init code is reached.
    _oob_domain: str | None = None
    _interactsh = None

    try:
        targets = state.live_hosts or [state.target]
        endpoints = state.endpoints or []

        # Use priority targets from attack surface mapping if available
        attack_sr = state.stage_results.get("attack_surface_mapping")
        brain_vectors: list[dict[str, Any]] = []
        attack_surface_data: dict[str, Any] = {}  # V6-T0-4: shared with checker closures
        if attack_sr and attack_sr.data:
            attack_surface_data = attack_sr.data
            priority = attack_surface_data.get("priority_targets", [])
            if priority:
                sorted_targets = [
                    t.get("host", "") for t in sorted(
                        priority, key=lambda x: x.get("priority", 0), reverse=True
                    )
                ]
                # Filter out empty host entries
                sorted_targets = [h for h in sorted_targets if h]
                if sorted_targets:
                    targets = sorted_targets
                    logger.info(
                        f"Using {len(targets)} priority-ranked targets "
                        f"from attack surface map"
                    )
            # Extract brain attack vectors for targeted scanning
            intel_plan = attack_surface_data.get("intelligence_plan", {})
            if intel_plan:
                brain_vectors = intel_plan.get("vectors", [])

        # Fallback: recover brain vectors from state.metadata if stage
        # timed out before its StageResult.data was written
        if not brain_vectors and state.metadata:
            saved_plan = state.metadata.get("intelligence_plan", {})
            if saved_plan:
                brain_vectors = saved_plan.get("vectors", [])
                if brain_vectors:
                    logger.info(
                        f"🧠 Recovered {len(brain_vectors)} brain vectors "
                        f"from metadata (attack_surface_mapping timed out)"
                    )

        if brain_vectors:
            logger.info(f"🧠 Loaded {len(brain_vectors)} brain attack vectors for targeted scanning")
            # Add brain-identified high-value endpoints to injection targets
            for vec in brain_vectors:
                ep = vec.get("endpoint", "")
                resolved = _resolve_brain_endpoint(ep, targets, state.target)
                if resolved and resolved not in endpoints:
                    endpoints.append(resolved)

        # ── Apply critique recommendations from orchestrator self-reflection ──
        _critique_recs: list[str] = []
        _historical_learning: dict[str, Any] = {}
        if state.metadata:
            _critique_recs = state.metadata.pop("critique_recommendations", [])
            _critique_action = state.metadata.pop("critique_adapt_action", None)
            _historical_learning = state.metadata.get("historical_learning", {}) or {}
            if _critique_recs:
                logger.info(
                    f"🧠 Applying {len(_critique_recs)} critique recommendations "
                    f"(action={_critique_action})"
                )
                for rec in _critique_recs:
                    logger.debug(f"  critique rec: {rec}")
        if _historical_learning.get("recommended_tools"):
            logger.info(
                "Historical learning suggests tools: {}",
                ", ".join(_historical_learning.get("recommended_tools", [])[:6]),
            )

        # ── DecisionEngine Profile-Aware Tool Selection (V11-T1-1) ──
        _skipped_tools: set[str] = set()
        _de_recommended_tools: list[str] = []
        try:
            from src.workflow.decision_engine import DecisionEngine, PROFILE_LIMITS
            _profile_limits = PROFILE_LIMITS.get(state.profile.value, PROFILE_LIMITS["balanced"])
            if _profile_limits.get("skip_aggressive_tools"):
                _skipped_tools = set(_profile_limits.get("aggressive_tools", []))
                if _skipped_tools:
                    logger.info(
                        f"🎯 Profile '{state.profile.value}' — skipping aggressive tools: "
                        f"{', '.join(sorted(_skipped_tools))}"
                    )

            # V13-T0-2: Call select_tools() with technology context for smarter selection
            _de_ctx: dict[str, Any] = {}
            if state.metadata and state.metadata.get("response_intel"):
                _ri = state.metadata["response_intel"]
                _de_ctx["technologies"] = {
                    "detected": list((_ri.get("technologies") or {}).keys())
                }
                if _ri.get("debug_mode_detected"):
                    _de_ctx["debug_mode"] = True
            if state.technologies:
                if "detected" not in _de_ctx.get("technologies", {}):
                    _de_ctx["technologies"] = {"detected": []}
                _de_ctx["technologies"]["detected"].extend(
                    t.lower() for t in (state.technologies or [])
                )
            if _de_ctx:
                try:
                    # V23: Pass available engines for brain-powered tool selection
                    _de_brain = getattr(state, "brain_engine", None)
                    _de_intel = getattr(state, "intelligence_engine", None)
                    _de_kb = getattr(_de_intel, "knowledge_base", None) if _de_intel else None
                    _de = DecisionEngine(
                        brain_engine=_de_brain,
                        knowledge_base=_de_kb,
                        registry=tool_registry,
                        profile=state.profile,
                    )
                    from src.utils.constants import WorkflowStage as _WS
                    _de_result = await asyncio.wait_for(
                        _de.select_tools(
                            stage=_WS.VULNERABILITY_SCAN,
                            target_type="web",
                            context=_de_ctx,
                        ),
                        timeout=1200.0,
                    )
                    _de_recommended_tools = _de_result.selected_tools or []
                    if _de_recommended_tools:
                        logger.info(
                            f"🧠 DecisionEngine recommended {len(_de_recommended_tools)} tools: "
                            f"{_de_recommended_tools[:10]}"
                        )
                except Exception as _de_exc:
                    logger.warning(f"DecisionEngine select_tools failed: {_de_exc}")
        except Exception as e:
            logger.debug(f"DecisionEngine profile check skipped: {e}")

        logger.info(
            f"Vulnerability scan started | targets={len(targets)} | "
            f"endpoints={len(endpoints)}"
        )

        # ── Start Interactsh OOB session (background) ──
        # This gives us an OOB domain for blind vuln payloads (SSRF, XXE, RCE)
        try:
            from src.tools.scanners.interactsh_wrapper import InteractshWrapper
            _interactsh = InteractshWrapper()
            if _interactsh.is_available():
                _oob_domain = await asyncio.wait_for(
                    _interactsh.start_session(), timeout=120.0
                )
                if _oob_domain:
                    logger.info(f"📡 OOB domain ready: {_oob_domain}")
                    # Store in state for deep_probe and other phases
                    state.metadata = state.metadata or {}
                    state.metadata["oob_domain"] = _oob_domain
        except Exception as exc:
            logger.debug(f"Interactsh session start skipped: {exc}")
            _interactsh = None

        # Carry over subdomain takeover findings from enumeration stage
        enum_sr = state.stage_results.get("enumeration")
        if enum_sr and enum_sr.data:
            takeover_findings = enum_sr.data.get("takeover_findings", [])
            if takeover_findings:
                all_findings.extend(takeover_findings)
                logger.info(f"Carried over {len(takeover_findings)} subdomain takeover findings")
            # Carry over GraphQL findings
            graphql_findings = enum_sr.data.get("graphql_findings", [])
            if graphql_findings:
                all_findings.extend(graphql_findings)
                logger.info(f"Carried over {len(graphql_findings)} GraphQL findings")

        # ── Extract auth headers from state (first-class or metadata fallback) ──
        _auth_headers: dict[str, str] = (
            state.auth_headers
            or (state.metadata.get("auth_headers", {}) if state.metadata else {})
        )
        if _auth_headers:
            logger.info(f"🔐 Authenticated scanning: {len(_auth_headers)} header(s) will be injected into probes")

        # ── Response Intelligence Analysis (V11-T2-1) ──
        # Analyze existing findings for technology/error/header signals
        _response_intel_dict: dict[str, Any] = {}
        try:
            from src.analysis.response_intelligence import analyze_responses, ResponseIntel
            _response_intel: ResponseIntel = analyze_responses(all_findings[:50])
            _response_intel_dict = _response_intel.to_dict()
            if _response_intel.technologies or _response_intel.error_disclosures:
                logger.info(f"Response intelligence: {_response_intel.summary()}")
                state.metadata = state.metadata or {}
                state.metadata["response_intel"] = _response_intel_dict
        except Exception as e:
            logger.debug(f"Response intelligence analysis skipped: {e}")

        # ── GF Pattern URL Classification (V8-T0-2) ──
        # Classify discovered endpoints by vulnerability type for targeted scanning
        _gf_classified: dict[str, list[str]] = {}
        if endpoints:
            try:
                from src.tools.recon.web_discovery.gf_patterns import GFPatternEngine
                _gf_engine = GFPatternEngine()
                _gf_classified = _gf_engine.classify(endpoints) or {}
                _gf_interesting_count = sum(
                    len(v) for k, v in _gf_classified.items() if k != "unmatched"
                )
                if _gf_interesting_count:
                    logger.info(
                        f"GF classification: {_gf_interesting_count} interesting URLs "
                        f"across {sum(1 for k, v in _gf_classified.items() if v and k != 'unmatched')} categories"
                    )
            except Exception as e:
                logger.debug(f"GF pattern classification skipped: {e}")

        # ── GF → Scanner Auto-Routing (V11-T0-3) ──
        # Route classified URLs to specialised scanners based on GF categories
        _gf_routed_tasks: list[dict[str, Any]] = []
        if _gf_classified:
            try:
                from src.tools.scanners.gf_router import route_urls as gf_route_urls
                _gf_routed_tasks = gf_route_urls(_gf_classified, max_urls_per_tool=30)
                if _gf_routed_tasks:
                    state.metadata = state.metadata or {}
                    state.metadata["gf_routed_tasks"] = len(_gf_routed_tasks)
                    # V23: Store full task details for downstream dispatch
                    state.metadata["gf_routed_tasks_detail"] = [
                        {"tool": t["tool"], "urls": t["urls"][:30],
                         "category": t.get("category", ""), "priority": t.get("priority", 99)}
                        for t in _gf_routed_tasks
                    ]
            except Exception as e:
                logger.debug(f"GF router skipped: {e}")

        # ── Multi-Pass Nuclei Scanning ──
        # Split nuclei into focused template category runs for better coverage
        # Each pass targets a specific template directory with its own timeout
        nuclei_tool = tool_registry.get("nuclei")

        # Dynamic target scaling: scan at least 25 hosts or 1/3 of total
        _nuclei_target_count = max(25, len(targets) // 3)
        if _scan_profile == "aggressive":
            _nuclei_target_count = max(50, len(targets) // 2)
        elif _scan_profile == "stealth":
            _nuclei_target_count = max(15, len(targets) // 4)
        _nuclei_targets = targets[:_nuclei_target_count]

        if nuclei_tool and nuclei_tool.is_available() and hasattr(nuclei_tool, "run_batch"):
            # Tiered pass strategy: Fast (critical, ALL hosts) → Medium (50%) → Deep (25%)
            nuclei_passes = [
                # Fast tier — critical templates, ALL _nuclei_targets, catches high-impact vulns first
                {"name": "cves", "templates": ["http/cves/"], "timeout": 600, "severity": "medium,high,critical", "tier": "fast"},
                {"name": "vulns", "templates": ["http/vulnerabilities/"], "timeout": 600, "tier": "fast"},
                {"name": "default-logins", "templates": ["http/default-logins/"], "timeout": 270, "tier": "fast"},
                {"name": "takeovers", "templates": ["http/takeovers/"], "timeout": 180, "tier": "fast"},
                # Medium tier — top 50% of hosts
                {"name": "exposures", "templates": ["http/exposures/"], "timeout": 630, "tier": "medium"},
                {"name": "misconfig", "templates": ["http/misconfiguration/"], "timeout": 540, "tier": "medium"},
                {"name": "exposed-panels", "templates": ["http/exposed-panels/"], "timeout": 360, "tier": "medium"},
            ]
            # Tier target slices
            _tier_targets = {
                "fast": _nuclei_targets,
                "medium": _nuclei_targets[: max(1, len(_nuclei_targets) * 2 // 3)],
                "deep": _nuclei_targets[: max(1, len(_nuclei_targets) // 3)],
            }
            # Add custom brain-generated templates if any exist
            import os
            custom_tmpl_dir = "data/nuclei_templates/custom"
            if os.path.isdir(custom_tmpl_dir) and os.listdir(custom_tmpl_dir):
                yaml_files = [f for f in os.listdir(custom_tmpl_dir) if f.endswith(".yaml")]
                if yaml_files:
                    nuclei_passes.append(
                        {"name": "custom-brain", "templates": [custom_tmpl_dir + "/"], "timeout": 180, "tier": "deep"}
                    )
                    logger.info(f"🧠 Added {len(yaml_files)} custom nuclei templates to scan passes")

            # Parallelize nuclei passes — each category is independent
            nuclei_sem = asyncio.Semaphore(2)  # Max 2 concurrent nuclei processes (was 3; reduced to prevent pthread_create EAGAIN)

            async def _nuclei_pass(npass: dict) -> list[dict]:
                async with nuclei_sem:
                    try:
                        opts = _get_scan_options(state.profile, "scanner")
                        # Adjust rate for WAF evasion (V6-T2-1)
                        _waf_r = _get_waf_result(state)
                        if _waf_r and _waf_r.detected and opts.get("rate"):
                            opts["rate"] = apply_rate_adjustment(opts["rate"], _waf_r)
                        opts["templates"] = npass["templates"]
                        # Select targets based on tier
                        _pass_tier = npass.get("tier", "fast")
                        _pass_targets = _tier_targets.get(_pass_tier, _nuclei_targets)
                        opts["timeout"] = npass["timeout"] + (len(_pass_targets) * 30)
                        # Per-pass severity override (e.g., CVEs skip low)
                        if "severity" in npass:
                            opts["severity"] = npass["severity"]
                        elif "severity" not in opts:
                            opts["severity"] = "low,medium,high,critical"
                        # Inject auth headers into nuclei
                        if _auth_headers:
                            opts.setdefault("headers", [])
                            for hk, hv in _auth_headers.items():
                                opts["headers"].append(f"{hk}: {hv}")
                        # Inject OOB domain for blind vulnerability detection
                        if _oob_domain:
                            opts["interactsh_url"] = _oob_domain
                        logger.debug(
                            f"Nuclei pass [{npass['name']}] tier={_pass_tier} "
                            f"targets={len(_pass_targets)}"
                        )
                        tool_result = await nuclei_tool.run_batch(
                            _pass_targets, opts, state.profile
                        )
                        findings: list[dict] = []
                        if tool_result and tool_result.findings:
                            for f in tool_result.findings:
                                fd = _finding_to_dict(f, "nuclei")
                                findings.append(fd)
                                logger.info(
                                    f"  [nuclei/{npass['name']}] {fd.get('title', 'N/A')} | "
                                    f"severity={fd.get('severity', '?')} | "
                                    f"url={fd.get('url', '?')}"
                                )
                        logger.info(f"Nuclei pass [{npass['name']}]: {len(findings)} findings")
                        return findings
                    except Exception as e:
                        logger.warning(f"Nuclei pass [{npass['name']}] failed: {e}")
                        if "nuclei" not in _failed_tools:
                            _failed_tools.append("nuclei")
                        return []

            nuclei_results = await asyncio.gather(
                *[_nuclei_pass(p) for p in nuclei_passes],
                return_exceptions=True,
            )
            total_nuclei_findings = 0
            _nuclei_suppressed = 0
            for res in nuclei_results:
                if isinstance(res, list):
                    for nf in res:
                        # ── BUG-3 FIX: Nuclei post-processing to reduce FP ──
                        _nf_title = str(nf.get("title", "")).lower()
                        _nf_sev = str(nf.get("severity", "")).upper()
                        _nf_tags = nf.get("tags", []) or []
                        _nf_tags_str = " ".join(str(t) for t in _nf_tags).lower() if _nf_tags else ""

                        # 1. Suppress pure tech-detect INFO findings (they flood results)
                        if _nf_sev == "INFO" and any(
                            kw in _nf_title or kw in _nf_tags_str
                            for kw in ("tech-detect", "technologies", "waf-detect", "fingerprint")
                        ):
                            _nuclei_suppressed += 1
                            continue

                        # 2. Suppress generic "missing header" INFO findings
                        if _nf_sev == "INFO" and any(
                            kw in _nf_title
                            for kw in ("missing", "not set", "not found", "absent")
                        ):
                            _nuclei_suppressed += 1
                            continue

                        all_findings.append(nf)
                        total_nuclei_findings += 1
                elif isinstance(res, Exception):
                    logger.warning(f"Nuclei parallel pass failed: {res}")
            if _nuclei_suppressed:
                logger.info(f"Nuclei post-filter: suppressed {_nuclei_suppressed} INFO/tech-detect findings")
            logger.info(f"Nuclei multi-pass complete (parallel): {total_nuclei_findings} total findings (after filter)")
            _sync_findings()  # Survive stage timeout

        # ── CMS-Specific Scanning (WordPress, etc.) ──
        _wpscan_done = False
        if state.technologies:
            wp_hosts = []
            for host, tech in state.technologies.items():
                tech_str = str(tech).lower() if tech else ""
                if "wordpress" in tech_str:
                    wp_hosts.append(host)
            if wp_hosts:
                wpscan_tool = tool_registry.get("wpscan")
                if wpscan_tool and wpscan_tool.is_available():
                    logger.info(f"WordPress detected on {len(wp_hosts)} hosts, running wpscan...")
                    for wp_host in wp_hosts[:3]:  # Max 3 WordPress hosts
                        try:
                            wp_url = f"https://{wp_host}" if not wp_host.startswith("http") else wp_host
                            wp_result = await executor.execute(
                                wpscan_tool, wp_url,
                                {"enumerate": "vp,vt,u", "timeout": 300},
                            )
                            if wp_result and wp_result.findings:
                                for f in wp_result.findings:
                                    fd = _finding_to_dict(f, "wpscan", fallback_url=wp_url)
                                    all_findings.append(fd)
                                    logger.info(
                                        f"  [wpscan] {fd.get('title', 'N/A')} | "
                                        f"severity={fd.get('severity', '?')}"
                                    )
                                logger.info(f"WPScan {wp_host}: {len(wp_result.findings)} findings")
                        except Exception as e:
                            logger.warning(f"WPScan {wp_host} failed: {e}")
                    _wpscan_done = True
                    _sync_findings()

        # ── Nikto Scanner (parallel across hosts) ──
        nikto_tool = tool_registry.get("nikto")
        if nikto_tool and nikto_tool.is_available():
            nikto_sem = asyncio.Semaphore(3)
            _nikto_timeout_count = 0

            async def _nikto_host(host: str) -> list[dict]:
                nonlocal _nikto_timeout_count
                if _nikto_timeout_count >= 3:
                    return []
                async with nikto_sem:
                    if _nikto_timeout_count >= 3:
                        return []
                    try:
                        opts = _get_scan_options(state.profile, "scanner")
                        tool_result = await executor.execute(nikto_tool, host, opts)
                        _nikto_timeout_count = 0
                        if tool_result and tool_result.findings:
                            return [_finding_to_dict(f, "nikto", fallback_url=host)
                                    for f in tool_result.findings]
                    except asyncio.TimeoutError:
                        _nikto_timeout_count += 1
                        logger.warning(f"Nikto timeout ({_nikto_timeout_count}/3) | {host}")
                        if _nikto_timeout_count >= 3:
                            logger.warning("Nikto: too many timeouts, skipping remaining hosts")
                    except Exception as e:
                        logger.warning(f"Nikto scanner@{host} failed: {e}")
                    return []

            nikto_results = await asyncio.gather(
                *[_nikto_host(h) for h in targets[:5]],
                return_exceptions=True,
            )
            for res in nikto_results:
                if isinstance(res, list):
                    all_findings.extend(res)
            _all_tools_run.append("nikto")

        _sync_findings()  # Survive stage timeout — nikto done

        # ── SearchSploit: CVE/Exploit lookup for discovered technologies ──
        if state.technologies:
            try:
                ssploit_tool = tool_registry.get("searchsploit")
                if ssploit_tool and ssploit_tool.is_available():
                    # ── Parse clean technology names from raw WhatWeb/httpx output ──
                    # state.technologies values may be raw JSON strings like:
                    #   '"plugins":{"httpserver":{"string":["nginx"]},"jquery":{"version":["3.2.1"]}}'
                    # We need to extract clean terms like: ["nginx", "jquery 3.2.1"]
                    import json as _json_tech
                    _TECH_NOISE = {
                        "html", "html5", "css", "javascript", "utf-8", "gzip",
                        "http", "https", "www", "text", "charset", "plugins",
                        "httpserver", "string", "version", "meta-generator",
                        "x-powered-by", "cookies", "ip", "country", "title",
                        "frame", "script", "headers", "metaname",
                    }
                    def _parse_tech_terms(raw_val: str) -> list[str]:
                        """Extract clean technology name+version from raw WhatWeb output."""
                        terms: list[str] = []
                        # Try JSON parse (WhatWeb --json output)
                        try:
                            data = _json_tech.loads("{" + raw_val + "}") if not raw_val.strip().startswith("{") else _json_tech.loads(raw_val)
                        except (ValueError, TypeError):
                            data = None
                        if isinstance(data, dict):
                            # Recursively extract tech names from WhatWeb plugin keys
                            def _extract(d: dict, prefix: str = "") -> None:
                                for key, val in d.items():
                                    key_lower = key.strip().lower()
                                    if key_lower in _TECH_NOISE or len(key_lower) < 2:
                                        continue
                                    if isinstance(val, dict):
                                        # Check for version inside
                                        ver = val.get("version", [])
                                        if isinstance(ver, list) and ver:
                                            terms.append(f"{key_lower} {ver[0]}")
                                        else:
                                            # Recurse but ALSO add the key as tech name
                                            terms.append(key_lower)
                                            _extract(val, key_lower)
                                    elif isinstance(val, list) and val:
                                        for v in val:
                                            if isinstance(v, str) and len(v) > 1 and v.lower() not in _TECH_NOISE:
                                                terms.append(v.lower())
                            _extract(data)
                        if not terms:
                            # Fallback: split on common delimiters and extract words
                            import re as _re_tech
                            # Clean any JSON-like artifacts
                            cleaned = _re_tech.sub(r'[{"\[\]\}:,]', ' ', raw_val)
                            for word in cleaned.split():
                                w = word.strip().lower().rstrip(';')
                                if len(w) > 2 and w not in _TECH_NOISE and not w.isdigit():
                                    terms.append(w)
                        return terms

                    tech_terms: list[str] = []
                    for _host, _tech_val in state.technologies.items():
                        if isinstance(_tech_val, list):
                            for tv in _tech_val:
                                tech_terms.extend(_parse_tech_terms(str(tv)))
                        elif isinstance(_tech_val, str) and _tech_val:
                            tech_terms.extend(_parse_tech_terms(_tech_val))
                    # Deduplicate, remove noise, limit length
                    unique_techs = list({t for t in tech_terms if t and len(t) > 2})[:15]
                    if unique_techs:
                        logger.info(f"🔍 SearchSploit: checking {len(unique_techs)} technologies for known exploits")
                        _all_tools_run.append("searchsploit")
                        ssploit_result = await ssploit_tool.run(
                            state.target,
                            options={"search_terms": unique_techs},
                        )
                        if ssploit_result and ssploit_result.findings:
                            # ── SearchSploit Noise Filter (v2 — relevance check) ──
                            # SearchSploit matches are generic "exploit exists for this tech"
                            # without version verification. Filter irrelevant results.
                            from src.utils.constants import SeverityLevel as _SL
                            _SSPLOIT_MAX_SEVERITY = _SL.MEDIUM
                            _ssploit_accepted = 0
                            _ssploit_rejected = 0
                            _tech_set_lower = {t.split()[0] for t in unique_techs}  # {"nginx", "jquery", ...}
                            for f in ssploit_result.findings:
                                fd = _finding_to_dict(f, "searchsploit")
                                # ── Relevance filter: title must mention a detected tech ──
                                _title_lower = fd.get("title", "").lower()
                                _is_relevant = any(tech in _title_lower for tech in _tech_set_lower)
                                if not _is_relevant:
                                    _ssploit_rejected += 1
                                    continue
                                # Cap severity — unverified exploit DB matches are at most MEDIUM
                                _sev = fd.get("severity", "").upper()
                                if _sev in ("CRITICAL", "HIGH"):
                                    fd["severity"] = _SSPLOIT_MAX_SEVERITY.value
                                    fd["original_severity"] = _sev
                                # Mark as unverified CVE match
                                fd["searchsploit_unverified"] = True
                                fd.setdefault("confidence_score", 30.0)
                                # Append note to description
                                fd["description"] = (
                                    fd.get("description", "")
                                    + "\n\n⚠️ Note: This is an unverified Exploit-DB match based on "
                                    "technology fingerprinting. The target version may not be affected. "
                                    "Manual verification required."
                                )
                                all_findings.append(fd)
                                _ssploit_accepted += 1
                            logger.info(
                                f"🔍 SearchSploit: {len(ssploit_result.findings)} raw, "
                                f"{_ssploit_accepted} relevant (rejected {_ssploit_rejected} irrelevant), "
                                f"severity capped to MEDIUM"
                            )
                            _sync_findings()
            except ImportError:
                pass
            except Exception as exc:
                logger.warning(f"SearchSploit check failed: {exc}")

        # ── Agentic Branch Point (T1-1 Phase 1) ──
        # After the initial broad scanners have run, let the LLM decide the
        # safest high-value next move using only the remaining built-in tools.
        try:
            intel = state.intelligence_engine
            if intel and getattr(intel, "is_available", False):
                _remaining_tools = [
                    t for t in [
                        "sqlmap", "commix", "dalfox", "ssrfmap", "corsy", "crlfuzz", "tplmap",
                        "header_checker", "tech_cve_checker", "sensitive_url_finder",
                        "js_analyzer", "http_method_checker", "open_redirect_checker",
                        "info_disclosure_checker", "cookie_checker", "api_endpoint_tester",
                        "cors_checker", "auth_bypass_checker", "rate_limit_checker",
                        "business_logic_checker", "deserialization_checker", "bfla_bola_checker",
                        "mass_assignment_checker", "idor_checker", "cache_poisoning_checker",
                        "websocket_checker", "cloud_misconfig_checker", "jwt_checker",
                        "fourxx_bypass", "http_smuggling_prober", "graphql_deep_scanner",
                        "cloud_infra_checker", "cicd_checker", "http2_http3_checker",
                        "deep_probe", "exploit_verifier",
                    ]
                    if t not in _all_tools_run and t not in _skipped_tools
                ]
                _elapsed = ""
                if state.start_time:
                    _elapsed_secs = max(0.0, time.time() - state.start_time)
                    _elapsed = f"{_elapsed_secs:.0f}s ({_elapsed_secs / 60:.1f}m)"

                _agentic = await asyncio.wait_for(
                    intel.decide_next_action(
                        current_stage=WorkflowStage.VULNERABILITY_SCAN.value,
                        findings_so_far=all_findings[:50],
                        completed_tools=list(_all_tools_run),
                        remaining_tools=_remaining_tools,
                        time_elapsed=_elapsed,
                        scan_profile=state.profile.value,
                        historical_learning=_historical_learning,
                    ),
                    timeout=1200.0,
                )

                if _agentic.reason:
                    logger.info(
                        f"🧠 Agentic next action | action={_agentic.action} | "
                        f"next_tool={_agentic.next_tool or '-'} | reason={_agentic.reason[:180]}"
                    )

                if _agentic.skip_tools:
                    _new_skips = {
                        t for t in _agentic.skip_tools
                        if t and t not in _all_tools_run
                    }
                    if _new_skips:
                        _skipped_tools.update(_new_skips)
                        logger.info(
                            f"🧠 Agentic skip list updated: {', '.join(sorted(_new_skips))}"
                        )

                if _agentic.deep_dive_target:
                    _resolved_deep_target = _resolve_brain_endpoint(
                        _agentic.deep_dive_target, targets, state.target
                    )
                    if _resolved_deep_target:
                        if _resolved_deep_target not in endpoints:
                            endpoints.insert(0, _resolved_deep_target)

                        _tool_to_vuln = {
                            "sqlmap": "sql_injection",
                            "commix": "command_injection",
                            "dalfox": "xss_reflected",
                            "ssrfmap": "server_side_request_forgery",
                            "tplmap": "ssti",
                            "idor_checker": "idor",
                            "graphql_deep_scanner": "graphql",
                            "fourxx_bypass": "authentication_bypass",
                            "jwt_checker": "auth_bypass",
                            "cicd_checker": "cicd_security",
                            "http2_http3_checker": "protocol_security",
                            "deep_probe": "deep_probe",
                        }
                        brain_vectors.insert(0, {
                            "endpoint": _resolved_deep_target,
                            "parameter": "",
                            "vuln_type": _tool_to_vuln.get(_agentic.next_tool, "deep_probe"),
                            "priority": "high",
                            "reasoning": _agentic.reason or "Agentic deep-dive target",
                            "tools": [_agentic.next_tool] if _agentic.next_tool else [],
                            "payloads": [],
                            "estimated_time": 90,
                        })
                        state.metadata = state.metadata or {}
                        state.metadata["agentic_next_action"] = {
                            "action": _agentic.action,
                            "next_tool": _agentic.next_tool,
                            "deep_dive_target": _resolved_deep_target,
                            "skip_tools": list(_agentic.skip_tools),
                            "reason": _agentic.reason,
                        }
                elif _agentic.next_tool or _agentic.skip_tools:
                    state.metadata = state.metadata or {}
                    state.metadata["agentic_next_action"] = {
                        "action": _agentic.action,
                        "next_tool": _agentic.next_tool,
                        "deep_dive_target": "",
                        "skip_tools": list(_agentic.skip_tools),
                        "reason": _agentic.reason,
                    }

                # P3-2: Handle new agentic actions
                if _agentic.action == "deep_dive_tool" and _agentic.deep_dive_tool:
                    # deep_dive_tool: specific tool for deep investigation
                    logger.info(
                        f"Agentic deep_dive_tool: {_agentic.deep_dive_tool} "
                        f"on {_agentic.deep_dive_target or 'current targets'}"
                    )
                    state.metadata = state.metadata or {}
                    state.metadata["agentic_next_action"] = {
                        "action": "deep_dive_tool",
                        "next_tool": _agentic.deep_dive_tool,
                        "deep_dive_target": _agentic.deep_dive_target,
                        "skip_tools": list(_agentic.skip_tools),
                        "reason": _agentic.reason,
                    }

                if _agentic.action == "change_strategy" and _agentic.change_strategy:
                    logger.info(f"Agentic strategy change: → {_agentic.change_strategy}")
                    state.metadata = state.metadata or {}
                    state.metadata["agentic_strategy_change"] = _agentic.change_strategy

                if _agentic.retry_with_auth:
                    logger.info("Agentic decision: retry_with_auth flagged")
                    state.metadata = state.metadata or {}
                    state.metadata["agentic_retry_with_auth"] = True

                if _agentic.request_oob_check:
                    logger.info("Agentic decision: OOB callback check requested")
                    state.metadata = state.metadata or {}
                    state.metadata["agentic_request_oob_check"] = True
        except asyncio.TimeoutError:
            logger.warning("Agentic next-action decision timed out")
        except Exception as exc:
            logger.warning(f"Agentic next-action decision failed: {exc}")

        # ── Injection Tests (sqlmap, commix) ──
        injection_tools = [t for t in ["sqlmap", "commix"] if t not in _skipped_tools]
        # Filter endpoints with query parameters (sqlmap needs ?key=value)
        # Clean up polluted URLs from crawlers (gospider [code-XXX] prefix, ANSI codes)
        import re as _re
        _ANSI_CLEAN_RE = _re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b.')
        def _clean_url(url: str) -> str:
            url = url.strip()
            # Discard URLs contaminated with ANSI escape codes — they're
            # terminal output artifacts, not real endpoints
            if '\x1b' in url:
                return ''
            if url.startswith("["):
                m = _re.match(r'\[code-\d+\]\s*-\s*', url)
                if m:
                    url = url[m.end():].strip()
            return url

        # Static asset extensions — never worth injection/XSS testing
        _STATIC_EXTS = frozenset({
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".pdf", ".zip", ".gz", ".tar", ".bz2", ".rar", ".7z",
            ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg",
            ".map", ".webp", ".avif", ".bmp", ".tiff",
            ".swf", ".flv", ".wmv",
        })

        def _is_static_asset(url: str) -> bool:
            """Return True if URL points to a static asset (not worth testing)."""
            from urllib.parse import urlparse as _up
            try:
                parsed = _up(url)
                path = parsed.path.lower().rstrip("/")
                # Extension-based check
                if any(path.endswith(ext) for ext in _STATIC_EXTS):
                    return True
                # Path pattern check — avatars, images, feeds, etc.
                _SKIP_PATTERNS = ("/avatar/", "/gravatar/avatar/", "/feed/", "/rss/",
                                  "/sitemap", "/robots.txt", "/favicon",
                                  "/_static/", "/wp-content/uploads/")
                if any(p in path for p in _SKIP_PATTERNS):
                    return True
                return False
            except Exception as _exc:
                logger.warning(f"full scan error: {_exc}")
                return False

        endpoints = {_clean_url(ep) for ep in endpoints if ep}
        endpoints.discard("")

        # Resolve bare paths (no hostname) by prepending target host
        _bare_paths = {ep for ep in endpoints if ep.startswith("/") and "://" not in ep}
        if _bare_paths:
            _targets = list(state.live_hosts or []) or [state.target]
            _resolved_set: set[str] = set()
            for _bp in _bare_paths:
                _full = _resolve_brain_endpoint(_bp, _targets, state.target)
                if _full:
                    _resolved_set.add(_full)
            endpoints -= _bare_paths
            endpoints |= _resolved_set
            logger.info(
                f"Bare path resolver: {len(_bare_paths)} bare → {len(_resolved_set)} resolved"
            )

        # Remove static assets early — saves many tool invocations
        _ep_before_static = len(endpoints)
        endpoints = {ep for ep in endpoints if not _is_static_asset(ep)}
        _static_dropped = _ep_before_static - len(endpoints)
        if _static_dropped:
            logger.info(f"Static asset filter: dropped {_static_dropped} static URLs from {_ep_before_static}")

        # Pre-filter endpoints through scope (avoid wasting tool invocations)
        if state.scope_config:
            from src.utils.scope_validator import ScopeValidator
            _sv = ScopeValidator.from_dict(state.scope_config)
            _before = len(endpoints)
            _filtered = set()
            for _ep in endpoints:
                try:
                    from urllib.parse import urlparse as _urlparse
                    _hostname = _urlparse(_ep).hostname or ""
                    if _hostname and _sv.is_in_scope(_hostname):
                        _filtered.add(_ep)
                except Exception as _exc:
                    _filtered.add(_ep)  # Keep if can't parse
            endpoints = _filtered
            _dropped = _before - len(endpoints)
            if _dropped > 0:
                logger.info(f"Scope filter: dropped {_dropped} out-of-scope URLs from {_before}")

        # Convert set back to list (subsequent code uses list operations like .append())
        endpoints = list(endpoints)

        param_endpoints = [ep for ep in endpoints if "?" in ep and "=" in ep]

        # Deduplicate by (host, param_names) pattern — same params on same host
        # only need to be tested once
        def _dedup_injection_targets(urls: list[str]) -> list[str]:
            from urllib.parse import urlparse, parse_qs
            # Only normalize ACTUAL locale prefixes, not functional subdomains
            _LOCALE_RE = _re.compile(
                r'^(?:[a-z]{2}|[a-z]{2}-[a-z]{2}|[a-z]{2}_[a-z]{2})$', _re.IGNORECASE
            )
            seen_patterns: set[tuple[str, ...]] = set()
            unique: list[str] = []
            for url in urls:
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or ""
                    # Normalize locale subdomains: ja.gravatar.com → *.gravatar.com
                    # But keep functional subdomains: api.gravatar.com, cdn.gravatar.com
                    parts = host.split(".")
                    if len(parts) >= 3 and _LOCALE_RE.match(parts[0]):
                        host = "*" + "." + ".".join(parts[1:])
                    path = parsed.path.rstrip("/")
                    params = tuple(sorted(parse_qs(parsed.query or "").keys()))
                    pattern = (host, path, *params)
                    if pattern not in seen_patterns:
                        seen_patterns.add(pattern)
                        unique.append(url)
                except Exception as _exc:
                    unique.append(url)
            return unique

        deduped_params = _dedup_injection_targets(param_endpoints)
        logger.info(f"Injection targets: {len(param_endpoints)} param URLs -> {len(deduped_params)} unique patterns")

        # ── Synthetic Parameter Injection ──
        # If no parameterized endpoints found, synthesize them by appending
        # common injection-worthy parameters to interesting non-param endpoints.
        # This compensates for Arjun being disabled (Python 3.13 compat).
        if len(deduped_params) < 3:
            _INJECT_PARAMS = ["id", "q", "search", "page", "file", "url", "name", "user", "email", "action"]
            _synth_targets: list[str] = []
            # Pick endpoints that look like they might accept params
            _injectable_patterns = _re.compile(
                r'/api/|/search|/user|/account|/profile|/page|/item|/product|'
                r'/order|/view|/get|/list|/detail|/show|/find|/lookup|/check',
                _re.IGNORECASE,
            )
            for ep in endpoints:
                if "?" in ep:
                    continue  # already has params
                if _is_static_asset(ep):
                    continue
                if _injectable_patterns.search(ep):
                    # Add top 3 common params
                    for param in _INJECT_PARAMS[:3]:
                        _synth_targets.append(f"{ep}?{param}=test123")
                    if len(_synth_targets) >= 9:
                        break
            if _synth_targets:
                _synth_deduped = _dedup_injection_targets(_synth_targets)
                logger.info(
                    f"🔧 Synthesized {len(_synth_deduped)} parameterized injection targets "
                    f"(Arjun disabled, no param URLs found)"
                )
                deduped_params.extend(_synth_deduped)

        # Prioritize brain-recommended injection targets
        brain_inj_eps: list[str] = []
        for vec in brain_vectors:
            vt = (vec.get("vuln_type") or "").lower()
            ep = vec.get("endpoint", "")
            if ep and any(kw in vt for kw in ("sqli", "sql", "injection", "xss", "command", "rce")):
                full_ep = _resolve_brain_endpoint(ep, targets, state.target)
                if full_ep and full_ep not in brain_inj_eps:
                    brain_inj_eps.append(full_ep)
        if brain_inj_eps:
            logger.info(f"🧠 Brain prioritized {len(brain_inj_eps)} injection endpoints")

        # -- C2: Score injection endpoints by "likely vulnerable" heuristics --
        _HIGH_VALUE_PARAMS = {
            "id", "user_id", "uid", "userid", "account_id", "item_id",
            "order_id", "product_id", "page_id", "post_id", "category_id",
            "search", "q", "query", "keyword", "term", "s",
            "file", "path", "url", "redirect", "next", "return",
            "page", "sort", "order", "filter", "type", "action",
            "username", "email", "name", "login", "password",
            "callback", "cb", "ref", "source", "template", "view",
        }
        _HIGH_VALUE_PATHS_RE = _re.compile(
            r"/(api|admin|auth|login|user|account|profile|settings|upload|"
            r"download|export|import|search|edit|delete|update|manage|dashboard|"
            r"graphql|rest|v[0-9]+|internal|debug|test)",
            _re.IGNORECASE,
        )

        # Business-logic keywords that indicate high-value transactional endpoints
        _BUSINESS_LOGIC_KEYWORDS = {
            "cart", "checkout", "order", "payment", "pay", "purchase", "buy",
            "transfer", "withdraw", "deposit", "balance", "wallet", "invoice",
            "subscribe", "billing", "coupon", "discount", "redeem", "refund",
            "price", "amount", "quantity", "total", "shipping", "promo",
        }

        # Tech-stack based scoring bonuses (detected techs → extra points)
        _TECH_SCORE_BONUSES: dict[str, int] = {
            "graphql": 30, "php": 20, "java": 15, "spring": 15,
            "asp.net": 15, "django": 10, "flask": 12, "rails": 10,
            "laravel": 12, "wordpress": 20, "joomla": 18, "drupal": 15,
            "tomcat": 12, "node": 8, "express": 8, "nginx": 3,
            "apache": 3, "iis": 10, "elasticsearch": 15, "jenkins": 20,
        }

        # Collect flattened tech list once for scoring
        _flat_techs: set[str] = set()
        for _tv in state.technologies.values():
            if isinstance(_tv, list):
                for _t in _tv:
                    _flat_techs.add(str(_t).lower())
            elif isinstance(_tv, str):
                _flat_techs.add(_tv.lower())

        def _score_endpoint(ep: str) -> int:
            """Score endpoint by injection likelihood (higher = more interesting)."""
            score = 0
            try:
                from urllib.parse import urlparse, parse_qs
                p = urlparse(ep)
                params = parse_qs(p.query, keep_blank_values=True)
                path_lower = p.path.lower()

                # High-value parameter names
                for pname in params:
                    pname_lower = pname.lower()
                    if pname_lower in _HIGH_VALUE_PARAMS:
                        score += 10
                    elif pname_lower.endswith("_id") or pname_lower.endswith("id"):
                        score += 8

                # Number of parameters (more params = more attack surface)
                score += min(len(params) * 2, 10)

                # High-value path patterns
                if _HIGH_VALUE_PATHS_RE.search(p.path):
                    score += 5

                # Dynamic-looking path segments (e.g. /users/123/orders)
                if _re.search(r"/\d+(/|$)", p.path):
                    score += 3

                # Business-logic keywords in path or param names → high value
                if any(kw in path_lower for kw in _BUSINESS_LOGIC_KEYWORDS):
                    score += 25
                for pname in params:
                    if pname.lower() in _BUSINESS_LOGIC_KEYWORDS:
                        score += 20

                # Auth-related endpoints gain extra priority
                if _re.search(r"/(auth|login|token|oauth|session|register|signup|reset|password)", path_lower):
                    score += 20

                # Technology-stack bonuses
                for tech, bonus in _TECH_SCORE_BONUSES.items():
                    if tech in _flat_techs:
                        score += bonus
                        break  # Only highest bonus

                # Deeper path depth = potentially more specific = more interesting
                segments = [s for s in p.path.split("/") if s]
                if len(segments) >= 3:
                    score += 5
                if len(segments) >= 5:
                    score += 5

            except Exception:
                pass
            return score

        # Sort deduped_params by score (highest first)
        deduped_params.sort(key=_score_endpoint, reverse=True)

        # P4.5: Sort ALL endpoint lists by quality score so that slices like
        # endpoints[:N] always select the most promising targets first.
        # This is critical because endpoints came from a set() → list()
        # conversion which produces an arbitrary order.
        endpoints.sort(key=_score_endpoint, reverse=True)
        if state.endpoints:
            state.endpoints.sort(key=_score_endpoint, reverse=True)
        logger.info(
            f"📊 Endpoint quality scoring: {len(endpoints)} endpoints sorted "
            f"(top score: {_score_endpoint(endpoints[0]) if endpoints else 0})"
        )

        # ── v5.0-P2.1: Endpoint Pre-Flight Validation ──
        # Before spending time on vulnerability scanning, probe each endpoint
        # to eliminate dead (404/5xx), WAF-blocked, and SPA catch-all URLs.
        # This prevents scanners from generating FPs against non-existent pages.
        _preflight_max = 80  # max endpoints to preflight (budget)
        _preflight_candidates = endpoints[:_preflight_max]
        _preflight_alive: list[str] = []
        _preflight_dead: list[str] = []
        _preflight_waf: list[str] = []
        _preflight_spa: list[str] = []

        if _preflight_candidates:
            try:
                from src.utils.response_validator import (
                    ResponseValidator as _PFResponseValidator,
                )

                _pf_rv = _PFResponseValidator()
                # Seed SPA baselines from earlier capture if available
                _pf_baselines: dict[str, str] = (
                    state.metadata.get("_spa_baselines", {})
                    if state.metadata
                    else {}
                )
                for _pf_h, _pf_b in _pf_baselines.items():
                    _pf_rv.set_baseline(_pf_h, _pf_b)

                _pf_timeout = httpx.Timeout(12.0, connect=8.0)
                _pf_hdrs = {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "Chrome/131.0.0.0"
                    ),
                }
                if _auth_headers:
                    _pf_hdrs.update(_auth_headers)

                _pf_sem = asyncio.Semaphore(10)

                async def _preflight_check(url: str) -> tuple[str, str]:
                    """Return (url, status) where status is alive/dead/waf/spa."""
                    async with _pf_sem:
                        try:
                            async with httpx.AsyncClient(
                                timeout=_pf_timeout,
                                verify=False,
                                follow_redirects=True,
                                headers=_pf_hdrs,
                            ) as _pf_client:
                                resp = await _pf_client.get(url)
                                body = resp.text[:8192] if resp.text else ""
                                hdrs = dict(resp.headers) if resp.headers else {}
                                code = resp.status_code

                                # Dead: 404, 410, 5xx
                                if code in (404, 410) or code >= 500:
                                    return (url, "dead")

                                # Use ResponseValidator for WAF/SPA detection
                                from urllib.parse import urlparse

                                _parsed = urlparse(url)
                                _host = _parsed.hostname or ""
                                vr = _pf_rv.validate(
                                    code,
                                    hdrs,
                                    body,
                                    url=url,
                                )
                                if vr.is_waf_block:
                                    return (url, "waf")
                                if vr.is_spa_catchall:
                                    return (url, "spa")
                                if vr.is_auth_redirect:
                                    return (url, "auth")

                                # Alive: meaningful response
                                if 200 <= code < 400 and len(body) > 50:
                                    return (url, "alive")

                                # Auth-required (401/403 without auth headers)
                                if code in (401, 403):
                                    return (url, "auth")

                                # Too-small body or odd status — mark dead
                                if len(body) <= 50:
                                    return (url, "dead")

                                return (url, "alive")
                        except Exception:
                            # Network error — keep endpoint (don't penalize
                            # for transient failures)
                            return (url, "alive")

                _pf_tasks = [
                    _preflight_check(ep) for ep in _preflight_candidates
                ]
                _pf_results = await asyncio.gather(*_pf_tasks)

                _preflight_auth: list[str] = []

                for _pf_url, _pf_status in _pf_results:
                    if _pf_status == "alive":
                        _preflight_alive.append(_pf_url)
                    elif _pf_status == "dead":
                        _preflight_dead.append(_pf_url)
                    elif _pf_status == "waf":
                        _preflight_waf.append(_pf_url)
                    elif _pf_status == "spa":
                        _preflight_spa.append(_pf_url)
                    elif _pf_status == "auth":
                        _preflight_auth.append(_pf_url)

                # ── Host auth detection: aggregate per-host auth results ──
                _host_profiles: dict[str, dict] = {}
                from urllib.parse import urlparse as _hp_urlparse

                _host_auth_counts: dict[str, int] = {}
                _host_total_counts: dict[str, int] = {}
                for _pf_url, _pf_status in _pf_results:
                    try:
                        _h = _hp_urlparse(_pf_url).hostname or ""
                    except Exception:
                        continue
                    if not _h:
                        continue
                    _host_total_counts[_h] = _host_total_counts.get(_h, 0) + 1
                    if _pf_status == "auth":
                        _host_auth_counts[_h] = _host_auth_counts.get(_h, 0) + 1

                for _h, _auth_n in _host_auth_counts.items():
                    _total_n = _host_total_counts.get(_h, 1)
                    # Host is auth-gated if ≥3 paths return auth OR >60% of paths
                    if _auth_n >= 3 or (_auth_n / max(_total_n, 1)) > 0.6:
                        _host_profiles[_h] = {"auth_gated": True, "auth_count": _auth_n, "total_count": _total_n}
                        logger.info(f"🔒 Host auth-gated: {_h} ({_auth_n}/{_total_n} paths returned 401/403)")

                if _host_profiles and state.metadata is not None:
                    state.metadata["host_profiles"] = _host_profiles

                # Auth endpoints are filtered out unless we have auth headers
                if _auth_headers:
                    _preflight_alive.extend(_preflight_auth)
                else:
                    _preflight_dead.extend(_preflight_auth)

                # Replace endpoints with alive ones + any beyond the preflight limit
                _pf_remaining = endpoints[_preflight_max:]
                endpoints = _preflight_alive + _pf_remaining

                logger.info(
                    f"✈️ Endpoint pre-flight: {len(_preflight_alive)} alive, "
                    f"{len(_preflight_dead)} dead, {len(_preflight_waf)} WAF-blocked, "
                    f"{len(_preflight_spa)} SPA catch-all, "
                    f"{len(_preflight_auth)} auth-gated "
                    f"(filtered {len(_preflight_dead) + len(_preflight_waf) + len(_preflight_spa)} endpoints)"
                )
                if state.metadata is not None:
                    state.metadata["preflight_results"] = {
                        "alive": len(_preflight_alive),
                        "dead": len(_preflight_dead),
                        "waf": len(_preflight_waf),
                        "spa": len(_preflight_spa),
                        "auth": len(_preflight_auth),
                        "auth_gated_hosts": list(_host_profiles.keys()),
                        "filtered_urls": (_preflight_dead + _preflight_waf)[:20],
                    }
            except Exception as _pf_exc:
                logger.warning(f"Endpoint pre-flight skipped: {_pf_exc}")

        # Also filter deduped_params with the same dead/waf list
        if _preflight_dead or _preflight_waf:
            _pf_reject = set(_preflight_dead + _preflight_waf)
            deduped_params = [p for p in deduped_params if p not in _pf_reject]

        # Also test top target roots (level 3 tests headers/cookies)
        top_roots = [
            f"https://{t}" if not t.startswith("http") else t
            for t in targets[:2]
        ]
        # Dynamic injection target scaling with high-value param prioritization
        _HIGH_VALUE_PARAMS = {"id", "user", "uid", "search", "query", "q", "name", "email",
                              "page", "file", "path", "url", "redirect", "token", "order",
                              "sort", "filter", "category", "item", "product"}

        def _param_priority(url: str) -> int:
            """Lower = higher priority. High-value params get priority 0."""
            try:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(url).query)
                for p in qs:
                    if p.lower() in _HIGH_VALUE_PARAMS:
                        return 0
                return 1
            except Exception:
                return 1

        deduped_params.sort(key=_param_priority)
        _sqli_count = max(80, len(deduped_params) // 3)
        if _scan_profile == "aggressive":
            _sqli_count = max(120, len(deduped_params) // 2)
        elif _scan_profile == "stealth":
            _sqli_count = max(30, len(deduped_params) // 5)
        _sqli_params = deduped_params[:_sqli_count]

        # Brain endpoints first, then GF-classified SQLi, then scored params, then roots
        _gf_sqli = _gf_classified.get("sqli", [])[:5] if _gf_classified else []
        scan_endpoints_inj = list(dict.fromkeys(
            brain_inj_eps[:5] + _gf_sqli + _sqli_params + [
                t for t in top_roots if t not in _sqli_params
            ]
        ))[:(_sqli_count + 10)]

        inj_sem = asyncio.Semaphore(2)  # Max 2 concurrent injection tests

        for tool_name in injection_tools:
            tool = tool_registry.get(tool_name)
            if not tool or not tool.is_available():
                continue
            _inj_timeout_count = 0
            _INJ_MAX_TIMEOUTS = 3

            async def _inject_ep(ep: str, _tool=tool, _name=tool_name) -> list[dict]:
                nonlocal _inj_timeout_count
                if _inj_timeout_count >= _INJ_MAX_TIMEOUTS:
                    return []
                async with inj_sem:
                    if _inj_timeout_count >= _INJ_MAX_TIMEOUTS:
                        return []
                    try:
                        opts = _get_scan_options(state.profile, "injection")
                        opts = await _brain_enhanced_options(state, _name, ep, opts)
                        # Inject auth headers for authenticated endpoint testing
                        if _auth_headers:
                            opts.setdefault("headers", [])
                            for hk, hv in _auth_headers.items():
                                if hk.lower() == "cookie":
                                    opts["cookie"] = hv
                                else:
                                    opts["headers"].append(f"{hk}: {hv}")
                        tool_result = await executor.execute(_tool, ep, opts)
                        _inj_timeout_count = 0
                        if tool_result and tool_result.findings:
                            return [_finding_to_dict(f, _name, fallback_url=ep)
                                    for f in tool_result.findings]
                    except asyncio.TimeoutError:
                        _inj_timeout_count += 1
                        logger.warning(
                            f"Injection {_name} timeout ({_inj_timeout_count}/{_INJ_MAX_TIMEOUTS}) | {ep}"
                        )
                        if _inj_timeout_count >= _INJ_MAX_TIMEOUTS:
                            logger.warning(f"{_name}: too many timeouts, skipping remaining endpoints")
                    except Exception as e:
                        logger.warning(f"Injection {_name}@{ep} failed: {e}")
                        if _name not in _failed_tools:
                            _failed_tools.append(_name)
                    return []

            inj_results = await asyncio.gather(
                *[_inject_ep(ep) for ep in scan_endpoints_inj],
                return_exceptions=True,
            )
            for res in inj_results:
                if isinstance(res, list):
                    all_findings.extend(res)
            _all_tools_run.append(tool_name)

        # -- SSL/TLS Check (parallel across hosts) --
        for tool_name in ["sslscan", "sslyze"]:
            tool = tool_registry.get(tool_name)
            if not tool or not tool.is_available():
                continue
            ssl_targets = targets[:5]
            ssl_sem = asyncio.Semaphore(3)

            async def _ssl_host(host: str) -> list[dict]:
                async with ssl_sem:
                    try:
                        tool_result = await executor.execute(tool, host, {"timeout": 90})
                        if tool_result and tool_result.findings:
                            return [_finding_to_dict(
                                f, tool_name,
                                fallback_url=host,
                                vuln_type_override="ssl_tls_misconfiguration",
                            ) for f in tool_result.findings]
                    except Exception as _exc:
                        logger.warning(f"full scan error: {_exc}")
                    return []

            ssl_results = await asyncio.gather(
                *[_ssl_host(h) for h in ssl_targets],
                return_exceptions=True,
            )
            for res in ssl_results:
                if isinstance(res, list):
                    all_findings.extend(res)
            break  # Bir SSL araci yeterli

        # -- XSS Scanning (dalfox, parallel across endpoints) --
        dalfox_tool = tool_registry.get("dalfox")
        if dalfox_tool and dalfox_tool.is_available() and endpoints and "dalfox" not in _skipped_tools:
            param_urls = [ep for ep in endpoints if "?" in ep or "=" in ep]
            # Prioritize GF-classified XSS URLs first (V8-T0-2)
            _gf_xss = _gf_classified.get("xss", []) if _gf_classified else []
            if _gf_xss:
                # GF XSS URLs first, then other parameterized URLs
                param_urls = list(dict.fromkeys(_gf_xss + param_urls))
            # Reuse same dedup logic as injection targets (locale subdomains etc.)
            param_urls = _dedup_injection_targets(param_urls)
            logger.info(f"XSS targets (dalfox): {len(param_urls)} unique param URLs (GF-prioritized: {len(_gf_xss)})")
            xss_sem = asyncio.Semaphore(3)
            _dalfox_timeout_count = 0  # Track consecutive timeouts
            _DALFOX_MAX_TIMEOUTS = 5   # Abort after this many timeouts

            async def _xss_ep(endpoint: str) -> list[dict]:
                nonlocal _dalfox_timeout_count
                # Skip if too many timeouts already
                if _dalfox_timeout_count >= _DALFOX_MAX_TIMEOUTS:
                    return []
                async with xss_sem:
                    if _dalfox_timeout_count >= _DALFOX_MAX_TIMEOUTS:
                        return []
                    try:
                        opts = _get_scan_options(state.profile, "xss")
                        # Enable parameter mining for hidden param discovery
                        opts["mining_dict"] = True
                        opts["mining_dom"] = True
                        opts = await _brain_enhanced_options(state, "dalfox", endpoint, opts)
                        # Inject auth headers for authenticated XSS testing
                        if _auth_headers:
                            opts.setdefault("headers", [])
                            for hk, hv in _auth_headers.items():
                                if hk.lower() == "cookie":
                                    opts["cookie"] = hv
                                else:
                                    opts["headers"].append(f"{hk}: {hv}")
                        tool_result = await executor.execute(dalfox_tool, endpoint, opts)
                        _dalfox_timeout_count = 0  # Reset on success
                        if tool_result and tool_result.findings:
                            return [_finding_to_dict(f, "dalfox", fallback_url=endpoint)
                                    for f in tool_result.findings]
                    except asyncio.TimeoutError:
                        _dalfox_timeout_count += 1
                        logger.warning(
                            f"Dalfox timeout ({_dalfox_timeout_count}/{_DALFOX_MAX_TIMEOUTS}) | {endpoint}"
                        )
                        if _dalfox_timeout_count >= _DALFOX_MAX_TIMEOUTS:
                            logger.warning("Dalfox: too many timeouts, skipping remaining URLs")
                    except Exception as e:
                        logger.warning(f"Dalfox XSS test {endpoint} failed: {e}")
                        if "dalfox" not in _failed_tools:
                            _failed_tools.append("dalfox")
                    return []

            # Dynamic XSS target scaling
            _dalfox_count = max(50, len(param_urls) // 4)
            if _scan_profile == "aggressive":
                _dalfox_count = max(80, len(param_urls) // 3)
            elif _scan_profile == "stealth":
                _dalfox_count = max(20, len(param_urls) // 5)
            xss_results = await asyncio.gather(
                *[_xss_ep(ep) for ep in param_urls[:_dalfox_count]],
                return_exceptions=True,
            )
            for res in xss_results:
                if isinstance(res, list):
                    all_findings.extend(res)
            _all_tools_run.append("dalfox")

        # -- SSRF Scanning (ssrfmap, V23 wiring) --
        ssrfmap_tool = tool_registry.get("ssrfmap")
        if ssrfmap_tool and ssrfmap_tool.is_available() and endpoints and "ssrfmap" not in _skipped_tools:
            # Prioritize GF-classified SSRF URLs, then URLs with SSRF-like params
            _gf_ssrf = _gf_classified.get("ssrf", []) if _gf_classified else []
            _ssrf_params = {"url", "uri", "path", "dest", "redirect", "src", "source",
                            "file", "document", "folder", "root", "pg", "view", "fetch",
                            "callback", "proxy", "forward", "next", "target", "link"}
            _ssrf_candidates = [
                ep for ep in endpoints
                if isinstance(ep, str) and "?" in ep
                and any(p in ep.lower() for p in _ssrf_params)
            ]
            ssrf_urls = list(dict.fromkeys(_gf_ssrf + _ssrf_candidates))[:15]
            if ssrf_urls:
                ssrf_sem = asyncio.Semaphore(2)

                async def _ssrf_ep(endpoint: str) -> list[dict]:
                    async with ssrf_sem:
                        try:
                            opts = _get_scan_options(state.profile, "scanners")
                            opts["timeout"] = min(opts.get("timeout", 120), 120)
                            if _auth_headers:
                                opts["headers"] = {**opts.get("headers", {}), **_auth_headers}
                            tool_result = await executor.execute(ssrfmap_tool, endpoint, opts)
                            if tool_result and tool_result.findings:
                                logger.info(f"SSRFMap {endpoint}: {len(tool_result.findings)} findings")
                                return [_finding_to_dict(
                                    f, "ssrfmap",
                                    fallback_url=endpoint,
                                    vuln_type_override="server_side_request_forgery",
                                ) for f in tool_result.findings]
                        except Exception as e:
                            logger.warning(f"SSRFMap {endpoint} failed: {e}")
                        return []

                ssrf_results = await asyncio.gather(
                    *[_ssrf_ep(u) for u in ssrf_urls],
                    return_exceptions=True,
                )
                for res in ssrf_results:
                    if isinstance(res, list):
                        all_findings.extend(res)
                _all_tools_run.append("ssrfmap")
                logger.info(f"SSRFMap completed: tested {len(ssrf_urls)} SSRF-candidate URLs")

        # -- CORS / Header Checks (parallel) --
        for tool_name in ["corsy"]:
            if tool_name in _skipped_tools:
                continue
            tool = tool_registry.get(tool_name)
            if not tool or not tool.is_available():
                continue
            cors_tool_sem = asyncio.Semaphore(3)

            async def _cors_host(host: str) -> list[dict]:
                async with cors_tool_sem:
                    try:
                        tool_result = await executor.execute(tool, host, {})
                        if tool_result and tool_result.findings:
                            return [_finding_to_dict(
                                f, tool_name,
                                fallback_url=host,
                                vuln_type_override="cors_misconfiguration",
                            ) for f in tool_result.findings]
                    except Exception as _exc:
                        logger.warning(f"full scan error: {_exc}")
                    return []

            cors_results = await asyncio.gather(
                *[_cors_host(h) for h in targets[:5]],
                return_exceptions=True,
            )
            for res in cors_results:
                if isinstance(res, list):
                    all_findings.extend(res)
            _all_tools_run.append(tool_name)

        # -- CRLFUZZ - CRLF Injection Testing (parallel) --
        crlfuzz_tool = tool_registry.get("crlfuzz")
        if crlfuzz_tool and crlfuzz_tool.is_available() and "crlfuzz" not in _skipped_tools:
            crlf_targets = [
                f"https://{h}" if not h.startswith("http") else h
                for h in targets[:5]
            ]
            crlf_sem = asyncio.Semaphore(3)

            async def _crlf_host(tgt_url: str) -> list[dict]:
                async with crlf_sem:
                    try:
                        tool_result = await executor.execute(crlfuzz_tool, tgt_url, {"timeout": 60})
                        if tool_result and tool_result.findings:
                            logger.info(f"CRLFUZZ {tgt_url}: {len(tool_result.findings)} findings")
                            return [_finding_to_dict(
                                f, "crlfuzz",
                                fallback_url=tgt_url,
                                vuln_type_override="crlf_injection",
                            ) for f in tool_result.findings]
                    except Exception as e:
                        logger.warning(f"CRLFUZZ {tgt_url} failed: {e}")
                    return []

            crlf_results = await asyncio.gather(
                *[_crlf_host(u) for u in crlf_targets],
                return_exceptions=True,
            )
            for res in crlf_results:
                if isinstance(res, list):
                    all_findings.extend(res)
            _all_tools_run.append("crlfuzz")

        # -- GF Router Supplementary Tool Dispatch (V25) --
        # Execute GF-routed tasks for tools NOT already explicitly invoked above.
        # Tools already handled: dalfox, sqlmap, ssrfmap, tplmap, commix, nuclei, corsy, crlfuzz, openredirex
        _GF_PIPELINE_HANDLED = {
            "dalfox", "sqlmap", "ssrfmap", "tplmap", "commix", "nuclei",
            "corsy", "crlfuzz", "openredirex",
        }
        if _gf_routed_tasks:
            _gf_sem = asyncio.Semaphore(2)
            for _gf_task in _gf_routed_tasks:
                _gf_tool_name = _gf_task.get("tool", "")
                if _gf_tool_name in _GF_PIPELINE_HANDLED or _gf_tool_name.startswith("custom:"):
                    continue
                if _gf_tool_name in _skipped_tools:
                    continue
                _gf_tool = tool_registry.get(_gf_tool_name)
                if not _gf_tool or not _gf_tool.is_available():
                    continue
                _gf_urls = _gf_task.get("urls", [])[:10]
                if not _gf_urls:
                    continue
                logger.info(f"🔀 GF-routed: dispatching {_gf_tool_name} on {len(_gf_urls)} {_gf_task.get('category', '')} URLs")

                async def _gf_dispatch(url: str, tool=_gf_tool, tname=_gf_tool_name) -> list[dict]:
                    async with _gf_sem:
                        try:
                            opts: dict[str, Any] = {"timeout": 120}
                            if _auth_headers:
                                opts["headers"] = {**opts.get("headers", {}), **_auth_headers}
                            res = await executor.execute(tool, url, opts)
                            if res and res.findings:
                                return [_finding_to_dict(f, tname, fallback_url=url) for f in res.findings]
                        except Exception as e:
                            logger.warning(f"GF-routed {tname} on {url[:80]} failed: {e}")
                        return []

                _gf_results = await asyncio.gather(
                    *[_gf_dispatch(u) for u in _gf_urls],
                    return_exceptions=True,
                )
                for _gf_r in _gf_results:
                    if isinstance(_gf_r, list):
                        all_findings.extend(_gf_r)
                _all_tools_run.append(_gf_tool_name)

        _sync_findings()  # Survive stage timeout — external tools done

        # -- HTTP Security Header Checks (custom, parallel) --
        try:
            from src.tools.scanners.custom_checks.header_checker import check_security_headers
            hdr_sem = asyncio.Semaphore(5)

            async def _hdr_check(host: str) -> list[dict]:
                async with hdr_sem:
                    target_url = f"https://{host}" if not host.startswith("http") else host
                    try:
                        header_findings = await check_security_headers(target_url, timeout=60, extra_headers=_auth_headers)
                        results = [_finding_to_dict(f, "header_checker") for f in header_findings]
                        if header_findings:
                            logger.info(f"Header check {target_url}: {len(header_findings)} findings")
                        return results
                    except Exception as e:
                        logger.warning(f"Header check {target_url} failed: {e}")
                    return []

            hdr_results = await asyncio.gather(
                *[_hdr_check(h) for h in _nuclei_targets],
                return_exceptions=True,
            )
            # Aggregate header findings by title — combine same header across hosts
            _header_by_title: dict[str, dict] = {}
            for res in hdr_results:
                if isinstance(res, list):
                    for f in res:
                        title = f.get("title", "")
                        if title in _header_by_title:
                            existing = _header_by_title[title]
                            url = f.get("url", f.get("endpoint", ""))
                            if url:
                                existing["evidence"] = (
                                    existing.get("evidence", "") + f"\n  - {url}"
                                )
                        else:
                            # Rewrite evidence to show "Affected hosts:" list format
                            url = f.get("url", f.get("endpoint", ""))
                            f["evidence"] = (
                                f.get("evidence", "")
                                + f"\n\nAffected hosts:\n  - {url}"
                            )
                            _header_by_title[title] = f
            aggregated_count = sum(
                len([r for r in res if isinstance(r, dict)])
                for res in hdr_results if isinstance(res, list)
            )
            if _header_by_title:
                all_findings.extend(_header_by_title.values())
                logger.info(
                    f"Header findings aggregated: {aggregated_count} → {len(_header_by_title)}"
                )
        except ImportError:
            logger.debug("Header checker module not available")


        # -- Technology CVE Checker --
        try:
            from src.tools.scanners.custom_checks.tech_cve_checker import (
                check_technology_cves,
                check_technology_cves_live,
            )
            active_sr_tech = state.stage_results.get("active_recon")
            if active_sr_tech and active_sr_tech.data:
                raw_techs = active_sr_tech.data.get("technologies", {})
                # Convert technologies dict {host: "tech_string"} to list of dicts
                tech_list = []
                if isinstance(raw_techs, dict):
                    for host, tech_str in raw_techs.items():
                        if isinstance(tech_str, str):
                            # Parse "nginx/1.25.1; WordPress, PHP/8.2, jQuery/3.6.0"
                            for part in _re.split(r'[;,]', tech_str):
                                part = part.strip()
                                if not part:
                                    continue
                                # Try to extract name/version: "nginx/1.25.1" or "PHP/8.2"
                                ver_match = _re.match(r'^(.+?)[/\s]+([\d.]+)', part)
                                if ver_match:
                                    tech_list.append({"name": ver_match.group(1).strip(), "version": ver_match.group(2), "host": host})
                                else:
                                    tech_list.append({"name": part, "version": "", "host": host})
                        elif isinstance(tech_str, dict):
                            tech_str["host"] = host
                            tech_list.append(tech_str)
                elif isinstance(raw_techs, list):
                    tech_list = raw_techs
                if tech_list:
                    # Use live NVD API if brain is available, otherwise static DB only
                    try:
                        cve_findings = await check_technology_cves_live(tech_list, state.target)
                    except Exception as _cve_live_exc:
                        logger.warning(f"NVD live query failed, using static DB: {_cve_live_exc}")
                        cve_findings = check_technology_cves(tech_list, state.target)
                    for f in cve_findings:
                        all_findings.append(_finding_to_dict(f, "tech_cve_checker"))
                    if cve_findings:
                        logger.info(f"Tech CVE checker: {len(cve_findings)} potential CVEs from {len(tech_list)} technologies")
        except ImportError:
            logger.debug("Tech CVE checker module not available")
        except Exception as e:
            logger.warning(f"Tech CVE checker error: {e}")

        # -- SPA Catch-All Detection (shared for sensitive_url_finder + rate_limit) --
        # Phase 0.3C: Check host profiles first — if the primary target was
        # already classified as SPA by HostProfiler, skip the expensive
        # aiohttp-based SPA probe entirely.
        _is_spa = False
        _spa_home_hash = ""
        _spa_from_hp = False
        _hp_dicts_spa = (state.metadata or {}).get("host_profiles") or {}
        if _hp_dicts_spa:
            _spa_target_url = (
                f"https://{state.target}"
                if not state.target.startswith("http")
                else state.target
            )
            for _hp_key, _hp_val in _hp_dicts_spa.items():
                if isinstance(_hp_val, dict) and (
                    _hp_key == _spa_target_url
                    or _hp_key.rstrip("/") == _spa_target_url.rstrip("/")
                    or state.target in _hp_key
                ):
                    if _hp_val.get("host_type") == "spa":
                        _is_spa = True
                        _spa_from_hp = True
                        logger.info(
                            f"🔍 SPA detected via host profiler for {state.target} "
                            "— skipping aiohttp SPA probe"
                        )
                    break

        if not _spa_from_hp:
            try:
                from src.utils.spa_detector import is_spa_catchall
                import aiohttp as _aiohttp_spa
                _spa_base = f"https://{state.target}" if not state.target.startswith("http") else state.target
                _spa_conn = _aiohttp_spa.TCPConnector(ssl=False, limit=5)
                async with _aiohttp_spa.ClientSession(connector=_spa_conn, timeout=_aiohttp_spa.ClientTimeout(total=12)) as _spa_sess:
                    _is_spa, _spa_home_hash = await is_spa_catchall(_spa_base, _spa_sess)
                if _is_spa:
                    logger.info(f"🔍 SPA catch-all detected for {state.target} — sensitive URL findings will be URL-pattern-only (no HTTP verify)")
            except Exception as e:
                logger.debug(f"SPA detection skipped: {e}")

        # Persist SPA detection result for FP engine and downstream consumers
        state.metadata["is_spa"] = _is_spa
        state.metadata["spa_home_hash"] = _spa_home_hash

        # -- Sensitive URL Pattern Analysis --
        try:
            from src.tools.scanners.custom_checks.sensitive_url_finder import find_sensitive_urls, verify_sensitive_urls
            # Gather all collected URLs from recon stages (ANSI-cleaned)
            all_urls = [_clean_url(ep) for ep in endpoints if ep]
            passive_sr = state.stage_results.get("passive_recon")
            if passive_sr and passive_sr.data:
                all_urls.extend(_clean_url(u) for u in passive_sr.data.get("urls", []) if u)
            active_sr = state.stage_results.get("active_recon")
            if active_sr and active_sr.data:
                all_urls.extend(_clean_url(u) for u in active_sr.data.get("crawled_urls", []) if u)
            all_urls = [u for u in all_urls if u]

            if all_urls:
                sensitive_findings = find_sensitive_urls(all_urls, state.target)
                if _is_spa:
                    # SPA catch-all: lower confidence & tag, HIGH→MEDIUM severity cap
                    _pre_count = len(sensitive_findings)
                    _filtered = []
                    for f in sensitive_findings:
                        # Keep only HIGH+ patterns that are structural (not path-based)
                        # .git, .env, etc. are worth checking even on SPA
                        _structural = any(
                            kw in (f.evidence or "").lower()
                            for kw in (".git", ".env", ".htpasswd", ".aws", "terraform", ".npmrc", ".pypirc")
                        )
                        if _structural:
                            f.confidence = max(f.confidence * 0.7, 20.0)
                            f.tags = list(f.tags or []) + ["spa_catchall_unverified"]
                            _filtered.append(f)
                        else:
                            # Non-structural on SPA → suppress (very likely FP)
                            pass
                    sensitive_findings = _filtered
                    _suppressed = _pre_count - len(sensitive_findings)
                    if _suppressed:
                        logger.info(f"SPA filter: suppressed {_suppressed}/{_pre_count} sensitive URL findings")
                # V26: HTTP-verify regex-matched candidates to eliminate FPs
                if sensitive_findings:
                    try:
                        sensitive_findings = await verify_sensitive_urls(sensitive_findings, timeout=10.0, concurrency=5)
                    except Exception as _verify_err:
                        logger.warning(f"Sensitive URL HTTP verification failed, using unverified: {_verify_err}")
                for f in sensitive_findings:
                    all_findings.append(_finding_to_dict(f, "sensitive_url_finder"))
                if sensitive_findings:
                    logger.info(f"Sensitive URL finder: {len(sensitive_findings)} findings from {len(all_urls)} URLs")
        except ImportError:
            logger.debug("Sensitive URL finder module not available")
        except Exception as e:
            logger.warning(f"Sensitive URL finder error: {e}")

        # -- JavaScript Endpoint & Secret Analyzer --
        try:
            from src.tools.scanners.custom_checks.js_analyzer import analyze_javascript_files
            # Gather all URLs to find JS files
            all_urls_for_js = list(endpoints)
            passive_sr_js = state.stage_results.get("passive_recon")
            if passive_sr_js and passive_sr_js.data:
                all_urls_for_js.extend(passive_sr_js.data.get("urls", []))
            active_sr_js = state.stage_results.get("active_recon")
            if active_sr_js and active_sr_js.data:
                all_urls_for_js.extend(active_sr_js.data.get("crawled_urls", []))

            if all_urls_for_js:
                js_findings, js_endpoints = await analyze_javascript_files(
                    all_urls_for_js, max_concurrent=5, max_files=20, timeout=60.0
                )
                for f in js_findings:
                    all_findings.append(_finding_to_dict(f, "js_analyzer"))
                # Add discovered endpoints back to state
                for ep in js_endpoints:
                    url = ep.get("url", "")
                    if url and url not in endpoints:
                        endpoints.append(url)
                if js_findings:
                    logger.info(f"JS analyzer: {len(js_findings)} findings, {len(js_endpoints)} new endpoints")
        except ImportError:
            logger.debug("JS analyzer module not available")
        except Exception as e:
            logger.warning(f"JS analyzer error: {e}")

        # -- Source Map Extraction (V8-T0-5) --
        try:
            from src.tools.recon.web_discovery.sourcemap_extractor import SourceMapExtractor as _SMExtractor
            _sm = _SMExtractor()
            if _sm.is_available():
                # Collect JS URLs from endpoints
                _js_urls = [u for u in endpoints if u.endswith((".js", ".mjs"))][:20]
                if _js_urls:
                    _sm_result = await _sm.run(
                        state.target, {"js_urls": _js_urls, "max_download_mb": 5}
                    )
                    if _sm_result and _sm_result.findings:
                        for _sf in _sm_result.findings:
                            all_findings.append(_finding_to_dict(_sf, "sourcemap_extractor"))
                        # Extract any new endpoints discovered in source maps
                        _sm_meta = _sm_result.metadata or {}
                        for _sm_ep in _sm_meta.get("endpoints", []):
                            if _sm_ep and _sm_ep not in endpoints:
                                endpoints.append(_sm_ep)
                        logger.info(
                            f"Source map extractor: {len(_sm_result.findings)} findings"
                        )
        except ImportError:
            logger.debug("Source map extractor module not available")
        except Exception as e:
            logger.warning(f"Source map extractor error: {e}")

        # ── Tech-Aware Tool Selection ──
        # Detect technology stack and run specialized tools accordingly
        _host_urls = [f"https://{h}" for h in (state.live_hosts or [])[:5]]

        # ── Filter auth-gated hosts from checker targets ──
        _host_profiles = (state.metadata or {}).get("host_profiles", {})
        if _host_profiles and not _auth_headers:
            from urllib.parse import urlparse as _ag_urlparse
            _host_urls_filtered = []
            for _u in _host_urls:
                _h = (_ag_urlparse(_u).hostname or "")
                if not _host_profiles.get(_h, {}).get("auth_gated", False):
                    _host_urls_filtered.append(_u)
            if _host_urls_filtered:
                _host_urls = _host_urls_filtered
            else:
                logger.warning("All hosts auth-gated; falling back to full list")
        _detected_techs = set()
        for _tv in state.technologies.values():
            if isinstance(_tv, list):
                for t in _tv:
                    _detected_techs.add(str(t).lower())
            elif isinstance(_tv, str):
                _detected_techs.add(_tv.lower())
        _tech_str = " ".join(_detected_techs)

        # WPScan for WordPress targets (skip if already run in CMS block)
        if not _wpscan_done and any(kw in _tech_str for kw in ("wordpress", "wp-", "woocommerce")):
            wpscan_tool = tool_registry.get("wpscan")
            if wpscan_tool and wpscan_tool.is_available():
                try:
                    logger.info("🎯 Tech-aware: WordPress detected → running WPScan")
                    for tgt in targets[:2]:
                        tgt_url = f"https://{tgt}" if not tgt.startswith("http") else tgt
                        wp_result = await executor.execute(wpscan_tool, tgt_url, {"timeout": 300})
                        if wp_result and wp_result.findings:
                            all_findings.extend(
                                [_finding_to_dict(f, "wpscan", fallback_url=tgt_url) for f in wp_result.findings]
                            )
                            logger.info(f"WPScan: {len(wp_result.findings)} findings on {tgt_url}")
                except Exception as e:
                    logger.warning(f"WPScan failed: {e}")

        # Prototype Pollution for Node.js / Express / React targets
        if any(kw in _tech_str for kw in ("node", "express", "react", "next.js", "angular", "vue")):
            try:
                from src.tools.scanners.custom_checks.prototype_pollution_checker import PrototypePollutionChecker
                logger.info("🎯 Tech-aware: Node.js/JS framework detected → running Prototype Pollution checker")
                pp_checker = PrototypePollutionChecker()
                for host_url in _host_urls[:3]:
                    try:
                        pp_result = await asyncio.wait_for(
                            pp_checker.run(host_url, {}), timeout=1200.0
                        )
                        if pp_result and pp_result.findings:
                            all_findings.extend(
                                [_finding_to_dict(f, "prototype_pollution_checker") for f in pp_result.findings]
                            )
                    except (asyncio.TimeoutError, Exception) as e:
                        logger.debug(f"Prototype pollution checker {host_url}: {e}")
            except ImportError:
                logger.debug("Prototype pollution checker not available")

        # SSTI for Python/Jinja2/Flask/Django targets
        if any(kw in _tech_str for kw in ("python", "flask", "django", "jinja", "tornado", "fastapi")):
            tplmap_tool = tool_registry.get("tplmap")
            if tplmap_tool and tplmap_tool.is_available() and deduped_params and "tplmap" not in _skipped_tools:
                try:
                    logger.info("🎯 Tech-aware: Python framework detected → running tplmap SSTI check")
                    # Prioritize GF-classified SSTI URLs
                    _gf_ssti = _gf_classified.get("ssti", []) if _gf_classified else []
                    _ssti_targets = list(dict.fromkeys(_gf_ssti + deduped_params))[:5]
                    for ep in _ssti_targets:
                        tpl_result = await executor.execute(tplmap_tool, ep, {"timeout": 120})
                        if tpl_result and tpl_result.findings:
                            all_findings.extend(
                                [_finding_to_dict(f, "tplmap", fallback_url=ep) for f in tpl_result.findings]
                            )
                except Exception as e:
                    logger.warning(f"tplmap failed: {e}")

        # SSTI for PHP targets (Twig, Blade, Smarty)
        if any(kw in _tech_str for kw in ("php", "laravel", "symfony", "codeigniter", "twig")):
            tplmap_tool = tool_registry.get("tplmap")
            if tplmap_tool and tplmap_tool.is_available() and deduped_params and "tplmap" not in _skipped_tools:
                try:
                    logger.info("🎯 Tech-aware: PHP framework detected → running tplmap SSTI check")
                    _gf_ssti_php = _gf_classified.get("ssti", []) if _gf_classified else []
                    _ssti_php_targets = list(dict.fromkeys(_gf_ssti_php + deduped_params))[:5]
                    for ep in _ssti_php_targets:
                        tpl_result = await executor.execute(tplmap_tool, ep, {"timeout": 120})
                        if tpl_result and tpl_result.findings:
                            all_findings.extend(
                                [_finding_to_dict(f, "tplmap", fallback_url=ep) for f in tpl_result.findings]
                            )
                except Exception as e:
                    logger.warning(f"tplmap PHP check failed: {e}")

        # JWT tool for targets with JWT/Bearer auth
        if any(kw in _tech_str for kw in ("jwt", "bearer", "oauth", "auth0")):
            jwt_tool_inst = tool_registry.get("jwt_tool")
            if jwt_tool_inst and jwt_tool_inst.is_available():
                try:
                    logger.info("🎯 Tech-aware: JWT/OAuth detected → running jwt_tool")
                    for tgt in targets[:2]:
                        jwt_result = await executor.execute(jwt_tool_inst, tgt, {"timeout": 90})
                        if jwt_result and jwt_result.findings:
                            all_findings.extend(
                                [_finding_to_dict(f, "jwt_tool") for f in jwt_result.findings]
                            )
                except Exception as e:
                    logger.warning(f"jwt_tool failed: {e}")

        _sync_findings()  # Survive stage timeout — tech-aware tools done
        logger.info(f"🎯 Tech-aware scan complete | detected: {list(_detected_techs)[:10]}")

        # -- Discard ANSI-contaminated URLs (crawlers sometimes inject them) --
        def _clean_url_ansi(u: str) -> str:
            if '\x1b' in u:
                return ''
            return u.strip()

        # -- Parallel Custom Checkers Block --
        # These 6 checkers are independent and can run concurrently
        _host_urls = [f"https://{h}" for h in (state.live_hosts or [])[:5]]
        # Filter auth-gated hosts from checker targets (reuse profiles from preflight)
        if _host_profiles and not _auth_headers:
            from urllib.parse import urlparse as _hu_urlparse
            _hu_filtered = [
                _u for _u in _host_urls
                if not _host_profiles.get(_hu_urlparse(_u).hostname or "", {}).get("auth_gated", False)
            ]
            if _hu_filtered:
                _host_urls = _hu_filtered
        _endpoints_snapshot = [_clean_url_ansi(ep) for ep in endpoints if _clean_url_ansi(ep)]

        async def _run_http_methods() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.http_method_checker import check_http_methods
                if not _host_urls:
                    return []
                findings = await check_http_methods(_host_urls, max_concurrent=3, timeout=60.0)
                result = [_finding_to_dict(f, "http_method_checker") for f in findings]
                if result:
                    logger.info(f"HTTP method checker: {len(result)} findings")
                return result
            except ImportError:
                logger.debug("HTTP method checker module not available")
            except Exception as e:
                logger.warning(f"HTTP method checker error: {e}")
            return []

        async def _run_open_redirect() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.open_redirect_checker import check_open_redirects
                # Prioritize GF-classified redirect URLs first
                _gf_redirect = _gf_classified.get("redirect", []) if _gf_classified else []
                redirect_urls = list(dict.fromkeys(_gf_redirect + _endpoints_snapshot[:30]))[:30]
                if not redirect_urls:
                    return []
                findings = await check_open_redirects(redirect_urls, max_urls=20, max_concurrent=3, timeout=60.0)
                result = [_finding_to_dict(f, "open_redirect_checker") for f in findings]
                if result:
                    logger.info(f"Open redirect checker: {len(result)} findings")
                return result
            except ImportError:
                logger.debug("Open redirect checker module not available")
            except Exception as e:
                logger.warning(f"Open redirect checker error: {e}")
            return []

        async def _run_info_disclosure() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.info_disclosure_checker import check_info_disclosure
                if not _host_urls:
                    return []
                findings = await check_info_disclosure(_host_urls, max_hosts=5, max_concurrent=5, timeout=60.0)
                result = [_finding_to_dict(f, "info_disclosure_checker") for f in findings]
                if result:
                    logger.info(f"Info disclosure checker: {len(result)} findings")
                return result
            except ImportError:
                logger.debug("Info disclosure checker module not available")
            except Exception as e:
                logger.warning(f"Info disclosure checker error: {e}")
            return []

        async def _run_cookie_checker() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.cookie_checker import check_cookie_security
                if not _host_urls:
                    return []
                findings = await check_cookie_security(_host_urls, max_hosts=5, max_concurrent=3, timeout=60.0)
                result = [_finding_to_dict(f, "cookie_checker") for f in findings]
                if result:
                    logger.info(f"Cookie checker: {len(result)} findings")
                return result
            except ImportError:
                logger.debug("Cookie checker module not available")
            except Exception as e:
                logger.warning(f"Cookie checker error: {e}")
            return []

        async def _run_api_tester() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.api_endpoint_tester import test_api_endpoints
                if not _host_urls:
                    return []
                findings = await test_api_endpoints(_host_urls, max_paths=25, max_concurrent=5, timeout=60.0)
                result = [_finding_to_dict(f, "api_endpoint_tester") for f in findings]
                if result:
                    logger.info(f"API endpoint tester: {len(result)} findings from {len(_host_urls)} hosts")
                else:
                    logger.info(f"API endpoint tester: 0 findings from {len(_host_urls)} hosts")
                return result
            except ImportError:
                logger.debug("API endpoint tester module not available")
            except Exception as e:
                logger.warning(f"API endpoint tester error: {e}")
            return []

        async def _run_cors_checker() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.cors_checker import check_cors_misconfigurations
                cors_targets = list(_host_urls)
                api_eps = [ep for ep in _endpoints_snapshot if "/api" in ep or "/v1" in ep or "/v2" in ep or "/v3" in ep]
                cors_targets.extend(api_eps[:10])
                cors_targets = list(dict.fromkeys(cors_targets))[:15]
                if not cors_targets:
                    return []
                findings = await check_cors_misconfigurations(cors_targets, max_concurrent=3, timeout=60.0)
                result = [_finding_to_dict(f, "cors_checker") for f in findings]
                if result:
                    logger.info(f"CORS checker: {len(result)} findings from {len(cors_targets)} targets")
                else:
                    logger.info(f"CORS checker: 0 findings from {len(cors_targets)} targets")
                return result
            except ImportError:
                logger.debug("CORS checker module not available")
            except Exception as e:
                logger.warning(f"CORS checker error: {e}")
            return []

        # ── Class-based security checkers (auth_bypass, rate_limit, business_logic) ──
        async def _run_auth_bypass() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
                if not _host_urls:
                    return []
                checker = AuthBypassChecker()
                results: list[dict] = []
                for host_url in _host_urls[:3]:
                    try:
                        tool_result = await asyncio.wait_for(
                            checker.run(host_url, {"timeout": 10, "concurrency": 2}),
                            timeout=1200.0,
                        )
                        if tool_result and tool_result.findings:
                            results.extend(
                                _finding_to_dict(f, "auth_bypass_checker") for f in tool_result.findings
                            )
                    except asyncio.TimeoutError:
                        logger.debug(f"Auth bypass checker timeout for {host_url}")
                    except Exception as e:
                        logger.debug(f"Auth bypass checker error for {host_url}: {e}")
                if results:
                    logger.info(f"Auth bypass checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("Auth bypass checker module not available")
            except Exception as e:
                logger.warning(f"Auth bypass checker error: {e}")
            return []

        async def _run_rate_limit() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.rate_limit_checker import RateLimitChecker
                if not _host_urls:
                    return []
                checker = RateLimitChecker()
                # Only test first 2 hosts to avoid excessive requests
                results: list[dict] = []
                for host_url in _host_urls[:2]:
                    try:
                        # ── BUG-9 FIX: Verify endpoints exist before rate-limit testing ──
                        # SPA catch-all targets return 200 for ANY path → false "no rate limit" findings
                        import aiohttp as _rl_aiohttp
                        _rl_conn = _rl_aiohttp.TCPConnector(ssl=False, limit=5)
                        _rl_to = _rl_aiohttp.ClientTimeout(total=8)
                        _validated_eps = []
                        _default_eps = [
                            {"url": f"{host_url.rstrip('/')}/login", "method": "POST", "description": "Login endpoint"},
                            {"url": f"{host_url.rstrip('/')}/api/v1/login", "method": "POST", "description": "API login"},
                            {"url": f"{host_url.rstrip('/')}/forgot-password", "method": "POST", "description": "Password reset"},
                        ]
                        async with _rl_aiohttp.ClientSession(connector=_rl_conn, timeout=_rl_to) as _rl_sess:
                            for ep in _default_eps:
                                try:
                                    async with _rl_sess.get(ep["url"], allow_redirects=True) as _rl_resp:
                                        _rl_body = await _rl_resp.text(errors="replace")
                                        _rl_ct = _rl_resp.headers.get("Content-Type", "").lower()
                                        # Valid login endpoint indicators:
                                        _has_form = any(kw in _rl_body.lower() for kw in (
                                            "password", "type=\"password", "type='password",
                                            "login", "sign in", "signin", "log in",
                                            "csrf", "_token", "authenticity_token",
                                        ))
                                        _is_api = "json" in _rl_ct
                                        _is_404 = _rl_resp.status in (404, 410)
                                        if _is_404:
                                            continue
                                        if _has_form or _is_api or _rl_resp.status == 405:
                                            _validated_eps.append(ep)
                                except Exception as _exc:
                                    logger.warning(f"full scan error: {_exc}")
                                    continue

                        if not _validated_eps:
                            logger.debug(f"Rate limit checker: no valid login endpoints found at {host_url}")
                            continue

                        tool_result = await asyncio.wait_for(
                            checker.run(host_url, {
                                "request_count": 30,
                                "timeout": 15,
                                "endpoints": _validated_eps,
                            }),
                            timeout=1200.0,
                        )
                        if tool_result and tool_result.findings:
                            results.extend(
                                _finding_to_dict(f, "rate_limit_checker") for f in tool_result.findings
                            )
                    except asyncio.TimeoutError:
                        logger.debug(f"Rate limit checker timeout for {host_url}")
                    except Exception as e:
                        logger.debug(f"Rate limit checker error for {host_url}: {e}")
                if results:
                    logger.info(f"Rate limit checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("Rate limit checker module not available")
            except Exception as e:
                logger.warning(f"Rate limit checker error: {e}")
            return []

        async def _run_business_logic() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.business_logic import BusinessLogicChecker
                if not _host_urls:
                    return []
                checker = BusinessLogicChecker()
                results: list[dict] = []

                # ── Build rich test definitions from discovered endpoints ──
                _biz_patterns_price = ("cart", "order", "checkout", "payment", "pay",
                                       "purchase", "billing", "invoice", "price", "amount",
                                       "total", "shipping", "subscribe")
                _biz_patterns_quantity = ("cart", "order", "quantity", "stock", "inventory",
                                          "item", "product", "add-to-cart")
                _biz_patterns_workflow = ("checkout", "payment", "order", "confirm",
                                          "finalize", "submit", "process", "complete")
                _biz_patterns_privilege = ("admin", "user", "profile", "settings", "role",
                                           "permission", "account", "manage", "dashboard")

                _price_eps = [ep for ep in endpoints if any(p in ep.lower() for p in _biz_patterns_price)][:8]
                _quantity_eps = [ep for ep in endpoints if any(p in ep.lower() for p in _biz_patterns_quantity)][:5]
                _workflow_eps = [ep for ep in endpoints if any(p in ep.lower() for p in _biz_patterns_workflow)][:5]
                _privilege_eps = [ep for ep in endpoints if any(p in ep.lower() for p in _biz_patterns_privilege)][:5]

                # V6-T0-4: Use LLM-generated test definitions from attack surface
                _dynamic_biz_cases = attack_surface_data.get("dynamic_business_logic_test_cases", [])

                # Build multi-type test definitions
                test_defs: list[dict] = list(_dynamic_biz_cases[:10])

                # Price manipulation tests
                for ep in _price_eps:
                    for field_name in ("price", "amount", "total", "cost"):
                        test_defs.append({
                            "type": "price", "url": ep, "method": "POST",
                            "body": {}, "field": field_name,
                        })

                # Quantity manipulation tests
                for ep in _quantity_eps:
                    test_defs.append({
                        "type": "quantity", "url": ep, "method": "POST",
                        "body": {}, "field": "quantity",
                    })

                # Workflow bypass tests (skip steps in multi-step flows)
                if len(_workflow_eps) >= 2:
                    test_defs.append({
                        "type": "workflow",
                        "steps": [{"url": ep, "method": "POST", "body": {}}
                                  for ep in _workflow_eps[:4]],
                    })

                # Privilege escalation tests
                for ep in _privilege_eps:
                    test_defs.append({
                        "type": "privilege", "url": ep, "method": "POST", "body": {},
                    })

                for host_url in _host_urls[:2]:
                    try:
                        opts: dict = {"timeout": 10}
                        if test_defs:
                            opts["test_definitions"] = test_defs
                        tool_result = await asyncio.wait_for(
                            checker.run(host_url, opts),
                            timeout=1200.0,
                        )
                        if tool_result and tool_result.findings:
                            results.extend(
                                _finding_to_dict(f, "business_logic_checker") for f in tool_result.findings
                            )
                    except asyncio.TimeoutError:
                        logger.debug(f"Business logic checker timeout for {host_url}")
                    except Exception as e:
                        logger.debug(f"Business logic checker error for {host_url}: {e}")
                if results:
                    logger.info(f"Business logic checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("Business logic checker module not available")
            except Exception as e:
                logger.warning(f"Business logic checker error: {e}")
            return []

        async def _run_deserialization() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.deserialization_checker import DeserializationChecker
                if not _host_urls:
                    return []
                checker = DeserializationChecker()
                results: list[dict] = []
                # Pass detected technologies for targeted testing
                tech_list = []
                for techs in state.technologies.values():
                    if isinstance(techs, list):
                        tech_list.extend(techs)
                    elif isinstance(techs, str):
                        tech_list.append(techs)
                for host_url in _host_urls[:3]:
                    try:
                        tool_result = await asyncio.wait_for(
                            checker.run(host_url, {
                                "endpoints": state.endpoints[:20],
                                "technologies": tech_list,
                                "timeout": 15,
                            }),
                            timeout=1200.0,
                        )
                        if tool_result and tool_result.findings:
                            results.extend(
                                _finding_to_dict(f, "deserialization_checker") for f in tool_result.findings
                            )
                    except asyncio.TimeoutError:
                        logger.debug(f"Deserialization checker timeout for {host_url}")
                    except Exception as e:
                        logger.debug(f"Deserialization checker error for {host_url}: {e}")
                if results:
                    logger.info(f"Deserialization checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("Deserialization checker module not available")
            except Exception as e:
                logger.warning(f"Deserialization checker error: {e}")
            return []

        async def _run_bfla_bola() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.bfla_bola_checker import BFLABOLAChecker
                if not _host_urls:
                    return []
                checker = BFLABOLAChecker()
                results: list[dict] = []
                for host_url in _host_urls[:3]:
                    try:
                        tool_result = await asyncio.wait_for(
                            checker.run(host_url, {
                                "endpoints": state.endpoints[:30],
                                "timeout": 15,
                                "auth_headers_regular": _auth_headers,
                            }),
                            timeout=1200.0,
                        )
                        if tool_result and tool_result.findings:
                            results.extend(
                                _finding_to_dict(f, "bfla_bola_checker") for f in tool_result.findings
                            )
                    except asyncio.TimeoutError:
                        logger.debug(f"BFLA/BOLA checker timeout for {host_url}")
                    except Exception as e:
                        logger.debug(f"BFLA/BOLA checker error for {host_url}: {e}")
                if results:
                    logger.info(f"BFLA/BOLA checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("BFLA/BOLA checker module not available")
            except Exception as e:
                logger.warning(f"BFLA/BOLA checker error: {e}")
            return []

        async def _run_mass_assignment() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.mass_assignment_checker import MassAssignmentChecker
                if not _host_urls:
                    return []
                checker = MassAssignmentChecker()
                results: list[dict] = []
                for host_url in _host_urls[:2]:
                    try:
                        tool_result = await asyncio.wait_for(
                            checker.run(host_url, {
                                "endpoints": state.endpoints[:20],
                                "timeout": 15,
                            }),
                            timeout=1200.0,
                        )
                        if tool_result and tool_result.findings:
                            results.extend(
                                _finding_to_dict(f, "mass_assignment_checker") for f in tool_result.findings
                            )
                    except asyncio.TimeoutError:
                        logger.debug(f"Mass assignment checker timeout for {host_url}")
                    except Exception as e:
                        logger.debug(f"Mass assignment checker error for {host_url}: {e}")
                if results:
                    logger.info(f"Mass assignment checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("Mass assignment checker module not available")
            except Exception as e:
                logger.warning(f"Mass assignment checker error: {e}")
            return []

        async def _run_idor() -> list[dict]:
            if not _auth_headers:
                return []  # IDOR needs at least one auth context
            try:
                from src.tools.scanners.custom_checks.idor_checker import IDORChecker
                checker = IDORChecker()
                results: list[dict] = []

                # V6-T0-4: Use LLM-generated test cases from attack surface
                _dynamic_idor_cases = attack_surface_data.get("dynamic_idor_test_cases", [])

                # Multi-role support: prefer first-class field, fallback to metadata
                _auth_roles_raw = (
                    state.auth_roles
                    or (state.metadata or {}).get("auth_roles", [])
                )

                for host_url in _host_urls[:2]:
                    try:
                        opts: dict = {
                            "auth_headers_a": _auth_headers,
                            "auth_headers_b": {},  # Unauthenticated comparison
                            "timeout": 15,
                        }
                        # If multi-role config is available, use pairwise testing
                        if _auth_roles_raw:
                            opts["auth_roles"] = _auth_roles_raw
                        # Inject dynamic test cases if available
                        if _dynamic_idor_cases:
                            opts["test_cases"] = _dynamic_idor_cases[:15]
                            opts["endpoints"] = state.endpoints[:50]
                        else:
                            opts["endpoints"] = state.endpoints[:50]
                        tool_result = await asyncio.wait_for(
                            checker.run(host_url, opts),
                            timeout=1200.0,
                        )
                        if tool_result and tool_result.findings:
                            results.extend(
                                _finding_to_dict(f, "idor_checker") for f in tool_result.findings
                            )
                    except (asyncio.TimeoutError, Exception) as e:
                        logger.warning(f"IDOR checker {host_url}: {e}")
                if results:
                    logger.info(f"IDOR checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("IDOR checker module not available")
            except Exception as e:
                logger.warning(f"IDOR checker error: {e}")
            return []

        async def _run_race_condition() -> list[dict]:
            """Race condition checker — TOCTOU via concurrent request flooding."""
            try:
                from src.tools.scanners.custom_checks.race_condition import RaceConditionChecker
                if not _host_urls:
                    return []
                checker = RaceConditionChecker()
                results: list[dict] = []
                _dynamic_rc_cases = attack_surface_data.get("dynamic_race_condition_test_cases", [])
                if not _dynamic_rc_cases:
                    # Heuristic fallback: common race-condition-vulnerable endpoint patterns
                    _rc_patterns = (
                        "/checkout", "/purchase", "/redeem", "/coupon", "/apply",
                        "/transfer", "/withdraw", "/vote", "/like", "/follow",
                        "/invite", "/claim", "/register", "/signup",
                    )
                    _rc_fallback = []
                    for ep in (state.endpoints or [])[:200]:
                        ep_lower = ep.lower() if isinstance(ep, str) else ""
                        if any(p in ep_lower for p in _rc_patterns):
                            _rc_fallback.append({
                                "endpoint": ep,
                                "method": "POST",
                                "description": f"Heuristic race condition target: {ep}",
                            })
                    if _rc_fallback:
                        _dynamic_rc_cases = _rc_fallback[:10]
                        logger.info(
                            f"Race condition: no LLM cases, using {len(_dynamic_rc_cases)} heuristic endpoints"
                        )
                    else:
                        logger.warning(
                            "Race condition checker: no dynamic test cases and no heuristic endpoints — skipping"
                        )
                        return []
                for host_url in _host_urls[:2]:
                    try:
                        opts: dict[str, Any] = {
                            "test_cases": _dynamic_rc_cases[:10],
                            "concurrency": 10,
                            "rounds": 3,
                            "timeout": 15,
                        }
                        tool_result = await asyncio.wait_for(
                            checker.run(host_url, opts),
                            timeout=1200.0,
                        )
                        if tool_result and tool_result.findings:
                            results.extend(
                                _finding_to_dict(f, "race_condition_checker") for f in tool_result.findings
                            )
                    except (asyncio.TimeoutError, Exception) as e:
                        logger.warning(f"Race condition checker {host_url}: {e}")
                if results:
                    logger.info(f"Race condition checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("Race condition checker module not available")
            except Exception as e:
                logger.warning(f"Race condition checker error: {e}")
            return []

        async def _run_cache_poisoning() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.cache_poisoning_checker import check_cache_poisoning
                target_urls = _host_urls[:5] + [
                    ep for ep in state.endpoints[:15]
                    if ep.startswith("http")
                ]
                if not target_urls:
                    return []
                results_raw = await asyncio.wait_for(
                    check_cache_poisoning(
                        target_urls=target_urls[:10],
                        max_concurrent=3,
                        timeout=1200.0,
                        oob_domain=_oob_domain,
                        extra_headers=_auth_headers or None,
                    ),
                    timeout=1200.0,
                )
                results = [_finding_to_dict(f, "cache_poisoning_checker") for f in results_raw]
                if results:
                    logger.info(f"Cache poisoning checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("Cache poisoning checker module not available")
            except asyncio.TimeoutError:
                logger.warning("Cache poisoning checker timed out")
            except Exception as e:
                logger.warning(f"Cache poisoning checker error: {e}")
            return []

        async def _run_websocket() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.websocket_checker import check_websocket_security
                target_urls = _host_urls[:5]
                if not target_urls:
                    return []
                # v5.0: Only run if websocket signals detected
                _ws_signal = any(
                    kw in ep.lower()
                    for ep in (state.endpoints or [])
                    for kw in ("ws://", "wss://", "/ws", "/socket", "/websocket", "/realtime", "/cable", "/hub")
                ) or any(
                    "websocket" in t.lower()
                    for t in (getattr(state, "technologies", None) or [])
                )
                if not _ws_signal:
                    logger.debug("WebSocket checker skipped — no websocket endpoint/tech detected")
                    return []
                results_raw = await asyncio.wait_for(
                    check_websocket_security(
                        target_urls=target_urls,
                        max_concurrent=3,
                        timeout=1200.0,
                        extra_headers=_auth_headers or None,
                    ),
                    timeout=1200.0,
                )
                results = [_finding_to_dict(f, "websocket_checker") for f in results_raw]
                if results:
                    logger.info(f"WebSocket checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("WebSocket checker module not available")
            except asyncio.TimeoutError:
                logger.warning("WebSocket checker timed out")
            except Exception as e:
                logger.warning(f"WebSocket checker error: {e}")
            return []

        async def _run_cloud_misconfig() -> list[dict]:
            try:
                from src.tools.scanners.custom_checks.cloud_misconfig_checker import check_cloud_misconfig
                target_url = _host_urls[0] if _host_urls else f"https://{state.target}"
                # Collect response bodies from earlier recon if available
                response_bodies: list[tuple[str, str]] = []
                for f in all_findings[:30]:
                    body = f.get("http_response", "")
                    url = f.get("url", "")
                    if body and url:
                        response_bodies.append((url, body))
                results_raw = await asyncio.wait_for(
                    check_cloud_misconfig(
                        target=target_url,
                        endpoints=state.endpoints[:20],
                        response_bodies=response_bodies[:20],
                        timeout=1200.0,
                    ),
                    timeout=1200.0,
                )
                results = [_finding_to_dict(f, "cloud_misconfig_checker") for f in results_raw]
                if results:
                    logger.info(f"Cloud misconfig checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("Cloud misconfig checker module not available")
            except asyncio.TimeoutError:
                logger.warning("Cloud misconfig checker timed out")
            except Exception as e:
                logger.warning(f"Cloud misconfig checker error: {e}")
            return []

        async def _run_jwt_checker() -> list[dict]:
            """JWT Deep Security Checker — alg:none, weak secret, kid injection, claim tampering."""
            try:
                from src.tools.scanners.custom_checks.jwt_checker import check_jwt_security
                # Look for JWT tokens in auth headers
                jwt_token = ""
                for hv in (_auth_headers or {}).values():
                    v = str(hv).strip()
                    if v.startswith("Bearer "):
                        v = v[7:]
                    # Crude JWT detection — 3 dot-separated base64 parts
                    parts = v.split(".")
                    if len(parts) == 3 and all(len(p) > 5 for p in parts):
                        jwt_token = v
                        break
                if not jwt_token:
                    return []
                target_url = _host_urls[0] if _host_urls else f"https://{state.target}"
                results_raw = await asyncio.wait_for(
                    check_jwt_security(
                        endpoint=target_url,
                        jwt_token=jwt_token,
                        timeout=1200.0,
                    ),
                    timeout=1200.0,
                )
                results = [_finding_to_dict(f, "jwt_checker") for f in results_raw]
                if results:
                    logger.info(f"JWT checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("JWT checker module not available")
            except asyncio.TimeoutError:
                logger.warning("JWT checker timed out")
            except Exception as e:
                logger.warning(f"JWT checker error: {e}")
            return []

        async def _run_fourxx_bypass() -> list[dict]:
            """403/401 Bypass Engine — path mutations, header bypass, method override."""
            try:
                from src.tools.scanners.custom_checks.fourxx_bypass import FourXXBypassChecker
                # Collect endpoints that returned 403/401 from earlier findings
                fourxx_eps: list[str] = []
                for f in all_findings:
                    status = str(f.get("http_status", "") or f.get("evidence", ""))
                    url = f.get("url", "")
                    if url and ("403" in status or "401" in status):
                        fourxx_eps.append(url)
                # Also check GF-classified "interesting" endpoints
                for ep in (state.endpoints or [])[:30]:
                    if ep not in fourxx_eps:
                        fourxx_eps.append(ep)
                fourxx_eps = fourxx_eps[:20]  # limit
                if not fourxx_eps:
                    return []
                checker = FourXXBypassChecker()
                target_url = _host_urls[0] if _host_urls else f"https://{state.target}"
                tool_result = await asyncio.wait_for(
                    checker.run(target=target_url, options={"endpoints": fourxx_eps}),
                    timeout=1200.0,
                )
                if tool_result and tool_result.findings:
                    results = [_finding_to_dict(f, "fourxx_bypass") for f in tool_result.findings]
                    if results:
                        logger.info(f"403/401 bypass: {len(results)} findings")
                    return results
                return []
            except ImportError:
                logger.debug("403/401 bypass module not available")
            except asyncio.TimeoutError:
                logger.warning("403/401 bypass checker timed out")
            except Exception as e:
                logger.warning(f"403/401 bypass error: {e}")
            return []

        async def _run_http_smuggling() -> list[dict]:
            """HTTP Request Smuggling Prober — CL.TE, TE.CL, TE.TE, H2C, etc."""
            try:
                from src.tools.scanners.custom_checks.http_smuggling_prober import check_http_smuggling
                target_urls = _host_urls[:5]
                if not target_urls:
                    return []
                results_raw = await asyncio.wait_for(
                    check_http_smuggling(
                        target_urls=target_urls,
                        max_concurrent=2,
                        timeout=1200.0,
                    ),
                    timeout=1200.0,
                )
                results = [_finding_to_dict(f, "http_smuggling_prober") for f in results_raw]
                if results:
                    logger.info(f"HTTP smuggling prober: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("HTTP smuggling prober module not available")
            except asyncio.TimeoutError:
                logger.warning("HTTP smuggling prober timed out")
            except Exception as e:
                logger.warning(f"HTTP smuggling prober error: {e}")
            return []

        async def _run_graphql_deep() -> list[dict]:
            """GraphQL Deep Scanner — batch, alias, depth, injection, IDOR, debug mode."""
            try:
                from src.tools.scanners.custom_checks.graphql_deep_scanner import scan_graphql_deep
                target_urls = _host_urls[:5]
                if not target_urls:
                    return []
                # v5.0: Only run if GraphQL endpoint detected in recon
                gql_url: str | None = None
                for ep in (state.endpoints or []):
                    if "graphql" in ep.lower() or "gql" in ep.lower():
                        gql_url = ep
                        break
                _gql_tech = any(
                    "graphql" in t.lower()
                    for t in (getattr(state, "technologies", None) or [])
                )
                if not gql_url and not _gql_tech:
                    logger.debug("GraphQL deep scanner skipped — no GraphQL endpoint/tech detected")
                    return []
                results_raw = await asyncio.wait_for(
                    scan_graphql_deep(
                        target_urls=target_urls,
                        max_concurrent=3,
                        timeout=1200.0,
                        graphql_url=gql_url,
                        headers=_auth_headers or None,
                    ),
                    timeout=1200.0,
                )
                results = [_finding_to_dict(f, "graphql_deep_scanner") for f in results_raw]
                if results:
                    logger.info(f"GraphQL deep scanner: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("GraphQL deep scanner module not available")
            except asyncio.TimeoutError:
                logger.warning("GraphQL deep scanner timed out")
            except Exception as e:
                logger.warning(f"GraphQL deep scanner error: {e}")
            return []

        async def _run_cloud_infra() -> list[dict]:
            """Cloud-native infrastructure checker — K8s, CI/CD, containers, monitoring."""
            try:
                from src.tools.scanners.custom_checks.cloud_checker import check_cloud_security
                target_urls = _host_urls[:5]
                if not target_urls:
                    return []
                # v5.0: Only run if cloud/infra signals detected
                _cloud_kw = {"aws", "amazon", "azure", "gcp", "google cloud", "kubernetes",
                             "k8s", "docker", "ecs", "eks", "aks", "gke", "lambda", "cloudfront",
                             "s3", "elasticbeanstalk", "heroku", "digitalocean", "vercel", "netlify"}
                _techs_lower = [t.lower() for t in (getattr(state, "technologies", None) or [])]
                _cloud_tech = any(kw in t for t in _techs_lower for kw in _cloud_kw)
                _cloud_header = bool(state.metadata.get("cdn_detected") or state.metadata.get("cloud_provider"))
                if not _cloud_tech and not _cloud_header:
                    logger.debug("Cloud infra checker skipped — no cloud signals detected")
                    return []
                results_raw = await asyncio.wait_for(
                    check_cloud_security(
                        targets=target_urls,
                        max_targets=5,
                        max_concurrent=3,
                        timeout=1200.0,
                        extra_headers=_auth_headers or None,
                    ),
                    timeout=1200.0,
                )
                results = [_finding_to_dict(f, "cloud_infra_checker") for f in results_raw]
                if results:
                    logger.info(f"Cloud infra checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("Cloud infra checker module not available")
            except asyncio.TimeoutError:
                logger.warning("Cloud infra checker timed out")
            except Exception as e:
                logger.warning(f"Cloud infra checker error: {e}")
            return []

        async def _run_cicd_checker() -> list[dict]:
            """CI/CD pipeline security checker — Jenkins, GitLab, dep confusion, build log secrets."""
            try:
                from src.tools.scanners.custom_checks.cicd_checker import check_cicd_security
                target_urls = _host_urls[:5]
                if not target_urls:
                    return []
                # v5.0: Only run if CI/CD tech or endpoints detected
                _cicd_kw = {"jenkins", "gitlab", "github", "circleci", "travis", "bamboo",
                            "teamcity", "drone", "buildkite", "argo", "gitea", "bitbucket"}
                _techs_lower = [t.lower() for t in (getattr(state, "technologies", None) or [])]
                _cicd_tech = any(kw in t for t in _techs_lower for kw in _cicd_kw)
                _cicd_ep = any(
                    kw in ep.lower()
                    for ep in (state.endpoints or [])
                    for kw in ("/jenkins", "/gitlab", "ci/cd", "/pipeline", "/.github", "/buildkite")
                )
                if not _cicd_tech and not _cicd_ep:
                    logger.debug("CI/CD checker skipped — no CI/CD signals detected")
                    return []
                _techs = list(_detected_techs) if _detected_techs else None
                results_raw = await asyncio.wait_for(
                    check_cicd_security(
                        targets=target_urls,
                        max_targets=5,
                        max_concurrent=3,
                        timeout=10.0,
                        extra_headers=_auth_headers or None,
                        technologies=_techs,
                    ),
                    timeout=1200.0,
                )
                results = [_finding_to_dict(f, "cicd_checker") for f in results_raw]
                if results:
                    logger.info(f"CI/CD checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("CI/CD checker module not available")
            except asyncio.TimeoutError:
                logger.warning("CI/CD checker timed out")
            except Exception as e:
                logger.warning(f"CI/CD checker error: {e}")
            return []

        async def _run_http2_http3_checker() -> list[dict]:
            """HTTP/2 & HTTP/3 protocol security — ALPN, H2C smuggling, Alt-Svc, protocol downgrade."""
            try:
                from src.tools.scanners.custom_checks.http2_http3_checker import check_http2_http3_security
                target_urls = _host_urls[:5]
                if not target_urls:
                    return []
                results_raw = await asyncio.wait_for(
                    check_http2_http3_security(
                        targets=target_urls,
                        max_targets=5,
                        max_concurrent=3,
                        timeout=10.0,
                        extra_headers=_auth_headers or None,
                    ),
                    timeout=1200.0,
                )
                results = [_finding_to_dict(f, "http2_http3_checker") for f in results_raw]
                if results:
                    logger.info(f"HTTP/2 & HTTP/3 checker: {len(results)} findings")
                return results
            except ImportError:
                logger.debug("HTTP/2 & HTTP/3 checker module not available")
            except asyncio.TimeoutError:
                logger.warning("HTTP/2 & HTTP/3 checker timed out")
            except Exception as e:
                logger.warning(f"HTTP/2 & HTTP/3 checker error: {e}")
            return []

        # ── Technology-aware custom checker routing (V14-T1-2) ──
        # Checkers that REQUIRE specific technologies to be useful.
        # If the required tech keywords are not detected, the checker is skipped.
        # Checkers NOT listed here always run (they are generic).
        _CHECKER_TECH_REQUIREMENTS: dict[str, list[str]] = {
            "jwt_checker": ["jwt", "bearer", "token", "oauth", "openid"],
            "graphql_deep_scanner": ["graphql", "gql", "hasura", "apollo"],
            "cicd_checker": ["jenkins", "gitlab", "github", "gitea", "circleci", "travis", "bamboo"],
            "deserialization_checker": ["java", "tomcat", "spring", "php", "python", "django", "flask", ".net", "aspnet"],
            "websocket_checker": ["websocket", "ws://", "wss://", "socket.io"],
            "http2_http3_checker": ["h2", "http/2", "http/3", "quic"],
        }

        # Collect all technology signals (lowercase) for matching
        _all_tech_signals: set[str] = set()
        for _t_val in (state.technologies or {}).values():
            _all_tech_signals.update(
                w.strip().lower()
                for w in str(_t_val).replace(";", ",").split(",")
                if w.strip()
            )
        # Also include ResponseIntel technologies
        _ri_techs = ((state.metadata or {}).get("response_intel") or {}).get("technologies") or {}
        _all_tech_signals.update(k.lower() for k in _ri_techs)
        # Include raw findings text for extra signal (e.g., jwt in auth headers)
        _finding_text = " ".join(
            f.get("title", "") + " " + f.get("description", "")
            for f in all_findings[:100]
        ).lower()

        def _checker_tech_relevant(checker_name: str) -> bool:
            """Check if a tech-gated checker has matching technology signals."""
            required = _CHECKER_TECH_REQUIREMENTS.get(checker_name)
            if required is None:
                return True  # Not tech-gated, always run
            for keyword in required:
                if keyword in _all_tech_signals or keyword in _finding_text:
                    return True
            return False

        # ── Host-profile-based checker skip (Phase 0.3B) ──
        # Build a pre-computed set of checkers that ALL profiled hosts agree
        # should be skipped.  If even one host says "run it", we run it.
        _host_profile_skips: set[str] = set()
        _hp_dicts = (state.metadata or {}).get("host_profiles") or {}
        if _hp_dicts:
            try:
                from src.analysis.host_profiler import HostIntelProfile
                _hp_objs = {
                    h: HostIntelProfile.from_dict(d)
                    for h, d in _hp_dicts.items()
                    if isinstance(d, dict)
                }
                if _hp_objs:
                    # Start with the skip set of the first host, then intersect
                    _iter = iter(_hp_objs.values())
                    _host_profile_skips = set(next(_iter).skip_checkers)
                    for _hp_obj in _iter:
                        _host_profile_skips &= set(_hp_obj.skip_checkers)
                    if _host_profile_skips:
                        logger.info(
                            f"🏠 Host-profile skip: {len(_host_profile_skips)} checkers "
                            f"irrelevant for all hosts: {sorted(_host_profile_skips)}"
                        )
            except Exception as _hp_skip_err:
                logger.debug(f"Host profile skip computation failed: {_hp_skip_err}")

        async def _run_if_enabled(checker_name: str, runner: Any) -> list[dict]:
            if checker_name in _skipped_tools:
                logger.info(f"🧠 Agentic skip applied to custom checker: {checker_name}")
                return []
            if not _checker_tech_relevant(checker_name):
                logger.info(f"⏭️ Tech-routing skip: {checker_name} (no matching tech signals)")
                return []
            if checker_name in _host_profile_skips:
                logger.info(f"🏠 Host-profile skip: {checker_name} (irrelevant for all profiled hosts)")
                return []
            return await runner()

        _checker_names_all = [
            "http_method_checker", "open_redirect_checker", "info_disclosure_checker",
            "cookie_checker", "api_endpoint_tester", "cors_checker",
            "auth_bypass_checker", "rate_limit_checker", "business_logic_checker",
            "deserialization_checker", "bfla_bola_checker", "mass_assignment_checker",
            "idor_checker", "race_condition_checker", "cache_poisoning_checker",
            "websocket_checker", "cloud_misconfig_checker", "jwt_checker", "fourxx_bypass",
            "http_smuggling_prober", "graphql_deep_scanner", "cloud_infra_checker",
            "cicd_checker", "http2_http3_checker",
        ]
        _active_checkers = sum(1 for n in _checker_names_all if _checker_tech_relevant(n) and n not in _skipped_tools)
        logger.info(f"Running custom checkers ({_active_checkers}/24 tech-relevant) in parallel...")
        checker_results = await asyncio.gather(
            _run_if_enabled("http_method_checker", _run_http_methods),
            _run_if_enabled("open_redirect_checker", _run_open_redirect),
            _run_if_enabled("info_disclosure_checker", _run_info_disclosure),
            _run_if_enabled("cookie_checker", _run_cookie_checker),
            _run_if_enabled("api_endpoint_tester", _run_api_tester),
            _run_if_enabled("cors_checker", _run_cors_checker),
            _run_if_enabled("auth_bypass_checker", _run_auth_bypass),
            _run_if_enabled("rate_limit_checker", _run_rate_limit),
            _run_if_enabled("business_logic_checker", _run_business_logic),
            _run_if_enabled("deserialization_checker", _run_deserialization),
            _run_if_enabled("bfla_bola_checker", _run_bfla_bola),
            _run_if_enabled("mass_assignment_checker", _run_mass_assignment),
            _run_if_enabled("idor_checker", _run_idor),
            _run_if_enabled("race_condition_checker", _run_race_condition),
            _run_if_enabled("cache_poisoning_checker", _run_cache_poisoning),
            _run_if_enabled("websocket_checker", _run_websocket),
            _run_if_enabled("cloud_misconfig_checker", _run_cloud_misconfig),
            _run_if_enabled("jwt_checker", _run_jwt_checker),
            _run_if_enabled("fourxx_bypass", _run_fourxx_bypass),
            _run_if_enabled("http_smuggling_prober", _run_http_smuggling),
            _run_if_enabled("graphql_deep_scanner", _run_graphql_deep),
            _run_if_enabled("cloud_infra_checker", _run_cloud_infra),
            _run_if_enabled("cicd_checker", _run_cicd_checker),
            _run_if_enabled("http2_http3_checker", _run_http2_http3_checker),
            return_exceptions=True,
        )
        _checker_names = _checker_names_all
        for i, res in enumerate(checker_results):
            checker_name = _checker_names[i] if i < len(_checker_names) else "custom_checker"
            if isinstance(res, list):
                all_findings.extend(res)
                if checker_name not in _all_tools_run:
                    _all_tools_run.append(checker_name)
            elif isinstance(res, Exception):
                logger.warning(f"Custom checker {checker_name} failed: {res}")
                if checker_name not in _failed_tools:
                    _failed_tools.append(checker_name)

        if _failed_tools:
            logger.info(f"Failed tools this scan: {_failed_tools}")
            state.metadata["failed_tools"] = _failed_tools

        # -- API Schema Fuzzing (T3-4) --
        # Discover OpenAPI/Swagger specs and fuzz API parameters
        try:
            import re as _re_mod
            _api_spec_paths = [
                "/swagger.json", "/openapi.json", "/v1/swagger.json",
                "/v2/swagger.json", "/api-docs", "/swagger/v1/swagger.json",
                "/openapi/v3/api-docs",
            ]
            _api_spec_urls: list[str] = []
            # Check endpoints for known API spec URL patterns
            for ep in endpoints:
                if _re_mod.search(r"swagger|openapi|api-docs", ep, _re_mod.IGNORECASE):
                    _api_spec_urls.append(ep)

            # Probe live hosts for common spec paths
            for host in (state.live_hosts or [])[:3]:
                base = f"https://{host}" if not host.startswith("http") else host
                for sp in _api_spec_paths:
                    _api_spec_urls.append(f"{base}{sp}")

            if _api_spec_urls:
                from src.tools.api_tools.swagger_parser import SwaggerParserWrapper
                from src.tools.api_tools.api_fuzzer import fuzz_api_endpoints

                _fuzz_sem = asyncio.Semaphore(2)

                async def _try_fuzz_spec(spec_url: str) -> list[dict]:
                    async with _fuzz_sem:
                        try:
                            async with httpx.AsyncClient(
                                timeout=10.0, verify=False
                            ) as _hc:
                                r = await _hc.get(spec_url)
                                if r.status_code != 200:
                                    return []
                                spec = r.json()
                            fuzz_eps = SwaggerParserWrapper.extract_fuzzable_endpoints(
                                spec, spec_url.rsplit("/", 1)[0]
                            )
                            if not fuzz_eps:
                                return []
                            fuzz_findings = await fuzz_api_endpoints(
                                fuzz_eps,
                                auth_headers=_auth_headers or None,
                                max_concurrent=3,
                                timeout=1200.0,
                                max_endpoints=30,
                            )
                            return [_finding_to_dict(f, "api_fuzzer") for f in fuzz_findings]
                        except Exception as exc:
                            logger.debug(f"API fuzz {spec_url}: {exc}")
                            return []

                _fuzz_results = await asyncio.gather(
                    *[_try_fuzz_spec(u) for u in _api_spec_urls[:10]],
                    return_exceptions=True,
                )
                _fuzz_count = 0
                for fr in _fuzz_results:
                    if isinstance(fr, list) and fr:
                        all_findings.extend(fr)
                        _fuzz_count += len(fr)
                if _fuzz_count:
                    logger.info(f"API schema fuzzer: {_fuzz_count} findings")
        except Exception as e:
            logger.debug(f"API schema fuzzer skipped: {e}")

        # _all_tools_run is populated at point-of-execution throughout the
        # vuln scan (each tool appends its name when it actually starts).
        # The following list adds only the tools that always run regardless
        # of conditions (core pipeline tools):
        for _core in ("nuclei", "header_checker", "cookie_checker",
                       "sensitive_url_finder", "js_analyzer",
                       "http_method_checker", "info_disclosure_checker"):
            if _core not in _all_tools_run:
                _all_tools_run.append(_core)
        # Also add arjun/wpscan if they were attempted
        # arjun is disabled (Python 3.13 compat issues)
        if tool_registry.get("wpscan"):
            _all_tools_run.append("wpscan")

        _sync_findings()  # Survive stage timeout — all tools complete

        # ── LLM-Powered Deep Analysis of Findings ──
        # Have the brain review tool outputs for subtle vulns that parsers miss
        intel = state.intelligence_engine
        if intel and intel.is_available and all_findings:
            logger.info("🧠 Running LLM deep analysis on tool outputs...")
            try:
                # Compile a summary of raw tool outputs for brain analysis
                tool_outputs = {}
                for f in all_findings:
                    tool = f.get("tool", "unknown")
                    if tool not in tool_outputs:
                        tool_outputs[tool] = []
                    tool_outputs[tool].append({
                        "title": f.get("title", ""),
                        "url": f.get("url", ""),
                        "severity": f.get("severity", ""),
                        "evidence": f.get("evidence", "")[:200],
                    })

                # Ask brain to find what automated tools missed
                brain_findings = await asyncio.wait_for(
                    intel.analyze_tool_output(
                        tool_name="multi-tool-aggregate",
                        target=state.target,
                        raw_output=json.dumps(tool_outputs, indent=2, default=str)[:8000],
                        parsed_findings=[f for f in all_findings[:10]],
                        context={
                            "technologies": dict(list(state.technologies.items())[:10]),
                            "endpoints_count": len(endpoints),
                            "ports": dict(list(state.open_ports.items())[:10]),
                        },
                    ),
                    timeout=1200.0,  # 5 min max — brain deep analysis shouldn't block scan
                )

                if brain_findings:
                    for bf in brain_findings:
                        # Convert brain-discovered findings to standard format
                        # Brain findings are HYPOTHESES, not confirmed vulnerabilities.
                        # They need actual testing to be promoted to real findings.
                        _brain_conf = min(_safe_float(bf.get("confidence", 30.0), 30.0), 35.0)  # Cap at 35%
                        brain_fd = {
                            "title": bf.get("title", "Brain-Discovered Finding"),
                            "vulnerability_type": bf.get("type", "unknown"),
                            "url": bf.get("endpoint", ""),
                            "severity": bf.get("severity", "low"),  # Default low, not medium
                            "tool": "brain_analysis",
                            "description": bf.get("evidence", ""),
                            "evidence": bf.get("recommended_test", ""),
                            "confidence_score": _brain_conf,
                            "finding_type": "hypothesis",  # NOT a confirmed finding
                            "tags": ["brain_hypothesis", "needs_verification"],
                        }
                        # Brain hypotheses with HIGH/CRITICAL should be downgraded
                        _bsev = str(brain_fd["severity"]).upper()
                        if _bsev in ("CRITICAL", "HIGH"):
                            brain_fd["severity"] = "medium"
                            brain_fd["original_severity"] = _bsev
                        all_findings.append(brain_fd)
                    logger.info(f"🧠 Brain analysis: {len(brain_findings)} hypotheses (capped confidence ≤35%)")

                _sync_findings()
            except asyncio.TimeoutError:
                logger.warning("Brain deep analysis timed out (300s) — skipping")
            except Exception as e:
                logger.warning(f"Brain deep analysis failed (non-critical): {e}")

        # ── LLM Adaptive Re-scan Decision ──
        # Ask brain if we should re-test anything with different parameters
        if intel and intel.is_available:
            try:
                rescan = await asyncio.wait_for(
                    intel.decide_rescan_strategy(
                        completed_findings=all_findings[:10],
                        failed_tools=_failed_tools,
                        remaining_time_seconds=3600,  # Conservative estimate
                        endpoints=list(endpoints)[:50],
                    ),
                    timeout=1200.0,  # 2 min max — secondary brain, should be fast
                )
                if rescan.get("rescan_needed") and rescan.get("priority_retests"):
                    logger.info(f"🧠 Brain suggests {len(rescan['priority_retests'])} re-tests")
                    for rt in rescan["priority_retests"][:3]:
                        logger.info(
                            f"  🔄 Re-test: {rt.get('tool', '?')} on "
                            f"{rt.get('endpoint', '?')} — {rt.get('reason', '')[:60]}"
                        )
                    # Execute top priority re-tests (max 2 to stay in time budget)
                    rescan_sem = asyncio.Semaphore(1)  # One re-test at a time
                    for rt in rescan["priority_retests"][:2]:
                        rt_tool_name = str(rt.get("tool", "")).lower().replace("-", "_")
                        rt_endpoint = rt.get("endpoint", "")
                        rt_options = rt.get("options", {})
                        if not rt_tool_name or not rt_endpoint:
                            continue
                        rt_tool = tool_registry.get(rt_tool_name)
                        if not rt_tool or not rt_tool.is_available():
                            logger.debug(f"Re-test tool {rt_tool_name} not available")
                            continue
                        async with rescan_sem:
                            try:
                                logger.info(f"  🔄 Executing re-test: {rt_tool_name} @ {rt_endpoint}")
                                rt_result = await asyncio.wait_for(
                                    executor.execute(rt_tool, rt_endpoint, rt_options),
                                    timeout=1200.0,
                                )
                                if rt_result and rt_result.findings:
                                    new_fds = [
                                        _finding_to_dict(f, rt_tool_name, fallback_url=rt_endpoint)
                                        for f in rt_result.findings
                                    ]
                                    all_findings.extend(new_fds)
                                    logger.info(
                                        f"  🔄 Re-test {rt_tool_name}: "
                                        f"{len(new_fds)} new findings"
                                    )
                            except asyncio.TimeoutError:
                                logger.warning(f"Re-test {rt_tool_name} timed out")
                            except Exception as e:
                                logger.warning(f"Re-test {rt_tool_name} failed: {e}")
                    _sync_findings()
            except asyncio.TimeoutError:
                logger.warning("Brain re-scan decision timed out (120s) — skipping")
            except Exception as e:
                logger.warning(f"Brain re-scan decision failed: {e}")

        # ── Metasploit Auxiliary Scanning & CVE Auto-Exploit ──
        # Run Metasploit auxiliary scanners for detected technologies
        # and auto-exploit any CVE matches found by searchsploit/tech_cve.
        try:
            from src.tools.exploit.metasploit_wrapper import MetasploitWrapper as _MsfW
            _msf = _MsfW()
            if _msf.is_available():
                # 1) Technology-based auxiliary scans
                _msf_techs = set()
                for _host_key, _tech_list in (state.technologies.items() if isinstance(state.technologies, dict) else []):
                    for _titem in (_tech_list if isinstance(_tech_list, list) else [str(_tech_list)]):
                        _msf_techs.add(str(_titem).lower().split("/")[0].split(" ")[0])

                _msf_aux_techs = {"apache", "tomcat", "iis", "wordpress", "joomla",
                                  "drupal", "jenkins", "elasticsearch", "phpmyadmin"}
                _matching_techs = _msf_techs & _msf_aux_techs
                if _matching_techs:
                    logger.info(f"🔫 Metasploit auxiliary: scanning {len(_matching_techs)} technologies")
                    _primary_target = targets[0] if targets else state.target
                    for _mt in list(_matching_techs)[:4]:
                        try:
                            _aux_result = await asyncio.wait_for(
                                _msf.run_auxiliary_scan(
                                    target=_primary_target, technology=_mt,
                                    port=443 if "https" in state.target else 80,
                                    ssl="https" in state.target,
                                ),
                                timeout=1200.0,
                            )
                            if _aux_result and _aux_result.findings:
                                for _af in _aux_result.findings:
                                    all_findings.append(_finding_to_dict(_af, "metasploit_aux"))
                                logger.info(f"  🔫 MSF aux ({_mt}): {len(_aux_result.findings)} findings")
                        except (asyncio.TimeoutError, Exception) as _maux_err:
                            logger.warning(f"MSF aux {_mt} failed: {_maux_err}")

                # 2) CVE auto-exploit for findings with CVE references
                import re as _re
                _cve_findings = []
                for _f in all_findings:
                    _combined = f"{_f.get('title', '')} {_f.get('description', '')} {_f.get('evidence', '')}"
                    _cve_match = _re.search(r"CVE-\d{4}-\d{4,7}", _combined, _re.IGNORECASE)
                    if _cve_match:
                        _cve_findings.append((_f, _cve_match.group(0).upper()))

                if _cve_findings:
                    logger.info(f"🔫 Metasploit CVE auto-exploit: {len(_cve_findings)} CVE findings")
                    _primary_target = targets[0] if targets else state.target
                    for _cf, _cve_id in _cve_findings[:6]:
                        try:
                            _cve_result = await asyncio.wait_for(
                                _msf.auto_exploit_cve(
                                    target=_primary_target, cve_id=_cve_id,
                                    port=443 if "https" in state.target else 80,
                                    ssl="https" in state.target,
                                    target_uri=_cf.get("endpoint", "/"),
                                ),
                                timeout=1200.0,
                            )
                            if _cve_result and _cve_result.findings:
                                for _xf in _cve_result.findings:
                                    fd = _finding_to_dict(_xf, "metasploit_exploit")
                                    fd["cve_id"] = _cve_id
                                    all_findings.append(fd)
                                logger.info(f"  🔫 MSF exploit ({_cve_id}): {len(_cve_result.findings)} findings")
                        except (asyncio.TimeoutError, Exception) as _mcve_err:
                            logger.warning(f"MSF CVE {_cve_id} failed: {_mcve_err}")

                    _all_tools_run.append("metasploit")
                    _sync_findings()
        except ImportError:
            logger.debug("MetasploitWrapper not available for auxiliary scanning")
        except Exception as _msf_global_err:
            logger.warning(f"Metasploit auxiliary scanning failed: {_msf_global_err}")

        # ══════════════════════════════════════════════════════════════
        # ██████  HUNTER MODE: LLM-Driven Deep Probing & PoC Verification
        # ══════════════════════════════════════════════════════════════

        class _PhaseSkipped(Exception):
            """Sentinel for budget-exhausted phase skip."""
        # After all standard scanners finish, the Intelligence Engine takes
        # over to:
        # 1. Generate custom nuclei templates for identified attack vectors
        # 2. Run deep iterative probes on high-value endpoints
        # 3. Generate & execute PoCs for all scan findings
        # ══════════════════════════════════════════════════════════════
        intel = state.intelligence_engine

        # ── HUNTER timeout budget (P2-3): profile-aware per-phase timeouts ──
        _HUNTER_BUDGETS = {
            ScanProfile.STEALTH: {"phase_a": 600, "phase_b": 900, "phase_c": 600, "total": 1800},
            ScanProfile.BALANCED: {"phase_a": 1200, "phase_b": 1800, "phase_c": 1800, "total": 3600},
            ScanProfile.AGGRESSIVE: {"phase_a": 1800, "phase_b": 2400, "phase_c": 2400, "total": 5400},
        }
        _hb = _HUNTER_BUDGETS.get(state.profile, _HUNTER_BUDGETS[ScanProfile.BALANCED])
        import time as _hunter_time
        _hunter_start = _hunter_time.monotonic()
        if intel and intel.is_available:
            # ── Phase A: Generate Custom Nuclei Templates ──
            # Use brain vectors if available, otherwise fallback to synthetic
            phase_a_vectors = brain_vectors
            if not phase_a_vectors:
                phase_a_vectors = _generate_synthetic_vectors(targets, endpoints, state)
                if phase_a_vectors:
                    logger.info(f"🧠 HUNTER Phase A: Using {len(phase_a_vectors)} synthetic vectors (brain returned none)")
            if phase_a_vectors:
                try:
                    logger.info("🧠 HUNTER: Generating custom nuclei templates from attack vectors...")
                    # Convert brain vectors to endpoint dicts for template writer
                    ep_dicts = []
                    for vec in phase_a_vectors[:8]:
                        ep = vec.get("endpoint", "")
                        resolved_url = _resolve_brain_endpoint(ep, targets, state.target)
                        if resolved_url:
                            ep_dicts.append({
                                "url": resolved_url,
                                "endpoint": ep,
                                "parameters": [vec.get("parameter", "")] if vec.get("parameter") else [],
                                "method": "GET",
                                "tech_stack": list(set(
                                    t for techs in state.technologies.values()
                                    for t in (techs if isinstance(techs, list) else [str(techs)])
                                ))[:10],
                            })

                    if ep_dicts:
                        templates = await asyncio.wait_for(
                            intel.write_custom_nuclei_templates(
                                endpoints=ep_dicts,
                                tech_stack=list(set(
                                    t for techs in state.technologies.values()
                                    for t in (techs if isinstance(techs, list) else [str(techs)])
                                ))[:10],
                                max_templates=3,
                            ),
                            timeout=float(_hb["phase_a"]),
                        )

                        if templates:
                            from src.tools.scanners.nuclei_template_writer import save_and_validate_templates
                            saved_paths = save_and_validate_templates(templates)
                            logger.info(
                                f"🧠 HUNTER: Generated {len(templates)} templates, "
                                f"{len(saved_paths)} saved & valid"
                            )
                            _all_tools_run.append("nuclei_template_writer")

                            # Run these custom templates immediately
                            if saved_paths and nuclei_tool and nuclei_tool.is_available():
                                try:
                                    custom_opts = _get_scan_options(state.profile, "scanner")
                                    custom_opts["templates"] = [str(p) for p in saved_paths]
                                    custom_opts["timeout"] = 1200
                                    custom_opts["severity"] = "low,medium,high,critical"
                                    custom_result = await nuclei_tool.run_batch(
                                        _nuclei_targets, custom_opts, state.profile
                                    )
                                    if custom_result and custom_result.findings:
                                        for f in custom_result.findings:
                                            fd = _finding_to_dict(f, "nuclei_custom")
                                            fd["tags"] = fd.get("tags", []) + ["brain_generated"]
                                            all_findings.append(fd)
                                        logger.info(
                                            f"🧠 HUNTER: Custom templates found "
                                            f"{len(custom_result.findings)} vulnerabilities!"
                                        )
                                        _sync_findings()
                                except Exception as e:
                                    logger.warning(f"Custom template scan failed: {e}")
                except asyncio.TimeoutError:
                    logger.warning("HUNTER: Custom template generation timed out")
                except Exception as e:
                    logger.warning(f"HUNTER: Template generation error: {e}")

            # ── Phase B: Deep Probe on High-Value Attack Vectors ──
            # If brain vectors exist, use them. Otherwise, auto-generate from
            # discovered endpoints (GraphQL, APIs, auth, admin, etc.)
            probe_source_vectors = brain_vectors
            if not probe_source_vectors:
                # Fallback: build synthetic vectors from high-value endpoints
                logger.info("🧠 HUNTER: No brain vectors — auto-generating probe targets from discovered endpoints")
                probe_source_vectors = _generate_synthetic_vectors(targets, endpoints, state)
                if probe_source_vectors:
                    logger.info(f"🧠 HUNTER: Generated {len(probe_source_vectors)} synthetic probe targets")

            if probe_source_vectors:
                try:
                    logger.info("🧠 HUNTER: Starting LLM-driven deep probing on attack vectors...")

                    # Prepare targets for deep probe — raise limit to 25
                    probe_targets = []
                    for vec in probe_source_vectors[:25]:
                        ep = vec.get("endpoint", "")
                        resolved_ep = _resolve_brain_endpoint(ep, targets, state.target)
                        if resolved_ep:
                            _priority_num = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                                vec.get("priority", "medium"), 2
                            )
                            probe_targets.append({
                                "endpoint": resolved_ep,
                                "vuln_type": vec.get("vuln_type", "xss"),
                                "parameters": [vec.get("parameter", "")] if vec.get("parameter") else [],
                                "priority": _priority_num,
                                "tech_stack": list(set(
                                    t for techs in state.technologies.values()
                                    for t in (techs if isinstance(techs, list) else [str(techs)])
                                ))[:5],
                            })

                    # P4.1: Wire creative_narratives → probe_targets
                    # LLM-generated attack scenarios become actual deep probe targets.
                    _narratives = attack_surface_data.get("creative_narratives", [])
                    _probe_eps = {t["endpoint"] for t in probe_targets}
                    _narratives_added = 0
                    for narr in _narratives:
                        if not isinstance(narr, dict):
                            continue
                        _n_ep = narr.get("target_endpoint", "")
                        if not _n_ep:
                            continue
                        _resolved = _resolve_brain_endpoint(_n_ep, targets, state.target)
                        if not _resolved or _resolved in _probe_eps:
                            continue
                        _sev = (narr.get("severity_estimate") or "medium").lower()
                        _npri = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(_sev, 2)
                        # Map vuln_class to deep_probe vuln_type
                        _vclass = (narr.get("vuln_class") or "unknown").lower()
                        _VT_MAP = {
                            "idor": "idor", "sqli": "sqli", "sql injection": "sqli",
                            "xss": "xss", "ssrf": "ssrf", "ssti": "ssti",
                            "rce": "rce", "command injection": "rce",
                            "race condition": "race_condition",
                            "mass assignment": "mass_assignment",
                            "auth bypass": "auth_bypass", "authentication bypass": "auth_bypass",
                            "open redirect": "open_redirect", "lfi": "lfi",
                            "xxe": "xxe", "csrf": "csrf",
                        }
                        _vtype = _VT_MAP.get(_vclass, _vclass.replace(" ", "_"))
                        probe_targets.append({
                            "endpoint": _resolved,
                            "vuln_type": _vtype,
                            "parameters": [],
                            "priority": _npri,
                            "tech_stack": list(set(
                                t for techs in state.technologies.values()
                                for t in (techs if isinstance(techs, list) else [str(techs)])
                            ))[:5],
                        })
                        _probe_eps.add(_resolved)
                        _narratives_added += 1
                    if _narratives_added:
                        logger.info(
                            f"🧠 HUNTER: {_narratives_added} creative narrative targets added to deep probe"
                        )

                    if probe_targets:
                        session_dir = ""
                        if state.session_id:
                            session_dir = f"output/evidence/{state.session_id}"
                            import os
                            os.makedirs(session_dir, exist_ok=True)

                        # Scale iterations by highest priority among targets
                        _max_priority = max((t.get("priority", 2) for t in probe_targets), default=2)
                        _PRIORITY_ITER_MAP = {4: 15, 3: 10, 2: 7, 1: 5}
                        _scaled_iters = _PRIORITY_ITER_MAP.get(_max_priority, 7)

                        deep_findings = await asyncio.wait_for(
                            intel.run_deep_probe(
                                targets=probe_targets,
                                session_dir=session_dir,
                                max_per_target=_scaled_iters,
                                oob_domain=_oob_domain or "",
                                interactsh=_interactsh,
                                auth_headers=_auth_headers or None,
                            ),
                            timeout=float(_hb["phase_b"]),
                        )

                        if deep_findings:
                            all_findings.extend(deep_findings)
                            confirmed = sum(1 for f in deep_findings if f.get("poc_confirmed"))
                            logger.info(
                                f"🧠 HUNTER: Deep probe produced {len(deep_findings)} findings "
                                f"({confirmed} PoC-confirmed!)"
                            )
                            _all_tools_run.append("deep_probe")
                            _sync_findings()
                except asyncio.TimeoutError:
                    logger.warning("HUNTER: Deep probe timed out")
                except Exception as e:
                    logger.warning(f"HUNTER: Deep probe error: {e}")

            # ── HUNTER budget check before Phase C (P2-3) ──
            _hunter_elapsed = _hunter_time.monotonic() - _hunter_start
            _hunter_remaining = _hb["total"] - _hunter_elapsed
            _skip_phase_c = False
            if _hunter_remaining < 60:
                logger.warning(
                    f"HUNTER: Total budget exhausted ({_hunter_elapsed:.0f}s / {_hb['total']}s) "
                    "— skipping Phase C"
                )
                _skip_phase_c = True
            else:
                # Adjust Phase C timeout to remaining budget
                _phase_c_budget = min(float(_hb["phase_c"]), _hunter_remaining)

            # ── Phase C: Exploit Verification & Evidence Collection ──
            # Uses ExploitVerifier to PROVE vulnerabilities with concrete evidence.
            # Replaces the old hardcoded 8-Finding PoC loop with a proper
            # verification engine that supports PoC scripts, Metasploit,
            # curl commands, and nuclei re-verification.
            # Evidence is collected via EvidenceAggregator and packaged per finding.
            try:
                if _skip_phase_c:
                    raise _PhaseSkipped("Phase C skipped — budget exhausted")
                from src.tools.exploit.exploit_verifier import ExploitVerifier
                from src.reporting.evidence.evidence_aggregator import EvidenceAggregator

                _session_dir = ""
                if state.session_id:
                    _session_dir = f"output/evidence/{state.session_id}"

                # Profile-configurable PoC timeout
                _poc_timeout_map = {
                    ScanProfile.STEALTH: 600.0,     # 10m — conservative, fewer retries
                    ScanProfile.BALANCED: 900.0,    # 15m — default
                    ScanProfile.AGGRESSIVE: 1200.0, # 20m — thorough verification
                }
                _poc_timeout = _poc_timeout_map.get(state.profile, 900.0)

                verifier = ExploitVerifier(
                    brain_engine=intel.brain if intel else None,
                    session_dir=_session_dir,
                    max_poc_iterations=3,
                    poc_timeout=_poc_timeout,
                )
                aggregator = EvidenceAggregator(session_dir=_session_dir)

                # Verify all qualifying findings (no hardcoded limit)
                proven_results = await asyncio.wait_for(
                    verifier.verify_batch(
                        findings=all_findings,
                        max_concurrent=2,
                        max_findings=0,  # No limit — verify all qualifying
                    ),
                    timeout=_phase_c_budget,
                )

                poc_confirmed_count = 0
                for proven in proven_results:
                    f = proven.finding
                    if proven.is_proven:
                        # Update the finding with proven evidence
                        f["poc_confirmed"] = True
                        f["poc_code"] = proven.poc_code
                        f["poc_evidence"] = proven.evidence_items
                        f["confidence"] = proven.confidence
                        f["evidence_chain_id"] = proven.evidence_chain_id
                        if proven.metasploit_module:
                            f["metasploit_module"] = proven.metasploit_module

                        # Collect and package evidence
                        chain = None
                        if verifier._chain_builder:
                            chain = verifier._chain_builder.get_chain(
                                proven.evidence_chain_id
                            )
                        try:
                            package = await aggregator.collect(
                                proven, evidence_chain=chain,
                                capture_screenshot=True,
                            )
                            aggregator.export(package)
                        except Exception as _ev_err:
                            logger.debug(f"Evidence export error: {_ev_err}")

                        poc_confirmed_count += 1
                        logger.info(
                            f"  🏆 PROVEN: {f.get('title', '?')[:60]} "
                            f"[{proven.strategy_used.value}]"
                        )

                _all_tools_run.append("exploit_verifier")
                _vstats = verifier.get_stats()
                logger.info(
                    f"🧠 HUNTER: Verification complete | "
                    f"tested={_vstats['total_verified']} | "
                    f"proven={_vstats['total_proven']} | "
                    f"rate={_vstats['prove_rate']}%"
                )

                # Export all evidence packages
                try:
                    exported = aggregator.export_all()
                    if exported:
                        logger.info(f"📦 Evidence exported: {len(exported)} packages")
                except Exception as _exp_err:
                    logger.debug(f"Evidence batch export error: {_exp_err}")

                _sync_findings()

            except asyncio.TimeoutError:
                logger.warning("HUNTER: Exploit verification timed out")
            except _PhaseSkipped as _ps:
                logger.info(str(_ps))
            except ImportError as _imp:
                logger.debug(f"HUNTER: ExploitVerifier not available: {_imp}")
                # Fallback to legacy Phase C
                _INFO_SEVERITIES = {"info", "informational", "none"}
                poc_candidates = [
                    f for f in all_findings
                    if f.get("confidence", f.get("confidence_score", 0)) >= 50.0
                    and not f.get("poc_confirmed")
                    and isinstance(f.get("url", ""), str) and f.get("url", "").startswith("http")
                    and str(f.get("severity", "")).lower() not in _INFO_SEVERITIES
                ]
                _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                poc_candidates.sort(
                    key=lambda f: _SEV_ORDER.get(str(f.get("severity", "low")).lower(), 4)
                )
                if poc_candidates and intel:
                    poc_sem = asyncio.Semaphore(2)

                    async def _run_poc_for_finding(finding: dict) -> dict | None:
                        async with poc_sem:
                            try:
                                _sd = f"output/evidence/{state.session_id}" if state.session_id else ""
                                return await asyncio.wait_for(
                                    intel.generate_and_execute_poc(finding=finding, session_dir=_sd),
                                    timeout=1200.0,
                                )
                            except Exception as _poc_err:
                                logger.warning(f"PoC execution failed: {_poc_err}")
                                return None

                    poc_results = await asyncio.gather(
                        *[_run_poc_for_finding(f) for f in poc_candidates[:25]],
                        return_exceptions=True,
                    )
                    for i, poc_res in enumerate(poc_results):
                        if isinstance(poc_res, dict) and poc_res.get("poc_confirmed"):
                            poc_candidates[i]["poc_confirmed"] = True
                            poc_candidates[i]["poc_code"] = poc_res.get("poc_code", "")
                            poc_candidates[i]["poc_evidence"] = poc_res.get("poc_evidence", [])
                            _boosted = min(
                                100.0,
                                _safe_float(poc_candidates[i].get("confidence", 0), 0.0)
                                + _safe_float(poc_res.get("poc_confidence_boost", 0), 0.0),
                            )
                            poc_candidates[i]["confidence"] = _boosted
                            poc_candidates[i]["confidence_score"] = _boosted
                    _all_tools_run.append("poc_executor")
                    _sync_findings()
            except Exception as _phase_c_err:
                logger.error(f"HUNTER Phase C error: {_phase_c_err}")

        # ── ResponseValidator pre-filter ──
        # Drop findings whose embedded http_response contains WAF/redirect/error
        # artifacts that slipped past individual checker validation.
        try:
            from src.utils.response_validator import ResponseValidator as _RV
            _rv = _RV()
            _pre_rv_count = len(all_findings)
            _rv_filtered: list[dict] = []
            for _f in all_findings:
                _http_resp = _f.get("http_response", "")
                if not _http_resp or not isinstance(_http_resp, str):
                    _rv_filtered.append(_f)
                    continue
                # Extract status code from raw HTTP response (first line)
                _sc = 200
                _first_line = _http_resp.split("\n", 1)[0]
                for _part in _first_line.split():
                    if _part.isdigit() and 100 <= int(_part) <= 599:
                        _sc = int(_part)
                        break
                # Extract headers (rough parse)
                _hdrs: dict[str, str] = {}
                _body = _http_resp
                if "\r\n\r\n" in _http_resp:
                    _hdr_block, _body = _http_resp.split("\r\n\r\n", 1)
                    for _hl in _hdr_block.split("\r\n")[1:]:
                        if ":" in _hl:
                            _k, _v = _hl.split(":", 1)
                            _hdrs[_k.strip()] = _v.strip()
                elif "\n\n" in _http_resp:
                    _hdr_block, _body = _http_resp.split("\n\n", 1)
                    for _hl in _hdr_block.split("\n")[1:]:
                        if ":" in _hl:
                            _k, _v = _hl.split(":", 1)
                            _hdrs[_k.strip()] = _v.strip()
                _vr = _rv.validate(_sc, _hdrs, _body[:5000])
                if _vr.is_valid:
                    _rv_filtered.append(_f)
                else:
                    # Soft WAF/CDN signals → lower confidence instead of drop
                    if _vr.confidence_modifier > -15:
                        _f["confidence"] = max(
                            10.0,
                            _safe_float(_f.get("confidence", 0), 0.0) + _vr.confidence_modifier,
                        )
                        _f["confidence_score"] = _f["confidence"]
                        _rv_filtered.append(_f)
                    else:
                        logger.debug(
                            f"ResponseValidator pre-filter dropped: "
                            f"{_f.get('title', '?')} — {_vr.rejection_reason}"
                        )
            all_findings = _rv_filtered
            _dropped = _pre_rv_count - len(all_findings)
            if _dropped:
                logger.info(f"ResponseValidator pre-filter: dropped {_dropped}/{_pre_rv_count} findings")
        except Exception as _rv_err:
            logger.warning(f"ResponseValidator pre-filter skipped: {_rv_err}")

        # Deduplicate findings:
        # 1. For header/info/nuclei findings: merge same title across hosts -> single finding
        # 2. For other findings: same (title, url) only reported once
        merged_by_title: dict[str, dict] = {}
        other_findings: list[dict] = []
        # Tools whose findings should be merged by title across hosts
        _merge_tools = {"header_checker", "info_disclosure_checker", "nuclei", "tech_cve_checker", "sensitive_url_finder"}
        for f in all_findings:
            title = f.get("title", "")
            tool = f.get("tool", "")
            if tool in _merge_tools and title:
                if title not in merged_by_title:
                    merged_by_title[title] = dict(f)
                    merged_by_title[title]["_urls"] = [f.get("url", "")]
                else:
                    merged_by_title[title]["_urls"].append(f.get("url", ""))
            else:
                other_findings.append(f)
        # Finalize merged findings: set url to comma-joined list
        for title, mf in merged_by_title.items():
            urls = list(dict.fromkeys(mf.pop("_urls", [])))  # unique, ordered
            mf["url"] = urls[0] if len(urls) == 1 else ", ".join(urls)
            mf["description"] = mf.get("description", "") + f" (Affected: {len(urls)} hosts)"
            other_findings.append(mf)
        # Standard dedup on remaining
        seen_findings = set()
        deduped_findings = []
        for f in other_findings:
            _url_val = f.get("url", "")
            if isinstance(_url_val, list):
                _url_val = _url_val[0] if _url_val else ""
            dedup_key = (f.get("title", ""), str(_url_val))
            if dedup_key not in seen_findings:
                seen_findings.add(dedup_key)
                deduped_findings.append(f)

        # --- Cross-tool semantic dedup ---
        # Catch duplicates where two tools report the same endpoint/vuln type
        # with different titles. E.g., brain_analysis "Potential XML-RPC Attack
        # Surface" vs sensitive_url_finder "Sensitive URL: WordPress XML-RPC".
        from urllib.parse import urlparse

        def _extract_path_key(url_str: Any) -> str:
            """Extract normalized path from URL for comparison."""
            if isinstance(url_str, list):
                url_str = url_str[0] if url_str else ""
            if not isinstance(url_str, str):
                url_str = str(url_str)
            for u in url_str.split(","):
                u = u.strip()
                if u.startswith("http"):
                    try:
                        p = urlparse(u).path.rstrip("/").lower()
                        if p:
                            return p
                    except Exception as _exc:
                        logger.warning(f"full scan error: {_exc}")
                elif u.startswith("/"):
                    return u.rstrip("/").lower()
            return url_str.strip().rstrip("/").lower()

        # Map: (normalized_path, vuln_type) → list of (index, finding)
        # Include vuln_type so different vulnerabilities at the same URL are preserved
        _path_groups: dict[tuple[str, str], list[tuple[int, dict]]] = {}
        for idx, f in enumerate(deduped_findings):
            pk = _extract_path_key(f.get("url", ""))
            vt = f.get("vulnerability_type", f.get("type", "unknown")).lower()
            if pk:
                _path_groups.setdefault((pk, vt), []).append((idx, f))

        _cross_remove: set[int] = set()
        for pk, group in _path_groups.items():
            if len(group) < 2:
                continue
            # Within same path, keep the finding with highest confidence
            # and mark lower ones as duplicates (different tools, same target)
            best_idx, best_f = max(group, key=lambda x: _safe_float(x[1].get("confidence_score", x[1].get("confidence")), 0.0))  # Bug 5.2l-7: was bare get()
            for idx, f in group:
                if idx != best_idx:
                    # Only mark as dup if it's from a different tool
                    if f.get("tool", "") != best_f.get("tool", ""):
                        _cross_remove.add(idx)

        if _cross_remove:
            before = len(deduped_findings)
            deduped_findings = [f for i, f in enumerate(deduped_findings) if i not in _cross_remove]
            logger.info(f"Cross-tool dedup: {before} -> {len(deduped_findings)} (removed {len(_cross_remove)} cross-tool duplicates)")

        if len(all_findings) != len(deduped_findings):
            logger.info(f"Finding dedup: {len(all_findings)} -> {len(deduped_findings)} unique findings")
        all_findings = deduped_findings

        state.raw_findings = all_findings

        # ── Harvest Interactsh OOB interactions ──
        if _interactsh and _oob_domain:
            try:
                await _interactsh.poll_interactions(wait_seconds=15)
                oob_findings = _interactsh.interactions_to_findings(target=state.target)
                if oob_findings:
                    for f in oob_findings:
                        fd = _finding_to_dict(f, "interactsh")
                        all_findings.append(fd)
                    state.raw_findings = all_findings
                    logger.info(f"📡 Interactsh OOB: {len(oob_findings)} interaction(s) → findings")
                # Run correlation engine with OOB data
                try:
                    from src.analysis.correlation_engine import CorrelationEngine
                    corr_engine = CorrelationEngine(
                        intelligence_engine=state.intelligence_engine,
                    )
                    corr_engine.add_findings(all_findings)
                    corr_engine.add_oob_interactions(_interactsh._interactions)
                    corr_report = corr_engine.correlate()
                    # V6-T0-3: LLM cross-finding reasoning for novel chains
                    if state.intelligence_engine and corr_report.correlated_findings:
                        try:
                            llm_chains = await corr_engine.detect_chains_llm(
                                corr_report.correlated_findings,
                            )
                            if llm_chains:
                                corr_report.attack_chains.extend(llm_chains)
                                corr_report.total_chains_found = len(corr_report.attack_chains)
                        except Exception as _llm_exc:
                            logger.debug("LLM chain detection skipped: {}", _llm_exc)
                    state.metadata = state.metadata or {}
                    state.metadata["correlation_report"] = {
                        "total_raw": corr_report.total_raw_findings,
                        "total_deduped": corr_report.total_after_dedup,
                        "chains_found": corr_report.total_chains_found,
                        "oob_confirmed": sum(
                            1 for f in corr_report.correlated_findings
                            if f.oob_confirmed
                        ),
                    }
                    if corr_report.attack_chains:
                        logger.info(
                            f"🔗 Correlation engine: {corr_report.total_chains_found} "
                            f"attack chain(s) detected"
                        )
                except Exception as corr_exc:
                    logger.warning(f"Correlation engine failed: {corr_exc}")
                await _interactsh.stop_session()
            except Exception as exc:
                logger.warning(f"Interactsh harvest failed: {exc}")
                try:
                    await _interactsh.stop_session()
                except Exception as _exc:
                    logger.warning(f"full scan error: {_exc}")

        result.data = {"total_findings": len(all_findings)}
        result.findings_count = len(all_findings)
        result.success = True

        logger.info(f"Vulnerability scan complete | findings={len(all_findings)}")

    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
        result.success = False
        result.errors.append(str(e))
    finally:
        # ── CRITICAL: Persist findings even when CancelledError (stage
        #    timeout from asyncio.wait_for) kills this coroutine.
        #    CancelledError is a BaseException and skips `except Exception`.
        try:
            _sync_findings()
            # Persist tools list to state for report
            state.tools_run = sorted(set(_all_tools_run))
            logger.info(
                f"Vuln scan finally-sync: {len(all_findings)} findings "
                f"persisted to state.raw_findings"
            )
        except Exception as _exc:
            logger.warning(f"full scan error: {_exc}")
        # Ensure interactsh session is always cleaned up
        if _interactsh and _interactsh._session_active:
            try:
                # Use shield to protect cleanup from CancelledError propagation
                await asyncio.shield(_interactsh.stop_session())
            except (Exception, asyncio.CancelledError):
                # Last resort: try synchronous kill
                try:
                    if hasattr(_interactsh, '_process') and _interactsh._process:
                        _interactsh._process.kill()
                except Exception as _exc:
                    logger.warning(f"full scan error: {_exc}")

    return result


async def handle_fp_elimination(state: WorkflowState) -> StageResult:
    """
    Asama 7: False Positive Eleme

    5 katmanli dogrulama ile gercek zafiyetleri ayiklar.
    """
    result = StageResult(stage=WorkflowStage.FP_ELIMINATION)

    try:
        raw_findings = state.raw_findings
        logger.info(f"FP elimination started | raw_findings={len(raw_findings)}")

        # ── Normalize URL fields — some tools (API fuzzer, Swagger parser) may
        #    store url/endpoint/target as lists.  Coerce to string early so all
        #    downstream code (.strip(), set hashing, Pydantic validation) works.
        for _f in raw_findings:
            if isinstance(_f, dict):
                for _key in ("url", "endpoint", "target"):
                    _v = _f.get(_key)
                    if isinstance(_v, list):
                        _f[_key] = _v[0] if _v else ""
                    elif _v is not None and not isinstance(_v, str):
                        _f[_key] = str(_v)

        if not raw_findings:
            result.data = {"message": "No findings to verify"}
            result.success = True
            return result

        from src.fp_engine.fp_detector import FPDetector
        from src.tools.base import Finding

        detector = state.fp_detector or FPDetector(
            brain_engine=state.brain_engine,
            intelligence_engine=state.intelligence_engine,
            response_intel=(state.metadata or {}).get("response_intel"),
            tool_executor=state.tool_executor,
            is_spa=bool((state.metadata or {}).get("is_spa")),
            auth_headers=(
                state.auth_headers
                or (state.metadata or {}).get("auth_headers")
            ),
            host_profiles=(state.metadata or {}).get("host_profiles"),
            waf_detection=(state.metadata or {}).get("waf_detection"),
        )
        verified: list[dict[str, Any]] = []
        false_positives: list[dict[str, Any]] = []

        def _dict_to_finding(d: dict[str, Any]) -> Finding:
            """raw_findings dict'ini Finding modeline dönüştür.

            All string fields are coerced via _coerce_to_str() and numeric
            fields via _safe_float() so that malformed dicts (e.g. list
            URLs from Swagger parsers, non-numeric confidence strings from
            LLM) never cause Pydantic validation errors.
            """
            severity_val = d.get("severity", "medium")
            from src.utils.constants import SeverityLevel
            # Handle numeric CVSS scores (e.g. 9.1 → critical)
            try:
                numeric = float(severity_val)
                if numeric >= 9.0:
                    severity_val = "critical"
                elif numeric >= 7.0:
                    severity_val = "high"
                elif numeric >= 4.0:
                    severity_val = "medium"
                elif numeric >= 0.1:
                    severity_val = "low"
                else:
                    severity_val = "info"
            except (ValueError, TypeError):
                pass  # Not numeric, use as-is
            try:
                sev = SeverityLevel(str(severity_val).lower())
            except (ValueError, KeyError):
                sev = SeverityLevel.MEDIUM
            # Restore tags — may be list or missing
            tags_raw = d.get("tags", [])
            tags = list(tags_raw) if isinstance(tags_raw, (list, tuple)) else []
            # Restore references
            refs_raw = d.get("references", [])
            refs = list(refs_raw) if isinstance(refs_raw, (list, tuple)) else []
            # Restore metadata
            meta_raw = d.get("metadata", {})
            meta = dict(meta_raw) if isinstance(meta_raw, dict) else {}
            # ── Coerce string fields to prevent Pydantic validation errors ──
            # Swagger/API parsers may produce list URLs, LLM may produce non-string
            # values for parameter/payload/description fields.
            _cs = _coerce_to_str
            # ── Coerce numeric fields (LLM may produce 'high'/'None'/'' etc.) ──
            # v4.0: default 0.0 (not 50.0) — unknown confidence must NOT auto-pass
            # the ≥50 quality gate.  FPDetector will assign a proper score.
            _raw_conf = d.get("confidence_score", d.get("confidence", 0.0))
            _confidence = _safe_float(_raw_conf, 0.0)
            _raw_cvss = d.get("cvss_score")
            _cvss = _safe_float(_raw_cvss, 0.0) if _raw_cvss is not None else None
            if _cvss is not None and _cvss == 0.0 and _raw_cvss is None:
                _cvss = None  # Preserve None semantics
            return Finding(
                title=_cs(d.get("title", "Untitled")) or "Untitled",
                description=_cs(d.get("description", "")),
                vulnerability_type=_cs(d.get("vulnerability_type", d.get("type", ""))),
                severity=sev,
                confidence=_confidence,
                target=_cs(d.get("url", d.get("target", ""))),
                endpoint=_cs(d.get("url", "")),
                parameter=_cs(d.get("parameter", "")),
                payload=_cs(d.get("payload", "")),
                evidence=_cs(d.get("evidence", "")),
                tool_name=_cs(d.get("tool", "")),
                http_request=_cs(d.get("http_request", "")),
                http_response=_cs(d.get("http_response", "")),
                cvss_score=_cvss,
                cve_id=_cs(d.get("cve_id", d.get("cve", ""))),
                cwe_id=_cs(d.get("cwe_id", d.get("cwe", ""))),
                references=refs,
                tags=tags,
                metadata=meta,
            )

        # ── Parallel FP analysis with per-finding timeout ──
        # Process findings in parallel batches (semaphore-limited) instead of
        # sequentially.  Each finding gets a per-finding timeout so one slow
        # brain call cannot block the whole stage.  Results are saved
        # incrementally to state so partial progress survives a stage timeout.
        # Throughput: (stage_timeout / per_finding_timeout) × concurrency
        #   = (2700 / 45) × 6 = 360 findings max (was 120 with 90s × 4)
        fp_sem = asyncio.Semaphore(12)  # Max 12 concurrent FP analyses

        async def _analyze_one(finding: dict[str, Any]) -> None:
            """Analyze a single finding, mutating verified/false_positives lists."""
            async with fp_sem:
                try:
                    # ── Evidence Quality Gate (v5.0): severity-proportional
                    # evidence requirements — replaces simple empty-check ──
                    from src.fp_engine.evidence_quality_gate import evaluate as _eqg_evaluate
                    _eqg_verdict = _eqg_evaluate(finding)
                    if not _eqg_verdict.passed:
                        _cap = _eqg_verdict.confidence_cap or 35.0
                        finding["confidence_score"] = min(
                            _safe_float(finding.get("confidence_score"), _cap), _cap,
                        )
                        finding["confidence"] = finding["confidence_score"]
                        finding["fp_reason"] = _eqg_verdict.reason
                        finding["evidence_gate_signals"] = _eqg_verdict.signals_found
                        false_positives.append(finding)
                        return

                    # OOB findings go through normal FP analysis (no fast-track bypass)
                    # DNS callbacks from CDN/proxy IPs are a known FP source

                    finding_obj = _dict_to_finding(finding) if isinstance(finding, dict) else finding
                    verdict = await asyncio.wait_for(
                        detector.analyze(finding_obj),
                        timeout=300.0,  # Per-finding timeout — 5min cap
                    )

                    if verdict.verdict == "false_positive":
                        finding["fp_reason"] = verdict.reasoning or "FP detected"
                        false_positives.append(finding)
                    else:
                        confidence = verdict.confidence_score
                        finding["confidence_score"] = confidence
                        finding["confidence"] = confidence
                        # Propagate FPVerdict fields for downstream audit trail (v4.0 Bug1)
                        if getattr(verdict, "known_fp_capped", False):
                            finding["_known_fp_capped"] = True
                        finding["fp_verdict"] = getattr(verdict, "verdict", "")
                        finding["fp_status"] = getattr(verdict, "status", "")
                        if getattr(verdict, "waf_detected", False):
                            finding["waf_detected"] = True
                        _ev_chain = getattr(verdict, "evidence_chain", None)
                        if _ev_chain:
                            finding["fp_evidence_chain"] = _ev_chain
                        _fp_reasoning = getattr(verdict, "reasoning", "")
                        if _fp_reasoning:
                            finding["fp_reasoning"] = _fp_reasoning

                        # Severity-tiered reporting threshold:
                        # MEDIUM+ needs ≥60 confidence, LOW/INFO keeps ≥50
                        _sev_str = str(finding.get("severity", "low")).lower()
                        _min_conf = 60.0 if _sev_str in ("medium", "high", "critical") else 50.0
                        if confidence >= _min_conf:
                            verified.append(finding)
                        else:
                            finding["fp_reason"] = f"Low confidence: {confidence}"
                            false_positives.append(finding)
                except asyncio.TimeoutError:
                    logger.warning(f"FP analysis timed out for: {finding.get('title', '?')[:50]}")
                    # Timeout → apply penalty instead of auto-pass (v4.0)
                    _orig_conf = _safe_float(finding.get("confidence_score") or finding.get("confidence"), 40.0)
                    _penalised = max(0.0, _orig_conf - 20.0)
                    finding["confidence_score"] = _penalised
                    finding["confidence"] = _penalised
                    finding["fp_status"] = "timeout"
                    if _penalised >= 50:
                        verified.append(finding)
                    else:
                        finding["fp_reason"] = f"FP timeout penalty: {_orig_conf:.0f}→{_penalised:.0f}"
                        false_positives.append(finding)
                except Exception as e:
                    logger.warning(f"FP check failed for finding: {e}")
                    # FP check failure → apply penalty (v4.0)
                    _orig_conf = _safe_float(finding.get("confidence_score") or finding.get("confidence"), 40.0)
                    _penalised = max(0.0, _orig_conf - 20.0)
                    finding["confidence_score"] = _penalised
                    finding["confidence"] = _penalised
                    if _penalised >= 50:
                        verified.append(finding)
                    else:
                        finding["fp_reason"] = f"FP check error penalty: {_orig_conf:.0f}→{_penalised:.0f}"
                        false_positives.append(finding)
                finally:
                    # ── Incremental save: sync partial results to state ──
                    state.verified_findings = list(verified)
                    state.false_positives = list(false_positives)

        # Launch all analyses in parallel (semaphore-limited)
        # Sort by severity so HIGH/CRITICAL findings are processed first
        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        _sorted_findings = sorted(
            raw_findings,
            key=lambda f: _sev_order.get(str(f.get("severity", "medium")).lower(), 3),
        )
        _gather_results = await asyncio.gather(
            *[_analyze_one(f) for f in _sorted_findings],
            return_exceptions=True,
        )
        # Log any unexpected exceptions from the gather
        for _gr in _gather_results:
            if isinstance(_gr, Exception):
                logger.warning(f"Unexpected FP analysis exception: {_gr}")

        logger.info(
            f"FP initial analysis complete | verified={len(verified)} | "
            f"fp={len(false_positives)}"
        )

        # ── LLM-Powered Deep Verification for high-value findings ──
        intel = state.intelligence_engine
        if intel and intel.is_available and verified:
            logger.info(f"🧠 Running LLM verification on {len(verified)} findings...")
            # Skip brain for deterministic tools with high confidence —
            # header_checker / cookie_checker produce binary results.
            _DETERMINISTIC_HIGH_TOOLS = {"header_checker", "cookie_checker"}
            _OOB_TOOLS = {"interactsh"}
            # Only deep-verify HIGH+ severity or confidence>=60 findings (expensive)
            high_value = [f for f in verified if
                          ((f.get("severity") or "").lower() in ("high", "critical") or
                           f.get("confidence_score", 0) >= 60)
                          and not (f.get("tool", "") in _DETERMINISTIC_HIGH_TOOLS
                                   and f.get("confidence_score", 0) >= 90)
                          and f.get("tool", "") not in _OOB_TOOLS]
            if not high_value:
                high_value = verified[:5]  # At least verify top 5

            brain_sem = asyncio.Semaphore(2)  # Max 2 concurrent LLM calls

            async def _verify_one(finding: dict[str, Any]) -> None:
                """Brain-verify a single finding (mutates finding dict in place)."""
                async with brain_sem:
                    try:
                        vr = await asyncio.wait_for(
                            intel.verify_finding(
                                finding=finding,
                                http_request=finding.get("http_request", ""),
                                http_response=finding.get("http_response", ""),
                            ),
                            timeout=1200.0,  # Per-finding brain verification timeout
                        )

                        if vr.confidence > 0:
                            finding["brain_verified"] = True
                            finding["brain_confidence"] = vr.confidence
                            finding["brain_reasoning"] = vr.reasoning
                            finding["exploit_feasibility"] = vr.exploit_feasibility

                            # Brain confidence always influences final score.
                            # D4: Asymmetric weighting — brain can upgrade freely,
                            # but downgrades are more conservative to protect
                            # tool-confirmed findings from brain uncertainty.
                            original_conf = _safe_float(finding.get("confidence_score"), 50.0)  # Bug 5.2l-4: was bare .get() without _safe_float
                            if vr.confidence >= original_conf:
                                # Brain upgrades — trust the brain more
                                merged = vr.confidence * 0.6 + original_conf * 0.4
                            else:
                                # Brain downgrades — be conservative, tool evidence matters
                                merged = vr.confidence * 0.3 + original_conf * 0.7
                            finding["confidence_score"] = round(merged, 1)

                            # Strong brain conviction can override further
                            if vr.confidence >= 80:
                                # Brain is very confident — floor at brain value
                                finding["confidence_score"] = max(
                                    finding["confidence_score"],
                                    vr.confidence
                                )
                            elif vr.confidence <= 30 and not vr.is_real:
                                # Brain says likely FP
                                if original_conf >= 80:
                                    # Detector had strong evidence — brain cannot
                                    # override with veto cap.  Keep merged score.
                                    # merged = brain*0.3 + det*0.7 already penalises.
                                    pass
                                else:
                                    # Detector was uncertain — apply additional
                                    # penalty but don't fully discard tool evidence
                                    finding["confidence_score"] = max(
                                        finding["confidence_score"] - 10,
                                        vr.confidence,
                                    )
                                finding["brain_fp_warning"] = vr.reasoning

                            # ── Guard 4a: KnownFP ceiling preservation (v4.0) ──
                            # If FPDetector capped this finding via KnownFP penalty,
                            # brain verification must NOT push it back above the ceiling.
                            if finding.get("_known_fp_capped"):
                                _KFP_CEIL = 49.9
                                if finding["confidence_score"] > _KFP_CEIL:
                                    logger.debug(
                                        f"Guard 4a: brain tried to elevate KnownFP-capped "
                                        f"finding to {finding['confidence_score']:.1f}, "
                                        f"re-capping at {_KFP_CEIL}"
                                    )
                                    finding["confidence_score"] = _KFP_CEIL

                            # Sync confidence field with confidence_score (v4.0)
                            finding["confidence"] = finding["confidence_score"]

                            # Store PoC steps from brain
                            if vr.suggested_poc_steps:
                                finding["brain_poc_steps"] = vr.suggested_poc_steps

                            if vr.cvss_override is not None:
                                finding["cvss_score"] = vr.cvss_override

                            logger.info(
                                f"  🧠 Verified: {finding.get('title', '?')[:50]} | "
                                f"brain_conf={vr.confidence:.0f} | "
                                f"feasibility={vr.exploit_feasibility}"
                            )
                    except asyncio.TimeoutError:
                        logger.warning(f"Brain verification timed out for: {finding.get('title', '?')[:50]}")
                    except Exception as e:
                        logger.warning(f"Brain verification failed for finding: {e}")

            # Run brain verifications in parallel (semaphore-limited)
            await asyncio.gather(
                *[_verify_one(f) for f in high_value[:6]],
                return_exceptions=True,
            )

        # ── Post-brain confidence re-filter ──
        # Brain may have downgraded some findings below quality gate (v4.0 Bug2: 30→50)
        post_verified: list[dict[str, Any]] = []
        for f in verified:
            cs = _safe_float(f.get("confidence_score"), 0.0)
            if cs < 50:
                f["fp_reason"] = f"Brain downgraded confidence to {cs:.0f}"
                false_positives.append(f)
                logger.debug(f"Post-brain FP: {f.get('title','?')[:50]} conf={cs}")
            else:
                post_verified.append(f)
        verified = post_verified

        # ── Evidence Chain Construction ──
        # Build cryptographic evidence chains for verified findings
        try:
            from src.fp_engine.scoring.evidence_chain import EvidenceChainBuilder
            ec_builder = EvidenceChainBuilder()
            chains_built = 0
            for f in verified:
                fid = f.get("id", f.get("title", "unknown")[:30])
                vtype = f.get("vulnerability_type", f.get("type", "unknown"))
                chain = ec_builder.create_chain(
                    finding_id=str(fid),
                    finding_title=f.get("title", "Untitled"),
                    vulnerability_type=vtype,
                )
                # Add tool output evidence
                tool_name = f.get("tool", "unknown")
                if f.get("evidence"):
                    ec_builder.add_tool_output(
                        chain, tool_name=tool_name, output=str(f["evidence"])
                    )
                # Add HTTP evidence if available
                http_req = f.get("http_request", "")
                http_resp = f.get("http_response", "")
                if http_req or http_resp:
                    ec_builder.add_http_evidence(
                        chain,
                        method=f.get("method", "GET"),
                        url=f.get("url", f.get("target", "")),
                        request_body=http_req if isinstance(http_req, str) else "",
                        response_body=http_resp[:5000] if isinstance(http_resp, str) else "",
                        response_status=f.get("status_code", 0),
                        payload=f.get("payload", ""),
                        parameter=f.get("parameter", ""),
                    )
                # Add brain analysis evidence
                if f.get("brain_verified") and f.get("brain_reasoning"):
                    ec_builder.add_brain_analysis(
                        chain, analysis=f["brain_reasoning"]
                    )
                ec_builder.finalize(chain)
                f["evidence_chain_id"] = chain.chain_id
                f["evidence_completeness"] = chain.completeness_score
                chains_built += 1
            if chains_built:
                logger.info(f"Evidence chains built: {chains_built}/{len(verified)}")
                state.metadata["evidence_chains"] = [
                    c.model_dump() for c in ec_builder.get_all_chains()
                ]
        except Exception as exc:
            logger.warning(f"Evidence chain construction failed (non-critical): {exc}")

        # ── Two-pass dedup: 1) same-tool exact, 2) cross-tool same-vuln ──
        from urllib.parse import urlparse, parse_qs, urlencode

        _DEFAULT_PORTS = {"http": "80", "https": "443"}

        def _normalize_url(url: Any) -> str:
            """Normalize URL for dedup: lowercase scheme+host, sort params, strip defaults."""
            if isinstance(url, list):
                url = url[0] if url else ""
            if not isinstance(url, str):
                url = str(url)
            try:
                p = urlparse(url.strip())
                scheme = (p.scheme or "https").lower()
                host = (p.netloc or "").lower()
                # Strip default ports (http:80, https:443)
                for s, dp in _DEFAULT_PORTS.items():
                    if scheme == s and host.endswith(f":{dp}"):
                        host = host[: -(len(dp) + 1)]
                path = p.path.rstrip("/") or "/"
                qs = parse_qs(p.query, keep_blank_values=False)
                sorted_qs = urlencode(sorted(qs.items()), doseq=True)
                return f"{scheme}://{host}{path}?{sorted_qs}" if sorted_qs else f"{scheme}://{host}{path}"
            except Exception:
                return url.strip().rstrip("/").lower()

        # Pass 1: Same tool + same normalized title → keep highest confidence
        seen: dict[str, dict[str, Any]] = {}
        for f in verified:
            raw_title = (f.get("title") or "").strip()
            norm_title = raw_title[:80].lower()
            tool = f.get("tool", "")
            key = f"{norm_title}||{tool}"
            existing = seen.get(key)
            if existing is None:
                seen[key] = f
            else:
                if f.get("confidence_score", 0) > existing.get("confidence_score", 0):
                    seen[key] = f
        pass1 = list(seen.values())
        dup_count_1 = len(verified) - len(pass1)

        # Pass 2: Cross-tool — same vuln type + same URL + same parameter
        # Use synonym normalization to catch cross-tool naming differences early
        _VULN_SYNONYMS: dict[str, str] = {
            # XSS
            "xss_reflected": "xss", "xss_stored": "xss", "xss_dom": "xss",
            "cross_site_scripting": "xss", "reflected_xss": "xss",
            "stored_xss": "xss", "dom_xss": "xss", "dom_based_xss": "xss",
            # SQLi
            "sqli_error": "sqli", "sqli_blind": "sqli", "sqli_union": "sqli",
            "sql_injection": "sqli", "blind_sql_injection": "sqli",
            "blind_sqli": "sqli", "error_based_sqli": "sqli",
            "union_based_sqli": "sqli", "time_based_sqli": "sqli",
            # SSRF
            "server_side_request_forgery": "ssrf",
            # SSTI
            "server_side_template_injection": "ssti", "template_injection": "ssti",
            # RCE
            "command_injection": "rce", "remote_code_execution": "rce",
            "os_command_injection": "rce", "cmd_injection": "rce",
            # Redirect
            "open_redirect": "redirect", "url_redirect": "redirect",
            "open_redirection": "redirect", "openredirect": "redirect",
            # CORS
            "cors_misconfiguration": "cors", "cors_misconfig": "cors",
            # CRLF
            "crlf_injection": "crlf", "header_injection": "crlf",
            # Info disclosure
            "info_disclosure": "information_disclosure",
            "sensitive_data_exposure": "information_disclosure",
            "information_exposure": "information_disclosure",
            # LFI/RFI
            "local_file_inclusion": "lfi", "path_traversal": "lfi",
            "directory_traversal": "lfi", "remote_file_inclusion": "rfi",
            # XXE
            "xml_external_entity": "xxe",
            # IDOR
            "insecure_direct_object_reference": "idor",
            # CSRF
            "cross_site_request_forgery": "csrf",
            # NoSQLi
            "nosql_injection": "nosqli",
            # JWT
            "jwt_vulnerability": "jwt", "jwt_misconfiguration": "jwt",
            # Deserialization
            "insecure_deserialization": "deserialization",
            # HTTP smuggling
            "http_request_smuggling": "http_smuggling",
            "request_smuggling": "http_smuggling",
            # Subdomain takeover
            "sub_takeover": "subdomain_takeover",
        }

        def _canonical_vtype(vt: str) -> str:
            return _VULN_SYNONYMS.get(vt, vt)

        seen2: dict[str, dict[str, Any]] = {}
        for f in pass1:
            vtype = _canonical_vtype(
                (f.get("vulnerability_type") or f.get("type") or "unknown").lower()
            )
            url = _normalize_url(f.get("url", f.get("target", "")))
            param = (f.get("parameter") or "").lower()
            key = f"{vtype}||{url}||{param}"
            existing = seen2.get(key)
            if existing is None:
                seen2[key] = f
            else:
                # Keep higher confidence; merge tool sources
                if f.get("confidence_score", 0) > existing.get("confidence_score", 0):
                    # Carry over the other tool's name for provenance
                    prev_tool = existing.get("tool", "")
                    seen2[key] = f
                    if prev_tool:
                        f.setdefault("also_found_by", []).append(prev_tool)
                else:
                    cur_tool = f.get("tool", "")
                    if cur_tool:
                        existing.setdefault("also_found_by", []).append(cur_tool)
        deduped = list(seen2.values())
        dup_count_2 = len(pass1) - len(deduped)

        # Pass 3: Semantic dedup — group by URL-path + vuln-type synonym
        # Handles cases where different params at same path are the same vuln
        def _url_path(url: Any) -> str:
            if isinstance(url, list):
                url = url[0] if url else ""
            if not isinstance(url, str):
                url = str(url)
            try:
                p = urlparse(url.strip())
                host = (p.netloc or "").lower()
                path = p.path.rstrip("/") or "/"
                return f"{host}{path}"
            except Exception:
                return url.lower()

        seen3: dict[str, dict[str, Any]] = {}
        for f in deduped:
            vtype = _canonical_vtype(
                (f.get("vulnerability_type") or f.get("type") or "unknown").lower()
            )
            path = _url_path(f.get("url", f.get("target", "")))
            key = f"{vtype}||{path}"
            existing = seen3.get(key)
            if existing is None:
                seen3[key] = f
            else:
                if f.get("confidence_score", 0) > existing.get("confidence_score", 0):
                    prev_tool = existing.get("tool", "")
                    seen3[key] = f
                    if prev_tool:
                        f.setdefault("also_found_by", []).append(prev_tool)
                else:
                    cur_tool = f.get("tool", "")
                    if cur_tool:
                        existing.setdefault("also_found_by", []).append(cur_tool)
        semantic_deduped = list(seen3.values())
        dup_count_3 = len(deduped) - len(semantic_deduped)

        total_deduped = dup_count_1 + dup_count_2 + dup_count_3
        if total_deduped:
            logger.info(
                f"Deduped {total_deduped} findings "
                f"(same-tool={dup_count_1}, cross-tool={dup_count_2}, "
                f"semantic={dup_count_3})"
            )
        verified = semantic_deduped

        # ── Confidence Calibration (T2-5) ──
        # Apply historical calibration to adjust confidence scores, then
        # record current outcomes for future calibration.
        try:
            from src.fp_engine.scoring.calibration import ConfidenceCalibrator

            calibrator = ConfidenceCalibrator()
            calibrator.load()

            # Apply calibration to verified findings
            for f in verified:
                vt = f.get("vulnerability_type", f.get("type", ""))
                raw_conf = _safe_float(f.get("confidence_score"), 0.0)  # Bug 5.2l-2: was 50.0
                if vt:
                    adj = calibrator.calibrate(vt, raw_conf)
                    # ── Guard 4b: KnownFP ceiling preservation (v4.0) ──
                    if f.get("_known_fp_capped") and adj > 49.9:
                        logger.debug(
                            f"Guard 4b: calibrator tried to elevate KnownFP-capped "
                            f"finding to {adj:.1f}, re-capping at 49.9"
                        )
                        adj = 49.9
                    if adj != raw_conf:
                        f["confidence_score_raw"] = raw_conf
                        f["confidence_score"] = adj
                        f["confidence"] = adj  # Keep fields in sync (v4.0)

            # Record outcomes: verified = TP, false_positives = FP
            for f in verified:
                vt = f.get("vulnerability_type", f.get("type", ""))
                conf = _safe_float(f.get("confidence_score_raw", f.get("confidence_score")), 0.0)  # Bug 5.2l-3: was 50.0
                if vt:
                    calibrator.record(vt, conf, was_true_positive=True)
            for f in false_positives:
                vt = f.get("vulnerability_type", f.get("type", ""))
                conf = _safe_float(f.get("confidence_score"), 0.0)  # Bug 5.2l-3: was 50.0
                if vt:
                    calibrator.record(vt, conf, was_true_positive=False)

            calibrator.save()
            state.metadata["calibration_summary"] = calibrator.summary()
        except Exception as cal_err:
            logger.debug(f"Confidence calibration skipped: {cal_err}")

        # ── Confidence → Severity Calibration (P2-5) ──
        # Low-confidence findings should not keep high severity ratings.
        _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        _sev_downgrades = 0
        for f in verified:
            conf = _safe_float(f.get("confidence_score", 0.0), 0.0)
            sev = str(f.get("severity", "medium")).lower()
            sev_rank = _SEVERITY_ORDER.get(sev, 2)

            new_sev = sev
            if conf < 40 and sev_rank >= 2:
                # Very low confidence → cap at LOW
                new_sev = "low"
            elif conf < 50 and sev_rank >= 3:
                # Low confidence + HIGH/CRITICAL → downgrade to MEDIUM
                new_sev = "medium"
            elif conf < 65 and sev_rank >= 4:
                # Below-threshold confidence + CRITICAL → downgrade to HIGH
                new_sev = "high"

            if new_sev != sev:
                f["original_severity"] = sev
                f["severity"] = new_sev
                f["severity_downgrade_reason"] = (
                    f"Severity downgraded {sev}→{new_sev} due to low confidence ({conf:.0f}%)"
                )
                _sev_downgrades += 1

        if _sev_downgrades:
            logger.info(f"Severity calibration: {_sev_downgrades} findings downgraded due to low confidence")

        # ── P6.2: Multi-Stage Verification Gate for CRITICAL/HIGH ──
        # CRITICAL findings require confidence ≥ 75 AND at least one strong
        # evidence keyword to remain at that severity level.
        # HIGH findings require confidence ≥ 70.
        _STRONG_EVIDENCE_KEYWORDS = {
            "reflected", "injected", "executed", "extracted", "callback",
            "confirmed", "oob", "verified", "exploit", "shell", "uid=",
            "root:", "admin", "token", "secret", "dumped",
        }
        _ms_downgrades = 0
        for f in verified:
            sev = str(f.get("severity", "")).lower()
            conf = _safe_float(f.get("confidence_score", 0.0), 0.0)
            _ev_text = str(f.get("evidence", "")).lower()

            if sev == "critical" and conf < 75.0:
                _has_strong = any(kw in _ev_text for kw in _STRONG_EVIDENCE_KEYWORDS)
                if not _has_strong:
                    f["severity"] = "high"
                    f["multi_stage_downgrade"] = f"CRITICAL→HIGH: confidence {conf:.0f}% < 75 without strong evidence"
                    _ms_downgrades += 1

            elif sev == "high" and conf < 70.0:
                _has_strong = any(kw in _ev_text for kw in _STRONG_EVIDENCE_KEYWORDS)
                if not _has_strong:
                    f["severity"] = "medium"
                    f["multi_stage_downgrade"] = f"HIGH→MEDIUM: confidence {conf:.0f}% < 70 without strong evidence"
                    _ms_downgrades += 1

        if _ms_downgrades:
            logger.info(f"Multi-stage verification: {_ms_downgrades} HIGH/CRITICAL findings downgraded")

        state.verified_findings = verified
        state.false_positives = false_positives

        # ── V24: Record FP verdicts for cross-scan learning ──
        try:
            from src.fp_engine.learning.fp_feedback import FPFeedbackManager
            _fp_fb = FPFeedbackManager()
            _fb_records: list[dict[str, Any]] = []
            for _vf in verified:
                _fb_records.append({
                    "finding_id": _vf.get("title", "")[:80],
                    "vuln_type": _vf.get("vulnerability_type") or _vf.get("type", ""),
                    "tool": _vf.get("tool", ""),
                    "endpoint": _vf.get("url") or _vf.get("endpoint", ""),
                    "verdict": "true_positive",
                    "verdict_source": "fp_engine",
                    "reason": "Passed FP elimination",
                    "confidence_score": _safe_float(_vf.get("confidence_score"), 0.0),  # Bug 5.2l-6: was 50.0
                })
            for _fpf in false_positives:
                _fb_records.append({
                    "finding_id": _fpf.get("title", "")[:80],
                    "vuln_type": _fpf.get("vulnerability_type") or _fpf.get("type", ""),
                    "tool": _fpf.get("tool", ""),
                    "endpoint": _fpf.get("url") or _fpf.get("endpoint", ""),
                    "verdict": "false_positive",
                    "verdict_source": "fp_engine",
                    "reason": _fpf.get("fp_reason", "Detected as FP"),
                    "fp_pattern_matched": _fpf.get("fp_pattern", ""),
                })
            if _fb_records:
                _fp_fb.record_batch(_fb_records)
                logger.info(
                    f"FP feedback recorded: {len(verified)} TP + "
                    f"{len(false_positives)} FP = {len(_fb_records)} records"
                )
                state.metadata["fp_feedback_recorded"] = len(_fb_records)
        except ImportError:
            pass
        except Exception as _fp_fb_exc:
            logger.warning(f"FP feedback recording failed: {_fp_fb_exc}")

        # AssetDB: doğrulanmış bulguları kaydet
        _adb.save_verified_findings(state)

        result.data = {
            "verified": len(verified),
            "false_positives": len(false_positives),
            "elimination_rate": (
                len(false_positives) / len(raw_findings) * 100
                if raw_findings else 0
            ),
        }
        result.findings_count = len(verified)
        result.success = True

        logger.info(
            f"FP elimination complete | verified={len(verified)} | "
            f"fp={len(false_positives)} | "
            f"rate={result.data['elimination_rate']:.1f}%"
        )

    except Exception as e:
        logger.error(f"FP elimination failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_reporting(state: WorkflowState) -> StageResult:
    """
    Aşama 8: Raporlama

    Doğrulanmış bulgular için profesyonel raporlar oluşturur.
    """
    result = StageResult(stage=WorkflowStage.REPORTING)

    try:
        findings = state.verified_findings

        # Fallback: if FP elimination didn't run or failed, use raw findings
        if not findings and state.raw_findings:
            logger.warning(
                "No verified findings available — falling back to raw_findings "
                f"({len(state.raw_findings)} unverified)"
            )
            findings = state.raw_findings
            # Mark as UNVERIFIED with LOW confidence — these bypassed FP engine (v4.0 Bug5)
            for f in findings:
                if isinstance(f, dict):
                    _existing = _safe_float(f.get("confidence_score") or f.get("confidence"), 0.0)
                    _fallback_conf = min(_existing, 40.0) if _existing > 0 else 25.0
                    f["confidence_score"] = _fallback_conf
                    f["confidence"] = _fallback_conf
                    f["fp_status"] = "UNVERIFIED_FALLBACK"

        # ── Normalize URL fields — coerce list values to strings ──
        for _f in findings:
            if isinstance(_f, dict):
                for _key in ("url", "endpoint", "target"):
                    _v = _f.get(_key)
                    if isinstance(_v, list):
                        _f[_key] = _v[0] if _v else ""
                    elif _v is not None and not isinstance(_v, str):
                        _f[_key] = str(_v)

        logger.info(f"Report generation started | findings={len(findings)}")

        if not findings:
            result.data = {"message": "No verified findings to report"}
            result.success = True
            return result

        # ── V24: Risk-based finding prioritization ──
        try:
            from src.brain.reasoning.risk_assessor import RiskAssessor
            _ra = RiskAssessor()
            _prioritized = _ra.prioritise_findings(findings)
            if _prioritized and len(_prioritized) == len(findings):
                # Annotate original dicts with risk data — do NOT replace
                for _f_dict, _r_assess in zip(findings, _prioritized):
                    _f_dict["risk_score"] = _r_assess.risk_score
                    _f_dict["priority_rank"] = _r_assess.priority_rank
                    _f_dict["risk_level"] = str(_r_assess.risk_level.value) if hasattr(_r_assess.risk_level, "value") else str(_r_assess.risk_level)
                # Re-sort findings by risk_score descending
                findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
                logger.info(f"Findings prioritized by risk score (RiskAssessor)")
                state.metadata["risk_prioritized"] = True
            else:
                logger.debug(f"RiskAssessor returned {len(_prioritized) if _prioritized else 0} assessments for {len(findings)} findings — skipping annotation")
        except ImportError:
            pass
        except Exception as _ra_exc:
            logger.warning(f"RiskAssessor prioritization skipped: {_ra_exc}")

        # ── LLM-Powered Finding Enrichment ──
        # Budget timer: cap total brain time in reporting to 300s to prevent
        # cumulative timeouts from stalling the entire stage.
        import time as _time
        _brain_budget_start = _time.monotonic()
        _BRAIN_BUDGET_SECONDS = 300.0  # 5 min total for all brain ops

        def _brain_budget_remaining() -> float:
            return max(0.0, _BRAIN_BUDGET_SECONDS - (_time.monotonic() - _brain_budget_start))

        intel = state.intelligence_engine
        _OOB_SKIP_TOOLS = {"interactsh"}
        if intel and intel.is_available:
            # Enrich HIGH/CRITICAL findings with professional narrative
            # Skip OOB/interactsh findings — DNS callbacks don't benefit from enrichment
            enrichable = [f for f in findings if
                          isinstance(f, dict) and
                          (f.get("severity") or "").lower() in ("high", "critical", "medium") and
                          (f.get("brain_confidence", 0) or f.get("confidence_score", 0)) >= 40
                          and f.get("tool", "") not in _OOB_SKIP_TOOLS]
            # Sort by confidence, enrich top ones first
            enrichable.sort(key=lambda x: x.get("brain_confidence", 0) or x.get("confidence_score", 0), reverse=True)
            if enrichable:
                logger.info(f"🧠 Enriching {len(enrichable[:3])} findings with LLM analysis...")
                for finding in enrichable[:3]:
                    if _brain_budget_remaining() < 10:
                        logger.info("⏱️ Brain budget depleted — skipping remaining enrichments")
                        break
                    try:
                        _timeout = min(1200.0, _brain_budget_remaining())
                        enriched = await asyncio.wait_for(
                            intel.enrich_report_finding(
                                finding=finding,
                                http_evidence=finding.get("http_request", "") + "\n---\n" + finding.get("http_response", ""),
                            ),
                            timeout=_timeout,
                        )
                        # Merge enriched data back into the original finding dict
                        if isinstance(enriched, dict) and enriched is not finding:
                            finding.update(enriched)
                    except asyncio.TimeoutError:
                        logger.warning(f"Brain enrichment timed out for: {finding.get('title', '?')[:50]}")
                    except Exception as e:
                        logger.warning(f"Brain enrichment failed for finding: {e}")

            # Generate PoC for HIGH+ findings (skip OOB/interactsh)
            high_findings = [f for f in findings if
                             isinstance(f, dict) and
                             (f.get("severity") or "").lower() in ("high", "critical") and
                             f.get("confidence_score", 0) >= 60
                             and f.get("tool", "") not in _OOB_SKIP_TOOLS]
            if high_findings:
                logger.info(f"🧠 Generating PoCs for {len(high_findings[:2])} high-value findings...")
                import os
                poc_dir = f"output/evidence/{state.session_id}/pocs"
                os.makedirs(poc_dir, exist_ok=True)

                for finding in high_findings[:2]:
                    if _brain_budget_remaining() < 10:
                        logger.info("⏱️ Brain budget depleted — skipping remaining PoC generation")
                        break
                    try:
                        _timeout = min(1200.0, _brain_budget_remaining())
                        poc = await asyncio.wait_for(
                            intel.generate_poc(
                                finding=finding,
                                http_request=finding.get("http_request", ""),
                                http_response=finding.get("http_response", ""),
                            ),
                            timeout=_timeout,
                        )
                        if poc and poc.script_content:
                            # Save PoC script
                            safe_title = "".join(c if c.isalnum() else "_" for c in finding.get("title", "poc")[:40])
                            poc_path = os.path.join(poc_dir, f"{safe_title}.py")
                            with open(poc_path, "w") as fh:
                                fh.write(poc.script_content)
                            finding["poc_script_path"] = poc_path
                            finding["poc_curl"] = poc.curl_command
                            finding["poc_browser_steps"] = poc.browser_steps
                            logger.info(f"  📝 PoC saved: {poc_path}")
                    except asyncio.TimeoutError:
                        logger.warning(f"PoC generation timed out for: {finding.get('title', '?')[:50]}")
                    except Exception as e:
                        logger.warning(f"PoC generation failed: {e}")

        # ── LLM-Powered Attack Chain Correlation ──
        if intel and intel.is_available and len(findings) >= 2 and _brain_budget_remaining() > 15:
            try:
                from src.brain.prompts.analysis_prompts import (
                    CORRELATION_SYSTEM,
                    build_finding_correlation_prompt,
                )
                from src.brain.engine import BrainType

                corr_findings = []
                for f in findings:
                    if isinstance(f, dict):
                        corr_findings.append({
                            "type": f.get("vulnerability_type", f.get("type", "unknown")),
                            "severity": f.get("severity", "info"),
                            "endpoint": f.get("url", f.get("endpoint", "")),
                            "tool": f.get("tool_name", f.get("source_tool", "")),
                            "title": f.get("title", ""),
                        })

                corr_prompt = build_finding_correlation_prompt(corr_findings, state.target)
                _budget_remaining = _brain_budget_remaining()
                if _budget_remaining < 5.0:
                    logger.warning("Brain budget exhausted, skipping correlation")
                else:
                    corr_response = await asyncio.wait_for(
                        state.brain_engine.think(
                            prompt=corr_prompt,
                            system_prompt=CORRELATION_SYSTEM,
                            brain=BrainType.PRIMARY,
                            temperature=0.2,
                        ),
                        timeout=min(1200.0, _budget_remaining),
                    )

                    # Parse correlation result using shared JSON extractor
                    corr_text = corr_response.text.strip()
                    from src.utils.json_utils import extract_json as _extract_json
                    corr_data = _extract_json(corr_text, log_failures=True)
                    if corr_data:
                        chains = corr_data.get("attack_chains", [])
                        if chains:
                            logger.info(f"🧠 Attack chain correlation: {len(chains)} chain(s) discovered")
                            # Store chains in state for report
                            state.metadata = state.metadata or {}
                            state.metadata["attack_chains"] = chains
                            # Log chain summaries
                            for chain in chains[:5]:
                                logger.info(
                                    f"  🔗 {chain.get('name', 'Chain')}: "
                                    f"impact={chain.get('combined_impact', '?')} | "
                                    f"{chain.get('narrative', '')[:100]}"
                                )
                        systemic = corr_data.get("systemic_issues", [])
                        if systemic:
                            state.metadata["systemic_issues"] = systemic
                            logger.info(f"🧠 Systemic issues: {len(systemic)} pattern(s)")
            except asyncio.TimeoutError:
                logger.warning("Attack chain correlation timed out")
            except Exception as exc:
                logger.warning(f"Attack chain correlation failed: {exc}")

        # ── Screenshot Capture for PoC-confirmed / HIGH+ findings ──
        try:
            from src.reporting.evidence.screenshot import ScreenshotCapture, ScreenshotConfig

            ss_config = ScreenshotConfig(
                output_dir=f"output/screenshots/{state.session_id}",
                timeout_seconds=20,
                delay_ms=1500,
            )
            ss_capture = ScreenshotCapture(config=ss_config)
            if ss_capture.is_available:
                # Screenshot findings that have PoC or HIGH/CRITICAL severity
                ss_findings = [
                    f for f in findings
                    if isinstance(f, dict)
                    and (
                        f.get("poc_confirmed")
                        or str(f.get("severity", "")).lower() in ("high", "critical")
                    )
                    and isinstance(f.get("url", ""), str)
                    and f.get("url", "").startswith("http")
                ]
                if ss_findings:
                    ss_urls = list(dict.fromkeys(f["url"] for f in ss_findings))[:8]
                    ss_results = await ss_capture.capture_multiple(
                        ss_urls, max_concurrent=2,
                    )
                    captured = [r for r in ss_results if r.success]
                    # Attach screenshot paths to findings
                    ss_path_map = {r.url: r.file_path for r in captured}
                    for f in findings:
                        if isinstance(f, dict) and f.get("url") in ss_path_map:
                            f["screenshot_path"] = ss_path_map[f["url"]]
                    if captured:
                        logger.info(
                            f"📸 Finding screenshots: {len(captured)}/{len(ss_urls)} captured"
                        )
        except Exception as ss_err:
            logger.debug(f"Finding screenshot capture skipped: {ss_err}")

        from src.reporting.report_generator import ReportGenerator

        # ── Quality Gates: Filter and normalize findings BEFORE report ──
        _pre_gate_count = len(findings)

        # Gate 1: Confidence threshold — exclude low-confidence findings
        _CONFIDENCE_THRESHOLD = 50.0
        _low_confidence = []
        _report_findings = []
        for f in findings:
            if isinstance(f, dict):
                # Use explicit None check to avoid falsy-zero trap (v4.0):
                # confidence_score=0 is falsy, `or` would fall through to `confidence`
                _cs_raw = f.get("confidence_score")
                if _cs_raw is None:
                    _cs_raw = f.get("confidence")
                conf = _safe_float(_cs_raw, 0.0)
                if conf < _CONFIDENCE_THRESHOLD:
                    _low_confidence.append(f)
                else:
                    _report_findings.append(f)
            else:
                _report_findings.append(f)
        if _low_confidence:
            logger.info(
                f"📊 Confidence gate: {len(_low_confidence)} findings excluded "
                f"(confidence < {_CONFIDENCE_THRESHOLD}%)"
            )
            state.metadata = state.metadata or {}
            state.metadata["low_confidence_excluded"] = len(_low_confidence)

        # Gate 2: CVSS-Severity consistency enforcement
        for f in _report_findings:
            if not isinstance(f, dict):
                continue
            cvss = f.get("cvss_score")
            sev = (f.get("severity") or "info").lower()
            if cvss is not None and isinstance(cvss, (int, float)) and cvss > 0:
                # Enforce: CVSS < 4.0 → max severity LOW
                if cvss < 4.0 and sev in ("medium", "high", "critical"):
                    f["original_severity"] = f["severity"]
                    f["severity"] = "low"
                    f["severity_reconciled"] = True
                    logger.debug(f"CVSS-severity reconciled: CVSS {cvss} → LOW (was {sev})")
                # CVSS < 7.0 → max severity MEDIUM
                elif cvss < 7.0 and sev in ("high", "critical"):
                    f["original_severity"] = f["severity"]
                    f["severity"] = "medium"
                    f["severity_reconciled"] = True
                    logger.debug(f"CVSS-severity reconciled: CVSS {cvss} → MEDIUM (was {sev})")
                # Bug 5.2m-2: Upward reconciliation — CVSS >= 9.0 but severity is LOW
                elif cvss >= 9.0 and sev in ("low", "info"):
                    f["original_severity"] = f["severity"]
                    f["severity"] = "high"
                    f["severity_reconciled"] = True
                    logger.debug(f"CVSS-severity reconciled UP: CVSS {cvss} → HIGH (was {sev})")
                elif cvss >= 7.0 and sev in ("low", "info"):
                    f["original_severity"] = f["severity"]
                    f["severity"] = "medium"
                    f["severity_reconciled"] = True
                    logger.debug(f"CVSS-severity reconciled UP: CVSS {cvss} → MEDIUM (was {sev})")

        # Gate 3: vulnerability_type normalization for empty/unknown types
        _VULN_TYPE_INFER = {
            "race condition": "race_condition",
            "email header injection": "header_injection",
            "file upload": "file_upload",
            "graphql": "graphql",
            "rate limit": "rate_limit_bypass",
            "cors": "cors_misconfiguration",
            "open redirect": "open_redirect",
            "subdomain takeover": "subdomain_takeover",
            "info disclosure": "information_disclosure",
            "jwt": "jwt_vulnerability",
            "prototype pollution": "prototype_pollution",
            "deserialization": "insecure_deserialization",
            "mass assignment": "mass_assignment",
            "http smuggling": "http_request_smuggling",
        }
        for f in _report_findings:
            if not isinstance(f, dict):
                continue
            vtype = (f.get("vulnerability_type") or "").strip()
            if not vtype or vtype.lower() in ("unknown", "other", ""):
                title = (f.get("title") or "").lower()
                for pattern, norm_type in _VULN_TYPE_INFER.items():
                    if pattern in title:
                        f["vulnerability_type"] = norm_type
                        break

        # Gate 4: Filter out findings from disabled nuclei templates
        _filtered = []
        for f in _report_findings:
            if isinstance(f, dict):
                tpl = f.get("template_id", "") or f.get("template", "") or ""
                if "_disabled" in tpl or "_disabled/" in str(f.get("matched_at", "")):
                    logger.debug(f"Filtered disabled template finding: {f.get('title', '?')}")
                    continue
            _filtered.append(f)
        if len(_filtered) < len(_report_findings):
            logger.info(
                f"📊 Disabled template filter: {len(_report_findings) - len(_filtered)} findings removed"
            )
        _report_findings = _filtered

        # Gate 5: Evidence quality validation (P1-5, Phase 5 Revolution)
        # Severity-proportional evidence requirements:
        #   CRITICAL: HTTP exchange (request+response) AND (poc_code OR concrete evidence)
        #   HIGH: HTTP exchange (request OR response) AND at least one evidence field
        #   MEDIUM: At least one non-trivial evidence field
        #   LOW/INFO: No requirements

        def _has_real_content(val: object) -> bool:
            """Check if a value has real content, not just placeholder."""
            if not val:
                return False
            s = str(val).strip()
            if len(s) < 8:
                return False
            _PLACEHOLDER_MARKERS = ("n/a", "none", "unknown", "null", "todo", "placeholder", "{}", "[]")
            return s.lower() not in _PLACEHOLDER_MARKERS

        _evidence_issues = 0
        for f in _report_findings:
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity", "")).upper()

            # Assess evidence quality per field
            has_http_request = _has_real_content(f.get("http_request"))
            has_http_response = _has_real_content(f.get("http_response"))
            has_http_exchange = has_http_request and has_http_response
            has_poc_code = _has_real_content(f.get("poc_code"))
            has_evidence = _has_real_content(f.get("evidence")) or _has_real_content(f.get("poc_evidence"))
            has_any_evidence = has_http_request or has_http_response or has_poc_code or has_evidence

            # Fix inconsistent poc_confirmed flag
            if f.get("poc_confirmed") and not has_poc_code:
                f["poc_confirmed"] = False
                _evidence_issues += 1

            if sev == "CRITICAL":
                # CRITICAL needs HTTP exchange AND (poc OR evidence)
                if not has_http_exchange or not (has_poc_code or has_evidence):
                    f["original_severity"] = f.get("original_severity", sev)
                    if has_any_evidence:
                        f["severity"] = "HIGH"
                        f["severity_downgrade_reason"] = "CRITICAL requires HTTP exchange + PoC/evidence"
                    else:
                        f["severity"] = "MEDIUM"
                        f["severity_downgrade_reason"] = "CRITICAL requires substantial evidence"
                    _evidence_issues += 1
            elif sev == "HIGH":
                # HIGH needs at least partial HTTP exchange + one evidence field
                if not (has_http_request or has_http_response) or not has_any_evidence:
                    f["original_severity"] = f.get("original_severity", sev)
                    f["severity"] = "MEDIUM"
                    f["severity_downgrade_reason"] = "HIGH requires HTTP evidence"
                    _evidence_issues += 1
            elif sev == "MEDIUM":
                # MEDIUM needs at least some evidence
                if not has_any_evidence:
                    f["original_severity"] = f.get("original_severity", sev)
                    f["severity"] = "LOW"
                    f["severity_downgrade_reason"] = "MEDIUM requires at least one evidence field"
                    _evidence_issues += 1
        if _evidence_issues:
            logger.info(f"📊 Evidence quality gate: {_evidence_issues} findings adjusted")

        # Gate 6: Evidence differentiation check (Phase 5 Revolution)
        # Findings claiming active vuln (XSS/SQLi/RCE/etc) but whose response
        # shows no sign of the payload having any effect are suspicious.
        _ACTIVE_VULN_TYPES = frozenset({
            "xss", "reflected_xss", "stored_xss", "dom_xss",
            "sqli", "sql_injection", "sqli_blind", "sqli_error",
            "rce", "command_injection", "os_command_injection",
            "ssti", "template_injection",
            "xxe", "xml_injection",
            "lfi", "local_file_inclusion", "path_traversal",
        })
        _diff_downgrades = 0
        for f in _report_findings:
            if not isinstance(f, dict):
                continue
            vtype = str(f.get("vulnerability_type") or "").lower().replace("-", "_").replace(" ", "_")
            if vtype not in _ACTIVE_VULN_TYPES:
                continue
            sev = str(f.get("severity", "")).upper()
            if sev not in ("HIGH", "CRITICAL"):
                continue
            # Check: does the response contain ANY trace of the payload?
            payload = str(f.get("payload") or "")
            response = str(f.get("http_response") or "")
            evidence = str(f.get("evidence") or "")
            if payload and len(payload) > 3 and response:
                # For injection vulns, the payload or a key fragment should appear
                # in the response (reflected) or there should be a clear error signature
                _payload_core = payload.strip("'\"` \t\n")[:30]
                _ERROR_SIGS = ("sql syntax", "mysql", "postgresql", "sqlite", "ora-",
                               "stack trace", "exception", "error in", "syntax error",
                               "root:x:", "etc/passwd", "uid=", "gid=")
                has_reflection = _payload_core and _payload_core.lower() in response.lower()
                has_error_sig = any(sig in response.lower() for sig in _ERROR_SIGS)
                has_evidence_match = _payload_core and _payload_core.lower() in evidence.lower()
                if not has_reflection and not has_error_sig and not has_evidence_match:
                    f["original_severity"] = f.get("original_severity", sev)
                    new_sev = "MEDIUM" if sev == "HIGH" else "HIGH"
                    f["severity"] = new_sev
                    f["severity_downgrade_reason"] = (
                        f"No payload reflection/error signature in response for {vtype}"
                    )
                    _diff_downgrades += 1
        if _diff_downgrades:
            logger.info(f"📊 Differential evidence gate: {_diff_downgrades} findings downgraded")

        findings = _report_findings
        logger.info(
            f"📊 Quality gates: {_pre_gate_count} → {len(findings)} findings "
            f"(confidence gate={len(_low_confidence)}, disabled templates={_pre_gate_count - len(_low_confidence) - len(findings) if _pre_gate_count > len(_low_confidence) + len(findings) else 0})"
        )

        generator = ReportGenerator(
            output_dir=f"output/reports/{state.session_id}",
            brain_engine=state.brain_engine,
        )

        # Brain enrichment already done above (intel.enrich_report_finding).
        # Do NOT re-enrich inside ReportGenerator — it would add 20 more
        # brain calls (~100-180 s each) and blow the stage timeout.

        # ── P0-8 (V17): Persist findings BEFORE report generation ──
        # Ensures findings are never lost even if report generation crashes.
        try:
            import json as _early_fj
            from pathlib import Path as _EarlyFjPath
            _early_fj_dir = _EarlyFjPath(f"output/sessions/{state.session_id}/findings")
            _early_fj_dir.mkdir(parents=True, exist_ok=True)
            _early_fj_path = str(_early_fj_dir / "findings.json")
            _early_fj_data = {
                "session_id": state.session_id,
                "target": state.target,
                "total_raw": len(state.raw_findings),
                "total_verified": len(state.verified_findings),
                "total_false_positives": len(state.false_positives),
                "verified_findings": state.verified_findings,
            }
            _EarlyFjPath(_early_fj_path).write_text(
                _early_fj.dumps(_early_fj_data, indent=2, default=str),
                encoding="utf-8",
            )
            logger.info(f"📦 Early findings JSON saved (pre-report): {_early_fj_path}")
        except Exception as _early_fj_err:
            logger.warning(f"Early findings JSON persistence failed: {_early_fj_err}")

        # Rapor oluştur
        report = await generator.generate(
            findings=findings,
            target=state.target,
            session_id=state.session_id,
            scan_time=state.elapsed_time,
            tools_used=sorted(set(getattr(state, "tools_run", []) + _get_tools_from_findings(findings))),
            use_brain=False,
        )

        # V13-T3-2: Inject technology stack, WAF, and profile into report
        _meta = getattr(state, "metadata", {}) or {}
        _resp_intel = _meta.get("response_intel", {})
        if isinstance(_resp_intel, dict):
            _tech_stack = _resp_intel.get("technologies", {})
            if _tech_stack:
                report.technology_stack = _tech_stack
            _waf = _resp_intel.get("waf_name", "") or _resp_intel.get("waf", "")
            if _waf:
                report.waf_detected = str(_waf)
        if hasattr(state, "scan_profile") and state.scan_profile:
            report.scan_profile = str(state.scan_profile)
        elif _meta.get("profile"):
            report.scan_profile = str(_meta["profile"])

        # Markdown kaydet
        md_path = generator.save_markdown(report)
        state.reports_generated.append(md_path)

        # JSON kaydet
        json_path = generator.save_json(report)
        state.reports_generated.append(json_path)

        # ── HTML report generation (2.4) ──
        try:
            from src.reporting.formatters.html_formatter import HtmlFormatter
            html_fmt = HtmlFormatter()
            html_str = html_fmt.format_report(report)
            if html_str:
                from pathlib import Path as _HtmlPath
                _html_dir = _HtmlPath(f"output/reports/{state.session_id}")
                _html_dir.mkdir(parents=True, exist_ok=True)
                _html_path = str(_html_dir / "report.html")
                _HtmlPath(_html_path).write_text(html_str, encoding="utf-8")
                state.reports_generated.append(_html_path)
                logger.info(f"HTML report saved: {_html_path}")
        except ImportError:
            logger.debug("HtmlFormatter module not available")
        except Exception as _html_err:
            logger.debug(f"HTML report generation skipped: {_html_err}")

        # ── Findings persistence to JSON (2.5) ──
        try:
            import json as _findings_json
            from pathlib import Path as _FindingsPath
            _findings_dir = _FindingsPath(f"output/sessions/{state.session_id}/findings")
            _findings_dir.mkdir(parents=True, exist_ok=True)
            _findings_path = str(_findings_dir / "findings.json")
            _findings_data = {
                "session_id": state.session_id,
                "target": state.target,
                "total_raw": len(state.raw_findings),
                "total_verified": len(state.verified_findings),
                "total_false_positives": len(state.false_positives),
                "verified_findings": state.verified_findings,
            }
            _FindingsPath(_findings_path).write_text(
                _findings_json.dumps(_findings_data, indent=2, default=str),
                encoding="utf-8",
            )
            logger.info(f"Findings JSON saved: {_findings_path}")
        except Exception as _fj_err:
            logger.debug(f"Findings JSON persistence skipped: {_fj_err}")

        # ── Report Self-Assessment (T4-3) ──
        assessment: dict = {}
        try:
            if state.brain_engine:
                assessment = await generator.self_assess(report)
                if assessment.get("verdict") not in ("skipped", None):
                    state.metadata["report_assessment"] = assessment
                    logger.info(
                        f"📝 Report quality: {assessment.get('overall_score', '?')}/100 "
                        f"({assessment.get('verdict', 'unknown')})"
                    )
        except Exception as assess_err:
            logger.debug(f"Report self-assessment skipped: {assess_err}")

        # ── Scan-over-Scan Diff (T2-3) — compare with previous scan ──
        try:
            from src.workflow.session_manager import SessionManager

            sm = SessionManager(output_dir="output")
            prev = sm.get_latest_session(target=state.target)
            if prev and prev.metadata.session_id != state.session_id:
                # Sync current state into a temporary session for comparison
                cur_session = sm.create_session(
                    target=state.target,
                    scope_config={},
                    profile="diff-cmp",
                    mode="autonomous",
                )
                sm.sync_from_workflow_state(cur_session, state)
                diff = sm.compare_sessions(
                    prev.metadata.session_id,
                    cur_session.metadata.session_id,
                )
                state.metadata["scan_diff"] = {
                    "previous_session": prev.metadata.session_id,
                    "new_findings": len(diff.new_findings),
                    "resolved_findings": len(diff.resolved_findings),
                    "new_subdomains": len(diff.new_subdomains),
                    "new_endpoints": len(diff.new_endpoints),
                    "summary": diff.summary,
                }
                logger.info(
                    f"📊 Scan diff vs {prev.metadata.session_id}: "
                    f"+{len(diff.new_findings)} new, "
                    f"-{len(diff.resolved_findings)} resolved, "
                    f"+{len(diff.new_subdomains)} subs"
                )
        except Exception as diff_err:
            logger.debug(f"Scan diff skipped: {diff_err}")

        # ── DiffEngine + Alerts (V9-T2-1) — Asset-level diff + notifications ──
        try:
            from src.analysis.diff_engine import DiffEngine
            from src.integrations.diff_alerts import send_diff_alerts
            from src.integrations.asset_db import AssetDB as _DiffAssetDB

            _diff_db = _DiffAssetDB()
            _diff_engine = DiffEngine(_diff_db)
            # Use same program_id as asset_db_hooks to ensure consistency
            _diff_program = _adb._program_name(state)
            # Find prior scan for this target
            _prior_scans = _diff_db.get_scan_runs(program_id=_diff_program)
            # Exclude current session — scan_runs column is "id" not "scan_id"
            _prior_scans = [s for s in _prior_scans if s.get("id") != state.session_id]
            if _prior_scans:
                _prev_scan_id = _prior_scans[0].get("id", "")
                if _prev_scan_id:
                    _diff_report = _diff_engine.diff(
                        program_id=_diff_program,
                        old_scan_id=_prev_scan_id,
                        new_scan_id=state.session_id,
                    )
                    _diff_md = _diff_engine.generate_markdown(_diff_report)
                    if _diff_md:
                        from pathlib import Path as _DiffPath
                        _report_dir = _DiffPath(f"output/reports/{state.session_id}")
                        _report_dir.mkdir(parents=True, exist_ok=True)
                        _diff_path = str(_report_dir / "diff_report.md")
                        _DiffPath(_diff_path).write_text(_diff_md, encoding="utf-8")
                        logger.info(f"Diff report saved: {_diff_path}")
                    # Send alerts via notification system
                    try:
                        from src.integrations.notification import build_notification_manager
                        _nm = build_notification_manager()
                        _alerts_sent = await send_diff_alerts(
                            report=_diff_report,
                            notify_fn=_nm.notify,
                        )
                        if _alerts_sent:
                            logger.info(f"Diff alerts sent: {_alerts_sent} notifications")
                    except Exception as _alert_exc:
                        logger.debug(f"Diff alert sending skipped: {_alert_exc}")
        except ImportError:
            logger.debug("DiffEngine/diff_alerts modules not available")
        except Exception as _diff_eng_err:
            logger.debug(f"DiffEngine integration skipped: {_diff_eng_err}")

        # ── HAR Export — HTTP archive evidence for all findings ──
        har_path = ""
        try:
            from src.reporting.evidence.request_logger import RequestLogger, HttpExchange
            from src.reporting.evidence.har_exporter import export_har

            req_logger = RequestLogger(
                output_dir=f"output/evidence/{state.session_id}",
                session_id=state.session_id,
            )
            # Log all findings that have HTTP request/response data
            for f in findings:
                if not isinstance(f, dict):
                    continue
                req_raw = f.get("http_request", "")
                resp_raw = f.get("http_response", "")
                if req_raw or resp_raw:
                    exchange = HttpExchange(
                        method=f.get("method", "GET"),
                        url=f.get("url", f.get("endpoint", "")),
                        request_raw=req_raw,
                        response_raw=resp_raw,
                        tool_name=f.get("tool_name", f.get("source_tool", "")),
                        finding_id=f.get("id", f.get("title", "")[:40]),
                        is_payload=bool(f.get("payload")),
                        payload_used=f.get("payload", ""),
                    )
                    req_logger.log(exchange)

            if req_logger.exchange_count > 0:
                # Save session traffic (JSON + raw text)
                req_logger.save_session()
                # Export HAR for Burp Suite / DevTools import
                har_path = export_har(req_logger)
                if har_path:
                    state.reports_generated.append(har_path)
                logger.info(
                    f"📦 HTTP archive exported | exchanges={req_logger.exchange_count} | "
                    f"har={har_path}"
                )
        except Exception as har_err:
            logger.debug(f"HAR export skipped: {har_err}")

        result.data = {
            "report_id": report.report_id,
            "finding_count": report.finding_count,
            "markdown_path": md_path,
            "json_path": json_path,
            "har_path": har_path,
        }
        result.findings_count = report.finding_count
        result.success = True

        logger.info(f"Reports generated | paths={state.reports_generated}")

        # ── Benchmark: Record scan metrics (V8-T0-1) ──
        try:
            import time as _bm_time
            from datetime import datetime as _bm_dt, timezone as _bm_tz
            from src.analysis.benchmark import (
                BenchmarkStore,
                ScanBenchmark,
                build_module_impact,
                build_stage_finding_counts,
                build_tool_execution_counts,
            )
            _scan_id = (
                (state.metadata or {}).get("asset_db_scan_id", "")
                or getattr(state, "session_id", "")
                or state.target
            )
            bm = ScanBenchmark(
                scan_id=_scan_id,
                target=state.target or "",
                timestamp=_bm_dt.now(_bm_tz.utc).isoformat(),
                duration_seconds=_bm_time.time() - state.metadata.get("scan_start_time", _bm_time.time()) if state.metadata else 0.0,
                total_endpoints_tested=len(state.endpoints or []),
                total_tools_run=len(state.tools_run or []),
                raw_findings=len(state.raw_findings or []),
                confirmed_findings=len(findings),
                fp_rate=round(len(state.false_positives or []) / max(len(state.raw_findings or []), 1) * 100, 1),
                tool_execution_counts=build_tool_execution_counts(state.tools_run or []),
                stage_finding_counts=build_stage_finding_counts(state.stage_results),
            )
            # Severity distribution
            for f in findings:
                sev = (f.get("severity", "") if isinstance(f, dict) else "").lower()
                if sev == "critical": bm.critical_count += 1
                elif sev == "high": bm.high_count += 1
                elif sev == "medium": bm.medium_count += 1
                elif sev == "low": bm.low_count += 1
                elif sev == "info": bm.info_count += 1
            # PoC stats
            poc_findings = [f for f in findings if isinstance(f, dict) and f.get("poc_confirmed")]
            bm.poc_attempted = len([f for f in findings if isinstance(f, dict) and f.get("poc_code")])
            bm.poc_confirmed = len(poc_findings)
            bm.poc_success_rate = round(bm.poc_confirmed / max(bm.poc_attempted, 1) * 100, 1)
            # Tool finding counts
            for f in findings:
                tool = f.get("tool", "unknown") if isinstance(f, dict) else "unknown"
                bm.tool_finding_counts[tool] = bm.tool_finding_counts.get(tool, 0) + 1
            bm.module_impact = build_module_impact(
                bm.tool_finding_counts,
                state.tools_run or [],
            )
            # Save
            store = BenchmarkStore()
            store.save(bm)
            logger.info(
                f"Benchmark saved | confirmed={bm.confirmed_findings} | "
                f"fp_rate={bm.fp_rate}% | poc={bm.poc_confirmed}/{bm.poc_attempted}"
            )
        except Exception as e:
            logger.debug(f"Benchmark recording skipped: {e}")

        # ── Brain quality metrics (A3) ──
        try:
            intel = state.intelligence_engine
            if intel and hasattr(intel, "get_brain_metrics"):
                _bm = intel.get_brain_metrics()
                state.metadata = state.metadata or {}
                state.metadata["brain_metrics"] = _bm
                logger.info(
                    f"Brain metrics | calls={_bm['total_calls']} "
                    f"json_ok={_bm['json_success_rate']}% "
                    f"call_ok={_bm['call_success_rate']}% "
                    f"cache_hits={_bm['cache_hits']}"
                )
        except Exception as _bm_err:
            logger.debug(f"Brain metrics collection skipped: {_bm_err}")

        # ── GlobalFindingStore: cross-scan dedup persistence (P6-3) ──
        try:
            from src.analysis.global_finding_store import GlobalFindingStore
            gfs = GlobalFindingStore()
            _scan_id = (state.metadata or {}).get("asset_db_scan_id", "") or state.session_id or ""
            _program = (state.scope_config or {}).get("program_name", "") or state.target or ""
            dedup_results = gfs.record_batch(findings, scan_id=_scan_id, program=_program)
            new_count = sum(1 for d in dedup_results if d.is_new)
            regr_count = sum(1 for d in dedup_results if d.is_regression)
            recur_count = len(dedup_results) - new_count - regr_count
            gfs.mark_resolved_not_in_scan(scan_id=_scan_id, program=_program, target=state.target or "")
            logger.info(
                f"GlobalFindingStore recorded | new={new_count} recurring={recur_count} "
                f"regressions={regr_count} total={len(dedup_results)}"
            )
            state.metadata = state.metadata or {}
            state.metadata["global_finding_stats"] = {
                "new": new_count, "recurring": recur_count, "regressions": regr_count,
            }
        except Exception as _gfs_err:
            logger.warning(f"GlobalFindingStore integration skipped: {_gfs_err}")

        # ── ScanProfiler: finalize and generate performance report (P2-1/P2-2) ──
        try:
            # Retrieve profiler created at pipeline start (handle_scope_analysis)
            profiler = (state.metadata or {}).get("scan_profiler")
            if profiler is None:
                # Fallback: create a new profiler if not available (e.g. scope stage skipped)
                import time as _prof_time
                from src.analysis.scan_profiler import ScanProfiler
                profiler = ScanProfiler()
                profiler.start_scan()
                # Backdate start to reflect actual scan duration (not reporting-time)
                profiler._scan_start = _prof_time.monotonic() - max(state.elapsed_time or 0.0, 0.0)

            # Reconstruct stage timings from orchestrator results
            for _stage_enum, _stage_res in (state.stage_results or {}).items():
                stage_name = _stage_enum.value if hasattr(_stage_enum, "value") else str(_stage_enum)
                duration = getattr(_stage_res, "duration", 0.0) or 0.0
                findings_n = getattr(_stage_res, "findings_count", 0) or 0
                profiler.record_stage(
                    name=stage_name,
                    duration_s=duration,
                    findings_count=findings_n,
                )

            # Feed per-tool timing from executor history (P2-2: real data, not 0.0)
            _exec_history = []
            if state.tool_executor and hasattr(state.tool_executor, "_execution_history"):
                _exec_history = state.tool_executor._execution_history or []
            _recorded_tools: set[str] = set()
            for _hist in _exec_history:
                _t_name = _hist.get("tool", "")
                _t_dur = _hist.get("execution_time", 0.0) or 0.0
                _t_ok = _hist.get("success", False)
                _t_fc = _hist.get("findings_count", 0) or 0
                if _t_name:
                    _recorded_tools.add(_t_name)
                    profiler.record_tool(
                        tool_name=_t_name,
                        duration_s=_t_dur,
                        success=_t_ok,
                        findings_count=_t_fc,
                    )
            # For inline tools (custom checkers etc.) without executor history,
            # estimate duration from stage timing divided by tool count
            _inline_tools = [t for t in (state.tools_run or []) if t not in _recorded_tools]
            if _inline_tools:
                # Estimate per-tool duration from vuln_scan stage
                _vuln_stage_dur = 0.0
                for _se, _sr in (state.stage_results or {}).items():
                    _sv = _se.value if hasattr(_se, "value") else str(_se)
                    if "vuln" in _sv.lower() or "scan" in _sv.lower():
                        _vuln_stage_dur = max(_vuln_stage_dur, getattr(_sr, "duration", 0.0) or 0.0)
                _est_per_tool = (_vuln_stage_dur / max(1, len(state.tools_run or [])))
                for _tool_name in _inline_tools:
                    profiler.record_tool(
                        tool_name=_tool_name,
                        duration_s=round(_est_per_tool, 1),
                        success=True,
                        findings_count=0,
                    )

            profiler.end_scan()
            perf_report = profiler.generate_report()
            # Save performance report
            import os as _perf_os
            _perf_dir = f"output/reports/{state.session_id or 'default'}"
            _perf_os.makedirs(_perf_dir, exist_ok=True)
            _perf_path = _perf_os.path.join(_perf_dir, "performance_report.md")
            with open(_perf_path, "w", encoding="utf-8") as _pf:
                _pf.write(perf_report.to_markdown())
            state.reports_generated.append(_perf_path)
            logger.info(
                f"Performance report saved | stages={len(perf_report.stage_timings)} "
                f"tools_profiled={len(profiler._tool_aggregate)} "
                f"bottlenecks={len(perf_report.bottlenecks)} | path={_perf_path}"
            )
        except Exception as _prof_err:
            logger.warning(f"ScanProfiler integration skipped: {_prof_err}")

        # ── Per-Scan Quality Report (V25 T5-3) ──
        try:
            from src.analysis.scan_quality_report import ScanQualityAnalyzer
            _qr_brain_metrics = (state.metadata or {}).get("brain_metrics", {})
            if not _qr_brain_metrics:
                _qr_intel = state.intelligence_engine
                if _qr_intel and hasattr(_qr_intel, "get_brain_metrics"):
                    _qr_brain_metrics = _qr_intel.get_brain_metrics()
            _qr_meta = dict(state.metadata or {})
            _qr_meta.setdefault("endpoints", list(state.endpoints or []))
            _qr_meta.setdefault("live_hosts", list(state.live_hosts or []))
            _qr_meta.setdefault("failed_tools", _meta.get("failed_tools", []))
            _qr_meta.setdefault("unavailable_tools", _meta.get("unavailable_tools", []))
            _qr_meta.setdefault("stage_finding_counts", _meta.get("stage_finding_counts", {}))
            _qr_meta["total_duration_s"] = state.elapsed_time
            _qr_analyzer = ScanQualityAnalyzer()
            _qr_report = _qr_analyzer.analyze(
                scan_id=state.session_id or "",
                target=state.target or "",
                state_metadata=_qr_meta,
                raw_findings_count=len(state.raw_findings or []),
                deduped_findings_count=len(findings),
                final_findings=findings,
                tools_run=state.tools_run or [],
                brain_metrics=_qr_brain_metrics,
            )
            import os as _qr_os
            _qr_dir = f"output/reports/{state.session_id or 'default'}"
            _qr_os.makedirs(_qr_dir, exist_ok=True)
            _qr_path = _qr_os.path.join(_qr_dir, "quality_report.md")
            with open(_qr_path, "w", encoding="utf-8") as _qr_fh:
                _qr_fh.write(_qr_report.to_markdown())
            state.reports_generated.append(_qr_path)
            state.metadata["scan_quality_score"] = _qr_report.score.overall
            logger.info(
                f"📊 Quality report saved | score={_qr_report.score.overall:.0f}/100 "
                f"warnings={len(_qr_report.warnings)} | path={_qr_path}"
            )
        except Exception as _qr_err:
            logger.warning(f"Scan quality report skipped: {_qr_err}")

        # ── Auto-Draft Report Generation (P6-4) ──
        try:
            from src.reporting.auto_draft import AutoDraftGenerator
            _draft_platform = (state.scope_config or {}).get("platform", "hackerone")
            drafter = AutoDraftGenerator(
                output_dir=f"output/drafts/{state.session_id or 'default'}",
                platform=_draft_platform,
                target=state.target or "",
            )
            draft_paths = drafter.generate_batch(findings, scan_id=state.session_id or "")
            if draft_paths:
                state.reports_generated.extend(str(p) for p in draft_paths)
                logger.info(f"Auto-draft reports generated: {len(draft_paths)}")
        except Exception as _draft_err:
            logger.warning(f"Auto-draft generation skipped: {_draft_err}")

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


async def handle_platform_submit(state: WorkflowState) -> StageResult:
    """
    Aşama 9: Platform Gönderimi

    Raporları draft olarak kaydeder veya API üzerinden gönderir.
    """
    result = StageResult(stage=WorkflowStage.PLATFORM_SUBMIT)

    # Şimdilik draft olarak kaydet
    result.data = {
        "mode": "draft",
        "reports": state.reports_generated,
        "message": "Reports saved as drafts. Manual submission recommended.",
    }
    result.success = True

    logger.info(f"Platform submit (draft mode) | reports={len(state.reports_generated)}")

    return result


async def handle_knowledge_update(state: WorkflowState) -> StageResult:
    """
    Aşama 10: Bilgi Güncelleme

    Oturum bilgilerini knowledge base'e kaydeder.
    """
    result = StageResult(stage=WorkflowStage.KNOWLEDGE_UPDATE)

    try:
        logger.info("Knowledge update started")

        # Oturum özeti
        session_summary = {
            "session_id": state.session_id,
            "target": state.target,
            "duration": state.elapsed_time,
            "total_findings": len(state.raw_findings),
            "verified_findings": len(state.verified_findings),
            "false_positives": len(state.false_positives),
            "subdomains_found": len(state.subdomains),
            "live_hosts": len(state.live_hosts),
            "endpoints": len(state.endpoints),
            "completed_stages": [getattr(s, "value", str(s)) for s in state.completed_stages],
        }

        try:
            from src.brain.memory.knowledge_base import KnowledgeBase

            kb = KnowledgeBase()
            kb.initialize()

            kb.record_scan_learning(
                session_id=state.session_id,
                target=state.target,
                profile=state.profile.value,
                mode=state.mode.value,
                technologies=state.technologies,
                tools_used=state.tools_run,
                raw_findings=state.raw_findings,
                verified_findings=state.verified_findings,
                false_positives=state.false_positives,
                duration_seconds=state.elapsed_time,
            )

            logger.debug(f"Session summary: {session_summary}")

        except Exception as e:
            logger.warning(f"KB update failed (non-critical): {e}")

        result.data = session_summary
        result.success = True

        # AssetDB: scan bitişini kaydet
        _adb.record_scan_finish(
            state, state.metadata.get("asset_db_scan_id"),
        )

        logger.info(
            f"Knowledge updated | findings_stored={len(state.verified_findings)} | "
            f"fp_patterns={len(state.false_positives)}"
        )

        # ── Comprehensive scan summary (operator visibility) ──
        _ft = state.metadata.get("failed_tools", [])
        _tr = state.tools_run or []
        logger.info(
            f"\n{'='*60}\n"
            f"  SCAN SUMMARY — {state.target}\n"
            f"{'='*60}\n"
            f"  Duration      : {state.elapsed_time:.0f}s ({state.elapsed_time/60:.1f}m)\n"
            f"  Profile       : {state.profile.value}\n"
            f"  Subdomains    : {len(state.subdomains)}\n"
            f"  Live hosts    : {len(state.live_hosts)}\n"
            f"  Endpoints     : {len(state.endpoints)}\n"
            f"  Tools run     : {len(_tr)}\n"
            f"  Raw findings  : {len(state.raw_findings)}\n"
            f"  Verified      : {len(state.verified_findings)}\n"
            f"  False positives: {len(state.false_positives)}\n"
            f"  Failed tools  : {len(_ft)} {_ft[:10] if _ft else ''}\n"
            f"{'='*60}"
        )

    except Exception as e:
        logger.error(f"Knowledge update failed: {e}")
        result.success = False
        result.errors.append(str(e))

    return result


# ============================================================
# Pipeline Builder
# ============================================================

def build_full_scan_pipeline(
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
    Tam scan pipeline'ı kur ve döndür.

    Tüm 10 aşama handler'ları kayıt edilir.
    Cognitive modules (AdaptiveStrategy, SelfReflection) otomatik
    oluşturulur ve orkestratöre enjekte edilir.

    Returns:
        Yapılandırılmış WorkflowOrchestrator
    """
    # ── Initialize cognitive modules ──
    adaptive_strategy = None
    self_reflection = None

    try:
        from src.workflow.adaptive_strategy import AdaptiveStrategyEngine
        adaptive_strategy = AdaptiveStrategyEngine(
            initial_profile=profile.value if hasattr(profile, 'value') else str(profile),
            brain_engine=brain_engine,
        )
        logger.info("AdaptiveStrategyEngine activated")
    except Exception as e:
        logger.debug(f"AdaptiveStrategyEngine init skipped: {e}")

    try:
        from src.brain.reasoning.self_reflection import SelfReflectionEngine
        self_reflection = SelfReflectionEngine(brain_engine=brain_engine)
        logger.info("SelfReflectionEngine activated")
    except Exception as e:
        logger.debug(f"SelfReflectionEngine init skipped: {e}")

    orchestrator = WorkflowOrchestrator(
        brain_engine=brain_engine,
        tool_executor=tool_executor,
        fp_detector=fp_detector,
        mode=mode,
        profile=profile,
        human_approval_callback=human_callback,
        session_manager=session_manager,
        adaptive_strategy=adaptive_strategy,
        self_reflection=self_reflection,
        brain_router=brain_router,
    )

    # Tüm handler'ları kaydet
    orchestrator.register_handler(WorkflowStage.SCOPE_ANALYSIS, handle_scope_analysis)
    orchestrator.register_handler(WorkflowStage.PASSIVE_RECON, handle_passive_recon)
    orchestrator.register_handler(WorkflowStage.ACTIVE_RECON, handle_active_recon)
    orchestrator.register_handler(WorkflowStage.ENUMERATION, handle_enumeration)
    orchestrator.register_handler(WorkflowStage.ATTACK_SURFACE_MAP, handle_attack_surface_map)
    orchestrator.register_handler(WorkflowStage.VULNERABILITY_SCAN, handle_vulnerability_scan)
    orchestrator.register_handler(WorkflowStage.FP_ELIMINATION, handle_fp_elimination)
    orchestrator.register_handler(WorkflowStage.REPORTING, handle_reporting)
    orchestrator.register_handler(WorkflowStage.PLATFORM_SUBMIT, handle_platform_submit)
    orchestrator.register_handler(WorkflowStage.KNOWLEDGE_UPDATE, handle_knowledge_update)

    logger.info(
        f"Full scan pipeline built | stages=10 | mode={mode} | "
        f"profile={profile}"
    )

    return orchestrator


# ============================================================
# Yardımcı Fonksiyonlar
# ============================================================

def _detect_target_type(target: str) -> str:
    """Hedef türünü tespit et."""
    import re

    # IP?
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return "ip"
    # CIDR?
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", target):
        return "cidr"
    # URL?
    if target.startswith(("http://", "https://")):
        return "url"
    # Domain
    return "domain"


def _deduplicate_hosts(
    hosts: list[str],
    base_domain: str = "",
    max_per_group: int = 2,
    max_total: int = 25,
) -> list[str]:
    """Akıllı host deduplication — CDN/cache/generic sunucu kopyalarını azaltır.

    Subdomain'leri yapısal benzerliğe göre gruplar ve her gruptan
    sınırlı sayıda temsilci seçer. Benzersiz/ilginç hostları korur.

    Gruplama mantığı:
      - cache{N}.{dc}.example.com → group "cache.*.example.com"
      - web{N}.{dc}.example.com   → group "web.*.example.com"
      - Tekrar eden yapısal kalıplar (önek + sayı) → aynı grup
      - Benzersiz isimler (api, admin, staging, dev, git, mail, vpn vb.) → her biri kendi grubu

    Returns:
        Deduplicated host listesi, max *max_total* eleman.
    """
    if len(hosts) <= max_total:
        return hosts

    # Özel / yüksek öncelikli subdomain kalıpları (bunlar asla atlanmaz)
    _PRIORITY_KEYWORDS = {
        "api", "admin", "dev", "test", "beta",
        "git", "gitlab", "github", "jenkins", "ci", "cd",
        "mail", "smtp", "imap", "pop", "webmail", "owa",
        "vpn", "sso", "auth", "login", "portal", "dashboard",
        "jira", "confluence", "wiki", "docs", "internal",
        "db", "database", "mysql", "postgres", "redis", "mongo",
        "ftp", "sftp", "backup", "bak", "old", "legacy",
        "shop", "store", "pay", "billing", "checkout",
        "upload", "media", "cdn", "static", "assets",
        "graphql", "ws", "socket", "grpc",
        "status", "monitor", "health", "nagios", "grafana",
        "support", "help", "id", "account", "profile",
    }
    # Hosts matching these keywords are deprioritized (scanned last, not first)
    _DEPRIORITY_KEYWORDS = {"staging", "stage", "stg", "preprod", "uat"}

    # Sayısal prefix/suffix pattern: web39, cache1, node-3
    _NUMERIC_RE = _re.compile(r"^([a-zA-Z]+)[\-_]?\d+$")
    # datacenter sub-label: dfw, mia, mdw, lax, etc. (2-4 harf)
    _DC_RE = _re.compile(r"^[a-z]{2,4}$")

    priority_hosts: list[str] = []
    groups: dict[str, list[str]] = defaultdict(list)

    for host in hosts:
        labels = host.split(".")
        # Ana domain çıkar — base_domain label sayısına göre
        if base_domain:
            base_labels = base_domain.split(".")
            sub_labels = labels[: len(labels) - len(base_labels)]
        else:
            sub_labels = labels[:-2] if len(labels) > 2 else labels[:1]

        if not sub_labels:
            groups["__root__"].append(host)
            continue

        first = sub_labels[0].lower()

        # Depriority keyword → scanned last
        is_depriority = any(kw in first for kw in _DEPRIORITY_KEYWORDS)
        if is_depriority:
            groups["__depriority__"].append(host)
            continue

        # Özel keyword mi?
        is_priority = any(kw in first for kw in _PRIORITY_KEYWORDS)
        if is_priority:
            priority_hosts.append(host)
            continue

        # Sayısal pattern: web39.dfw → group key "web.*.rest"
        num_match = _NUMERIC_RE.match(first)
        if num_match:
            prefix = num_match.group(1)
            # datacenter label'ı atla
            rest_labels = []
            for lbl in sub_labels[1:]:
                if _DC_RE.match(lbl):
                    rest_labels.append("*")
                else:
                    rest_labels.append(lbl)
            group_key = f"{prefix}.*." + ".".join(rest_labels) if rest_labels else f"{prefix}.*"
            groups[group_key].append(host)
        else:
            # Non-numeric, non-priority → group by first subdomain label
            groups[first].append(host)
    selected: list[str] = list(priority_hosts)
    depriority_hosts: list[str] = []
    for group_key in sorted(groups.keys()):
        if group_key == "__depriority__":
            depriority_hosts.extend(groups[group_key][:max_per_group])
            continue
        members = groups[group_key]
        selected.extend(members[:max_per_group])

    # Depriority hosts go at the very end (scanned last)
    selected.extend(depriority_hosts)

    if len(selected) > max_total:
        selected = selected[:max_total]

    logger.info(
        f"Host dedup | input={len(hosts)} | priority={len(priority_hosts)} | "
        f"groups={len(groups)} | output={len(selected)}"
    )
    return selected


def _get_scan_options(profile: ScanProfile, scan_type: str) -> dict[str, Any]:
    """Tarama profili bazlı seçenekler."""
    options: dict[str, Any] = {}

    if profile == ScanProfile.STEALTH:
        options["rate"] = 1
        options["threads"] = 1
        if scan_type == "port_scan":
            options["ports"] = "21,22,25,80,443,8080,8443"
        elif scan_type == "scanner":
            options["level"] = 1
        elif scan_type == "injection":
            options["level"] = 1
            options["risk"] = 1
            options["timeout"] = 600
        elif scan_type == "fuzzing":
            options["threads"] = 2
            options["timeout"] = 300
        elif scan_type == "xss":
            options["timeout"] = 300

    elif profile == ScanProfile.BALANCED:
        options["rate"] = 10
        options["threads"] = 4
        if scan_type == "port_scan":
            pass
        elif scan_type == "scanner":
            options["level"] = 2
        elif scan_type == "injection":
            options["level"] = 2
            options["risk"] = 1
            options["timeout"] = 120
        elif scan_type == "fuzzing":
            options["rate"] = 20
            options["threads"] = 10
            options["timeout"] = 240
        elif scan_type == "xss":
            options["timeout"] = 180

    elif profile == ScanProfile.AGGRESSIVE:
        options["rate"] = 20
        options["threads"] = 8
        if scan_type == "port_scan":
            pass
        elif scan_type == "scanner":
            options["level"] = 3
        elif scan_type == "injection":
            options["level"] = 3
            options["risk"] = 3
            options["timeout"] = 240
        elif scan_type == "fuzzing":
            options["threads"] = 25
            options["timeout"] = 120
        elif scan_type == "xss":
            options["timeout"] = 120

    return options


def _calculate_host_priority(host: str, ports: list[int], tech: str) -> int:
    """Host öncelik skoru hesapla (0-100)."""
    score = 0

    score += min(len(ports) * 2, 20)

    web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000, 9000}
    score += len(set(ports) & web_ports) * 5

    risky_ports = {21, 23, 445, 1433, 3306, 5432, 6379, 27017}
    score += len(set(ports) & risky_ports) * 8

    host_lower = host.lower()
    high_value_keywords = {
        "api": 15, "admin": 15, "staging": 12, "stage": 12,
        "dev": 10, "test": 8, "beta": 8,
        "git": 12, "gitlab": 12, "jenkins": 15, "ci": 10,
        "login": 12, "auth": 12, "sso": 12,
        "portal": 10, "dashboard": 10,
        "upload": 10, "graphql": 12, "ws": 8,
        "jira": 10, "confluence": 10, "internal": 12,
        "vpn": 10, "ftp": 8, "sftp": 8,
        "id": 8, "account": 8, "profile": 8,
        "support": 6, "help": 4, "status": 6,
    }
    # Check ALL subdomain labels for high-value keywords, not just the first
    host_labels = host_lower.split(".")
    for keyword, bonus in high_value_keywords.items():
        for label in host_labels[:-1]:  # skip TLD
            if keyword in label:
                score += bonus
                break  # found this keyword in one label, move to next keyword

    first_label = host_lower.split(".")[0]
    if _re.match(r"^(web|cache|node|lb|edge)\d+$", first_label):
        score -= 5

    if tech:
        tech_lower = str(tech).lower()
        if any(k in tech_lower for k in ["wordpress", "joomla", "drupal"]):
            score += 10
        if any(k in tech_lower for k in ["php", "asp", "jsp"]):
            score += 5
        if "apache" in tech_lower or "nginx" in tech_lower:
            score += 3

    if not ports and score < 5:
        score = 5

    return max(0, score)




def _identify_attack_vectors(state: WorkflowState) -> list[dict[str, str]]:
    """Mevcut verilere gore saldiri vektorlerini belirle."""
    vectors: list[dict[str, str]] = []

    if state.endpoints:
        vectors.append({
            "type": "web_application",
            "description": f"{len(state.endpoints)} web endpoints discovered",
            "priority": "high",
        })

    all_ports = set()
    for ports in state.open_ports.values():
        all_ports.update(ports)

    if 21 in all_ports:
        vectors.append({"type": "ftp", "description": "FTP service found", "priority": "medium"})
    if 22 in all_ports:
        vectors.append({"type": "ssh", "description": "SSH service found", "priority": "low"})
    if 445 in all_ports:
        vectors.append({"type": "smb", "description": "SMB service found", "priority": "high"})
    if any(p in all_ports for p in [3306, 5432, 1433, 27017]):
        vectors.append({"type": "database", "description": "Database service exposed", "priority": "critical"})
    if 6379 in all_ports:
        vectors.append({"type": "redis", "description": "Redis exposed", "priority": "critical"})

    return vectors


def _get_tools_from_findings(findings: list[dict]) -> list[str]:
    """Bulgulardan kullanilan araclari cikar."""
    tools = set()
    for f in findings:
        tool = f.get("tool", "")
        if tool:
            tools.add(tool)
    return sorted(tools)


__all__ = [
    "build_full_scan_pipeline",
    "handle_scope_analysis",
    "handle_passive_recon",
    "handle_active_recon",
    "handle_enumeration",
    "handle_attack_surface_map",
    "handle_vulnerability_scan",
    "handle_fp_elimination",
    "handle_reporting",
    "handle_platform_submit",
    "handle_knowledge_update",
]
