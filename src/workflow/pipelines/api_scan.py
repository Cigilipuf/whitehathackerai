"""
WhiteHatHacker AI — API Security Scan Pipeline

REST / GraphQL / SOAP API'lerine özelleştirilmiş tarama pipeline'ı.
Endpoint keşfi, auth analizi, parametre fuzzing, iş mantığı testleri.
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


# ============================================================
# Stage Handlers
# ============================================================

async def handle_api_discovery(state: WorkflowState) -> StageResult:
    """
    API Discovery: Endpoint keşfi ve dokümantasyon analizi.

    - Swagger/OpenAPI spec arama
    - GraphQL introspection
    - Endpoint crawling
    - Parametre keşfi
    """
    result = StageResult(stage=WorkflowStage.PASSIVE_RECON)

    try:
        target = state.target
        logger.info(f"API discovery started | target={target}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        collected: dict[str, Any] = {
            "api_endpoints": [],
            "openapi_specs": [],
            "graphql_endpoints": [],
            "parameters": {},
            "auth_schemes": [],
            "content_types": [],
        }

        # ── OpenAPI/Swagger keşfi ──
        common_spec_paths = [
            "/swagger.json", "/swagger/v1/swagger.json",
            "/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/openapi.yaml",
            "/.well-known/openapi.json",
            "/docs", "/redoc",
        ]

        ffuf = tool_registry.get("ffuf")
        if ffuf:
            try:
                spec_result = await _execute_tool(
                    executor,
                    ffuf,
                    target,
                    {
                        "wordlist": "custom",
                        "custom_words": common_spec_paths,
                        "match_codes": "200,301,302",
                        "extensions": "",
                    },
                    timeout=1200.0,
                )
                if spec_result and spec_result.findings:
                    for finding in spec_result.findings:
                        collected["openapi_specs"].append(finding.get("url", ""))
            except Exception as e:
                logger.warning(f"OpenAPI discovery failed: {e}")

        # ── GraphQL Introspection ──
        graphql_tool = tool_registry.get("graphql_introspection")
        if graphql_tool:
            for path in ["/graphql", "/api/graphql", "/gql", "/query"]:
                try:
                    gql_result = await _execute_tool(
                        executor,
                        graphql_tool,
                        f"{target.rstrip('/')}{path}",
                        {},
                        timeout=1200.0,
                    )
                    if gql_result and gql_result.findings:
                        collected["graphql_endpoints"].append(path)
                        collected["api_endpoints"].extend(gql_result.findings)
                except Exception as _exc:
                    logger.warning(f"api scan error: {_exc}")
                    continue

        # ── HTTP Crawling ──
        for crawler in ["katana", "gospider", "hakrawler"]:
            tool = tool_registry.get(crawler)
            if tool:
                try:
                    crawl_result = await _execute_tool(
                        executor,
                        tool,
                        target,
                        {"depth": 3, "filter_api": True},
                        timeout=1200.0,
                    )
                    for finding in (crawl_result.findings if crawl_result and crawl_result.findings else []):
                        url = finding.get("url", "")
                        if any(p in url for p in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                            collected["api_endpoints"].append(finding)
                except Exception as e:
                    logger.warning(f"{crawler} failed: {e}")
                break  # ilk mevcut crawler yeterli

        # ── Parameter Discovery ──
        arjun = tool_registry.get("arjun")
        if arjun and collected["api_endpoints"]:
            sample_endpoints = collected["api_endpoints"][:10]
            for ep in sample_endpoints:
                url = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                try:
                    param_result = await _execute_tool(
                        executor, arjun, url, {}, timeout=1200.0,
                    )
                    if param_result and param_result.findings:
                        collected["parameters"][url] = param_result.findings
                except Exception as _exc:
                    logger.warning(f"api scan error: {_exc}")
                    continue

        # ── Teknoloji Tespiti ──
        whatweb = tool_registry.get("whatweb")
        if whatweb:
            try:
                tech_result = await _execute_tool(
                    executor, whatweb, target, {}, timeout=1200.0,
                )
                if tech_result and tech_result.findings:
                    collected["content_types"] = [
                        f.get("technology", "") for f in tech_result.findings
                    ]
            except Exception as _exc:
                logger.warning(f"api scan error: {_exc}")

        # Sonuçları state'e kaydet
        total_endpoints = len(collected["api_endpoints"])
        total_specs = len(collected["openapi_specs"])

        summary = (
            f"API discovery: {total_endpoints} endpoints, "
            f"{total_specs} specs, "
            f"{len(collected['graphql_endpoints'])} GraphQL paths"
        )
        result.data = {**collected, "summary": summary}
        result.success = True

        state.metadata["api_discovery"] = collected
        logger.info(summary)

    except Exception as e:
        result.success = False
        result.errors.append(str(e))
        logger.error(f"API discovery error: {e}")

    return result


async def handle_api_auth_analysis(state: WorkflowState) -> StageResult:
    """
    Authentication & Authorization analizi.

    - JWT token analizi
    - OAuth flow analizi
    - API key header kontrolü
    - IDOR tespiti
    """
    result = StageResult(stage=WorkflowStage.ENUMERATION)

    try:
        target = state.target
        discovery = state.metadata.get("api_discovery", {})
        logger.info(f"API auth analysis started | target={target}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        auth_findings: list[dict[str, Any]] = []

        # ── JWT Analizi ──
        jwt_tool = tool_registry.get("jwt_tool")
        if jwt_tool:
            try:
                jwt_result = await _execute_tool(
                    executor, jwt_tool, target, {"mode": "analyze"}, timeout=1200.0,
                )
                if jwt_result and jwt_result.findings:
                    auth_findings.extend(jwt_result.findings)
            except Exception as e:
                logger.warning(f"JWT analysis failed: {e}")

        # ── OAuth Tester ──
        oauth_tool = tool_registry.get("oauth_tester")
        if oauth_tool:
            try:
                oauth_result = await _execute_tool(
                    executor, oauth_tool, target, {}, timeout=1200.0,
                )
                if oauth_result and oauth_result.findings:
                    auth_findings.extend(oauth_result.findings)
            except Exception as e:
                logger.warning(f"OAuth test failed: {e}")

        # ── IDOR Checker ──
        idor_tool = tool_registry.get("idor_checker")
        if idor_tool:
            endpoints = discovery.get("api_endpoints", [])[:10]
            for ep in endpoints:
                url = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                try:
                    idor_result = await _execute_tool(
                        executor, idor_tool, url, {}, timeout=1200.0,
                    )
                    if idor_result and idor_result.findings:
                        auth_findings.extend(idor_result.findings)
                except Exception as _exc:
                    logger.warning(f"api scan error: {_exc}")
                    continue

        # ── Auth Bypass ──
        auth_bypass = tool_registry.get("auth_bypass")
        if auth_bypass:
            try:
                bypass_result = await _execute_tool(
                    executor, auth_bypass, target, {}, timeout=1200.0,
                )
                if bypass_result and bypass_result.findings:
                    auth_findings.extend(bypass_result.findings)
            except Exception as e:
                logger.warning(f"Auth bypass test failed: {e}")

        summary = f"Auth analysis: {len(auth_findings)} potential issues"
        result.data = {"auth_findings": auth_findings, "summary": summary}
        result.success = True

        state.metadata.setdefault("all_findings", []).extend(auth_findings)
        # Sync findings to state.raw_findings so FP elimination can access them
        state.raw_findings = list(state.metadata.get("all_findings", []))
        logger.info(summary)

    except Exception as e:
        result.success = False
        result.errors.append(str(e))
        logger.error(f"API auth analysis error: {e}")

    return result


async def handle_api_injection_scan(state: WorkflowState) -> StageResult:
    """
    API Injection testleri.

    - SQLi (parametre bazlı)
    - NoSQLi
    - Command injection
    - SSRF
    - SSTI
    """
    result = StageResult(stage=WorkflowStage.VULNERABILITY_SCAN)

    try:
        target = state.target
        discovery = state.metadata.get("api_discovery", {})
        logger.info(f"API injection scan started | target={target}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        vuln_findings: list[dict[str, Any]] = []

        endpoints_with_params = [
            url for url, params in discovery.get("parameters", {}).items()
            if params
        ]
        if not endpoints_with_params:
            endpoints_with_params = [target]

        # ── SQLi ──
        sqlmap = tool_registry.get("sqlmap")
        if sqlmap:
            for ep in endpoints_with_params[:5]:
                try:
                    sqli_result = await _execute_tool(
                        executor,
                        sqlmap,
                        ep,
                        {"level": 2, "risk": 2, "batch": True, "threads": 4},
                        timeout=1200.0,
                    )
                    if sqli_result and sqli_result.findings:
                        vuln_findings.extend(sqli_result.findings)
                except Exception as e:
                    logger.warning(f"SQLi test failed on {ep}: {e}")

        # ── Command Injection ──
        commix = tool_registry.get("commix")
        if commix:
            for ep in endpoints_with_params[:3]:
                try:
                    cmd_result = await _execute_tool(
                        executor,
                        commix,
                        ep,
                        {"level": 2, "batch": True},
                        timeout=1200.0,
                    )
                    if cmd_result and cmd_result.findings:
                        vuln_findings.extend(cmd_result.findings)
                except Exception as e:
                    logger.warning(f"Command injection test failed: {e}")

        # ── SSRF ──
        ssrf_tool = tool_registry.get("ssrfmap")
        if ssrf_tool:
            for ep in endpoints_with_params[:3]:
                try:
                    ssrf_result = await _execute_tool(
                        executor, ssrf_tool, ep, {}, timeout=1200.0,
                    )
                    if ssrf_result and ssrf_result.findings:
                        vuln_findings.extend(ssrf_result.findings)
                except Exception as _exc:
                    logger.warning(f"api scan error: {_exc}")
                    continue

        # ── SSTI ──
        tplmap = tool_registry.get("tplmap")
        if tplmap:
            for ep in endpoints_with_params[:3]:
                try:
                    ssti_result = await _execute_tool(
                        executor, tplmap, ep, {}, timeout=1200.0,
                    )
                    if ssti_result and ssti_result.findings:
                        vuln_findings.extend(ssti_result.findings)
                except Exception as _exc:
                    logger.warning(f"api scan error: {_exc}")
                    continue

        # ── API-specific: CORS ──
        corsy = tool_registry.get("corsy")
        if corsy:
            try:
                cors_result = await _execute_tool(
                    executor, corsy, target, {}, timeout=1200.0,
                )
                if cors_result and cors_result.findings:
                    vuln_findings.extend(cors_result.findings)
            except Exception as _exc:
                logger.warning(f"api scan error: {_exc}")

        # ── CRLF ──
        crlfuzz = tool_registry.get("crlfuzz")
        if crlfuzz:
            try:
                crlf_result = await _execute_tool(
                    executor, crlfuzz, target, {}, timeout=1200.0,
                )
                if crlf_result and crlf_result.findings:
                    vuln_findings.extend(crlf_result.findings)
            except Exception as _exc:
                logger.warning(f"api scan error: {_exc}")

        summary = f"API injection scan: {len(vuln_findings)} potential vulns"
        result.data = {"injection_findings": vuln_findings, "summary": summary}
        result.success = True

        state.metadata.setdefault("all_findings", []).extend(vuln_findings)
        # Sync findings to state.raw_findings so FP elimination can access them
        state.raw_findings = list(state.metadata.get("all_findings", []))
        logger.info(summary)

    except Exception as e:
        result.success = False
        result.errors.append(str(e))
        logger.error(f"API injection scan error: {e}")

    return result


async def handle_api_business_logic(state: WorkflowState) -> StageResult:
    """
    İş mantığı testleri.

    - Rate limiting bypass
    - Race condition
    - Business logic flaws
    - Mass assignment
    """
    result = StageResult(stage=WorkflowStage.VULNERABILITY_SCAN)

    try:
        target = state.target
        logger.info(f"Business logic tests started | target={target}")

        from src.tools.registry import tool_registry
        from src.tools.executor import ToolExecutor

        executor = ToolExecutor()
        logic_findings: list[dict[str, Any]] = []

        # ── Rate Limit ──
        rl_tool = tool_registry.get("rate_limit_checker")
        if rl_tool:
            try:
                rl_result = await _execute_tool(
                    executor, rl_tool, target, {}, timeout=1200.0,
                )
                if rl_result and rl_result.findings:
                    logic_findings.extend(rl_result.findings)
            except Exception as _exc:
                logger.warning(f"api scan error: {_exc}")

        # ── Race Condition ──
        race_tool = tool_registry.get("race_condition")
        if race_tool:
            try:
                race_result = await _execute_tool(
                    executor, race_tool, target, {}, timeout=1200.0,
                )
                if race_result and race_result.findings:
                    logic_findings.extend(race_result.findings)
            except Exception as _exc:
                logger.warning(f"api scan error: {_exc}")

        # ── Business Logic ──
        bl_tool = tool_registry.get("business_logic")
        if bl_tool:
            try:
                bl_result = await _execute_tool(
                    executor, bl_tool, target, {}, timeout=1200.0,
                )
                if bl_result and bl_result.findings:
                    logic_findings.extend(bl_result.findings)
            except Exception as _exc:
                logger.warning(f"api scan error: {_exc}")

        # ── Brain analizi: API yanıtlarına bakarak mantık hatası tespiti ──
        if state.brain_engine:
            try:
                from src.brain.prompts.analysis_prompts import (
                    build_vulnerability_analysis_prompt,
                )

                discovery = state.metadata.get("api_discovery", {})
                context = {
                    "target": target,
                    "endpoints": discovery.get("api_endpoints", [])[:20],
                    "parameters": discovery.get("parameters", {}),
                }

                prompt = build_vulnerability_analysis_prompt(
                    findings=[{
                        "type": "api_business_logic_review",
                        "context": str(context)[:2000],
                    }],
                    target=target,
                )

                brain_result = await state.brain_engine.analyze(prompt)
                if brain_result and brain_result.get("findings"):
                    for bf in brain_result["findings"]:
                        bf["source_tool"] = "brain_analysis"
                        logic_findings.append(bf)

            except Exception as e:
                logger.warning(f"Brain business logic analysis failed: {e}")

        summary = f"Business logic: {len(logic_findings)} potential issues"
        result.data = {"logic_findings": logic_findings, "summary": summary}
        result.success = True

        state.metadata.setdefault("all_findings", []).extend(logic_findings)
        # Sync findings to state.raw_findings so FP elimination can access them
        state.raw_findings = list(state.metadata.get("all_findings", []))
        logger.info(summary)

    except Exception as e:
        result.success = False
        result.errors.append(str(e))
        logger.error(f"Business logic test error: {e}")

    return result


# ============================================================
# Pipeline Builder
# ============================================================

def build_api_scan_pipeline(
    target: str = "",
    brain_engine: Any | None = None,
    tool_executor: Any | None = None,
    fp_detector: Any | None = None,
    profile: ScanProfile = ScanProfile.BALANCED,
    mode: OperationMode = OperationMode.SEMI_AUTONOMOUS,
    human_callback: Any = None,
    session_manager: Any | None = None,
    brain_router: Any | None = None,
) -> WorkflowOrchestrator:
    """
    API Security scan pipeline oluştur.

    Aşamalar:
    1. Scope analizi
    2. API keşfi (endpoint, spec, GraphQL)
    3. Auth analizi (JWT, OAuth, IDOR)
    4. Injection taraması (SQLi, CMDi, SSRF, SSTI)
    5. İş mantığı testleri (rate limit, race condition)
    6. FP eleme
    7. Raporlama
    8. Bilgi güncelleme
    """
    orchestrator = WorkflowOrchestrator(
        brain_engine=brain_engine,
        tool_executor=tool_executor,
        fp_detector=fp_detector,
        profile=profile,
        mode=mode,
        human_approval_callback=human_callback,
        session_manager=session_manager,
        brain_router=brain_router,
    )

    # Aşama kaydı
    orchestrator.register_handler(WorkflowStage.SCOPE_ANALYSIS, handle_scope_analysis)
    orchestrator.register_handler(WorkflowStage.PASSIVE_RECON, handle_api_discovery)
    orchestrator.register_handler(WorkflowStage.ENUMERATION, handle_api_auth_analysis)
    orchestrator.register_handler(WorkflowStage.ATTACK_SURFACE_MAP, handle_api_injection_scan)
    orchestrator.register_handler(WorkflowStage.VULNERABILITY_SCAN, handle_api_business_logic)
    orchestrator.register_handler(WorkflowStage.FP_ELIMINATION, handle_fp_elimination)
    orchestrator.register_handler(WorkflowStage.REPORTING, handle_reporting)
    orchestrator.register_handler(WorkflowStage.KNOWLEDGE_UPDATE, handle_knowledge_update)

    logger.info(
        f"API scan pipeline built | target={target} | "
        f"profile={profile} | mode={mode}"
    )

    return orchestrator
