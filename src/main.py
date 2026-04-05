"""
WhiteHatHacker AI — Ana Giriş Noktası

Bot'u başlatır, konfigürasyonu yükler, modelleri ve araçları hazırlar.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from loguru import logger


def _expand_env_vars(obj: Any) -> Any:
    """YAML değerlerindeki ${VAR:-default} kalıplarını ortam değişkenleriyle genişlet."""
    if isinstance(obj, str):
        pattern = re.compile(r"\$\{([^}:]+)(?::-(.*?))?\}")
        def _replace(m: re.Match) -> str:
            var_name = m.group(1)
            default = m.group(2) if m.group(2) is not None else ""
            return os.environ.get(var_name, default)
        return pattern.sub(_replace, obj)
    if isinstance(obj, dict):
        return {k: _expand_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_vars(item) for item in obj]
    return obj


def load_config(config_path: str = "config/settings.yaml") -> dict[str, Any]:
    """Ana konfigürasyon dosyasını yükle ve ortam değişkenlerini genişlet."""
    # .env dosyasını ortam değişkenlerine yükle
    from dotenv import load_dotenv
    load_dotenv()

    path = Path(config_path)
    if not path.exists():
        logger.error(f"Configuration file not found: {config_path}")
        sys.exit(1)

    with open(path) as f:
        config = yaml.safe_load(f)

    # Guard against empty YAML file (yaml.safe_load returns None)
    if not config or not isinstance(config, dict):
        logger.error(f"Configuration file is empty or invalid: {config_path}")
        sys.exit(1)

    # ${VAR:-default} kalıplarını genişlet (BUG-4 fix)
    config = _expand_env_vars(config)

    logger.info(f"Configuration loaded from {config_path}")
    return config


def _build_pipeline_orchestrator(
    pipeline_type: str,
    *,
    brain_engine: Any,
    tool_executor: Any,
    fp_detector: Any,
    mode: Any,
    profile: Any,
    session_manager: Any,
    brain_router: Any,
    max_iterations: int | None = None,
    time_budget_seconds: int | None = None,
) -> Any:
    """Build the requested orchestrator pipeline with consistent dependency wiring."""
    from src.workflow.pipelines import (
        build_api_scan_pipeline,
        build_full_scan_pipeline,
        build_network_scan_pipeline,
        build_quick_recon_pipeline,
        build_web_app_pipeline,
    )
    from src.workflow.pipelines.agentic_scan import build_agentic_pipeline

    pipeline_key = str(pipeline_type or "full").strip().lower()
    builders = {
        "full": lambda: build_full_scan_pipeline(
            brain_engine=brain_engine,
            tool_executor=tool_executor,
            fp_detector=fp_detector,
            mode=mode,
            profile=profile,
            session_manager=session_manager,
            brain_router=brain_router,
        ),
        "web": lambda: build_web_app_pipeline(
            brain_engine=brain_engine,
            tool_executor=tool_executor,
            fp_detector=fp_detector,
            mode=mode,
            profile=profile,
            session_manager=session_manager,
            brain_router=brain_router,
        ),
        "api": lambda: build_api_scan_pipeline(
            brain_engine=brain_engine,
            tool_executor=tool_executor,
            fp_detector=fp_detector,
            mode=mode,
            profile=profile,
            session_manager=session_manager,
            brain_router=brain_router,
        ),
        "network": lambda: build_network_scan_pipeline(
            brain_engine=brain_engine,
            tool_executor=tool_executor,
            fp_detector=fp_detector,
            mode=mode,
            profile=profile,
            session_manager=session_manager,
            brain_router=brain_router,
        ),
        "quick_recon": lambda: build_quick_recon_pipeline(
            brain_engine=brain_engine,
            tool_executor=tool_executor,
            fp_detector=fp_detector,
            mode=mode,
            profile=profile,
            session_manager=session_manager,
            brain_router=brain_router,
        ),
        "agentic": lambda: build_agentic_pipeline(
            brain_engine=brain_engine,
            tool_executor=tool_executor,
            fp_detector=fp_detector,
            mode=mode,
            profile=profile,
            session_manager=session_manager,
            brain_router=brain_router,
            max_iterations=max_iterations,
            time_budget_seconds=time_budget_seconds,
        ),
    }

    if pipeline_key not in builders:
        raise ValueError(f"Unknown pipeline type: {pipeline_type}")

    return builders[pipeline_key]()


async def initialize_app(config: dict[str, Any], pipeline_type: str = "full") -> dict[str, Any]:
    """Uygulamayı başlat — modeller, araçlar, veritabanı."""
    from src.brain.engine import BrainEngine, ModelConfig
    from src.brain.router import BrainRouter
    from src.fp_engine.fp_detector import FPDetector
    from src.tools.executor import ToolExecutor
    from src.tools.register_tools import register_all_tools
    from src.tools.registry import tool_registry
    from src.utils.constants import OperationMode, ScanProfile
    from src.utils.logger import setup_logger, log_startup_diagnostics
    from src.utils.rate_limiter import RateLimiter, RateLimitConfig
    from src.workflow.session_manager import SessionManager

    # 1. Logger kur (multi-sink)
    log_config = config.get("logging", {})
    setup_logger(
        level=log_config.get("level", "INFO"),
        log_dir=log_config.get("log_dir", "output/logs"),
        rotation=log_config.get("rotation", "100 MB"),
        retention=log_config.get("retention", "30 days"),
        serialize=log_config.get("serialize", True),
        dev_mode=log_config.get("dev_mode", False),
    )

    log_startup_diagnostics()

    logger.info("="*60)
    logger.info("  WhiteHatHacker AI v3.5 — Starting...")
    logger.info("="*60)

    # 2. Brain Engine oluştur
    from src.brain.engine import InferenceBackend

    brain_config = config.get("brain", {})

    primary_cfg = brain_config.get("primary", {})
    secondary_cfg = brain_config.get("secondary", {})

    def _build_model_config(cfg: dict[str, Any], defaults: dict[str, Any]) -> ModelConfig:
        """YAML config dict'inden ModelConfig oluştur."""
        return ModelConfig(
            name=cfg.get("name", defaults["name"]),
            backend=InferenceBackend(cfg.get("backend", "remote")),
            # Remote
            api_url=cfg.get("api_url", ""),
            api_key=cfg.get("api_key", ""),
            model_name=cfg.get("model_name", ""),
            # Local
            model_path=cfg.get("model_path", ""),
            gpu_layers=cfg.get("gpu_layers", defaults.get("gpu_layers", -1)),
            threads=cfg.get("threads", defaults.get("threads", 8)),
            batch_size=cfg.get("batch_size", defaults.get("batch_size", 512)),
            # Ortak
            context_length=cfg.get("context_length", defaults["context_length"]),
            temperature=cfg.get("temperature", defaults["temperature"]),
            top_p=cfg.get("top_p", defaults["top_p"]),
            top_k=cfg.get("top_k", defaults.get("top_k", 40)),
            repeat_penalty=cfg.get("repeat_penalty", defaults["repeat_penalty"]),
            max_tokens=cfg.get("max_tokens", defaults["max_tokens"]),
            timeout=cfg.get("timeout", defaults.get("timeout", 120.0)),
            # Qwen3 thinking mode
            thinking_mode=cfg.get("thinking_mode", defaults.get("thinking_mode")),
        )

    # Hardcoded defaults below are used when keys are MISSING from
    # config/settings.yaml → brain.primary / brain.secondary.  They silently
    # override YAML values only for absent keys; present keys always win.
    # Keep these in sync with the values documented in settings.yaml.
    primary_model_config = _build_model_config(primary_cfg, {
        "name": "Primary", "context_length": 32768, "temperature": 0.6,
        "top_p": 0.95, "top_k": 20, "repeat_penalty": 1.1,
        "max_tokens": 8192, "timeout": 600.0, "thinking_mode": True,
    })

    secondary_model_config = _build_model_config(secondary_cfg, {
        "name": "Secondary", "context_length": 32768, "temperature": 0.7,
        "top_p": 0.8, "top_k": 20, "repeat_penalty": 1.05,
        "max_tokens": 2048, "timeout": 120.0, "thinking_mode": False,
    })

    # P3-5: Lightweight fallback brain (only if configured with model_path or api_url)
    fallback_cfg = brain_config.get("fallback", {})
    fallback_model_config = None
    if fallback_cfg.get("model_path") or fallback_cfg.get("api_url"):
        fallback_model_config = _build_model_config(fallback_cfg, {
            "name": "Fallback-7B", "context_length": 8192, "temperature": 0.3,
            "top_p": 0.9, "top_k": 40, "repeat_penalty": 1.1,
            "max_tokens": 1024, "timeout": 60.0, "thinking_mode": False,
        })

    brain_engine = BrainEngine(primary_model_config, secondary_model_config, fallback_model_config)
    brain_router = BrainRouter()

    # 3. Rate Limiter
    tools_config = config.get("tools", {})
    rl_config = tools_config.get("rate_limit", {})
    rate_limiter = RateLimiter(RateLimitConfig(
        max_requests_per_second=rl_config.get("max_requests_per_second", 10),
        max_requests_per_host=rl_config.get("max_requests_per_host", 3),
        burst_size=rl_config.get("burst_size", 20),
    ))

    # 4. Tool Executor
    mode = OperationMode(config.get("mode", "semi-autonomous"))
    profile = ScanProfile(config.get("scan_profile", "balanced"))

    tool_executor = ToolExecutor(
        rate_limiter=rate_limiter,
        registry=tool_registry,
        mode=mode,
        profile=profile,
    )

    # 5. Register all security tools (BUG-1 fix)
    register_all_tools(tool_registry)
    logger.info(f"Tool registry populated: {tool_registry.count} tools available")

    # 6. FP Detector
    fp_detector = FPDetector(brain_engine=brain_engine)

    # 6b. Session Manager
    session_manager = SessionManager(output_dir="output")

    # 7. Workflow Orchestrator — with all stage handlers (BUG-2 fix)
    orchestrator = _build_pipeline_orchestrator(
        pipeline_type,
        brain_engine=brain_engine,
        tool_executor=tool_executor,
        fp_detector=fp_detector,
        mode=mode,
        profile=profile,
        session_manager=session_manager,
        brain_router=brain_router,
    )

    # 8. Database Manager
    from src.integrations.database import DatabaseManager
    db_config = config.get("database", {})
    db_path = db_config.get("path", "output/whai.db")
    database = DatabaseManager(db_path=db_path)

    components = {
        "config": config,
        "brain_engine": brain_engine,
        "brain_router": brain_router,
        "rate_limiter": rate_limiter,
        "tool_executor": tool_executor,
        "tool_registry": tool_registry,
        "fp_detector": fp_detector,
        "session_manager": session_manager,
        "orchestrator": orchestrator,
        "pipeline_type": pipeline_type,
        "database": database,
    }

    logger.info(
        f"All components initialized successfully | "
        f"tools={tool_registry.count} | mode={mode} | profile={profile} | pipeline={pipeline_type}"
    )
    return components


async def run_scan(
    target: str,
    scope: dict[str, Any] | None = None,
    config_path: str = "config/settings.yaml",
    mode_override: str | None = None,
    profile_override: str | None = None,
    allow_no_brain: bool = False,
    auth_headers: dict[str, str] | None = None,
    incremental: bool = False,
    pipeline_type: str = "full",
    max_iterations: int | None = None,
    time_budget_hours: float | None = None,
) -> Any:
    """Tam tarama çalıştır."""
    config = load_config(config_path)

    # CLI override'ları uygula
    if mode_override:
        config["mode"] = mode_override
    if profile_override:
        config["scan_profile"] = profile_override

    components = await initialize_app(config, pipeline_type=pipeline_type)

    orchestrator = components["orchestrator"]

    # Apply CLI overrides for agentic pipeline budget/iterations
    if pipeline_type == "agentic":
        if max_iterations is not None:
            orchestrator._max_iterations_override = max_iterations
        if time_budget_hours is not None:
            orchestrator._time_budget_seconds_override = int(time_budget_hours * 3600)

    # Install signal handlers for graceful shutdown
    from src.workflow.orchestrator import install_signal_handlers
    install_signal_handlers(orchestrator)

    # Scope validator ayarla (varsa)
    if scope:
        from src.utils.scope_validator import ScopeValidator
        scope_validator = ScopeValidator.from_dict(scope)
        components["tool_executor"].scope_validator = scope_validator
    else:
        # No explicit scope — create a minimal validator from target domain
        from src.utils.scope_validator import ScopeValidator, ScopeDefinition, ScopeTarget
        default_scope = ScopeDefinition(
            program_name="ad-hoc",
            targets=[ScopeTarget(value=target, target_type="domain")],
        )
        components["tool_executor"].scope_validator = ScopeValidator(scope=default_scope)
        logger.info(f"Default scope validator created from target: {target}")

    # Auth session manager — wire from scope YAML auth section
    from src.tools.auth.session_manager import build_auth_session, build_auth_roles
    auth_mgr = build_auth_session(scope or {})
    if auth_mgr:
        ok = await auth_mgr.authenticate()
        if ok:
            components["tool_executor"].auth_session = auth_mgr
            logger.info("AuthSessionManager: authenticated session attached to executor")
        else:
            logger.warning("AuthSessionManager: authentication failed — running unauthenticated")

    # Multi-role auth — build role list for IDOR pairwise testing
    _auth_role_managers = build_auth_roles(scope or {})
    _auth_roles_meta: list[dict[str, Any]] = []
    for _rm in _auth_role_managers:
        _rok = await _rm.authenticate()
        if _rok:
            _auth_roles_meta.append({
                "role_name": _rm.config.role_name,
                "headers": _rm.get_auth_headers(),
            })
    if len(_auth_roles_meta) >= 2:
        logger.info(f"Multi-role auth: {len(_auth_roles_meta)} roles authenticated for IDOR testing")

    # Legacy static auth_headers fallback
    elif auth_headers:
        from src.tools.auth.session_manager import AuthConfig, AuthSessionManager, AuthType
        cfg = AuthConfig(auth_type=AuthType.CUSTOM_HEADERS, custom_headers=auth_headers)
        legacy_mgr = AuthSessionManager(cfg)
        await legacy_mgr.authenticate()
        components["tool_executor"].auth_session = legacy_mgr
        logger.info(f"Legacy auth_headers injected — {len(auth_headers)} header(s)")

    # Brain modeli yükle ve doğrula
    brain = components["brain_engine"]
    try:
        await brain.initialize()
    except Exception as e:
        if allow_no_brain:
            logger.warning(f"Brain initialization failed: {e} — continuing without AI brain (--no-brain flag)")
        else:
            logger.critical(
                f"Brain initialization FAILED: {e}\n"
                "  → Ensure LM Studio / ollama is running and a model is loaded.\n"
                "  → Use --no-brain flag to force scan without AI (NOT RECOMMENDED)."
            )
            await brain.shutdown()
            sys.exit(1)

    # ── Pre-scan brain health check ──
    if not allow_no_brain:
        health = await brain.verify_brain_ready()
        if not health["ready"]:
            tunnel_hint = ""
            if health.get("tunnel_status") == "failed":
                tunnel_hint = (
                    "\n  → SSH TUNNEL IS DOWN! Run: bash scripts/ssh_tunnel.sh start"
                    "\n  → Or ensure the remote Mac (LM Studio host) is reachable."
                )
            logger.critical(
                f"PRE-SCAN BRAIN CHECK FAILED!\n"
                f"  → {health['error']}\n"
                f"  → Primary OK: {health['primary_ok']} | Secondary OK: {health['secondary_ok']}\n"
                f"  → Tunnel: {health.get('tunnel_status', 'unknown')}\n"
                f"  → Models found: {health['models'] or 'NONE'}"
                f"{tunnel_hint}\n"
                f"  → Fix: Load a model in LM Studio, then restart the scan.\n"
                f"  → Or use --no-brain flag to force scan without AI (NOT RECOMMENDED)."
            )
            await brain.shutdown()
            sys.exit(1)
        else:
            logger.info(
                f"Pre-scan brain check PASSED | "
                f"tunnel={health.get('tunnel_status', 'n/a')} | "
                f"primary={'OK' if health['primary_ok'] else 'FAIL'} | "
                f"secondary={'OK' if health['secondary_ok'] else 'FAIL'} | "
                f"models={health['models']}"
            )
            # Start background tunnel watchdog to auto-reconnect during scan
            await brain.start_tunnel_watchdog(interval=60.0)
    else:
        logger.warning(
            "Pre-scan brain check SKIPPED (--no-brain flag). "
            "Bot will run without AI brain — findings quality will be significantly reduced."
        )

    # Taramayı başlat
    try:
        extra_metadata = {}
        if auth_headers:
            extra_metadata["auth_headers"] = auth_headers
            logger.info(f"Authenticated scanning enabled — {len(auth_headers)} header(s) injected")
        if _auth_roles_meta:
            extra_metadata["auth_roles"] = _auth_roles_meta
        if incremental:
            extra_metadata["incremental"] = True
            logger.info("Incremental scan mode — only new/changed assets will be scanned")
        extra_metadata["pipeline_type"] = pipeline_type
        state = await orchestrator.run(target=target, scope=scope, extra_metadata=extra_metadata)
    finally:
        # Temizlik — always shutdown brain even on failure
        await brain.stop_tunnel_watchdog()
        await brain.shutdown()

    return state


async def resume_scan(
    session_id: str,
    config_path: str = "config/settings.yaml",
    allow_no_brain: bool = False,
    pipeline_type: str | None = None,
) -> Any:
    """Resume an interrupted scan from its last checkpoint."""
    from src.workflow.session_manager import SessionManager

    sm = SessionManager(output_dir="output")
    session = sm.load_session(session_id)
    if not session:
        logger.error(f"Session {session_id} not found")
        sys.exit(1)

    config = load_config(config_path)
    # Restore mode/profile from session
    config["mode"] = session.metadata.mode or config.get("mode", "semi-autonomous")
    config["scan_profile"] = session.metadata.profile or config.get("scan_profile", "balanced")

    pipeline_type = pipeline_type or session.workflow_metadata.get("pipeline_type", "full")
    components = await initialize_app(config, pipeline_type=pipeline_type)
    orchestrator = components["orchestrator"]

    from src.workflow.orchestrator import install_signal_handlers
    install_signal_handlers(orchestrator)

    brain = components["brain_engine"]
    try:
        await brain.initialize()
    except Exception as e:
        if allow_no_brain:
            logger.warning(f"Brain init failed: {e} — continuing without AI brain")
        else:
            logger.critical(f"Brain initialization FAILED: {e}")
            await brain.shutdown()
            sys.exit(1)

    if not allow_no_brain:
        health = await brain.verify_brain_ready()
        if not health["ready"]:
            logger.critical(f"PRE-SCAN BRAIN CHECK FAILED: {health['error']}")
            await brain.shutdown()
            sys.exit(1)

    # Determine resume stage
    from src.utils.constants import WorkflowStage
    completed = session.metadata.completed_stages or []
    all_stages = list(WorkflowStage)
    start_from = None
    for stage in all_stages:
        if str(stage) not in completed and stage.value not in completed:
            start_from = stage
            break

    logger.info(
        f"RESUMING scan | session={session_id} | target={session.metadata.target} | "
        f"completed_stages={len(completed)} | resuming_from={start_from}"
    )

    try:
        # Start the orchestrator with start_from — it creates a fresh WorkflowState
        # We need to hook into the state after creation to inject session data
        # Store the session and SM on orchestrator for the run() method to use
        orchestrator._resume_session = session
        orchestrator._resume_sm = sm
        state = await orchestrator.run(
            target=session.metadata.target,
            scope=session.metadata.scope_config or None,
            start_from=start_from,
            extra_metadata={"resumed_from": session_id},
        )
    finally:
        await brain.shutdown()

    return state


def main() -> None:
    """CLI ana giriş noktası."""
    # Typer CLI'a yönlendir
    from src.cli import app
    app()


if __name__ == "__main__":
    main()
