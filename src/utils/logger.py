"""
WhiteHatHacker AI — Gelişmiş Yapılandırılmış Loglama Sistemi (v2)

Multi-sink loguru tabanlı loglama:
  • KONSOL   — Renkli, okunabilir, filtrelenmiş (level'e göre)
  • ANA LOG  — Tüm seviyeler, JSON serialize, rotasyonlu
  • HATA LOG — Sadece WARNING+, ayrı dosya, hızlı hata taraması
  • DEBUG LOG — TRACE+DEBUG, ayrı dosya, geliştirme sürecinde detay
  • BRAIN LOG — Brain engine istek/yanıt, ayrı dosya
  • TOOL LOG  — Araç çalıştırma detayları, ayrı dosya

Her tarama oturumu benzersiz session ID ile loglanır.
Hassas veriler (API key, credential) ASLA loglanmaz.
Exception'lar tam traceback ile otomatik yakalanır.
"""

from __future__ import annotations

import atexit
import re
import secrets
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from loguru import logger

from src.utils.constants import SESSION_ID_LENGTH


# ============================================================
# Hassas Veri Filtreleme
# ============================================================

_SENSITIVE_PATTERNS: tuple[str, ...] = (
    "api_key", "api_token", "apikey", "secret_key", "client_secret",
    "password", "credential", "bearer", "cookie",
    "jwt", "private_key", "access_key",
    "refresh_token", "authorization", "auth_token", "auth_key",
)

# Önceden derlenmiş regex — kelime sınırı ile daha hassas eşleme
_SENSITIVE_RE = re.compile(
    r'\b(' + '|'.join(re.escape(p) for p in _SENSITIVE_PATTERNS) + r')\s*[=:]\s*\S+',
    re.IGNORECASE,
)


def _sanitize_message(message: str) -> str:
    """Mesajdaki hassas verileri maskele."""
    if not message:
        return message
    return _SENSITIVE_RE.sub(r'\1=***REDACTED***', message)


def _sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Log kaydındaki hassas verileri maskele (sink filter olarak kullanılır)."""
    record["message"] = _sanitize_message(str(record.get("message", "")))
    return record


# ============================================================
# Session ID Yönetimi (Thread-safe)
# ============================================================

_current_session_id: str | None = None
_session_lock = threading.Lock()


def generate_session_id() -> str:
    """Benzersiz tarama oturumu ID'si oluştur."""
    global _current_session_id
    with _session_lock:
        _current_session_id = secrets.token_hex(SESSION_ID_LENGTH // 2)
        return _current_session_id


def get_session_id() -> str:
    """Mevcut oturum ID'sini döndür (yoksa otomatik oluştur)."""
    global _current_session_id
    with _session_lock:
        if _current_session_id is None:
            _current_session_id = secrets.token_hex(SESSION_ID_LENGTH // 2)
        return _current_session_id


# ============================================================
# Extra Context — her log kaydına session + extra bilgi ekle
# ============================================================

# Use contextvars instead of threading.local for proper async coroutine isolation
import contextvars
_log_context_var: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "_log_context_var", default={}
)


def set_log_context(**kwargs: Any) -> None:
    """Set extra log context (e.g. stage, tool_name, target). Async-safe via contextvars."""
    current = _log_context_var.get().copy()
    current.update(kwargs)
    _log_context_var.set(current)


def clear_log_context() -> None:
    """Clear log context."""
    _log_context_var.set({})


def get_log_context() -> dict[str, Any]:
    """Get current log context."""
    return _log_context_var.get()


@contextmanager
def log_context(**kwargs: Any) -> Generator[None, None, None]:
    """Context manager ile geçici log context.

    Kullanım:
        with log_context(stage="passive_recon", target="example.com"):
            logger.info("Tarama başladı")
    """
    old = _log_context_var.get().copy()
    set_log_context(**kwargs)
    try:
        yield
    finally:
        _log_context_var.set(old)


def _inject_context(record: dict[str, Any]) -> None:
    """Loguru patcher — her kayda session_id, context ekle + hassas veri maskele.

    Sanitization burada yapılır (patcher her kayıt başına 1 kez çalışır)
    — böylece 6 sink filter'ında ayrı ayrı regex çalışmaz.
    """
    record["extra"]["session_id"] = get_session_id()[:8]
    ctx = get_log_context()
    if ctx:
        record["extra"]["ctx"] = ctx
    # Sanitize once in patcher, not per-sink
    record["message"] = _sanitize_message(str(record.get("message", "")))


# ============================================================
# Performans Ölçüm Yardımcıları
# ============================================================

@contextmanager
def log_duration(
    operation: str,
    level: str = "DEBUG",
    warn_threshold: float = 0.0,
) -> Generator[dict[str, Any], None, None]:
    """Bir işlemin süresini ölç ve logla.

    Args:
        operation: İşlem adı
        level: Normal log seviyesi
        warn_threshold: Bu süreden uzun sürerse WARNING seviyesinde logla (saniye, 0=kapalı)

    Kullanım:
        with log_duration("nmap taraması", warn_threshold=60.0) as d:
            await run_nmap(...)
        # Otomatik olarak süre loglanır
        # d["elapsed"] ile süreye erişilebilir
    """
    result: dict[str, Any] = {"elapsed": 0.0, "operation": operation}
    t0 = time.perf_counter()
    try:
        yield result
    finally:
        elapsed = time.perf_counter() - t0
        result["elapsed"] = elapsed
        msg = f"⏱ {operation} | {elapsed:.3f}s"
        if warn_threshold > 0 and elapsed > warn_threshold:
            logger.warning(f"{msg} (threshold={warn_threshold}s EXCEEDED)")
        else:
            logger.log(level, msg)


# ============================================================
# Exception Formatting
# ============================================================

def format_exception_chain(exc: BaseException) -> str:
    """Exception zincirini okunabilir stringe çevir (cause dahil)."""
    parts: list[str] = []
    current: BaseException | None = exc
    depth = 0
    while current and depth < 10:
        tb = "".join(traceback.format_exception(type(current), current, current.__traceback__))
        parts.append(f"{'  [Caused by] ' if depth > 0 else ''}{tb.strip()}")
        current = current.__cause__ or current.__context__
        depth += 1
    return "\n".join(parts)


# ============================================================
# Sink Formatları
# ============================================================

# Konsol — renkli, kompakt, okunabilir
_CONSOLE_FORMAT = (
    "<green>{time:HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>[{extra[session_id]}]</cyan> | "
    "<blue>{name}</blue>:<blue>{function}</blue>:<blue>{line}</blue> | "
    "<level>{message}</level>"
)

# Dosya — tek satır, ayrıntılı, grep-dostu
_FILE_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
    "[{extra[session_id]}] | {process.id}:{thread.name} | "
    "{name}:{function}:{line} | {message}"
)

# Hata dosyası — exception bilgisi dahil
_ERROR_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
    "[{extra[session_id]}] | {process.id}:{thread.name} | "
    "{name}:{function}:{line} | {message}"
)


# ============================================================
# Ana Logger Konfigürasyonu — Çok Katmanlı (Multi-Sink)
# ============================================================

_setup_done = False
_sink_ids: list[int] = []


def setup_logger(
    level: str = "INFO",
    log_file: str | None = None,
    rotation: str = "100 MB",
    retention: str = "30 days",
    serialize: bool = True,
    dev_mode: bool = False,
    log_dir: str | None = None,
) -> None:
    """
    Çok katmanlı yapılandırılmış logger'ı kur.

    Args:
        level: Konsol log seviyesi (DEBUG, INFO, WARNING, ERROR)
        log_file: Ana log dosyası yolu (None = otomatik oluştur)
        rotation: Dosya rotasyonu boyutu
        retention: Log dosyası saklama süresi
        serialize: JSON formatında mı logla (dosya sink'leri için)
        dev_mode: True ise DEBUG seviyesinde konsola yazar + ekstra debug dosyası
        log_dir: Log dizini (varsayılan: output/logs)

    Sinkler:
        1. KONSOL:    Renkli, level'e göre filtrelenir
        2. ANA LOG:   Tüm seviyeler, JSON, rotasyonlu                 → whai_YYYY-MM-DD.log
        3. HATA LOG:  Sadece WARNING+ERROR+CRITICAL, ayrı dosya       → errors_YYYY-MM-DD.log
        4. DEBUG LOG: TRACE+DEBUG, ayrı dosya (dev_mode'da)            → debug_YYYY-MM-DD.log
        5. BRAIN LOG: Brain engine çağrıları (brain modülü filtresi)   → brain_YYYY-MM-DD.log
        6. TOOL LOG:  Araç çalıştırma (tools modülü filtresi)         → tools_YYYY-MM-DD.log
    """
    global _setup_done, _sink_ids

    # Mevcut handler'ları temizle
    logger.remove()
    _sink_ids.clear()

    # Patcher — her kayda session_id ve context ekle
    logger.configure(patcher=_inject_context)

    session_id = get_session_id()
    console_level = "DEBUG" if dev_mode else level.upper()

    # ── SINK 1: Konsol (stderr) ──────────────────────────────
    sid = logger.add(
        sys.stderr,
        format=_CONSOLE_FORMAT,
        level=console_level,
        colorize=True,
        backtrace=True,
        diagnose=dev_mode,  # dev_mode'da detaylı traceback
    )
    _sink_ids.append(sid)

    # Log dizinini belirle
    logs_dir = Path(log_dir) if log_dir else Path("output/logs")
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Bugünün tarihi — dosya adlarında
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # ── SINK 2: Ana Log (tüm seviyeler, JSON) ───────────────
    main_log = log_file or str(logs_dir / f"whai_{today}.log")
    Path(main_log).parent.mkdir(parents=True, exist_ok=True)
    sid = logger.add(
        main_log,
        format=_FILE_FORMAT,
        level="TRACE",  # Her şeyi kaydet
        rotation=rotation,
        retention=retention,
        serialize=serialize,
        compression="gz",
        encoding="utf-8",
        backtrace=True,
        diagnose=True,
        enqueue=True,  # Thread-safe async writing
    )
    _sink_ids.append(sid)

    # ── SINK 3: Hata Log (WARNING ve üzeri) ──────────────────
    error_log = str(logs_dir / f"errors_{today}.log")
    sid = logger.add(
        error_log,
        format=_ERROR_FORMAT,
        level="WARNING",
        rotation=rotation,
        retention=retention,
        serialize=serialize,
        compression="gz",
        encoding="utf-8",
        backtrace=True,
        diagnose=True,
        enqueue=True,
    )
    _sink_ids.append(sid)

    # ── SINK 4: Debug Log (TRACE + DEBUG, dev_mode'da) ───────
    if dev_mode:
        debug_log = str(logs_dir / f"debug_{today}.log")
        sid = logger.add(
            debug_log,
            format=_FILE_FORMAT,
            level="TRACE",
            rotation="50 MB",
            retention="7 days",
            serialize=False,  # Okunabilir flat text
            compression="gz",
            encoding="utf-8",
            filter=lambda record: record["level"].no <= 10,  # TRACE(5) + DEBUG(10)
            backtrace=True,
            diagnose=True,
            enqueue=True,
        )
        _sink_ids.append(sid)

    # ── SINK 5: Brain Log (brain modülü) ─────────────────────
    brain_log = str(logs_dir / f"brain_{today}.log")
    sid = logger.add(
        brain_log,
        format=_FILE_FORMAT,
        level="DEBUG",
        rotation=rotation,
        retention=retention,
        serialize=serialize,
        encoding="utf-8",
        filter=lambda record: "src.brain" in record["name"],
        backtrace=True,
        diagnose=True,
        enqueue=True,
    )
    _sink_ids.append(sid)

    # ── SINK 6: Tool Log (tools modülü) ──────────────────────
    tool_log = str(logs_dir / f"tools_{today}.log")
    sid = logger.add(
        tool_log,
        format=_FILE_FORMAT,
        level="DEBUG",
        rotation=rotation,
        retention=retention,
        serialize=serialize,
        encoding="utf-8",
        filter=lambda record: (
            "src.tools" in record["name"] or "src.workflow" in record["name"]
        ),
        backtrace=True,
        diagnose=True,
        enqueue=True,
    )
    _sink_ids.append(sid)

    _setup_done = True

    logger.info(
        f"Logger initialized | session={session_id} | console_level={console_level} | "
        f"dev_mode={dev_mode} | sinks={len(_sink_ids)} | log_dir={logs_dir}"
    )


# ============================================================
# Modül-Spesifik Logger
# ============================================================

def get_logger(name: str) -> "logger":
    """Modül-spesifik logger döndür (bind ile ek meta ekler)."""
    return logger.bind(module=name)


# ============================================================
# Exception Hook — Yakalanmamış exception'ları logla
# ============================================================

def _unhandled_exception_hook(exc_type: type, exc_value: BaseException, exc_tb: Any) -> None:
    """sys.excepthook — yakalanmamış exception'ları ERROR seviyesinde logla."""
    if issubclass(exc_type, KeyboardInterrupt):
        # Ctrl+C normal çıkış
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    logger.opt(exception=(exc_type, exc_value, exc_tb)).critical(
        f"Unhandled exception: {exc_type.__name__}: {exc_value}"
    )


# İlk import'ta exception hook'u kaydet
sys.excepthook = _unhandled_exception_hook


# ============================================================
# Structured Event Loggers — Belirli olay türleri için
# ============================================================

def log_tool_execution(
    tool_name: str,
    target: str,
    command: str = "",
    exit_code: int | None = None,
    duration: float = 0.0,
    findings_count: int = 0,
    error: str = "",
    **extra: Any,
) -> None:
    """Araç çalıştırmasını yapılandırılmış formatta logla."""
    parts = [f"TOOL_EXEC | tool={tool_name} | target={target}"]
    if command:
        # Komutu kısalt (çok uzunsa)
        cmd_display = command[:300] + ("..." if len(command) > 300 else "")
        parts.append(f"cmd={cmd_display}")
    if exit_code is not None:
        parts.append(f"exit={exit_code}")
    parts.append(f"duration={duration:.2f}s")
    if findings_count:
        parts.append(f"findings={findings_count}")
    if error:
        parts.append(f"error={error[:200]}")
    for k, v in extra.items():
        parts.append(f"{k}={v}")

    msg = " | ".join(parts)
    if error:
        logger.error(msg)
    elif exit_code and exit_code != 0:
        logger.warning(msg)
    else:
        logger.info(msg)


def log_brain_call(
    brain_type: str,
    prompt_preview: str = "",
    response_preview: str = "",
    tokens_used: int = 0,
    duration: float = 0.0,
    model_name: str = "",
    error: str = "",
    **extra: Any,
) -> None:
    """Brain engine çağrısını yapılandırılmış formatta logla."""
    parts = [f"BRAIN_CALL | brain={brain_type}"]
    if model_name:
        parts.append(f"model={model_name}")
    if prompt_preview:
        parts.append(f"prompt={prompt_preview[:150]}...")
    if response_preview:
        parts.append(f"response={response_preview[:150]}...")
    if tokens_used:
        parts.append(f"tokens={tokens_used}")
    parts.append(f"duration={duration:.2f}s")
    if error:
        parts.append(f"error={error[:200]}")
    for k, v in extra.items():
        parts.append(f"{k}={v}")

    msg = " | ".join(parts)
    if error:
        logger.error(msg)
    else:
        logger.debug(msg)


def log_finding(
    title: str,
    severity: str,
    confidence: float,
    vuln_type: str = "",
    target: str = "",
    tool: str = "",
    fp_verdict: str = "",
    **extra: Any,
) -> None:
    """Zafiyet bulgusunu yapılandırılmış formatta logla."""
    parts = [
        f"FINDING | severity={severity} | confidence={confidence:.0f}",
        f"title={title[:100]}",
    ]
    if vuln_type:
        parts.append(f"type={vuln_type}")
    if target:
        parts.append(f"target={target}")
    if tool:
        parts.append(f"tool={tool}")
    if fp_verdict:
        parts.append(f"fp={fp_verdict}")
    for k, v in extra.items():
        parts.append(f"{k}={v}")

    msg = " | ".join(parts)
    if severity in ("critical", "high"):
        logger.warning(msg)
    else:
        logger.info(msg)


def log_stage_transition(
    from_stage: str,
    to_stage: str,
    duration: float = 0.0,
    findings_so_far: int = 0,
    **extra: Any,
) -> None:
    """Workflow aşama geçişini logla."""
    parts = [
        f"STAGE_TRANSITION | {from_stage} → {to_stage}",
        f"duration={duration:.1f}s",
        f"findings_so_far={findings_so_far}",
    ]
    for k, v in extra.items():
        parts.append(f"{k}={v}")
    logger.info(" | ".join(parts))


def log_scope_check(
    target: str,
    result: str,
    reason: str = "",
) -> None:
    """Scope doğrulama sonucunu logla."""
    msg = f"SCOPE_CHECK | target={target} | result={result}"
    if reason:
        msg += f" | reason={reason}"
    if result == "REJECT":
        logger.warning(msg)
    else:
        logger.debug(msg)


def log_http_exchange(
    method: str,
    url: str,
    status_code: int = 0,
    duration: float = 0.0,
    request_size: int = 0,
    response_size: int = 0,
    error: str = "",
    **extra: Any,
) -> None:
    """HTTP istek/yanıt çiftini logla."""
    parts = [f"HTTP | {method} {url[:200]}"]
    if status_code:
        parts.append(f"status={status_code}")
    parts.append(f"duration={duration:.3f}s")
    if request_size:
        parts.append(f"req_size={request_size}")
    if response_size:
        parts.append(f"resp_size={response_size}")
    if error:
        parts.append(f"error={error[:200]}")
    for k, v in extra.items():
        parts.append(f"{k}={v}")

    msg = " | ".join(parts)
    if error or status_code >= 500:
        logger.error(msg)
    elif status_code >= 400:
        logger.warning(msg)
    else:
        logger.debug(msg)


# ============================================================
# Startup Diagnostics — Başlangıçta sistem durumunu logla
# ============================================================

def log_startup_diagnostics() -> None:
    """Uygulama başlangıcında sistem ve konfigürasyon bilgilerini logla."""
    import platform

    diag_lines = [
        "STARTUP_DIAGNOSTICS",
        f"  python={platform.python_version()}",
        f"  os={platform.system()} {platform.release()}",
        f"  arch={platform.machine()}",
        f"  pid={__import__('os').getpid()}",
        f"  cwd={Path.cwd()}",
        f"  session={get_session_id()}",
    ]

    # GPU bilgisi (varsa)
    try:
        import subprocess
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            diag_lines.append(f"  gpu={result.stdout.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        diag_lines.append("  gpu=none")

    # RAM bilgisi
    try:
        import shutil
        total, used, free = shutil.disk_usage("/")
        diag_lines.append(f"  disk_free={free // (1024**3)}GB")
    except Exception as _exc:
        logger.debug(f"logger error: {_exc}")

    logger.info("\n".join(diag_lines))


# ============================================================
# Atexit — Clean shutdown
# ============================================================

def _shutdown_logger() -> None:
    """Process çıkışında log buffer'larını flush et."""
    try:
        logger.complete()
    except (ValueError, OSError, RuntimeError):
        # Stream already closed during interpreter shutdown (common in pytest)
        pass
    except Exception:
        pass


atexit.register(_shutdown_logger)


# ============================================================
# Public API
# ============================================================

__all__ = [
    # Core
    "logger",
    "setup_logger",
    "get_logger",
    # Session
    "generate_session_id",
    "get_session_id",
    # Context
    "set_log_context",
    "clear_log_context",
    "get_log_context",
    "log_context",
    # Structured loggers
    "log_tool_execution",
    "log_brain_call",
    "log_finding",
    "log_stage_transition",
    "log_scope_check",
    "log_http_exchange",
    # Utilities
    "log_duration",
    "format_exception_chain",
    "log_startup_diagnostics",
]
