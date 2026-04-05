"""
WhiteHatHacker AI — Araç Çalıştırma Motoru

Güvenlik araçlarını güvenli şekilde çalıştırır.
Her çalıştırma öncesinde:
  1. Scope doğrulama
  2. Rate limit kontrolü
  3. Risk seviyesi kontrolü (insan onayı gerekebilir)

Transient failure'lar (timeout, bağlantı hatası, geçici hata)
otomatik olarak exponential backoff ile yeniden denenir.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

from loguru import logger

from src.tools.auth.session_manager import AuthSessionManager
from src.tools.base import SecurityTool, ToolResult
from src.tools.registry import ToolRegistry, tool_registry
from src.utils.constants import OperationMode, RiskLevel, ScanProfile
from src.utils.rate_limiter import RateLimiter
from src.utils.scope_validator import ScopeValidator

# ── Retry configuration ──────────────────────────────────────
DEFAULT_MAX_RETRIES = 2          # Max retry attempts (total runs = 1 + retries)
RETRY_BASE_DELAY = 3.0           # Base delay in seconds
RETRY_BACKOFF_FACTOR = 2.0       # Exponential backoff multiplier
RETRY_MAX_DELAY = 30.0           # Max delay between retries

# Error patterns that indicate transient (retryable) failures
_RETRYABLE_PATTERNS = (
    "timeout",
    "timed out",
    "connection refused",
    "connection reset",
    "network unreachable",
    "name resolution",
    "dns resolution",
    "temporary failure",
    "resource temporarily unavailable",
    "broken pipe",
    "too many open files",
    "waf",
    "blocked",
    "rate limit",
    "rate-limit",
    "429",
    "403 forbidden",
    "access denied",
)

# Error patterns that should NEVER be retried
_NON_RETRYABLE_PATTERNS = (
    "out of scope",
    "not registered",
    "not installed",
    "not available",
    "risk tool rejected",
    "scope",
)


class ToolExecutor:
    """
    Güvenlik araçları çalıştırma motoru.

    Her araç çalıştırılmadan önce:
    - Scope doğrulaması
    - Rate limiting
    - Risk seviyesi kontrolü
    - İnsan onayı (yarı-otonom modda, yüksek riskli araçlar için)

    Kullanım:
        executor = ToolExecutor(scope_validator, rate_limiter)
        result = await executor.run_tool("nmap", "example.com", options={...})
        results = await executor.run_parallel(["subfinder", "amass"], "example.com")
    """

    def __init__(
        self,
        scope_validator: ScopeValidator | None = None,
        rate_limiter: RateLimiter | None = None,
        registry: ToolRegistry | None = None,
        mode: OperationMode = OperationMode.SEMI_AUTONOMOUS,
        profile: ScanProfile = ScanProfile.BALANCED,
        human_approval_callback: Any | None = None,
    ) -> None:
        self.scope_validator = scope_validator
        self.rate_limiter = rate_limiter or RateLimiter()
        self.registry = registry or tool_registry
        self.mode = mode
        self.profile = profile
        self.human_approval_callback = human_approval_callback

        self._execution_history: list[dict[str, Any]] = []
        self._max_history_size = 500  # Evict oldest entries beyond this limit
        self._blocked_count = 0
        self.perf_profiler: Any = None  # Optional PerfProfiler for T4-4
        self.auth_session: AuthSessionManager | None = None  # V14-T0: Auth injection

        logger.info(
            f"ToolExecutor initialized | mode={mode} | profile={profile} | "
            f"tools={len(self.registry)}"
        )

    async def run_tool(
        self,
        tool_name: str,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile | None = None,
        skip_scope_check: bool = False,
        max_retries: int | None = None,
    ) -> ToolResult:
        """
        Tek bir aracı çalıştır (tam güvenlik kontrolleri + otomatik retry ile).

        Transient failure'lar (timeout, bağlantı hatası) exponential backoff
        ile otomatik yeniden denenir. Scope/risk reddleri retry edilmez.

        Args:
            tool_name: Araç adı (registry'deki)
            target: Hedef URL/IP/domain
            options: Araç-spesifik opsiyonlar
            profile: Tarama profili (None = global default)
            skip_scope_check: Scope kontrolünü atla (TEHLİKELİ — sadece internal test)
            max_retries: Override retry sayısı (None = DEFAULT_MAX_RETRIES)

        Returns:
            ToolResult
        """
        retries = max_retries if max_retries is not None else DEFAULT_MAX_RETRIES

        # 0. Target type safety — Swagger/API parsers may produce list[str]
        if isinstance(target, list):
            target = target[0] if target else ""
        if not isinstance(target, str):
            target = str(target)

        # 1. Aracı bul
        tool = self.registry.get(tool_name)
        if tool is None:
            logger.error(f"Tool not found: {tool_name}")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error_message=f"Tool '{tool_name}' not registered",
                target=target,
            )

        # 2. Araç kurulu mu?
        if not tool.is_available():
            logger.error(f"Tool not available: {tool_name}")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error_message=f"Tool '{tool_name}' is not installed",
                target=target,
            )

        # 3. Scope kontrolü (ZORUNLU — atlanamaz, skip sadece internal test için)
        if not skip_scope_check:
            if self.scope_validator:
                is_valid, reason = self.scope_validator.validate_target(target)
                if not is_valid:
                    logger.warning(f"BLOCKED (scope) | tool={tool_name} | target={target} | reason={reason}")
                    self._blocked_count += 1
                    return ToolResult(
                        tool_name=tool_name,
                        success=False,
                        error_message=f"Target out of scope: {reason}",
                        target=target,
                    )
            else:
                # Scope validator olmadan çalışmak tehlikeli — block execution
                logger.error(
                    f"BLOCKED (no scope validator) | tool={tool_name} | target={target} | "
                    "Refusing to run tool without scope enforcement."
                )
                self._blocked_count += 1
                return ToolResult(
                    tool_name=tool_name,
                    success=False,
                    error_message="No scope validator configured — refusing to execute",
                    target=target,
                )

        # 4. Risk seviyesi kontrolü
        if not await self._check_risk_approval(tool, target):
            logger.warning(f"BLOCKED (risk) | tool={tool_name} | target={target} | risk={tool.risk_level}")
            self._blocked_count += 1
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error_message=f"High risk tool rejected (risk={tool.risk_level})",
                target=target,
            )

        # 5. Rate limiting
        host = self._extract_host(target)
        await self.rate_limiter.acquire(host)

        # 5b. Auth injection — merge session headers/cookies into options
        options = self._inject_auth(options or {})

        # 6. Çalıştır (retry loop ile)
        use_profile = profile or self.profile
        last_result: ToolResult | None = None

        for attempt in range(1 + retries):
            if attempt > 0:
                _base_delay = RETRY_BASE_DELAY * (RETRY_BACKOFF_FACTOR ** (attempt - 1))
                _jitter = random.uniform(0, _base_delay * 0.5)  # noqa: S311
                delay = min(_base_delay + _jitter, RETRY_MAX_DELAY)
                logger.warning(
                    f"Retrying tool | name={tool_name} | target={target} | "
                    f"attempt={attempt + 1}/{1 + retries} | delay={delay:.1f}s"
                )
                await asyncio.sleep(delay)
                # Re-acquire rate limit before retry
                await self.rate_limiter.acquire(host)

            logger.info(
                f"Running tool | name={tool_name} | target={target} | "
                f"profile={use_profile}"
                + (f" | attempt={attempt + 1}/{1 + retries}" if attempt > 0 else "")
            )

            import time as _time
            _exec_start = _time.monotonic()

            try:
                # Executor-level timeout as safety net
                # Use 1.5x the tool's default timeout to allow graceful tool-level timeout first
                executor_timeout = getattr(tool, 'default_timeout', 600) * 1.5 + 30
                result = await asyncio.wait_for(
                    tool.run(target, options, use_profile),
                    timeout=executor_timeout,
                )

                # Measure execution time at executor level (wrappers may not set it)
                _exec_elapsed = _time.monotonic() - _exec_start
                if result.execution_time == 0.0:
                    result.execution_time = round(_exec_elapsed, 2)

                # Geçmişe ekle (evict oldest if over limit)
                self._execution_history.append({
                    "tool": tool_name,
                    "target": target,
                    "success": result.success,
                    "findings_count": len(result.findings),
                    "execution_time": result.execution_time,
                    "attempt": attempt + 1,
                })
                if len(self._execution_history) > self._max_history_size:
                    self._execution_history = self._execution_history[-self._max_history_size:]

                logger.info(
                    f"Tool completed | name={tool_name} | "
                    f"success={result.success} | "
                    f"findings={len(result.findings)} | "
                    f"time={result.execution_time:.1f}s"
                    + (f" | attempt={attempt + 1}" if attempt > 0 else "")
                )

                # ── PerfProfiler: record tool timing (T4-4 / P2-2) ──
                if self.perf_profiler:
                    try:
                        self.perf_profiler.record_tool(
                            name=tool_name,
                            duration=result.execution_time,
                            success=result.success,
                        )
                    except Exception as _prof_err:
                        logger.warning(f"PerfProfiler.record_tool failed: {_prof_err}")

                # Success or non-retryable failure → return immediately
                if result.success or not self._is_retryable(result):
                    return result

                # Retryable failure — store and continue loop
                last_result = result
                logger.warning(
                    f"Tool failed (retryable) | name={tool_name} | "
                    f"error={result.error_message}"
                )
                continue

            except asyncio.TimeoutError:
                _exec_elapsed = _time.monotonic() - _exec_start
                logger.error(
                    f"Tool executor timeout | name={tool_name} | "
                    f"elapsed={_exec_elapsed:.1f}s"
                    + (f" | attempt={attempt + 1}" if attempt > 0 else "")
                )
                last_result = ToolResult(
                    tool_name=tool_name,
                    success=False,
                    error_message=f"Executor timeout after {_exec_elapsed:.0f}s",
                    target=target,
                )
                # Timeout is always retryable
                continue

            except Exception as e:
                logger.error(
                    f"Tool execution failed | name={tool_name} | error={e}"
                    + (f" | attempt={attempt + 1}" if attempt > 0 else "")
                )
                last_result = ToolResult(
                    tool_name=tool_name,
                    success=False,
                    error_message=str(e),
                    target=target,
                )
                # Check if exception is retryable
                if not self._is_retryable(last_result):
                    return last_result
                continue

        # All retries exhausted — return the last result
        if last_result is not None and retries > 0:
            logger.error(
                f"Tool FAILED after {1 + retries} attempts | name={tool_name} | "
                f"target={target} | last_error={last_result.error_message}"
            )
        return last_result or ToolResult(
            tool_name=tool_name,
            success=False,
            error_message="Unknown failure after retries",
            target=target,
        )

    async def execute(
        self,
        tool: SecurityTool,
        target: str,
        options: dict[str, Any] | None = None,
    ) -> ToolResult:
        """
        Araç NESNESI ile çalıştır (pipeline handler'lar için köprü metod).

        Pipeline handler'lar tool_registry'den bir tool nesnesi alır ve
        doğrudan bu nesne ile çalıştırmak ister. Bu metod, run_tool() üzerinden
        tüm güvenlik kontrollerini uygulayarak çalıştırır.

        Args:
            tool: SecurityTool nesnesi (registry'den alınmış)
            target: Hedef URL/IP/domain
            options: Araç-spesifik opsiyonlar

        Returns:
            ToolResult
        """
        return await self.run_tool(
            tool_name=tool.name,
            target=target,
            options=options,
        )

    async def run_parallel(
        self,
        tool_names: list[str],
        target: str,
        options: dict[str, dict[str, Any]] | None = None,
        max_concurrent: int = 5,
    ) -> list[ToolResult]:
        """
        Birden fazla aracı paralel çalıştır.

        Args:
            tool_names: Araç adları listesi
            target: Hedef
            options: Araç-spesifik opsiyonlar dict'i {tool_name: {options}}
            max_concurrent: Maksimum eşzamanlı araç sayısı

        Returns:
            ToolResult listesi
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        options = options or {}

        async def _run_with_semaphore(tool_name: str) -> ToolResult:
            async with semaphore:
                return await self.run_tool(
                    tool_name, target, options.get(tool_name)
                )

        tasks = [_run_with_semaphore(name) for name in tool_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Exception'ları ToolResult'a dönüştür
        processed: list[ToolResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append(ToolResult(
                    tool_name=tool_names[i],
                    success=False,
                    error_message=str(result),
                    target=target,
                ))
            else:
                processed.append(result)

        total_findings = sum(len(r.findings) for r in processed)
        successful = sum(1 for r in processed if r.success)
        logger.info(
            f"Parallel execution complete | "
            f"tools={len(tool_names)} | successful={successful} | "
            f"total_findings={total_findings}"
        )

        return processed

    async def run_chain(
        self,
        tool_chain: list[tuple[str, dict[str, Any] | None]],
        target: str,
        stop_on_failure: bool = False,
    ) -> list[ToolResult]:
        """
        Araçları sıralı (zincir) olarak çalıştır.
        Bir önceki aracın çıktısı bir sonrakine girdi olabilir.

        Args:
            tool_chain: [(tool_name, options), ...] listesi
            target: İlk hedef
            stop_on_failure: Başarısızlıkta dur mu?
        """
        results: list[ToolResult] = []

        for tool_name, options in tool_chain:
            result = await self.run_tool(tool_name, target, options)
            results.append(result)

            if not result.success and stop_on_failure:
                logger.warning(f"Chain stopped | tool={tool_name} | reason=failure")
                break

        return results

    # ── Private Helpers ───────────────────────────────────────

    @staticmethod
    def _is_retryable(result: ToolResult) -> bool:
        """
        Determine if a failed ToolResult represents a transient failure
        that should be retried.

        Returns True for: timeouts, network errors, resource limits
        Returns False for: scope blocks, missing tools, risk rejections
        """
        if result.success:
            return False

        error = (result.error_message or "").lower()

        # Never retry these
        for pattern in _NON_RETRYABLE_PATTERNS:
            if pattern in error:
                return False

        # Retryable if matches known transient patterns
        for pattern in _RETRYABLE_PATTERNS:
            if pattern in error:
                return True

        # Also retry on non-zero exit code (tool crash / transient OS error)
        # but only if the error message doesn't indicate a permanent failure
        if "exit" in error and any(c.isdigit() for c in error):
            return True

        return False

    async def _check_risk_approval(self, tool: SecurityTool, target: str) -> bool:
        """Risk seviyesine göre onay kontrolü."""
        if self.mode == OperationMode.AUTONOMOUS:
            # Otonom modda her şey otomatik onaylanır
            return True

        # Yarı-otonom modda: yüksek riskli araçlar insan onayı gerektirir
        if tool.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            if self.human_approval_callback:
                return await self.human_approval_callback(
                    f"High risk tool '{tool.name}' (risk={tool.risk_level}) "
                    f"wants to run on target '{target}'. Approve?"
                )
            else:
                logger.warning(
                    f"No human approval callback configured for high-risk tool: {tool.name}"
                )
                return False

        return True

    @staticmethod
    def _extract_host(target: str) -> str:
        """URL/target'tan hostname çıkar."""
        from urllib.parse import urlparse

        parsed = urlparse(target)
        if parsed.hostname:
            return parsed.hostname
        return target.split("/")[0].split(":")[0]

    def _inject_auth(self, options: dict[str, Any]) -> dict[str, Any]:
        """Merge authenticated session headers/cookies into tool options."""
        if not self.auth_session or not self.auth_session.is_authenticated:
            return options
        options = dict(options)  # shallow copy — avoid mutating caller's dict

        auth_headers = self.auth_session.get_auth_headers()
        auth_cookies = self.auth_session.get_auth_cookies()

        if auth_headers:
            existing = options.get("headers") or {}
            # Auth headers have lower priority — tool-level overrides win
            merged = {**auth_headers, **existing}
            options["headers"] = merged

        if auth_cookies:
            existing = options.get("cookies") or {}
            merged = {**auth_cookies, **existing}
            options["cookies"] = merged

        # Provide pre-built CLI flags for tools that shell-out
        if auth_headers or auth_cookies:
            options.setdefault(
                "_auth_cli_flags",
                self.auth_session.get_cli_header_flags(),
            )

        return options

    def get_stats(self) -> dict[str, Any]:
        """Executor istatistikleri."""
        return {
            "total_executions": len(self._execution_history),
            "blocked_count": self._blocked_count,
            "successful": sum(1 for e in self._execution_history if e["success"]),
            "failed": sum(1 for e in self._execution_history if not e["success"]),
            "total_findings": sum(e["findings_count"] for e in self._execution_history),
            "rate_limiter_stats": self.rate_limiter.get_stats(),
            "auth_active": bool(
                self.auth_session and self.auth_session.is_authenticated
            ),
        }


__all__ = ["ToolExecutor"]
