"""
WhiteHatHacker AI — Dual Brain Engine (v2.2 — BaronLLM v2)

Tek bir BaronLLM v2 (Qwen3-14B fine-tune) modeli, /think ve /no_think
soft-switch ile dual-brain mimarisi olarak çalıştırılır.
Desteklenen backend'ler:
  - LOCAL:  llama-cpp-python (GGUF dosyaları)
  - REMOTE: OpenAI-uyumlu API (LM Studio, ollama, vLLM, vb.)

Primary:   BaronLLM v2 /think modu  (derin analiz, CoT reasoning)
Secondary: BaronLLM v2 /no_think modu (hızlı triage, direkt yanıt)

v2.2 Değişiklikler:
  - Tek model, dual-brain: /think ve /no_think soft-switch
  - BaronLLM v2 (Qwen3-14B base, offensive security fine-tune)
  - Unified model — same GGUF for both primary & secondary
v2.1 Eklemeler:
  - Otomatik retry (exponential backoff) — ConnectError, ReadTimeout
  - SSH tunnel sağlık kontrolü & otomatik yeniden bağlantı
  - Connection pool keepalive & limitleri
  - Detaylı inference zamanlama logları
"""

from __future__ import annotations

import asyncio
import copy
import json
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, AsyncGenerator

import httpx
from loguru import logger
from pydantic import BaseModel, Field

from src.utils.constants import BrainType


# ============================================================
# Retry / Resilience Sabitleri
# ============================================================

MAX_RETRIES = 3                 # Bir LLM çağrısı için maks tekrar
RETRY_BASE_DELAY = 2.0          # İlk geri-çekilme süresi (saniye)
RETRY_BACKOFF_FACTOR = 2.0      # Exponential çarpan (2, 4, 8 …)
SSH_TUNNEL_SCRIPT = "scripts/ssh_tunnel.sh"
SSH_HEALTH_COOLDOWN = 30.0      # SSH check'ler arası min süre (saniye)
POOL_MAX_CONNECTIONS = 10       # httpx connection pool max bağlantı
POOL_MAX_KEEPALIVE = 5          # Max keepalive bağlantı
POOL_KEEPALIVE_EXPIRY = 120.0   # Keepalive expiry (saniye)

# ── Circuit Breaker Sabitleri ──
CB_FAILURE_THRESHOLD = 8        # Bu kadar ardışık hatadan sonra devre açılır
CB_RECOVERY_TIMEOUT = 120.0     # Açık devre bu süre sonra half-open olur (saniye)
CB_HALF_OPEN_MAX = 2            # Half-open durumda izin verilen deneme sayısı

# ── Pre-compiled Regex ──
import re as _re_module
_THINK_BLOCK_RE = _re_module.compile(r"<think>(.*?)</think>", _re_module.DOTALL)


# ============================================================
# Circuit Breaker
# ============================================================

class _CircuitState(StrEnum):
    CLOSED = "closed"       # Normal — istekler geçer
    OPEN = "open"           # Devre açık — istekler engellenir
    HALF_OPEN = "half_open" # Deneme — tek isteğe izin ver


@dataclass
class CircuitBreaker:
    """Per-brain circuit breaker.

    CLOSED  → ardışık hatalar threshold'u aşarsa → OPEN
    OPEN    → recovery_timeout sonra → HALF_OPEN
    HALF_OPEN → başarılı → CLOSED; başarısız → OPEN

    Thread-safe: all mutations guarded by asyncio.Lock.
    """

    label: str = ""
    failure_threshold: int = CB_FAILURE_THRESHOLD
    recovery_timeout: float = CB_RECOVERY_TIMEOUT

    _state: _CircuitState = field(default=_CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _half_open_attempts: int = field(default=0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _sync_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @property
    def state(self) -> _CircuitState:
        """Mevcut durumu döndür — OPEN→HALF_OPEN geçişi zamana bağlı."""
        _transitioned = False
        with self._sync_lock:
            if self._state == _CircuitState.OPEN:
                if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                    self._state = _CircuitState.HALF_OPEN
                    self._half_open_attempts = 0
                    _transitioned = True
            s = self._state
        if _transitioned:
            logger.info(f"Circuit [{self.label}]: OPEN → HALF_OPEN (recovery timeout elapsed)")
        return s

    @property
    def is_available(self) -> bool:
        """Bu brain'e istek gönderilebilir mi?"""
        _transitioned = False
        with self._sync_lock:
            if self._state == _CircuitState.OPEN:
                if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                    self._state = _CircuitState.HALF_OPEN
                    self._half_open_attempts = 0
                    _transitioned = True
            s = self._state
        if _transitioned:
            logger.info(f"Circuit [{self.label}]: OPEN → HALF_OPEN (recovery timeout elapsed)")
        if s == _CircuitState.CLOSED:
            return True
        if s == _CircuitState.HALF_OPEN:
            return self._half_open_attempts < CB_HALF_OPEN_MAX
        return False  # OPEN

    async def async_record_success(self) -> None:
        """Başarılı çağrı — devre CLOSED'a döner (async-safe)."""
        async with self._lock:
            if self._state != _CircuitState.CLOSED:
                logger.info(f"Circuit [{self.label}]: {self._state} → CLOSED (success)")
            self._state = _CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_attempts = 0

    def record_success(self) -> None:
        """Başarılı çağrı — devre CLOSED'a döner (sync compat, thread-safe)."""
        with self._sync_lock:
            if self._state != _CircuitState.CLOSED:
                logger.info(f"Circuit [{self.label}]: {self._state} → CLOSED (success)")
            self._state = _CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_attempts = 0

    async def async_record_failure(self) -> None:
        """Başarısız çağrı — threshold aşılırsa devre açılır (async-safe)."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == _CircuitState.HALF_OPEN:
                self._state = _CircuitState.OPEN
                logger.warning(f"Circuit [{self.label}]: HALF_OPEN → OPEN (half-open probe failed)")
            elif self._failure_count >= self.failure_threshold:
                if self._state != _CircuitState.OPEN:
                    logger.warning(
                        f"Circuit [{self.label}]: CLOSED → OPEN "
                        f"(consecutive failures: {self._failure_count})"
                    )
                self._state = _CircuitState.OPEN

    def record_failure(self) -> None:
        """Başarısız çağrı — threshold aşılırsa devre açılır (thread-safe)."""
        with self._sync_lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == _CircuitState.HALF_OPEN:
                self._state = _CircuitState.OPEN
                logger.warning(f"Circuit [{self.label}]: HALF_OPEN → OPEN (half-open probe failed)")
            elif self._failure_count >= self.failure_threshold:
                if self._state != _CircuitState.OPEN:
                    logger.warning(
                        f"Circuit [{self.label}]: CLOSED → OPEN "
                        f"(consecutive failures: {self._failure_count})"
                    )
                self._state = _CircuitState.OPEN

    def record_half_open_attempt(self) -> None:
        """Half-open deneme sayacı."""
        with self._sync_lock:
            self._half_open_attempts += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": str(self.state),
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
        }


# ============================================================
# Veri Modelleri
# ============================================================

class InferenceBackend(StrEnum):
    """Model çalıştırma backend'i."""
    LOCAL = "local"     # llama-cpp-python (local GGUF)
    REMOTE = "remote"   # OpenAI-uyumlu API (LM Studio, ollama, vLLM)


class ModelConfig(BaseModel):
    """Tek bir model konfigürasyonu."""

    name: str

    # Backend seçimi
    backend: InferenceBackend = InferenceBackend.REMOTE

    # ── LOCAL backend (llama-cpp-python) ──
    model_path: str = ""
    gpu_layers: int = -1
    threads: int = 8
    batch_size: int = 512

    # ── REMOTE backend (OpenAI-uyumlu API) ──
    api_url: str = ""          # örn: "http://YOUR_LM_STUDIO_IP:1239"
    api_key: str = ""          # opsiyonel API key
    model_name: str = ""       # LM Studio model identifier (opsiyonel)

    # ── Ortak parametreler ──
    context_length: int = 32768
    temperature: float = 0.1
    top_p: float = 0.9
    top_k: int = 40
    repeat_penalty: float = 1.1
    max_tokens: int = 16384
    timeout: float = 420.0     # HTTP istek timeout (saniye) — brain inference can take 5-7min for complex tasks

    # ── Qwen3 Thinking Mode ──
    thinking_mode: bool | None = None  # True=/think, False=/no_think, None=no prefix


class BrainResponse(BaseModel):
    """Brain inference yanıtı."""

    text: str                           # Yanıt metni
    model_used: BrainType               # Kullanılan model
    tokens_used: int = 0                # Kullanılan token sayısı
    inference_time: float = 0.0         # Inference süresi (saniye)
    finish_reason: str = "stop"         # Bitiş nedeni
    metadata: dict[str, Any] = Field(default_factory=dict)  # Ek metadata

    @property
    def content(self) -> str:
        """text alias — uyumluluk için."""
        return self.text


class ChatMessage(BaseModel):
    """Tek bir sohbet mesajı."""

    role: str       # system | user | assistant
    content: str


# ============================================================
# Brain Engine
# ============================================================

class BrainEngine:
    """
    Dual Brain Engine — Tek BaronLLM v2 modeli, /think ve /no_think ile dual-brain.

    Backend'ler:
      - REMOTE (varsayılan): LM Studio / ollama / vLLM gibi OpenAI-uyumlu API'ye bağlanır
      - LOCAL: llama-cpp-python ile local GGUF dosyası yükler

    Primary (/think):    Derin analiz, CoT reasoning, exploit stratejisi, FP eleme
    Secondary (/no_think): Hızlı triage, recon kararları, araç seçimi

    Kullanım (Remote — LM Studio):
        primary_cfg = ModelConfig(
            name="BaronLLM-v2-Think",
            backend="remote",
            api_url="http://YOUR_LM_STUDIO_IP:1239",
        )
        secondary_cfg = ModelConfig(
            name="BaronLLM-v2-Fast",
            backend="remote",
            api_url="http://YOUR_LM_STUDIO_IP:1239",
        )
        engine = BrainEngine(primary_cfg, secondary_cfg)
        await engine.initialize()
        response = await engine.think("Analiz et: ...", brain=BrainType.PRIMARY)
    """

    def __init__(
        self,
        primary_config: ModelConfig | None = None,
        secondary_config: ModelConfig | None = None,
        fallback_config: ModelConfig | None = None,
    ) -> None:
        self.primary_config = primary_config
        self.secondary_config = secondary_config
        self.fallback_config = fallback_config  # P3-5: lightweight local fallback

        # Local backend model instances
        self._primary_model: Any = None     # Llama instance (local only)
        self._secondary_model: Any = None   # Llama instance (local only)
        self._fallback_model: Any = None    # P3-5: lightweight local fallback model

        # Remote backend HTTP clients
        self._primary_client: httpx.AsyncClient | None = None
        self._secondary_client: httpx.AsyncClient | None = None
        self._fallback_client: httpx.AsyncClient | None = None  # P3-5: fallback (if remote)

        self._active_brain: BrainType = BrainType.SECONDARY

        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._inference_count = 0
        self._total_inference_time = 0.0
        self._failed_inferences = 0
        self._retry_count = 0
        self._fallback_count = 0
        self._last_ssh_check: float = 0.0   # son SSH tunnel check zamanı

        # Per-brain circuit breakers
        self._cb_primary = CircuitBreaker(label="PRIMARY")
        self._cb_secondary = CircuitBreaker(label="SECONDARY")

        # Inference concurrency limiter — prevents overwhelming a single LM Studio
        # instance when primary/secondary share the same server
        self._inference_semaphore = asyncio.Semaphore(3)
        self._chars_per_token_estimate = 3
        self._message_token_overhead = 8
        self._min_completion_tokens = 128

        logger.info("BrainEngine created | dual-model architecture | retry+circuit-breaker enabled"
                     + (" | fallback model configured" if fallback_config else ""))

    def _estimate_tokens(self, text: str) -> int:
        """Cheap token estimate used for budget guards before inference."""
        if not text:
            return 0
        return max(1, len(text) // self._chars_per_token_estimate)

    def _estimate_message_tokens(self, messages: list[dict[str, str]]) -> int:
        """Estimate total prompt tokens including message framing overhead."""
        total = self._message_token_overhead
        for message in messages:
            total += self._message_token_overhead
            total += self._estimate_tokens(message.get("content", ""))
        return total

    def _fit_messages_to_context(
        self,
        messages: list[dict[str, str]],
        config: ModelConfig,
        requested_max_tokens: int,
    ) -> tuple[list[dict[str, str]], int, int]:
        """Trim the user prompt if needed so prompt + completion fits model context."""
        fitted = copy.deepcopy(messages)
        budget = max(128, int(config.context_length))
        completion_tokens = max(1, min(requested_max_tokens, config.max_tokens))
        prompt_tokens = self._estimate_message_tokens(fitted)

        if prompt_tokens + completion_tokens <= budget:
            return fitted, completion_tokens, prompt_tokens

        available_for_completion = max(self._min_completion_tokens, budget - prompt_tokens)
        completion_tokens = max(1, min(completion_tokens, available_for_completion))
        if prompt_tokens + completion_tokens <= budget:
            logger.warning(
                f"Brain prompt near context limit | prompt_tokens={prompt_tokens} | "
                f"completion_tokens={completion_tokens} | context={budget}"
            )
            return fitted, completion_tokens, prompt_tokens

        for idx in range(len(fitted) - 1, -1, -1):
            if fitted[idx].get("role") != "user":
                continue
            content = fitted[idx].get("content", "")
            prefix = "[TRIMMED TO FIT CONTEXT]\n"
            probe_messages = copy.deepcopy(fitted)
            probe_messages[idx]["content"] = ""
            other_prompt_tokens = self._estimate_message_tokens(probe_messages)
            allowed_user_tokens = max(16, budget - completion_tokens - other_prompt_tokens)
            keep_len = max(64, allowed_user_tokens * self._chars_per_token_estimate)
            fitted[idx]["content"] = prefix + content[-keep_len:]
            break

        prompt_tokens = self._estimate_message_tokens(fitted)
        available_for_completion = max(1, budget - prompt_tokens)
        completion_tokens = max(1, min(completion_tokens, available_for_completion))

        logger.warning(
            f"Brain prompt trimmed to fit context | prompt_tokens={prompt_tokens} | "
            f"completion_tokens={completion_tokens} | context={budget}"
        )
        return fitted, completion_tokens, prompt_tokens

    # ── Lifecycle ─────────────────────────────────────────────

    async def initialize(self) -> None:
        """Modelleri yükle / uzak sunuculara bağlantıyı doğrula."""
        async with self._init_lock:
            if self._initialized:
                logger.warning("BrainEngine already initialized")
                return

            # Primary model
            if self.primary_config:
                await self._init_model("PRIMARY", self.primary_config, is_primary=True)

            # Secondary model
            if self.secondary_config:
                await self._init_model("SECONDARY", self.secondary_config, is_primary=False)

            # P3-5: Fallback model (lightweight local for emergency triage)
            if self.fallback_config:
                await self._init_fallback("FALLBACK", self.fallback_config)

            self._initialized = True
            available = []
            if self.has_primary:
                backend = self.primary_config.backend if self.primary_config else "?"
                mode = "think" if (self.primary_config and self.primary_config.thinking_mode) else "no_think"
                available.append(f"primary(BaronLLM-v2/{backend}/{mode})")
            if self.has_secondary:
                backend = self.secondary_config.backend if self.secondary_config else "?"
                mode = "think" if (self.secondary_config and self.secondary_config.thinking_mode) else "no_think"
                available.append(f"secondary(BaronLLM-v2/{backend}/{mode})")

            if self.has_fallback:
                available.append(f"fallback({self.fallback_config.name}/{self.fallback_config.backend})")

            if not available:
                logger.warning(
                    "BrainEngine initialized with NO models loaded! "
                    "The bot will operate without AI brain capabilities."
                )

            logger.info(f"BrainEngine initialized | available: {', '.join(available) or 'NONE'}")

    async def _init_model(self, label: str, config: ModelConfig, is_primary: bool) -> None:
        """Tek bir modeli backend'e göre başlat."""

        if config.backend == InferenceBackend.REMOTE:
            # ── REMOTE: OpenAI-uyumlu API sunucusuna bağlan ──
            if not config.api_url:
                logger.warning(f"{label} model: api_url boş — atlanıyor")
                return

            base_url = config.api_url.rstrip("/")
            headers = {"Content-Type": "application/json"}
            if config.api_key:
                headers["Authorization"] = f"Bearer {config.api_key}"

            # Connection pool with keepalive — SSH tunnel uzun süreli bağlantılarda stabil kalır
            pool_limits = httpx.Limits(
                max_connections=POOL_MAX_CONNECTIONS,
                max_keepalive_connections=POOL_MAX_KEEPALIVE,
                keepalive_expiry=POOL_KEEPALIVE_EXPIRY,
            )

            client = httpx.AsyncClient(
                base_url=base_url,
                headers=headers,
                timeout=httpx.Timeout(config.timeout, connect=15.0, pool=30.0),
                limits=pool_limits,
            )

            # Bağlantı testi
            try:
                resp = await client.get("/v1/models")
                if resp.status_code == 200:
                    models_data = resp.json()
                    model_list = [m.get("id", "?") for m in models_data.get("data", [])]
                    logger.info(
                        f"{label} brain connected via API | "
                        f"url={base_url} | models={model_list}"
                    )
                elif resp.status_code == 401:
                    logger.warning(
                        f"{label} brain API returned 401 Unauthorized — "
                        f"API key mismatch. Check WHAI_PRIMARY_API_KEY in .env "
                        f"matches LM Studio server key. url={base_url}"
                    )
                else:
                    logger.warning(
                        f"{label} brain API responded with {resp.status_code} — "
                        f"models endpoint may not be available, proceeding anyway"
                    )
            except httpx.ConnectError:
                logger.warning(
                    f"{label} brain API unreachable at {base_url} — "
                    "bağlantı daha sonra kurulabilir, devam ediliyor"
                )
                # Client'ı yine de kur — bağlantı sonradan gelebilir
            except Exception as e:
                logger.warning(f"{label} brain API check failed: {e} — devam ediliyor")

            if is_primary:
                # Close previous client if it exists (prevent resource leak)
                if self._primary_client is not None:
                    try:
                        await self._primary_client.aclose()
                    except Exception as _close_err:
                        logger.warning(f"Failed to close primary client: {_close_err}")
                self._primary_client = client
            else:
                if self._secondary_client is not None:
                    try:
                        await self._secondary_client.aclose()
                    except Exception as _close_err:
                        logger.warning(f"Failed to close secondary client: {_close_err}")
                self._secondary_client = client

        elif config.backend == InferenceBackend.LOCAL:
            # ── LOCAL: llama-cpp-python ile GGUF yükle ──
            try:
                from llama_cpp import Llama
            except ImportError:
                logger.error(
                    f"{label}: llama-cpp-python gerekli (local backend). "
                    "Remote backend kullanmak için config'de backend: remote ayarlayın."
                )
                return

            model_path = Path(config.model_path)
            if not model_path.exists():
                logger.warning(f"{label} model file not found: {model_path}")
                return

            logger.info(f"Loading {label} brain (local): {config.name}")
            start = time.monotonic()
            model = await asyncio.to_thread(
                Llama,
                model_path=str(model_path),
                n_ctx=config.context_length,
                n_gpu_layers=config.gpu_layers,
                n_threads=config.threads,
                n_batch=config.batch_size,
                verbose=False,
            )
            elapsed = time.monotonic() - start
            logger.info(f"{label} brain loaded in {elapsed:.1f}s | {config.name}")

            if is_primary:
                self._primary_model = model
            else:
                self._secondary_model = model

    async def _init_fallback(self, label: str, config: ModelConfig) -> None:
        """P3-5: Initialize lightweight fallback model for emergency triage."""
        if config.backend == InferenceBackend.REMOTE:
            if not config.api_url:
                logger.warning(f"{label} model: api_url empty — skipping")
                return
            base_url = config.api_url.rstrip("/")
            headers = {"Content-Type": "application/json"}
            if config.api_key:
                headers["Authorization"] = f"Bearer {config.api_key}"
            client = httpx.AsyncClient(
                base_url=base_url,
                headers=headers,
                timeout=httpx.Timeout(config.timeout, connect=10.0, pool=15.0),
            )
            try:
                resp = await client.get("/v1/models")
                if resp.status_code == 200:
                    logger.info(f"{label} brain (remote) connected at {base_url}")
                else:
                    logger.warning(f"{label} brain API: status {resp.status_code}")
            except Exception as e:
                logger.warning(f"{label} brain API check failed: {e}")
            self._fallback_client = client

        elif config.backend == InferenceBackend.LOCAL:
            try:
                from llama_cpp import Llama
            except ImportError:
                logger.warning(f"{label}: llama-cpp-python required for local fallback")
                return
            model_path = Path(config.model_path)
            if not model_path.exists():
                logger.warning(f"{label} model not found: {model_path} — fallback unavailable")
                return
            logger.info(f"Loading {label} brain (local): {config.name}")
            start = time.monotonic()
            self._fallback_model = await asyncio.to_thread(
                Llama,
                model_path=str(model_path),
                n_ctx=config.context_length,
                n_gpu_layers=config.gpu_layers,
                n_threads=config.threads,
                n_batch=config.batch_size,
                verbose=False,
            )
            logger.info(f"{label} brain loaded in {time.monotonic() - start:.1f}s")

    async def shutdown(self) -> None:
        """Kaynakları serbest bırak."""
        logger.info("Shutting down BrainEngine...")
        self._primary_model = None
        self._secondary_model = None
        self._fallback_model = None

        if self._primary_client:
            await self._primary_client.aclose()
            self._primary_client = None
        if self._secondary_client:
            await self._secondary_client.aclose()
            self._secondary_client = None
        if self._fallback_client:
            await self._fallback_client.aclose()
            self._fallback_client = None

        self._initialized = False
        logger.info("BrainEngine shut down")

    # ── Core Inference ────────────────────────────────────────

    async def think(
        self,
        prompt: str,
        brain: BrainType = BrainType.SECONDARY,
        system_prompt: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> BrainResponse:
        """
        Beyin modeliyle düşün (inference).

        Local veya remote backend'i otomatik seçer.

        Args:
            prompt: Kullanıcı/görev prompt'u
            brain: Kullanılacak model (primary/secondary/both)
            system_prompt: Sistem prompt'u (opsiyonel)
            max_tokens: Maksimum token sayısı (None = config default)
            temperature: Sıcaklık (None = config default)
            json_mode: JSON çıktı modu

        Returns:
            BrainResponse
        """
        if not self._initialized:
            await self.initialize()

        if brain == BrainType.BOTH:
            return await self._ensemble_think(prompt, system_prompt, max_tokens, temperature, json_mode, **kwargs)

        # Model/client ve config'i al
        model, client, config = self._get_backend(brain)

        if model is None and client is None:
            # Fallback: diğer modeli dene
            fallback_brain = BrainType.PRIMARY if brain == BrainType.SECONDARY else BrainType.SECONDARY
            logger.warning(f"Brain {brain} not available, falling back to {fallback_brain}")
            model, client, config = self._get_backend(fallback_brain)
            brain = fallback_brain

        if model is None and client is None:
            raise RuntimeError("No brain model available for inference")

        # Circuit breaker kontrolü — devre açıksa doğrudan fallback dene
        cb = self._get_circuit_breaker(brain)
        original_brain = brain

        if not cb.is_available:
            fallback_brain = BrainType.PRIMARY if brain == BrainType.SECONDARY else BrainType.SECONDARY
            fb_model, fb_client, fb_config = self._get_backend(fallback_brain)
            fb_cb = self._get_circuit_breaker(fallback_brain)

            if (fb_model is not None or fb_client is not None) and fb_cb.is_available:
                logger.warning(
                    f"Circuit [{brain}] is {cb.state} — "
                    f"routing to {fallback_brain} directly"
                )
                model, client, config = fb_model, fb_client, fb_config
                brain = fallback_brain
                cb = fb_cb
                self._fallback_count += 1
            else:
                # Her iki devre de açık veya yok — circuit breaker half-open denemesi
                logger.warning(
                    f"Both circuits unavailable — attempting {original_brain} anyway"
                )

        if cb.state == _CircuitState.HALF_OPEN:
            cb.record_half_open_attempt()

        # Mesajları oluştur — thinking mode prefix eklenir
        messages = self._build_messages(prompt, system_prompt, thinking_mode=config.thinking_mode)

        # İnference parametreleri
        _max_tokens = max_tokens or config.max_tokens
        _temperature = temperature if temperature is not None else config.temperature
        messages, _max_tokens, estimated_prompt_tokens = self._fit_messages_to_context(
            messages, config, _max_tokens
        )

        start = time.monotonic()
        response: dict[str, Any] | None = None  # Defensive init — prevent UnboundLocalError

        try:
            if client is not None:
                # ── REMOTE inference (OpenAI-uyumlu API) ──
                response = await self._remote_inference(
                    client, config, messages, _max_tokens, _temperature, json_mode,
                )
            else:
                # ── LOCAL inference (llama-cpp-python) ──
                response = await self._local_inference(
                    model, config, messages, _max_tokens, _temperature, json_mode,
                )

            # Başarılı — circuit breaker'ı resetle
            await cb.async_record_success()

        except Exception as _retry_err:
            # Tüm retry'lar tükendi — circuit breaker'a kaydet
            logger.warning(f"Brain {brain} all retries exhausted: {_retry_err}")
            await cb.async_record_failure()

            # Cross-brain fallback: diğer brain'i dene (eğer mevcut ve devre kapalıysa)
            if brain == original_brain:
                fallback_brain = BrainType.PRIMARY if brain == BrainType.SECONDARY else BrainType.SECONDARY
                fb_model, fb_client, fb_config = self._get_backend(fallback_brain)
                fb_cb = self._get_circuit_breaker(fallback_brain)

                if (fb_model is not None or fb_client is not None) and fb_cb.is_available:
                    logger.warning(
                        f"Brain {brain} failed after retries — "
                        f"cross-fallback to {fallback_brain}"
                    )
                    self._fallback_count += 1

                    try:
                        fb_start = time.monotonic()
                        if fb_client is not None:
                            response = await self._remote_inference(
                                fb_client, fb_config, messages,
                                max_tokens or fb_config.max_tokens,
                                temperature if temperature is not None else fb_config.temperature,
                                json_mode,
                            )
                        else:
                            response = await self._local_inference(
                                fb_model, fb_config, messages,
                                max_tokens or fb_config.max_tokens,
                                temperature if temperature is not None else fb_config.temperature,
                                json_mode,
                            )

                        await fb_cb.async_record_success()
                        brain = fallback_brain
                        config = fb_config
                        start = fb_start  # zamanı fallback'e göre güncelle

                    except Exception as _exc:
                        await fb_cb.async_record_failure()
                        # P3-5: Both primary and secondary failed — try lightweight fallback
                        if self.has_fallback and self.fallback_config:
                            response = await self._try_fallback_inference(
                                messages, max_tokens, temperature, json_mode,
                            )
                            if response is not None:
                                brain = BrainType.SECONDARY  # approximate label
                                config = self.fallback_config
                                start = time.monotonic() - 0.01  # already elapsed
                            else:
                                raise  # Fallback also failed
                        else:
                            raise  # No fallback configured
                else:
                    # P3-5: Primary/secondary not available — try lightweight fallback
                    if self.has_fallback and self.fallback_config:
                        response = await self._try_fallback_inference(
                            messages, max_tokens, temperature, json_mode,
                        )
                        if response is not None:
                            brain = BrainType.SECONDARY
                            config = self.fallback_config
                            start = time.monotonic() - 0.01
                        else:
                            raise  # Fallback also failed
                    else:
                        raise  # No fallback available

        elapsed = time.monotonic() - start
        self._inference_count += 1
        self._total_inference_time += elapsed

        # Safety check — response must have been assigned
        if response is None:
            raise RuntimeError(
                f"Brain inference failed: response was not assigned "
                f"(brain={brain}, original={original_brain})"
            )

        # Yanıtı parse et
        if not response.get("choices"):
            raise RuntimeError(
                f"Brain response has no choices | model={brain}"
            )
        choice = response["choices"][0]
        raw_text = choice["message"]["content"] or ""

        # Qwen3 <think>...</think> bloklarını ayıkla
        text, thinking = self._strip_thinking_block(raw_text)
        if thinking:
            logger.debug(
                f"Brain thinking captured | model={brain} | "
                f"thinking_len={len(thinking)} chars"
            )

        usage = response.get("usage", {})
        tokens_used = usage.get("total_tokens", 0)

        logger.debug(
            f"Brain inference | model={brain} | "
            f"tokens={tokens_used} | prompt_est={estimated_prompt_tokens} | time={elapsed:.2f}s | "
            f"finish={choice.get('finish_reason', 'unknown')}"
        )

        return BrainResponse(
            text=text.strip(),
            model_used=brain,
            tokens_used=tokens_used,
            inference_time=elapsed,
            finish_reason=choice.get("finish_reason", "stop"),
            metadata={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "estimated_prompt_tokens": estimated_prompt_tokens,
                "backend": config.backend if config else "unknown",
                "thinking": thinking,  # CoT reasoning (debug için)
            },
        )

    async def _try_fallback_inference(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None,
        temperature: float | None,
        json_mode: bool,
    ) -> dict[str, Any] | None:
        """P3-5: Attempt inference on the lightweight fallback model.

        Called only when both primary and secondary brains have failed.
        The fallback is a smaller model (e.g. Qwen2.5-7B-Q4) for basic
        triage/tool selection — not for deep analysis.

        Returns the API response dict or None on failure.
        """
        fb_config = self.fallback_config
        if not fb_config:
            return None

        fb_model = self._fallback_model
        fb_client = self._fallback_client

        if fb_model is None and fb_client is None:
            return None

        # Fit messages to fallback's (smaller) context window
        _max = max_tokens or fb_config.max_tokens
        _temp = temperature if temperature is not None else fb_config.temperature
        fitted_msgs, _max, _ = self._fit_messages_to_context(messages, fb_config, _max)

        logger.warning(
            "Both primary & secondary brains failed — "
            "attempting P3-5 lightweight fallback brain"
        )

        try:
            if fb_client is not None:
                response = await self._remote_inference(
                    fb_client, fb_config, fitted_msgs, _max, _temp, json_mode,
                )
            else:
                response = await self._local_inference(
                    fb_model, fb_config, fitted_msgs, _max, _temp, json_mode,
                )
            self._fallback_count += 1
            logger.info("Fallback brain inference succeeded")
            return response
        except Exception as e:
            logger.error(f"Fallback brain also failed: {e}")
            return None

    async def _remote_inference(
        self,
        client: httpx.AsyncClient,
        config: ModelConfig,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
        json_mode: bool,
    ) -> dict[str, Any]:
        """OpenAI-uyumlu API üzerinden remote inference — retry destekli.

        Uses semaphore to limit concurrent requests to a shared LM Studio instance.
        """
        async with self._inference_semaphore:
            return await self._remote_inference_inner(
                client, config, messages, max_tokens, temperature, json_mode
            )

    async def _remote_inference_inner(
        self,
        client: httpx.AsyncClient,
        config: ModelConfig,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
        json_mode: bool,
    ) -> dict[str, Any]:
        """Inner remote inference with retry logic."""
        if json_mode:
            # Instruct the model to return only JSON.
            # LM Studio >=0.3.x does support response_format: json_object.
            # We add both the instruction AND response_format for belt-and-suspenders.
            messages = copy.deepcopy(messages)
            if messages and messages[-1]["role"] == "user":
                messages[-1]["content"] += (
                    "\n\n**CRITICAL: You MUST return ONLY valid JSON.**\n"
                    "- Your ENTIRE response must be a single JSON object parseable by `json.loads()`.\n"
                    "- Do NOT wrap the JSON in markdown code fences (no ```json ... ```).\n"
                    "- Do NOT include any explanation, preamble, or trailing text outside the JSON.\n"
                    "- Do NOT include comments inside the JSON.\n"
                    "- Start your response with `{` and end with `}`."
                )

        payload: dict[str, Any] = {
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": config.top_p,
            "stream": False,
        }

        # response_format — only if the backend actually supports it.
        # LM Studio >=0.3.6 requires "json_schema" or "text" only;
        # "json_object" causes HTTP 400.  We already inject the JSON
        # instruction into the user message above, so skipping
        # response_format for remote backends is safe.
        # If you upgrade to a server that supports json_object, uncomment:
        # if json_mode:
        #     payload["response_format"] = {"type": "json_object"}

        # Model adı (LM Studio bunu genellikle otomatik algılar)
        if config.model_name:
            payload["model"] = config.model_name

        # repeat_penalty → LM Studio'da frequency_penalty olarak
        if config.repeat_penalty and config.repeat_penalty != 1.0:
            payload["frequency_penalty"] = config.repeat_penalty - 1.0

        last_error: Exception | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                t0 = time.monotonic()
                resp = await client.post("/v1/chat/completions", json=payload)
                resp.raise_for_status()
                elapsed = time.monotonic() - t0

                if attempt > 1:
                    logger.info(
                        f"LLM inference succeeded on attempt {attempt} | "
                        f"time={elapsed:.1f}s"
                    )

                return resp.json()

            except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError) as e:
                last_error = e
                self._failed_inferences += 1
                delay = RETRY_BASE_DELAY * (RETRY_BACKOFF_FACTOR ** (attempt - 1))
                logger.warning(
                    f"LLM connection error (attempt {attempt}/{MAX_RETRIES}): {type(e).__name__}: {e} "
                    f"| retrying in {delay:.0f}s..."
                )

                # SSH tunnel sağlık kontrolü — bağlantı kopmuş olabilir
                await self._ensure_ssh_tunnel()

                # After tunnel reconnect, _refresh_remote_clients() may have
                # replaced self._primary_client / self._secondary_client.
                # Re-fetch the current client so the next retry uses the fresh one.
                refreshed = self._get_client_for_config(config)
                if refreshed is not None:
                    client = refreshed

                if attempt < MAX_RETRIES:
                    await asyncio.sleep(delay)

            except httpx.ReadTimeout as e:
                last_error = e
                self._failed_inferences += 1
                delay = RETRY_BASE_DELAY * (RETRY_BACKOFF_FACTOR ** (attempt - 1))
                logger.warning(
                    f"LLM read timeout (attempt {attempt}/{MAX_RETRIES}): "
                    f"model may be processing large prompt, timeout={config.timeout}s "
                    f"| retrying in {delay:.0f}s..."
                )
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(delay)

            except httpx.HTTPStatusError as e:
                # HTTP hataları genellikle retry ile düzelmez (4xx vb.)
                if e.response.status_code >= 500:
                    last_error = e
                    delay = RETRY_BASE_DELAY * (RETRY_BACKOFF_FACTOR ** (attempt - 1))
                    logger.warning(
                        f"LLM server error {e.response.status_code} "
                        f"(attempt {attempt}/{MAX_RETRIES}) | retrying in {delay:.0f}s..."
                    )
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(delay)
                elif e.response.status_code == 400 and "response_format" in e.response.text:
                    # API doesn't support response_format — strip it from payload and retry
                    payload.pop("response_format", None)
                    logger.warning(
                        f"LLM API rejected response_format (400) — "
                        f"retrying without it (attempt {attempt}/{MAX_RETRIES})"
                    )
                    if attempt < MAX_RETRIES:
                        continue  # Retry immediately without delay
                    else:
                        raise RuntimeError(
                            f"LLM API hatası: {e.response.status_code} — {e.response.text[:500]}"
                        ) from e
                else:
                    raise RuntimeError(
                        f"LLM API hatası: {e.response.status_code} — {e.response.text[:500]}"
                    ) from e

        # Tüm denemeler başarısız
        self._retry_count += MAX_RETRIES
        if isinstance(last_error, (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
            raise RuntimeError(
                f"LLM sunucusuna bağlanılamıyor ({config.api_url}). "
                f"{MAX_RETRIES} deneme yapıldı. SSH tunnel ve LM Studio kontrol edin. "
                f"Son hata: {last_error}"
            ) from last_error
        elif isinstance(last_error, httpx.ReadTimeout):
            raise RuntimeError(
                f"LLM yanıt zaman aşımı ({config.timeout}s). "
                f"{MAX_RETRIES} deneme yapıldı. Model çok yavaş olabilir. "
                f"Son hata: {last_error}"
            ) from last_error
        else:
            raise RuntimeError(
                f"LLM inference başarısız ({MAX_RETRIES} deneme). Son hata: {last_error}"
            ) from last_error

    async def _ensure_ssh_tunnel(self) -> None:
        """SSH tunnel'ı kontrol et ve gerekirse yeniden başlat.

        Cooldown ile çağrılır — aynı sorun için art arda check yapılmaz.
        After a reconnect, httpx clients are re-created to flush stale sockets.
        """
        now = time.monotonic()
        if now - self._last_ssh_check < SSH_HEALTH_COOLDOWN:
            return
        self._last_ssh_check = now

        tunnel_script = Path(SSH_TUNNEL_SCRIPT)
        if not tunnel_script.exists():
            logger.debug("SSH tunnel script bulunamadı — atlıyor")
            return

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["bash", str(tunnel_script), "check"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if "reconnecting" in result.stdout.lower() or "DOWN" in result.stdout:
                logger.warning(f"SSH tunnel was down — reconnect attempted: {result.stdout.strip()}")
                # Tunnel'ın stabilize olması için kısa bekleme
                await asyncio.sleep(3)
                # Re-create httpx clients to flush stale TCP connections
                await self._refresh_remote_clients()
            else:
                logger.debug("SSH tunnel health: OK")
        except subprocess.TimeoutExpired:
            logger.warning("SSH tunnel check timed out (30s)")
        except Exception as e:
            logger.warning(f"SSH tunnel check failed: {e}")

    async def _refresh_remote_clients(self) -> None:
        """Re-create httpx clients after SSH tunnel reconnect to clear stale sockets."""
        if self.primary_config and self.primary_config.backend == InferenceBackend.REMOTE:
            logger.info("Refreshing PRIMARY httpx client after tunnel reconnect...")
            await self._init_model("PRIMARY", self.primary_config, is_primary=True)
        if self.secondary_config and self.secondary_config.backend == InferenceBackend.REMOTE:
            logger.info("Refreshing SECONDARY httpx client after tunnel reconnect...")
            await self._init_model("SECONDARY", self.secondary_config, is_primary=False)

    async def _local_inference(
        self,
        model: Any,
        config: ModelConfig,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
        json_mode: bool,
    ) -> dict[str, Any]:
        """llama-cpp-python ile local inference."""
        return await asyncio.to_thread(
            model.create_chat_completion,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=config.top_p,
            top_k=config.top_k,
            repeat_penalty=config.repeat_penalty,
            response_format={"type": "json_object"} if json_mode else None,
        )

    async def think_stream(
        self,
        prompt: str,
        brain: BrainType = BrainType.SECONDARY,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[str, None]:
        """Streaming inference — token token yanıt döndür.

        Circuit breaker ve cross-brain fallback destekli.
        """
        if not self._initialized:
            await self.initialize()

        # Brain seçimi ve circuit breaker kontrolü
        brains_to_try: list[BrainType] = [brain]
        fallback = BrainType.PRIMARY if brain == BrainType.SECONDARY else BrainType.SECONDARY
        brains_to_try.append(fallback)

        last_error: Exception | None = None

        for attempt_brain in brains_to_try:
            model, client, config = self._get_backend(attempt_brain)
            if model is None and client is None:
                continue

            cb = self._get_circuit_breaker(attempt_brain)
            if not cb.is_available:
                logger.debug(f"Circuit [{attempt_brain}] not available for streaming, trying next")
                continue

            if cb.state == _CircuitState.HALF_OPEN:
                cb.record_half_open_attempt()

            messages = self._build_messages(prompt, system_prompt, thinking_mode=config.thinking_mode)
            messages, stream_max_tokens, estimated_prompt_tokens = self._fit_messages_to_context(
                messages, config, int(kwargs.get("max_tokens") or config.max_tokens)
            )
            streamed_tokens = 0

            try:
                if client is not None:
                    # ── REMOTE streaming ──
                    payload: dict[str, Any] = {
                        "messages": messages,
                        "max_tokens": stream_max_tokens,
                        "temperature": config.temperature,
                        "stream": True,
                    }
                    if config.model_name:
                        payload["model"] = config.model_name

                    async with client.stream("POST", "/v1/chat/completions", json=payload) as resp:
                        async for line in resp.aiter_lines():
                            if not line.startswith("data: "):
                                continue
                            data = line[6:]
                            if data.strip() == "[DONE]":
                                break
                            try:
                                chunk = json.loads(data)
                                if not chunk.get("choices"):
                                    continue
                                delta = chunk["choices"][0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    streamed_tokens += self._estimate_tokens(content)
                                    if streamed_tokens > stream_max_tokens:
                                        logger.warning(
                                            f"Streaming completion budget hit | model={attempt_brain} | "
                                            f"completion_est={streamed_tokens} | max_tokens={stream_max_tokens} | "
                                            f"prompt_est={estimated_prompt_tokens}"
                                        )
                                        break
                                    yield content
                            except Exception as _exc:
                                logger.warning(f"engine error: {_exc}")
                                continue

                    await cb.async_record_success()
                    return  # Başarılı stream — çık

                else:
                    # ── LOCAL streaming (llama-cpp-python) ──
                    result_queue: queue.Queue[str | None] = queue.Queue()

                    def _stream_worker() -> None:
                        try:
                            stream_gen = model.create_chat_completion(
                                messages=messages,
                                max_tokens=stream_max_tokens,
                                temperature=config.temperature,
                                stream=True,
                            )
                            for chunk in stream_gen:
                                if not chunk.get("choices"):
                                    continue
                                delta = chunk["choices"][0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    result_queue.put(content)
                        except Exception as _stream_err:
                            logger.error(f"Local streaming worker failed: {type(_stream_err).__name__}: {_stream_err}")
                        finally:
                            result_queue.put(None)

                    loop = asyncio.get_running_loop()
                    task = loop.run_in_executor(None, _stream_worker)

                    while True:
                        try:
                            token = await asyncio.to_thread(result_queue.get, timeout=60)
                        except queue.Empty:
                            logger.warning("Local stream: queue read timed out (60s)")
                            break
                        except Exception as _q_err:
                            logger.error(f"Local stream consumer error: {_q_err}")
                            break
                        if token is None:
                            break
                        streamed_tokens += self._estimate_tokens(token)
                        if streamed_tokens > stream_max_tokens:
                            logger.warning(
                                f"Local streaming completion budget hit | model={attempt_brain} | "
                                f"completion_est={streamed_tokens} | max_tokens={stream_max_tokens} | "
                                f"prompt_est={estimated_prompt_tokens}"
                            )
                            break
                        yield token

                    await task
                    await cb.async_record_success()
                    return  # Başarılı stream — çık

            except (httpx.ConnectError, httpx.ReadError, httpx.ReadTimeout,
                    httpx.RemoteProtocolError) as e:
                last_error = e
                await cb.async_record_failure()
                logger.warning(
                    f"Streaming failed on {attempt_brain}: {type(e).__name__}: {e} "
                    f"— trying next brain"
                )
                if attempt_brain != brains_to_try[-1]:
                    self._fallback_count += 1
                continue
            except Exception as e:
                last_error = e
                await cb.async_record_failure()
                logger.warning(f"Streaming error on {attempt_brain}: {e}")
                continue

        # Hiçbir brain çalışmadı
        raise RuntimeError(
            f"Streaming inference failed on all brains. Last error: {last_error}"
        )

    async def _ensemble_think(
        self,
        prompt: str,
        system_prompt: str | None,
        max_tokens: int | None,
        temperature: float | None,
        json_mode: bool,
        **kwargs: Any,
    ) -> BrainResponse:
        """
        Her iki modelle de düşün ve sonuçları karşılaştır (ensemble).
        Kritik kararlar için kullanılır.
        """
        tasks = []

        if self.has_primary:
            tasks.append(self.think(
                prompt, BrainType.PRIMARY, system_prompt, max_tokens, temperature, json_mode, **kwargs
            ))

        if self.has_secondary:
            tasks.append(self.think(
                prompt, BrainType.SECONDARY, system_prompt, max_tokens, temperature, json_mode, **kwargs
            ))

        if not tasks:
            raise RuntimeError("No brain models available for ensemble")

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Başarılı sonuçları filtrele
        valid_results = [r for r in results if isinstance(r, BrainResponse)]

        if not valid_results:
            raise RuntimeError("All ensemble models failed")

        if len(valid_results) == 1:
            return valid_results[0]

        # En detaylı (uzun) yanıtı seç — primary'nin yanıtı genellikle daha detaylıdır
        primary_result = next((r for r in valid_results if r.model_used == BrainType.PRIMARY), None)

        return BrainResponse(
            text=primary_result.text if primary_result else valid_results[0].text,
            model_used=BrainType.BOTH,
            tokens_used=sum(r.tokens_used for r in valid_results),
            inference_time=max(r.inference_time for r in valid_results),
            finish_reason="ensemble",
            metadata={
                "ensemble_count": len(valid_results),
                "models_used": [r.model_used for r in valid_results],
            },
        )

    # ── Helpers ───────────────────────────────────────────────

    def _get_backend(
        self, brain: BrainType
    ) -> tuple[Any | None, httpx.AsyncClient | None, ModelConfig | None]:
        """Model/client ve config'i döndür (local veya remote)."""
        if brain == BrainType.PRIMARY:
            return self._primary_model, self._primary_client, self.primary_config
        elif brain == BrainType.SECONDARY:
            return self._secondary_model, self._secondary_client, self.secondary_config
        return None, None, None

    def _get_client_for_config(self, config: ModelConfig | None) -> httpx.AsyncClient | None:
        """Return the current httpx client that matches the given config.

        Used after tunnel reconnect to pick up the refreshed client instance.
        """
        if config is None:
            return None
        if config is self.primary_config:
            return self._primary_client
        if config is self.secondary_config:
            return self._secondary_client
        return None

    def _get_circuit_breaker(self, brain: BrainType) -> CircuitBreaker:
        """Brain tipine göre circuit breaker döndür."""
        if brain == BrainType.PRIMARY:
            return self._cb_primary
        return self._cb_secondary

    # Eski API uyumluluğu (internal kullanım — _ensemble_think vb.)
    def _get_model(self, brain: BrainType) -> tuple[Any | None, ModelConfig | None]:
        """Geriye uyumluluk: model veya client döndür."""
        model, client, config = self._get_backend(brain)
        # Remote client varsa onu "model" olarak döndür (null değil, çünkü ensemble kontrolü yapar)
        effective = model or client
        return effective, config

    @staticmethod
    def _strip_thinking_block(text: str) -> tuple[str, str]:
        """Qwen3 <think>...</think> bloğunu yanıttan ayıkla.

        Returns:
            (clean_text, thinking_content)
            - clean_text: <think> bloğu çıkarılmış temiz yanıt
            - thinking_content: <think> içeriği (debug/log için), boş string eğer yoksa
        """
        match = _THINK_BLOCK_RE.search(text)

        if not match:
            return text, ""

        thinking = match.group(1).strip()
        clean = _THINK_BLOCK_RE.sub("", text, count=1).strip()
        return clean, thinking

    @staticmethod
    def _build_messages(
        prompt: str,
        system_prompt: str | None = None,
        thinking_mode: bool | None = None,
    ) -> list[dict[str, str]]:
        """Chat mesajlarını oluştur.

        Qwen3 /think ve /no_think soft-switch desteği:
          - thinking_mode=True  → kullanıcı mesajına '/think' prefix eklenir
          - thinking_mode=False → kullanıcı mesajına '/no_think' prefix eklenir
          - thinking_mode=None  → prefix eklenmez (geriye uyumluluk)

        /think: Model extended thinking (chain-of-thought) kullanır.
                Derin analiz, exploit stratejisi, FP eleme gibi karmaşık görevler.
        /no_think: Model doğrudan yanıt verir, thinking atlanır.
                   Hızlı triage, araç seçimi, scope analizi gibi basit görevler.
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        # Qwen3 thinking mode prefix injection
        if thinking_mode is True:
            prompt = f"/think\n{prompt}"
        elif thinking_mode is False:
            prompt = f"/no_think\n{prompt}"

        messages.append({"role": "user", "content": prompt})
        return messages

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def has_primary(self) -> bool:
        return self._primary_model is not None or self._primary_client is not None

    @property
    def has_secondary(self) -> bool:
        return self._secondary_model is not None or self._secondary_client is not None

    @property
    def has_fallback(self) -> bool:
        """P3-5: Is a lightweight fallback model available?"""
        return self._fallback_model is not None or self._fallback_client is not None

    async def verify_brain_ready(self) -> dict[str, Any]:
        """Pre-scan brain health check — SSH tunnel, API erişilebilirliği VE model yüklü mü?

        Checks in order (with retry + exponential backoff):
        1. If remote backend, ensure SSH tunnel is alive (auto-start if needed)
        2. Re-initialize clients if they were not created during init (tunnel was down)
        3. Verify API responds and models are loaded

        Returns:
            dict with keys:
                ready (bool): En az bir brain kullanılabilir mi
                primary_ok (bool): Primary brain hazır mı
                secondary_ok (bool): Secondary brain hazır mı
                models (list[str]): API'de yüklü model id'leri
                tunnel_status (str): SSH tunnel durumu
                error (str|None): Hata mesajı (varsa)
                attempts (int): Kaç deneme yapıldı
        """
        max_attempts = 3
        backoff_delays = [0, 10, 20]  # seconds before each retry

        for attempt in range(max_attempts):
            if attempt > 0:
                delay = backoff_delays[min(attempt, len(backoff_delays) - 1)]
                logger.info(f"Brain health check retry {attempt + 1}/{max_attempts} after {delay}s backoff...")
                await asyncio.sleep(delay)

            result = await self._verify_brain_ready_once()
            result["attempts"] = attempt + 1

            if result["ready"]:
                return result

            logger.warning(
                f"Brain health check attempt {attempt + 1}/{max_attempts} failed: "
                f"{result.get('error', 'unknown')}"
            )

        return result

    async def _verify_brain_ready_once(self) -> dict[str, Any]:
        """Single attempt at brain health verification."""
        result: dict[str, Any] = {
            "ready": False,
            "primary_ok": False,
            "secondary_ok": False,
            "models": [],
            "tunnel_status": "unknown",
            "error": None,
        }

        # ── Step 1: Ensure SSH tunnel is alive for remote backends ──
        has_remote = (
            (self.primary_config and self.primary_config.backend == InferenceBackend.REMOTE)
            or (self.secondary_config and self.secondary_config.backend == InferenceBackend.REMOTE)
        )
        if has_remote:
            tunnel_ok = await self._ensure_ssh_tunnel_for_health_check()
            result["tunnel_status"] = "ok" if tunnel_ok else "failed"
            if not tunnel_ok:
                logger.warning("SSH tunnel could not be established — brain may be unreachable")

        # ── Step 2: Re-initialize clients if tunnel was down during init ──
        if has_remote:
            if self.primary_config and self.primary_config.backend == InferenceBackend.REMOTE and self._primary_client is None:
                logger.info("Re-initializing PRIMARY client after tunnel check...")
                await self._init_model("PRIMARY", self.primary_config, is_primary=True)
            if self.secondary_config and self.secondary_config.backend == InferenceBackend.REMOTE and self._secondary_client is None:
                logger.info("Re-initializing SECONDARY client after tunnel check...")
                await self._init_model("SECONDARY", self.secondary_config, is_primary=False)

        # ── Step 3: Check API connectivity and models ──
        async def _check_remote(client: httpx.AsyncClient | None, label: str) -> bool:
            if client is None:
                return False
            try:
                resp = await client.get("/v1/models", timeout=10.0)
                if resp.status_code == 401:
                    logger.warning(
                        f"Brain health: {label} API returned 401 Unauthorized — "
                        f"API key mismatch. Update WHAI_PRIMARY_API_KEY in .env"
                    )
                    return False
                if resp.status_code != 200:
                    logger.warning(f"Brain health: {label} API returned {resp.status_code}")
                    return False
                data = resp.json()
                model_ids = [m.get("id", "?") for m in data.get("data", [])]
                result["models"].extend(model_ids)
                if not model_ids:
                    logger.warning(f"Brain health: {label} API reachable but NO models loaded!")
                    return False
                logger.info(f"Brain health: {label} OK — models={model_ids}")
                return True
            except httpx.ConnectError:
                logger.warning(f"Brain health: {label} API unreachable (ConnectError)")
                return False
            except Exception as e:
                logger.warning(f"Brain health: {label} API check failed: {e}")
                return False

        def _check_local(model: Any, label: str) -> bool:
            if model is None:
                return False
            logger.info(f"Brain health: {label} local model loaded")
            return True

        # Primary check
        if self.primary_config:
            if self.primary_config.backend == InferenceBackend.REMOTE:
                result["primary_ok"] = await _check_remote(self._primary_client, "PRIMARY")
            else:
                result["primary_ok"] = _check_local(self._primary_model, "PRIMARY")

        # Secondary check
        if self.secondary_config:
            if self.secondary_config.backend == InferenceBackend.REMOTE:
                result["secondary_ok"] = await _check_remote(self._secondary_client, "SECONDARY")
            else:
                result["secondary_ok"] = _check_local(self._secondary_model, "SECONDARY")

        result["ready"] = result["primary_ok"] or result["secondary_ok"]

        if not result["ready"]:
            if not self.has_primary and not self.has_secondary:
                result["error"] = (
                    "Brain engine has no models configured. "
                    "Check config/settings.yaml brain section."
                )
            else:
                urls = []
                if self.primary_config and self.primary_config.api_url:
                    urls.append(self.primary_config.api_url)
                if self.secondary_config and self.secondary_config.api_url:
                    urls.append(self.secondary_config.api_url)
                tunnel_hint = ""
                if result["tunnel_status"] == "failed":
                    tunnel_hint = (
                        " SSH tunnel is DOWN — run 'bash scripts/ssh_tunnel.sh start' "
                        "or ensure the remote Mac is reachable."
                    )
                result["error"] = (
                    f"Brain API unreachable or no models loaded.{tunnel_hint} "
                    f"Ensure LM Studio is running with a model loaded. "
                    f"API URL(s): {', '.join(set(urls)) or 'not configured'}"
                )

        return result

    async def _ensure_ssh_tunnel_for_health_check(self) -> bool:
        """Ensure SSH tunnel is alive, start it if not. Returns True if tunnel is OK."""
        tunnel_script = Path(SSH_TUNNEL_SCRIPT)
        if not tunnel_script.exists():
            logger.debug("SSH tunnel script not found — skipping tunnel check")
            return True  # No tunnel script = assume direct connection

        try:
            # Check status first
            status_result = await asyncio.to_thread(
                subprocess.run,
                ["bash", str(tunnel_script), "status"],
                capture_output=True, text=True, timeout=10,
            )
            if status_result.returncode == 0 and "ACTIVE" in status_result.stdout:
                logger.info("SSH tunnel: ACTIVE")
                return True

            # Tunnel is down — try to start it
            logger.warning("SSH tunnel is DOWN — attempting to start...")
            start_result = await asyncio.to_thread(
                subprocess.run,
                ["bash", str(tunnel_script), "start"],
                capture_output=True, text=True, timeout=30,
            )
            if start_result.returncode == 0:
                logger.info(f"SSH tunnel started: {start_result.stdout.strip()}")
                await asyncio.sleep(2)  # Allow tunnel to stabilize
                # Refresh httpx clients — old pool has stale sockets
                await self._refresh_remote_clients()
                return True
            else:
                logger.error(f"SSH tunnel start failed: {start_result.stderr.strip()}")
                return False

        except subprocess.TimeoutExpired:
            logger.warning("SSH tunnel check/start timed out")
            return False
        except Exception as e:
            logger.warning(f"SSH tunnel check/start error: {e}")
            return False

    def get_stats(self) -> dict[str, Any]:
        """İnference istatistiklerini döndür."""
        return {
            "initialized": self._initialized,
            "primary_loaded": self.has_primary,
            "secondary_loaded": self.has_secondary,
            "inference_count": self._inference_count,
            "total_inference_time": round(self._total_inference_time, 2),
            "avg_inference_time": round(
                self._total_inference_time / max(1, self._inference_count), 2
            ),
            "failed_inferences": self._failed_inferences,
            "total_retries": self._retry_count,
            "cross_brain_fallbacks": self._fallback_count,
            "circuit_breaker": {
                "primary": self._cb_primary.to_dict(),
                "secondary": self._cb_secondary.to_dict(),
            },
        }

    # ── Background Tunnel Watchdog ─────────────────────────────
    _tunnel_watchdog_task: asyncio.Task | None = None

    async def start_tunnel_watchdog(self, interval: float = 60.0) -> None:
        """Start a background task that checks SSH tunnel every `interval` seconds."""
        has_remote = (
            (self.primary_config and self.primary_config.backend == InferenceBackend.REMOTE)
            or (self.secondary_config and self.secondary_config.backend == InferenceBackend.REMOTE)
        )
        if not has_remote:
            return
        if self._tunnel_watchdog_task and not self._tunnel_watchdog_task.done():
            return  # Already running
        self._tunnel_watchdog_task = asyncio.create_task(
            self._tunnel_watchdog_loop(interval)
        )
        logger.info(f"SSH tunnel watchdog started (check every {interval:.0f}s)")

    async def stop_tunnel_watchdog(self) -> None:
        """Stop the background tunnel watchdog."""
        if self._tunnel_watchdog_task and not self._tunnel_watchdog_task.done():
            self._tunnel_watchdog_task.cancel()
            try:
                await self._tunnel_watchdog_task
            except asyncio.CancelledError:
                pass
            logger.info("SSH tunnel watchdog stopped")

    async def _tunnel_watchdog_loop(self, interval: float) -> None:
        """Periodically check tunnel health and reconnect if needed."""
        while True:
            try:
                await asyncio.sleep(interval)
                ok = await self._ensure_ssh_tunnel_for_health_check()
                if not ok:
                    logger.debug("Tunnel watchdog: tunnel down — reconnect attempted")
                else:
                    logger.debug("Tunnel watchdog: tunnel OK")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Tunnel watchdog error: {e}")


__all__ = [
    "BrainEngine", "BrainResponse", "ModelConfig", "ChatMessage",
    "InferenceBackend", "CircuitBreaker",
]
