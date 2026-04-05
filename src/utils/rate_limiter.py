"""
WhiteHatHacker AI — Rate Limiting Modülü

Her dış istek rate limiter'dan geçer.
Devre dışı bırakılamaz — hedef sisteme zarar vermemek ZORUNLU.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from loguru import logger


@dataclass
class RateLimitConfig:
    """Rate limit konfigürasyonu."""

    max_requests_per_second: float = 10.0    # Global RPS
    max_requests_per_host: float = 3.0       # Host başına RPS
    burst_size: int = 20                     # Burst kapasitesi
    cooldown_period: float = 60.0            # Cooldown süresi (saniye)


class TokenBucket:
    """Token bucket algoritması ile rate limiting."""

    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = rate              # Token/saniye
        self.capacity = capacity      # Maksimum token
        self.tokens = float(capacity) # Mevcut token
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> float:
        """
        Token al. Yeterli token yoksa bekle.

        Returns:
            Bekleme süresi (saniye)
        """
        while True:
            async with self._lock:
                self._refill()

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return 0.0

                # Bekleme süresi hesapla — release lock before sleeping
                deficit = tokens - self.tokens
                wait_time = deficit / self.rate

            # Sleep OUTSIDE the lock so other coroutines aren't blocked
            await asyncio.sleep(wait_time)

            # Re-acquire lock, refill, and try to consume
            async with self._lock:
                self._refill()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return wait_time
            # If tokens still insufficient (race), loop and retry

    def _refill(self) -> None:
        """Token'ları yenile."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        new_tokens = elapsed * self.rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = now


class RateLimiter:
    """
    Multi-tenant rate limiter.

    Global RPS + host bazlı RPS sınırlaması yapar.
    Her araç çalıştırılmadan önce kontrol edilir.
    """

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self.config = config or RateLimitConfig()

        # Global rate limiter
        self._global_bucket = TokenBucket(
            rate=self.config.max_requests_per_second,
            capacity=self.config.burst_size,
        )

        # Host bazlı rate limiter'lar
        self._host_buckets: dict[str, TokenBucket] = {}

        # İstatistikler
        self._stats: dict[str, int] = defaultdict(int)
        self._total_wait_time: float = 0.0

        logger.info(
            f"RateLimiter initialized | "
            f"global_rps={self.config.max_requests_per_second} | "
            f"host_rps={self.config.max_requests_per_host} | "
            f"burst={self.config.burst_size}"
        )

    async def acquire(self, host: str = "global") -> float:
        """
        İstek izni al. Rate limit'e uygun olana kadar bekle.

        Args:
            host: Hedef hostname

        Returns:
            Toplam bekleme süresi (saniye)
        """
        total_wait = 0.0

        # 1. Global rate limit kontrolü
        wait = await self._global_bucket.acquire()
        total_wait += wait

        # 2. Host bazlı rate limit kontrolü
        if host != "global":
            bucket = self._get_host_bucket(host)
            wait = await bucket.acquire()
            total_wait += wait

        # İstatistik güncelle
        self._stats[host] += 1
        self._stats["_total"] += 1
        self._total_wait_time += total_wait

        if total_wait > 0.1:
            logger.debug(f"Rate limited | host={host} | wait={total_wait:.2f}s")

        return total_wait

    def _get_host_bucket(self, host: str) -> TokenBucket:
        """Host için token bucket oluştur veya mevcut olanı döndür."""
        if host not in self._host_buckets:
            self._host_buckets[host] = TokenBucket(
                rate=self.config.max_requests_per_host,
                capacity=max(5, int(self.config.max_requests_per_host * 3)),
            )
        return self._host_buckets[host]

    def get_stats(self) -> dict[str, Any]:
        """Rate limiter istatistiklerini döndür."""
        return {
            "total_requests": self._stats.get("_total", 0),
            "total_wait_time": round(self._total_wait_time, 2),
            "requests_by_host": {k: v for k, v in self._stats.items() if not k.startswith("_")},
            "active_hosts": len(self._host_buckets),
        }

    def reset_host(self, host: str) -> None:
        """Belirli bir host için rate limit'i sıfırla."""
        if host in self._host_buckets:
            del self._host_buckets[host]

    def reset_all(self) -> None:
        """Tüm rate limit'leri sıfırla."""
        self._host_buckets.clear()
        self._stats.clear()
        self._total_wait_time = 0.0


__all__ = ["RateLimiter", "RateLimitConfig"]
