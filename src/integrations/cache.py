"""
WhiteHatHacker AI — Cache System

Anahtar-değer önbellek sistemi. Pahalı operasyon sonuçlarını
(DNS çözümleme, tool çıktıları, brain yanıtları) önbelleğe alır.
SQLite tabanlı persistent cache + bellek içi hızlı cache.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Any, Generator



# ============================================================
# Memory Cache (hızlı, geçici)
# ============================================================

class MemoryCache:
    """Thread-safe bellek içi LRU benzeri cache."""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300) -> None:
        self._store: dict[str, tuple[Any, float, float]] = {}  # value, expires, inserted_at
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._lock = Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Any | None:
        with self._lock:
            if key in self._store:
                value, expires, _ = self._store[key]
                if expires == 0 or time.time() < expires:
                    self._hits += 1
                    return value
                else:
                    del self._store[key]
            self._misses += 1
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        with self._lock:
            if len(self._store) >= self._max_size:
                self._evict()

            actual_ttl = ttl if ttl is not None else self._default_ttl
            expires = time.time() + actual_ttl if actual_ttl > 0 else 0
            self._store[key] = (value, expires, time.time())

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def _evict(self) -> None:
        """En eski/süresi dolmuş öğeyi çıkar."""
        now = time.time()
        # Önce süresi dolmuş olanları temizle
        expired = [k for k, (_, exp, _) in self._store.items() if exp and exp < now]
        for k in expired:
            del self._store[k]

        # Hala dolu ise en eski girişi sil (by insertion time, not expiry)
        if len(self._store) >= self._max_size and self._store:
            oldest = min(self._store, key=lambda k: self._store[k][2])
            del self._store[oldest]

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "size": len(self._store),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": (
                round(self._hits / (self._hits + self._misses) * 100, 1)
                if (self._hits + self._misses) > 0 else 0
            ),
        }


# ============================================================
# Persistent Cache (SQLite tabanlı)
# ============================================================

class PersistentCache:
    """
    SQLite tabanlı kalıcı cache.

    Tarama oturumları arası koruma gerektiren veriler için:
    - DNS çözümleme sonuçları
    - Teknoloji tespitleri
    - API yanıtları

    Usage:
        cache = PersistentCache("output/cache.db")
        cache.set("dns:example.com", {"A": "1.2.3.4"}, ttl=3600)
        result = cache.get("dns:example.com")
    """

    def __init__(self, db_path: str | Path = "output/cache.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL,
                    namespace TEXT DEFAULT ''
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cache_ns ON cache(namespace)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cache_exp ON cache(expires_at)"
            )

    def _conn(self):
        """Context manager for safe connection handling."""
        @contextmanager
        def _cm() -> Generator[sqlite3.Connection, None, None]:
            conn = sqlite3.connect(str(self.db_path), timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            try:
                yield conn
                conn.commit()
            except Exception as _exc:
                conn.rollback()
                raise
            finally:
                conn.close()
        return _cm()

    def get(self, key: str) -> Any | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()

            if row is None:
                return None

            value_json, expires_at = row
            if expires_at and time.time() > expires_at:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                return None

            return json.loads(value_json)

    def set(
        self,
        key: str,
        value: Any,
        ttl: int = 3600,
        namespace: str = "",
    ) -> None:
        with self._conn() as conn:
            now = time.time()
            expires = now + ttl if ttl > 0 else None
            conn.execute(
                """INSERT OR REPLACE INTO cache
                   (key, value, created_at, expires_at, namespace)
                   VALUES (?, ?, ?, ?, ?)""",
                (key, json.dumps(value, ensure_ascii=False), now, expires, namespace),
            )

    def delete(self, key: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))

    def clear_namespace(self, namespace: str) -> int:
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM cache WHERE namespace = ?", (namespace,)
            )
            return cursor.rowcount

    def clear_expired(self) -> int:
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM cache WHERE expires_at IS NOT NULL AND expires_at < ?",
                (time.time(),),
            )
            return cursor.rowcount

    def clear_all(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM cache")

    @property
    def size(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]


# ============================================================
# Unified Cache (Memory + Persistent)
# ============================================================

class CacheManager:
    """
    İki katmanlı cache yöneticisi.

    L1: Bellek içi (hızlı, geçici)
    L2: SQLite (yavaş, kalıcı)

    Usage:
        cache = CacheManager()
        cache.set("key", "value", ttl=600)
        result = cache.get("key")  # L1'den veya L2'den döner
    """

    def __init__(
        self,
        memory_max: int = 1000,
        memory_ttl: int = 300,
        db_path: str = "output/cache.db",
    ) -> None:
        self._l1 = MemoryCache(max_size=memory_max, default_ttl=memory_ttl)
        self._l2 = PersistentCache(db_path=db_path)

    def get(self, key: str) -> Any | None:
        # L1 kontrol
        result = self._l1.get(key)
        if result is not None:
            return result

        # L2 kontrol
        result = self._l2.get(key)
        if result is not None:
            # L1'e kopyala (cache warming)
            self._l1.set(key, result)
            return result

        return None

    def set(
        self,
        key: str,
        value: Any,
        ttl: int = 600,
        persistent: bool = True,
        namespace: str = "",
    ) -> None:
        self._l1.set(key, value, ttl=ttl)
        if persistent:
            self._l2.set(key, value, ttl=ttl, namespace=namespace)

    def delete(self, key: str) -> None:
        self._l1.delete(key)
        self._l2.delete(key)

    def clear(self) -> None:
        self._l1.clear()
        self._l2.clear_all()

    def cleanup(self) -> int:
        """Süresi dolmuş öğeleri temizle."""
        return self._l2.clear_expired()

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "l1_memory": self._l1.stats,
            "l2_persistent_size": self._l2.size,
        }


__all__ = [
    "CacheManager",
    "MemoryCache",
    "PersistentCache",
]
