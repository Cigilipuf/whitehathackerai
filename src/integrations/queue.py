"""
WhiteHatHacker AI — Task Queue

asyncio tabanlı hafif görev kuyruğu.
Arka plan görevleri, ertelenmiş işler ve toplu operasyonlar için.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from enum import StrEnum
from typing import Any, Callable, Awaitable

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Models
# ============================================================

class QueueItemStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"


class QueueItem(BaseModel):
    item_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    status: QueueItemStatus = QueueItemStatus.PENDING
    priority: int = 5          # 1=en yüksek, 10=en düşük
    max_retries: int = 2
    retry_count: int = 0
    retry_delay: float = 5.0
    created_at: float = Field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    result: Any = None
    error: str = ""


# ============================================================
# Async Task Queue
# ============================================================

class AsyncTaskQueue:
    """
    asyncio tabanlı öncelikli görev kuyruğu.

    Usage:
        queue = AsyncTaskQueue(max_workers=3)

        async def my_handler(item: QueueItem) -> dict:
            # iş yap
            return {"status": "done"}

        queue.register_handler("scan_task", my_handler)

        queue.enqueue("scan_task", payload={"target": "example.com"})

        await queue.start()
    """

    def __init__(self, max_workers: int = 3) -> None:
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._handlers: dict[str, Callable[[QueueItem], Awaitable[Any]]] = {}
        self._max_workers = max_workers
        self._items: dict[str, QueueItem] = {}
        self._running = False
        self._workers: list[asyncio.Task] = []
        self._processed = 0
        self._failed = 0

    def register_handler(
        self,
        task_name: str,
        handler: Callable[[QueueItem], Awaitable[Any]],
    ) -> None:
        """Görev adı için handler kaydet."""
        self._handlers[task_name] = handler

    def enqueue(
        self,
        name: str,
        payload: dict[str, Any] | None = None,
        priority: int = 5,
        max_retries: int = 2,
    ) -> QueueItem:
        """Kuyruğa görev ekle."""
        item = QueueItem(
            name=name,
            payload=payload or {},
            priority=priority,
            max_retries=max_retries,
        )
        self._items[item.item_id] = item
        self._queue.put_nowait((priority, item.item_id))

        logger.debug(f"Enqueued: {item.item_id} | {name} | priority={priority}")
        return item

    async def start(self) -> None:
        """Worker'ları başlat ve kuyruk boşalana kadar çalıştır."""
        self._running = True
        self._workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self._max_workers)
        ]

        logger.info(f"Queue started | workers={self._max_workers}")

        # Tüm öğeler tamamlanana kadar bekle
        await self._queue.join()

        # Worker'ları durdur
        self._running = False
        for w in self._workers:
            w.cancel()

        logger.info(
            f"Queue finished | processed={self._processed} | "
            f"failed={self._failed}"
        )

    async def _worker(self, worker_id: int) -> None:
        """Worker döngüsü."""
        while self._running:
            try:
                priority, item_id = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            item = self._items.get(item_id)
            if not item:
                self._queue.task_done()
                continue

            item.status = QueueItemStatus.PROCESSING
            item.started_at = time.time()

            handler = self._handlers.get(item.name)
            if not handler:
                item.status = QueueItemStatus.FAILED
                item.error = f"No handler for task: {item.name}"
                self._failed += 1
                self._queue.task_done()
                continue

            try:
                result = await handler(item)
                item.result = result
                item.status = QueueItemStatus.COMPLETED
                item.completed_at = time.time()
                self._processed += 1

            except Exception as e:
                item.error = str(e)

                if item.retry_count < item.max_retries:
                    item.retry_count += 1
                    item.status = QueueItemStatus.RETRYING
                    await asyncio.sleep(item.retry_delay)
                    self._queue.put_nowait((item.priority, item.item_id))
                    logger.warning(
                        f"Retrying {item.item_id} ({item.retry_count}/{item.max_retries})"
                    )
                else:
                    item.status = QueueItemStatus.FAILED
                    item.completed_at = time.time()
                    self._failed += 1
                    logger.error(f"Queue item failed: {item.item_id} | {e}")

            finally:
                self._queue.task_done()

    def get_item(self, item_id: str) -> QueueItem | None:
        return self._items.get(item_id)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "queue_size": self._queue.qsize(),
            "total_items": len(self._items),
            "processed": self._processed,
            "failed": self._failed,
            "running": self._running,
        }


__all__ = [
    "AsyncTaskQueue",
    "QueueItem",
    "QueueItemStatus",
]
