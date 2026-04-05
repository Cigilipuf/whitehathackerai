"""
WhiteHatHacker AI — Task Scheduler

Görev zamanlayıcı: Araç çalıştırma sırasını, paralelliği ve
öncelikleri yönetir. Rate-limit uyumlu, hata toleranslı.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from enum import StrEnum
from typing import Any, Callable, Awaitable

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Enums & Models
# ============================================================

class TaskStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    WAITING = "waiting"      # Bağımlılık bekliyor


class TaskPriority(StrEnum):
    CRITICAL = "critical"    # 1 — hemen çalıştır
    HIGH = "high"            # 2
    NORMAL = "normal"        # 3
    LOW = "low"              # 4
    BACKGROUND = "background"  # 5

PRIORITY_VALUES = {
    TaskPriority.CRITICAL: 1,
    TaskPriority.HIGH: 2,
    TaskPriority.NORMAL: 3,
    TaskPriority.LOW: 4,
    TaskPriority.BACKGROUND: 5,
}


class ScheduledTask(BaseModel):
    """Zamanlanmış görev."""

    task_id: str = Field(default_factory=lambda: f"TASK-{uuid.uuid4().hex[:8]}")
    name: str = ""
    description: str = ""
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.QUEUED

    # Hedef
    tool_name: str = ""
    target: str = ""
    options: dict[str, Any] = Field(default_factory=dict)

    # Bağımlılıklar
    depends_on: list[str] = Field(default_factory=list)   # Task ID'leri
    blocks: list[str] = Field(default_factory=list)

    # Zamanlama
    created_at: float = Field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    timeout_seconds: int = 600

    # Paralel grubu
    parallel_group: str = ""  # Aynı gruptakiler paralel çalışabilir

    # Sonuç
    result: dict[str, Any] | None = None
    error: str = ""
    retry_count: int = 0
    max_retries: int = 2


class SchedulerConfig(BaseModel):
    """Zamanlayıcı ayarları."""

    max_parallel_tasks: int = 5
    max_parallel_per_host: int = 3
    global_rate_limit_rps: int = 10
    task_timeout_default: int = 600
    retry_delay_seconds: int = 30
    queue_poll_interval: float = 0.5


# ============================================================
# Task Scheduler
# ============================================================

class TaskScheduler:
    """
    Görev zamanlayıcı.

    Özellikleri:
    - Öncelik bazlı kuyruk
    - Bağımlılık grafiği (DAG) yönetimi
    - Paralel grup desteği
    - Host başına eşzamanlılık limiti
    - Otomatik retry mekanizması
    - Görev iptali ve skip desteği

    Usage:
        scheduler = TaskScheduler()

        # Görevleri ekle
        t1 = scheduler.add_task(
            name="subdomain_scan",
            tool_name="subfinder",
            target="example.com",
            priority="high",
        )
        t2 = scheduler.add_task(
            name="port_scan",
            tool_name="nmap",
            target="example.com",
            depends_on=[t1.task_id],
        )

        # Çalıştır
        results = await scheduler.run(executor_fn=my_tool_executor)
    """

    def __init__(self, config: SchedulerConfig | None = None) -> None:
        self.config = config or SchedulerConfig()
        self._tasks: dict[str, ScheduledTask] = {}
        self._queue: list[str] = []  # Task ID sıralı kuyruk
        self._running: set[str] = set()
        self._completed: set[str] = set()
        self._failed: set[str] = set()
        self._host_counts: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
        self._cancelled = False

    # --------- Task Management ---------

    def add_task(
        self,
        name: str,
        tool_name: str = "",
        target: str = "",
        options: dict[str, Any] | None = None,
        priority: str = "normal",
        depends_on: list[str] | None = None,
        parallel_group: str = "",
        timeout: int = 0,
        description: str = "",
    ) -> ScheduledTask:
        """Yeni görev ekle."""
        task = ScheduledTask(
            name=name,
            description=description or f"Run {tool_name} on {target}",
            priority=TaskPriority(priority),
            tool_name=tool_name,
            target=target,
            options=options or {},
            depends_on=depends_on or [],
            parallel_group=parallel_group,
            timeout_seconds=timeout or self.config.task_timeout_default,
        )

        self._tasks[task.task_id] = task
        self._queue.append(task.task_id)

        # Bağımlılık ilişkilerini güncelle
        for dep_id in task.depends_on:
            if dep_id in self._tasks:
                self._tasks[dep_id].blocks.append(task.task_id)

        logger.debug(
            f"Task added: {task.task_id} | {name} | "
            f"priority={priority} | depends_on={depends_on}"
        )

        return task

    def add_task_batch(
        self,
        tasks: list[dict[str, Any]],
        parallel_group: str = "",
    ) -> list[ScheduledTask]:
        """Toplu görev ekleme (aynı paralel grupta)."""
        result = []
        for t in tasks:
            task = self.add_task(
                parallel_group=parallel_group or t.get("parallel_group", ""),
                **{k: v for k, v in t.items() if k != "parallel_group"},
            )
            result.append(task)
        return result

    def cancel_task(self, task_id: str) -> bool:
        """Görevi iptal et."""
        if task_id in self._tasks:
            task = self._tasks[task_id]
            if task.status in (TaskStatus.QUEUED, TaskStatus.WAITING):
                task.status = TaskStatus.CANCELLED
                if task_id in self._queue:
                    self._queue.remove(task_id)
                logger.info(f"Task cancelled: {task_id}")
                return True
        return False

    def skip_task(self, task_id: str, reason: str = "") -> bool:
        """Görevi atla."""
        if task_id in self._tasks:
            task = self._tasks[task_id]
            if task.status in (TaskStatus.QUEUED, TaskStatus.WAITING):
                task.status = TaskStatus.SKIPPED
                task.error = reason or "Manually skipped"
                task.completed_at = time.time()
                self._completed.add(task_id)
                if task_id in self._queue:
                    self._queue.remove(task_id)
                logger.info(f"Task skipped: {task_id} | {reason}")
                return True
        return False

    def cancel_all(self) -> None:
        """Tüm kuyruktakileri iptal et."""
        self._cancelled = True
        for tid in list(self._queue):
            self.cancel_task(tid)

    # --------- Execution ---------

    async def run(
        self,
        executor_fn: Callable[[ScheduledTask], Awaitable[dict[str, Any]]],
    ) -> list[ScheduledTask]:
        """
        Tüm görevleri çalıştır.

        Args:
            executor_fn: (ScheduledTask) -> dict çalıştırıcı fonksiyon

        Returns:
            Tamamlanan görev listesi
        """
        self._cancelled = False
        self._sort_queue()

        total = len(self._queue)
        logger.info(f"Scheduler starting | tasks={total} | max_parallel={self.config.max_parallel_tasks}")

        active: set[asyncio.Task] = set()

        while (self._queue or active) and not self._cancelled:
            # Hazır görevleri bul ve çalıştır
            while self._queue and len(active) < self.config.max_parallel_tasks:
                next_id = self._pick_next()
                if next_id is None:
                    break

                task = self._tasks[next_id]

                # Host limiti kontrolü
                host = self._extract_host(task.target)
                if host and self._host_counts[host] >= self.config.max_parallel_per_host:
                    continue

                # Başlat
                task.status = TaskStatus.RUNNING
                task.started_at = time.time()
                self._running.add(next_id)
                if host:
                    self._host_counts[host] += 1

                atask = asyncio.create_task(
                    self._execute_task(task, executor_fn),
                    name=next_id,
                )
                active.add(atask)

            if not active:
                # Bağımlılık bekleyenleri kontrol et
                if self._queue:
                    await asyncio.sleep(self.config.queue_poll_interval)
                    continue
                break

            # Bir tane tamamlanmasını bekle
            done, active = await asyncio.wait(
                active, return_when=asyncio.FIRST_COMPLETED
            )

            for finished in done:
                try:
                    finished.result()
                except Exception as e:
                    logger.error(f"Task execution error: {e}")

        # Sonuçlar
        completed_total = len(self._completed)
        failed_total = len(self._failed)
        logger.info(
            f"Scheduler finished | completed={completed_total} | "
            f"failed={failed_total} | total={total}"
        )

        return list(self._tasks.values())

    async def _execute_task(
        self,
        task: ScheduledTask,
        executor_fn: Callable[[ScheduledTask], Awaitable[dict[str, Any]]],
    ) -> None:
        """Tek bir görevi çalıştır."""
        try:
            result = await asyncio.wait_for(
                executor_fn(task),
                timeout=task.timeout_seconds,
            )
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            async with self._lock:
                self._completed.add(task.task_id)

            duration = task.completed_at - task.started_at
            logger.info(
                f"Task completed: {task.task_id} | {task.name} | "
                f"{duration:.1f}s"
            )

        except asyncio.TimeoutError:
            task.error = f"Timeout after {task.timeout_seconds}s"
            task.status = TaskStatus.FAILED
            async with self._lock:
                self._failed.add(task.task_id)
            logger.warning(f"Task timeout: {task.task_id} | {task.name}")

        except Exception as e:
            task.error = str(e)

            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.QUEUED
                async with self._lock:
                    self._queue.append(task.task_id)
                logger.warning(
                    f"Task failed, retrying ({task.retry_count}/{task.max_retries}): "
                    f"{task.task_id} | {e}"
                )
                await asyncio.sleep(self.config.retry_delay_seconds)
            else:
                task.status = TaskStatus.FAILED
                task.completed_at = time.time()
                async with self._lock:
                    self._failed.add(task.task_id)
                logger.error(f"Task failed permanently: {task.task_id} | {e}")

        finally:
            self._running.discard(task.task_id)
            host = self._extract_host(task.target)
            if host and self._host_counts[host] > 0:
                self._host_counts[host] -= 1

    # --------- Queue Management ---------

    def _sort_queue(self) -> None:
        """Kuyruğu önceliğe göre sırala."""
        self._queue.sort(
            key=lambda tid: PRIORITY_VALUES.get(
                self._tasks[tid].priority, 3
            )
        )

    def _pick_next(self) -> str | None:
        """Çalıştırılmaya hazır sonraki görevi seç."""
        to_remove: list[int] = []
        result: str | None = None

        for i, tid in enumerate(self._queue):
            task = self._tasks[tid]

            # Already skipped (by a previous _dependencies_met call)
            if task.status == TaskStatus.SKIPPED:
                to_remove.append(i)
                continue

            # Bağımlılıkları kontrol et
            if self._dependencies_met(task):
                if task.status == TaskStatus.SKIPPED:
                    # _dependencies_met just marked it skipped due to failed dep
                    to_remove.append(i)
                    continue
                to_remove.append(i)
                result = tid
                break

        # Remove indices in reverse order to preserve positions
        for idx in reversed(to_remove):
            self._queue.pop(idx)

        return result

    def _dependencies_met(self, task: ScheduledTask) -> bool:
        """Tüm bağımlılıklar tamamlandı mı?"""
        for dep_id in task.depends_on:
            if dep_id not in self._completed:
                # Bağımlılık başarısız olduysa görevi de atla
                if dep_id in self._failed:
                    task.status = TaskStatus.SKIPPED
                    task.error = f"Dependency {dep_id} failed"
                    self._completed.add(task.task_id)
                    return False
                return False
        return True

    @staticmethod
    def _extract_host(target: str) -> str:
        """Hedeften host bilgisini çıkar."""
        if not target:
            return ""
        host = target
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        return host.split("/")[0].split(":")[0]

    # --------- Info ---------

    def get_task(self, task_id: str) -> ScheduledTask | None:
        return self._tasks.get(task_id)

    def get_status(self) -> dict[str, Any]:
        """Zamanlayıcı durumu."""
        status_counts: dict[str, int] = defaultdict(int)
        for t in self._tasks.values():
            status_counts[t.status] += 1

        return {
            "total_tasks": len(self._tasks),
            "queued": status_counts.get(TaskStatus.QUEUED, 0),
            "running": len(self._running),
            "completed": len(self._completed),
            "failed": len(self._failed),
            "cancelled": status_counts.get(TaskStatus.CANCELLED, 0),
            "skipped": status_counts.get(TaskStatus.SKIPPED, 0),
        }

    def get_results(self) -> list[dict[str, Any]]:
        """Tüm görev sonuçlarını getir."""
        return [
            {
                "task_id": t.task_id,
                "name": t.name,
                "tool": t.tool_name,
                "target": t.target,
                "status": t.status,
                "duration": (
                    round(t.completed_at - t.started_at, 1)
                    if t.started_at and t.completed_at else 0
                ),
                "error": t.error,
                "result_keys": list(t.result.keys()) if t.result else [],
            }
            for t in self._tasks.values()
        ]


__all__ = [
    "TaskScheduler",
    "ScheduledTask",
    "SchedulerConfig",
    "TaskStatus",
    "TaskPriority",
]
