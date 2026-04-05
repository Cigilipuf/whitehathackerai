"""
WhiteHatHacker AI — FP Feedback Loop

False positive tespitlerini kaydeden, geri bildirim toplayan
ve FP veritabanını güncelleyen öğrenme modülü.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Models
# ============================================================

class FPFeedbackRecord(BaseModel):
    """Tek bir FP geri bildirim kaydı."""

    finding_id: str = ""
    vuln_type: str = ""
    tool: str = ""
    endpoint: str = ""
    parameter: str = ""
    original_confidence: float = 0.0

    # Karar
    verdict: str = ""              # "true_positive", "false_positive", "unsure"
    verdict_source: str = ""       # "auto_fp_engine", "human_review", "multi_tool_verify"

    # Detaylar
    reason: str = ""
    fp_pattern_matched: str = ""   # Eşleşen pattern ID (varsa)

    # Zaman
    timestamp: str = ""
    session_id: str = ""

    # Ek meta
    metadata: dict[str, Any] = Field(default_factory=dict)


class FPStatistics(BaseModel):
    """FP istatistikleri."""

    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    unsure: int = 0
    fp_rate: float = 0.0

    by_tool: dict[str, dict[str, int]] = Field(default_factory=dict)
    by_vuln_type: dict[str, dict[str, int]] = Field(default_factory=dict)
    by_pattern: dict[str, int] = Field(default_factory=dict)


# ============================================================
# FP Feedback Manager
# ============================================================

class FPFeedbackManager:
    """
    FP geri bildirim döngüsü yöneticisi.

    İşlevler:
    1. FP/TP kararlarını kaydet
    2. Zaman içinde araç ve zafiyet türü bazlı FP oranlarını hesapla
    3. Pattern eşleme kalitesini izle
    4. Sonraki taramalarda güven ayarlaması için veri sağla

    Usage:
        feedback = FPFeedbackManager("/path/to/db.sqlite")

        # Karar kaydet
        feedback.record(FPFeedbackRecord(
            finding_id="F-001",
            vuln_type="sql_injection",
            tool="sqlmap",
            verdict="false_positive",
            reason="WAF blocking masked as injection"
        ))

        # İstatistikler
        stats = feedback.get_statistics()
        tool_rate = feedback.get_tool_fp_rate("sqlmap")
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = str(db_path or "output/fp_feedback.db")
        self._records: list[FPFeedbackRecord] = []
        self._init_db()

    def _init_db(self) -> None:
        """SQLite veritabanını oluştur."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self._db_path, timeout=30) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fp_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    endpoint TEXT,
                    parameter TEXT,
                    original_confidence REAL,
                    verdict TEXT NOT NULL,
                    verdict_source TEXT,
                    reason TEXT,
                    fp_pattern_matched TEXT,
                    timestamp TEXT NOT NULL,
                    session_id TEXT,
                    metadata TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_fp_tool
                ON fp_feedback(tool)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_fp_vuln_type
                ON fp_feedback(vuln_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_fp_verdict
                ON fp_feedback(verdict)
            """)
            conn.commit()

        logger.debug(f"FP feedback database initialized: {self._db_path}")

    def record(self, feedback: FPFeedbackRecord) -> None:
        """
        FP geri bildirimi kaydet.
        """
        if not feedback.timestamp:
            feedback.timestamp = datetime.now(timezone.utc).isoformat()

        self._records.append(feedback)

        # SQLite'a yaz
        with sqlite3.connect(self._db_path, timeout=30) as conn:
            conn.execute(
                """INSERT INTO fp_feedback
                   (finding_id, vuln_type, tool, endpoint, parameter,
                    original_confidence, verdict, verdict_source, reason,
                    fp_pattern_matched, timestamp, session_id, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    feedback.finding_id,
                    feedback.vuln_type,
                    feedback.tool,
                    feedback.endpoint,
                    feedback.parameter,
                    feedback.original_confidence,
                    feedback.verdict,
                    feedback.verdict_source,
                    feedback.reason,
                    feedback.fp_pattern_matched,
                    feedback.timestamp,
                    feedback.session_id,
                    json.dumps(feedback.metadata),
                ),
            )
            conn.commit()

        logger.info(
            f"FP feedback recorded | finding={feedback.finding_id} | "
            f"verdict={feedback.verdict} | tool={feedback.tool}"
        )

    def record_batch(self, records: list[FPFeedbackRecord]) -> None:
        """Toplu kayıt."""
        for r in records:
            self.record(r)

    def get_statistics(self) -> FPStatistics:
        """Genel FP istatistikleri."""
        with sqlite3.connect(self._db_path, timeout=30) as conn:
            conn.row_factory = sqlite3.Row

            # Toplam verdicts
            rows = conn.execute(
                "SELECT verdict, COUNT(*) as cnt FROM fp_feedback GROUP BY verdict"
            ).fetchall()

            verdict_counts = {row["verdict"]: row["cnt"] for row in rows}
            total = sum(verdict_counts.values())
            tp = verdict_counts.get("true_positive", 0)
            fp = verdict_counts.get("false_positive", 0)
            unsure = verdict_counts.get("unsure", 0)

            # Araç bazlı
            by_tool: dict[str, dict[str, int]] = {}
            rows = conn.execute(
                "SELECT tool, verdict, COUNT(*) as cnt FROM fp_feedback GROUP BY tool, verdict"
            ).fetchall()
            for row in rows:
                tool = row["tool"]
                if tool not in by_tool:
                    by_tool[tool] = {"true_positive": 0, "false_positive": 0, "unsure": 0}
                by_tool[tool][row["verdict"]] = row["cnt"]

            # Zafiyet türü bazlı
            by_vuln: dict[str, dict[str, int]] = {}
            rows = conn.execute(
                "SELECT vuln_type, verdict, COUNT(*) as cnt FROM fp_feedback GROUP BY vuln_type, verdict"
            ).fetchall()
            for row in rows:
                vtype = row["vuln_type"]
                if vtype not in by_vuln:
                    by_vuln[vtype] = {"true_positive": 0, "false_positive": 0, "unsure": 0}
                by_vuln[vtype][row["verdict"]] = row["cnt"]

            # Pattern bazlı
            by_pattern: dict[str, int] = {}
            rows = conn.execute(
                """SELECT fp_pattern_matched, COUNT(*) as cnt
                   FROM fp_feedback
                   WHERE fp_pattern_matched != '' AND fp_pattern_matched IS NOT NULL
                   GROUP BY fp_pattern_matched"""
            ).fetchall()
            for row in rows:
                by_pattern[row["fp_pattern_matched"]] = row["cnt"]

        fp_rate = fp / total if total > 0 else 0.0

        return FPStatistics(
            total_findings=total,
            true_positives=tp,
            false_positives=fp,
            unsure=unsure,
            fp_rate=round(fp_rate, 3),
            by_tool=by_tool,
            by_vuln_type=by_vuln,
            by_pattern=by_pattern,
        )

    def get_tool_fp_rate(self, tool_name: str) -> float:
        """Belirli bir aracın FP oranı."""
        with sqlite3.connect(self._db_path, timeout=30) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM fp_feedback WHERE tool = ?", (tool_name,)
            ).fetchone()[0]

            fps = conn.execute(
                "SELECT COUNT(*) FROM fp_feedback WHERE tool = ? AND verdict = 'false_positive'",
                (tool_name,),
            ).fetchone()[0]

        return fps / total if total > 0 else 0.0

    def get_vuln_type_fp_rate(self, vuln_type: str) -> float:
        """Belirli bir zafiyet türünün FP oranı."""
        with sqlite3.connect(self._db_path, timeout=30) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM fp_feedback WHERE vuln_type = ?", (vuln_type,)
            ).fetchone()[0]

            fps = conn.execute(
                "SELECT COUNT(*) FROM fp_feedback WHERE vuln_type = ? AND verdict = 'false_positive'",
                (vuln_type,),
            ).fetchone()[0]

        return fps / total if total > 0 else 0.0

    def get_confidence_adjustment(
        self, tool: str, vuln_type: str
    ) -> float:
        """
        Geçmiş veriye göre güven skoru ayarlaması öner.

        Returns:
            float: -30 ile +10 arası ayarlama değeri
        """
        tool_rate = self.get_tool_fp_rate(tool)
        vuln_rate = self.get_vuln_type_fp_rate(vuln_type)

        # Ağırlıklı FP oranı
        combined_rate = (tool_rate * 0.6) + (vuln_rate * 0.4)

        if combined_rate > 0.5:
            return -25.0  # Çok yüksek FP oranı
        elif combined_rate > 0.3:
            return -15.0
        elif combined_rate > 0.15:
            return -8.0
        elif combined_rate < 0.05 and tool_rate < 0.1:
            return 5.0    # Güvenilir tool+vuln_type

        return 0.0

    def get_recent_fps(
        self, limit: int = 20
    ) -> list[FPFeedbackRecord]:
        """Son n adet FP kaydı."""
        with sqlite3.connect(self._db_path, timeout=30) as conn:
            conn.row_factory = sqlite3.Row

            rows = conn.execute(
                """SELECT * FROM fp_feedback
                   WHERE verdict = 'false_positive'
                   ORDER BY timestamp DESC LIMIT ?""",
                (limit,),
            ).fetchall()

        results: list[FPFeedbackRecord] = []
        for r in rows:
            # Deserialize metadata JSON (stored via json.dumps at record time)
            _raw_meta = r["metadata"]
            try:
                _meta = json.loads(_raw_meta) if _raw_meta else {}
            except (json.JSONDecodeError, TypeError):
                _meta = {}

            results.append(
                FPFeedbackRecord(
                    finding_id=r["finding_id"],
                    vuln_type=r["vuln_type"],
                    tool=r["tool"],
                    endpoint=r["endpoint"] or "",
                    parameter=r["parameter"] or "",
                    original_confidence=r["original_confidence"] or 0.0,
                    verdict=r["verdict"],
                    verdict_source=r["verdict_source"] or "",
                    reason=r["reason"] or "",
                    fp_pattern_matched=r["fp_pattern_matched"] or "",
                    timestamp=r["timestamp"],
                    session_id=r["session_id"] or "",
                    metadata=_meta,
                )
            )
        return results


__all__ = [
    "FPFeedbackManager",
    "FPFeedbackRecord",
    "FPStatistics",
]
