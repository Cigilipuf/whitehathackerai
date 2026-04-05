"""
WhiteHatHacker AI — FP Pattern Learner

Geçmiş tarama oturumlarından yeni FP kalıplarını otomatik olarak
keşfeden ve öğrenen modül. Tekrarlayan FP'leri tespit ederek
pattern veritabanını genişletir.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, Field

from src.fp_engine.learning.fp_feedback import FPFeedbackManager, FPFeedbackRecord
from src.fp_engine.patterns.known_fps import FPPattern


# ============================================================
# Models
# ============================================================

class LearnedPattern(BaseModel):
    """Öğrenilen yeni FP kalıbı."""

    pattern_id: str = ""
    name: str = ""
    vuln_type: str = ""
    source_tool: str = ""
    description: str = ""
    occurrence_count: int = 0
    confidence_penalty: int = -15

    # Otomatik çıkarılan kurallar
    common_endpoint_pattern: str = ""
    common_status_codes: list[int] = Field(default_factory=list)
    common_keywords: list[str] = Field(default_factory=list)

    # Durum
    status: str = "candidate"     # candidate, approved, rejected
    created_at: str = ""

    def to_fp_pattern(self) -> FPPattern:
        """Onaylanmış kalıbı FPPattern'e dönüştür."""
        rules = []

        if self.common_endpoint_pattern:
            rules.append({
                "field": "url",
                "operator": "regex",
                "value": self.common_endpoint_pattern,
            })

        if self.common_status_codes:
            codes = "|".join(str(c) for c in self.common_status_codes)
            rules.append({
                "field": "status_code",
                "operator": "regex",
                "value": f"({codes})",
            })

        if self.common_keywords:
            keyword_regex = "|".join(re.escape(k) for k in self.common_keywords)
            rules.append({
                "field": "evidence",
                "operator": "regex",
                "value": f"({keyword_regex})",
            })

        return FPPattern(
            id=self.pattern_id,
            name=self.name,
            vuln_type=self.vuln_type,
            source_tool=self.source_tool,
            description=self.description,
            match_rules=rules,
            action="flag",
            confidence_penalty=self.confidence_penalty,
            reason=f"Auto-learned pattern from {self.occurrence_count} historical FP records",
        )


# ============================================================
# Pattern Learner
# ============================================================

class PatternLearner:
    """
    Geçmiş FP verilerinden yeni kalıplar öğrenen motor.

    Strateji:
    1. FP kaydedilen bulguları topla
    2. Tool + vuln_type gruplarında kümeleme yap
    3. Tekrarlayan desenleri çıkar (endpoint, keyword, status code)
    4. Minimum eşik aşan desenleri aday kalıp olarak öner
    5. Onaylanan kalıpları FP veritabanına ekle

    Usage:
        learner = PatternLearner(feedback_manager)
        candidates = learner.learn()
        for c in candidates:
            print(f"New pattern: {c.name} (seen {c.occurrence_count} times)")
    """

    # Minimum tekrar sayısı — bu kadar FP görmeden kalıp oluşturma
    MIN_OCCURRENCES = 3

    def __init__(
        self,
        feedback_manager: FPFeedbackManager | None = None,
        min_occurrences: int = 3,
    ) -> None:
        self._feedback = feedback_manager
        self.MIN_OCCURRENCES = min_occurrences
        self._candidates: list[LearnedPattern] = []
        self._counter = 0

    def learn(
        self,
        fp_records: list[FPFeedbackRecord] | None = None,
    ) -> list[LearnedPattern]:
        """
        FP kayıtlarından yeni kalıplar çıkar.

        Args:
            fp_records: Doğrudan FP kayıt listesi (None ise feedback manager'dan çeker)

        Returns:
            Aday kalıp listesi
        """
        records = fp_records or self._load_fp_records()

        if not records:
            logger.info("No FP records to learn from")
            return []

        # 1. Tool + vuln_type grupla
        groups = self._group_by_tool_vuln(records)

        # 2. Her grup için desen çıkar
        self._candidates.clear()

        for (tool, vuln_type), group_records in groups.items():
            if len(group_records) < self.MIN_OCCURRENCES:
                continue

            patterns = self._extract_patterns(tool, vuln_type, group_records)
            self._candidates.extend(patterns)

        logger.info(
            f"Pattern learning complete | records={len(records)} | "
            f"candidates={len(self._candidates)}"
        )

        return self._candidates

    def _load_fp_records(self) -> list[FPFeedbackRecord]:
        """Feedback manager'dan FP kayıtlarını yükle."""
        if not self._feedback:
            return []
        return self._feedback.get_recent_fps(limit=500)

    @staticmethod
    def _group_by_tool_vuln(
        records: list[FPFeedbackRecord],
    ) -> dict[tuple[str, str], list[FPFeedbackRecord]]:
        """Tool + vuln_type bazında grupla."""
        groups: dict[tuple[str, str], list[FPFeedbackRecord]] = defaultdict(list)
        for r in records:
            groups[(r.tool, r.vuln_type)].append(r)
        return dict(groups)

    def _extract_patterns(
        self,
        tool: str,
        vuln_type: str,
        records: list[FPFeedbackRecord],
    ) -> list[LearnedPattern]:
        """Bir grup FP kaydından desenleri çıkar."""
        patterns: list[LearnedPattern] = []

        # Endpoint desenleri
        endpoint_pattern = self._find_common_endpoint_pattern(
            [r.endpoint for r in records if r.endpoint]
        )

        # Status code desenleri
        status_codes = self._find_common_status_codes(records)

        # Keyword desenleri (reason alanından)
        keywords = self._find_common_keywords(
            [r.reason for r in records if r.reason]
        )

        # Yeterli ortak özellik varsa kalıp oluştur
        if endpoint_pattern or status_codes or keywords:
            self._counter += 1

            pattern = LearnedPattern(
                pattern_id=f"LEARNED-{self._counter:04d}",
                name=f"Auto-learned {vuln_type} FP from {tool}",
                vuln_type=vuln_type,
                source_tool=tool,
                description=(
                    f"Pattern auto-learned from {len(records)} confirmed FP records. "
                    f"Common characteristics: "
                    f"endpoint={endpoint_pattern or 'N/A'}, "
                    f"status_codes={status_codes or 'N/A'}, "
                    f"keywords={keywords[:3] if keywords else 'N/A'}"
                ),
                occurrence_count=len(records),
                confidence_penalty=self._calculate_penalty(len(records)),
                common_endpoint_pattern=endpoint_pattern,
                common_status_codes=status_codes,
                common_keywords=keywords[:5],
            )
            patterns.append(pattern)

        return patterns

    @staticmethod
    def _find_common_endpoint_pattern(endpoints: list[str]) -> str:
        """Endpoint'ler arasında ortak URL kalıbı bul."""
        if not endpoints or len(endpoints) < 2:
            return ""

        # Path bölümlerini çıkar
        paths = []
        for ep in endpoints:
            # URL'den path kısmını al
            path = ep
            for prefix in ("https://", "http://"):
                if path.startswith(prefix):
                    path = path[len(prefix):]
            path = "/" + path.split("/", 1)[-1] if "/" in path else "/"
            paths.append(path)

        # Ortak path segment'ları bul
        segments: Counter[str] = Counter()
        for path in paths:
            parts = [p for p in path.split("/") if p]
            for part in parts:
                segments[part] += 1

        # %60'dan fazla endpoint'te geçen segmentler
        threshold = len(endpoints) * 0.6
        common = [seg for seg, cnt in segments.items() if cnt >= threshold]

        if common:
            return ".*(" + "|".join(re.escape(s) for s in common[:3]) + ").*"

        return ""

    @staticmethod
    def _find_common_status_codes(records: list[FPFeedbackRecord]) -> list[int]:
        """Ortak HTTP status kodlarını bul."""
        codes: Counter[int] = Counter()

        for r in records:
            meta = r.metadata
            if isinstance(meta, dict) and "status_code" in meta:
                codes[meta["status_code"]] += 1

        if not codes:
            return []

        threshold = len(records) * 0.5
        return [code for code, cnt in codes.most_common() if cnt >= threshold]

    @staticmethod
    def _find_common_keywords(reasons: list[str]) -> list[str]:
        """Reason metinlerinden ortak anahtar kelimeleri çıkar."""
        if not reasons:
            return []

        # Kelime frekansı — stop words hariç
        stop_words = {
            "the", "a", "an", "is", "was", "were", "are", "been", "be",
            "have", "has", "had", "do", "does", "did", "will", "would",
            "could", "should", "may", "might", "shall", "can", "need",
            "to", "of", "in", "for", "on", "with", "at", "by", "from",
            "as", "into", "through", "during", "before", "after",
            "and", "but", "or", "nor", "not", "so", "if", "that",
            "this", "it", "its", "what", "which", "who", "whom",
        }

        word_freq: Counter[str] = Counter()
        for reason in reasons:
            words = re.findall(r"\b[a-z]{3,}\b", reason.lower())
            for word in words:
                if word not in stop_words:
                    word_freq[word] += 1

        threshold = len(reasons) * 0.4
        return [word for word, cnt in word_freq.most_common(10) if cnt >= threshold]

    @staticmethod
    def _calculate_penalty(occurrence_count: int) -> int:
        """Tekrar sayısına göre ceza skoru belirle."""
        if occurrence_count >= 20:
            return -30
        elif occurrence_count >= 10:
            return -25
        elif occurrence_count >= 5:
            return -20
        else:
            return -15

    def approve_candidate(self, pattern_id: str) -> FPPattern | None:
        """Aday kalıbı onayla ve FPPattern'e dönüştür."""
        for c in self._candidates:
            if c.pattern_id == pattern_id:
                c.status = "approved"
                fp_pattern = c.to_fp_pattern()
                logger.info(f"Pattern approved: {pattern_id} → {fp_pattern.name}")
                return fp_pattern
        return None

    def reject_candidate(self, pattern_id: str) -> bool:
        """Aday kalıbı reddet."""
        for c in self._candidates:
            if c.pattern_id == pattern_id:
                c.status = "rejected"
                logger.info(f"Pattern rejected: {pattern_id}")
                return True
        return False

    def save_candidates(self, path: str | Path) -> None:
        """Adayları JSON olarak kaydet."""
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)

        data = [c.model_dump() for c in self._candidates]
        output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        logger.info(f"Saved {len(data)} pattern candidates to {output}")

    def load_candidates(self, path: str | Path) -> list[LearnedPattern]:
        """Kaydedilmiş adayları yükle."""
        input_path = Path(path)
        if not input_path.exists():
            return []

        data = json.loads(input_path.read_text())
        self._candidates = [LearnedPattern(**item) for item in data]
        return self._candidates


__all__ = [
    "PatternLearner",
    "LearnedPattern",
]
