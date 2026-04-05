"""
WhiteHatHacker AI — Confidence Calibration System (T2-5)

Tracks historical accuracy of confidence scores per vuln_type and
applies calibration adjustments so that a "70% confidence" truly
means ~70% of such findings are real.

Calibration data is stored in ``output/calibration.json`` and
survives across scans.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from loguru import logger


_DEFAULT_PATH = Path("output/calibration.json")


class CalibrationBucket:
    """Stats for a single (vuln_type, confidence_range) bucket."""

    __slots__ = ("total", "true_positive")

    def __init__(self, total: int = 0, true_positive: int = 0) -> None:
        self.total = total
        self.true_positive = true_positive

    @property
    def tp_rate(self) -> float:
        return self.true_positive / self.total if self.total > 0 else 0.5

    def to_dict(self) -> dict[str, int]:
        return {"total": self.total, "true_positive": self.true_positive}

    @classmethod
    def from_dict(cls, d: dict[str, int]) -> CalibrationBucket:
        return cls(total=d.get("total", 0), true_positive=d.get("true_positive", 0))


def _bucket_key(confidence: float) -> str:
    """Map a confidence score into a 10-point bucket label."""
    lo = int(confidence // 10) * 10
    hi = min(lo + 10, 100)
    return f"{lo}-{hi}"


class ConfidenceCalibrator:
    """
    Learns from past scan outcomes and provides a calibration offset
    for future confidence scores.

    Usage::

        cal = ConfidenceCalibrator()
        cal.load()

        # After FP analysis — record each finding's outcome
        cal.record("xss", confidence=72.0, was_true_positive=True)

        # Before reporting — get calibrated score
        adjusted = cal.calibrate("xss", raw_confidence=72.0)

        cal.save()
    """

    def __init__(self, path: Path | str = _DEFAULT_PATH) -> None:
        self._path = Path(path)
        # {vuln_type: {bucket_key: CalibrationBucket}}
        self._data: dict[str, dict[str, CalibrationBucket]] = {}

    # ── Persistence ───────────────────────────────────────────

    def load(self) -> None:
        """Load calibration data from disk."""
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for vtype, buckets in raw.items():
                self._data[vtype] = {
                    k: CalibrationBucket.from_dict(v) for k, v in buckets.items()
                }
            logger.debug(f"Calibration loaded | types={len(self._data)}")
        except Exception as e:
            logger.warning(f"Calibration load failed: {e}")

    def save(self) -> None:
        """Persist calibration data to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        raw: dict[str, Any] = {}
        for vtype, buckets in self._data.items():
            raw[vtype] = {k: v.to_dict() for k, v in buckets.items()}
        self._path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        logger.debug(f"Calibration saved | types={len(self._data)}")

    # ── Recording ─────────────────────────────────────────────

    def record(
        self,
        vuln_type: str,
        confidence: float,
        was_true_positive: bool,
    ) -> None:
        """Record the outcome of a finding for calibration learning."""
        vt = vuln_type.lower().replace("-", "_").replace(" ", "_")
        bk = _bucket_key(confidence)
        if vt not in self._data:
            self._data[vt] = {}
        if bk not in self._data[vt]:
            self._data[vt][bk] = CalibrationBucket()
        bucket = self._data[vt][bk]
        bucket.total += 1
        if was_true_positive:
            bucket.true_positive += 1

    # ── Calibration ───────────────────────────────────────────

    def calibrate(self, vuln_type: str, raw_confidence: float) -> float:
        """Return an adjusted confidence score based on historical accuracy.

        If no historical data exists for this (vuln_type, bucket), the
        raw score is returned unchanged.
        """
        vt = vuln_type.lower().replace("-", "_").replace(" ", "_")
        bk = _bucket_key(raw_confidence)

        buckets = self._data.get(vt, {})
        bucket = buckets.get(bk)

        if bucket is None or bucket.total < 5:
            # Not enough data — return raw
            return raw_confidence

        # Compute offset: if TP rate for this bucket is 0.9 but raw is 0.75
        # → offset = +15 (scale back).  If TP rate is 0.5 but raw is 0.75
        # → offset = -25 (scale down).
        expected_midpoint = (int(bk.split("-")[0]) + int(bk.split("-")[1])) / 2.0
        actual_tp_pct = bucket.tp_rate * 100.0
        offset = (actual_tp_pct - expected_midpoint) * 0.4  # dampen

        adjusted = max(0.0, min(100.0, raw_confidence + offset))

        if abs(offset) > 1.0:
            logger.debug(
                f"Calibrated {vt} {bk}: {raw_confidence:.1f} → {adjusted:.1f} "
                f"(tp_rate={bucket.tp_rate:.0%}, n={bucket.total})"
            )

        return round(adjusted, 1)

    # ── Reporting ─────────────────────────────────────────────

    def summary(self) -> dict[str, Any]:
        """Return a summary dict for logging / metadata."""
        out: dict[str, Any] = {}
        for vt, buckets in self._data.items():
            total = sum(b.total for b in buckets.values())
            tp = sum(b.true_positive for b in buckets.values())
            out[vt] = {
                "total": total,
                "true_positive": tp,
                "tp_rate": round(tp / total, 3) if total > 0 else None,
            }
        return out


__all__ = ["ConfidenceCalibrator", "CalibrationBucket"]
