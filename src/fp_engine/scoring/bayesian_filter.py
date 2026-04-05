"""WhiteHatHacker AI — Bayesian False-Positive Filter.

Uses Bayesian probability updating to estimate the likelihood that a
vulnerability finding is a true positive vs. false positive, based on
accumulating evidence signals.
"""

from __future__ import annotations

import math
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class EvidenceSignal(BaseModel):
    """A single piece of evidence for/against a finding being real."""

    name: str
    observed: bool  # True = signal IS present
    true_positive_rate: float = 0.8   # P(signal | TP)
    false_positive_rate: float = 0.2  # P(signal | FP)
    weight: float = 1.0
    description: str = ""


class BayesianResult(BaseModel):
    """Output of the Bayesian filter."""

    prior: float = 0.5
    posterior: float = 0.5
    log_odds: float = 0.0
    signals_used: int = 0
    verdict: str = "uncertain"  # true_positive / false_positive / uncertain
    confidence: float = 50.0    # 0-100
    signal_details: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Pre-defined evidence signals per vuln type
# ---------------------------------------------------------------------------

DEFAULT_SIGNALS: dict[str, list[EvidenceSignal]] = {
    "sqli": [
        EvidenceSignal(name="sqlmap_confirmed", observed=False,
                       true_positive_rate=0.95, false_positive_rate=0.03,
                       description="sqlmap confirmed exploitable injection"),
        EvidenceSignal(name="data_extracted", observed=False,
                       true_positive_rate=0.99, false_positive_rate=0.01,
                       description="Actual data extracted from database"),
        EvidenceSignal(name="time_based_delay", observed=False,
                       true_positive_rate=0.85, false_positive_rate=0.10,
                       description="Consistent time-based delay observed"),
        EvidenceSignal(name="error_based_output", observed=False,
                       true_positive_rate=0.75, false_positive_rate=0.15,
                       description="Database error messages in response"),
        EvidenceSignal(name="waf_block", observed=False,
                       true_positive_rate=0.30, false_positive_rate=0.70,
                       description="WAF blocking — may mask real vuln or cause FP"),
    ],
    "xss": [
        EvidenceSignal(name="payload_reflected_unencoded", observed=False,
                       true_positive_rate=0.90, false_positive_rate=0.05,
                       description="Payload reflected without encoding"),
        EvidenceSignal(name="dom_execution_confirmed", observed=False,
                       true_positive_rate=0.98, false_positive_rate=0.01,
                       description="JavaScript actually executed in DOM"),
        EvidenceSignal(name="stored_in_page", observed=False,
                       true_positive_rate=0.95, false_positive_rate=0.02,
                       description="Payload persisted and rendered on page load"),
        EvidenceSignal(name="csp_blocks", observed=False,
                       true_positive_rate=0.20, false_positive_rate=0.60,
                       description="CSP header blocks inline scripts"),
    ],
    "ssrf": [
        EvidenceSignal(name="oob_callback", observed=False,
                       true_positive_rate=0.97, false_positive_rate=0.01,
                       description="Out-of-band callback received"),
        EvidenceSignal(name="internal_content", observed=False,
                       true_positive_rate=0.95, false_positive_rate=0.03,
                       description="Internal network content in response"),
        EvidenceSignal(name="metadata_access", observed=False,
                       true_positive_rate=0.99, false_positive_rate=0.01,
                       description="Cloud metadata endpoint accessible"),
        EvidenceSignal(name="response_difference", observed=False,
                       true_positive_rate=0.70, false_positive_rate=0.20,
                       description="Different response for internal vs external URL"),
    ],
    "rce": [
        EvidenceSignal(name="command_output", observed=False,
                       true_positive_rate=0.99, false_positive_rate=0.01,
                       description="Command output visible in response"),
        EvidenceSignal(name="oob_dns_callback", observed=False,
                       true_positive_rate=0.97, false_positive_rate=0.02,
                       description="DNS callback from target server"),
        EvidenceSignal(name="time_delay", observed=False,
                       true_positive_rate=0.85, false_positive_rate=0.08,
                       description="Consistent time delay with sleep command"),
    ],
    "default": [
        EvidenceSignal(name="multi_tool_agree", observed=False,
                       true_positive_rate=0.90, false_positive_rate=0.05,
                       description="Multiple tools agree on finding"),
        EvidenceSignal(name="manual_verify", observed=False,
                       true_positive_rate=0.95, false_positive_rate=0.02,
                       description="Manual verification confirms finding"),
        EvidenceSignal(name="response_anomaly", observed=False,
                       true_positive_rate=0.60, false_positive_rate=0.25,
                       description="Response differs from baseline"),
    ],
}


# ---------------------------------------------------------------------------
# Bayesian Filter
# ---------------------------------------------------------------------------

class BayesianFilter:
    """Bayesian probability engine for FP/TP classification."""

    def __init__(self, default_prior: float = 0.5) -> None:
        self.default_prior = default_prior
        self.signal_db = {k: [s.model_copy() for s in v] for k, v in DEFAULT_SIGNALS.items()}

    # ---- Main entry ------------------------------------------------------

    def evaluate(
        self,
        vuln_type: str,
        evidence: dict[str, bool],
        *,
        prior: float | None = None,
    ) -> BayesianResult:
        """Compute posterior P(TP | evidence) using Bayes' theorem.

        Args:
            vuln_type: Type of vulnerability (sqli, xss, ssrf, ...)
            evidence: dict mapping signal names → observed (True/False)
            prior: Prior probability of being a true positive
        """
        p_tp = prior if prior is not None else self.default_prior
        templates = self.signal_db.get(vuln_type, self.signal_db["default"])

        log_prior = math.log(p_tp / (1.0 - p_tp)) if 0.0 < p_tp < 1.0 else 0.0
        log_odds = log_prior
        details: list[dict[str, Any]] = []
        signals_used = 0

        for sig_template in templates:
            if sig_template.name not in evidence:
                continue

            sig = sig_template.model_copy()
            sig.observed = evidence[sig_template.name]
            signals_used += 1

            # Likelihood ratio
            if sig.observed:
                lr = sig.true_positive_rate / max(sig.false_positive_rate, 1e-10)
            else:
                lr = (1.0 - sig.true_positive_rate) / max(1.0 - sig.false_positive_rate, 1e-10)

            log_lr = math.log(max(lr, 1e-10)) * sig.weight
            log_odds += log_lr

            details.append({
                "signal": sig.name,
                "observed": sig.observed,
                "likelihood_ratio": round(lr, 4),
                "log_lr": round(log_lr, 4),
                "cumulative_log_odds": round(log_odds, 4),
                "description": sig.description,
            })

        # Convert log-odds back to probability
        posterior = 1.0 / (1.0 + math.exp(-log_odds))
        posterior = max(0.001, min(0.999, posterior))

        # Confidence mapped to 0-100
        confidence = posterior * 100.0

        # Verdict
        if posterior >= 0.8:
            verdict = "true_positive"
        elif posterior <= 0.2:
            verdict = "false_positive"
        else:
            verdict = "uncertain"

        result = BayesianResult(
            prior=round(p_tp, 4),
            posterior=round(posterior, 4),
            log_odds=round(log_odds, 4),
            signals_used=signals_used,
            verdict=verdict,
            confidence=round(confidence, 1),
            signal_details=details,
        )

        logger.debug(
            f"Bayesian filter [{vuln_type}]: prior={p_tp:.2f} → "
            f"posterior={posterior:.2f} ({verdict}), {signals_used} signals"
        )
        return result

    # ---- Batch evaluation ------------------------------------------------

    def evaluate_batch(
        self,
        findings: list[dict[str, Any]],
    ) -> list[BayesianResult]:
        """Evaluate a batch of findings."""
        results: list[BayesianResult] = []
        for f in findings:
            result = self.evaluate(
                vuln_type=f.get("vuln_type", "default"),
                evidence=f.get("evidence", {}),
                prior=f.get("prior"),
            )
            results.append(result)
        return results

    # ---- Signal management -----------------------------------------------

    def add_signal(self, vuln_type: str, signal: EvidenceSignal) -> None:
        """Register a new evidence signal for a vuln type."""
        self.signal_db.setdefault(vuln_type, []).append(signal)

    def get_signals(self, vuln_type: str) -> list[EvidenceSignal]:
        """Return available signals for a vuln type."""
        return self.signal_db.get(vuln_type, self.signal_db["default"])

    def update_signal_rates(
        self,
        vuln_type: str,
        signal_name: str,
        tp_rate: float | None = None,
        fp_rate: float | None = None,
    ) -> None:
        """Update signal rates from learning / feedback."""
        signals = self.signal_db.get(vuln_type, [])
        for sig in signals:
            if sig.name == signal_name:
                if tp_rate is not None:
                    sig.true_positive_rate = tp_rate
                if fp_rate is not None:
                    sig.false_positive_rate = fp_rate
                logger.info(
                    f"Updated signal {signal_name}/{vuln_type}: "
                    f"TP={sig.true_positive_rate}, FP={sig.false_positive_rate}"
                )
                return
