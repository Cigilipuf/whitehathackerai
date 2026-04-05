"""
WhiteHatHacker AI — Benchmark Lab Engine (v3.3 Phase 5)

Core engine for running vulnerability scanner benchmarks against
intentionally-vulnerable lab applications.  Computes TPR, FPR
(false discovery rate), precision, recall, F1 and generates
calibration recommendations.

Architecture
~~~~~~~~~~~~
    LabManager          — Docker container lifecycle, health checks
    BenchmarkEvaluator  — TP/FP/FN classification against manifests
    CalibrationEngine   — Threshold adjustment suggestions
    BenchmarkReporter   — Rich Markdown report generation

Usage (programmatic)::

    from src.analysis.benchmark_lab import BenchmarkEvaluator, load_manifests
    manifests = load_manifests()
    evaluator = BenchmarkEvaluator(manifests)
    result = evaluator.evaluate("dvwa", findings)
    print(f"TPR={result.tpr:.0%}, Precision={result.precision:.0%}")
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------

_MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "benchmark" / "manifests.json"
)


def load_manifests(path: Path | None = None) -> dict[str, Any]:
    """Load benchmark lab manifests from JSON file.

    Returns dict keyed by lab name (dvwa, juiceshop, …).
    Raises FileNotFoundError when manifest is missing.
    """
    p = path or _MANIFEST_PATH
    if not p.exists():
        raise FileNotFoundError(f"Benchmark manifest not found: {p}")
    with open(p) as fh:
        data = json.load(fh)
    # Strip metadata key
    data.pop("_meta", None)
    return data


# ---------------------------------------------------------------------------
# Vulnerability type normalisation  (comprehensive synonym map)
# ---------------------------------------------------------------------------

_VULN_SYNONYMS: dict[str, str] = {
    # SQL Injection
    "sqli": "sql_injection",
    "sql_injection": "sql_injection",
    "sql-injection": "sql_injection",
    "blind_sqli": "sql_injection",
    "blind_sql_injection": "sql_injection",
    "time_based_sqli": "sql_injection",
    "boolean_based_sqli": "sql_injection",
    "union_sqli": "sql_injection",
    "error_based_sqli": "sql_injection",
    "nosql_injection": "sql_injection",
    "nosqli": "sql_injection",
    # XSS
    "xss": "xss_reflected",
    "reflected_xss": "xss_reflected",
    "xss_reflected": "xss_reflected",
    "reflected-xss": "xss_reflected",
    "stored_xss": "xss_stored",
    "xss_stored": "xss_stored",
    "stored-xss": "xss_stored",
    "dom_xss": "xss_dom",
    "xss_dom": "xss_dom",
    "dom-xss": "xss_dom",
    "dom_based_xss": "xss_dom",
    # Command Injection
    "command_injection": "command_injection",
    "cmd_injection": "command_injection",
    "cmd-injection": "command_injection",
    "os_command_injection": "command_injection",
    "rce": "command_injection",
    "remote_code_execution": "command_injection",
    # LFI / Path Traversal
    "lfi": "lfi",
    "local_file_inclusion": "lfi",
    "file_inclusion": "lfi",
    "path_traversal": "path_traversal",
    "directory_traversal": "path_traversal",
    # CSRF
    "csrf": "csrf",
    "cross_site_request_forgery": "csrf",
    # File Upload
    "file_upload": "file_upload",
    "unrestricted_file_upload": "file_upload",
    "unrestricted_upload": "file_upload",
    # Information Disclosure
    "information_disclosure": "information_disclosure",
    "info_disclosure": "information_disclosure",
    "info_leak": "information_disclosure",
    "sensitive_data_exposure": "information_disclosure",
    "sensitive_information": "information_disclosure",
    "exposed_panel": "information_disclosure",
    "exposed_config": "information_disclosure",
    "debug_endpoint": "information_disclosure",
    "phpinfo": "information_disclosure",
    "server_status": "information_disclosure",
    "source_code_disclosure": "information_disclosure",
    "git_exposure": "information_disclosure",
    "env_file": "information_disclosure",
    # Authentication
    "broken_auth": "broken_auth",
    "broken_authentication": "broken_auth",
    "auth_bypass": "broken_auth",
    "authentication_bypass": "broken_auth",
    "jwt": "broken_auth",
    "jwt_vulnerability": "broken_auth",
    "weak_credentials": "broken_auth",
    # IDOR / BOLA
    "idor": "idor",
    "bola": "idor",
    "object_level_auth": "idor",
    "insecure_direct_object_reference": "idor",
    # Brute Force
    "brute_force": "brute_force",
    "brute-force": "brute_force",
    "rate_limit_bypass": "brute_force",
    # Security Misconfiguration
    "security_misconfiguration": "security_misconfiguration",
    "security_misconfig": "security_misconfiguration",
    "misconfiguration": "security_misconfiguration",
    # XXE
    "xxe": "xxe",
    "xml_external_entity": "xxe",
    # Deserialization
    "deserialization": "deserialization",
    "insecure_deserialization": "deserialization",
    # Mass Assignment
    "mass_assignment": "mass_assignment",
    # SSRF
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    # Excessive Data Exposure
    "excessive_data_exposure": "excessive_data_exposure",
    # Rate Limiting
    "rate_limiting": "rate_limiting",
    "no_rate_limit": "rate_limiting",
    "missing_rate_limit": "rate_limiting",
    # GraphQL
    "graphql_introspection": "graphql_introspection",
    "graphql_batch_query": "graphql_batch_query",
    "graphql_injection": "graphql_batch_query",
    # SSJS
    "server_side_js_injection": "server_side_js_injection",
    "ssjs": "server_side_js_injection",
    "ssjs_injection": "server_side_js_injection",
    # SSTI
    "ssti": "server_side_template_injection",
    "server_side_template_injection": "server_side_template_injection",
    # Noise categories  (for acceptable_noise matching)
    "missing_security_headers": "missing_security_headers",
    "missing_csp": "missing_csp",
    "missing_hsts": "missing_hsts",
    "missing_x_frame_options": "missing_x_frame_options",
    "missing_x_content_type_options": "missing_x_content_type_options",
    "cookie_no_httponly": "cookie_no_httponly",
    "cookie_no_secure": "cookie_no_secure",
    "cookie_no_samesite": "cookie_no_samesite",
    "server_version_disclosure": "server_version_disclosure",
    "directory_listing": "directory_listing",
    "http_only": "http_only",
    "weak_tls": "weak_tls",
    "no_tls": "no_tls",
    "cors_misconfiguration": "cors_misconfiguration",
    "default_credentials": "default_credentials",
    # Additional common tool output types
    "open_redirect": "open_redirect",
    "cors": "cors_misconfiguration",
    "crlf_injection": "crlf_injection",
    "http_smuggling": "http_smuggling",
    "subdomain_takeover": "subdomain_takeover",
    "prototype_pollution": "prototype_pollution",
    "cache_poisoning": "cache_poisoning",
    "websocket": "websocket_vulnerability",
}


def normalize_vuln_type(raw: str) -> str:
    """Normalise a raw vulnerability type string to canonical form."""
    key = raw.lower().strip().replace(" ", "_").replace("-", "_")
    return _VULN_SYNONYMS.get(key, key)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ClassifiedFinding:
    """A single finding annotated with its benchmark classification."""

    normalized_type: str
    classification: str  # "tp" | "fp" | "noise"
    matched_expected: str | None = None
    severity: str = ""
    confidence: float = 0.0
    endpoint: str = ""


@dataclass
class LabBenchmarkResult:
    """Benchmark metrics for a single lab."""

    lab: str
    url: str = ""
    duration_s: float = 0.0

    # Counts
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    noise_count: int = 0

    # Rates
    tpr: float = 0.0        # Recall = TP / (TP + FN)
    precision: float = 0.0  # TP / (TP + FP)
    fpr: float = 0.0        # False Discovery Rate = FP / (TP + FP)
    f1: float = 0.0         # Harmonic mean of precision & recall

    # Per-class breakdown
    per_class: dict[str, dict[str, Any]] = field(default_factory=dict)
    missed_classes: list[str] = field(default_factory=list)
    extra_types: list[str] = field(default_factory=list)

    # Classified findings (excluded from serialisation by default)
    classified: list[ClassifiedFinding] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Drop the heavy classified list for serialisation
        d.pop("classified", None)
        return d


@dataclass
class BenchmarkSuiteResult:
    """Aggregate benchmark across multiple labs."""

    results: list[LabBenchmarkResult] = field(default_factory=list)
    overall_tpr: float = 0.0
    overall_precision: float = 0.0
    overall_fpr: float = 0.0
    overall_f1: float = 0.0
    total_tp: int = 0
    total_fp: int = 0
    total_fn: int = 0
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "overall_tpr": self.overall_tpr,
            "overall_precision": self.overall_precision,
            "overall_fpr": self.overall_fpr,
            "overall_f1": self.overall_f1,
            "total_tp": self.total_tp,
            "total_fp": self.total_fp,
            "total_fn": self.total_fn,
            "labs": {r.lab: r.to_dict() for r in self.results},
        }


# ---------------------------------------------------------------------------
# BenchmarkEvaluator — TP/FP/FN classification
# ---------------------------------------------------------------------------

class BenchmarkEvaluator:
    """Evaluates scan findings against expected lab manifests.

    Classification logic:
        TP   — normalised type matches an ``expected_vulns`` class
        FP   — normalised type NOT in expected_vulns AND NOT in acceptable_noise
        Noise — normalised type in ``acceptable_noise`` (excluded from metrics)
        FN   — expected class with zero matching findings
    """

    def __init__(self, manifests: dict[str, Any] | None = None):
        self._manifests = manifests or load_manifests()

    @property
    def available_labs(self) -> list[str]:
        return list(self._manifests.keys())

    def evaluate(self, lab: str, findings: list[dict[str, Any]]) -> LabBenchmarkResult:
        """Classify *findings* against the manifest for *lab*."""
        manifest = self._manifests.get(lab)
        if not manifest:
            raise ValueError(f"No manifest for lab: {lab}")

        expected_vulns = manifest.get("expected_vulns", [])
        expected_classes = {v["class"] for v in expected_vulns}
        normalized_expected_classes = {normalize_vuln_type(c) for c in expected_classes}
        noise_classes = set(manifest.get("acceptable_noise", []))
        normalized_noise_classes = {normalize_vuln_type(c) for c in noise_classes}

        # Classify each finding
        classified: list[ClassifiedFinding] = []
        type_counts: dict[str, int] = {}

        for f in findings:
            raw_type = (
                f.get("vulnerability_type", "")
                or f.get("type", "")
                or f.get("vuln_type", "")
                or ""
            )
            norm_type = normalize_vuln_type(raw_type)
            type_counts[norm_type] = type_counts.get(norm_type, 0) + 1

            sev = str(f.get("severity", ""))
            conf = 0.0
            try:
                conf = float(f.get("confidence", 0) or f.get("confidence_score", 0) or 0)
            except (ValueError, TypeError):
                pass
            endpoint = str(f.get("endpoint", "") or f.get("url", "") or "")

            if norm_type in normalized_expected_classes:
                classified.append(ClassifiedFinding(
                    normalized_type=norm_type,
                    classification="tp",
                    matched_expected=norm_type,
                    severity=sev, confidence=conf, endpoint=endpoint,
                ))
            elif norm_type in normalized_noise_classes:
                classified.append(ClassifiedFinding(
                    normalized_type=norm_type,
                    classification="noise",
                    severity=sev, confidence=conf, endpoint=endpoint,
                ))
            else:
                classified.append(ClassifiedFinding(
                    normalized_type=norm_type,
                    classification="fp",
                    severity=sev, confidence=conf, endpoint=endpoint,
                ))

        tp = sum(1 for c in classified if c.classification == "tp")
        fp = sum(1 for c in classified if c.classification == "fp")
        noise = sum(1 for c in classified if c.classification == "noise")

        # FN = expected classes not detected
        detected_classes = {c.normalized_type for c in classified if c.classification == "tp"}
        missed = sorted(normalized_expected_classes - detected_classes)
        fn = len(missed)

        # Metrics
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        fdr = fp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = (2 * precision * tpr / (precision + tpr)) if (precision + tpr) > 0 else 0.0

        # Per-class detail
        per_class: dict[str, dict[str, Any]] = {}
        for vc in expected_vulns:
            cls = normalize_vuln_type(vc["class"])
            actual = type_counts.get(cls, 0)
            per_class[cls] = {
                "expected_min": vc.get("min_count", 1),
                "detected": actual,
                "found": actual > 0,
            }

        extra_types = sorted(
            t for t in type_counts
            if t not in normalized_expected_classes and t not in normalized_noise_classes and type_counts[t] > 0
        )

        return LabBenchmarkResult(
            lab=lab,
            url=manifest.get("url", ""),
            total_findings=len(findings),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            noise_count=noise,
            tpr=round(tpr, 4),
            precision=round(precision, 4),
            fpr=round(fdr, 4),
            f1=round(f1, 4),
            per_class=per_class,
            missed_classes=missed,
            extra_types=extra_types,
            classified=classified,
        )

    def evaluate_suite(
        self,
        lab_findings: dict[str, list[dict[str, Any]]],
    ) -> BenchmarkSuiteResult:
        """Evaluate multiple labs and compute aggregate metrics."""
        results: list[LabBenchmarkResult] = []
        for lab, findings in lab_findings.items():
            if lab in self._manifests:
                results.append(self.evaluate(lab, findings))

        total_tp = sum(r.true_positives for r in results)
        total_fp = sum(r.false_positives for r in results)
        total_fn = sum(r.false_negatives for r in results)

        overall_tpr = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        overall_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
        overall_fdr = total_fp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        overall_f1 = (
            (2 * overall_prec * overall_tpr / (overall_prec + overall_tpr))
            if (overall_prec + overall_tpr) > 0
            else 0.0
        )

        return BenchmarkSuiteResult(
            results=results,
            overall_tpr=round(overall_tpr, 4),
            overall_precision=round(overall_prec, 4),
            overall_fpr=round(overall_fdr, 4),
            overall_f1=round(overall_f1, 4),
            total_tp=total_tp,
            total_fp=total_fp,
            total_fn=total_fn,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        )


# ---------------------------------------------------------------------------
# LabManager — Docker lifecycle
# ---------------------------------------------------------------------------

class LabManager:
    """Manages Docker lab container lifecycle and health checking."""

    def __init__(self, manifests: dict[str, Any] | None = None):
        self._manifests = manifests or load_manifests()

    async def check_health(self, lab: str, timeout: float = 10.0) -> bool:
        """Check if a single lab container is reachable and ready."""
        manifest = self._manifests.get(lab)
        if not manifest:
            return False

        url = manifest["url"]
        health_ep = manifest.get("health_endpoint", "/")
        check_url = f"{url.rstrip('/')}{health_ep}"
        ok_statuses = set(manifest.get("health_status", [200]))

        try:
            import httpx  # deferred import — optional dependency for tests

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(timeout),
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(check_url)
                return resp.status_code in ok_statuses or resp.status_code < 500
        except Exception:
            return False

    async def check_all_health(
        self, labs: list[str] | None = None,
    ) -> dict[str, bool]:
        """Check health of multiple labs concurrently."""
        import asyncio as _aio
        target_labs = labs or list(self._manifests.keys())
        coros = [self.check_health(lab) for lab in target_labs]
        gathered = await _aio.gather(*coros, return_exceptions=True)
        return {
            lab: (r is True)
            for lab, r in zip(target_labs, gathered)
        }

    def start_labs(self, labs: list[str] | None = None) -> bool:
        """Start Docker lab containers via ``docker compose``."""
        compose_path = (
            Path(__file__).resolve().parent.parent.parent
            / "docker"
            / "benchmark-lab.yaml"
        )
        if not compose_path.exists():
            logger.error(f"Docker compose file not found: {compose_path}")
            return False

        cmd = ["docker", "compose", "-f", str(compose_path), "up", "-d"]
        if labs:
            for lab in labs:
                svc = self._manifests.get(lab, {}).get("docker_service", lab)
                cmd.append(svc)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                logger.info(f"Lab containers started: {labs or 'all'}")
                return True
            logger.error(f"docker compose failed: {result.stderr[:500]}")
            return False
        except Exception as exc:
            logger.error(f"Failed to start labs: {exc}")
            return False

    def stop_labs(self) -> bool:
        """Stop all Docker lab containers."""
        compose_path = (
            Path(__file__).resolve().parent.parent.parent
            / "docker"
            / "benchmark-lab.yaml"
        )
        try:
            result = subprocess.run(
                ["docker", "compose", "-f", str(compose_path), "down"],
                capture_output=True, text=True, timeout=60,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def wait_for_ready(
        self,
        labs: list[str],
        max_wait: int = 120,
        poll_interval: float = 5.0,
    ) -> dict[str, bool]:
        """Poll until every *lab* responds healthy or *max_wait* elapses."""
        start = time.monotonic()
        ready: dict[str, bool] = {lab: False for lab in labs}

        while time.monotonic() - start < max_wait:
            for lab in labs:
                if not ready[lab]:
                    ready[lab] = await self.check_health(lab)
            if all(ready.values()):
                return ready
            await asyncio.sleep(poll_interval)

        return ready


# ---------------------------------------------------------------------------
# BenchmarkScanner — scan invocation
# ---------------------------------------------------------------------------

class BenchmarkScanner:
    """Invokes the WHAI scanner against benchmark lab targets."""

    def __init__(
        self,
        profile: str = "aggressive",
        no_brain: bool = True,
        extra_args: list[str] | None = None,
    ):
        self._profile = profile
        self._no_brain = no_brain
        self._extra_args = extra_args or []

    async def scan_lab(
        self,
        lab: str,
        url: str,
        output_dir: Path,
        timeout: int = 1800,
    ) -> Path | None:
        """Run a scan against *url* and return the findings JSON path."""
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable, "-m", "src.cli", "scan", url,
            "--profile", self._profile,
            "--mode", "autonomous",
            "--output", str(output_dir),
        ]
        if self._no_brain:
            cmd.append("--no-brain")
        cmd.extend(self._extra_args)

        logger.info(f"Scanning {lab} at {url} (timeout={timeout}s)")
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning(f"Scan timeout for {lab} after {timeout}s")

            elapsed = time.monotonic() - start
            logger.info(f"Scan of {lab} finished in {elapsed:.0f}s")

            # Search for findings JSON in output directory
            for candidate in [
                output_dir / "findings.json",
                output_dir / f"{lab}_findings.json",
            ]:
                if candidate.exists():
                    return candidate

            # Recursive search as fallback
            for p in sorted(output_dir.rglob("findings.json")):
                return p

            logger.warning(f"No findings file found for {lab} in {output_dir}")
            return None

        except Exception as exc:
            logger.error(f"Scan invocation failed for {lab}: {exc}")
            return None


# ---------------------------------------------------------------------------
# CalibrationEngine
# ---------------------------------------------------------------------------

@dataclass
class CalibrationRecommendation:
    """A single calibration recommendation."""

    current_threshold: float
    suggested_threshold: float
    reason: str
    overall_tpr: float
    overall_fpr: float
    overall_f1: float
    target_met: bool  # TPR ≥ 0.80 AND FPR ≤ 0.20


class CalibrationEngine:
    """Analyses benchmark results and suggests FP threshold adjustments."""

    TPR_TARGET = 0.80
    FPR_TARGET = 0.20

    def recommend(
        self,
        suite: BenchmarkSuiteResult,
        current_threshold: float = 65.0,
    ) -> CalibrationRecommendation:
        """Suggest a threshold adjustment based on *suite* metrics."""
        tpr = suite.overall_tpr
        fpr = suite.overall_fpr

        target_met = tpr >= self.TPR_TARGET and fpr <= self.FPR_TARGET

        if target_met:
            return CalibrationRecommendation(
                current_threshold=current_threshold,
                suggested_threshold=current_threshold,
                reason=(
                    f"Targets met (TPR={tpr:.0%} ≥ {self.TPR_TARGET:.0%}, "
                    f"FPR={fpr:.0%} ≤ {self.FPR_TARGET:.0%}). "
                    "Keep current threshold."
                ),
                overall_tpr=tpr,
                overall_fpr=fpr,
                overall_f1=suite.overall_f1,
                target_met=True,
            )

        if fpr > 0.30 and tpr < 0.70:
            suggested = min(current_threshold + 5, 80.0)
            reason = (
                f"Both TPR ({tpr:.0%}) and FPR ({fpr:.0%}) far from target. "
                f"Raise threshold to {suggested:.0f} AND improve detection logic."
            )
        elif fpr > self.FPR_TARGET:
            suggested = min(current_threshold + 5, 80.0)
            reason = (
                f"FPR too high ({fpr:.0%} > {self.FPR_TARGET:.0%}). "
                f"Raise FP threshold from {current_threshold:.0f} to {suggested:.0f}."
            )
        elif tpr < self.TPR_TARGET:
            suggested = max(current_threshold - 5, 50.0)
            reason = (
                f"TPR below target ({tpr:.0%} < {self.TPR_TARGET:.0%}). "
                f"Lower threshold from {current_threshold:.0f} to {suggested:.0f} "
                "to catch more vulns, or add more detection checks."
            )
        else:
            suggested = current_threshold
            reason = "Close to targets — fine-tune individual tool confidence."

        return CalibrationRecommendation(
            current_threshold=current_threshold,
            suggested_threshold=suggested,
            reason=reason,
            overall_tpr=tpr,
            overall_fpr=fpr,
            overall_f1=suite.overall_f1,
            target_met=False,
        )


# ---------------------------------------------------------------------------
# BenchmarkReporter — Markdown report
# ---------------------------------------------------------------------------

class BenchmarkReporter:
    """Generates rich Markdown benchmark reports."""

    def generate(self, suite: BenchmarkSuiteResult) -> str:
        """Generate a comprehensive Markdown report from *suite*."""
        lines: list[str] = [
            "# WhiteHatHacker AI — Benchmark Report",
            f"**Generated:** {suite.timestamp or time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Overall Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| **TPR (Recall)** | {suite.overall_tpr:.1%} |",
            f"| **Precision** | {suite.overall_precision:.1%} |",
            f"| **FPR (FDR)** | {suite.overall_fpr:.1%} |",
            f"| **F1 Score** | {suite.overall_f1:.3f} |",
            f"| True Positives | {suite.total_tp} |",
            f"| False Positives | {suite.total_fp} |",
            f"| False Negatives | {suite.total_fn} |",
            f"| Labs Tested | {len(suite.results)} |",
            "",
            "### Target Assessment",
            "",
        ]

        tpr_ok = suite.overall_tpr >= CalibrationEngine.TPR_TARGET
        fpr_ok = suite.overall_fpr <= CalibrationEngine.FPR_TARGET
        lines.append(
            f"- TPR ≥ {CalibrationEngine.TPR_TARGET:.0%}: "
            f"{'✅ PASS' if tpr_ok else '❌ FAIL'} ({suite.overall_tpr:.1%})"
        )
        lines.append(
            f"- FPR ≤ {CalibrationEngine.FPR_TARGET:.0%}: "
            f"{'✅ PASS' if fpr_ok else '❌ FAIL'} ({suite.overall_fpr:.1%})"
        )

        # Per-lab summary table
        lines.extend([
            "",
            "## Per-Lab Summary",
            "",
            "| Lab | TPR | Precision | FPR | F1 | TP | FP | FN | Noise | Total |",
            "|-----|-----|-----------|-----|----|----|----|----|-------|-------|",
        ])

        for r in suite.results:
            lines.append(
                f"| {r.lab} | {r.tpr:.0%} | {r.precision:.0%} | {r.fpr:.0%} "
                f"| {r.f1:.2f} | {r.true_positives} | {r.false_positives} "
                f"| {r.false_negatives} | {r.noise_count} | {r.total_findings} |"
            )

        # Per-lab detail
        for r in suite.results:
            lines.extend([
                "",
                f"## {r.lab.upper()} — {r.url}",
                "",
                f"TPR={r.tpr:.0%} | Precision={r.precision:.0%} | "
                f"FPR={r.fpr:.0%} | F1={r.f1:.2f}",
                "",
            ])

            if r.missed_classes:
                lines.append(f"**Missed vulnerabilities:** {', '.join(r.missed_classes)}")
            if r.extra_types:
                lines.append(f"**False positive types:** {', '.join(r.extra_types)}")

            lines.extend([
                "",
                "| Vuln Class | Expected | Detected | Status |",
                "|------------|----------|----------|--------|",
            ])
            for cls, info in sorted(r.per_class.items()):
                status = "✅" if info["found"] else "❌"
                lines.append(
                    f"| {cls} | ≥{info['expected_min']} | {info['detected']} | {status} |"
                )

        return "\n".join(lines)

    def save(
        self,
        suite: BenchmarkSuiteResult,
        output_dir: Path | None = None,
    ) -> Path:
        """Save report to Markdown and JSON files.  Returns the .md path."""
        out = output_dir or Path("output/reports")
        out.mkdir(parents=True, exist_ok=True)

        md_path = out / "benchmark_report.md"
        md_path.write_text(self.generate(suite), encoding="utf-8")

        json_path = out / "benchmark_report.json"
        json_path.write_text(
            json.dumps(suite.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        logger.info(f"Benchmark report saved: {md_path}")
        return md_path


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def load_findings(path: Path) -> list[dict[str, Any]]:
    """Load a findings JSON file (list of dicts)."""
    with open(path) as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    return [data]
