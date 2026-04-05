"""
WhiteHatHacker AI — Benchmark Runner (v3.3 Phase 5)

Thin CLI wrapper around the core ``src.analysis.benchmark_lab`` engine.
Evaluates scan findings against expected vulnerability manifests and
computes TPR, FPR (false discovery rate), precision, recall, F1.

Usage:
    # Evaluate existing findings JSON
    python3 scripts/benchmark_runner.py --lab dvwa --findings output/scans/dvwa/findings.json

    # Evaluate all labs from a directory
    python3 scripts/benchmark_runner.py --lab all --findings-dir output/scans

    # Run scan then evaluate (requires Docker labs running)
    python3 scripts/benchmark_runner.py --lab dvwa --scan

    # Start Docker labs, scan, evaluate, report, stop
    python3 scripts/benchmark_runner.py --lab all --start-labs --scan --report --stop-labs

    # Calibration recommendation
    python3 scripts/benchmark_runner.py --lab all --findings-dir output/scans --calibrate
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Allow running from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.analysis.benchmark_lab import (  # noqa: E402
    BenchmarkEvaluator,
    BenchmarkReporter,
    BenchmarkScanner,
    BenchmarkSuiteResult,
    CalibrationEngine,
    LabManager,
    load_findings,
    load_manifests,
)


def _find_findings(lab: str, findings_dir: Path) -> Path | None:
    """Locate a findings JSON file for *lab* in *findings_dir*."""
    candidates = [
        findings_dir / f"{lab}_findings.json",
        findings_dir / lab / "findings.json",
        findings_dir / f"{lab}.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    # Recursive fallback — pick the first findings.json under a dir named like the lab
    for p in sorted(findings_dir.rglob("findings.json")):
        if lab in str(p):
            return p
    return None


async def _async_main(args: argparse.Namespace) -> int:
    manifests = load_manifests()
    evaluator = BenchmarkEvaluator(manifests)
    lab_manager = LabManager(manifests)
    reporter = BenchmarkReporter()

    labs = evaluator.available_labs if args.lab == "all" else [args.lab]

    # Validate lab names
    for lab in labs:
        if lab not in manifests:
            print(f"ERROR: Unknown lab '{lab}'. Available: {evaluator.available_labs}")
            return 1

    # ── Optionally start Docker labs ──
    if args.start_labs:
        print("Starting Docker lab containers…")
        if not lab_manager.start_labs(labs):
            print("ERROR: Failed to start Docker labs")
            return 1
        print("Waiting for labs to become ready…")
        ready = await lab_manager.wait_for_ready(labs, max_wait=120)
        not_ready = [l for l, ok in ready.items() if not ok]
        if not_ready:
            print(f"WARNING: Labs not ready after 120s: {not_ready}")

    # ── Check health ──
    if args.health:
        health = await lab_manager.check_all_health(labs)
        for lab, ok in health.items():
            status = "✅ UP" if ok else "❌ DOWN"
            print(f"  {lab}: {status}")
        if not all(health.values()):
            return 1
        return 0

    # ── Collect findings per lab ──
    lab_findings: dict[str, list[dict]] = {}
    scanner = BenchmarkScanner(
        profile=args.profile,
        no_brain=args.no_brain,
    )

    for lab in labs:
        # Option A: explicit findings file
        if args.findings:
            fpath = Path(args.findings)
            if fpath.exists():
                lab_findings[lab] = load_findings(fpath)
                continue

        # Option B: search findings-dir
        if args.findings_dir:
            fpath = _find_findings(lab, Path(args.findings_dir))
            if fpath:
                lab_findings[lab] = load_findings(fpath)
                continue

        # Option C: run scan
        if args.scan:
            out_dir = Path(args.output) / lab
            findings_path = await scanner.scan_lab(
                lab,
                manifests[lab]["url"],
                out_dir,
                timeout=args.scan_timeout,
            )
            if findings_path:
                lab_findings[lab] = load_findings(findings_path)
                continue
            print(f"WARNING: Scan produced no findings for {lab}")
            continue

        print(f"WARNING: No findings available for {lab} (use --findings, --findings-dir, or --scan)")

    if not lab_findings:
        print("ERROR: No findings to evaluate")
        return 1

    # ── Evaluate ──
    suite = evaluator.evaluate_suite(lab_findings)

    # Print summary
    print(f"\n{'='*60}")
    print(f"  WhiteHatHacker AI — Benchmark Results")
    print(f"{'='*60}")
    print(f"  Overall TPR  : {suite.overall_tpr:.1%}")
    print(f"  Overall Prec : {suite.overall_precision:.1%}")
    print(f"  Overall FPR  : {suite.overall_fpr:.1%}")
    print(f"  Overall F1   : {suite.overall_f1:.3f}")
    print(f"  TP={suite.total_tp}  FP={suite.total_fp}  FN={suite.total_fn}")
    print()

    for r in suite.results:
        missed = f"  MISSED: {', '.join(r.missed_classes)}" if r.missed_classes else ""
        print(
            f"  {r.lab:12s}  TPR={r.tpr:.0%}  Prec={r.precision:.0%}  "
            f"FPR={r.fpr:.0%}  F1={r.f1:.2f}  "
            f"(TP={r.true_positives} FP={r.false_positives} FN={r.false_negatives})"
            f"{missed}"
        )

    # ── Calibration ──
    if args.calibrate:
        cal = CalibrationEngine()
        rec = cal.recommend(suite, current_threshold=args.threshold)
        print(f"\n  Calibration: {rec.reason}")
        if rec.suggested_threshold != rec.current_threshold:
            print(f"  → Suggested threshold: {rec.suggested_threshold:.0f}")

    # ── Report ──
    if args.report:
        out = Path(args.output) / "reports"
        md_path = reporter.save(suite, out)
        print(f"\n  Report saved: {md_path}")

    # ── Optionally stop Docker labs ──
    if args.stop_labs:
        print("\nStopping Docker labs…")
        lab_manager.stop_labs()

    # Exit code: error if TPR below 50% or FPR above 50%
    if suite.overall_tpr < 0.5:
        print(f"\n⚠  Overall TPR below 50% ({suite.overall_tpr:.0%})")
        return 1
    if suite.overall_fpr > 0.5:
        print(f"\n⚠  Overall FPR above 50% ({suite.overall_fpr:.0%})")
        return 1

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WhiteHatHacker AI — Benchmark Runner (v3.3)",
    )
    parser.add_argument(
        "--lab", required=True,
        help="Lab to benchmark: dvwa|juiceshop|webgoat|vampi|crapi|dvga|nodegoat|all",
    )
    parser.add_argument(
        "--findings",
        help="Path to a single findings JSON file (for one lab)",
    )
    parser.add_argument(
        "--findings-dir", default="output/scans",
        help="Directory to search for findings JSON files (default: output/scans)",
    )
    parser.add_argument(
        "--scan", action="store_true",
        help="Run WHAI scan against the lab (requires Docker lab running)",
    )
    parser.add_argument(
        "--scan-timeout", type=int, default=1800,
        help="Per-lab scan timeout in seconds (default: 1800)",
    )
    parser.add_argument(
        "--profile", default="aggressive",
        help="Scan profile: stealth|balanced|aggressive (default: aggressive)",
    )
    parser.add_argument(
        "--no-brain", action="store_true", default=True,
        help="Run without brain LLM (default: True for benchmark)",
    )
    parser.add_argument(
        "--start-labs", action="store_true",
        help="Start Docker lab containers before scanning",
    )
    parser.add_argument(
        "--stop-labs", action="store_true",
        help="Stop Docker lab containers after evaluation",
    )
    parser.add_argument(
        "--health", action="store_true",
        help="Only check lab container health and exit",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Generate Markdown + JSON benchmark report",
    )
    parser.add_argument(
        "--calibrate", action="store_true",
        help="Show FP threshold calibration recommendation",
    )
    parser.add_argument(
        "--threshold", type=float, default=65.0,
        help="Current FP confidence threshold for calibration (default: 65)",
    )
    parser.add_argument(
        "--output", default="output",
        help="Output base directory (default: output)",
    )
    args = parser.parse_args()

    rc = asyncio.run(_async_main(args))
    sys.exit(rc)


if __name__ == "__main__":
    main()
