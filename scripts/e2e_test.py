#!/usr/bin/env python3
"""End-to-end test: Tam pipeline testi (scanme.nmap.org)."""

import asyncio
import os
import sys

# Proje kökünü PATH'e ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Test için autonomous mod
os.environ["WHAI_MODE"] = "autonomous"

from dotenv import load_dotenv
load_dotenv()

from src.main import load_config, initialize_app


async def e2e_test():
    # 1. Load config
    config = load_config()

    # Override mode for test
    config["mode"] = "autonomous"

    # 2. Initialize all components
    print("[1/5] Initializing components...")
    components = await initialize_app(config)

    print(f"     Brain: {components['brain_engine']}")
    print(f"     Tools: {components['tool_registry'].count}")
    print(f"     Orchestrator: {components['orchestrator']}")

    # 3. Initialize brain
    brain = components["brain_engine"]
    print("[2/5] Initializing brain engine...")
    try:
        await brain.initialize()
        print(f"     Brain initialized: primary={brain.has_primary}, secondary={brain.has_secondary}")
    except Exception as e:
        print(f"     Brain init warning: {e}")

    # 4. Run the orchestrator
    orchestrator = components["orchestrator"]

    print("[3/5] Starting full scan pipeline against scanme.nmap.org...")
    print("=" * 60)

    state = await orchestrator.run(
        target="scanme.nmap.org",
        scope=None,
    )

    print("=" * 60)
    print("[4/5] Pipeline complete!")
    print(f"     Session: {state.session_id}")
    print(f"     Duration: {state.elapsed_time:.1f}s")
    print(f"     Stages completed: {len(state.completed_stages)}/10")

    # Print stage results
    print()
    print("[5/5] Stage Results:")
    for stage_name, result in state.stage_results.items():
        if result.skipped:
            status = "SKIP"
        elif result.success:
            status = " OK "
        else:
            status = "FAIL"
        reason = f" ({result.skip_reason})" if result.skipped else ""
        errors = f" | errors={result.errors}" if result.errors else ""
        print(
            f"     [{status}] {stage_name} | "
            f"{result.duration:.1f}s | "
            f"findings={result.findings_count}{reason}{errors}"
        )

    print()
    print(f"     Subdomains: {len(state.subdomains)}")
    print(f"     Live hosts: {len(state.live_hosts)}")
    print(f"     Endpoints:  {len(state.endpoints)}")
    print(f"     Raw findings: {len(state.raw_findings)}")
    print(f"     Verified:   {len(state.verified_findings)}")
    print(f"     FP:         {len(state.false_positives)}")
    print(f"     Reports:    {len(state.reports_generated)}")

    # Cleanup
    await brain.shutdown()
    print()
    print("[DONE] End-to-end test completed successfully!")


if __name__ == "__main__":
    asyncio.run(e2e_test())
