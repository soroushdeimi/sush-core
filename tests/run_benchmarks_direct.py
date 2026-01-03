#!/usr/bin/env python3
"""Run benchmarks with direct file output."""

import asyncio
import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.run_benchmarks import BenchmarkRunner

OUTPUT_FILE = Path("tests/data/benchmark_results.csv")
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

LOG_FILE = Path("tests/data/benchmark_run.log")


def log(msg):
    """Log to both console and file."""
    print(msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")


async def main():
    log("=" * 60)
    log("sushCore Comprehensive Benchmark Suite")
    log("=" * 60)
    log(f"Results will be saved to: {OUTPUT_FILE}")
    log("=" * 60)

    runner = BenchmarkRunner()

    try:
        log("\nStarting Experiment A: Crypto Overhead Analysis...")
        await runner.experiment_a_crypto_overhead()
        log(f"Experiment A completed. {len(runner.results)} results collected.")

        log("\nStarting Experiment B: End-to-End Throughput...")
        await runner.experiment_b_end_to_end_throughput()
        log(f"Experiment B completed. {len(runner.results)} total results.")

        log("\nStarting Experiment C: Adaptive Response Time...")
        await runner.experiment_c_adaptive_response_time()
        log(f"Experiment C completed. {len(runner.results)} total results.")

        log("\nSaving results...")
        runner.save_results()
        log(f"✓ Saved {len(runner.results)} results to {OUTPUT_FILE}")

        log("\n" + "=" * 60)
        log("All benchmarks completed successfully!")
        log("=" * 60)

        return True

    except Exception as e:
        log(f"✗ Benchmark failed: {e}")
        import traceback

        traceback.print_exc()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            traceback.print_exc(file=f)
        return False


if __name__ == "__main__":
    # Clear log file
    if LOG_FILE.exists():
        LOG_FILE.unlink()

    success = asyncio.run(main())
    sys.exit(0 if success else 1)
