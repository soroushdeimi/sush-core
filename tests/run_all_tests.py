#!/usr/bin/env python3
"""Run all tests and benchmarks with Session Resumption."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sush.core.quantum_obfuscator import QuantumObfuscator
from tests.run_benchmarks import BenchmarkRunner

OUTPUT_FILE = Path("tests/data/test_results.txt")


def log(msg):
    """Log to both console and file."""
    print(msg)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")


async def test_session_resumption():
    """Test Session Resumption performance."""
    log("\n" + "=" * 60)
    log("TEST 1: Session Resumption Performance")
    log("=" * 60)

    obfuscator = QuantumObfuscator(enable_session_resumption=True)
    peer_pub, peer_priv = obfuscator.kem.generate_keypair()

    # First session (full handshake)
    start = time.perf_counter()
    session1 = await obfuscator.initialize_session("test_session_1", peer_pub)
    time_full = time.perf_counter() - start
    log(f"First session (full handshake): {time_full*1000:.3f}ms")

    # Second session (should resume)
    start = time.perf_counter()
    session2 = await obfuscator.initialize_session("test_session_2", peer_pub)
    time_resumed = time.perf_counter() - start
    log(f"Second session (resumed):       {time_resumed*1000:.3f}ms")

    if time_resumed > 0:
        speedup = time_full / time_resumed
        improvement = ((time_full - time_resumed) / time_full) * 100
        log(f"Speedup: {speedup:.1f}x")
        log(f"Improvement: {improvement:.1f}%")

    # Stats
    if obfuscator.session_cache:
        stats = obfuscator.session_cache.get_stats()
        log(f"\nCache Stats:")
        log(f"  Cached sessions: {stats['cached_sessions']}")
        log(f"  Total resumptions: {stats['total_resumptions']}")

    return {
        "full_handshake_ms": time_full * 1000,
        "resumed_ms": time_resumed * 1000,
        "speedup": speedup if time_resumed > 0 else 0,
    }


async def run_benchmarks():
    """Run full benchmark suite."""
    log("\n" + "=" * 60)
    log("TEST 2: Full Benchmark Suite")
    log("=" * 60)

    runner = BenchmarkRunner()

    try:
        log("Running Experiment A: Crypto Overhead...")
        await runner.experiment_a_crypto_overhead()
        log(f"✓ Experiment A completed: {len([r for r in runner.results if r.get('experiment') == 'A'])} results")

        log("\nRunning Experiment B: End-to-End Throughput...")
        await runner.experiment_b_end_to_end_throughput()
        log(f"✓ Experiment B completed: {len([r for r in runner.results if r.get('experiment') == 'B'])} results")

        log("\nRunning Experiment C: Adaptive Response...")
        await runner.experiment_c_adaptive_response_time()
        log(f"✓ Experiment C completed: {len([r for r in runner.results if r.get('experiment') == 'C'])} results")

        log("\nSaving results...")
        runner.save_results()
        log(f"✓ Saved {len(runner.results)} total results")

        return True
    except Exception as e:
        log(f"✗ Benchmark failed: {e}")
        import traceback
        log(traceback.format_exc())
        return False


async def main():
    """Run all tests."""
    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    log("=" * 60)
    log("sushCore Comprehensive Test Suite")
    log("With Session Resumption Enabled")
    log("=" * 60)

    # Test 1: Session Resumption
    resumption_results = await test_session_resumption()

    # Test 2: Full Benchmarks
    benchmark_success = await run_benchmarks()

    # Summary
    log("\n" + "=" * 60)
    log("TEST SUMMARY")
    log("=" * 60)
    log(f"Session Resumption:")
    log(f"  Full handshake: {resumption_results['full_handshake_ms']:.3f}ms")
    log(f"  Resumed:        {resumption_results['resumed_ms']:.3f}ms")
    log(f"  Speedup:        {resumption_results['speedup']:.1f}x")
    log(f"\nBenchmarks: {'✓ PASSED' if benchmark_success else '✗ FAILED'}")
    log("=" * 60)

    print(f"\nResults saved to: {OUTPUT_FILE}")
    return benchmark_success


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

