#!/usr/bin/env python3
"""Test Session Resumption impact on benchmark performance."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np

from sush.core.quantum_obfuscator import QuantumObfuscator

OUTPUT_FILE = Path("tests/data/resumption_test_results.txt")


def log(msg):
    """Log to file and console."""
    print(msg)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(f"{msg}\n")


async def test_with_resumption():
    """Test with Session Resumption enabled."""
    log("\n" + "=" * 60)
    log("TEST: With Session Resumption")
    log("=" * 60)

    obfuscator = QuantumObfuscator(enable_session_resumption=True)
    peer_pub, _ = obfuscator.kem.generate_keypair()

    handshake_times = []
    obfuscate_times = []
    total_times = []

    payload = b"x" * 1024  # 1KB
    iterations = 50

    for i in range(iterations):
        session_id = f"test_{i}_{int(time.time())}"

        # Measure handshake time
        start = time.perf_counter()
        await obfuscator.initialize_session(session_id, peer_pub)
        handshake_time = time.perf_counter() - start
        handshake_times.append(handshake_time)

        # Measure obfuscation
        start = time.perf_counter()
        await obfuscator.obfuscate_data(session_id, payload)
        obfuscate_time = time.perf_counter() - start
        obfuscate_times.append(obfuscate_time)

        total_times.append(handshake_time + obfuscate_time)

        if (i + 1) % 10 == 0:
            log(f"  Iteration {i + 1}/{iterations}")

    # Statistics
    first_handshake = handshake_times[0]
    avg_resumed_handshake = np.mean(handshake_times[1:]) if len(handshake_times) > 1 else 0
    speedup = first_handshake / avg_resumed_handshake if avg_resumed_handshake > 0 else 0

    log("\nResults:")
    log(f"  First handshake:     {first_handshake * 1000:.3f}ms")
    log(f"  Avg resumed:        {avg_resumed_handshake * 1000:.3f}ms")
    log(f"  Speedup:             {speedup:.1f}x")
    log(f"  Total handshake overhead: {sum(handshake_times) * 1000:.3f}ms")

    if obfuscator.session_cache:
        stats = obfuscator.session_cache.get_stats()
        log(f"  Cache resumptions:   {stats['total_resumptions']}")

    return {
        "first_handshake_ms": first_handshake * 1000,
        "avg_resumed_ms": avg_resumed_handshake * 1000,
        "speedup": speedup,
        "total_overhead_ms": sum(handshake_times) * 1000,
    }


async def test_without_resumption():
    """Test without Session Resumption."""
    log("\n" + "=" * 60)
    log("TEST: Without Session Resumption")
    log("=" * 60)

    obfuscator = QuantumObfuscator(enable_session_resumption=False)
    peer_pub, _ = obfuscator.kem.generate_keypair()

    handshake_times = []
    obfuscate_times = []
    total_times = []

    payload = b"x" * 1024  # 1KB
    iterations = 50

    for i in range(iterations):
        session_id = f"test_{i}_{int(time.time())}"

        # Measure handshake time
        start = time.perf_counter()
        await obfuscator.initialize_session(session_id, peer_pub)
        handshake_time = time.perf_counter() - start
        handshake_times.append(handshake_time)

        # Measure obfuscation
        start = time.perf_counter()
        await obfuscator.obfuscate_data(session_id, payload)
        obfuscate_time = time.perf_counter() - start
        obfuscate_times.append(obfuscate_time)

        total_times.append(handshake_time + obfuscate_time)

        if (i + 1) % 10 == 0:
            log(f"  Iteration {i + 1}/{iterations}")

    # Statistics
    avg_handshake = np.mean(handshake_times)

    log("\nResults:")
    log(f"  Avg handshake:       {avg_handshake * 1000:.3f}ms")
    log(f"  Total handshake overhead: {sum(handshake_times) * 1000:.3f}ms")

    return {
        "avg_handshake_ms": avg_handshake * 1000,
        "total_overhead_ms": sum(handshake_times) * 1000,
    }


async def main():
    """Run comparison test."""
    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    log("=" * 60)
    log("Session Resumption Impact Test")
    log("=" * 60)

    # Test with resumption
    with_results = await test_with_resumption()

    # Test without resumption
    without_results = await test_without_resumption()

    # Comparison
    log("\n" + "=" * 60)
    log("COMPARISON")
    log("=" * 60)
    log("Total handshake overhead:")
    log(f"  With resumption:    {with_results['total_overhead_ms']:.3f}ms")
    log(f"  Without resumption: {without_results['total_overhead_ms']:.3f}ms")

    if without_results["total_overhead_ms"] > 0:
        savings = without_results["total_overhead_ms"] - with_results["total_overhead_ms"]
        savings_percent = (savings / without_results["total_overhead_ms"]) * 100
        log(f"  Time saved:         {savings:.3f}ms ({savings_percent:.1f}%)")

    log(f"\nSpeedup: {with_results['speedup']:.1f}x for resumed sessions")
    log("=" * 60)

    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
