#!/usr/bin/env python3
"""Test Session Resumption performance improvement."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sush.core.quantum_obfuscator import QuantumObfuscator


async def test_resumption_performance():
    """Test performance difference between full handshake and resumption."""
    print("=" * 60)
    print("Session Resumption Performance Test")
    print("=" * 60)

    # Test with resumption enabled
    obfuscator_enabled = QuantumObfuscator(enable_session_resumption=True)
    peer_pub, peer_priv = obfuscator_enabled.kem.generate_keypair()

    print("\n1. Testing WITH Session Resumption:")
    print("-" * 60)

    # First session (full handshake)
    start = time.perf_counter()
    session1 = await obfuscator_enabled.initialize_session("session1", peer_pub)
    time_full = time.perf_counter() - start
    print(f"   First session (full handshake): {time_full*1000:.3f}ms")

    # Second session (should resume)
    start = time.perf_counter()
    session2 = await obfuscator_enabled.initialize_session("session2", peer_pub)
    time_resumed = time.perf_counter() - start
    print(f"   Second session (resumed):       {time_resumed*1000:.3f}ms")

    improvement = ((time_full - time_resumed) / time_full) * 100
    speedup = time_full / time_resumed if time_resumed > 0 else 0
    print(f"   Improvement: {improvement:.1f}% ({speedup:.1f}x faster)")

    # Test with resumption disabled
    obfuscator_disabled = QuantumObfuscator(enable_session_resumption=False)

    print("\n2. Testing WITHOUT Session Resumption:")
    print("-" * 60)

    # First session
    start = time.perf_counter()
    session3 = await obfuscator_disabled.initialize_session("session3", peer_pub)
    time_no_resume_1 = time.perf_counter() - start
    print(f"   First session:  {time_no_resume_1*1000:.3f}ms")

    # Second session (also full handshake)
    start = time.perf_counter()
    session4 = await obfuscator_disabled.initialize_session("session4", peer_pub)
    time_no_resume_2 = time.perf_counter() - start
    print(f"   Second session: {time_no_resume_2*1000:.3f}ms")

    # Stats
    if obfuscator_enabled.session_cache:
        stats = obfuscator_enabled.session_cache.get_stats()
        print("\n3. Cache Statistics:")
        print("-" * 60)
        print(f"   Cached sessions: {stats['cached_sessions']}")
        print(f"   Active sessions: {stats['active_sessions']}")
        print(f"   Total resumptions: {stats['total_resumptions']}")

    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  Full handshake:     {time_full*1000:.3f}ms")
    print(f"  Resumed session:    {time_resumed*1000:.3f}ms")
    print(f"  Speedup:            {speedup:.1f}x")
    print(f"  Time saved:         {(time_full - time_resumed)*1000:.3f}ms per session")
    print("=" * 60)

    return {
        "full_handshake_ms": time_full * 1000,
        "resumed_ms": time_resumed * 1000,
        "speedup": speedup,
        "improvement_percent": improvement,
    }


if __name__ == "__main__":
    results = asyncio.run(test_resumption_performance())
    sys.exit(0)

