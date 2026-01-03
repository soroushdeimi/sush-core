#!/usr/bin/env python3
"""Simple benchmark test that prints results."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sush.core.quantum_obfuscator import QuantumObfuscator


async def simple_test():
    print("=" * 60)
    print("Simple Benchmark Test")
    print("=" * 60)

    try:
        obfuscator = QuantumObfuscator()
        print("✓ QuantumObfuscator created")

        # Generate peer keypair
        peer_pub, peer_priv = obfuscator.kem.generate_keypair()
        print("✓ Keypair generated")

        # Initialize session
        session_id = "test_session_001"
        await obfuscator.initialize_session(session_id, peer_pub)
        print("✓ Session initialized")

        # Test with 1KB payload
        payload = b"x" * 1024
        print(f"✓ Test payload created: {len(payload)} bytes")

        # Measure obfuscation
        start = time.perf_counter()
        obfuscated = await obfuscator.obfuscate_data(session_id, payload)
        obfuscate_time = time.perf_counter() - start
        print(f"✓ Obfuscation completed: {obfuscate_time * 1000:.2f}ms")

        # Measure deobfuscation
        start = time.perf_counter()
        deobfuscated = await obfuscator.deobfuscate_data(session_id, obfuscated)
        deobfuscate_time = time.perf_counter() - start
        print(f"✓ Deobfuscation completed: {deobfuscate_time * 1000:.2f}ms")

        # Verify
        if deobfuscated == payload:
            print("✓ Data integrity verified")
        else:
            print("✗ Data corruption detected!")

        total_time = obfuscate_time + deobfuscate_time
        throughput = (len(payload) * 8) / (total_time * 1_000_000)

        print("\n" + "=" * 60)
        print("RESULTS:")
        print(f"  Total time: {total_time * 1000:.2f}ms")
        print(f"  Throughput: {throughput:.2f} Mbps")
        print("=" * 60)

        return True

    except Exception as e:
        print(f"✗ ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    result = asyncio.run(simple_test())
    sys.exit(0 if result else 1)
