#!/usr/bin/env python3
"""
Smoke test for Sush Core - Basic functionality verification.
Quick test to ensure core components can be imported and initialized.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_basic_imports():
    """Test that core modules can be imported."""
    try:
        from sush.control.adaptive_control import AdaptiveControlLoop
        from sush.core.adaptive_cipher import AdaptiveCipherSuite
        from sush.core.ml_kem import MLKEMKeyExchange
        from sush.core.quantum_obfuscator import QuantumObfuscator
        from sush.network.mirror_network import MirrorNetwork
        from sush.transport.adaptive_transport import AdaptiveTransport

        return True
    except ImportError as e:
        print(f"Import failed: {e}")
        return False


def test_basic_initialization():
    """Test that components can be initialized."""
    try:
        from sush.core.ml_kem import MLKEMKeyExchange

        kem = MLKEMKeyExchange()
        public_key, private_key = kem.generate_keypair()

        assert len(public_key) > 0, "Public key should be generated"
        assert len(private_key) > 0, "Private key should be generated"

        return True
    except Exception as e:
        print(f"Initialization failed: {e}")
        return False


def main():
    """Run smoke tests."""
    print("Sush Core Smoke Test")
    print("=" * 40)

    tests = [
        ("Import Test", test_basic_imports()),
        ("Initialization Test", test_basic_initialization()),
    ]

    passed = sum(1 for _, result in tests if result)
    total = len(tests)

    for name, result in tests:
        status = "PASS" if result else "FAIL"
        print(f"{name}: {status}")

    print(f"\nResults: {passed}/{total} tests passed")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
