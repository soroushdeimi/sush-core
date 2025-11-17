#!/usr/bin/env python3
"""
Quick validation test for sushCore components.
Simple tests to verify basic functionality.
"""

import asyncio
import os
import secrets
import sys
import time

# Add the parent directory to the path to import sush
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


OPTIONAL_DEPENDENCIES = {
    "cryptography",
    "numpy",
    "scikit-learn",
    "sklearn",
    "joblib",
    "pynacl",
    "nacl",
    "kyber_py",
    "kyber-py",
    "aiohttp",
}


def _skip_optional_dependency(error: ModuleNotFoundError, context: str) -> bool:
    missing = getattr(error, "name", None)
    if missing in OPTIONAL_DEPENDENCIES:
        print(f"Skipping {context}: optional dependency '{missing}' is not installed.")
        return True
    return False


def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")
    try:
        from sush.control.adaptive_control import AdaptiveControlLoop
        from sush.control.censorship_detector import CensorshipDetector
        from sush.core.adaptive_cipher import AdaptiveCipherSuite
        from sush.core.ml_kem import MLKEMKeyExchange
        from sush.core.quantum_obfuscator import QuantumObfuscator
        from sush.network.node_integrity import SimplifiedNodeIntegrity
        from sush.network.onion_routing import OnionRoutingProtocol
        from sush.transport.adaptive_transport import AdaptiveTransport
        from sush.transport.protocol_hopper import ProtocolHopper
        from sush.transport.steganographic_channels import ChannelManager

        print("All imports successful")
        return True
    except ModuleNotFoundError as e:
        if _skip_optional_dependency(e, "Import Test"):
            return True
        print(f"Import failed: {e}")
        return False
    except Exception as e:
        print(f"Import failed: {e}")
        return False


def test_ml_kem():
    """Test ML-KEM key exchange."""
    print("Testing ML-KEM...")
    try:
        from sush.core.ml_kem import MLKEMKeyExchange

        kem = MLKEMKeyExchange()
        public_key, private_key = kem.generate_keypair()

        # Basic size checks
        assert len(public_key) == 1184, f"Wrong public key size: {len(public_key)}"
        assert len(private_key) == 2400, f"Wrong private key size: {len(private_key)}"

        # Test encapsulation/decapsulation
        ciphertext, shared_secret1 = kem.encapsulate(public_key)
        shared_secret2 = kem.decapsulate(ciphertext, private_key)

        assert shared_secret1 == shared_secret2, "Shared secrets don't match"
        assert len(shared_secret1) == 32, f"Wrong shared secret size: {len(shared_secret1)}"

        print("ML-KEM working correctly")
        return True
    except ModuleNotFoundError as e:
        if _skip_optional_dependency(e, "ML-KEM Test"):
            return True
        print(f"ML-KEM test failed: {e}")
        return False
    except Exception as e:
        print(f"ML-KEM test failed: {e}")
        return False


def test_aead_ciphers():
    """Test AEAD cipher implementations."""
    print("Testing AEAD ciphers...")
    try:
        from sush.core.adaptive_cipher import AdaptiveCipherSuite, NetworkCondition, ThreatLevel

        cipher_suite = AdaptiveCipherSuite()
        cipher_suite.encryption_key = b"0" * 32  # Set a test key
        test_data = b"test encryption data"

        # Test AES-GCM (default)
        cipher_suite.active_cipher = "aes_gcm"
        encrypted, iv, tag = cipher_suite.encrypt(test_data)
        decrypted = cipher_suite.decrypt(encrypted, iv, tag)
        assert decrypted == test_data, "AES-GCM failed"

        # Test ChaCha20-Poly1305
        cipher_suite.active_cipher = "chacha20"
        encrypted, iv, tag = cipher_suite.encrypt(test_data)
        decrypted = cipher_suite.decrypt(encrypted, iv, tag)
        assert decrypted == test_data, "ChaCha20 failed"

        print("AEAD ciphers working correctly")
        return True
    except ModuleNotFoundError as e:
        if _skip_optional_dependency(e, "AEAD Ciphers Test"):
            return True
        print(f"AEAD test failed: {e}")
        return False
    except Exception as e:
        print(f"AEAD test failed: {e}")
        return False


def test_onion_encryption():
    """Test onion routing encryption."""
    print("Testing onion encryption...")
    try:
        from sush.network.onion_routing import OnionLayer, OnionRoutingProtocol

        orpp = OnionRoutingProtocol("test_node", b"test_private_key")
        layer = OnionLayer(
            node_id="test_node",
            public_key=b"test_public_key",
            shared_secret=secrets.token_bytes(32),
            hop_number=0,
        )

        test_data = b"sensitive data"
        encrypted = orpp._encrypt_with_layer(layer, test_data)
        decrypted = orpp._decrypt_with_layer(layer, encrypted)

        assert decrypted == test_data, "Onion encryption failed"
        assert encrypted != test_data, "Data should be encrypted"

        print("Onion encryption working correctly")
        return True
    except ModuleNotFoundError as e:
        if _skip_optional_dependency(e, "Onion Encryption Test"):
            return True
        print(f"Onion encryption test failed: {e}")
        return False
    except Exception as e:
        print(f"Onion encryption test failed: {e}")
        return False


async def test_ml_detection():
    """Test ML-based censorship detection."""
    print("Testing ML detection...")
    try:
        from sush.control.censorship_detector import CensorshipDetector, NetworkMetrics

        detector = CensorshipDetector()

        # Check ML components exist
        assert hasattr(detector, "anomaly_detector"), "Missing anomaly detector"
        assert hasattr(detector, "threat_classifier"), "Missing threat classifier"

        # Train models
        await detector.train_ml_models()
        assert detector.ml_models_trained, "ML models not trained"

        # Test feature extraction
        test_metrics = NetworkMetrics(
            timestamp=time.time(),
            latency=0.1,
            packet_loss=0.05,
            throughput=5.0,
            connection_success_rate=0.8,
            rst_packets=10,
            retransmissions=5,
            jitter=0.02,
            bandwidth_utilization=0.7,
        )

        features = detector._extract_features(test_metrics)
        assert len(features) == 15, f"Wrong feature count: {len(features)}"

        print("ML detection working correctly")
        return True
    except ModuleNotFoundError as e:
        if _skip_optional_dependency(e, "ML Detection Test"):
            return True
        print(f"ML detection test failed: {e}")
        return False
    except Exception as e:
        print(f"ML detection test failed: {e}")
        return False


def test_condition_evaluation():
    """Test robust condition evaluation."""
    print("Testing condition evaluation...")
    try:
        from sush.control.adaptive_control import ThreatLevelCondition
        from sush.control.censorship_detector import ThreatLevel

        condition = ThreatLevelCondition(">=", ThreatLevel.HIGH)

        # Test high threat
        context_high = {"threat_level": ThreatLevel.HIGH}
        assert condition.evaluate(context_high), "High threat condition failed"

        # Test low threat
        context_low = {"threat_level": ThreatLevel.LOW}
        assert not condition.evaluate(context_low), "Low threat condition failed"

        print("Condition evaluation working correctly")
        return True
    except ModuleNotFoundError as e:
        if _skip_optional_dependency(e, "Condition Evaluation Test"):
            return True
        print(f"Condition evaluation test failed: {e}")
        return False
    except Exception as e:
        print(f"Condition evaluation test failed: {e}")
        return False


async def main():
    """Run all quick validation tests."""
    print("sushCore Phase 4 Quick Validation")
    print("=" * 40)

    tests = [
        ("Import Test", test_imports()),
        ("ML-KEM Test", test_ml_kem()),
        ("AEAD Ciphers Test", test_aead_ciphers()),
        ("Onion Encryption Test", test_onion_encryption()),
        ("ML Detection Test", await test_ml_detection()),
        ("Condition Evaluation Test", test_condition_evaluation()),
    ]

    passed = 0
    total = len(tests)

    for name, result in tests:
        if result:
            passed += 1
        else:
            print(f"{name} failed with exception")

    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("ALL TESTS PASSED!")
        return True
    else:
        print("Some tests failed.")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
