#!/usr/bin/env python3
"""Integration validation for sushCore phases."""

import asyncio
import os
import sys
import time
import traceback

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
}

OPTIONAL_IMPORT_ERROR = None

try:
    from sush.control.adaptive_control import (
        CensorshipTypeCondition,
        CompoundCondition,
        ThreatLevelCondition,
    )
    from sush.control.censorship_detector import (
        CensorshipDetector,
        CensorshipType,
        NetworkMetrics,
    )
    from sush.control.censorship_detector import (
        ThreatLevel as DetectorThreatLevel,
    )
    from sush.core.adaptive_cipher import (
        AdaptiveCipherSuite,
        NetworkCondition,
    )
    from sush.core.adaptive_cipher import (
        ThreatLevel as CipherThreatLevel,
    )
    from sush.core.ml_kem import MLKEMKeyExchange
    from sush.core.quantum_obfuscator import QuantumObfuscator
    from sush.network.node_integrity import SimplifiedNodeIntegrity
    from sush.network.onion_routing import OnionLayer, OnionRoutingProtocol
    from sush.transport.adaptive_transport import AdaptiveTransport
    from sush.transport.protocol_hopper import ProtocolHopper
    from sush.transport.steganographic_channels import ChannelManager
except ModuleNotFoundError as exc:
    if exc.name in OPTIONAL_DEPENDENCIES:
        OPTIONAL_IMPORT_ERROR = exc
    else:
        raise


def optional_available(context: str) -> bool:
    """Return True when optional dependencies are present, otherwise log skip."""
    if OPTIONAL_IMPORT_ERROR is not None:
        missing = getattr(OPTIONAL_IMPORT_ERROR, "name", "dependency")
        print(f"Skipping {context}: optional dependency '{missing}' is not installed.")
        return False
    return True


async def test_security_hardening():
    """Validate Phase 1 components (crypto, onion, signatures)."""
    if not optional_available("Phase 1 tests"):
        return

    print("Testing Phase 1: Security Hardening...")

    # ML-KEM
    print("  Testing ML-KEM quantum-resistant key exchange...")
    kem = MLKEMKeyExchange()
    public_key, private_key = kem.generate_keypair()
    assert len(public_key) == 1184
    assert len(private_key) == 2400
    ciphertext, shared_secret1 = kem.encapsulate(public_key)
    shared_secret2 = kem.decapsulate(ciphertext, private_key)
    assert shared_secret1 == shared_secret2
    assert len(shared_secret1) == 32

    # AEAD Ciphers
    print("  Testing AEAD cipher selections...")
    cipher_suite = AdaptiveCipherSuite()
    cipher_suite.encryption_key = os.urandom(32)
    payload = b"integration-test"
    for cipher_name in ["aes_gcm", "chacha20", "aes_ocb"]:
        cipher_suite.active_cipher = cipher_name
        encrypted, iv, tag = cipher_suite.encrypt(payload)
        decrypted = cipher_suite.decrypt(encrypted, iv, tag)
        assert decrypted == payload, f"Cipher roundtrip failed for {cipher_name}"

    # Onion encryption helpers
    print("  Testing onion routing primitives...")
    onion = OnionRoutingProtocol("integration_node", os.urandom(32))
    layer = OnionLayer(
        node_id="hop0", public_key=os.urandom(32), shared_secret=os.urandom(32), hop_number=0
    )
    encrypted = onion._encrypt_with_layer(layer, payload)
    decrypted = onion._decrypt_with_layer(layer, encrypted)
    assert decrypted == payload

    # Ed25519 signatures
    print("  Testing Ed25519 node integrity signatures...")
    integrity = SimplifiedNodeIntegrity("integration_node", os.urandom(32))
    await integrity.register_node("integration_node", integrity.public_key.encode().hex())
    sample = "integration-signature"
    signature = integrity._sign_data(sample)
    assert integrity._verify_signature("integration_node", sample, signature)

    print("Phase 1: Security Hardening - PASSED\n")


async def test_functional_components():
    """Validate Phase 2 components (transport/steg)."""
    if not optional_available("Phase 2 tests"):
        return

    print("Testing Phase 2: Functional Components...")

    # Steganographic channels
    print("  Testing steganographic channel registry...")
    channels = ChannelManager()
    assert {"ttl", "ntp", "dns"} <= set(channels.channels.keys())

    # Protocol hopper
    print("  Testing protocol hopper sequence generation...")
    hopper = ProtocolHopper()
    sequence = hopper.generate_hop_sequence(os.urandom(32), "session123", 5)
    assert len(sequence.ports) == 5

    # Adaptive transport lifecycle (partial)
    print("  Testing adaptive transport configuration...")
    transport = AdaptiveTransport()
    transport.configure({"enable_steganography": True, "enable_traffic_morphing": True})
    status = transport.get_status()
    assert isinstance(status, dict)

    print("Phase 2: Functional Components - PASSED\n")


async def test_ml_enhancements():
    """Validate Phase 3 components (ML + conditions)."""
    if not optional_available("Phase 3 tests"):
        return

    print("Testing Phase 3: ML Enhancements...")

    detector = CensorshipDetector()
    await detector.train_ml_models()
    assert detector.ml_models_trained

    metrics = NetworkMetrics(
        timestamp=time.time(),
        latency=0.05,
        packet_loss=0.02,
        throughput=8.0,
        connection_success_rate=0.9,
        rst_packets=2,
        retransmissions=1,
        jitter=0.01,
        bandwidth_utilization=0.6,
    )
    features = detector._extract_features(metrics)
    assert len(features) == 15

    # Condition evaluation
    print("  Testing adaptive control conditions...")
    threat_condition = ThreatLevelCondition(">=", DetectorThreatLevel.HIGH)
    censorship_condition = CensorshipTypeCondition(CensorshipType.DPI_FILTERING)
    compound = CompoundCondition(threat_condition, "AND", censorship_condition)

    assert threat_condition.evaluate({"threat_level": DetectorThreatLevel.HIGH})
    assert not threat_condition.evaluate({"threat_level": DetectorThreatLevel.LOW})
    assert compound.evaluate(
        {
            "threat_level": DetectorThreatLevel.CRITICAL,
            "detected_censorship": [CensorshipType.DPI_FILTERING],
        }
    )

    print("Phase 3: ML Enhancements - PASSED\n")


async def test_end_to_end_integration():
    """Simple end-to-end obfuscation + transport check."""
    if not optional_available("End-to-End Integration tests"):
        return

    print("Testing End-to-End Integration...")

    obfuscator = QuantumObfuscator()
    transport = AdaptiveTransport()

    session_id = "integration-session"
    peer_public_key = obfuscator.get_public_key()
    await obfuscator.initialize_session(session_id, peer_public_key)

    original = b"integration roundtrip"
    obfuscated_packets = await obfuscator.obfuscate_data(session_id, original)
    recovered = await obfuscator.deobfuscate_data(session_id, obfuscated_packets)
    assert recovered == original

    await transport.configure({"enable_steganography": False})
    metrics = await transport.get_performance_metrics()
    assert isinstance(metrics, dict)

    print("End-to-End Integration - PASSED\n")


async def run_validation():
    """Entry point for integration validation."""
    print("sushCore Phase 4 Validation")
    print("=" * 50)

    if not optional_available("integration suite"):
        return True

    try:
        await test_security_hardening()
        await test_functional_components()
        await test_ml_enhancements()
        await test_end_to_end_integration()
        print("ALL TESTS PASSED!")
        print("sushCore security hardening and enhancement checks complete")
        return True
    except Exception as exc:
        print(f"\nTest failed: {exc}")
        traceback.print_exc()
        return False


def main():
    """CLI entry point."""
    success = asyncio.run(run_validation())
    if success:
        print("\nsushCore integration suite finished successfully")
        return 0
    print("\nValidation failed!")
    return 1


if __name__ == "__main__":
    sys.exit(main())
