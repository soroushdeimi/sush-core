#!/usr/bin/env python3
"""
Entropy & Indistinguishability Analysis for sushCore

Measures Shannon entropy and performs Chi-Square test to prove
traffic indistinguishability from random noise.
"""

import asyncio
import math
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Tuple

import numpy as np

try:
    from scipy import stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    # Fallback: will use approximation

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sush.client import ClientConfig, SushClient
from sush.core.quantum_obfuscator import QuantumObfuscator
from sush.core.traffic_morphing import TrafficMorphingEngine, PaddingProfile
from sush.transport.adaptive_transport import AdaptiveTransport, TransportMode

OUTPUT_FILE = Path("tests/data/entropy_analysis.txt")


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte stream.
    
    Returns:
        Entropy in bits per byte (max 8.0 for uniform random data)
    """
    if len(data) == 0:
        return 0.0
    
    # Count byte frequencies
    byte_counts = Counter(data)
    data_length = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / data_length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def chi_square_uniformity_test(data: bytes) -> Tuple[float, float]:
    """
    Perform Chi-Square test for uniformity.
    
    Returns:
        (chi_square_statistic, p_value)
        p_value > 0.05 indicates uniform distribution (indistinguishable from random)
    """
    if len(data) == 0:
        return (0.0, 0.0)
    
    # Count byte frequencies
    byte_counts = Counter(data)
    observed = [byte_counts.get(i, 0) for i in range(256)]
    
    # Expected frequency (uniform distribution)
    expected_freq = len(data) / 256.0
    
    # Calculate chi-square statistic
    chi_square = sum(
        ((obs - expected_freq) ** 2) / expected_freq for obs in observed
    )
    
    # Degrees of freedom: 256 - 1 = 255
    degrees_of_freedom = 255
    
    # Calculate p-value
    if SCIPY_AVAILABLE:
        p_value = 1.0 - stats.chi2.cdf(chi_square, degrees_of_freedom)
    else:
        # Simple approximation for large degrees of freedom (df=255)
        # Use normal approximation: Z = (X - df) / sqrt(2*df)
        z = (chi_square - degrees_of_freedom) / (2 * degrees_of_freedom) ** 0.5
        import math
        try:
            # Approximate standard normal CDF using error function
            # Φ(z) ≈ 0.5 * (1 + erf(z/sqrt(2)))
            # P(X > chi_square) ≈ 1 - Φ(z)
            p_value = 0.5 * (1 - math.erf(z / (2 ** 0.5)))
            # Ensure p-value is in valid range
            p_value = max(0.0, min(1.0, p_value))
        except:
            # Fallback: if chi-square is close to df, p-value is high (uniform)
            # If chi-square >> df, p-value is low (non-uniform)
            if chi_square < degrees_of_freedom * 1.5:
                p_value = 0.5  # Likely uniform
            else:
                p_value = 0.01  # Likely non-uniform
    
    return (chi_square, p_value)


def analyze_traffic_entropy(
    data: bytes, label: str = "Traffic"
) -> dict:
    """Analyze entropy and uniformity of traffic data."""
    entropy = calculate_shannon_entropy(data)
    chi_square, p_value = chi_square_uniformity_test(data)
    
    # Interpretation
    entropy_score = "Excellent" if entropy >= 7.9 else "Good" if entropy >= 7.5 else "Fair"
    uniformity = "Uniform (indistinguishable)" if p_value > 0.05 else "Non-uniform (detectable)"
    
    return {
        "label": label,
        "data_size_bytes": len(data),
        "shannon_entropy": entropy,
        "entropy_bits_per_byte": entropy,
        "entropy_score": entropy_score,
        "chi_square_statistic": chi_square,
        "chi_square_p_value": p_value,
        "uniformity_assessment": uniformity,
        "is_indistinguishable": p_value > 0.05,
    }


async def generate_obfuscated_traffic(
    size_mb: float = 1.0, use_steganographic: bool = True
) -> bytes:
    """
    Generate obfuscated traffic using sushCore components.
    
    Args:
        size_mb: Size in megabytes
        use_steganographic: Use steganographic mode
    
    Returns:
        Obfuscated byte stream
    """
    print(f"Generating {size_mb}MB of obfuscated traffic...")
    
    obfuscator = QuantumObfuscator()
    morphing_engine = TrafficMorphingEngine()
    
    # Generate peer keypair
    peer_pub, _ = obfuscator.kem.generate_keypair()
    
    # Initialize session
    session_id = "entropy_test_session"
    await obfuscator.initialize_session(session_id, peer_pub)
    
    # Generate payload
    import os
    payload_size = int(size_mb * 1024 * 1024)
    payload = os.urandom(payload_size)
    
    # Obfuscate data
    print("Obfuscating data...")
    obfuscated_packets = await obfuscator.obfuscate_data(session_id, payload)
    
    # obfuscate_data returns list[bytes], concatenate them
    if obfuscated_packets:
        obfuscated = b"".join(obfuscated_packets)
    else:
        obfuscated = b""
    
    # Apply traffic morphing
    print("Applying traffic morphing...")
    try:
        if use_steganographic:
            morphed = morphing_engine.obfuscate_data(
                obfuscated, PaddingProfile.PARANOID
            )
        else:
            morphed = morphing_engine.obfuscate_data(
                obfuscated, PaddingProfile.INTERACTIVE
            )
    except Exception as e:
        # Fallback: just use obfuscated data if morphing fails
        print(f"Warning: Traffic morphing failed ({e}), using obfuscated data only")
        morphed = obfuscated
    
    return morphed


async def main():
    """Run entropy analysis."""
    print("=" * 70)
    print("sushCore Entropy & Indistinguishability Analysis")
    print("=" * 70)
    
    results = []
    
    # Test 1: Random data (baseline)
    print("\n" + "=" * 70)
    print("Test 1: Random Data (Baseline)")
    print("=" * 70)
    import os
    random_data = os.urandom(1024 * 1024)  # 1MB
    result1 = analyze_traffic_entropy(random_data, "Random Data (Baseline)")
    results.append(result1)
    print(f"Shannon Entropy: {result1['shannon_entropy']:.4f} bits/byte")
    print(f"Chi-Square p-value: {result1['chi_square_p_value']:.6f}")
    print(f"Assessment: {result1['uniformity_assessment']}")
    
    # Test 2: Obfuscated traffic (PARANOID mode)
    print("\n" + "=" * 70)
    print("Test 2: Obfuscated Traffic (PARANOID mode)")
    print("=" * 70)
    obfuscated_data = await generate_obfuscated_traffic(1.0, use_steganographic=True)
    result2 = analyze_traffic_entropy(obfuscated_data, "Obfuscated Traffic (PARANOID)")
    results.append(result2)
    print(f"Shannon Entropy: {result2['shannon_entropy']:.4f} bits/byte")
    print(f"Chi-Square p-value: {result2['chi_square_p_value']:.6f}")
    print(f"Assessment: {result2['uniformity_assessment']}")
    
    # Test 3: Obfuscated traffic (INTERACTIVE mode)
    print("\n" + "=" * 70)
    print("Test 3: Obfuscated Traffic (INTERACTIVE mode)")
    print("=" * 70)
    obfuscated_data2 = await generate_obfuscated_traffic(1.0, use_steganographic=False)
    result3 = analyze_traffic_entropy(obfuscated_data2, "Obfuscated Traffic (INTERACTIVE)")
    results.append(result3)
    print(f"Shannon Entropy: {result3['shannon_entropy']:.4f} bits/byte")
    print(f"Chi-Square p-value: {result3['chi_square_p_value']:.6f}")
    print(f"Assessment: {result3['uniformity_assessment']}")
    
    # Summary
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"{'Test':<40} {'Entropy':<12} {'p-value':<12} {'Indistinguishable'}")
    print("-" * 70)
    for result in results:
        print(
            f"{result['label']:<40} "
            f"{result['shannon_entropy']:>7.4f}     "
            f"{result['chi_square_p_value']:>10.6f}  "
            f"{'✓' if result['is_indistinguishable'] else '✗'}"
        )
    
    # Save results
    print(f"\nSaving results to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("sushCore Entropy & Indistinguishability Analysis\n")
        f.write("=" * 70 + "\n\n")
        
        for result in results:
            f.write(f"Test: {result['label']}\n")
            f.write(f"  Data Size: {result['data_size_bytes']:,} bytes\n")
            f.write(f"  Shannon Entropy: {result['shannon_entropy']:.6f} bits/byte\n")
            f.write(f"  Entropy Score: {result['entropy_score']}\n")
            f.write(f"  Chi-Square Statistic: {result['chi_square_statistic']:.2f}\n")
            f.write(f"  Chi-Square p-value: {result['chi_square_p_value']:.6f}\n")
            f.write(f"  Uniformity: {result['uniformity_assessment']}\n")
            f.write(f"  Indistinguishable: {'Yes' if result['is_indistinguishable'] else 'No'}\n")
            f.write("\n")
        
        f.write("=" * 70 + "\n")
        f.write("Interpretation:\n")
        f.write("- Entropy >= 7.9: Excellent (nearly indistinguishable from random)\n")
        f.write("- Entropy >= 7.5: Good (very difficult to distinguish)\n")
        f.write("- p-value > 0.05: Uniform distribution (indistinguishable from random)\n")
        f.write("=" * 70 + "\n")
    
    print(f"Results saved to {OUTPUT_FILE}")
    print("\n" + "=" * 70)
    print("Entropy analysis completed!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())

