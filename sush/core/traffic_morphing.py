"""
Traffic Morphing Engine - Eliminate statistical fingerprints
"""

import os
import random
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class PacketProfile:
    """Traffic shaping profile."""

    min_size: int
    max_size: int
    timing_variance: float  # 0-1, higher = more random timing
    padding_strategy: str  # 'fixed', 'random', 'none'


class TrafficMorphingEngine:
    """Transform traffic to avoid statistical detection."""

    def __init__(self):
        self.profiles = {
            "web_browsing": PacketProfile(100, 1500, 0.3, "random"),
            "video_streaming": PacketProfile(800, 1500, 0.1, "fixed"),
            "file_transfer": PacketProfile(1400, 1500, 0.05, "none"),
            "chat": PacketProfile(50, 300, 0.5, "random"),
        }
        self.active_profile = "web_browsing"
        self.packet_buffer = []

    def morph_packet(self, data: bytes) -> list[bytes]:
        """Transform packet to match traffic profile."""
        profile = self.profiles[self.active_profile]

        if profile.padding_strategy == "fixed":
            return [self._pad_to_size(data, profile.max_size)]
        elif profile.padding_strategy == "random":
            target_size = random.randint(profile.min_size, profile.max_size)
            return [self._pad_to_size(data, target_size)]
        else:
            # Fragment large packets or pad small ones
            if len(data) > profile.max_size:
                return self._fragment_packet(data, profile.max_size)
            elif len(data) < profile.min_size:
                return [self._pad_to_size(data, profile.min_size)]
            else:
                return [data]

    def _pad_to_size(self, data: bytes, target_size: int) -> bytes:
        """Pad packet to target size."""
        if len(data) >= target_size:
            return data

        padding_needed = target_size - len(data)
        padding = os.urandom(padding_needed)

        # Add padding marker (last byte indicates padding length)
        if padding_needed < 255:
            padding = padding[:-1] + bytes([padding_needed])

        return data + padding

    def _fragment_packet(self, data: bytes, max_size: int) -> list[bytes]:
        """Fragment large packet into smaller ones."""
        fragments = []

        for i in range(0, len(data), max_size):
            fragment = data[i : i + max_size]
            fragments.append(fragment)

        return fragments

    def get_timing_delay(self) -> float:
        """Get delay for realistic packet timing."""
        profile = self.profiles[self.active_profile]

        # Base delay based on profile type
        base_delays = {
            "web_browsing": 0.05,
            "video_streaming": 0.033,  # ~30 FPS
            "file_transfer": 0.001,
            "chat": 0.1,
        }

        base_delay = base_delays.get(self.active_profile, 0.05)

        # Add variance
        variance = profile.timing_variance * base_delay
        delay = base_delay + random.uniform(-variance, variance)

        return max(0, delay)

    def inject_noise(self, data: bytes, noise_level: float = 0.1) -> bytes:
        """Inject random noise into packet."""
        if noise_level <= 0:
            return data

        # Calculate noise bytes to inject
        noise_bytes = int(len(data) * noise_level)
        if noise_bytes == 0:
            return data

        # Generate cryptographic noise
        noise = os.urandom(noise_bytes)

        # Insert noise at random positions
        result = bytearray(data)
        for _ in range(noise_bytes):
            pos = random.randint(0, len(result))
            result.insert(pos, noise[0])
            noise = noise[1:]

        return bytes(result)

    def remove_noise(self, data: bytes, noise_level: float = 0.1) -> bytes:
        """Remove injected noise from packet."""
        if noise_level <= 0:
            return data

        # This is a simplified noise removal
        # In practice, you'd need a more sophisticated method
        noise_bytes = int(len(data) * noise_level / (1 + noise_level))

        if noise_bytes >= len(data):
            return data

        # Remove estimated noise bytes from end
        return data[:-noise_bytes] if noise_bytes > 0 else data

    def set_profile(self, profile_name: str):
        """Switch to different traffic profile."""
        if profile_name in self.profiles:
            self.active_profile = profile_name

    def create_decoy_traffic(self, duration: float = 10.0) -> list[bytes]:
        """Generate decoy traffic packets."""
        profile = self.profiles[self.active_profile]
        packets = []

        start_time = time.time()
        while time.time() - start_time < duration:
            # Generate random packet
            size = random.randint(profile.min_size, profile.max_size)
            packet = os.urandom(size)
            packets.append(packet)

            # Realistic delay
            delay = self.get_timing_delay()
            time.sleep(delay)

        return packets

    def analyze_traffic_pattern(self, packets: list[bytes]) -> dict[str, Any]:
        """Analyze traffic for fingerprinting risks."""
        if not packets:
            return {}

        sizes = [len(p) for p in packets]

        return {
            "total_packets": len(packets),
            "avg_size": sum(sizes) / len(sizes),
            "min_size": min(sizes),
            "max_size": max(sizes),
            "size_variance": self._calculate_variance(sizes),
            "fingerprint_risk": self._assess_fingerprint_risk(sizes),
        }

    def _calculate_variance(self, values: list[int]) -> float:
        """Calculate variance of values."""
        if len(values) < 2:
            return 0.0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance

    def _assess_fingerprint_risk(self, sizes: list[int]) -> str:
        """Assess fingerprinting risk based on packet sizes."""
        variance = self._calculate_variance(sizes)

        if variance < 100:
            return "high"  # Very uniform sizes
        elif variance < 1000:
            return "medium"
        else:
            return "low"

    def get_profile_info(self) -> dict[str, Any]:
        """Get current profile information."""
        profile = self.profiles[self.active_profile]

        return {
            "active_profile": self.active_profile,
            "min_size": profile.min_size,
            "max_size": profile.max_size,
            "timing_variance": profile.timing_variance,
            "padding_strategy": profile.padding_strategy,
        }

    def extract_original_data(self, morphed_packet: bytes) -> bytes:
        """Extract original data from morphed packet."""
        # Check if packet has padding (look for padding marker in last byte)
        if len(morphed_packet) == 0:
            return morphed_packet

        # Try to detect padding marker
        try:
            potential_padding_length = morphed_packet[-1]
            if potential_padding_length < len(morphed_packet) and potential_padding_length > 0:
                # Remove padding if marker is valid
                original_length = len(morphed_packet) - potential_padding_length
                if original_length > 0:
                    return morphed_packet[:original_length]
        except (IndexError, ValueError):
            pass

        # If no padding detected, return as-is
        return morphed_packet

    def update_strategy(self, network_conditions: dict[str, Any]):
        """Update morphing strategy based on network conditions."""
        threat_level = network_conditions.get("threat_level", "medium")
        bandwidth = network_conditions.get("bandwidth", 1000000)

        # Select profile based on conditions
        if threat_level == "high":
            self.active_profile = "web_browsing"  # More morphing for high threat
        elif bandwidth < 100000:  # Low bandwidth
            self.active_profile = "chat"  # Smaller packets
        else:
            self.active_profile = "web_browsing"  # Default

    def get_statistics(self) -> dict[str, Any]:
        """Get morphing engine statistics."""
        return {
            "active_profile": self.active_profile,
            "total_profiles": len(self.profiles),
            "buffer_size": len(self.packet_buffer),
            "profile_info": self.get_profile_info(),
        }
