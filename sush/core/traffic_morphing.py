"""
Traffic Morphing Engine - Eliminate statistical fingerprints
"""

import os
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class PaddingProfile(Enum):
    """Adaptive padding profiles for different traffic types."""

    INTERACTIVE = "interactive"  # Low latency, minimal padding (pad to nearest 64 bytes)
    STREAMING = "streaming"  # High throughput (pad to MTU ~1400 bytes)
    PARANOID = "paranoid"  # Max security (uniform distribution strategy)


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

        # Adaptive padding configuration
        self.adaptive_padding_enabled = True
        self.active_padding_profile = PaddingProfile.INTERACTIVE

        # Packet history for heuristic detection
        self.packet_history: list[tuple[float, int]] = []  # (timestamp, size)
        self.history_window = 5.0  # seconds
        self.history_max_size = 100  # max packets to track

    def morph_packet(
        self, data: bytes, traffic_type: Optional[PaddingProfile] = None
    ) -> list[bytes]:
        """
        Transform packet to match traffic profile.

        Args:
            data: Original packet data
            traffic_type: Optional hint for padding profile. If None, uses heuristic detection.

        Returns:
            List of morphed packets
        """
        # Update packet history for heuristic detection
        self._update_packet_history(len(data))

        # Determine padding profile
        if traffic_type is None and self.adaptive_padding_enabled:
            traffic_type = self._detect_traffic_type()
        elif traffic_type is None:
            traffic_type = self.active_padding_profile

        # Apply adaptive padding if enabled
        if self.adaptive_padding_enabled:
            padded_data = self._apply_adaptive_padding(data, traffic_type)
        else:
            # Fall back to legacy profile-based padding
            profile = self.profiles[self.active_profile]
            if profile.padding_strategy == "fixed":
                padded_data = self._pad_to_size(data, profile.max_size)
            elif profile.padding_strategy == "random":
                target_size = random.randint(profile.min_size, profile.max_size)
                padded_data = self._pad_to_size(data, target_size)
            else:
                # Fragment large packets or pad small ones
                if len(data) > profile.max_size:
                    return self._fragment_packet(data, profile.max_size)
                elif len(data) < profile.min_size:
                    padded_data = self._pad_to_size(data, profile.min_size)
                else:
                    padded_data = data

        return [padded_data]

    def obfuscate_data(self, data: bytes, traffic_type: Optional[PaddingProfile] = None) -> bytes:
        """
        Obfuscate data with adaptive padding (alias for morph_packet returning single packet).

        Args:
            data: Original data
            traffic_type: Optional hint for padding profile

        Returns:
            Obfuscated data with padding
        """
        morphed = self.morph_packet(data, traffic_type)
        return morphed[0] if morphed else data

    def _apply_adaptive_padding(self, data: bytes, profile: PaddingProfile) -> bytes:
        """
        Apply adaptive padding based on profile.

        Args:
            data: Original data
            profile: Padding profile to use

        Returns:
            Padded data with framing header
        """
        if profile == PaddingProfile.INTERACTIVE:
            # Pad to nearest 64 bytes (minimal overhead)
            target_size = ((len(data) + 63) // 64) * 64
            if target_size < 64:
                target_size = 64
        elif profile == PaddingProfile.STREAMING:
            # Pad to MTU (1400 bytes) for high throughput
            target_size = 1400
        elif profile == PaddingProfile.PARANOID:
            # Uniform distribution strategy (current random padding)
            profile_obj = self.profiles.get(self.active_profile, self.profiles["web_browsing"])
            # Ensure target_size is at least data size + header overhead
            min_target = len(data) + 8
            max_target = max(profile_obj.max_size, min_target)
            target_size = random.randint(max(profile_obj.min_size, min_target), max_target)
        else:
            # Default: minimal padding
            target_size = len(data) + 8

        return self._pad_to_size(data, target_size)

    def _detect_traffic_type(self) -> PaddingProfile:
        """
        Heuristically detect traffic type based on packet history.

        Returns:
            Detected PaddingProfile
        """
        if not self.packet_history:
            return PaddingProfile.INTERACTIVE  # Default

        # Clean old history
        current_time = time.time()
        self.packet_history = [
            (ts, size)
            for ts, size in self.packet_history
            if current_time - ts < self.history_window
        ]

        if len(self.packet_history) < 3:
            return PaddingProfile.INTERACTIVE  # Not enough data

        # Analyze packet characteristics
        sizes = [size for _, size in self.packet_history]
        avg_size = sum(sizes) / len(sizes)

        # Calculate packet frequency (packets per second)
        if len(self.packet_history) >= 2:
            time_span = self.packet_history[-1][0] - self.packet_history[0][0]
            if time_span > 0:
                packet_rate = len(self.packet_history) / time_span
            else:
                packet_rate = 0
        else:
            packet_rate = 0

        # Heuristic rules
        if avg_size > 1000 and packet_rate > 10:
            # Large packets + high frequency = streaming
            return PaddingProfile.STREAMING
        elif avg_size < 200 and packet_rate < 5:
            # Small packets + low frequency = interactive
            return PaddingProfile.INTERACTIVE
        elif avg_size > 500:
            # Medium-large packets = paranoid (more security)
            return PaddingProfile.PARANOID
        else:
            # Default to interactive for low overhead
            return PaddingProfile.INTERACTIVE

    def _update_packet_history(self, packet_size: int):
        """Update packet history for heuristic detection."""
        current_time = time.time()

        # Add new packet
        self.packet_history.append((current_time, packet_size))

        # Trim old packets
        self.packet_history = [
            (ts, size)
            for ts, size in self.packet_history
            if current_time - ts < self.history_window
        ]

        # Limit history size
        if len(self.packet_history) > self.history_max_size:
            self.packet_history = self.packet_history[-self.history_max_size :]

    def _pad_to_size(self, data: bytes, target_size: int) -> bytes:
        """Pad packet to target size using standard framing."""
        # Header overhead is 8 bytes
        required_overhead = 8

        if len(data) + required_overhead > target_size:
            # Can't pad to target size if data + header is already bigger
            # Just add header and minimal padding if needed, or return as is if strictly larger
            # For safety, we always add header so extraction works
            target_size = len(data) + required_overhead

        padding_needed = target_size - (len(data) + required_overhead)

        if padding_needed < 0:
            # Should not happen due to check above
            padding_needed = 0

        padding = os.urandom(padding_needed)

        # Format: [OrigLen(4)][PadLen(4)][Data][Padding]
        header = len(data).to_bytes(4, "big") + len(padding).to_bytes(4, "big")

        return header + data + padding

    def _fragment_packet(self, data: bytes, max_size: int) -> list[bytes]:
        """Fragment large packet into smaller ones with framing."""
        fragments = []

        # Effective payload size per fragment (max_size - header_size)
        header_size = 8
        payload_size = max_size - header_size

        if payload_size <= 0:
            # Should not happen with reasonable max_size
            payload_size = max_size

        for i in range(0, len(data), payload_size):
            chunk = data[i : i + payload_size]
            # We apply padding/framing to each fragment effectively
            # But here we just frame it as a packet with 0 padding
            # Format: [Len][0][Chunk]
            header = len(chunk).to_bytes(4, "big") + (0).to_bytes(4, "big")
            fragment = header + chunk
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
        """Inject random noise into packet with framing header."""
        if noise_level <= 0:
            return data

        # Calculate noise bytes to inject
        noise_bytes = int(len(data) * noise_level)
        if noise_bytes == 0:
            return data

        # Generate cryptographic noise
        noise = os.urandom(noise_bytes)

        # Append noise to end of data (simpler than random insertion)
        result = data + noise

        # Add framing header: [4 bytes: original_length][4 bytes: noise_length][data][noise]
        header = len(data).to_bytes(4, "big") + noise_bytes.to_bytes(4, "big")
        return header + result

    def remove_noise(self, data: bytes, noise_level: float = 0.1) -> bytes:
        """Remove injected noise from packet using framing header."""
        if noise_level <= 0:
            return data

        if len(data) < 8:
            return data

        try:
            # Parse framing header
            original_length = int.from_bytes(data[0:4], "big")
            noise_length = int.from_bytes(data[4:8], "big")

            # Validate header values
            if original_length < 0 or noise_length < 0:
                return data
            if original_length + noise_length + 8 > len(data):
                return data

            # Extract original data (skip 8-byte header)
            original_data = data[8 : 8 + original_length]

            return original_data
        except (ValueError, IndexError):
            # Fallback to old method if header parsing fails
            noise_bytes = int(len(data) * noise_level / (1 + noise_level))
            if noise_bytes >= len(data):
                return data
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
        """Extract original data from morphed packet using framing header."""
        if len(morphed_packet) < 8:
            return morphed_packet

        try:
            # Parse framing header: [4 bytes: original_length][4 bytes: noise_length]
            original_length = int.from_bytes(morphed_packet[0:4], "big")
            noise_length = int.from_bytes(morphed_packet[4:8], "big")

            # Validate header values
            if original_length < 0 or noise_length < 0:
                return morphed_packet
            if original_length + noise_length + 8 > len(morphed_packet):
                return morphed_packet

            # Extract original data (skip 8-byte header)
            original_data = morphed_packet[8 : 8 + original_length]
            return original_data
        except (ValueError, IndexError):
            # Fallback: try old padding marker method for backward compatibility
            try:
                potential_padding_length = morphed_packet[-1]
                if potential_padding_length < len(morphed_packet) and potential_padding_length > 0:
                    original_length = len(morphed_packet) - potential_padding_length
                    if original_length > 0:
                        return morphed_packet[:original_length]
            except (IndexError, ValueError):
                pass

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

    def set_padding_profile(self, profile: PaddingProfile):
        """Set active adaptive padding profile."""
        self.active_padding_profile = profile

    def enable_adaptive_padding(self, enabled: bool = True):
        """Enable or disable adaptive padding."""
        self.adaptive_padding_enabled = enabled

    def get_statistics(self) -> dict[str, Any]:
        """Get morphing engine statistics."""
        return {
            "active_profile": self.active_profile,
            "total_profiles": len(self.profiles),
            "buffer_size": len(self.packet_buffer),
            "profile_info": self.get_profile_info(),
            "adaptive_padding_enabled": self.adaptive_padding_enabled,
            "active_padding_profile": self.active_padding_profile.value
            if self.adaptive_padding_enabled
            else None,
            "packet_history_size": len(self.packet_history),
        }
