"""
Adaptive Transport - Coordinate transport layer components
"""

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Optional

from .metadata_channels import MetadataChannels
from .protocol_hopper import ProtocolHopper
from .steganographic_channels import ChannelManager


class TransportMode(Enum):
    DIRECT = auto()  # Direct connection
    STEGANOGRAPHIC = auto()  # Hidden in other protocols
    METADATA = auto()  # Control via metadata channels
    HYBRID = auto()  # Combination approach


@dataclass
class TransportConfig:
    """Configuration knobs for the adaptive transport layer."""

    mode: TransportMode = TransportMode.DIRECT
    enable_hopping: bool = True
    hop_interval: float = 30.0
    steganographic_channel: str = "ntp"
    metadata_channel: str = "ttl"
    connection_timeout: float = 10.0

    # Behavioural flags used by the control loop
    enable_steganography: bool = True
    enable_traffic_morphing: bool = True


class AdaptiveTransport:
    """Adaptive transport layer coordination."""

    def __init__(self, config: Optional[TransportConfig] = None):
        self.config = config or TransportConfig()
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.protocol_hopper = ProtocolHopper()
        self.stego_channels = ChannelManager()
        self.metadata_channels = MetadataChannels()

        # Runtime state
        self.active_connections: dict[str, dict[str, Any]] = {}
        self._aggressiveness = 0.5
        self._steganography_enabled = self.config.enable_steganography
        self._traffic_signature_minimized = False
        self._redundancy_enabled = False

        self.transport_stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "hops_completed": 0,
            "steganographic_bytes": 0,
        }

    async def configure(self, options: dict[str, Any]) -> None:
        """
        Apply configuration coming from the higher layers.

        We keep the method async because the surrounding code awaits it.  The
        body runs synchronously but returning an awaitable keeps the API stable.
        """
        for key, value in options.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

        if "enable_steganography" in options:
            self._steganography_enabled = bool(options["enable_steganography"])
        if "enable_traffic_morphing" in options:
            # Currently traffic morphing is handled in the obfuscator; we simply
            # remember the flag so status reporting stays consistent.
            self._traffic_signature_minimized = not bool(options["enable_traffic_morphing"])

        self.logger.debug("Adaptive transport configured with %s", options)

    async def establish_connection(self, target: str) -> str:
        """Establish connection using current transport mode."""
        connection_id = f"conn_{len(self.active_connections)}"

        try:
            mode = self.config.mode
            if mode == TransportMode.STEGANOGRAPHIC and not self._steganography_enabled:
                self.logger.warning("Steganography disabled, falling back to DIRECT transport")
                mode = TransportMode.DIRECT
            if mode == TransportMode.HYBRID and not self._steganography_enabled:
                mode = TransportMode.DIRECT

            if mode == TransportMode.DIRECT:
                connection = await self._establish_direct_connection(target)
            elif mode == TransportMode.STEGANOGRAPHIC:
                connection = await self._establish_steganographic_connection(target)
            elif mode == TransportMode.METADATA:
                connection = await self._establish_metadata_connection(target)
            else:  # HYBRID
                connection = await self._establish_hybrid_connection(target)

            self.active_connections[connection_id] = {
                "connection": connection,
                "target": target,
                "mode": mode,
                "created_at": asyncio.get_event_loop().time(),
            }

            self.logger.info(
                f"Established {self.config.mode.name} connection {connection_id} to {target}"
            )
            return connection_id

        except Exception as e:
            self.logger.error(f"Failed to establish connection to {target}: {e}")
            raise

    async def _establish_direct_connection(self, target: str) -> dict:
        """Establish direct connection with protocol hopping."""
        if self.config.enable_hopping:
            # Create hopping sequence
            sequence_id = f"seq_{target}"
            sequence = self.protocol_hopper.create_hop_sequence(sequence_id)
            await self.protocol_hopper.start_hopping(sequence_id)
            self.transport_stats["hops_completed"] += len(sequence.ports)

        # Create connection using current protocol/port
        resource = await self.protocol_hopper.create_connection(
            target.split(":")[0], int(target.split(":")[1]) if ":" in target else 443
        )

        return resource

    async def _establish_steganographic_connection(self, target: str) -> dict:
        """Establish steganographic connection."""
        channel = self.config.steganographic_channel
        self.stego_channels.switch_channel(channel)

        return {"type": "steganographic", "channel": channel, "target": target}

    async def _establish_metadata_connection(self, target: str) -> dict:
        """Establish metadata-only connection."""
        channel = self.config.metadata_channel
        self.metadata_channels.switch_channel(channel)

        return {"type": "metadata", "channel": channel, "target": target}

    async def _establish_hybrid_connection(self, target: str) -> dict:
        """Establish hybrid connection using multiple methods."""
        # Use steganographic for data, metadata for control
        stego_conn = await self._establish_steganographic_connection(target)
        meta_conn = await self._establish_metadata_connection(target)

        return {"type": "hybrid", "data_channel": stego_conn, "control_channel": meta_conn}

    async def send_data(self, connection_id: str, data: bytes) -> bool:
        """Send data through established connection."""
        if connection_id not in self.active_connections:
            return False

        conn_info = self.active_connections[connection_id]
        mode = conn_info["mode"]
        connection = conn_info["connection"]
        target = conn_info["target"]

        try:
            if mode == TransportMode.DIRECT:
                success = await self._send_direct_data(connection, data)
            elif mode == TransportMode.STEGANOGRAPHIC:
                if not self._steganography_enabled:
                    success = await self._send_direct_data(connection, data)
                else:
                    success = await self.stego_channels.send_data(data, target)
            elif mode == TransportMode.METADATA:
                success = await self.metadata_channels.send_control_signal(data, target)
            else:  # HYBRID
                if not self._steganography_enabled:
                    success = await self._send_direct_data(connection, data)
                else:
                    success = await self.stego_channels.send_data(data, target)

            if success:
                self.transport_stats["packets_sent"] += 1
                if mode in [TransportMode.STEGANOGRAPHIC, TransportMode.HYBRID]:
                    self.transport_stats["steganographic_bytes"] += len(data)

            return success

        except Exception as e:
            self.logger.error(f"Failed to send data on connection {connection_id}: {e}")
            return False

    async def _send_direct_data(self, connection: dict, data: bytes) -> bool:
        """Send data through direct connection."""
        if connection["type"] == "tcp":
            writer = connection["writer"]
            writer.write(data)
            await writer.drain()
            return True
        elif connection["type"] == "udp":
            sock = connection["socket"]
            sock.send(data)
            return True

        return False

    async def receive_data(self, connection_id: str, timeout: float = 5.0) -> Optional[bytes]:
        """Receive data from connection."""
        if connection_id not in self.active_connections:
            return None

        conn_info = self.active_connections[connection_id]
        mode = conn_info["mode"]
        connection = conn_info["connection"]

        try:
            if mode == TransportMode.DIRECT:
                data = await self._receive_direct_data(connection, timeout)
            elif mode == TransportMode.STEGANOGRAPHIC:
                if not self._steganography_enabled:
                    data = await self._receive_direct_data(connection, timeout)
                else:
                    data = await self.stego_channels.receive_data()
            elif mode == TransportMode.METADATA:
                data = await self.metadata_channels.receive_control_signal(timeout=timeout)
            else:  # HYBRID
                if not self._steganography_enabled:
                    data = await self._receive_direct_data(connection, timeout)
                else:
                    data = await self.stego_channels.receive_data()

            if data:
                self.transport_stats["packets_received"] += 1

            return data

        except Exception as e:
            self.logger.error(f"Failed to receive data on connection {connection_id}: {e}")
            return None

    async def _receive_direct_data(self, connection: dict, timeout: float) -> Optional[bytes]:
        """Receive data from direct connection."""
        if connection["type"] == "tcp":
            reader = connection["reader"]
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                return data if data else None
            except asyncio.TimeoutError:
                return None

        # UDP receive would require more complex implementation
        return None

    async def close_connection(self, connection_id: str):
        """Close connection and cleanup resources."""
        if connection_id not in self.active_connections:
            return

        conn_info = self.active_connections[connection_id]
        connection = conn_info["connection"]

        try:
            if conn_info["mode"] == TransportMode.DIRECT:
                await self._close_direct_connection(connection)

            del self.active_connections[connection_id]
            self.logger.info(f"Closed connection {connection_id}")

        except Exception as e:
            self.logger.error(f"Error closing connection {connection_id}: {e}")

    async def _close_direct_connection(self, connection: dict):
        """Close direct connection."""
        if connection["type"] == "tcp":
            writer = connection["writer"]
            writer.close()
            await writer.wait_closed()
        elif connection["type"] == "udp":
            sock = connection["socket"]
            sock.close()

    async def set_aggressiveness(self, value: float) -> None:
        """Adjust how aggressive the transport layer should behave."""
        self._aggressiveness = max(0.0, min(1.0, float(value)))
        if self._aggressiveness > 0.75:
            await self.enable_protocol_hopping()
        self.logger.debug("Transport aggressiveness set to %.2f", self._aggressiveness)

    async def enable_protocol_hopping(self) -> None:
        """Ensure port/protocol hopping remains active."""
        self.config.enable_hopping = True
        self.logger.debug("Protocol hopping enabled")

    async def enable_steganography(self) -> None:
        """Allow the transport to use steganography-based channels."""
        self._steganography_enabled = True
        self.logger.debug("Steganography enabled")

    async def disable_steganography(self) -> None:
        """Disable steganographic channels (falls back to direct mode)."""
        self._steganography_enabled = False
        self.logger.debug("Steganography disabled")

    async def minimize_traffic_signature(self) -> None:
        """Bias internals towards lower-observable footprints."""
        self._traffic_signature_minimized = True
        self.logger.debug("Traffic signature minimisation activated")

    async def enable_redundancy(self) -> None:
        """Flip redundancy flag used by the control logic."""
        self._redundancy_enabled = True
        self.logger.debug("Transport redundancy enabled")

    async def get_performance_metrics(self) -> dict[str, Any]:
        """Expose metrics for the adaptive control loop."""
        return {
            "mode": self.config.mode.name,
            "packets_sent": self.transport_stats["packets_sent"],
            "packets_received": self.transport_stats["packets_received"],
            "steganography_enabled": self._steganography_enabled,
            "aggressiveness": self._aggressiveness,
            "hopping_enabled": self.config.enable_hopping,
        }

    def adapt_to_conditions(self, network_conditions: dict[str, Any]):
        """Adapt transport strategy based on network conditions."""
        threat_level = network_conditions.get("threat_level", "low")
        packet_loss = network_conditions.get("packet_loss", 0.0)
        latency = network_conditions.get("latency", 0.0)

        if threat_level == "high":
            self.config.mode = TransportMode.STEGANOGRAPHIC
            self.config.enable_hopping = True
            self.config.hop_interval = 10.0  # Faster hopping
        elif packet_loss > 0.1:
            self.config.mode = TransportMode.METADATA  # More reliable
        elif latency > 0.2:
            self.config.mode = TransportMode.DIRECT  # Fastest
        else:
            self.config.mode = TransportMode.HYBRID  # Best of both

        self.logger.info(f"Adapted to {self.config.mode.name} mode based on conditions")

    def get_statistics(self) -> dict[str, Any]:
        """Get transport layer statistics."""
        return {
            "active_connections": len(self.active_connections),
            "transport_mode": self.config.mode.name,
            "hopping_enabled": self.config.enable_hopping,
            "stats": self.transport_stats.copy(),
            "channel_info": {
                "steganographic": self.stego_channels.get_channel_info(),
                "metadata": self.metadata_channels.get_channel_info(),
            },
            "aggressiveness": self._aggressiveness,
            "steganography_enabled": self._steganography_enabled,
        }

    def get_status(self) -> dict[str, Any]:
        """Alias for get_statistics for compatibility."""
        return self.get_statistics()

    def get_performance_metrics(self) -> dict[str, float]:
        """Return lightweight performance metrics for adaptive control."""
        return {
            "avg_latency": 0.0,
            "throughput": 0.0,
            "success_rate": 1.0,
            "aggressiveness": self._aggressiveness,
        }

    def get_status(self) -> dict[str, Any]:
        """Provide a richer snapshot for user-facing status commands."""
        return {
            "mode": self.config.mode.name,
            "active_connections": len(self.active_connections),
            "hopping_enabled": self.config.enable_hopping,
            "steganography_enabled": self._steganography_enabled,
            "redundancy_enabled": self._redundancy_enabled,
            "aggressiveness": self._aggressiveness,
            "traffic_signature_minimized": self._traffic_signature_minimized,
            "statistics": self.transport_stats.copy(),
        }
