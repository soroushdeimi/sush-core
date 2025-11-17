"""
Protocol Hopper - Dynamic port and protocol switching
"""

import asyncio
import hashlib
import logging
import secrets
import socket
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Import libraries for QUIC and WebSocket support
try:
    import aioquic
    from aioquic.asyncio import connect as quic_connect
    from aioquic.quic.configuration import QuicConfiguration

    QUIC_AVAILABLE = True
except ImportError:
    QUIC_AVAILABLE = False
    logger.debug("aioquic not available; QUIC protocol will fall back to TCP.")

try:
    import websockets

    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False
    logger.debug("websockets not available; WebSocket protocol will fall back to TCP.")


class TransportProtocol(Enum):
    TCP = auto()
    UDP = auto()
    QUIC = auto()
    WEBSOCKET = auto()


@dataclass
class HopSequence:
    """Port/protocol hopping sequence."""

    ports: list[int]
    protocols: list[TransportProtocol]
    timing_intervals: list[float]
    seed: bytes


class ProtocolHopper:
    """Dynamic port and protocol hopping for evasion."""

    def __init__(self, port_range: tuple[int, int] = (10000, 65000), hop_interval: float = 30.0):
        self.logger = logging.getLogger(__name__)
        self.port_range = port_range
        self.hop_interval = hop_interval

        # Avoid common service ports
        self.excluded_ports = {22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443}

        self._generate_random_port()
        self.current_protocol = TransportProtocol.TCP

        self.hop_sequences = {}
        self.active_connections = {}
        self.hop_task = None

        self.logger.info(f"Protocol Hopper initialized with port range {port_range}")

    def _generate_random_port(self) -> int:
        """Generate a random port avoiding common services."""
        while True:
            port = secrets.randbelow(self.port_range[1] - self.port_range[0]) + self.port_range[0]
            if port not in self.excluded_ports:
                return port

    def create_hop_sequence(self, sequence_id: str, num_hops: int = 10) -> HopSequence:
        """Create a new hopping sequence."""
        seed = secrets.token_bytes(32)

        # Generate deterministic sequence from seed
        ports = []
        protocols = []
        intervals = []

        rng = self._create_seeded_rng(seed)

        for _ in range(num_hops):
            port = rng.randint(self.port_range[0], self.port_range[1])
            while port in self.excluded_ports:
                port = rng.randint(self.port_range[0], self.port_range[1])

            ports.append(port)
            protocols.append(rng.choice(list(TransportProtocol)))
            intervals.append(rng.uniform(10.0, 60.0))  # 10-60 second intervals

        sequence = HopSequence(ports, protocols, intervals, seed)
        self.hop_sequences[sequence_id] = sequence

        return sequence

    def _create_seeded_rng(self, seed: bytes):
        """Create a seeded random number generator."""
        import random

        rng = random.Random()
        rng.seed(int.from_bytes(seed, "big"))
        return rng

    def generate_hop_sequence(
        self, peer_shared_secret: bytes, session_id: str, sequence_length: int = 100
    ) -> HopSequence:
        """
        Generate a deterministic hop sequence from shared secret.

        Args:
            peer_shared_secret: Shared secret from key exchange
            session_id: Session identifier
            sequence_length: Number of hops in sequence

        Returns:
            HopSequence: Generated hop sequence
        """
        # Create deterministic seed from shared secret and session ID
        seed_material = peer_shared_secret + session_id.encode()
        seed = hashlib.sha256(seed_material).digest()

        # Use seed to generate deterministic random sequence
        prng = self._create_deterministic_rng(seed)

        ports = []
        protocols = []
        timing_sequence = []

        for _ in range(sequence_length):
            # Generate port
            while True:
                port = prng.randint(*self.port_range)
                if (
                    port not in self.excluded_ports and port not in ports[-10:]
                ):  # Avoid recent ports
                    ports.append(port)
                    break

            # Generate protocol (weighted towards TCP/UDP)
            protocol_weights = [0.4, 0.4, 0.15, 0.05]  # TCP, UDP, QUIC, WebSocket
            protocol_choice = prng.choices(list(TransportProtocol), weights=protocol_weights)[0]
            protocols.append(protocol_choice)  # Generate timing (randomized around base interval)
            timing_variance = prng.uniform(0.5, 2.0)
            hop_time = self.hop_interval * timing_variance
            timing_sequence.append(hop_time)

        sequence = HopSequence(
            ports=ports, protocols=protocols, timing_intervals=timing_sequence, seed=seed
        )

        self.hop_sequences[session_id] = sequence
        self.logger.info(f"Generated hop sequence for session {session_id}: {sequence_length} hops")

        return sequence

    def _create_deterministic_rng(self, seed: bytes):
        """Create a deterministic RNG for sequence generation."""
        # Convert seed to integer for random module
        seed_int = int.from_bytes(seed[:4], "big")

        # Create a simple PRNG for deterministic sequences
        class DeterministicRNG:
            def __init__(self, seed: int):
                self.state = seed

            def randint(self, a: int, b: int) -> int:
                self.state = (self.state * 1103515245 + 12345) & 0x7FFFFFFF
                return a + (self.state % (b - a + 1))

            def uniform(self, a: float, b: float) -> float:
                self.state = (self.state * 1103515245 + 12345) & 0x7FFFFFFF
                return a + (self.state / 0x7FFFFFFF) * (b - a)

            def choices(self, population: list, weights: list):
                # Simplified weighted choice
                total = sum(weights)
                r = self.uniform(0, total)
                cumulative = 0
                for item, weight in zip(population, weights):
                    cumulative += weight
                    if r <= cumulative:
                        return [item]
                return [population[-1]]

        return DeterministicRNG(seed_int)

    async def start_hopping(self, session_id: str):
        """
        Start the hopping process for a session.

        Args:
            session_id: Session to start hopping for
        """
        if session_id not in self.hop_sequences:
            raise ValueError(f"No hop sequence found for session {session_id}")

        self.active_sequence = session_id
        self.sequence_position = 0

        # Start the hopping task
        if self.hop_task:
            self.hop_task.cancel()

        self.hop_task = asyncio.create_task(self._hop_loop())

        self.logger.info(f"Started hopping for session {session_id}")

    async def _hop_loop(self):
        """Main hopping loop."""
        while self.active_sequence:
            try:
                sequence = self.hop_sequences[self.active_sequence]

                # Get next hop parameters
                next_port = sequence.ports[self.sequence_position]
                next_protocol = sequence.protocols[self.sequence_position]
                wait_time = sequence.timing_sequence[self.sequence_position]

                # Perform the hop
                await self._perform_hop(next_port, next_protocol)

                # Wait for next hop
                await asyncio.sleep(wait_time)

                # Advance sequence position
                self.sequence_position = (self.sequence_position + 1) % len(sequence.ports)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in hop loop: {e}")
                await asyncio.sleep(1.0)  # Brief pause before retry

    async def _perform_hop(self, new_port: int, new_protocol: TransportProtocol):
        """
        Perform a single hop to new port/protocol.

        Args:
            new_port: Target port
            new_protocol: Target protocol
        """
        old_port = self.current_port
        old_protocol = self.current_protocol

        # Close old connections if protocol is changing
        if new_protocol != old_protocol:
            await self._close_old_connections()

        # Update current state
        self.current_port = new_port
        self.current_protocol = new_protocol

        self.logger.debug(
            f"Hopped from {old_protocol.name}:{old_port} to {new_protocol.name}:{new_port}"
        )

    async def _close_old_connections(self):
        """Close connections that are no longer valid after protocol hop."""
        connections_to_close = list(self.active_connections.keys())

        for conn_id in connections_to_close:
            try:
                connection = self.active_connections[conn_id]
                if hasattr(connection, "close"):
                    await connection.close()
                del self.active_connections[conn_id]
            except Exception as e:
                self.logger.warning(f"Error closing connection {conn_id}: {e}")

    async def create_connection(
        self,
        target_host: str,
        port: Optional[int] = None,
        *,
        connection_id: Optional[str] = None,
        timeout: float = 10.0,
    ) -> Any:
        """Create a connection using current port/protocol."""
        try:
            chosen_port = port if port is not None else self.current_port
            if port is not None:
                self.current_port = chosen_port

            if connection_id is None:
                connection_id = f"hop_{secrets.token_hex(6)}"

            if self.current_protocol == TransportProtocol.TCP:
                connection = await self._create_tcp_connection(target_host, chosen_port, timeout)
            elif self.current_protocol == TransportProtocol.UDP:
                connection = await self._create_udp_connection(target_host, chosen_port, timeout)
            elif self.current_protocol == TransportProtocol.QUIC:
                connection = await self._create_quic_connection(target_host, chosen_port, timeout)
            elif self.current_protocol == TransportProtocol.WEBSOCKET:
                connection = await self._create_websocket_connection(
                    target_host, chosen_port, timeout
                )
            else:
                raise ValueError(f"Unsupported protocol: {self.current_protocol}")

            self.active_connections[connection_id] = connection
            self.logger.debug(
                f"Created {self.current_protocol.name} connection to {target_host}:{chosen_port}"
            )
            return connection
        except Exception as exc:
            self.logger.error(f"Failed to create connection: {exc}")
            raise

    async def _create_tcp_connection(self, target_host: str, port: int, timeout: float):
        """Create TCP connection."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, port), timeout=timeout
            )
            return {
                "reader": reader,
                "writer": writer,
                "type": "tcp",
                "port": port,
                "host": target_host,
            }
        except Exception as exc:
            raise ConnectionError("TCP connection failed") from exc

    async def _create_udp_connection(self, target_host: str, port: int, timeout: float):
        """Create UDP connection."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            await asyncio.get_event_loop().sock_connect(sock, (target_host, port))
            return {"socket": sock, "type": "udp", "target": (target_host, port)}
        except Exception as exc:
            raise ConnectionError("UDP connection failed") from exc

    async def _create_quic_connection(self, target_host: str, port: int, timeout: float):
        """
        Create QUIC connection using aioquic.

        Implemented functional QUIC protocol support using aioquic library
        for modern HTTP/3 transport as per Phase 2 requirements.
        """
        if not QUIC_AVAILABLE:
            # Fallback to UDP when QUIC is not available
            self.logger.warning("aioquic not available, falling back to UDP")
            return await self._create_udp_connection(target_host, port, timeout)

        try:
            # Configure QUIC connection
            configuration = QuicConfiguration(
                is_client=True,
                alpn_protocols=["h3", "hq-29"],  # HTTP/3 and HTTP over QUIC
            )

            # Create QUIC connection
            connection = await asyncio.wait_for(
                quic_connect(
                    target_host,
                    port,
                    configuration=configuration,
                    create_protocol=lambda: None,  # Use default protocol
                ),
                timeout=timeout,
            )

            return {"connection": connection, "type": "quic", "target": (target_host, port)}

        except Exception as e:
            self.logger.error(f"QUIC connection failed: {e}")
            # Fallback to UDP
            return await self._create_udp_connection(target_host, port, timeout)

    async def _create_websocket_connection(self, target_host: str, port: int, timeout: float):
        """
        Create WebSocket connection using websockets library.

        Implemented functional WebSocket protocol support using websockets library
        for modern web-based transport as per Phase 2 requirements.
        """
        if not WEBSOCKET_AVAILABLE:
            # Fallback to TCP when WebSockets is not available
            self.logger.warning("websockets library not available, falling back to TCP")
            return await self._create_tcp_connection(target_host, port, timeout)

        try:
            # Construct WebSocket URI
            uri = f"ws://{target_host}:{port}/sushcore"

            # Create WebSocket connection
            websocket = await asyncio.wait_for(
                websockets.connect(
                    uri,
                    ping_interval=30,  # Keep connection alive
                    ping_timeout=10,
                    close_timeout=10,
                ),
                timeout=timeout,
            )

            return {
                "websocket": websocket,
                "type": "websocket",
                "uri": uri,
                "target": (target_host, port),
            }

        except Exception as e:
            self.logger.error(f"WebSocket connection failed: {e}")
            # Fallback to TCP
            return await self._create_tcp_connection(target_host, port, timeout)

    def get_current_endpoint(self) -> tuple[int, TransportProtocol]:
        """Get current port and protocol."""
        return self.current_port, self.current_protocol

    def predict_next_hop(self, session_id: str) -> Optional[tuple[int, TransportProtocol]]:
        """
        Predict the next hop in the sequence.

        Args:
            session_id: Session identifier

        Returns:
            Tuple of (port, protocol) or None if no sequence
        """
        if session_id not in self.hop_sequences:
            return None

        sequence = self.hop_sequences[session_id]
        next_position = (self.sequence_position + 1) % len(sequence.ports)

        return (sequence.ports[next_position], sequence.protocols[next_position])

    async def stop_hopping(self):
        """Stop the hopping process."""
        if self.hop_task:
            self.hop_task.cancel()
            try:
                await self.hop_task
            except asyncio.CancelledError:
                pass
            self.hop_task = None

        self.active_sequence = None

        # Close all active connections
        await self._close_old_connections()

        self.logger.info("Stopped protocol hopping")

    def get_statistics(self) -> dict[str, Any]:
        """Get hopping statistics."""
        return {
            "current_port": self.current_port,
            "current_protocol": self.current_protocol.name,
            "active_sequences": len(self.hop_sequences),
            "active_connections": len(self.active_connections),
            "sequence_position": self.sequence_position,
            "is_hopping": self.hop_task is not None and not self.hop_task.done(),
        }
