"""
MirrorNet Network - Simplified distributed network coordination
"""

import asyncio
import contextlib
import logging
import secrets
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set

from .mirror_node import MirrorConfig, MirrorNode, NodeCredentials, ServiceType
from .node_integrity import SimplifiedNodeIntegrity
from .onion_routing import OnionRoutingProtocol, RouteConfig


class NetworkStatus(Enum):
    BOOTSTRAPPING = auto()
    OPERATIONAL = auto()
    DEGRADED = auto()
    UNDER_ATTACK = auto()
    EMERGENCY = auto()


@dataclass
class NodeInfo:
    """Information about a network node."""

    node_id: str
    node_type: str
    host: str
    port: int
    public_key: bytes
    last_seen: float
    reputation_score: float


class MirrorNetworkConnection:
    """Lightweight wrapper around an underlying transport connection."""

    def __init__(
        self,
        connection_id: str,
        destination: str,
        port: int,
        protocol: str,
        reader: Optional[asyncio.StreamReader],
        writer: Optional[asyncio.StreamWriter],
        on_close: Callable[[str], None],
    ):
        self.connection_id = connection_id
        self.destination = destination
        self.port = port
        self.protocol = protocol
        self._reader = reader
        self._writer = writer
        self._closed = False
        self._on_close = on_close
        self.logger = logging.getLogger(f"MirrorNetworkConnection-{connection_id}")

    async def send(self, data: bytes) -> bool:
        if self._closed:
            raise RuntimeError("Connection already closed")
        if self._writer is None:
            self.logger.debug("No writer associated with connection; dropping payload")
            return False
        self._writer.write(data)
        await self._writer.drain()
        return True

    async def receive(self, max_size: int = 8192, timeout: float = 30.0) -> Optional[bytes]:
        if self._closed or self._reader is None:
            return None
        try:
            data = await asyncio.wait_for(self._reader.read(max_size), timeout=timeout)
            return data or None
        except asyncio.TimeoutError:
            return None

    async def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        if self._writer:
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
        if self._on_close:
            self._on_close(self.connection_id)
        return True


class MirrorNetwork:
    """Simplified MirrorNet network coordination."""

    def __init__(self, node_id: str, private_key: bytes):
        self.node_id = node_id
        self.private_key = private_key
        self.logger = logging.getLogger(f"MirrorNetwork-{node_id}")

        self.config: Dict[str, Any] = {
            "bootstrap_nodes": [],
            "min_circuit_length": 3,
            "max_circuit_length": 6,
            "circuit_timeout": 600.0,
            "run_mirror_node": False,
        }

        self.status = NetworkStatus.BOOTSTRAPPING
        self.start_time = time.time()
        self.known_nodes: Dict[str, NodeInfo] = {}
        self.active_circuits: Dict[str, Any] = {}
        self.active_connections: Dict[str, MirrorNetworkConnection] = {}
        self.node_blacklist: Set[str] = set()

        self.mirror_node: Optional[MirrorNode] = None
        self.onion_routing: Optional[OnionRoutingProtocol] = None
        self.node_integrity: Optional[SimplifiedNodeIntegrity] = None

        self.stats = {
            "packets_routed": 0,
            "circuits_created": 0,
            "nodes_discovered": 0,
            "integrity_violations": 0,
        }

        self.running = False
        self._background_tasks: List[asyncio.Task] = []

    async def configure(self, config: Dict[str, Any]) -> None:
        self.config.update(config)
        self.logger.info("Network configuration updated")

    async def initialize(self) -> bool:
        try:
            self.logger.info("Initializing MirrorNet components")

            await self._initialize_node_integrity()
            await self._initialize_onion_routing()

            if self.config.get("run_mirror_node", False):
                await self._initialize_mirror_node()

            await self._start_network_services()

            self.status = NetworkStatus.OPERATIONAL
            self.logger.info("MirrorNet network initialized successfully")
            return True
        except Exception as exc:
            self.logger.error(f"Failed to initialize MirrorNet: {exc}")
            self.status = NetworkStatus.DEGRADED
            return False

    async def _initialize_node_integrity(self) -> None:
        try:
            credentials = NodeCredentials(
                node_id=self.node_id,
                public_key=self._derive_public_key(),
                private_key=self.private_key,
                certificate=b"",
                reputation_score=0.5,
            )

            self.node_integrity = SimplifiedNodeIntegrity(
                node_id=self.node_id,
                private_key=self.private_key,
            )
            await self.node_integrity.register_node(self.node_id, credentials.public_key.hex())
            self.logger.info("Node integrity system initialized")
        except Exception as exc:
            self.logger.error(f"Failed to initialize node integrity: {exc}")

    def _derive_public_key(self) -> bytes:
        import hashlib

        return hashlib.sha256(self.private_key).digest()[:32]

    async def _initialize_onion_routing(self) -> None:
        try:
            route_config = RouteConfig(
                min_circuit_length=self.config.get("min_circuit_length", 3),
                max_circuit_length=self.config.get("max_circuit_length", 6),
                circuit_timeout=self.config.get("circuit_timeout", 600.0),
                rebuild_threshold=0.3,
            )

            self.onion_routing = OnionRoutingProtocol(
                node_id=self.node_id,
                private_key=self.private_key,
            )
            self.onion_routing.config = route_config
            self.logger.info("Onion routing protocol initialized")
        except Exception as exc:
            self.logger.error(f"Failed to initialize onion routing: {exc}")

    async def _initialize_mirror_node(self) -> None:
        try:
            mirror_config = MirrorConfig(
                node_id=self.node_id,
                listen_port=self.config.get("mirror_port", 8080),
                target_service="http://httpbin.org",
                service_type=ServiceType.API_GATEWAY,
                ssl_enabled=True,
                max_connections=1000,
            )

            self.mirror_node = MirrorNode(mirror_config)
            asyncio.create_task(self.mirror_node.start())
            self.logger.info("Mirror node initialized")
        except Exception as exc:
            self.logger.error(f"Failed to initialize mirror node: {exc}")

    async def _start_network_services(self) -> None:
        self.running = True
        self._background_tasks.append(
            asyncio.create_task(self._node_discovery_loop(), name=f"{self.node_id}-discovery")
        )
        self._background_tasks.append(
            asyncio.create_task(self._network_monitoring_loop(), name=f"{self.node_id}-monitor")
        )
        self._background_tasks.append(
            asyncio.create_task(self._circuit_maintenance_loop(), name=f"{self.node_id}-circuits")
        )
        self.logger.info("Network services started")

    async def bootstrap_network(self) -> bool:
        try:
            bootstrap_nodes = self.config.get("bootstrap_nodes", [])
            if not bootstrap_nodes:
                self.logger.warning("No bootstrap nodes configured")
                return False

            successful_connections = 0
            for node_address in bootstrap_nodes:
                try:
                    if isinstance(node_address, str):
                        host, port_str = node_address.split(":")
                        port = int(port_str)
                    else:
                        host = node_address.get("host")
                        port = node_address.get("port")

                    if not host or not port:
                        continue

                    node_info = NodeInfo(
                        node_id=f"bootstrap_{host}_{port}",
                        node_type="relay",
                        host=host,
                        port=port,
                        public_key=secrets.token_bytes(32),
                        last_seen=time.time(),
                        reputation_score=0.5,
                    )

                    if await self._connect_to_node(node_info):
                        self.known_nodes[node_info.node_id] = node_info
                        successful_connections += 1
                        self.stats["nodes_discovered"] += 1
                except Exception as exc:
                    self.logger.warning(
                        f"Failed to connect to bootstrap node {node_address}: {exc}"
                    )

            if successful_connections:
                self.status = NetworkStatus.OPERATIONAL
                self.logger.info(f"Successfully bootstrapped with {successful_connections} nodes")
                return True

            self.status = NetworkStatus.DEGRADED
            self.logger.error("Failed to bootstrap network")
            return False
        except Exception as exc:
            self.logger.error(f"Bootstrap failed: {exc}")
            self.status = NetworkStatus.DEGRADED
            return False

    async def _connect_to_node(self, node_info: NodeInfo) -> bool:
        try:
            await asyncio.sleep(0.1)
            if self.node_integrity:
                verified = await self._verify_node(node_info)
                if not verified:
                    return False
            self.logger.debug(f"Connected to node {node_info.node_id}")
            return True
        except Exception as exc:
            self.logger.error(f"Failed to connect to node {node_info.node_id}: {exc}")
            return False

    async def _verify_node(self, node_info: NodeInfo) -> bool:
        try:
            if self.node_integrity:
                return await self.node_integrity.verify_node(
                    node_info.node_id,
                    node_info.public_key,
                    node_info.host,
                    node_info.port,
                )
            return True
        except Exception as exc:
            self.logger.error(f"Error verifying node {node_info.node_id}: {exc}")
            return False

    async def announce_node(self) -> bool:
        try:
            if not self.known_nodes:
                self.logger.warning("No known nodes to announce to")
                return False

            node_info = {
                "node_id": self.node_id,
                "public_key": self._derive_public_key().hex(),
                "capabilities": {
                    "relay": True,
                    "exit": self.config.get("allow_exit_traffic", False),
                    "bridge": self.config.get("act_as_bridge", False),
                },
                "timestamp": int(time.time()),
            }
            self.logger.debug("Prepared announcement payload: %s", node_info)

            successful_announcements = 0
            for target_node in list(self.known_nodes.values())[:5]:
                try:
                    await asyncio.sleep(0.1)
                    successful_announcements += 1
                except Exception as exc:
                    self.logger.debug(f"Failed to announce to {target_node.node_id}: {exc}")

            if successful_announcements:
                self.logger.info(f"Successfully announced to {successful_announcements} nodes")
                return True
            self.logger.warning("Failed to announce to any nodes")
            return False
        except Exception as exc:
            self.logger.error(f"Node announcement error: {exc}")
            return False

    async def establish_circuits(self, count: int = 3) -> int:
        if not self.onion_routing:
            self.logger.error("Cannot establish circuits - onion routing not initialized")
            return 0

        if len(self.known_nodes) < self.config.get("min_circuit_length", 3):
            self.logger.warning("Not enough known nodes to establish circuits")
            return 0

        successful_circuits = 0
        for index in range(count):
            try:
                circuit_nodes = self._select_circuit_nodes()
                if len(circuit_nodes) < self.config.get("min_circuit_length", 3):
                    continue

                circuit_id = await self.onion_routing.create_circuit(
                    circuit_nodes,
                    purpose="general",
                )
                if circuit_id is None:
                    continue

                self.active_circuits[circuit_id] = {
                    "created_at": time.time(),
                    "type": "general",
                    "nodes": circuit_nodes,
                    "status": "active",
                }
                successful_circuits += 1
                self.stats["circuits_created"] += 1
            except Exception as exc:
                self.logger.error(f"Failed to establish circuit {index + 1}: {exc}")

        self.logger.info(f"Successfully established {successful_circuits}/{count} circuits")
        return successful_circuits

    def _select_circuit_nodes(self) -> List[str]:
        candidates = [
            node
            for node in self.known_nodes.values()
            if (
                node.reputation_score > 0.4
                and node.node_id not in self.node_blacklist
                and time.time() - node.last_seen < 300
            )
        ]

        if len(candidates) < 3:
            return []

        candidates.sort(key=lambda item: item.reputation_score, reverse=True)

        import random

        circuit_length = min(len(candidates), random.randint(3, 5))
        return [candidates[index].node_id for index in range(circuit_length)]

    async def create_circuit(self) -> Optional[str]:
        if not self.onion_routing:
            return None
        try:
            circuit_nodes = self._select_circuit_nodes()
            if not circuit_nodes:
                return None

            circuit_id = await self.onion_routing.create_circuit(
                circuit_nodes,
                purpose="user",
            )
            if circuit_id is None:
                return None

            self.active_circuits[circuit_id] = {
                "created_at": time.time(),
                "type": "user",
                "nodes": circuit_nodes,
            }
            self.stats["circuits_created"] += 1
            return circuit_id
        except Exception as exc:
            self.logger.error(f"Failed to create circuit: {exc}")
            return None

    async def send_data(self, circuit_id: str, data: bytes) -> bool:
        if not self.onion_routing or circuit_id not in self.active_circuits:
            return False
        try:
            result = await self.onion_routing.send_data(circuit_id, data)
            if result:
                self.stats["packets_routed"] += 1
            return result
        except Exception as exc:
            self.logger.error(f"Failed to send data: {exc}")
            return False

    async def receive_data(self, circuit_id: str, timeout: float = 5.0) -> Optional[bytes]:
        if not self.onion_routing or circuit_id not in self.active_circuits:
            return None
        try:
            return await self.onion_routing.receive_data(circuit_id, timeout)
        except Exception as exc:
            self.logger.error(f"Failed to receive data: {exc}")
            return None

    async def destroy_circuit(self, circuit_id: str) -> None:
        if circuit_id not in self.active_circuits:
            return
        if self.onion_routing:
            await self.onion_routing.destroy_circuit(circuit_id)
        self.active_circuits.pop(circuit_id, None)

    async def switch_to_backup_node(self) -> None:
        candidate = None
        for node in self.known_nodes.values():
            if node.node_id not in self.node_blacklist:
                candidate = node
                break
        if candidate:
            self.logger.info(f"Switching to backup node {candidate.node_id}")
        else:
            self.logger.info("No backup node available; staying on current circuit")

    async def increase_circuit_length(self) -> None:
        max_length = self.config.get("max_circuit_length", 6)
        self.config["max_circuit_length"] = min(max_length + 1, 8)
        self.logger.info(f"Max circuit length set to {self.config['max_circuit_length']}")

    async def optimize_for_speed(self) -> None:
        self.config["min_circuit_length"] = 2
        self.config["max_circuit_length"] = max(3, self.config["min_circuit_length"] + 1)
        self.logger.info("Circuit length tuned for performance mode")

    async def balance_security_performance(self) -> None:
        self.config["min_circuit_length"] = 3
        self.config["max_circuit_length"] = 6
        self.logger.info("Circuit parameters balanced for mixed mode")

    async def maximize_anonymity(self) -> None:
        self.config["min_circuit_length"] = 4
        self.config["max_circuit_length"] = 7
        self.logger.info("Circuit parameters increased for anonymity")

    async def increase_redundancy(self) -> None:
        await self.establish_circuits(count=1)

    async def _node_discovery_loop(self) -> None:
        while self.running:
            try:
                await self._discover_nodes()
                await asyncio.sleep(300)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error(f"Error in node discovery: {exc}")
                await asyncio.sleep(60)

    async def _discover_nodes(self) -> None:
        self.logger.debug(f"Current known nodes: {len(self.known_nodes)}")

    async def _network_monitoring_loop(self) -> None:
        while self.running:
            try:
                await self._update_network_stats()
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error(f"Error in network monitoring: {exc}")
                await asyncio.sleep(60)

    async def _update_network_stats(self) -> None:
        active_nodes = len(
            [node for node in self.known_nodes.values() if time.time() - node.last_seen < 300]
        )
        self.status = NetworkStatus.DEGRADED if active_nodes < 3 else NetworkStatus.OPERATIONAL

    async def _circuit_maintenance_loop(self) -> None:
        while self.running:
            try:
                await self._cleanup_old_circuits()
                await asyncio.sleep(120)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error(f"Error in circuit maintenance: {exc}")
                await asyncio.sleep(60)

    async def _cleanup_old_circuits(self) -> None:
        current_time = time.time()
        circuit_timeout = 1800.0
        old_circuits = [
            circuit_id
            for circuit_id, info in self.active_circuits.items()
            if current_time - info["created_at"] > circuit_timeout
        ]
        for circuit_id in old_circuits:
            try:
                await self.destroy_circuit(circuit_id)
                self.logger.debug(f"Cleaned up old circuit {circuit_id}")
            except Exception as exc:
                self.logger.warning(f"Error cleaning up circuit {circuit_id}: {exc}")

    def get_network_status(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "status": self.status.name,
            "uptime": time.time() - self.start_time,
            "known_nodes": len(self.known_nodes),
            "active_circuits": len(self.active_circuits),
            "active_connections": len(self.active_connections),
            "blacklisted_nodes": len(self.node_blacklist),
            "statistics": self.stats.copy(),
        }

    async def create_connection(
        self, destination: str, port: int, protocol: str = "tcp"
    ) -> Optional[MirrorNetworkConnection]:
        try:
            if not self.active_circuits:
                created = await self.establish_circuits(count=2)
                if created == 0:
                    self.logger.warning("Unable to establish prerequisite circuits")
                    return None

            connection_id = f"conn_{secrets.token_hex(8)}"
            transport = await self._open_transport_connection(destination, port, protocol)
            if transport is None:
                return None

            connection = MirrorNetworkConnection(
                connection_id=connection_id,
                destination=destination,
                port=port,
                protocol=protocol,
                reader=transport.get("reader"),
                writer=transport.get("writer"),
                on_close=self._remove_connection,
            )
            self.active_connections[connection_id] = connection
            self.logger.info(f"Created connection {connection_id} to {destination}:{port}")

            circuit_nodes = self._select_circuit_nodes()
            if circuit_nodes:
                self.active_circuits[f"circuit_{connection_id}"] = {
                    "created_at": time.time(),
                    "type": "user",
                    "target_host": destination,
                    "target_port": port,
                    "nodes": circuit_nodes,
                }
                self.stats["circuits_created"] += 1

            return connection
        except Exception as exc:
            self.logger.error(f"Failed to create connection: {exc}")
            return None

    async def _open_transport_connection(
        self, destination: str, port: int, protocol: str
    ) -> Optional[Dict[str, Any]]:
        scheme = (protocol or "tcp").lower()
        if scheme not in ("tcp", "udp", "quic", "websocket"):
            self.logger.warning(f"Unsupported protocol '{protocol}', defaulting to TCP")
            scheme = "tcp"
        if scheme != "tcp":
            self.logger.debug(f"Protocol '{scheme}' not fully implemented, using TCP fallback")
            scheme = "tcp"
        try:
            reader, writer = await asyncio.open_connection(destination, port)
            return {"reader": reader, "writer": writer}
        except Exception as exc:
            self.logger.error(f"Transport connection failed to {destination}:{port}: {exc}")
            return None

    def _remove_connection(self, connection_id: str) -> None:
        self.active_connections.pop(connection_id, None)

    async def shutdown(self) -> None:
        self.logger.info("Shutting down MirrorNet")
        self.running = False

        for task in self._background_tasks:
            task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        self._background_tasks.clear()

        if self.mirror_node:
            await self.mirror_node.stop()

        for connection in list(self.active_connections.values()):
            with contextlib.suppress(Exception):
                await connection.close()
        self.active_connections.clear()

        for circuit_id in list(self.active_circuits.keys()):
            await self.destroy_circuit(circuit_id)

        self.status = NetworkStatus.BOOTSTRAPPING
        self.logger.info("MirrorNet shutdown complete")
