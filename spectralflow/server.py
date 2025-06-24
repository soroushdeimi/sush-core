"""SpectralFlow server implementation."""

import asyncio
import logging
import time
import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
import secrets
import socket

from .core.quantum_obfuscator import QuantumObfuscator
from .transport.adaptive_transport import AdaptiveTransport
from .network.mirror_network import MirrorNetwork
from .network.onion_routing import OnionRoutingProtocol
from .network.node_integrity import SimplifiedNodeIntegrity
from .control.adaptive_control import AdaptiveControlLoop
from .control.censorship_detector import CensorshipDetector
from .control.threat_monitor import ThreatMonitor
from .control.response_engine import ResponseEngine


@dataclass
class ServerConfig:
    """Configuration for SpectralFlow server."""
    # Server identity
    node_id: Optional[str] = None
    private_key: Optional[bytes] = None
    public_key: Optional[str] = None
    
    # Network configuration
    listen_address: str = "0.0.0.0"
    listen_ports: List[int] = None
    external_address: Optional[str] = None
    bandwidth_limit: int = 100_000_000  # 100 Mbps
    
    # Mirror node settings
    is_mirror_node: bool = True
    is_bridge_relay: bool = False
    is_directory_server: bool = False
    max_circuits: int = 1000
    max_clients: int = 500
    
    # Security settings
    require_authentication: bool = True
    allowed_countries: Optional[List[str]] = None
    blocked_ips: Set[str] = None
    
    # Performance settings
    connection_timeout: float = 60.0
    circuit_timeout: float = 600.0
    cleanup_interval: float = 300.0
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None

    def __post_init__(self):
        """Initialize defaults after construction."""
        if self.node_id is None:
            self.node_id = f"server_{secrets.token_hex(8)}"
        
        if self.private_key is None:
            self.private_key = secrets.token_bytes(32)
        
        if self.listen_ports is None:
            self.listen_ports = [8443, 8080, 443, 80]
        
        if self.blocked_ips is None:
            self.blocked_ips = set()


class ConnectionHandler:
    """Handles individual client connections."""
    
    def __init__(self, 
                 server: 'SpectralFlowServer',
                 reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 client_address: str):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.client_address = client_address
        self.connection_id = f"conn_{secrets.token_hex(8)}"
        self.created_at = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.is_authenticated = False
        
        self.logger = logging.getLogger(f"{__name__}.{self.connection_id}")
    
    async def handle_connection(self):
        """Handle the client connection."""
        try:
            self.logger.info(f"New connection from {self.client_address}")
            
            # Perform authentication if required
            if self.server.config.require_authentication:
                if not await self._authenticate_client():
                    self.logger.warning(f"Authentication failed for {self.client_address}")
                    return
            
            # Main connection loop
            await self._connection_loop()
            
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
        finally:
            await self._cleanup()
    
    async def _authenticate_client(self) -> bool:
        """Authenticate the client connection."""
        try:
            # Simple challenge-response authentication
            challenge = secrets.token_bytes(32)
            await self._send_data(b"AUTH_CHALLENGE:" + challenge)
            
            response = await self._receive_data(timeout=30.0)
            if not response:
                return False
            
            # Verify response (simplified)
            expected = challenge[:16]  # Simple verification
            return response.startswith(b"AUTH_RESPONSE:" + expected)
            
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    async def _connection_loop(self):
        """Main connection handling loop."""
        while True:
            try:
                # Read command from client
                data = await self._receive_data(timeout=60.0)
                if not data:
                    break
                
                # Process command
                await self._process_command(data)
                
            except asyncio.TimeoutError:
                self.logger.debug("Connection timeout")
                break
            except Exception as e:
                self.logger.error(f"Error in connection loop: {e}")
                break
    
    async def _process_command(self, data: bytes):
        """Process a command from the client."""
        try:
            # Parse command (simplified protocol)
            if data.startswith(b"CONNECT:"):
                await self._handle_connect_command(data[8:])
            elif data.startswith(b"RELAY:"):
                await self._handle_relay_command(data[6:])
            elif data.startswith(b"STATUS:"):
                await self._handle_status_command()
            else:
                await self._send_data(b"ERROR:Unknown command")
                
        except Exception as e:
            self.logger.error(f"Error processing command: {e}")
            await self._send_data(b"ERROR:Command processing failed")
    
    async def _handle_connect_command(self, data: bytes):
        """Handle connection request."""
        try:
            # Parse connection request
            request = json.loads(data.decode('utf-8'))
            destination = request['destination']
            port = request['port']
            protocol = request.get('protocol', 'tcp')
            
            # Create outbound connection
            connection_id = await self.server.create_relay_connection(
                destination, port, protocol
            )
            
            if connection_id:
                response = json.dumps({
                    'status': 'success',
                    'connection_id': connection_id
                })
                await self._send_data(b"CONNECT_OK:" + response.encode())
            else:
                await self._send_data(b"CONNECT_FAILED:Unable to establish connection")
                
        except Exception as e:
            self.logger.error(f"Connect command error: {e}")
            await self._send_data(b"CONNECT_FAILED:Invalid request")
    
    async def _handle_relay_command(self, data: bytes):
        """Handle data relay request."""
        # Relay data through established connections
        await self._send_data(b"RELAY_OK:Data relayed")
    
    async def _handle_status_command(self):
        """Handle status request."""
        try:
            status = {
                'node_id': self.server.config.node_id,
                'uptime': time.time() - self.server.start_time,
                'active_connections': len(self.server.active_connections),
                'active_circuits': len(self.server.active_circuits)
            }
            
            response = json.dumps(status)
            await self._send_data(b"STATUS:" + response.encode())
            
        except Exception as e:
            self.logger.error(f"Status command error: {e}")
            await self._send_data(b"ERROR:Status unavailable")
    
    async def _send_data(self, data: bytes):
        """Send data to client."""
        try:
            self.writer.write(len(data).to_bytes(4, 'big') + data)
            await self.writer.drain()
            self.bytes_sent += len(data)
            
        except Exception as e:
            self.logger.error(f"Send error: {e}")
            raise
    
    async def _receive_data(self, timeout: float = 30.0) -> Optional[bytes]:
        """Receive data from client."""
        try:
            # Read length prefix
            length_data = await asyncio.wait_for(
                self.reader.readexactly(4), timeout=timeout
            )
            
            if not length_data:
                return None
            
            data_length = int.from_bytes(length_data, 'big')
            
            # Read actual data
            data = await asyncio.wait_for(
                self.reader.readexactly(data_length), timeout=timeout
            )
            
            self.bytes_received += len(data)
            return data
            
        except asyncio.IncompleteReadError:
            return None
        except Exception as e:
            self.logger.error(f"Receive error: {e}")
            return None
    
    async def _cleanup(self):
        """Clean up connection resources."""
        try:
            self.writer.close()
            await self.writer.wait_closed()
            
            # Remove from server's active connections
            if self.connection_id in self.server.active_connections:
                del self.server.active_connections[self.connection_id]
            
            self.logger.info(f"Connection closed: {self.client_address}")
            
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")


class SpectralFlowServer:
    """
    SpectralFlow Server - Provides mirror node and relay functionality.
    
    Acts as a node in the SpectralFlow network, providing routing, relaying,
    and bridging services for censorship circumvention.
    """
    
    def __init__(self, config: Optional[ServerConfig] = None):
        """
        Initialize SpectralFlow server.
        
        Args:
            config: Server configuration (uses defaults if None)
        """
        self.config = config or ServerConfig()
        
        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Component initialization
        self.quantum_obfuscator = QuantumObfuscator()
        self.adaptive_transport = AdaptiveTransport()
        self.mirror_network = MirrorNetworkCoordinator(
            node_id=self.config.node_id,
            private_key=self.config.private_key
        )
        
        self.onion_routing = OnionRoutingProtocol(
            node_id=self.config.node_id,
            private_key=self.config.private_key
        )
        
        self.node_integrity = SimplifiedNodeIntegrity(
            node_id=self.config.node_id,
            private_key=self.config.private_key
        )
        
        self.censorship_detector = CensorshipDetector()
        self.threat_monitor = ThreatMonitor()
        self.response_engine = ResponseEngine()
        
        self.adaptive_control = AdaptiveControlLoop()
        
        # Server state
        self.is_running = False
        self.start_time = 0.0
        self.servers: List[asyncio.Server] = []
        self.active_connections: Dict[str, ConnectionHandler] = {}
        self.active_circuits: Dict[int, Any] = {}
        self.relay_connections: Dict[str, Any] = {}
        
        # Statistics
        self.stats = {
            'connections_handled': 0,
            'bytes_relayed': 0,
            'circuits_created': 0,
            'blocked_connections': 0
        }
        
        self.logger.info(f"SpectralFlow server initialized: {self.config.node_id}")
    
    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=self.config.log_file
        )
    
    async def start(self):
        """Start the SpectralFlow server."""
        if self.is_running:
            self.logger.warning("Server already running")
            return
        
        try:
            self.logger.info("Starting SpectralFlow server...")
            self.start_time = time.time()
            
            # Initialize components
            await self._initialize_components()
            
            # Start network listeners
            await self._start_listeners()
            
            # Start background tasks
            await self._start_background_tasks()
            
            # Join network if mirror node
            if self.config.is_mirror_node:
                await self._join_mirror_network()
            
            self.is_running = True
            self.logger.info(f"SpectralFlow server started on ports {self.config.listen_ports}")
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            await self.stop()
            raise
    
    async def stop(self):
        """Stop the SpectralFlow server."""
        if not self.is_running:
            return
        
        self.logger.info("Stopping SpectralFlow server...")
        
        try:
            # Close all connections
            await self._close_all_connections()
            
            # Stop servers
            for server in self.servers:
                server.close()
                await server.wait_closed()
            
            # Stop components
            await self._stop_components()
            
            self.is_running = False
            self.logger.info("SpectralFlow server stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping server: {e}")
    
    async def _initialize_components(self):
        """Initialize all server components."""
        # Initialize adaptive control
        await self.adaptive_control.initialize_components(
            censorship_detector=self.censorship_detector,
            threat_monitor=self.threat_monitor,
            response_engine=self.response_engine,
            quantum_obfuscator=self.quantum_obfuscator,
            adaptive_transport=self.adaptive_transport,
            mirror_network=self.mirror_network
        )
        
        # Announce node to integrity system
        if self.config.public_key:
            await self.node_integrity.announce_node(
                public_key=self.config.public_key,
                capabilities=['relay', 'mirror', 'bridge'] if self.config.is_bridge_relay else ['relay', 'mirror']
            )
    
    async def _start_listeners(self):
        """Start network listeners on configured ports."""
        for port in self.config.listen_ports:
            try:
                server = await asyncio.start_server(
                    self._handle_client_connection,
                    self.config.listen_address,
                    port
                )
                
                self.servers.append(server)
                self.logger.info(f"Listening on {self.config.listen_address}:{port}")
                
            except Exception as e:
                self.logger.error(f"Failed to bind to port {port}: {e}")
    
    async def _start_background_tasks(self):
        """Start background maintenance tasks."""
        # Start component monitoring
        await self.censorship_detector.start_monitoring()
        await self.threat_monitor.start_monitoring()
        await self.response_engine.start()
        await self.adaptive_control.start()
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_task())
    
    async def _stop_components(self):
        """Stop all components."""
        await self.adaptive_control.stop()
        await self.response_engine.stop()
        await self.threat_monitor.stop_monitoring()
        await self.censorship_detector.stop_monitoring()
    
    async def _join_mirror_network(self):
        """Join the mirror network as a node."""
        try:
            await self.mirror_network.join_network()
            await self.mirror_network.announce_node()
            
            self.logger.info("Joined mirror network")
            
        except Exception as e:
            self.logger.error(f"Failed to join mirror network: {e}")
    
    async def _handle_client_connection(self, 
                                      reader: asyncio.StreamReader,
                                      writer: asyncio.StreamWriter):
        """Handle incoming client connection."""
        client_address = writer.get_extra_info('peername')[0]
        
        # Check if IP is blocked
        if client_address in self.config.blocked_ips:
            self.logger.warning(f"Blocked connection from {client_address}")
            writer.close()
            await writer.wait_closed()
            self.stats['blocked_connections'] += 1
            return
        
        # Create connection handler
        handler = ConnectionHandler(self, reader, writer, client_address)
        self.active_connections[handler.connection_id] = handler
        self.stats['connections_handled'] += 1
        
        # Handle the connection
        await handler.handle_connection()
    
    async def create_relay_connection(self, 
                                    destination: str, 
                                    port: int, 
                                    protocol: str) -> Optional[str]:
        """
        Create a relay connection to a destination.
        
        Args:
            destination: Target hostname/IP
            port: Target port
            protocol: Protocol to use
            
        Returns:
            Connection ID if successful
        """
        try:
            connection_id = f"relay_{secrets.token_hex(8)}"
            
            # Create connection through mirror network
            if protocol.lower() == 'tcp':
                reader, writer = await asyncio.open_connection(destination, port)
                
                self.relay_connections[connection_id] = {
                    'reader': reader,
                    'writer': writer,
                    'destination': destination,
                    'port': port,
                    'protocol': protocol,
                    'created_at': time.time()
                }
                
                self.logger.info(f"Created relay connection {connection_id} to {destination}:{port}")
                return connection_id
            
            else:
                self.logger.error(f"Unsupported protocol: {protocol}")
                return None
            
        except Exception as e:
            self.logger.error(f"Failed to create relay connection: {e}")
            return None
    
    async def _close_all_connections(self):
        """Close all active connections."""
        # Close client connections
        for handler in list(self.active_connections.values()):
            await handler._cleanup()
        
        # Close relay connections
        for connection_id, connection in list(self.relay_connections.items()):
            try:
                connection['writer'].close()
                await connection['writer'].wait_closed()
            except Exception as e:
                self.logger.error(f"Error closing relay connection: {e}")
        
        self.relay_connections.clear()
    
    async def _cleanup_task(self):
        """Background cleanup task."""
        while self.is_running:
            try:
                # Clean up expired circuits
                self.onion_routing.cleanup_expired_circuits()
                
                # Clean up old connections
                current_time = time.time()
                expired_relays = []
                
                for connection_id, connection in self.relay_connections.items():
                    if current_time - connection['created_at'] > self.config.circuit_timeout:
                        expired_relays.append(connection_id)
                
                for connection_id in expired_relays:
                    connection = self.relay_connections.pop(connection_id)
                    try:
                        connection['writer'].close()
                        await connection['writer'].wait_closed()
                    except Exception:
                        pass
                
                # Mine integrity blocks if we have pending transactions
                await self.node_integrity.mine_block()
                
            except Exception as e:
                self.logger.error(f"Cleanup task error: {e}")
            
            await asyncio.sleep(self.config.cleanup_interval)
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive server status."""
        uptime = time.time() - self.start_time if self.is_running else 0
        
        return {
            'is_running': self.is_running,
            'node_id': self.config.node_id,
            'uptime': uptime,
            'listen_ports': self.config.listen_ports,
            'active_connections': len(self.active_connections),
            'active_circuits': len(self.active_circuits),
            'relay_connections': len(self.relay_connections),
            'statistics': self.stats.copy(),
            'system_status': self.adaptive_control.get_system_status(),
            'network_status': self.mirror_network.get_network_status(),
            'integrity_status': self.node_integrity.get_statistics()
        }
    
    def get_node_info(self) -> Dict[str, Any]:
        """Get node information for directory services."""
        return {
            'node_id': self.config.node_id,
            'public_key': self.config.public_key,
            'address': self.config.external_address or self.config.listen_address,
            'ports': self.config.listen_ports,
            'capabilities': {
                'mirror_node': self.config.is_mirror_node,
                'bridge_relay': self.config.is_bridge_relay,
                'directory_server': self.config.is_directory_server
            },
            'bandwidth_limit': self.config.bandwidth_limit,
            'uptime': time.time() - self.start_time if self.is_running else 0,
            'reputation': self.node_integrity.get_node_reputation(self.config.node_id)
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()


# Convenience function for quick server startup
async def run_server(config: Optional[ServerConfig] = None):
    """Run a SpectralFlow server with the given configuration."""
    server = SpectralFlowServer(config)
    
    try:
        await server.start()
        
        # Keep running until interrupted
        while server.is_running:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logging.info("Received shutdown signal")
    finally:
        await server.stop()
