"""SpectralFlow client implementation."""

import logging
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
import secrets

from .core.quantum_obfuscator import QuantumObfuscator
from .transport.adaptive_transport import AdaptiveTransport, TransportConfig, TransportMode
from .network.mirror_network import MirrorNetwork
from .control.adaptive_control import AdaptiveControlLoop
from .control.censorship_detector import CensorshipDetector
from .control.threat_monitor import ThreatMonitor
from .control.response_engine import ResponseEngine


@dataclass
class ClientConfig:
    """Configuration for SpectralFlow client."""
    # Identity
    node_id: Optional[str] = None
    private_key: Optional[bytes] = None
    
    # Network configuration
    bootstrap_nodes: List[str] = None
    preferred_protocols: List[str] = None
    preferred_ports: List[int] = None
    
    # Security settings
    obfuscation_level: float = 0.6
    enable_steganography: bool = True
    enable_traffic_morphing: bool = True
    
    # Performance settings
    connection_timeout: float = 30.0
    max_concurrent_connections: int = 10
    adaptation_interval: float = 5.0
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None

    def __post_init__(self):
        """Initialize defaults after construction."""
        if self.node_id is None:
            self.node_id = f"client_{secrets.token_hex(8)}"
        
        if self.private_key is None:
            self.private_key = secrets.token_bytes(32)
        
        if self.bootstrap_nodes is None:
            self.bootstrap_nodes = [
                "mirror1.spectralflow.net:8443",
                "mirror2.spectralflow.net:8443", 
                "mirror3.spectralflow.net:8443"
            ]
        
        if self.preferred_protocols is None:
            self.preferred_protocols = ["tcp", "udp", "quic", "websocket"]
        
        if self.preferred_ports is None:
            self.preferred_ports = [443, 80, 53, 8080, 8443]


class SpectralFlowClient:
    """
    SpectralFlow Client - Main entry point for censorship circumvention.
    
    Provides a high-level interface for applications to use SpectralFlow's
    quantum-resistant, self-adapting censorship circumvention capabilities.
    """
    
    def __init__(self, config: Optional[ClientConfig] = None):
        """
        Initialize SpectralFlow client.
        
        Args:
            config: Client configuration (uses defaults if None)
        """
        self.config = config or ClientConfig()
        
        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Component initialization
        self.quantum_obfuscator = QuantumObfuscator()
        self.quantum_obfuscator.set_obfuscation_level(self._get_obfuscation_level_name())
        
        self.adaptive_transport = AdaptiveTransport(
            config=TransportConfig(
                mode=TransportMode.DIRECT,
                enable_hopping=True,
                hop_interval=30.0
            )
        )
        
        self.mirror_network = MirrorNetwork(
            node_id=self.config.node_id,
            private_key=self.config.private_key
        )
        
        self.censorship_detector = CensorshipDetector()
        self.threat_monitor = ThreatMonitor()
        self.response_engine = ResponseEngine()
        
        self.adaptive_control = AdaptiveControlLoop(
            adaptation_interval=self.config.adaptation_interval
        )
        
        # Client state
        self.is_connected = False
        self.is_running = False
        self.active_connections: Dict[str, Any] = {}
        self.connection_callbacks: Dict[str, Callable] = {}
        
        self.logger.info(f"SpectralFlow client initialized with node ID: {self.config.node_id}")
    
    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        
        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=self.config.log_file
        )
        
        # Suppress verbose third-party logs
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
    
    async def start(self):
        """Start the SpectralFlow client."""
        if self.is_running:
            self.logger.warning("Client already running")
            return
        
        try:
            self.logger.info("Starting SpectralFlow client...")
            
            # Initialize components
            await self._initialize_components()
            
            # Start components
            await self._start_components()
            
            # Connect to network
            await self._connect_to_network()
            
            self.is_running = True
            self.is_connected = True
            
            self.logger.info("SpectralFlow client started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start client: {e}")
            await self.stop()
            raise
    
    async def stop(self):
        """Stop the SpectralFlow client."""
        if not self.is_running:
            return
        
        self.logger.info("Stopping SpectralFlow client...")
        
        try:
            # Close active connections
            await self._close_all_connections()
            
            # Stop components
            await self._stop_components()
            
            self.is_running = False
            self.is_connected = False
            
            self.logger.info("SpectralFlow client stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping client: {e}")
    
    async def _initialize_components(self):
        """Initialize all components."""
        await self.adaptive_control.initialize_components(
            censorship_detector=self.censorship_detector,
            threat_monitor=self.threat_monitor,
            response_engine=self.response_engine,
            quantum_obfuscator=self.quantum_obfuscator,
            adaptive_transport=self.adaptive_transport,
            mirror_network=self.mirror_network
        )
        
        # Configure mirror network
        await self.mirror_network.configure({
            'bootstrap_nodes': self.config.bootstrap_nodes,
            'max_concurrent_connections': self.config.max_concurrent_connections
        })
    
    async def _start_components(self):
        """Start all components."""
        await self.censorship_detector.start_monitoring()
        await self.threat_monitor.start_monitoring()
        await self.response_engine.start()
        await self.adaptive_control.start()
        
        self.logger.info("All components started")
    
    async def _stop_components(self):
        """Stop all components."""
        await self.adaptive_control.stop()
        await self.response_engine.stop()
        await self.threat_monitor.stop_monitoring()
        await self.censorship_detector.stop_monitoring()
        
        self.logger.info("All components stopped")
    
    async def _connect_to_network(self):
        """Connect to the MirrorNet network."""
        try:
            # Bootstrap network connection
            await self.mirror_network.bootstrap_network()
            
            # Announce presence
            await self.mirror_network.announce_node()
            
            # Establish initial circuits
            await self.mirror_network.establish_circuits(count=3)
            
            self.logger.info("Connected to MirrorNet")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to network: {e}")
            raise
    
    async def _close_all_connections(self):
        """Close all active connections."""
        for connection_id in list(self.active_connections.keys()):
            await self.close_connection(connection_id)
    
    async def connect(self, 
                     destination: str, 
                     port: int, 
                     protocol: str = "tcp") -> str:
        """
        Establish a connection through SpectralFlow.
        
        Args:
            destination: Target hostname or IP
            port: Target port
            protocol: Protocol to use
            
        Returns:
            Connection ID for the established connection
        """
        if not self.is_connected:
            raise RuntimeError("Client not connected to network")
        
        connection_id = f"conn_{secrets.token_hex(8)}"
        
        try:
            self.logger.info(f"Establishing connection to {destination}:{port} via {protocol}")
            
            # Create connection through mirror network
            connection = await self.mirror_network.create_connection(
                destination=destination,
                port=port,
                protocol=protocol
            )
            
            # Store connection
            self.active_connections[connection_id] = {
                'connection': connection,
                'destination': destination,
                'port': port,
                'protocol': protocol,
                'created_at': time.time(),
                'bytes_sent': 0,
                'bytes_received': 0
            }
            
            self.logger.info(f"Connection established: {connection_id}")
            return connection_id
            
        except Exception as e:
            self.logger.error(f"Failed to establish connection: {e}")
            raise
    
    async def send_data(self, connection_id: str, data: bytes) -> bool:
        """
        Send data through an established connection.
        
        Args:
            connection_id: ID of the connection
            data: Data to send
            
        Returns:
            True if data was sent successfully
        """
        if connection_id not in self.active_connections:
            raise ValueError(f"Unknown connection ID: {connection_id}")
        
        try:
            connection_info = self.active_connections[connection_id]
            connection = connection_info['connection']
            
            # Send data through connection
            success = await connection.send(data)
            
            if success:
                connection_info['bytes_sent'] += len(data)
                self.logger.debug(f"Sent {len(data)} bytes via {connection_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to send data via {connection_id}: {e}")
            return False
    
    async def receive_data(self, 
                          connection_id: str, 
                          max_size: int = 8192,
                          timeout: float = 30.0) -> Optional[bytes]:
        """
        Receive data from an established connection.
        
        Args:
            connection_id: ID of the connection
            max_size: Maximum bytes to receive
            timeout: Receive timeout in seconds
            
        Returns:
            Received data or None if timeout/error
        """
        if connection_id not in self.active_connections:
            raise ValueError(f"Unknown connection ID: {connection_id}")
        
        try:
            connection_info = self.active_connections[connection_id]
            connection = connection_info['connection']
            
            # Receive data through connection
            data = await connection.receive(max_size=max_size, timeout=timeout)
            
            if data:
                connection_info['bytes_received'] += len(data)
                self.logger.debug(f"Received {len(data)} bytes via {connection_id}")
            
            return data
            
        except Exception as e:
            self.logger.error(f"Failed to receive data via {connection_id}: {e}")
            return None
    
    async def close_connection(self, connection_id: str) -> bool:
        """
        Close an established connection.
        
        Args:
            connection_id: ID of the connection to close
            
        Returns:
            True if connection was closed successfully
        """
        if connection_id not in self.active_connections:
            return False
        
        try:
            connection_info = self.active_connections[connection_id]
            connection = connection_info['connection']
            
            # Check if connection object exists before trying to close it
            if connection is not None:
                # Close the connection
                await connection.close()
            
            # Remove from active connections
            del self.active_connections[connection_id]
            
            self.logger.info(f"Connection closed: {connection_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to close connection {connection_id}: {e}")
            # Still remove from active connections even if close failed
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]
            return False
    
    def set_connection_callback(self, event: str, callback: Callable):
        """
        Set callback for connection events.
        
        Args:
            event: Event type ('data_received', 'connection_closed', etc.)
            callback: Callback function
        """
        self.connection_callbacks[event] = callback
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive client status."""
        return {
            'is_running': self.is_running,
            'is_connected': self.is_connected,
            'node_id': self.config.node_id,
            'active_connections': len(self.active_connections),
            'system_status': self.adaptive_control.get_system_status(),
            'network_status': self.mirror_network.get_network_status(),
            'transport_status': self.adaptive_transport.get_statistics(),
            'security_status': {
                'obfuscation_level': self.quantum_obfuscator.current_obfuscation_level,
                'current_threat_level': self.censorship_detector.current_threat_level.name,
                'steganography_enabled': self.config.enable_steganography,
                'traffic_morphing_enabled': self.config.enable_traffic_morphing
            }
        }
    
    def get_connection_stats(self, connection_id: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific connection."""
        if connection_id not in self.active_connections:
            return None
        
        connection_info = self.active_connections[connection_id]
        
        return {
            'connection_id': connection_id,
            'destination': connection_info['destination'],
            'port': connection_info['port'],
            'protocol': connection_info['protocol'],
            'created_at': connection_info['created_at'],
            'duration': time.time() - connection_info['created_at'],
            'bytes_sent': connection_info['bytes_sent'],
            'bytes_received': connection_info['bytes_received']
        }
    
    async def force_adaptation(self, strategy: str):
        """Force a specific adaptation strategy."""
        from .control.adaptive_control import AdaptationStrategy
        
        strategy_map = {
            'aggressive': AdaptationStrategy.AGGRESSIVE,
            'balanced': AdaptationStrategy.BALANCED,
            'stealth': AdaptationStrategy.STEALTH,
            'performance': AdaptationStrategy.PERFORMANCE,
            'defensive': AdaptationStrategy.DEFENSIVE
        }
        
        if strategy.lower() in strategy_map:
            await self.adaptive_control.force_adaptation(strategy_map[strategy.lower()])
        else:
            raise ValueError(f"Unknown strategy: {strategy}")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()

    def _get_obfuscation_level_name(self) -> str:
        """Convert numeric obfuscation level to string name."""
        if self.config.obfuscation_level <= 0.25:
            return "low"
        elif self.config.obfuscation_level <= 0.5:
            return "medium"
        elif self.config.obfuscation_level <= 0.75:
            return "high"
        else:
            return "extreme"


# Convenience functions for quick usage
async def create_client(config: Optional[ClientConfig] = None) -> SpectralFlowClient:
    """Create and start a SpectralFlow client."""
    client = SpectralFlowClient(config)
    await client.start()
    return client


async def connect_through_spectralflow(destination: str, 
                                     port: int, 
                                     protocol: str = "tcp",
                                     config: Optional[ClientConfig] = None) -> SpectralFlowClient:
    """
    Quick connection through SpectralFlow.
    
    Args:
        destination: Target hostname or IP
        port: Target port  
        protocol: Protocol to use
        config: Client configuration
        
    Returns:
        Connected SpectralFlow client
    """
    client = await create_client(config)
    await client.connect(destination, port, protocol)
    return client
