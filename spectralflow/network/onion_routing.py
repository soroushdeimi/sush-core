"""Quantum-resistant onion routing implementation."""

import asyncio
import logging
import secrets
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum, auto
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from ..core.ml_kem import MLKEMKeyExchange


class CircuitState(Enum):
    """Circuit states in onion routing."""
    BUILDING = auto()
    ESTABLISHED = auto()
    EXTENDING = auto()
    TEARDOWN = auto()
    FAILED = auto()


class CellType(Enum):
    """Types of onion routing cells."""
    CREATE = auto()        # Circuit creation
    CREATED = auto()       # Circuit creation response
    EXTEND = auto()        # Circuit extension
    EXTENDED = auto()      # Circuit extension response
    RELAY = auto()         # Data relay
    DESTROY = auto()       # Circuit destruction


@dataclass
class OnionLayer:
    """Represents one layer of onion encryption."""
    node_id: str
    public_key: bytes
    shared_secret: bytes
    hop_number: int


@dataclass
class Circuit:
    """Represents an onion routing circuit."""
    circuit_id: int
    state: CircuitState
    path: List[str]  # Node IDs in the path
    layers: List[OnionLayer]
    created_at: float
    last_activity: float
    purpose: str  # 'general', 'directory', 'introduction', etc.


@dataclass
class Cell:
    """Onion routing cell structure."""
    circuit_id: int
    command: CellType
    payload: bytes
    encrypted: bool = False


@dataclass
class RouteConfig:
    """Configuration for routing in the onion network."""
    max_hops: int = 3
    min_hops: int = 2
    entry_guards: List[str] = None
    exit_policies: Dict[str, Any] = None
    circuit_timeout: int = 600
    max_circuits: int = 100


@dataclass  
class CircuitNode:
    """Represents a node in a circuit path."""
    node_id: str
    address: str
    port: int
    public_key: bytes
    role: str  # 'guard', 'middle', 'exit'


class OnionRoutingProtocol:
    """
    Onion Routing Protocol for MirrorNet.
    
    Implements Tor-inspired onion routing with quantum-resistant cryptography.
    Provides multi-hop circuits with layered encryption to protect against
    traffic analysis and provide anonymity.
    """
    
    def __init__(self, node_id: str, private_key: bytes):
        """
        Initialize Onion Routing Protocol.
        
        Args:
            node_id: This node's identifier
            private_key: This node's private key
        """
        self.logger = logging.getLogger(__name__)
        self.node_id = node_id
        
        # Cryptographic components
        self.kem = MLKEMKeyExchange()
        self.private_key = private_key
        self.public_key, _ = self.kem.generate_keypair()
        
        # Circuit management
        self.circuits: Dict[int, Circuit] = {}
        self.next_circuit_id = 1
        self.circuit_timeout = 600.0  # 10 minutes
        
        # Node directory (simplified)
        self.known_nodes: Dict[str, Dict[str, Any]] = {}
        
        # Statistics
        self.stats = {
            'circuits_created': 0,
            'circuits_failed': 0,
            'cells_processed': 0,
            'bytes_relayed': 0
        }
        
        self.logger.info(f"Onion Routing Protocol initialized for node {node_id}")
    
    async def create_circuit(self, 
                           path: List[str], 
                           purpose: str = 'general') -> Optional[int]:
        """
        Create a new onion routing circuit.
        
        Args:
            path: List of node IDs to use in the circuit
            purpose: Purpose of the circuit
            
        Returns:
            Circuit ID if successful, None if failed
        """
        if len(path) < 2:
            self.logger.error("Circuit path must have at least 2 nodes")
            return None
        
        circuit_id = self._get_next_circuit_id()
        
        try:
            # Create circuit object
            circuit = Circuit(
                circuit_id=circuit_id,
                state=CircuitState.BUILDING,
                path=path,
                layers=[],
                created_at=time.time(),
                last_activity=time.time(),
                purpose=purpose
            )
            
            self.circuits[circuit_id] = circuit
            
            # Build circuit hop by hop
            success = await self._build_circuit(circuit)
            
            if success:
                circuit.state = CircuitState.ESTABLISHED
                self.stats['circuits_created'] += 1
                self.logger.info(f"Created circuit {circuit_id} with path {path}")
                return circuit_id
            else:
                circuit.state = CircuitState.FAILED
                self.stats['circuits_failed'] += 1
                del self.circuits[circuit_id]
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to create circuit: {e}")
            if circuit_id in self.circuits:
                del self.circuits[circuit_id]
            self.stats['circuits_failed'] += 1
            return None
    
    async def _build_circuit(self, circuit: Circuit) -> bool:
        """Build circuit by establishing hops one by one."""
        try:
            # First hop - direct connection
            first_node = circuit.path[0]
            
            if first_node not in self.known_nodes:
                self.logger.error(f"Unknown node: {first_node}")
                return False
            
            # Create first hop
            first_hop_success = await self._create_first_hop(circuit, first_node)
            if not first_hop_success:
                return False
            
            # Extend circuit for remaining hops
            for i in range(1, len(circuit.path)):
                next_node = circuit.path[i]
                extend_success = await self._extend_circuit(circuit, next_node)
                if not extend_success:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error building circuit: {e}")
            return False
    
    async def _create_first_hop(self, circuit: Circuit, node_id: str) -> bool:
        """Create the first hop of a circuit."""
        try:
            node_info = self.known_nodes[node_id]
            node_public_key = bytes.fromhex(node_info['public_key'])
            
            # Perform key exchange
            ciphertext, shared_secret = self.kem.encapsulate(node_public_key)
            
            # Create onion layer
            layer = OnionLayer(
                node_id=node_id,
                public_key=node_public_key,
                shared_secret=shared_secret,
                hop_number=0
            )
            
            circuit.layers.append(layer)
            
            # Send CREATE cell
            create_cell = Cell(
                circuit_id=circuit.circuit_id,
                command=CellType.CREATE,
                payload=ciphertext
            )
            
            # Simulate sending cell (in real implementation, would send over network)
            response = await self._send_cell(node_id, create_cell)
            
            if response and response.command == CellType.CREATED:
                self.logger.debug(f"First hop created to {node_id}")
                return True
            else:
                self.logger.error(f"Failed to create first hop to {node_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error creating first hop: {e}")
            return False
    
    async def _extend_circuit(self, circuit: Circuit, next_node_id: str) -> bool:
        """Extend circuit to next node."""
        try:
            if next_node_id not in self.known_nodes:
                self.logger.error(f"Unknown node: {next_node_id}")
                return False
            
            next_node_info = self.known_nodes[next_node_id]
            next_node_public_key = bytes.fromhex(next_node_info['public_key'])
            
            # Perform key exchange for next hop
            ciphertext, shared_secret = self.kem.encapsulate(next_node_public_key)
            
            # Create EXTEND payload
            extend_payload = (
                len(next_node_id).to_bytes(1, 'big') +
                next_node_id.encode() +
                ciphertext
            )
            
            # Encrypt payload through existing layers
            encrypted_payload = self._encrypt_through_layers(circuit, extend_payload)
            
            # Send EXTEND cell through circuit
            extend_cell = Cell(
                circuit_id=circuit.circuit_id,
                command=CellType.EXTEND,
                payload=encrypted_payload,
                encrypted=True
            )
            
            # Send through first hop
            first_node = circuit.path[0]
            response = await self._send_cell(first_node, extend_cell)
            
            if response and response.command == CellType.EXTENDED:
                # Add new layer
                layer = OnionLayer(
                    node_id=next_node_id,
                    public_key=next_node_public_key,
                    shared_secret=shared_secret,
                    hop_number=len(circuit.layers)
                )
                
                circuit.layers.append(layer)
                self.logger.debug(f"Extended circuit to {next_node_id}")
                return True
            else:
                self.logger.error(f"Failed to extend circuit to {next_node_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error extending circuit: {e}")
            return False
    
    def _encrypt_through_layers(self, circuit: Circuit, data: bytes) -> bytes:
        """Encrypt data through all circuit layers (forward direction)."""
        encrypted_data = data
        
        # Encrypt through layers in reverse order (outermost first)
        for layer in reversed(circuit.layers):
            encrypted_data = self._encrypt_with_layer(layer, encrypted_data)
        
        return encrypted_data
    
    def _decrypt_through_layers(self, circuit: Circuit, data: bytes) -> bytes:
        """Decrypt data through circuit layers (backward direction)."""
        decrypted_data = data
        
        # Decrypt through layers in forward order
        for layer in circuit.layers:
            decrypted_data = self._decrypt_with_layer(layer, decrypted_data)
        
        return decrypted_data
    def _encrypt_with_layer(self, layer: OnionLayer, data: bytes) -> bytes:
        """
        Encrypt data with a specific layer's key using AES-256-CTR.
        
        Replaced insecure XOR encryption with proper AES-256-CTR stream cipher
        for cryptographic security as per security hardening requirements.
        """
        # Derive encryption key from shared secret using HKDF
        encryption_key = self._derive_layer_key_secure(layer.shared_secret, "encrypt")
        
        # Generate a random IV for AES-CTR
        iv = secrets.token_bytes(16)  # 128-bit IV for AES
        
        # Encrypt using AES-256-CTR
        cipher = Cipher(
            algorithms.AES(encryption_key), 
            modes.CTR(iv), 
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Prepend IV to ciphertext (receiver needs it for decryption)
        return iv + ciphertext

    def _decrypt_with_layer(self, layer: OnionLayer, data: bytes) -> bytes:
        """
        Decrypt data with a specific layer's key using AES-256-CTR.
        
        Replaced insecure XOR decryption with proper AES-256-CTR stream cipher
        for cryptographic security as per security hardening requirements.
        """        # Extract IV and ciphertext
        if len(data) < 16:
            raise ValueError("Encrypted data too short to contain IV")
        
        iv = data[:16]
        ciphertext = data[16:]
        
        # Derive decryption key from shared secret using HKDF (same purpose as encryption)
        decryption_key = self._derive_layer_key_secure(layer.shared_secret, "encrypt")
        
        # Decrypt using AES-256-CTR
        cipher = Cipher(
            algorithms.AES(decryption_key), 
            modes.CTR(iv), 
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    def _derive_layer_key_secure(self, shared_secret: bytes, purpose: str) -> bytes:
        """
        Derive layer-specific key from shared secret using HKDF.
        
        Replaced simple SHA256 concatenation with proper HKDF for key derivation
        to ensure cryptographic security and key separation.
        """
        # Use HKDF for proper key derivation
        info = f"SpectralFlow-ORPP-{purpose}".encode()
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-256
            salt=None,  # Can be None for this use case
            info=info,
            backend=default_backend()
        )
        
        return hkdf.derive(shared_secret)

    def _derive_layer_key(self, shared_secret: bytes, purpose: str) -> bytes:
        """
        Legacy key derivation method - kept for backward compatibility.
        Use _derive_layer_key_secure for new implementations.
        """
        # Use HKDF-like key derivation
        info = f"SpectralFlow-ORPP-{purpose}".encode()
        combined = shared_secret + info
        return hashlib.sha256(combined).digest()
    
    def _generate_key_stream(self, key: bytes, length: int) -> bytes:
        """Generate key stream for encryption."""
        # Simple key stream generation (use proper stream cipher in production)
        stream = b""
        counter = 0
        
        while len(stream) < length:
            counter_bytes = counter.to_bytes(8, 'big')
            block = hashlib.sha256(key + counter_bytes).digest()
            stream += block
            counter += 1
        
        return stream[:length]
    
    async def send_data(self, circuit_id: int, data: bytes) -> bool:
        """Send data through an established circuit."""
        if circuit_id not in self.circuits:
            self.logger.error(f"Circuit {circuit_id} not found")
            return False
        
        circuit = self.circuits[circuit_id]
        
        if circuit.state != CircuitState.ESTABLISHED:
            self.logger.error(f"Circuit {circuit_id} not in established state")
            return False
        
        try:
            # Encrypt data through all layers
            encrypted_data = self._encrypt_through_layers(circuit, data)
            
            # Create RELAY cell
            relay_cell = Cell(
                circuit_id=circuit_id,
                command=CellType.RELAY,
                payload=encrypted_data,
                encrypted=True
            )
            
            # Send through first hop
            first_node = circuit.path[0]
            success = await self._send_cell(first_node, relay_cell, expect_response=False)
            
            if success:
                circuit.last_activity = time.time()
                self.stats['bytes_relayed'] += len(data)
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending data through circuit {circuit_id}: {e}")
            return False
    
    async def receive_data(self, circuit_id: int, timeout: float = 5.0) -> Optional[bytes]:
        """Receive data from a circuit."""
        if circuit_id not in self.circuits:
            return None
        
        circuit = self.circuits[circuit_id]
        
        try:
            # In real implementation, would listen for incoming cells
            # For now, simulate receiving data
            await asyncio.sleep(0.1)  # Simulate network delay
            
            # Would receive encrypted cell and decrypt through layers
            # This is a placeholder implementation
            
            return None  # No data received in simulation
            
        except Exception as e:
            self.logger.error(f"Error receiving data from circuit {circuit_id}: {e}")
            return None
    
    async def destroy_circuit(self, circuit_id: int) -> bool:
        """Destroy a circuit."""
        if circuit_id not in self.circuits:
            return False
        
        circuit = self.circuits[circuit_id]
        
        try:
            # Send DESTROY cell
            destroy_cell = Cell(
                circuit_id=circuit_id,
                command=CellType.DESTROY,
                payload=b"circuit_teardown"
            )
            
            # Send to first hop
            first_node = circuit.path[0]
            await self._send_cell(first_node, destroy_cell, expect_response=False)
            
            # Update circuit state
            circuit.state = CircuitState.TEARDOWN
            
            # Remove from active circuits
            del self.circuits[circuit_id]
            
            self.logger.info(f"Destroyed circuit {circuit_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error destroying circuit {circuit_id}: {e}")
            return False

    async def _send_cell(self,
                        node_id: str, 
                        cell: Cell, 
                        expect_response: bool = True) -> Optional[Cell]:
        """Send a cell to a node over real network connection."""
        try:
            # Get node connection info
            if node_id not in self.known_nodes:
                self.logger.error(f"Unknown node: {node_id}")
                return None
            
            node_info = self.known_nodes[node_id]
            address = node_info.get('address', 'localhost')
            port = node_info.get('port', 8080)
            
            # Serialize cell for transmission
            cell_data = self._serialize_cell(cell)
            
            # Establish connection and send cell
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port),
                    timeout=10.0
                )
                
                # Send cell with length prefix
                length_prefix = struct.pack('!I', len(cell_data))
                writer.write(length_prefix + cell_data)
                await writer.drain()
                
                response_cell = None
                if expect_response:
                    # Read response length
                    response_length_data = await reader.readexactly(4)
                    response_length = struct.unpack('!I', response_length_data)[0]
                    
                    # Read response data
                    response_data = await reader.readexactly(response_length)
                    response_cell = self._deserialize_cell(response_data)
                
                writer.close()
                await writer.wait_closed()
                
                self.stats['cells_processed'] += 1
                return response_cell
                
            except (ConnectionRefusedError, asyncio.TimeoutError) as e:
                self.logger.warning(f"Connection to {node_id} ({address}:{port}) failed: {e}")
                return None
            
        except Exception as e:
            self.logger.error(f"Error sending cell to {node_id}: {e}")
            return None
    
    def _get_next_circuit_id(self) -> int:
        """Get next available circuit ID."""
        circuit_id = self.next_circuit_id
        self.next_circuit_id += 1
        return circuit_id
    
    def add_known_node(self, node_id: str, node_info: Dict[str, Any]):
        """Add a node to the known nodes directory."""
        self.known_nodes[node_id] = {
            'public_key': node_info.get('public_key', ''),
            'address': node_info.get('address', ''),
            'port': node_info.get('port', 8080),
            'capabilities': node_info.get('capabilities', []),
            'last_seen': time.time()
        }
        
        self.logger.debug(f"Added known node: {node_id}")
    
    def select_circuit_path(self, 
                          length: int = 3, 
                          exclude_nodes: List[str] = None) -> Optional[List[str]]:
        """
        Select nodes for a circuit path.
        
        Args:
            length: Desired path length
            exclude_nodes: Nodes to exclude from selection
            
        Returns:
            List of node IDs for the path
        """
        if exclude_nodes is None:
            exclude_nodes = []
        
        # Filter available nodes
        available_nodes = [
            node_id for node_id in self.known_nodes.keys()
            if node_id not in exclude_nodes and node_id != self.node_id        ]
        
        if len(available_nodes) < length:
            self.logger.error(f"Not enough nodes for path length {length}")
            return None
        
        # Simple random selection (in production, use bandwidth weighting)
        selected_nodes = secrets.SystemRandom().sample(available_nodes, length)
        
        return selected_nodes
    
    def _serialize_cell(self, cell: Cell) -> bytes:
        """Serialize a cell for network transmission."""
        command_byte = cell.command.value.to_bytes(1, 'big')
        circuit_id_bytes = cell.circuit_id.to_bytes(4, 'big')
        payload_length = len(cell.payload).to_bytes(4, 'big')
        return command_byte + circuit_id_bytes + payload_length + cell.payload
    
    def _deserialize_cell(self, data: bytes) -> Cell:
        """Deserialize a cell from network data."""
        if len(data) < 9:
            raise ValueError("Invalid cell data")
        
        command_value = int.from_bytes(data[0:1], 'big')
        circuit_id = int.from_bytes(data[1:5], 'big')
        payload_length = int.from_bytes(data[5:9], 'big')
        payload = data[9:9+payload_length]
        
        command = CellType(command_value)
        return Cell(circuit_id=circuit_id, command=command, payload=payload)
    
    def cleanup_expired_circuits(self):
        """Clean up expired circuits."""
        current_time = time.time()
        expired_circuits = []
        
        for circuit_id, circuit in self.circuits.items():
            if current_time - circuit.last_activity > self.circuit_timeout:
                expired_circuits.append(circuit_id)
        
        for circuit_id in expired_circuits:
            self.logger.info(f"Cleaning up expired circuit {circuit_id}")
            asyncio.create_task(self.destroy_circuit(circuit_id))
    
    def get_circuit_info(self, circuit_id: int) -> Optional[Dict[str, Any]]:
        """Get information about a circuit."""
        if circuit_id not in self.circuits:
            return None
        
        circuit = self.circuits[circuit_id]
        
        return {
            'circuit_id': circuit_id,
            'state': circuit.state.name,
            'path': circuit.path,
            'hop_count': len(circuit.layers),
            'created_at': circuit.created_at,
            'last_activity': circuit.last_activity,
            'purpose': circuit.purpose,
            'age': time.time() - circuit.created_at
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get onion routing statistics."""
        active_circuits = len(self.circuits)
        
        return {
            'node_id': self.node_id,
            'active_circuits': active_circuits,
            'known_nodes': len(self.known_nodes),
            'circuits_created': self.stats['circuits_created'],
            'circuits_failed': self.stats['circuits_failed'],
            'cells_processed': self.stats['cells_processed'],
            'bytes_relayed': self.stats['bytes_relayed'],
            'success_rate': (
                self.stats['circuits_created'] / 
                max(self.stats['circuits_created'] + self.stats['circuits_failed'], 1)
            )
        }
