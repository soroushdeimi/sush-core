"""Quantum-resistant obfuscation system."""

import logging
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from .ml_kem import MLKEMKeyExchange
from .adaptive_cipher import AdaptiveCipherSuite, ThreatLevel, NetworkCondition
from .traffic_morphing import TrafficMorphingEngine


@dataclass
class ObfuscationContext:
    """Context for obfuscation operations."""
    session_id: str
    threat_level: ThreatLevel
    network_condition: NetworkCondition
    peer_public_key: Optional[bytes] = None
    shared_secret: Optional[bytes] = None
    derived_keys: Optional[Dict[str, bytes]] = None


class QuantumObfuscator:
    """Quantum-resistant obfuscation system."""
    
    def __init__(self, mtu: int = 1500):
        self.logger = logging.getLogger(__name__)
        
        # Initialize core components
        self.kem = MLKEMKeyExchange()
        self.cipher_suite = AdaptiveCipherSuite()
        self.traffic_morpher = TrafficMorphingEngine()
        
        # Generate our key pair
        self.public_key, self.private_key = self.kem.generate_keypair()
        
        # Active sessions
        self.sessions: Dict[str, ObfuscationContext] = {}
        
        self.logger.info("Quantum Obfuscator initialized with ML-KEM-768")
    
    async def initialize_session(self, 
                                session_id: str,
                                peer_public_key: bytes,
                                threat_level: ThreatLevel = ThreatLevel.MEDIUM,
                                network_condition: NetworkCondition = NetworkCondition.MEDIUM_BANDWIDTH) -> ObfuscationContext:
        """
        Initialize a new obfuscation session with a peer.
        
        Args:
            session_id: Unique session identifier
            peer_public_key: Peer's ML-KEM public key
            threat_level: Current threat assessment
            network_condition: Current network conditions
            
        Returns:
            ObfuscationContext: Session context for subsequent operations
        """
        self.logger.info(f"Initializing session {session_id}")
        
        # Perform ML-KEM key exchange
        ciphertext, shared_secret = self.kem.encapsulate(peer_public_key)
        
        # Derive symmetric keys
        derived_keys = self.kem.derive_keys(shared_secret, session_id.encode())
        
        # Select initial cipher profile
        cipher_profile = self.cipher_suite.select_cipher_profile(threat_level, network_condition)
        
        # Create session context
        context = ObfuscationContext(
            session_id=session_id,
            threat_level=threat_level,
            network_condition=network_condition,
            peer_public_key=peer_public_key,
            shared_secret=shared_secret,
            derived_keys=derived_keys
        )
        
        self.sessions[session_id] = context
        
        self.logger.info(f"Session {session_id} initialized with cipher profile: {cipher_profile}")
        
        return context
    
    async def accept_session(self, 
                           session_id: str,
                           ciphertext: bytes,
                           threat_level: ThreatLevel = ThreatLevel.MEDIUM,
                           network_condition: NetworkCondition = NetworkCondition.MEDIUM_BANDWIDTH) -> ObfuscationContext:
        """
        Accept and establish a session from peer's key exchange.
        
        Args:
            session_id: Unique session identifier
            ciphertext: ML-KEM ciphertext from peer
            threat_level: Current threat assessment
            network_condition: Current network conditions
            
        Returns:
            ObfuscationContext: Session context for subsequent operations
        """
        self.logger.info(f"Accepting session {session_id}")
        
        # Decapsulate shared secret
        shared_secret = self.kem.decapsulate(ciphertext, self.private_key)
        
        # Derive symmetric keys
        derived_keys = self.kem.derive_keys(shared_secret, session_id.encode())
        
        # Select initial cipher profile
        cipher_profile = self.cipher_suite.select_cipher_profile(threat_level, network_condition)
        
        # Create session context
        context = ObfuscationContext(
            session_id=session_id,
            threat_level=threat_level,
            network_condition=network_condition,
            shared_secret=shared_secret,
            derived_keys=derived_keys
        )
        
        self.sessions[session_id] = context
        
        self.logger.info(f"Session {session_id} accepted with cipher profile: {cipher_profile}")
        
        return context
    
    async def obfuscate_data(self, 
                           session_id: str, 
                           data: bytes,
                           additional_data: bytes = b"") -> List[bytes]:
        """
        Obfuscate data using quantum-resistant encryption and traffic morphing.
        
        Args:
            session_id: Session identifier
            data: Plaintext data to obfuscate
            additional_data: Additional authenticated data
            
        Returns:
            List[bytes]: Obfuscated packets (may be multiple due to morphing)
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        context = self.sessions[session_id]
        
        # Update cipher suite keys
        self._update_cipher_keys(context)
        
        # Encrypt data with adaptive cipher suite
        ciphertext, iv, tag = self.cipher_suite.encrypt(data, additional_data)
        
        # Create encrypted packet
        encrypted_packet = self._create_encrypted_packet(ciphertext, iv, tag)
        
        # Apply traffic morphing
        morphed_packets = self.traffic_morpher.morph_packet(encrypted_packet)
        
        self.logger.debug(f"Obfuscated {len(data)} bytes into {len(morphed_packets)} packets")
        
        return morphed_packets
    
    async def deobfuscate_data(self, 
                             session_id: str, 
                             packets: List[bytes],
                             additional_data: bytes = b"") -> bytes:
        """
        Deobfuscate data by reversing traffic morphing and decryption.
        
        Args:
            session_id: Session identifier
            packets: List of obfuscated packets
            additional_data: Additional authenticated data
            
        Returns:
            bytes: Original plaintext data
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        context = self.sessions[session_id]
        
        # Reconstruct encrypted packet from morphed packets
        encrypted_packet = self._reconstruct_encrypted_packet(packets)
        
        # Parse encrypted packet
        ciphertext, iv, tag = self._parse_encrypted_packet(encrypted_packet)
          # Update cipher suite keys
        self._update_cipher_keys(context)
          # Decrypt data
        plaintext = self.cipher_suite.decrypt(ciphertext, iv, tag, additional_data)
        
        self.logger.debug(f"Deobfuscated {len(packets)} packets into {len(plaintext)} bytes")
        
        return plaintext
    
    def _update_cipher_keys(self, context: ObfuscationContext):
        """Update cipher suite with session keys."""
        if not context.derived_keys:
            raise ValueError("No derived keys available")
          
        # Ensure consistent key derivation
        if 'aes_key' in context.derived_keys:
            encryption_key = context.derived_keys['aes_key']
        elif 'encryption_key' in context.derived_keys:
            encryption_key = context.derived_keys['encryption_key']
        elif 'key' in context.derived_keys:
            encryption_key = context.derived_keys['key']
        else:
            # Generate a consistent fallback key from shared secret
            import hashlib
            encryption_key = hashlib.sha256(context.shared_secret + b"encryption").digest()
        
        # Set the encryption key for the cipher suite
        self.cipher_suite.encryption_key = encryption_key
        
        self.logger.debug(f"Updated cipher keys for session {context.session_id}")
    
    def _create_encrypted_packet(self, ciphertext: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Create encrypted packet with proper framing.
        
        Args:
            ciphertext: Encrypted data
            iv: Initialization vector
            tag: Authentication tag
            
        Returns:
            bytes: Framed encrypted packet
        """
        # Packet format: IV_SIZE(1) + TAG_SIZE(1) + IV + TAG + CIPHERTEXT
        iv_size = len(iv)
        tag_size = len(tag)
        
        if iv_size > 255 or tag_size > 255:
            raise ValueError("IV or tag too large for packet format")
        
        packet = (
            iv_size.to_bytes(1, 'big') +
            tag_size.to_bytes(1, 'big') +
            iv +
            tag +
            ciphertext
        )
        
        return packet
    
    def _parse_encrypted_packet(self, packet: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Parse encrypted packet to extract components.
        
        Args:
            packet: Encrypted packet
            
        Returns:
            Tuple[bytes, bytes, bytes]: (ciphertext, iv, tag)
        """
        if len(packet) < 2:
            raise ValueError("Invalid packet format")
        
        iv_size = packet[0]
        tag_size = packet[1]
        
        if len(packet) < 2 + iv_size + tag_size:
            raise ValueError("Packet too short for declared sizes")
        
        iv = packet[2:2 + iv_size]
        tag = packet[2 + iv_size:2 + iv_size + tag_size]
        ciphertext = packet[2 + iv_size + tag_size:]
        
        return ciphertext, iv, tag
    
    def _reconstruct_encrypted_packet(self, packets: List[bytes]) -> bytes:
        """
        Reconstruct original encrypted packet from morphed packets.
        
        Args:
            packets: List of morphed packets
            
        Returns:
            bytes: Reconstructed encrypted packet
        """
        if len(packets) == 1:
            # Single packet - extract original data
            return self.traffic_morpher.extract_original_data(packets[0])
        
        # Multiple packets - need to reassemble fragments
        # This is a simplified implementation
        reconstructed = b""
        for packet in packets:
            original_data = self.traffic_morpher.extract_original_data(packet)
            reconstructed += original_data
        
        return reconstructed
    
    async def adapt_to_conditions(self, 
                                session_id: str,
                                threat_level: ThreatLevel,
                                network_condition: NetworkCondition,
                                performance_feedback: Optional[float] = None):
        """
        Adapt obfuscation parameters based on changing conditions.
        
        Args:
            session_id: Session to adapt
            threat_level: New threat level
            network_condition: New network conditions
            performance_feedback: Performance score (0.0 to 1.0)
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        context = self.sessions[session_id]
        
        # Update context
        old_threat = context.threat_level
        old_network = context.network_condition
        
        context.threat_level = threat_level
        context.network_condition = network_condition
        
        # Adapt cipher suite
        new_profile = self.cipher_suite.select_cipher_profile(threat_level, network_condition)
        
        # Update state machine if feedback provided
        if performance_feedback is not None:
            self.cipher_suite.update_state_machine(
                (old_threat, old_network),
                self.cipher_suite.current_profile.name if self.cipher_suite.current_profile else "unknown",
                performance_feedback
            )
        
        # Adapt traffic morphing
        network_conditions = {
            'threat_level': threat_level.name.lower(),
            'bandwidth': 1000000 if network_condition == NetworkCondition.HIGH_BANDWIDTH else 100000,
            'latency': 0.01 if network_condition == NetworkCondition.HIGH_BANDWIDTH else 0.1,
            'packet_loss': 0.01 if network_condition != NetworkCondition.UNSTABLE else 0.1
        }
        
        self.traffic_morpher.update_strategy(network_conditions)
        
        self.logger.info(f"Adapted session {session_id} to threat={threat_level.name}, "
                        f"network={network_condition.name}, cipher={new_profile}")
    
    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """Get information about a session."""
        if session_id not in self.sessions:
            return {}
        
        context = self.sessions[session_id]
        
        return {
            'session_id': context.session_id,
            'threat_level': context.threat_level.name,
            'network_condition': context.network_condition.name,
            'cipher_profile': self.cipher_suite.get_current_profile_info(),
            'traffic_stats': self.traffic_morpher.get_statistics(),
            'has_shared_secret': context.shared_secret is not None,
            'has_derived_keys': context.derived_keys is not None
        }
    
    def cleanup_session(self, session_id: str):
        """Clean up session resources."""
        if session_id in self.sessions:
            del self.sessions[session_id]
            self.logger.info(f"Cleaned up session {session_id}")
    
    def get_public_key(self) -> bytes:
        """Get our public key for key exchange."""
        return self.public_key
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall obfuscator statistics."""
        return {
            'active_sessions': len(self.sessions),
            'cipher_transitions': len(self.cipher_suite.get_transition_history()),
            'traffic_morphing': self.traffic_morpher.get_statistics(),
            'ml_kem_parameters': self.kem.get_parameters()
        }
    
    def set_obfuscation_level(self, level: str):
        """
        Set the obfuscation level for the quantum obfuscator.
        
        Args:
            level: Obfuscation level ('low', 'medium', 'high', 'extreme')
        """
        level_map = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,  
            'high': ThreatLevel.HIGH,
            'extreme': ThreatLevel.CRITICAL
        }
        
        if level not in level_map:
            raise ValueError(f"Invalid obfuscation level: {level}")
        
        self.default_threat_level = level_map[level]
        self.logger.info(f"Obfuscation level set to: {level}")
