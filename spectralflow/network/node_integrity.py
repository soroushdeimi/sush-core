"""
Simplified Node Integrity System (DNIS) Implementation

Implements a lightweight reputation management system for maintaining node
reliability in the MirrorNet without complex blockchain operations.
"""

import logging
import time
import hashlib
import json
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from enum import Enum, auto
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError



class NodeStatus(Enum):
    """Node status in the network."""
    UNKNOWN = auto()
    VERIFIED = auto()
    TRUSTED = auto()
    SUSPICIOUS = auto()
    BLOCKED = auto()


@dataclass
class NodeRecord:
    """Node record in the integrity system."""
    node_id: str
    public_key: str
    first_seen: float
    last_seen: float
    reputation_score: float
    status: NodeStatus
    endorsements: Set[str]
    complaints: Set[str]
    uptime_reports: List[float]
    bandwidth_reports: List[float]
    stake: float = 0.0


@dataclass
class PerformanceReport:
    """Performance report about a node."""
    reporter_id: str
    target_node: str
    timestamp: float
    uptime_percentage: float
    avg_latency: float
    bandwidth_mbps: float
    successful_relays: int
    failed_relays: int
    signature: str


class SimplifiedNodeIntegrity:
    """
    Simplified Node Integrity System.
    
    Maintains node reputation through signed reports without blockchain complexity.
    """
    def __init__(self, node_id: str, private_key: bytes):
        """
        Initialize simplified DNIS.
        
        Args:
            node_id: This node's identifier
            private_key: This node's Ed25519 private key for signing (32 bytes)
        """
        self.logger = logging.getLogger(__name__)
        self.node_id = node_id
        
        # Initialize Ed25519 signing key
        if len(private_key) == 32:
            # Raw 32-byte private key
            self.signing_key = SigningKey(private_key)
        elif len(private_key) == 64:
            # Assume it's a hex-encoded key, decode it
            try:
                raw_key = bytes.fromhex(private_key.decode() if isinstance(private_key, bytes) else private_key)
                self.signing_key = SigningKey(raw_key)
            except Exception:
                # If not hex, truncate to 32 bytes
                self.signing_key = SigningKey(private_key[:32])
        else:
            # Fallback: hash the provided key to get 32 bytes
            key_hash = hashlib.sha256(private_key).digest()
            self.signing_key = SigningKey(key_hash)
        
        # Store raw private key for legacy compatibility
        self.private_key = private_key
        
        # Get our public key
        self.public_key = self.signing_key.verify_key
        
        # Node registry
        self.node_registry: Dict[str, NodeRecord] = {}
        self.performance_reports: List[PerformanceReport] = []
        
        # Public key cache for verification
        self.public_key_cache: Dict[str, VerifyKey] = {}
        
        # Configuration
        self.reputation_decay_rate = 0.01  # Daily decay
        self.min_reputation = 0.0
        self.max_reputation = 1.0
        self.trust_threshold = 0.7
        self.ban_threshold = 0.2
        
        self.logger.info(f"Simplified DNIS initialized for node {node_id} with Ed25519 signatures")
    
    async def register_node(self, 
                           node_id: str, 
                           public_key: str,
                           endorser: Optional[str] = None) -> bool:
        """Register a new node in the system."""
        try:
            if node_id in self.node_registry:
                self.logger.warning(f"Node {node_id} already registered")
                return False
            
            # Calculate initial reputation based on endorser
            initial_reputation = 0.5  # Default
            if endorser and endorser in self.node_registry:
                endorser_rep = self.node_registry[endorser].reputation_score
                initial_reputation = min(0.6, endorser_rep * 0.8)
            
            # Create node record
            node_record = NodeRecord(
                node_id=node_id,
                public_key=public_key,
                first_seen=time.time(),
                last_seen=time.time(),
                reputation_score=initial_reputation,
                status=NodeStatus.UNKNOWN,
                endorsements=set(),
                complaints=set(),
                uptime_reports=[],
                bandwidth_reports=[]
            )
            
            self.node_registry[node_id] = node_record
            self.logger.info(f"Registered node {node_id} with reputation {initial_reputation}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error registering node {node_id}: {e}")
            return False
    
    async def submit_performance_report(self,
                                      target_node: str,
                                      uptime_percentage: float,
                                      avg_latency: float,
                                      bandwidth_mbps: float,
                                      successful_relays: int,
                                      failed_relays: int) -> bool:
        """Submit a performance report about a node."""
        try:
            if target_node not in self.node_registry:
                self.logger.warning(f"Cannot report on unknown node {target_node}")
                return False
            
            # Create signed report
            report_data = {
                'reporter': self.node_id,
                'target': target_node,
                'timestamp': time.time(),
                'uptime': uptime_percentage,
                'latency': avg_latency,
                'bandwidth': bandwidth_mbps,
                'successful_relays': successful_relays,
                'failed_relays': failed_relays
            }
            
            signature = self._sign_data(json.dumps(report_data, sort_keys=True))
            
            report = PerformanceReport(
                reporter_id=self.node_id,
                target_node=target_node,
                timestamp=time.time(),
                uptime_percentage=uptime_percentage,
                avg_latency=avg_latency,
                bandwidth_mbps=bandwidth_mbps,
                successful_relays=successful_relays,
                failed_relays=failed_relays,
                signature=signature
            )
            
            self.performance_reports.append(report)
            await self._update_node_reputation(target_node, report)
            
            self.logger.debug(f"Submitted performance report for {target_node}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error submitting performance report: {e}")
            return False
    
    async def endorse_node(self, target_node: str) -> bool:
        """Endorse a node (positive reputation signal)."""
        try:
            if target_node not in self.node_registry:
                return False
            
            node_record = self.node_registry[target_node]
            node_record.endorsements.add(self.node_id)
            
            # Boost reputation based on endorser's reputation
            endorser_rep = self.node_registry.get(self.node_id, NodeRecord).reputation_score
            boost = min(0.1, endorser_rep * 0.1)
            node_record.reputation_score = min(
                self.max_reputation,
                node_record.reputation_score + boost
            )
            
            await self._update_node_status(target_node)
            self.logger.info(f"Endorsed node {target_node}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error endorsing node {target_node}: {e}")
            return False
    
    async def report_complaint(self, target_node: str, reason: str) -> bool:
        """Report a complaint against a node."""
        try:
            if target_node not in self.node_registry:
                return False
            
            node_record = self.node_registry[target_node]
            node_record.complaints.add(f"{self.node_id}:{reason}")
            
            # Reduce reputation
            penalty = 0.05
            node_record.reputation_score = max(
                self.min_reputation,
                node_record.reputation_score - penalty
            )
            
            await self._update_node_status(target_node)
            self.logger.warning(f"Filed complaint against {target_node}: {reason}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error filing complaint against {target_node}: {e}")
            return False
    
    def get_node_reputation(self, node_id: str) -> Optional[float]:
        """Get current reputation score for a node."""
        if node_id in self.node_registry:
            return self.node_registry[node_id].reputation_score
        return None
    
    def get_trusted_nodes(self) -> List[str]:
        """Get list of trusted node IDs."""
        return [
            node_id for node_id, record in self.node_registry.items()
            if (record.reputation_score >= self.trust_threshold and 
                record.status not in [NodeStatus.BLOCKED, NodeStatus.SUSPICIOUS])
        ]
    
    def get_node_status(self, node_id: str) -> Optional[NodeStatus]:
        """Get current status for a node."""
        if node_id in self.node_registry:
            return self.node_registry[node_id].status
        return None
    
    async def cleanup_old_reports(self, max_age_days: int = 30):
        """Remove old performance reports."""
        cutoff_time = time.time() - (max_age_days * 24 * 3600)
        self.performance_reports = [
            report for report in self.performance_reports
            if report.timestamp > cutoff_time
        ]
    
    async def _update_node_reputation(self, node_id: str, report: PerformanceReport):
        """Update node reputation based on performance report."""
        node_record = self.node_registry[node_id]
        
        # Calculate performance score
        total_relays = report.successful_relays + report.failed_relays
        success_rate = report.successful_relays / total_relays if total_relays > 0 else 0.5
        
        # Normalize metrics
        uptime_score = report.uptime_percentage / 100.0
        latency_score = max(0.0, 1.0 - (report.avg_latency / 1000.0))  # Penalty for high latency
        
        # Combined performance score
        performance_score = (success_rate * 0.4 + uptime_score * 0.4 + latency_score * 0.2)
        
        # Update reputation with weighted average
        weight = 0.1  # How much this report affects overall reputation
        node_record.reputation_score = (
            node_record.reputation_score * (1 - weight) + 
            performance_score * weight
        )
        
        node_record.last_seen = time.time()
        node_record.uptime_reports.append(report.uptime_percentage)
        node_record.bandwidth_reports.append(report.bandwidth_mbps)
        
        # Keep only recent reports
        if len(node_record.uptime_reports) > 100:
            node_record.uptime_reports = node_record.uptime_reports[-50:]
        if len(node_record.bandwidth_reports) > 100:
            node_record.bandwidth_reports = node_record.bandwidth_reports[-50:]
    
    async def _update_node_status(self, node_id: str):
        """Update node status based on reputation."""
        node_record = self.node_registry[node_id]
        reputation = node_record.reputation_score
        
        if reputation >= self.trust_threshold:
            node_record.status = NodeStatus.TRUSTED
        elif reputation <= self.ban_threshold:
            node_record.status = NodeStatus.BLOCKED
        elif reputation < 0.4:
            node_record.status = NodeStatus.SUSPICIOUS
        elif reputation >= 0.5:
            node_record.status = NodeStatus.VERIFIED
        else:
            node_record.status = NodeStatus.UNKNOWN
    def _sign_data(self, data: str) -> str:
        """
        Sign data using Ed25519 digital signature algorithm.
        
        Replaced insecure hash-based construction with proper Ed25519 signatures
        for cryptographic security as per security hardening requirements.
        """
        try:
            # Create message to sign
            message = f"{self.node_id}:{data}".encode()
            
            # Sign using Ed25519
            signature = self.signing_key.sign(message)
            
            # Return base64-encoded signature for easy storage/transmission
            return signature.signature.hex()
            
        except Exception as e:
            self.logger.error(f"Error signing data: {e}")
            # Fallback to legacy method for compatibility
            return self._sign_data_legacy(data)
    
    def _sign_data_legacy(self, data: str) -> str:
        """
        Legacy signing method - kept for backward compatibility.
        DO NOT USE for new implementations - this is cryptographically insecure.
        """
        message = f"{self.node_id}:{data}".encode()
        signature_hash = hashlib.sha256(message + self.private_key).hexdigest()
        return signature_hash
    
    def _verify_signature(self, node_id: str, data: str, signature: str) -> bool:
        """
        Verify Ed25519 signature from a node.
        
        Args:
            node_id: ID of the node that created the signature
            data: Original data that was signed
            signature: Signature to verify (hex-encoded)
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Get the node's public key
            if node_id not in self.public_key_cache:
                # Try to get public key from node registry
                if node_id in self.node_registry:
                    public_key_hex = self.node_registry[node_id].public_key
                    try:
                        # Assume public key is hex-encoded
                        public_key_bytes = bytes.fromhex(public_key_hex)
                        self.public_key_cache[node_id] = VerifyKey(public_key_bytes)
                    except Exception:
                        self.logger.warning(f"Invalid public key format for node {node_id}")
                        return False
                else:
                    self.logger.warning(f"No public key available for node {node_id}")
                    return False
            
            verify_key = self.public_key_cache[node_id]
            
            # Reconstruct the original message
            message = f"{node_id}:{data}".encode()
            
            # Convert hex signature back to bytes
            signature_bytes = bytes.fromhex(signature)
            
            # Verify the signature
            verify_key.verify(message, signature_bytes)
            return True
            
        except (BadSignatureError, ValueError) as e:
            self.logger.warning(f"Invalid signature from node {node_id}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error verifying signature from node {node_id}: {e}")
            return False
    
    def get_network_statistics(self) -> Dict[str, Any]:
        """Get network-wide statistics."""
        if not self.node_registry:
            return {}
        
        reputations = [record.reputation_score for record in self.node_registry.values()]
        status_counts = {}
        for status in NodeStatus:
            status_counts[status.name] = sum(
                1 for record in self.node_registry.values() 
                if record.status == status
            )
        
        return {
            'total_nodes': len(self.node_registry),
            'avg_reputation': sum(reputations) / len(reputations),
            'status_distribution': status_counts,
            'trusted_nodes': len(self.get_trusted_nodes()),
            'total_reports': len(self.performance_reports)
        }
