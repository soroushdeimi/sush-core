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
    """Simplified Node Integrity System."""

    def __init__(self, node_id: str, private_key: bytes):
        self.logger = logging.getLogger(__name__)
        self.node_id = node_id
        if len(private_key) == 32:
            self.signing_key = SigningKey(private_key)
        elif len(private_key) == 64:
            try:
                raw_key = bytes.fromhex(
                    private_key.decode() if isinstance(private_key, bytes) else private_key
                )
                self.signing_key = SigningKey(raw_key)
            except Exception:
                self.signing_key = SigningKey(private_key[:32])
        else:
            key_hash = hashlib.sha256(private_key).digest()
            self.signing_key = SigningKey(key_hash)
        self.private_key = private_key
        self.public_key = self.signing_key.verify_key
        self.node_registry: Dict[str, NodeRecord] = {}
        self.performance_reports: List[PerformanceReport] = []
        self.public_key_cache: Dict[str, VerifyKey] = {}
        self.reputation_decay_rate = 0.01
        self.min_reputation = 0.0
        self.max_reputation = 1.0
        self.trust_threshold = 0.7
        self.ban_threshold = 0.2
        self.logger.info(f"Simplified DNIS initialized for node {node_id} with Ed25519 signatures")

    async def register_node(
        self, node_id: str, public_key: str, endorser: Optional[str] = None
    ) -> bool:
        try:
            if node_id in self.node_registry:
                self.logger.warning(f"Node {node_id} already registered")
                return False
            initial_reputation = 0.5
            if endorser and endorser in self.node_registry:
                endorser_rep = self.node_registry[endorser].reputation_score
                initial_reputation = min(0.6, endorser_rep * 0.8)
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
                bandwidth_reports=[],
            )
            self.node_registry[node_id] = node_record
            self.logger.info(f"Registered node {node_id} with reputation {initial_reputation}")
            return True
        except Exception as e:
            self.logger.error(f"Error registering node {node_id}: {e}")
            return False

    async def submit_performance_report(
        self,
        target_node: str,
        uptime_percentage: float,
        avg_latency: float,
        bandwidth_mbps: float,
        successful_relays: int,
        failed_relays: int,
    ) -> bool:
        try:
            if target_node not in self.node_registry:
                self.logger.warning(f"Cannot report on unknown node {target_node}")
                return False
            report_data = {
                "reporter": self.node_id,
                "target": target_node,
                "timestamp": time.time(),
                "uptime": uptime_percentage,
                "latency": avg_latency,
                "bandwidth": bandwidth_mbps,
                "successful_relays": successful_relays,
                "failed_relays": failed_relays,
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
                signature=signature,
            )
            self.performance_reports.append(report)
            await self._update_node_reputation(target_node, report)
            self.logger.debug(f"Submitted performance report for {target_node}")
            return True
        except Exception as e:
            self.logger.error(f"Error submitting performance report: {e}")
            return False

    async def endorse_node(self, target_node: str) -> bool:
        try:
            if target_node not in self.node_registry:
                return False
            node_record = self.node_registry[target_node]
            node_record.endorsements.add(self.node_id)
            endorser_rep = self.node_registry.get(self.node_id, NodeRecord).reputation_score
            boost = min(0.1, endorser_rep * 0.1)
            node_record.reputation_score = min(
                self.max_reputation, node_record.reputation_score + boost
            )
            await self._update_node_status(target_node)
            self.logger.info(f"Endorsed node {target_node}")
            return True
        except Exception as e:
            self.logger.error(f"Error endorsing node {target_node}: {e}")
            return False

    async def report_complaint(self, target_node: str, reason: str) -> bool:
        try:
            if target_node not in self.node_registry:
                return False
            node_record = self.node_registry[target_node]
            node_record.complaints.add(f"{self.node_id}:{reason}")
            penalty = 0.05
            node_record.reputation_score = max(
                self.min_reputation, node_record.reputation_score - penalty
            )
            await self._update_node_status(target_node)
            self.logger.warning(f"Filed complaint against {target_node}: {reason}")
            return True
        except Exception as e:
            self.logger.error(f"Error filing complaint against {target_node}: {e}")
            return False

    def get_node_reputation(self, node_id: str) -> Optional[float]:
        if node_id in self.node_registry:
            return self.node_registry[node_id].reputation_score
        return None

    def get_trusted_nodes(self) -> List[str]:
        return [
            node_id
            for node_id, record in self.node_registry.items()
            if (
                record.reputation_score >= self.trust_threshold
                and record.status not in [NodeStatus.BLOCKED, NodeStatus.SUSPICIOUS]
            )
        ]

    def get_node_status(self, node_id: str) -> Optional[NodeStatus]:
        if node_id in self.node_registry:
            return self.node_registry[node_id].status
        return None

    async def cleanup_old_reports(self, max_age_days: int = 30):
        cutoff_time = time.time() - (max_age_days * 24 * 3600)
        self.performance_reports = [
            report for report in self.performance_reports if report.timestamp > cutoff_time
        ]

    async def _update_node_reputation(self, node_id: str, report: PerformanceReport):
        node_record = self.node_registry[node_id]
        total_relays = report.successful_relays + report.failed_relays
        success_rate = report.successful_relays / total_relays if total_relays > 0 else 0.5
        uptime_score = report.uptime_percentage / 100.0
        latency_score = max(0.0, 1.0 - (report.avg_latency / 1000.0))
        performance_score = success_rate * 0.4 + uptime_score * 0.4 + latency_score * 0.2
        weight = 0.1
        node_record.reputation_score = (
            node_record.reputation_score * (1 - weight) + performance_score * weight
        )
        node_record.last_seen = time.time()
        node_record.uptime_reports.append(report.uptime_percentage)
        node_record.bandwidth_reports.append(report.bandwidth_mbps)
        if len(node_record.uptime_reports) > 100:
            node_record.uptime_reports = node_record.uptime_reports[-50:]
        if len(node_record.bandwidth_reports) > 100:
            node_record.bandwidth_reports = node_record.bandwidth_reports[-50:]

    async def _update_node_status(self, node_id: str):
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
        try:
            message = f"{self.node_id}:{data}".encode()
            signature = self.signing_key.sign(message)
            return signature.signature.hex()
        except Exception as e:
            self.logger.error(f"Error signing data: {e}")
            return self._sign_data_legacy(data)

    def _sign_data_legacy(self, data: str) -> str:
        message = f"{self.node_id}:{data}".encode()
        signature_hash = hashlib.sha256(message + self.private_key).hexdigest()
        return signature_hash

    def _verify_signature(self, node_id: str, data: str, signature: str) -> bool:
        try:
            if node_id not in self.public_key_cache:
                if node_id in self.node_registry:
                    public_key_hex = self.node_registry[node_id].public_key
                    try:
                        public_key_bytes = bytes.fromhex(public_key_hex)
                        self.public_key_cache[node_id] = VerifyKey(public_key_bytes)
                    except Exception:
                        self.logger.warning(f"Invalid public key format for node {node_id}")
                        return False
                else:
                    self.logger.warning(f"No public key available for node {node_id}")
                    return False
            verify_key = self.public_key_cache[node_id]
            message = f"{node_id}:{data}".encode()
            signature_bytes = bytes.fromhex(signature)
            verify_key.verify(message, signature_bytes)
            return True
        except (BadSignatureError, ValueError) as e:
            self.logger.warning(f"Invalid signature from node {node_id}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error verifying signature from node {node_id}: {e}")
            return False

    def get_network_statistics(self) -> Dict[str, Any]:
        if not self.node_registry:
            return {}
        reputations = [record.reputation_score for record in self.node_registry.values()]
        status_counts = {}
        for status in NodeStatus:
            status_counts[status.name] = sum(
                1 for record in self.node_registry.values() if record.status == status
            )
        return {
            "total_nodes": len(self.node_registry),
            "avg_reputation": sum(reputations) / len(reputations),
            "status_distribution": status_counts,
            "trusted_nodes": len(self.get_trusted_nodes()),
            "total_reports": len(self.performance_reports),
        }
