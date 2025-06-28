"""Censorship detection using ML models and statistical analysis."""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import numpy as np
from collections import deque, defaultdict
import statistics

# Machine Learning imports
from sklearn.ensemble import IsolationForest
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split


class ThreatLevel(Enum):
    """Threat severity levels."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class CensorshipType(Enum):
    """Types of censorship detected."""
    IP_BLOCKING = auto()
    PORT_BLOCKING = auto()
    DPI_FILTERING = auto()
    TRAFFIC_SHAPING = auto()
    CONNECTION_RESET = auto()
    DNS_POISONING = auto()
    TIMING_ATTACK = auto()
    STATISTICAL_ANALYSIS = auto()


@dataclass
class ThreatEvent:
    """Represents a detected threat or censorship attempt."""
    timestamp: float
    threat_type: CensorshipType
    severity: ThreatLevel
    confidence: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkMetrics:
    """Network performance and behavior metrics."""
    timestamp: float
    latency: float
    packet_loss: float
    throughput: float
    connection_success_rate: float
    rst_packets: int
    retransmissions: int
    jitter: float
    bandwidth_utilization: float


class CensorshipDetector:
    """Detects network censorship using ML algorithms."""
    
    def __init__(self, 
                 learning_rate: float = 0.01,
                 window_size: int = 100,
                 confidence_threshold: float = 0.8):
        self.learning_rate = learning_rate
        self.window_size = window_size
        self.confidence_threshold = confidence_threshold
        
        # Metrics collection
        self.metrics_history: deque = deque(maxlen=window_size)
        self.threat_history: deque = deque(maxlen=1000)
        
        # Connection tracking
        self.connection_attempts: defaultdict = defaultdict(list)
        self.failure_patterns: defaultdict = defaultdict(int)
        
        # Baseline metrics for anomaly detection
        self.baseline_latency: Optional[float] = None
        self.baseline_throughput: Optional[float] = None
        self.baseline_loss_rate: Optional[float] = None
        
        # Detection state
        self.is_monitoring = False
        self.current_threat_level = ThreatLevel.NONE
        
        # Machine Learning Models
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # Expected proportion of anomalies
            random_state=42,
            n_estimators=100        )
        
        self.threat_classifier = GaussianNB()
        self.feature_scaler = StandardScaler()
        
        # ML training data
        self.training_features: List[List[float]] = []
        self.training_labels: List[int] = []  # 0: normal, 1: censorship
        self.ml_models_trained = False
        self.feature_buffer: deque = deque(maxlen=50)  # For batch ML inference
        
        self.logger = logging.getLogger(__name__)
    
    async def start_monitoring(self):
        """Start continuous censorship monitoring."""
        self.is_monitoring = True
        self.logger.info("Starting censorship detection monitoring")
        
        # Train ML models if not already trained
        if not self.ml_models_trained:
            self.logger.info("Training ML models for censorship detection...")
            await self.train_ml_models()
        
        # Start monitoring tasks in background (don't wait for them)
        asyncio.create_task(self._monitor_connections())
        asyncio.create_task(self._analyze_patterns())
        asyncio.create_task(self._update_baselines())
        asyncio.create_task(self._ml_batch_analysis())
    
    async def stop_monitoring(self):
        """Stop censorship monitoring."""
        self.is_monitoring = False
        self.logger.info("Stopping censorship detection monitoring")
    
    async def record_metrics(self, metrics: NetworkMetrics):
        """Record network metrics for analysis."""
        self.metrics_history.append(metrics)
        
        # Extract features for ML models
        features = self._extract_features(metrics)
        self.feature_buffer.append(features)
        
        # Check for immediate threats
        threats = await self._detect_immediate_threats(metrics)
        
        # Use ML models for enhanced detection if trained
        if self.ml_models_trained:
            ml_threats = await self._ml_threat_detection(features)
            threats.extend(ml_threats)
        
        for threat in threats:
            self.threat_history.append(threat)
            self.logger.warning(f"Threat detected: {threat.threat_type.name} "
                              f"(confidence: {threat.confidence:.2f})")
    
    def _extract_features(self, metrics: NetworkMetrics) -> List[float]:
        """Extract ML features from network metrics."""
        features = [
            metrics.latency,
            metrics.packet_loss,
            metrics.throughput,
            metrics.connection_success_rate,
            metrics.rst_packets,
            metrics.retransmissions,
            metrics.jitter,
            metrics.bandwidth_utilization
        ]
        
        # Add derived features
        if len(self.metrics_history) > 1:
            prev_metrics = self.metrics_history[-2]
            
            # Rate of change features
            features.extend([
                metrics.latency - prev_metrics.latency,  # Latency delta
                metrics.throughput - prev_metrics.throughput,  # Throughput delta
                metrics.packet_loss - prev_metrics.packet_loss,  # Loss delta
            ])
        else:
            # No previous metrics, use zeros
            features.extend([0.0, 0.0, 0.0])
        
        # Statistical features from recent history
        if len(self.metrics_history) >= 5:
            recent_latencies = [m.latency for m in list(self.metrics_history)[-5:]]
            recent_throughputs = [m.throughput for m in list(self.metrics_history)[-5:]]
            
            features.extend([
                statistics.mean(recent_latencies),
                statistics.stdev(recent_latencies) if len(recent_latencies) > 1 else 0,
                statistics.mean(recent_throughputs),
                statistics.stdev(recent_throughputs) if len(recent_throughputs) > 1 else 0,
            ])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        return features
    
    async def _ml_threat_detection(self, features: List[float]) -> List[ThreatEvent]:
        """Use ML models for threat detection."""
        threats = []
        
        try:
            # Prepare features for ML models
            feature_array = np.array([features])
            
            # Scale features
            scaled_features = self.feature_scaler.transform(feature_array)
            
            # Anomaly detection
            anomaly_score = self.anomaly_detector.decision_function(scaled_features)[0]
            is_anomaly = self.anomaly_detector.predict(scaled_features)[0] == -1
            
            if is_anomaly:
                confidence = min(abs(anomaly_score) / 2.0, 1.0)  # Convert score to confidence
                threat = ThreatEvent(
                    timestamp=time.time(),
                    threat_type=CensorshipType.STATISTICAL_ANALYSIS,
                    severity=ThreatLevel.MEDIUM if confidence > 0.7 else ThreatLevel.LOW,
                    confidence=confidence,
                    details={'anomaly_score': anomaly_score, 'ml_detection': True}
                )
                threats.append(threat)
            
            # Threat classification
            threat_probability = self.threat_classifier.predict_proba(scaled_features)[0]
            if len(threat_probability) > 1 and threat_probability[1] > self.confidence_threshold:
                threat = ThreatEvent(
                    timestamp=time.time(),
                    threat_type=CensorshipType.DPI_FILTERING,  # Most common type
                    severity=ThreatLevel.HIGH,
                    confidence=threat_probability[1],
                    details={'ml_classification': True, 'probabilities': threat_probability.tolist()}
                )
                threats.append(threat)
                
        except Exception as e:
            self.logger.error(f"Error in ML threat detection: {e}")
        
        return threats
    
    async def train_ml_models(self, normal_data: List[List[float]] = None, 
                             threat_data: List[List[float]] = None):
        """Train ML models with provided or collected data."""
        try:
            # Use provided data or generate synthetic training data
            if normal_data is None or threat_data is None:
                normal_data, threat_data = self._generate_training_data()
            
            # Prepare training data
            all_features = normal_data + threat_data
            all_labels = [0] * len(normal_data) + [1] * len(threat_data)
            
            if len(all_features) < 10:
                self.logger.warning("Insufficient training data for ML models")
                return
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                all_features, all_labels, test_size=0.2, random_state=42
            )
            
            # Scale features
            X_train_scaled = self.feature_scaler.fit_transform(X_train)
            X_test_scaled = self.feature_scaler.transform(X_test)
            
            # Train anomaly detector (unsupervised - use only normal data)
            normal_train_data = [X_train_scaled[i] for i, label in enumerate(y_train) if label == 0]
            if len(normal_train_data) > 5:
                self.anomaly_detector.fit(normal_train_data)
            
            # Train threat classifier (supervised)
            self.threat_classifier.fit(X_train_scaled, y_train)
            
            # Evaluate models
            if len(X_test) > 0:
                classifier_score = self.threat_classifier.score(X_test_scaled, y_test)
                self.logger.info(f"ML threat classifier accuracy: {classifier_score:.3f}")
            
            self.ml_models_trained = True
            self.logger.info("ML models trained successfully")
            
        except Exception as e:
            self.logger.error(f"Error training ML models: {e}")
    
    def _generate_training_data(self) -> Tuple[List[List[float]], List[List[float]]]:
        """Generate synthetic training data for ML models."""
        normal_data = []
        threat_data = []
        
        # Generate normal network behavior patterns
        for _ in range(50):
            normal_features = [
                np.random.normal(0.05, 0.02),  # Normal latency ~50ms
                np.random.normal(0.01, 0.005),  # Low packet loss ~1%
                np.random.normal(10.0, 2.0),   # Good throughput ~10MB/s
                np.random.normal(0.95, 0.03),  # High success rate ~95%
                np.random.poisson(2),          # Few RST packets
                np.random.poisson(3),          # Few retransmissions
                np.random.normal(0.01, 0.005), # Low jitter
                np.random.normal(0.5, 0.1),    # Moderate bandwidth usage
                0, 0, 0,  # Delta features
                0, 0, 0, 0  # Statistical features (simplified)
            ]
            normal_data.append(normal_features)
        
        # Generate censorship/threat behavior patterns
        for _ in range(30):
            threat_features = [
                np.random.normal(0.2, 0.1),    # High latency
                np.random.normal(0.15, 0.05),  # High packet loss
                np.random.normal(2.0, 1.0),    # Low throughput
                np.random.normal(0.3, 0.15),   # Low success rate
                np.random.poisson(20),         # Many RST packets
                np.random.poisson(15),         # Many retransmissions  
                np.random.normal(0.1, 0.03),   # High jitter
                np.random.normal(0.8, 0.1),    # High bandwidth usage
                0, 0, 0,  # Delta features
                0, 0, 0, 0  # Statistical features (simplified)
            ]
            threat_data.append(threat_features)
        
        return normal_data, threat_data
    
    async def _detect_immediate_threats(self, metrics: NetworkMetrics) -> List[ThreatEvent]:
        """Detect immediate threats from current metrics."""
        threats = []
        
        # Check for connection reset patterns
        if metrics.rst_packets > 10:  # Threshold for abnormal RST packets
            threat = ThreatEvent(
                timestamp=metrics.timestamp,
                threat_type=CensorshipType.CONNECTION_RESET,
                severity=ThreatLevel.MEDIUM,
                confidence=min(metrics.rst_packets / 20.0, 1.0),
                details={'rst_packets': metrics.rst_packets}
            )
            threats.append(threat)
        
        # Check for traffic shaping (sudden throughput drops)
        if (self.baseline_throughput and 
            metrics.throughput < self.baseline_throughput * 0.3):
            threat = ThreatEvent(
                timestamp=metrics.timestamp,
                threat_type=CensorshipType.TRAFFIC_SHAPING,
                severity=ThreatLevel.MEDIUM,
                confidence=0.7,
                details={
                    'current_throughput': metrics.throughput,
                    'baseline_throughput': self.baseline_throughput
                }
            )
            threats.append(threat)
        
        # Check for timing attacks (unusual jitter patterns)
        if metrics.jitter > 0.5:  # High jitter threshold
            threat = ThreatEvent(
                timestamp=metrics.timestamp,
                threat_type=CensorshipType.TIMING_ATTACK,
                severity=ThreatLevel.LOW,
                confidence=min(metrics.jitter / 1.0, 1.0),
                details={'jitter': metrics.jitter}
            )
            threats.append(threat)
        
        return threats
    
    async def _monitor_connections(self):
        """Monitor connection patterns for blocking detection."""
        while self.is_monitoring:
            try:
                # Analyze connection failure patterns
                await self._analyze_connection_failures()
                await asyncio.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.logger.error(f"Error in connection monitoring: {e}")
    
    async def _analyze_patterns(self):
        """Analyze historical patterns for advanced threat detection."""
        while self.is_monitoring:
            try:
                if len(self.metrics_history) >= 10:
                    await self._statistical_analysis()
                    await self._pattern_recognition()
                await asyncio.sleep(10)  # Analyze every 10 seconds
            except Exception as e:
                self.logger.error(f"Error in pattern analysis: {e}")
    async def _update_baselines(self):
        """Update baseline metrics for anomaly detection."""
        while self.is_monitoring:
            try:
                if len(self.metrics_history) >= 20:
                    await self._compute_baselines()
                await asyncio.sleep(60)  # Update every minute
            except Exception as e:
                self.logger.error(f"Error updating baselines: {e}")
    
    async def _ml_batch_analysis(self):
        """Perform batch ML analysis on collected features."""
        while self.is_monitoring:
            try:
                if len(self.feature_buffer) >= 10 and self.ml_models_trained:
                    await self._analyze_feature_batch()
                await asyncio.sleep(30)  # Analyze every 30 seconds
            except Exception as e:
                self.logger.error(f"Error in ML batch analysis: {e}")
    
    async def _analyze_feature_batch(self):
        """Analyze a batch of features for patterns."""
        if not self.ml_models_trained or len(self.feature_buffer) < 5:
            return
        
        try:
            # Convert feature buffer to numpy array
            features_array = np.array(list(self.feature_buffer))
            scaled_features = self.feature_scaler.transform(features_array)
            
            # Batch anomaly detection
            anomaly_scores = self.anomaly_detector.decision_function(scaled_features)
            anomaly_predictions = self.anomaly_detector.predict(scaled_features)
            
            # Count anomalies in the batch
            anomaly_count = np.sum(anomaly_predictions == -1)
            anomaly_rate = anomaly_count / len(anomaly_predictions)
            
            # If anomaly rate is high, generate a threat event
            if anomaly_rate > 0.3:  # More than 30% anomalies
                threat = ThreatEvent(
                    timestamp=time.time(),
                    threat_type=CensorshipType.STATISTICAL_ANALYSIS,
                    severity=ThreatLevel.HIGH if anomaly_rate > 0.6 else ThreatLevel.MEDIUM,
                    confidence=min(anomaly_rate * 1.5, 1.0),
                    details={
                        'batch_anomaly_rate': anomaly_rate,
                        'batch_size': len(anomaly_predictions),
                        'ml_batch_analysis': True
                    }
                )
                self.threat_history.append(threat)
                self.logger.warning(f"High anomaly rate detected in batch: {anomaly_rate:.2f}")
            
        except Exception as e:
            self.logger.error(f"Error in batch analysis: {e}")
    
    async def _analyze_connection_failures(self):
        """Analyze connection failure patterns."""
        current_time = time.time()
        
        # Clean old connection attempts (older than 5 minutes)
        for endpoint in list(self.connection_attempts.keys()):
            self.connection_attempts[endpoint] = [
                t for t in self.connection_attempts[endpoint] 
                if current_time - t < 300
            ]
            if not self.connection_attempts[endpoint]:
                del self.connection_attempts[endpoint]
        
        # Check for systematic blocking patterns
        for endpoint, attempts in self.connection_attempts.items():
            if len(attempts) >= 5:  # Multiple failures to same endpoint
                failure_rate = len(attempts) / 5.0  # failures per 5 minutes
                if failure_rate > 0.8:  # High failure rate
                    threat = ThreatEvent(
                        timestamp=current_time,
                        threat_type=CensorshipType.IP_BLOCKING,
                        severity=ThreatLevel.HIGH,
                        confidence=min(failure_rate, 1.0),
                        destination_ip=endpoint.split(':')[0] if ':' in endpoint else endpoint,
                        details={'failure_rate': failure_rate, 'attempts': len(attempts)}
                    )
                    self.threat_history.append(threat)
    
    async def _statistical_analysis(self):
        """Perform statistical analysis on metrics."""
        if len(self.metrics_history) < 10:
            return
        
        recent_metrics = list(self.metrics_history)[-10:]
        
        # Analyze latency distribution
        latencies = [m.latency for m in recent_metrics]
        latency_variance = statistics.variance(latencies) if len(latencies) > 1 else 0
        
        # High variance might indicate interference
        if latency_variance > 0.1:  # Threshold for unusual variance
            threat = ThreatEvent(
                timestamp=time.time(),
                threat_type=CensorshipType.STATISTICAL_ANALYSIS,
                severity=ThreatLevel.LOW,
                confidence=min(latency_variance / 0.2, 1.0),
                details={'latency_variance': latency_variance}
            )
            self.threat_history.append(threat)
    
    async def _pattern_recognition(self):
        """Advanced pattern recognition for censorship detection."""
        if len(self.metrics_history) < 20:
            return
        
        recent_metrics = list(self.metrics_history)[-20:]
        
        # Check for DPI filtering patterns (sudden drops in success rates)
        success_rates = [m.connection_success_rate for m in recent_metrics]
        
        # Detect sudden drops that might indicate DPI activation
        for i in range(1, len(success_rates)):
            if (success_rates[i-1] > 0.9 and success_rates[i] < 0.5):
                threat = ThreatEvent(
                    timestamp=recent_metrics[i].timestamp,
                    threat_type=CensorshipType.DPI_FILTERING,
                    severity=ThreatLevel.HIGH,
                    confidence=0.8,
                    details={
                        'success_rate_drop': success_rates[i-1] - success_rates[i]
                    }
                )
                self.threat_history.append(threat)
    
    async def _compute_baselines(self):
        """Compute baseline metrics from recent history."""
        if len(self.metrics_history) < 20:
            return
        
        recent_metrics = list(self.metrics_history)[-20:]
        
        # Compute running averages
        latencies = [m.latency for m in recent_metrics]
        throughputs = [m.throughput for m in recent_metrics]
        loss_rates = [m.packet_loss for m in recent_metrics]
        
        self.baseline_latency = statistics.mean(latencies)
        self.baseline_throughput = statistics.mean(throughputs)
        self.baseline_loss_rate = statistics.mean(loss_rates)
        
        self.logger.debug(f"Updated baselines - Latency: {self.baseline_latency:.3f}s, "
                         f"Throughput: {self.baseline_throughput:.2f} MB/s, "
                         f"Loss rate: {self.baseline_loss_rate:.3f}")
    
    async def record_connection_attempt(self, endpoint: str, success: bool):
        """Record a connection attempt for pattern analysis."""
        current_time = time.time()
        
        if not success:
            self.connection_attempts[endpoint].append(current_time)
            self.failure_patterns[endpoint] += 1
    
    def get_current_threat_level(self) -> ThreatLevel:
        """Get the current overall threat level."""
        if not self.threat_history:
            return ThreatLevel.NONE
        
        # Check recent threats (last 5 minutes)
        current_time = time.time()
        recent_threats = [
            t for t in self.threat_history 
            if current_time - t.timestamp < 300
        ]
        
        if not recent_threats:
            return ThreatLevel.NONE
        
        # Return highest severity from recent threats
        max_severity = max(t.severity for t in recent_threats)
        return max_severity
    
    def get_recent_threats(self, count: int = 10) -> List[ThreatEvent]:
        """Get the most recent threat events."""
        return list(self.threat_history)[-count:]
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get comprehensive threat statistics."""
        if not self.threat_history:
            return {}
        
        threats = list(self.threat_history)
        threat_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for threat in threats:
            threat_counts[threat.threat_type] += 1
            severity_counts[threat.severity] += 1
        
        return {
            'total_threats': len(threats),
            'threat_types': dict(threat_counts),
            'severity_distribution': dict(severity_counts),
            'current_threat_level': self.current_threat_level.name,
            'baseline_metrics': {
                'latency': self.baseline_latency,
                'throughput': self.baseline_throughput,
                'packet_loss': self.baseline_loss_rate
            }
        }
