"""
Generate realistic training data for censorship detection models.

This module generates synthetic network metrics that mimic real-world
censorship patterns based on research and observed behaviors.
"""

import time
from typing import Tuple

import numpy as np

from sush.control.censorship_detector import NetworkMetrics


class RealTrainingDataProvider:
    """Generates realistic training data for censorship detection."""

    def __init__(self, random_seed: int = 42):
        """Initialize the data provider with a random seed for reproducibility."""
        np.random.seed(random_seed)

    def generate_dataset(
        self, num_samples: int = 10000
    ) -> Tuple[list[list[float]], list[int]]:
        """
        Generate a complete dataset with realistic censorship patterns.

        Args:
            num_samples: Total number of samples to generate

        Returns:
            Tuple of (features_list, labels_list) where:
            - features_list: List of feature vectors (15 features each)
            - labels_list: List of labels (0=normal, 1=threat)
        """
        normal_samples = num_samples // 2
        threat_samples = num_samples - normal_samples

        normal_features = self._generate_normal_patterns(normal_samples)
        threat_features = self._generate_threat_patterns(threat_samples)

        all_features = normal_features + threat_features
        all_labels = [0] * len(normal_features) + [1] * len(threat_features)

        return all_features, all_labels

    def _generate_normal_patterns(self, num_samples: int) -> list[list[float]]:
        """
        Generate normal network behavior patterns.

        Characteristics:
        - Low latency (20-100ms)
        - Low packet loss (<1%)
        - Good throughput (5-20 MB/s)
        - High connection success rate (>95%)
        - Low jitter (<10ms)
        """
        features = []

        for _ in range(num_samples):
            base_time = time.time()

            # Base metrics (normal network conditions)
            latency = np.random.normal(0.05, 0.02)  # 20-100ms average
            latency = max(0.01, min(0.2, latency))  # Clamp to reasonable range

            packet_loss = np.random.exponential(0.005)  # Low loss rate
            packet_loss = min(0.05, packet_loss)  # Max 5%

            throughput = np.random.normal(10.0, 3.0)  # 5-20 MB/s
            throughput = max(1.0, throughput)  # Min 1 MB/s

            connection_success_rate = np.random.normal(0.97, 0.02)  # High success
            connection_success_rate = max(0.9, min(1.0, connection_success_rate))

            rst_packets = np.random.poisson(1)  # Very few RST packets
            retransmissions = np.random.poisson(2)  # Few retransmissions

            jitter = np.random.exponential(0.005)  # Low jitter
            jitter = min(0.01, jitter)  # Max 10ms

            bandwidth_utilization = np.random.normal(0.4, 0.15)  # Moderate usage
            bandwidth_utilization = max(0.1, min(0.8, bandwidth_utilization))

            # Create NetworkMetrics object to extract features properly
            metrics = NetworkMetrics(
                timestamp=base_time,
                latency=latency,
                packet_loss=packet_loss,
                throughput=throughput,
                connection_success_rate=connection_success_rate,
                rst_packets=rst_packets,
                retransmissions=retransmissions,
                jitter=jitter,
                bandwidth_utilization=bandwidth_utilization,
            )

            # Extract features (15 features total)
            feature_vector = self._extract_features(metrics, [metrics])
            features.append(feature_vector)

        return features

    def _generate_threat_patterns(self, num_samples: int) -> list[list[float]]:
        """
        Generate threat patterns mimicking real censorship techniques.

        Includes:
        - GFW Pattern: Random packet loss + High TCP Reset rate
        - Throttling Pattern: Low throughput + Normal latency
        - DPI Pattern: High latency (processing delay) + Connection drops
        - Mixed patterns
        """
        features = []

        # Distribute samples across different threat types
        gfw_samples = num_samples // 4
        throttling_samples = num_samples // 4
        dpi_samples = num_samples // 4
        mixed_samples = num_samples - (gfw_samples + throttling_samples + dpi_samples)

        # GFW Pattern: Random packet loss + High TCP Reset rate
        features.extend(self._generate_gfw_pattern(gfw_samples))

        # Throttling Pattern: Low throughput + Normal latency
        features.extend(self._generate_throttling_pattern(throttling_samples))

        # DPI Pattern: High latency + Connection drops after handshake
        features.extend(self._generate_dpi_pattern(dpi_samples))

        # Mixed patterns (combination of multiple techniques)
        features.extend(self._generate_mixed_pattern(mixed_samples))

        return features

    def _generate_gfw_pattern(self, num_samples: int) -> list[list[float]]:
        """
        Generate GFW (Great Firewall) pattern.

        Characteristics:
        - Random packet loss (5-30%)
        - High TCP Reset rate (10-50 RST packets)
        - Normal latency initially, then spikes
        - Connection success rate drops significantly
        """
        features = []
        base_time = time.time()

        for _ in range(num_samples):
            # GFW signature: high packet loss + many RST packets
            latency = np.random.normal(0.15, 0.1)  # Slightly elevated
            latency = max(0.05, min(0.5, latency))

            packet_loss = np.random.uniform(0.05, 0.3)  # High random loss

            throughput = np.random.normal(3.0, 1.5)  # Reduced throughput
            throughput = max(0.5, throughput)

            connection_success_rate = np.random.uniform(0.3, 0.7)  # Low success

            rst_packets = np.random.poisson(25)  # Many RST packets (GFW signature)
            retransmissions = np.random.poisson(20)  # Many retransmissions

            jitter = np.random.uniform(0.02, 0.1)  # Elevated jitter
            bandwidth_utilization = np.random.normal(0.6, 0.2)

            metrics = NetworkMetrics(
                timestamp=base_time,
                latency=latency,
                packet_loss=packet_loss,
                throughput=throughput,
                connection_success_rate=connection_success_rate,
                rst_packets=rst_packets,
                retransmissions=retransmissions,
                jitter=jitter,
                bandwidth_utilization=bandwidth_utilization,
            )

            feature_vector = self._extract_features(metrics, [metrics])
            features.append(feature_vector)

        return features

    def _generate_throttling_pattern(self, num_samples: int) -> list[list[float]]:
        """
        Generate traffic throttling pattern.

        Characteristics:
        - Low throughput (0.5-2 MB/s)
        - Normal latency (not blocked, just slowed)
        - Normal packet loss
        - Connection succeeds but slowly
        """
        features = []
        base_time = time.time()

        for _ in range(num_samples):
            latency = np.random.normal(0.08, 0.03)  # Normal latency
            latency = max(0.03, min(0.15, latency))

            packet_loss = np.random.exponential(0.01)  # Normal loss
            packet_loss = min(0.05, packet_loss)

            throughput = np.random.uniform(0.5, 2.0)  # Low throughput (throttled)

            connection_success_rate = np.random.normal(0.85, 0.1)  # Still connects
            connection_success_rate = max(0.7, min(0.95, connection_success_rate))

            rst_packets = np.random.poisson(3)  # Few RST packets
            retransmissions = np.random.poisson(5)  # Some retransmissions

            jitter = np.random.exponential(0.008)  # Slightly elevated
            jitter = min(0.02, jitter)

            bandwidth_utilization = np.random.normal(0.3, 0.1)  # Low utilization

            metrics = NetworkMetrics(
                timestamp=base_time,
                latency=latency,
                packet_loss=packet_loss,
                throughput=throughput,
                connection_success_rate=connection_success_rate,
                rst_packets=rst_packets,
                retransmissions=retransmissions,
                jitter=jitter,
                bandwidth_utilization=bandwidth_utilization,
            )

            feature_vector = self._extract_features(metrics, [metrics])
            features.append(feature_vector)

        return features

    def _generate_dpi_pattern(self, num_samples: int) -> list[list[float]]:
        """
        Generate DPI (Deep Packet Inspection) pattern.

        Characteristics:
        - High latency (processing delay during inspection)
        - Connection drops after handshake (DPI detected suspicious traffic)
        - Normal initial metrics, then sudden drop
        - High jitter (processing delays)
        """
        features = []
        base_time = time.time()

        for _ in range(num_samples):
            # DPI adds processing delay
            latency = np.random.normal(0.3, 0.15)  # High latency (processing)
            latency = max(0.1, min(1.0, latency))

            packet_loss = np.random.uniform(0.1, 0.4)  # High loss after detection

            throughput = np.random.normal(1.5, 1.0)  # Low throughput
            throughput = max(0.2, throughput)

            # Connection often fails after handshake (DPI detected)
            connection_success_rate = np.random.uniform(0.2, 0.6)  # Low success

            rst_packets = np.random.poisson(15)  # Moderate RST packets
            retransmissions = np.random.poisson(25)  # Many retransmissions

            jitter = np.random.uniform(0.05, 0.2)  # High jitter (processing delays)
            bandwidth_utilization = np.random.normal(0.5, 0.2)

            metrics = NetworkMetrics(
                timestamp=base_time,
                latency=latency,
                packet_loss=packet_loss,
                throughput=throughput,
                connection_success_rate=connection_success_rate,
                rst_packets=rst_packets,
                retransmissions=retransmissions,
                jitter=jitter,
                bandwidth_utilization=bandwidth_utilization,
            )

            feature_vector = self._extract_features(metrics, [metrics])
            features.append(feature_vector)

        return features

    def _generate_mixed_pattern(self, num_samples: int) -> list[list[float]]:
        """
        Generate mixed threat patterns (combination of techniques).

        Characteristics:
        - Combination of GFW, throttling, and DPI patterns
        - More severe overall impact
        """
        features = []
        base_time = time.time()

        for _ in range(num_samples):
            # Mix of all patterns
            latency = np.random.normal(0.25, 0.2)  # High latency
            latency = max(0.1, min(0.8, latency))

            packet_loss = np.random.uniform(0.1, 0.5)  # High loss

            throughput = np.random.uniform(0.3, 1.5)  # Very low throughput

            connection_success_rate = np.random.uniform(0.1, 0.5)  # Very low success

            rst_packets = np.random.poisson(30)  # Many RST packets
            retransmissions = np.random.poisson(35)  # Many retransmissions

            jitter = np.random.uniform(0.1, 0.3)  # Very high jitter
            bandwidth_utilization = np.random.normal(0.7, 0.2)  # High utilization

            metrics = NetworkMetrics(
                timestamp=base_time,
                latency=latency,
                packet_loss=packet_loss,
                throughput=throughput,
                connection_success_rate=connection_success_rate,
                rst_packets=rst_packets,
                retransmissions=retransmissions,
                jitter=jitter,
                bandwidth_utilization=bandwidth_utilization,
            )

            feature_vector = self._extract_features(metrics, [metrics])
            features.append(feature_vector)

        return features

    def _extract_features(
        self, metrics: NetworkMetrics, history: list[NetworkMetrics]
    ) -> list[float]:
        """
        Extract feature vector from metrics (matching CensorshipDetector._extract_features).

        Returns 15 features:
        - 8 base features (latency, packet_loss, throughput, etc.)
        - 3 delta features (if history available)
        - 4 statistical features (if history available)
        """
        import statistics

        # Base features (8)
        features = [
            metrics.latency,
            metrics.packet_loss,
            metrics.throughput,
            metrics.connection_success_rate,
            float(metrics.rst_packets),
            float(metrics.retransmissions),
            metrics.jitter,
            metrics.bandwidth_utilization,
        ]

        # Delta features (3) - rate of change
        if len(history) > 1:
            prev_metrics = history[-2]
            features.extend(
                [
                    metrics.latency - prev_metrics.latency,
                    metrics.throughput - prev_metrics.throughput,
                    metrics.packet_loss - prev_metrics.packet_loss,
                ]
            )
        else:
            features.extend([0.0, 0.0, 0.0])

        # Statistical features (4) - mean and std of recent history
        if len(history) >= 5:
            recent_latencies = [m.latency for m in history[-5:]]
            recent_throughputs = [m.throughput for m in history[-5:]]

            features.extend(
                [
                    statistics.mean(recent_latencies),
                    statistics.stdev(recent_latencies) if len(recent_latencies) > 1 else 0.0,
                    statistics.mean(recent_throughputs),
                    statistics.stdev(recent_throughputs) if len(recent_throughputs) > 1 else 0.0,
                ]
            )
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])

        return features
