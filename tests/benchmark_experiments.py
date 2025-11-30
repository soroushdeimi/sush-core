#!/usr/bin/env python3
"""
Benchmark Experiments for sushCore
Measures real performance of production-grade implementations.
"""

import asyncio
import csv
import logging
import os
import time
from pathlib import Path

import numpy as np

from sush.core.quantum_obfuscator import QuantumObfuscator
from sush.core.traffic_morphing import TrafficMorphingEngine
from sush.control.adaptive_control import AdaptiveControlLoop
from sush.control.censorship_detector import CensorshipDetector, NetworkMetrics
from sush.control.response_engine import ResponseEngine
from sush.control.threat_monitor import ThreatMonitor
from sush.core.adaptive_cipher import NetworkCondition, ThreatLevel as CipherThreatLevel
from sush.transport.adaptive_transport import AdaptiveTransport

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

RESULTS_DIR = Path("experiment_results")
RESULTS_DIR.mkdir(exist_ok=True)
CSV_FILE = RESULTS_DIR / "experiment_data.csv"


class ExperimentRunner:
    """Run benchmark experiments on real sushCore components."""

    def __init__(self):
        self.results = []
        self.quantum_obfuscator = QuantumObfuscator()
        self.traffic_morpher = TrafficMorphingEngine()

    async def experiment_a_latency_overhead(self):
        """Experiment A: Measure crypto processing overhead."""
        logger.info("Starting Experiment A: Latency Overhead Analysis")

        payload_sizes = [1024, 102400, 1048576]  # 1KB, 100KB, 1MB
        modes = ["DIRECT", "PARANOID"]

        for size in payload_sizes:
            payload = os.urandom(size)

            for mode in modes:
                logger.info(f"Testing {size} bytes in {mode} mode")

                # DIRECT mode: No crypto, just morphing
                if mode == "DIRECT":
                    start = time.perf_counter()
                    morphed = self.traffic_morpher.morph_packet(payload)
                    morph_time = time.perf_counter() - start

                    start = time.perf_counter()
                    reconstructed = b""
                    for packet in morphed:
                        extracted = self.traffic_morpher.extract_original_data(packet)
                        reconstructed += extracted
                    extract_time = time.perf_counter() - start

                    total_time = morph_time + extract_time
                    crypto_time = 0.0
                    overhead_bytes = sum(len(p) for p in morphed) - len(payload)

                else:  # PARANOID mode: Full crypto + morphing
                    # Initialize session with high threat level
                    session_id = f"bench_{size}_{int(time.time())}"
                    peer_pub, _ = self.quantum_obfuscator.kem.generate_keypair()

                    start = time.perf_counter()
                    await self.quantum_obfuscator.initialize_session(
                        session_id,
                        peer_pub,
                        threat_level=CipherThreatLevel.CRITICAL,
                        network_condition=NetworkCondition.MEDIUM_BANDWIDTH,
                    )
                    init_time = time.perf_counter() - start

                    start = time.perf_counter()
                    obfuscated = await self.quantum_obfuscator.obfuscate_data(session_id, payload)
                    obfuscate_time = time.perf_counter() - start

                    start = time.perf_counter()
                    deobfuscated = await self.quantum_obfuscator.deobfuscate_data(
                        session_id, obfuscated
                    )
                    deobfuscate_time = time.perf_counter() - start

                    total_time = init_time + obfuscate_time + deobfuscate_time
                    crypto_time = total_time
                    overhead_bytes = sum(len(p) for p in obfuscated) - len(payload)

                    # Verify correctness
                    assert deobfuscated == payload, "Data corruption detected!"

                self.results.append(
                    {
                        "experiment": "A",
                        "payload_size_bytes": size,
                        "mode": mode,
                        "total_time_seconds": total_time,
                        "crypto_time_seconds": crypto_time,
                        "overhead_bytes": overhead_bytes,
                        "overhead_percent": (overhead_bytes / len(payload)) * 100 if payload else 0,
                        "throughput_mbps": (size * 8) / (total_time * 1_000_000)
                        if total_time > 0
                        else 0,
                        "timestamp": time.time(),
                    }
                )

                logger.info(
                    f"  {mode}: {total_time * 1000:.2f}ms, "
                    f"Overhead: {overhead_bytes} bytes ({overhead_bytes / len(payload) * 100:.1f}%)"
                )

    async def experiment_b_adaptive_response(self):
        """Experiment B: Measure adaptive control loop response time."""
        logger.info("Starting Experiment B: Adaptive Response Timing")

        detector = CensorshipDetector()
        monitor = ThreatMonitor()
        response_engine = ResponseEngine()
        control_loop = AdaptiveControlLoop()

        await control_loop.initialize_components(
            censorship_detector=detector,
            threat_monitor=monitor,
            response_engine=response_engine,
            quantum_obfuscator=self.quantum_obfuscator,
            adaptive_transport=AdaptiveTransport(),
            mirror_network=None,
        )

        await detector.start_monitoring()
        await monitor.start_monitoring()
        await response_engine.start()
        await control_loop.start()

        # Simulate chaotic network conditions
        chaotic_metrics = [
            NetworkMetrics(
                timestamp=time.time() + i * 0.1,
                latency=50.0 + np.random.uniform(-20, 100),
                packet_loss=np.random.uniform(0.0, 0.3),
                throughput=1000000.0 * (1 - np.random.uniform(0, 0.5)),
                connection_success_rate=1.0 - np.random.uniform(0, 0.4),
                rst_packets=int(np.random.exponential(5)),
                retransmissions=int(np.random.exponential(10)),
                jitter=np.random.uniform(0, 50),
                bandwidth_utilization=np.random.uniform(0.3, 0.9),
            )
            for i in range(50)
        ]

        initial_strategy = control_loop.get_system_status()["current_strategy"]
        adaptation_times = []

        for i, metrics in enumerate(chaotic_metrics):
            record_start = time.perf_counter()
            await detector.record_metrics(metrics)

            # Force control loop to process (it runs on interval, so we trigger manually)
            # Wait for adaptation interval to allow processing
            await asyncio.sleep(control_loop.adaptation_interval + 0.1)

            # Also manually trigger evaluation if possible
            if hasattr(control_loop, "_evaluate_conditions"):
                await control_loop._evaluate_conditions()

            current_status = control_loop.get_system_status()
            current_strategy = current_status["current_strategy"]

            if current_strategy != initial_strategy:
                adaptation_time = time.perf_counter() - record_start
                adaptation_times.append(
                    {
                        "metric_index": i,
                        "adaptation_time_seconds": adaptation_time,
                        "from_strategy": str(initial_strategy),
                        "to_strategy": str(current_strategy),
                        "threat_level": str(current_status.get("threat_level", "unknown")),
                        "timestamp": metrics.timestamp,
                    }
                )
                logger.info(
                    f"  Adaptation detected: {initial_strategy} -> {current_strategy} "
                    f"in {adaptation_time * 1000:.2f}ms"
                )
                initial_strategy = current_strategy

        # Record all adaptation events
        for event in adaptation_times:
            self.results.append(
                {
                    "experiment": "B",
                    "metric_index": event["metric_index"],
                    "adaptation_time_seconds": event["adaptation_time_seconds"],
                    "from_strategy": event["from_strategy"],
                    "to_strategy": event["to_strategy"],
                    "threat_level": event["threat_level"],
                    "timestamp": event["timestamp"],
                }
            )

        await control_loop.stop()
        await response_engine.stop()
        await monitor.stop_monitoring()
        await detector.stop_monitoring()

    def save_results(self):
        """Save experiment results to CSV."""
        if not self.results:
            logger.warning("No results to save")
            return

        fieldnames = set()
        for result in self.results:
            fieldnames.update(result.keys())

        fieldnames = sorted(fieldnames)

        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)

        logger.info(f"Saved {len(self.results)} results to {CSV_FILE}")


async def main():
    """Run all benchmark experiments."""
    print("=" * 60)
    print("sushCore Benchmark Experiments")
    print("=" * 60)

    runner = ExperimentRunner()

    try:
        await runner.experiment_a_latency_overhead()
        await runner.experiment_b_adaptive_response()
        runner.save_results()

        print("\n" + "=" * 60)
        print("Experiments completed successfully!")
        print(f"Results saved to: {CSV_FILE}")
        print("=" * 60)

    except Exception as e:
        logger.error(f"Experiment failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    asyncio.run(main())
