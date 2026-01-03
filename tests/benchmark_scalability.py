#!/usr/bin/env python3
"""
Scalability & Concurrency Benchmark for sushCore

Measures system performance under concurrent load with multiple clients.
"""

import asyncio
import csv
import logging
import sys
import time
from pathlib import Path
from typing import List, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sush.server import ServerConfig, SushServer

logging.basicConfig(
    level=logging.WARNING,  # Reduce noise for benchmark
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

OUTPUT_FILE = Path("tests/data/scalability_results.csv")
DATA_DIR = Path("tests/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)


async def run_single_client_transfer(
    client_id: int, server_host: str, server_port: int, payload_size: int
) -> tuple[int, float, bool, int]:
    """
    Run a single client transfer and measure performance.

    Returns:
        (client_id, latency_seconds, success, bytes_transferred)
    """
    # Use direct TCP connection - no need for full SushClient for benchmark
    import asyncio
    import os

    payload = os.urandom(payload_size)

    # Measure transfer
    start_time = time.perf_counter()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server_host, server_port), timeout=5.0
        )

        # Send payload with length prefix
        writer.write(len(payload).to_bytes(4, "big") + payload)
        await writer.drain()

        # Receive response
        try:
            length_data = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
            response_length = int.from_bytes(length_data, "big")
            response = await asyncio.wait_for(reader.readexactly(response_length), timeout=2.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            response = b""

        writer.close()
        await writer.wait_closed()

        elapsed_time = time.perf_counter() - start_time
        bytes_transferred = len(payload) + len(response)
        success = True

    except Exception as e:
        elapsed_time = time.perf_counter() - start_time
        bytes_transferred = 0
        success = False
        logger.debug(f"Client {client_id} connection failed: {e}")

    return (client_id, elapsed_time, success, bytes_transferred)


async def benchmark_concurrent_clients(
    num_clients: int, server_host: str, server_port: int, payload_size: int
) -> dict:
    """
    Run benchmark with specified number of concurrent clients.

    Returns:
        Dictionary with benchmark results
    """
    logger.info(f"Starting benchmark with {num_clients} concurrent clients...")

    start_time = time.perf_counter()

    # Create tasks for all clients
    tasks = [
        run_single_client_transfer(i, server_host, server_port, payload_size)
        for i in range(num_clients)
    ]

    # Run all clients concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    total_time = time.perf_counter() - start_time

    # Process results
    successful_transfers = 0
    total_bytes = 0
    latencies = []

    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Task exception: {result}")
            continue

        client_id, latency, success, bytes_transferred = result

        if success:
            successful_transfers += 1
            total_bytes += bytes_transferred
            latencies.append(latency)

    # Calculate metrics
    success_rate = (successful_transfers / num_clients) * 100 if num_clients > 0 else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    min_latency = min(latencies) if latencies else 0.0
    max_latency = max(latencies) if latencies else 0.0

    # Throughput calculation
    total_megabits = (total_bytes * 8) / (1024 * 1024)  # Convert to megabits
    throughput_mbps = total_megabits / total_time if total_time > 0 else 0.0

    return {
        "num_clients": num_clients,
        "payload_size_bytes": payload_size,
        "total_time_seconds": total_time,
        "successful_transfers": successful_transfers,
        "success_rate_percent": success_rate,
        "avg_latency_seconds": avg_latency,
        "min_latency_seconds": min_latency,
        "max_latency_seconds": max_latency,
        "total_bytes_transferred": total_bytes,
        "throughput_mbps": throughput_mbps,
        "timestamp": time.time(),
    }


async def main():
    """Run scalability benchmarks."""
    print("=" * 70)
    print("sushCore Scalability & Concurrency Benchmark")
    print("=" * 70)

    # Server configuration
    server_host = "127.0.0.1"
    server_port = 9090

    # Start server
    print("\nStarting server...")
    server_config = ServerConfig(
        listen_address=server_host,
        listen_ports=[server_port],
        require_authentication=False,  # Disable auth for benchmark (localhost testing)
        log_level="WARNING",
    )
    server = SushServer(server_config)

    try:
        await server.start()
        print(f"Server started on {server_host}:{server_port}")

        # Wait for server to be ready
        await asyncio.sleep(2)

        # Test configurations
        payload_size = 100 * 1024  # 100KB
        client_counts = [1, 10, 50, 100]

        results = []

        for num_clients in client_counts:
            print(f"\n{'=' * 70}")
            print(f"Testing with {num_clients} concurrent clients...")
            print(f"{'=' * 70}")

            result = await benchmark_concurrent_clients(
                num_clients, server_host, server_port, payload_size
            )
            results.append(result)

            print(f"\nResults for {num_clients} clients:")
            print(f"  Success Rate: {result['success_rate_percent']:.1f}%")
            print(f"  Avg Latency: {result['avg_latency_seconds'] * 1000:.2f}ms")
            print(f"  Throughput: {result['throughput_mbps']:.2f} Mbps")
            print(f"  Total Time: {result['total_time_seconds']:.2f}s")

            # Small delay between tests
            await asyncio.sleep(1)

        # Save results
        print(f"\n{'=' * 70}")
        print("Saving results...")
        print(f"{'=' * 70}")

        if results:
            fieldnames = list(results[0].keys())
            with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)

            print(f"Results saved to {OUTPUT_FILE}")
            print(f"Total tests: {len(results)}")

        print("\n" + "=" * 70)
        print("Scalability benchmark completed!")
        print("=" * 70)

    except Exception as e:
        logger.error(f"Benchmark failed: {e}", exc_info=True)
        raise
    finally:
        print("\nStopping server...")
        await server.stop()
        print("Server stopped")


if __name__ == "__main__":
    asyncio.run(main())
