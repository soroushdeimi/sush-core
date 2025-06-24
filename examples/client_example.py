#!/usr/bin/env python3
"""
SpectralFlow Client Example

Demonstrates how to use the SpectralFlow client for censorship circumvention.
"""

import asyncio
import logging
import sys
import argparse
from spectralflow.client import SpectralFlowClient, ClientConfig


async def simple_connection_example():
    """Simple example of creating a connection through SpectralFlow."""
    print("=== Simple Connection Example ===")
    
    # Create client configuration
    config = ClientConfig(
        log_level="INFO",
        obfuscation_level=0.8,
        enable_steganography=True
    )
    
    # Create and start client
    async with SpectralFlowClient(config) as client:
        print(f"Client started with node ID: {client.config.node_id}")
        
        # Connect to a target
        try:
            connection_id = await client.connect("httpbin.org", 80, "tcp")
            print(f"Connected to httpbin.org:80 via connection {connection_id}")
            
            # Send HTTP request
            http_request = (
                b"GET /ip HTTP/1.1\r\n"
                b"Host: httpbin.org\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            
            success = await client.send_data(connection_id, http_request)
            if success:
                print("HTTP request sent successfully")
                
                # Receive response
                response = await client.receive_data(connection_id, timeout=10.0)
                if response:
                    print(f"Received response ({len(response)} bytes):")
                    print(response.decode('utf-8', errors='ignore')[:500])
                else:
                    print("No response received")
            
            # Close connection
            await client.close_connection(connection_id)
            print("Connection closed")
            
        except Exception as e:
            print(f"Connection failed: {e}")


async def multi_connection_example():
    """Example of handling multiple simultaneous connections."""
    print("\n=== Multi-Connection Example ===")
    
    config = ClientConfig(
        max_concurrent_connections=5,
        obfuscation_level=0.6
    )
    
    async with SpectralFlowClient(config) as client:
        connections = []
        
        # Create multiple connections
        targets = [
            ("httpbin.org", 80),
            ("www.google.com", 80),
            ("www.github.com", 80)
        ]
        
        for host, port in targets:
            try:
                connection_id = await client.connect(host, port, "tcp")
                connections.append((connection_id, host, port))
                print(f"Connected to {host}:{port}")
            except Exception as e:
                print(f"Failed to connect to {host}:{port}: {e}")
        
        # Show connection stats
        for connection_id, host, port in connections:
            stats = client.get_connection_stats(connection_id)
            if stats:
                print(f"Connection {connection_id} to {host}:{port} - Duration: {stats['duration']:.2f}s")
        
        # Close all connections
        for connection_id, host, port in connections:
            await client.close_connection(connection_id)
            print(f"Closed connection to {host}:{port}")


async def adaptive_behavior_example():
    """Example demonstrating adaptive behavior and threat response."""
    print("\n=== Adaptive Behavior Example ===")
    
    config = ClientConfig(
        adaptation_interval=2.0,  # Adapt every 2 seconds
        enable_steganography=True,
        enable_traffic_morphing=True
    )
    
    async with SpectralFlowClient(config) as client:
        print("Monitoring system adaptation...")
        
        # Monitor status for 30 seconds
        start_time = asyncio.get_event_loop().time()
        last_strategy = None
        
        while asyncio.get_event_loop().time() - start_time < 30:
            status = client.get_status()
            current_strategy = status['system_status']['current_strategy']
            threat_level = status['security_status']['current_threat_level']
            
            if current_strategy != last_strategy:
                print(f"Strategy changed to: {current_strategy} (Threat: {threat_level})")
                last_strategy = current_strategy
            
            await asyncio.sleep(1)
        
        # Force strategy changes to demonstrate adaptation
        print("\nTesting forced adaptations:")
        
        strategies = ["aggressive", "stealth", "performance", "balanced"]
        for strategy in strategies:
            await client.force_adaptation(strategy)
            await asyncio.sleep(2)
            
            status = client.get_status()
            current_strategy = status['system_status']['current_strategy']
            print(f"Forced adaptation to: {current_strategy}")


async def status_monitoring_example():
    """Example of monitoring client status and statistics."""
    print("\n=== Status Monitoring Example ===")
    
    config = ClientConfig(log_level="DEBUG")
    
    async with SpectralFlowClient(config) as client:
        # Get comprehensive status
        status = client.get_status()
        
        print("=== Client Status ===")
        print(f"Running: {status['is_running']}")
        print(f"Connected: {status['is_connected']}")
        print(f"Node ID: {status['node_id']}")
        print(f"Active Connections: {status['active_connections']}")
        
        print("\n=== System Status ===")
        sys_status = status['system_status']
        print(f"System State: {sys_status['system_state']}")
        print(f"Current Strategy: {sys_status['current_strategy']}")
        print(f"Threat Level: {sys_status['threat_level']}")
        print(f"Recent Adaptations: {sys_status['recent_adaptations']}")
        
        print("\n=== Security Status ===")
        sec_status = status['security_status']
        print(f"Obfuscation Level: {sec_status['obfuscation_level']}")
        print(f"Steganography: {sec_status['steganography_enabled']}")
        print(f"Traffic Morphing: {sec_status['traffic_morphing_enabled']}")
        
        print("\n=== Network Status ===")
        net_status = status['network_status']
        print(f"Connected Mirrors: {net_status.get('connected_mirrors', 0)}")
        print(f"Active Circuits: {net_status.get('active_circuits', 0)}")
        print(f"Network Health: {net_status.get('network_health', 'Unknown')}")


async def main():
    """Main function to run examples."""
    parser = argparse.ArgumentParser(description="SpectralFlow Client Examples")
    parser.add_argument(
        "--example", 
        choices=["simple", "multi", "adaptive", "status", "all"],
        default="all",
        help="Example to run"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("SpectralFlow Client Examples")
    print("============================")
    
    try:
        if args.example == "simple" or args.example == "all":
            await simple_connection_example()
        
        if args.example == "multi" or args.example == "all":
            await multi_connection_example()
        
        if args.example == "adaptive" or args.example == "all":
            await adaptive_behavior_example()
        
        if args.example == "status" or args.example == "all":
            await status_monitoring_example()
        
        print("\nAll examples completed successfully!")
        
    except KeyboardInterrupt:
        print("\nExamples interrupted by user")
    except Exception as e:
        print(f"\nExample failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
