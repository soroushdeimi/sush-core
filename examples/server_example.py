#!/usr/bin/env python3
"""
Sushcore Server Example

Demonstrates how to run a SpectralFlow server/mirror node.
"""

import asyncio
import logging
import sys
import argparse
import signal
from spectralflow.server import SpectralFlowServer, ServerConfig


class GracefulExit(SystemExit):
    """Custom exception for graceful shutdown."""
    code = 1


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    print(f"Received signal {signum}, initiating graceful shutdown...")
    raise GracefulExit()


async def run_basic_server():
    """Run a basic SpectralFlow server."""
    print("=== Basic Server Example ===")
    
    config = ServerConfig(
        listen_address="0.0.0.0",
        listen_ports=[8443, 8080],
        is_mirror_node=True,
        max_clients=100,
        log_level="INFO"
    )
    
    server = SpectralFlowServer(config)
    
    try:
        await server.start()
        print(f"Server started on ports {config.listen_ports}")
        print(f"Node ID: {config.node_id}")
        print("Press Ctrl+C to stop...")
        
        # Keep server running
        while server.is_running:
            # Print status every 30 seconds
            await asyncio.sleep(30)
            status = server.get_status()
            print(f"Status: {status['active_connections']} connections, "
                  f"{status['relay_connections']} relays, "
                  f"uptime: {status['uptime']:.1f}s")
    
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        await server.stop()


async def run_bridge_relay():
    """Run a bridge relay server."""
    print("=== Bridge Relay Example ===")
    
    config = ServerConfig(
        listen_address="0.0.0.0",
        listen_ports=[443, 80, 53],  # Common ports to avoid blocking
        is_mirror_node=True,
        is_bridge_relay=True,
        require_authentication=True,
        max_clients=50,
        bandwidth_limit=50_000_000,  # 50 Mbps
        log_level="INFO"
    )
    
    server = SpectralFlowServer(config)
    
    try:
        await server.start()
        
        # Display bridge information
        node_info = server.get_node_info()
        print(f"Bridge Relay started!")
        print(f"Node ID: {node_info['node_id']}")
        print(f"Listening on: {node_info['address']}:{node_info['ports']}")
        print(f"Capabilities: {node_info['capabilities']}")
        print(f"Bridge line for clients:")
        print(f"Bridge {node_info['address']}:{node_info['ports'][0]} {node_info['node_id']}")
        
        # Keep running
        while server.is_running:
            await asyncio.sleep(10)
            
            # Show periodic stats
            status = server.get_status()
            if status['active_connections'] > 0:
                print(f"Active: {status['active_connections']} connections, "
                      f"{status['statistics']['bytes_relayed']} bytes relayed")
    
    except KeyboardInterrupt:
        print("Shutting down bridge relay...")
    finally:
        await server.stop()


async def run_directory_server():
    """Run a directory server."""
    print("=== Directory Server Example ===")
    
    config = ServerConfig(
        listen_address="0.0.0.0",
        listen_ports=[8080, 8443],
        is_mirror_node=True,
        is_directory_server=True,
        max_clients=200,
        log_level="INFO"
    )
    
    server = SpectralFlowServer(config)
    
    try:
        await server.start()
        
        print("Directory server started!")
        print(f"Node ID: {config.node_id}")
        print("Providing directory services to the network...")
        
        # Monitor directory status
        while server.is_running:
            await asyncio.sleep(60)  # Check every minute
            
            status = server.get_status()
            integrity_status = status['integrity_status']
            
            print(f"Directory status: {integrity_status['total_nodes']} nodes, "
                  f"{integrity_status['trusted_nodes']} trusted, "
                  f"blockchain height: {integrity_status['blockchain_height']}")
    
    except KeyboardInterrupt:
        print("Shutting down directory server...")
    finally:
        await server.stop()


async def run_high_performance_server():
    """Run a high-performance server optimized for throughput."""
    print("=== High-Performance Server Example ===")
    
    config = ServerConfig(
        listen_address="0.0.0.0",
        listen_ports=[8443, 8080, 443, 80, 53],
        is_mirror_node=True,
        max_clients=1000,
        max_circuits=2000,
        bandwidth_limit=1_000_000_000,  # 1 Gbps
        connection_timeout=30.0,
        circuit_timeout=300.0,  # Shorter timeout for high turnover
        cleanup_interval=60.0,
        log_level="WARNING"  # Reduce logging overhead
    )
    
    server = SpectralFlowServer(config)
    
    try:
        await server.start()
        
        print("High-performance server started!")
        print(f"Optimized for: {config.max_clients} clients, {config.bandwidth_limit/1_000_000:.0f} Mbps")
        
        # Enhanced monitoring
        last_stats = None
        
        while server.is_running:
            await asyncio.sleep(10)
            
            status = server.get_status()
            current_stats = status['statistics']
            
            if last_stats:
                # Calculate rates
                time_diff = 10.0  # 10 seconds
                bytes_diff = current_stats['bytes_relayed'] - last_stats['bytes_relayed']
                conn_diff = current_stats['connections_handled'] - last_stats['connections_handled']
                
                mbps = (bytes_diff * 8) / (time_diff * 1_000_000)
                conn_rate = conn_diff / time_diff
                
                print(f"Performance: {mbps:.1f} Mbps, {conn_rate:.1f} conn/s, "
                      f"{status['active_connections']} active connections")
            
            last_stats = current_stats.copy()
    
    except KeyboardInterrupt:
        print("Shutting down high-performance server...")
    finally:
        await server.stop()


async def run_monitoring_server():
    """Run a server with detailed monitoring and statistics."""
    print("=== Monitoring Server Example ===")
    
    config = ServerConfig(
        listen_address="0.0.0.0",
        listen_ports=[8443],
        is_mirror_node=True,
        log_level="DEBUG"
    )
    
    server = SpectralFlowServer(config)
    
    try:
        await server.start()
        
        print("Monitoring server started!")
        print("Detailed statistics will be displayed every 30 seconds...")
        
        while server.is_running:
            await asyncio.sleep(30)
            
            # Get comprehensive status
            status = server.get_status()
            
            print("\n" + "="*60)
            print(f"SPECTRALFLOW SERVER STATUS - Uptime: {status['uptime']:.1f}s")
            print("="*60)
            
            print(f"Connections: {status['active_connections']} active, "
                  f"{status['relay_connections']} relays")
            print(f"Circuits: {status['active_circuits']} active")
            
            print("\nStatistics:")
            stats = status['statistics']
            print(f"  Total connections handled: {stats['connections_handled']}")
            print(f"  Total bytes relayed: {stats['bytes_relayed']:,}")
            print(f"  Circuits created: {stats['circuits_created']}")
            print(f"  Blocked connections: {stats['blocked_connections']}")
            
            print("\nSystem Status:")
            sys_status = status['system_status']
            print(f"  System state: {sys_status['system_state']}")
            print(f"  Current strategy: {sys_status['current_strategy']}")
            print(f"  Threat level: {sys_status['threat_level']}")
            
            print("\nNetwork Status:")
            net_status = status['network_status']
            print(f"  Network health: {net_status.get('network_health', 'Unknown')}")
            print(f"  Connected mirrors: {net_status.get('connected_mirrors', 0)}")
            
            print("\nIntegrity Status:")
            integrity_status = status['integrity_status']
            print(f"  Blockchain height: {integrity_status['blockchain_height']}")
            print(f"  Total nodes: {integrity_status['total_nodes']}")
            print(f"  Trusted nodes: {integrity_status['trusted_nodes']}")
            print(f"  Chain valid: {integrity_status['chain_valid']}")
    
    except KeyboardInterrupt:
        print("Shutting down monitoring server...")
    finally:
        await server.stop()


async def main():
    """Main function to run server examples."""
    parser = argparse.ArgumentParser(description="SpectralFlow Server Examples")
    parser.add_argument(
        "--mode",
        choices=["basic", "bridge", "directory", "performance", "monitoring"],
        default="basic",
        help="Server mode to run"
    )
    parser.add_argument(
        "--address",
        default="0.0.0.0",
        help="Listen address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=[8443],
        help="Listen ports (default: 8443)"
    )
    
    args = parser.parse_args()
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("SpectralFlow Server Examples")
    print("============================")
    
    try:
        if args.mode == "basic":
            await run_basic_server()
        elif args.mode == "bridge":
            await run_bridge_relay()
        elif args.mode == "directory":
            await run_directory_server()
        elif args.mode == "performance":
            await run_high_performance_server()
        elif args.mode == "monitoring":
            await run_monitoring_server()
        
    except GracefulExit:
        print("Server shutdown completed.")
    except Exception as e:
        print(f"Server failed with error: {e}")
        logging.exception("Server error")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
