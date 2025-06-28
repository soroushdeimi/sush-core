#!/usr/bin/env python3
"""
Sush Core Command Line Interface

Simple CLI for running Sush Core client operations.
"""

import asyncio
import argparse
import sys
import logging

from spectralflow.client import SpectralFlowClient, ClientConfig


async def run_client_interactive(log_level="INFO"):
    """Run client in interactive mode."""
    config = ClientConfig(log_level=log_level)
    
    async with SpectralFlowClient(config) as client:
        print(f"Sush Core Client Started (Node ID: {client.config.node_id})")
        print("Type 'help' for available commands")
        
        while True:
            try:
                command = input("sush> ").strip()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == "help":
                    print_help()
                elif cmd == "status":
                    await show_status(client)
                elif cmd == "connect":
                    if len(parts) >= 3:
                        await connect_command(client, parts[1], int(parts[2]))
                    else:
                        print("Usage: connect <host> <port>")
                elif cmd == "disconnect":
                    if len(parts) >= 2:
                        await disconnect_command(client, parts[1])
                    else:
                        print("Usage: disconnect <connection_id>")
                elif cmd == "list":
                    await list_connections(client)
                elif cmd == "send":
                    if len(parts) >= 3:
                        await send_command(client, parts[1], " ".join(parts[2:]))
                    else:
                        print("Usage: send <connection_id> <data>")
                elif cmd == "adapt":
                    if len(parts) >= 2:
                        await adapt_command(client, parts[1])
                    else:
                        print("Usage: adapt <strategy>")
                elif cmd == "quit" or cmd == "exit":
                    break
                else:
                    print(f"Unknown command: {cmd}")
                    
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except Exception as e:
                print(f"Error: {e}")


def print_help():
    """Print help information."""
    print("""
Available commands:
  help              - Show this help message
  status            - Show client status
  connect <host> <port> - Connect to a target
  disconnect <id>   - Disconnect a connection
  list              - List active connections
  send <id> <data>  - Send data through connection
  adapt <strategy>  - Force adaptation strategy
  quit              - Exit the client
    """)


async def show_status(client):
    """Show client status."""
    status = client.get_status()
    
    print(f"Status: {'Running' if status['is_running'] else 'Stopped'}")
    print(f"Connected: {'Yes' if status['is_connected'] else 'No'}")
    print(f"Active Connections: {status['active_connections']}")
    print(f"System State: {status['system_status']['system_state']}")
    print(f"Current Strategy: {status['system_status']['current_strategy']}")
    print(f"Threat Level: {status['security_status']['current_threat_level']}")


async def connect_command(client, host, port):
    """Handle connect command."""
    try:
        connection_id = await client.connect(host, port, "tcp")
        print(f"Connected to {host}:{port} (ID: {connection_id})")
    except Exception as e:
        print(f"Connection failed: {e}")


async def disconnect_command(client, connection_id):
    """Handle disconnect command."""
    try:
        success = await client.close_connection(connection_id)
        if success:
            print(f"Disconnected {connection_id}")
        else:
            print(f"Failed to disconnect {connection_id}")
    except Exception as e:
        print(f"Disconnect failed: {e}")


async def list_connections(client):
    """List active connections."""
    status = client.get_status()
    if status['active_connections'] == 0:
        print("No active connections")
        return
    
    print("Active connections:")
    for connection_id in client.active_connections:
        stats = client.get_connection_stats(connection_id)
        if stats:
            print(f"  {connection_id}: {stats['destination']}:{stats['port']} "
                  f"({stats['duration']:.1f}s, {stats['bytes_sent']}B sent, "
                  f"{stats['bytes_received']}B received)")


async def send_command(client, connection_id, data):
    """Handle send command."""
    try:
        success = await client.send_data(connection_id, data.encode())
        if success:
            print(f"Sent {len(data)} bytes to {connection_id}")
        else:
            print(f"Failed to send data to {connection_id}")
    except Exception as e:
        print(f"Send failed: {e}")


async def adapt_command(client, strategy):
    """Handle adapt command."""
    try:
        await client.force_adaptation(strategy)
        print(f"Forced adaptation to {strategy}")
    except Exception as e:
        print(f"Adaptation failed: {e}")


async def run_proxy_mode(local_port, remote_host, remote_port):
    """Run client in proxy mode."""
    config = ClientConfig(log_level="WARNING")
    async with SpectralFlowClient(config) as client:
        print(f"Sush Core Proxy: localhost:{local_port} -> {remote_host}:{remote_port}")
        
        async def handle_proxy_connection(reader, writer):
            """Handle incoming proxy connection."""
            try:
                # Connect through Sush Core
                connection_id = await client.connect(remote_host, remote_port, "tcp")
                
                # Relay data bidirectionally
                async def relay_to_remote():
                    while True:
                        data = await reader.read(8192)
                        if not data:
                            break
                        await client.send_data(connection_id, data)
                
                async def relay_from_remote():
                    while True:
                        data = await client.receive_data(connection_id, timeout=1.0)
                        if not data:
                            continue
                        writer.write(data)
                        await writer.drain()
                
                # Run both relay tasks
                await asyncio.gather(
                    relay_to_remote(),
                    relay_from_remote(),
                    return_exceptions=True
                )
                
            except Exception as e:
                print(f"Proxy connection error: {e}")
            finally:
                writer.close()
                await writer.wait_closed()
                if 'connection_id' in locals():
                    await client.close_connection(connection_id)
        
        # Start proxy server
        server = await asyncio.start_server(
            handle_proxy_connection,
            'localhost',
            local_port
        )
        
        print(f"Proxy server listening on localhost:{local_port}")
        print("Press Ctrl+C to stop")
        
        async with server:
            await server.serve_forever()


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(description="Sush Core CLI")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Interactive mode
    interactive_parser = subparsers.add_parser('interactive', help='Run in interactive mode')
    interactive_parser.add_argument('--log-level', default='INFO', 
                                   choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                                   help='Logging level (default: INFO)')
    
    # Proxy mode
    proxy_parser = subparsers.add_parser('proxy', help='Run as SOCKS proxy')
    proxy_parser.add_argument('local_port', type=int, help='Local port to bind')
    proxy_parser.add_argument('remote_host', help='Remote host to connect to')
    proxy_parser.add_argument('remote_port', type=int, help='Remote port to connect to')
    
    # Quick connect
    connect_parser = subparsers.add_parser('connect', help='Quick connect to target')
    connect_parser.add_argument('host', help='Target host')
    connect_parser.add_argument('port', type=int, help='Target port')
    connect_parser.add_argument('--data', help='Data to send')
    
    args = parser.parse_args()
    
    # Default to interactive mode if no command specified
    if not args.command:
        args.command = 'interactive'
        args.log_level = 'INFO'
    
    # Setup logging
    logging.basicConfig(
        level=logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        if args.command == 'interactive':
            asyncio.run(run_client_interactive(args.log_level))
        elif args.command == 'proxy':
            asyncio.run(run_proxy_mode(args.local_port, args.remote_host, args.remote_port))
        elif args.command == 'connect':
            asyncio.run(quick_connect(args.host, args.port, args.data))
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


async def quick_connect(host, port, data=None):
    """Quick connect to a target."""
    config = ClientConfig(log_level="INFO")
    
    async with SpectralFlowClient(config) as client:
        try:
            connection_id = await client.connect(host, port, "tcp")
            print(f"Connected to {host}:{port}")
            
            if data:
                await client.send_data(connection_id, data.encode())
                print(f"Sent: {data}")
                
                response = await client.receive_data(connection_id, timeout=10.0)
                if response:
                    print(f"Received: {response.decode('utf-8', errors='ignore')}")
            
            await client.close_connection(connection_id)
            print("Connection closed")
            
        except Exception as e:
            print(f"Connection failed: {e}")


if __name__ == "__main__":
    main()
