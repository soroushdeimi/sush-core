"""Network threat monitoring system."""

import asyncio
import contextlib
import time
import socket
import random
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum, auto
import dns.resolver
import dns.exception
from collections import defaultdict, deque
import logging


class ProbeType(Enum):
    """Types of network probes."""
    TCP_CONNECT = auto()
    UDP_PING = auto()
    DNS_QUERY = auto()
    HTTP_REQUEST = auto()
    TLS_HANDSHAKE = auto()
    ICMP_PING = auto()


class ProbeResult(Enum):
    """Results of network probes."""
    SUCCESS = auto()
    TIMEOUT = auto()
    CONNECTION_REFUSED = auto()
    HOST_UNREACHABLE = auto()
    PROTOCOL_ERROR = auto()
    FILTERED = auto()


@dataclass
class ProbeTarget:
    """Network probe target configuration."""
    host: str
    port: Optional[int] = None
    protocol: str = 'tcp'
    timeout: float = 5.0
    probe_type: ProbeType = ProbeType.TCP_CONNECT


@dataclass
class ProbeResponse:
    """Response from a network probe."""
    target: ProbeTarget
    result: ProbeResult
    timestamp: float
    latency: Optional[float] = None
    error_message: Optional[str] = None
    details: Dict[str, any] = field(default_factory=dict)


class ThreatMonitor:
    """
    Comprehensive threat monitoring system.
    
    Performs active network probing to detect censorship infrastructure
    and gather intelligence about network conditions.
    """
    
    def __init__(self, probe_interval: float = 30.0):
        self.probe_interval = probe_interval
        self.is_monitoring = False
        
        # Probe targets and results
        self.probe_targets: List[ProbeTarget] = []
        self.probe_history: deque = deque(maxlen=1000)
        self.target_status: Dict[str, ProbeResult] = {}
        
        # DNS monitoring
        self.dns_servers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '208.67.222.222', # OpenDNS
            '9.9.9.9'       # Quad9
        ]
        self.dns_poison_domains = [
            'www.google.com',
            'www.twitter.com', 
            'www.facebook.com',
            'www.youtube.com'
        ]
        
        # Known censorship infrastructure
        self.known_censors: Set[str] = set()
        self.suspicious_ips: Set[str] = set()
        
        self.logger = logging.getLogger(__name__)
        self._tasks: List[asyncio.Task] = []
    
    async def start_monitoring(self):
        """Start threat monitoring."""
        if self.is_monitoring:
            return

        self.is_monitoring = True
        self.logger.info("Starting threat monitoring")
        
        # Initialize default probe targets
        await self._initialize_probe_targets()
        
        # Start monitoring tasks
        self._tasks = [
            asyncio.create_task(self._continuous_probing()),
            asyncio.create_task(self._dns_monitoring()),
            asyncio.create_task(self._infrastructure_detection()),
        ]
    
    async def stop_monitoring(self):
        """Stop threat monitoring."""
        self.is_monitoring = False
        self.logger.info("Stopping threat monitoring")
        for task in self._tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()
    
    async def _initialize_probe_targets(self):
        """Initialize default probe targets."""
        # Test common censored services
        censored_targets = [
            ProbeTarget('www.google.com', 443, 'tcp', 5.0, ProbeType.TLS_HANDSHAKE),
            ProbeTarget('www.twitter.com', 443, 'tcp', 5.0, ProbeType.TLS_HANDSHAKE),
            ProbeTarget('www.facebook.com', 443, 'tcp', 5.0, ProbeType.TLS_HANDSHAKE),
            ProbeTarget('www.youtube.com', 443, 'tcp', 5.0, ProbeType.HTTP_REQUEST),
            ProbeTarget('api.telegram.org', 443, 'tcp', 5.0, ProbeType.TLS_HANDSHAKE),
        ]
        
        # Test common protocols and ports
        protocol_targets = [
            ProbeTarget('8.8.8.8', 53, 'udp', 3.0, ProbeType.DNS_QUERY),
            ProbeTarget('1.1.1.1', 53, 'tcp', 3.0, ProbeType.TCP_CONNECT),
            ProbeTarget('208.67.222.222', 443, 'tcp', 5.0, ProbeType.TLS_HANDSHAKE),
        ]
        
        self.probe_targets.extend(censored_targets)
        self.probe_targets.extend(protocol_targets)
        
        self.logger.info(f"Initialized {len(self.probe_targets)} probe targets")
    
    async def _continuous_probing(self):
        """Continuously probe targets to detect censorship."""
        while self.is_monitoring:
            try:
                # Randomize probe order to avoid patterns
                targets = random.sample(self.probe_targets, len(self.probe_targets))
                
                for target in targets:
                    if not self.is_monitoring:
                        break
                    
                    response = await self._probe_target(target)
                    self.probe_history.append(response)
                    self.target_status[f"{target.host}:{target.port}"] = response.result
                    
                    # Add random delay between probes
                    await asyncio.sleep(random.uniform(1, 3))
                
                await asyncio.sleep(self.probe_interval)
                
            except Exception as e:
                self.logger.error(f"Error in continuous probing: {e}")
                await asyncio.sleep(10)
    
    async def _probe_target(self, target: ProbeTarget) -> ProbeResponse:
        """Probe a single target."""
        start_time = time.time()
        
        try:
            if target.probe_type == ProbeType.TCP_CONNECT:
                result = await self._tcp_connect_probe(target)
            elif target.probe_type == ProbeType.UDP_PING:
                result = await self._udp_ping_probe(target)
            elif target.probe_type == ProbeType.DNS_QUERY:
                result = await self._dns_query_probe(target)
            elif target.probe_type == ProbeType.HTTP_REQUEST:
                result = await self._http_request_probe(target)
            elif target.probe_type == ProbeType.TLS_HANDSHAKE:
                result = await self._tls_handshake_probe(target)
            else:
                result = ProbeResult.PROTOCOL_ERROR
            
            latency = time.time() - start_time
            
            return ProbeResponse(
                target=target,
                result=result,
                timestamp=start_time,
                latency=latency
            )
            
        except Exception as e:
            return ProbeResponse(
                target=target,
                result=ProbeResult.PROTOCOL_ERROR,
                timestamp=start_time,
                error_message=str(e)
            )
    
    async def _tcp_connect_probe(self, target: ProbeTarget) -> ProbeResult:
        """Perform TCP connect probe."""
        try:
            future = asyncio.open_connection(target.host, target.port)
            reader, writer = await asyncio.wait_for(future, timeout=target.timeout)
            writer.close()
            await writer.wait_closed()
            return ProbeResult.SUCCESS
        except asyncio.TimeoutError:
            return ProbeResult.TIMEOUT
        except ConnectionRefusedError:
            return ProbeResult.CONNECTION_REFUSED
        except OSError as e:
            if 'unreachable' in str(e).lower():
                return ProbeResult.HOST_UNREACHABLE
            return ProbeResult.FILTERED
    
    async def _udp_ping_probe(self, target: ProbeTarget) -> ProbeResult:
        """Perform UDP ping probe."""
        try:
            # Create UDP socket and send ping
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(target.timeout)
            
            # Send a simple UDP packet
            message = b"PING"
            sock.sendto(message, (target.host, target.port))
            
            # Try to receive response (might timeout for filtered ports)
            try:
                sock.recvfrom(1024)
                return ProbeResult.SUCCESS
            except socket.timeout:
                return ProbeResult.TIMEOUT
            finally:
                sock.close()
                
        except Exception:
            return ProbeResult.FILTERED
    
    async def _dns_query_probe(self, target: ProbeTarget) -> ProbeResult:
        """Perform DNS query probe."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [target.host]
            resolver.timeout = target.timeout
            
            # Query for a common domain
            resolver.resolve('www.google.com', 'A')
            return ProbeResult.SUCCESS
            
        except dns.exception.Timeout:
            return ProbeResult.TIMEOUT
        except Exception:
            return ProbeResult.FILTERED
    
    async def _http_request_probe(self, target: ProbeTarget) -> ProbeResult:
        """Perform HTTP request probe."""
        try:
            # Simple HTTP request without external dependencies
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port or 80),
                timeout=target.timeout
            )
            
            # Send basic HTTP GET request
            request = f"GET / HTTP/1.1\r\nHost: {target.host}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            # Read response headers
            response = await asyncio.wait_for(
                reader.read(1024), 
                timeout=target.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            # Check if we got a valid HTTP response
            if b'HTTP/' in response:
                return ProbeResult.SUCCESS
            else:
                return ProbeResult.FILTERED
                
        except asyncio.TimeoutError:
            return ProbeResult.TIMEOUT
        except ConnectionRefusedError:
            return ProbeResult.CONNECTION_REFUSED
        except Exception:
            return ProbeResult.FILTERED
    
    async def _tls_handshake_probe(self, target: ProbeTarget) -> ProbeResult:
        """Perform TLS handshake probe."""
        try:
            # Open SSL context and connect
            import ssl
            context = ssl.create_default_context()
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    target.host, 
                    target.port or 443,
                    ssl=context,
                    server_hostname=target.host
                ),
                timeout=target.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            return ProbeResult.SUCCESS
            
        except asyncio.TimeoutError:
            return ProbeResult.TIMEOUT
        except ConnectionRefusedError:
            return ProbeResult.CONNECTION_REFUSED
        except ssl.SSLError:
            return ProbeResult.FILTERED
        except Exception:
            return ProbeResult.HOST_UNREACHABLE
    
    async def _dns_monitoring(self):
        """Monitor DNS for poisoning and manipulation."""
        while self.is_monitoring:
            try:
                for domain in self.dns_poison_domains:
                    # Query multiple DNS servers for the same domain
                    responses = {}
                    
                    for dns_server in self.dns_servers:
                        try:
                            resolver = dns.resolver.Resolver()
                            resolver.nameservers = [dns_server]
                            resolver.timeout = 5.0
                            
                            answer = resolver.resolve(domain, 'A')
                            ips = [str(rdata) for rdata in answer]
                            responses[dns_server] = sorted(ips)
                            
                        except Exception as e:
                            self.logger.debug(f"DNS query failed for {domain} via {dns_server}: {e}")
                    
                    # Check for inconsistencies (potential poisoning)
                    if len(set(str(r) for r in responses.values())) > 1:
                        self.logger.warning(f"DNS poisoning detected for {domain}: {responses}")
                        
                        # Record suspicious IPs
                        for ip_list in responses.values():
                            for ip in ip_list:
                                if self._is_suspicious_ip(ip):
                                    self.suspicious_ips.add(ip)
                
                await asyncio.sleep(60)  # Check DNS every minute
                
            except Exception as e:
                self.logger.error(f"Error in DNS monitoring: {e}")
                await asyncio.sleep(30)
    
    async def _infrastructure_detection(self):
        """Detect censorship infrastructure and patterns."""
        while self.is_monitoring:
            try:
                # Analyze probe results for patterns
                await self._analyze_blocking_patterns()
                await self._detect_middleboxes()
                
                await asyncio.sleep(120)  # Analyze every 2 minutes
                
            except Exception as e:
                self.logger.error(f"Error in infrastructure detection: {e}")
                await asyncio.sleep(60)
    
    async def _analyze_blocking_patterns(self):
        """Analyze probe results to detect blocking patterns."""
        if len(self.probe_history) < 10:
            return
        
        recent_probes = list(self.probe_history)[-50:]  # Last 50 probes
        
        # Group by target
        target_results = defaultdict(list)
        for probe in recent_probes:
            key = f"{probe.target.host}:{probe.target.port}"
            target_results[key].append(probe.result)
        
        # Look for systematic blocking
        for target, results in target_results.items():
            failure_rate = sum(1 for r in results if r != ProbeResult.SUCCESS) / len(results)
            
            if failure_rate > 0.8 and len(results) >= 5:
                self.logger.warning(f"Systematic blocking detected for {target} "
                                  f"(failure rate: {failure_rate:.2f})")
    
    async def _detect_middleboxes(self):
        """Detect presence of middleboxes and DPI equipment."""
        # Look for RST injection patterns
        recent_tcp_probes = [
            p for p in list(self.probe_history)[-20:]
            if p.target.probe_type == ProbeType.TCP_CONNECT
        ]
        
        # Check for immediate RST responses (possible DPI)
        fast_failures = [
            p for p in recent_tcp_probes
            if (p.result == ProbeResult.CONNECTION_REFUSED and 
                p.latency and p.latency < 0.01)  # Very fast response
        ]
        
        if len(fast_failures) > 3:
            self.logger.warning("Possible DPI/middlebox detected - fast RST responses")
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if an IP address is suspicious."""
        # Simple heuristics for suspicious IPs
        suspicious_ranges = [
            '127.',     # Localhost redirect
            '0.0.0.0',  # Null route
            '10.',      # Private range (unexpected for public domains)
            '192.168.', # Private range
            '172.'      # Private range
        ]
        
        return any(ip.startswith(prefix) for prefix in suspicious_ranges)
    
    def add_probe_target(self, target: ProbeTarget):
        """Add a new probe target."""
        self.probe_targets.append(target)
        self.logger.info(f"Added probe target: {target.host}:{target.port}")
    
    def get_target_status(self) -> Dict[str, ProbeResult]:
        """Get current status of all probe targets."""
        return self.target_status.copy()
    
    def get_probe_statistics(self) -> Dict[str, any]:
        """Get comprehensive probe statistics."""
        if not self.probe_history:
            return {}
        
        recent_probes = list(self.probe_history)[-100:]  # Last 100 probes
        
        # Count results by type
        result_counts = defaultdict(int)
        for probe in recent_probes:
            result_counts[probe.result] += 1
        
        # Calculate success rate
        total_probes = len(recent_probes)
        success_rate = result_counts[ProbeResult.SUCCESS] / total_probes if total_probes > 0 else 0
        
        # Average latency for successful probes
        successful_probes = [p for p in recent_probes if p.result == ProbeResult.SUCCESS and p.latency]
        avg_latency = sum(p.latency for p in successful_probes) / len(successful_probes) if successful_probes else 0
        
        return {
            'total_probes': total_probes,
            'success_rate': success_rate,
            'average_latency': avg_latency,
            'result_distribution': dict(result_counts),
            'suspicious_ips': len(self.suspicious_ips),
            'known_censors': len(self.known_censors)
        }
