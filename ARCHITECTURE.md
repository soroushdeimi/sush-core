# sushCore Architecture

*How the layers work together to beat censorship*

## The Big Picture

sush has four layers that each solve different problems:

```
┌─────────────────────────────────────────────────────────┐
│                    Control Layer                        │
│  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │ Adaptive Control │  │ Censorship Detector         │  │
│  │ (Learns & Adapts)│  │ (ML Pattern Recognition)    │  │
│  └─────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                    Network Layer                        │
│  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │ MirrorNet       │  │ Node Integrity              │  │
│  │ (Multi-hop)     │  │ (Trust Verification)        │  │
│  └─────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                   Transport Layer                       │
│  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │ Protocol Hopper │  │ Steganographic Channels     │  │
│  │ (QUIC/WS/DNS)   │  │ (Hide in Normal Traffic)    │  │
│  └─────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                     Core Layer                          │
│  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │ Quantum Crypto  │  │ Adaptive Encryption         │  │
│  │ (Future-proof)  │  │ (Smart Algorithm Choice)    │  │
│  └─────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Core Layer - The Crypto Foundation

### Quantum Obfuscator (`sush.core.quantum_obfuscator`)

This is where the serious crypto happens. Uses ML-KEM (Kyber) because RSA and ECDH will break when quantum computers get good enough.

**What it does:**
- **ML-KEM Key Exchange**: Quantum-safe key agreement
- **Session Management**: Sets up secure connections
- **Crypto Coordination**: Picks the right algorithms

**Why quantum-safe matters:**
Current crypto (RSA, ECDH) will be broken by quantum computers in ~10-15 years. ML-KEM is designed to survive that.

### Adaptive Cipher Suite (`sush.core.adaptive_cipher`)

Picks the best encryption based on current conditions.

**Algorithm choices:**
- **ChaCha20-Poly1305**: Secure, works well on mobile processors
- **AES-256-GCM**: Fast on Intel CPUs with AES-NI
- **AES-256-OCB**: Low latency (we use GCM as substitute)

**Decision logic:**
```python
if high_threat_level:
    use_chacha20()  # More secure
elif intel_cpu_with_aes_ni:
    use_aes_gcm()   # Fastest
else:
    use_chacha20()  # Best compatibility
```

### Traffic Morphing Engine (`sush.core.traffic_morphing`)

Makes your traffic look normal to DPI systems.

**Techniques:**
- **Size padding**: All packets look similar sized
- **Timing jitter**: Breaks timing analysis
- **Protocol mimicry**: Looks like HTTPS/HTTP2

### Protocol Hopper (`sush.transport.protocol_hopper`)

Dynamic switching between transport protocols to evade protocol-specific blocking.

**Supported Protocols:**
- **QUIC**: UDP-based, built-in encryption, connection migration
- **WebSocket**: TCP-based, HTTP-compatible, firewall-friendly  
- **DNS**: Universal availability, steganographic potential
- **HTTP/HTTPS**: Mimics web traffic, proxy-friendly

**Hopping Strategy:**
```python
class HoppingStrategy:
    def select_protocol(self, network_state, failure_history):
        # Avoid recently failed protocols
        # Prefer protocols with high success rate
        # Consider current network characteristics
        return optimal_protocol
```

### Steganographic Channels (`sush.transport.steganographic_channels`)

Covert communication channels hidden within legitimate network protocols.

**Available Channels:**

1. **TTL Channel**: Encode data in IP Time-To-Live fields
   - Capacity: ~3 bits per packet
   - Detection Resistance: High
   - Reliability: Medium

2. **NTP Channel**: Embed data in Network Time Protocol timestamps
   - Capacity: ~8 bits per packet  
   - Detection Resistance: Very High
   - Reliability: High

3. **DNS Channel**: Use DNS subdomain queries for data transport
   - Capacity: Variable (20-60 bytes per query)
   - Detection Resistance: Medium
   - Reliability: Very High

## Network Layer

### MirrorNet Onion Routing (`sush.network.onion_routing`)

Multi-hop routing through a distributed network of mirror nodes with layered encryption.

**Routing Process:**
1. Client selects 3-5 mirror nodes
2. Establishes layered encryption (AES-256-CTR with HKDF)
3. Each hop decrypts one layer
4. Final hop connects to destination

**Security Features:**
- **Perfect Forward Secrecy**: Ephemeral keys for each session
- **Traffic Analysis Resistance**: Constant packet sizes and timing
- **Node Compromise Resilience**: No single node can compromise entire path

### Distributed Node Integrity System (DNIS) (`sush.network.node_integrity`)

Cryptographic verification of node authenticity and behavior monitoring.

**Verification Methods:**
- **Ed25519 Digital Signatures**: Quantum-resistant node authentication
- **Behavioral Analysis**: ML-based detection of compromised nodes
- **Reputation System**: Distributed scoring of node reliability

**Trust Model:**
```python
class NodeTrust:
    def calculate_trust(self, node_id):
        signature_validity = verify_ed25519_signature(node_id)
        behavioral_score = ml_behavior_analysis(node_id)
        reputation_score = distributed_reputation(node_id)
        return combine_scores(signature_validity, behavioral_score, reputation_score)
```

## Control Layer

### Adaptive Control Loop (`sush.control.adaptive_control`)

Intelligent system adaptation based on real-time network conditions and threat assessment.

**Core Components:**

1. **Condition Evaluators**: Object-oriented threat assessment
   ```python
   class ThreatLevelCondition(ConditionEvaluator):
       def evaluate(self, context):
           return context['threat_level'] >= self.threshold
   ```

2. **Adaptation Strategies**: Predefined response patterns
   - **Stealth Mode**: Maximum obfuscation, reduced performance
   - **Balanced Mode**: Optimal security/performance trade-off
   - **Performance Mode**: Minimal overhead, basic security

3. **ML Integration**: Machine learning-enhanced decision making

### Censorship Detector (`sush.control.censorship_detector`)

ML-powered system for real-time censorship detection and classification.

**ML Components:**

1. **Feature Extraction**: 15-dimensional feature vectors from network metrics
   ```python
   features = [
       latency, packet_loss, throughput, connection_success_rate,
       rst_packets, retransmissions, jitter, bandwidth_utilization,
       # ... additional features
   ]
   ```

2. **Anomaly Detection**: IsolationForest for unusual pattern detection
3. **Threat Classification**: GaussianNB for censorship type identification
4. **Adaptive Learning**: Continuous model updates based on observed patterns

**Detection Types:**
- **DPI Filtering**: Deep Packet Inspection-based blocking
- **IP Blocking**: Address-based restrictions  
- **DNS Poisoning**: Domain name system manipulation
- **Protocol Blocking**: Transport protocol restrictions
- **Behavioral Analysis**: Advanced traffic pattern analysis

## Data Flow

### Client Connection Establishment

```
1. Client → ML-KEM Key Exchange → Server
2. Client ← Session Keys ← Server  
3. Client → Encrypted Request → Onion Route → Server
4. Server → Encrypted Response → Onion Route → Client
```

### Adaptive Response Flow

```
1. Network Metrics Collection
2. ML-based Threat Detection
3. Condition Evaluation (Threat, Performance, Stability)
4. Strategy Selection (Stealth/Balanced/Performance)
5. Protocol/Cipher Adaptation
6. Traffic Morphing Adjustment
7. Route Optimization
```

## Performance Characteristics

### Latency Overhead
- **Core Encryption**: ~1-2ms per packet
- **Onion Routing**: ~50-100ms (3-hop path)
- **Protocol Hopping**: ~10-50ms (connection establishment)
- **ML Processing**: ~5-10ms (batch processing)

### Throughput Impact
- **Encryption Overhead**: ~5-10% CPU utilization
- **Traffic Morphing**: ~10-20% bandwidth overhead
- **Steganographic Channels**: Significant capacity reduction (use sparingly)

### Memory Usage
- **Base System**: ~50-100MB RAM
- **ML Models**: ~10-20MB additional
- **Connection State**: ~1KB per active session

## Security Analysis

### Threat Model

**Adversary Capabilities:**
- Network-level monitoring and blocking
- Deep packet inspection (DPI)
- Statistical traffic analysis
- Protocol fingerprinting
- Node compromise attempts

**Protection Mechanisms:**
- Quantum-resistant cryptography (future-proof)
- Multi-layer obfuscation (defeats DPI)
- Distributed routing (prevents single point of failure)
- Adaptive protocols (evades static blocking rules)
- ML-based adaptation (responds to new attack patterns)

### Attack Resistance

1. **Cryptanalytic Attacks**: Defeated by quantum-resistant primitives
2. **Traffic Analysis**: Mitigated by morphing and steganography  
3. **Protocol Fingerprinting**: Countered by dynamic protocol hopping
4. **Node Compromise**: Limited impact due to layered encryption
5. **Statistical Analysis**: Disrupted by adaptive timing and padding

## Implementation Details

### Concurrency Model
- **Async/Await**: All I/O operations are asynchronous
- **Connection Pooling**: Efficient resource utilization
- **Batch Processing**: ML operations grouped for efficiency

### Error Handling
- **Graceful Degradation**: System continues with reduced functionality
- **Automatic Recovery**: Self-healing from transient failures  
- **Comprehensive Logging**: Detailed diagnostics for troubleshooting

### Configuration Management
- **Environment Variables**: Container/deployment friendly
- **Configuration Files**: Human-readable settings
- **Runtime Adaptation**: Dynamic parameter adjustment

## Future Enhancements

### Planned Features
- **Bridge Discovery Protocol**: Automated bridge node discovery
- **Mobile Client Support**: iOS/Android applications
- **WebAssembly Integration**: Browser-based deployment
- **Enhanced ML Models**: Improved censorship detection
- **Network Topology Optimization**: Intelligent routing

### Research Directions
- **Post-Quantum Steganography**: Quantum-resistant covert channels
- **Federated Learning**: Distributed ML model training
- **Blockchain Integration**: Decentralized node discovery
- **Hardware Security Modules**: Enhanced key protection

---

This architecture provides a robust foundation for censorship-resistant communication while maintaining the flexibility to adapt to evolving threats and network conditions.
