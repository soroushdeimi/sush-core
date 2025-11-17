# sushCore Architecture

*Current component layout and execution model*

## The Big Picture

Sush Core is structured into four cooperating layers. Each layer is implemented
in the `sush` namespace and can be wired together or exercised separately.

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
│  │ (port/proto hop)│  │ (TTL / NTP / DNS paths)     │  │
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

- Generates an ML‑KEM key pair at startup (Kyber768 via `kyber-py`, with a deterministic mock fallback).
- Manages per-session shared secrets and derives AEAD keys through HKDF.
- Provides `set_obfuscation_level()` that now accepts both symbolic (`"high"`) and numeric values.
- Drives the `AdaptiveCipherSuite` and `TrafficMorphingEngine` used by higher layers.

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

Coordinates direct transports. Today it primarily manages TCP/UDP sockets and
port hopping. QUIC/WebSocket helpers are present but fall back to TCP unless
their optional dependencies are installed. The API is being consolidated in
Phase 3.

### Steganographic Channels (`sush.transport.steganographic_channels`)

Provides pluggable carriers (TTL, NTP, DNS). TTL falls back to socket APIs when
raw sockets are unavailable; NTP/DNS currently operate in “best effort” mode and
are meant for experimentation rather than production throughput.

## Network Layer

### MirrorNet (`sush.network.mirror_network`) and Onion Routing (`sush.network.onion_routing`)

`MirrorNetwork` maintains a local directory of known nodes, builds placeholder
circuits, and hands connection objects back to the client. Onion routing
encrypt/decrypt routines exist, but the networking layer is still simulated (no
real relay mesh yet). Completing this plumbing is part of Phase 3.

Recent updates:
- `join_network()` bootstraps from configured nodes and spins up initial circuits.
- `get_performance_metrics()` supplies lightweight stats to the adaptive control
  loop for feedback.

### Distributed Node Integrity System (`sush.network.node_integrity`)

Uses Ed25519 keys (`