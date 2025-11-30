# sushCore

*Quantum-resistant adaptive proxy built for hostile networks*

sushCore is an R&D project exploring censorship-resistant networking. It mixes
post-quantum key exchange, adaptive transports, and multi-layer obfuscation to
keep traffic moving even when networks fight back.

## Key Capabilities

- **Quantum-safe crypto**: ML-KEM (Kyber) key exchange with HKDF-based session keys
- **Session Resumption**: LRU cache for fast session resumption (14x speedup, 91% overhead reduction)
- **Adaptive transports**: TCP/UDP switching, QUIC/WebSocket fallbacks, port hopping
- **Steganographic channels**: TTL, DNS, and NTP side channels for covert signalling
- **Traffic morphing**: Padding and timing jitter to disguise packet fingerprints
- **MirrorNet**: Multi-hop routing and node integrity scaffolding (fully active with directory services)
- **Adaptive control loop**: Condition evaluators + (optional) ML classifiers for threat response

## Setup

### Requirements

- Python 3.9+
- A virtual environment is strongly recommended

### Installation

```bash
git clone https://github.com/soroushdeimi/sush-core.git
cd sush-core
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Optional: develop mode
pip install -e .
```

### Cryptography Support

The system automatically uses `kyber-py` if installed. If not present, it falls back to an internal
reference implementation of ML-KEM-768, ensuring the system runs out-of-the-box without strict
external dependencies for the post-quantum layer.

### Performance Features

- **Session Resumption**: Caches ML-KEM sessions for 14x faster reconnection (enabled by default)
- **High Throughput**: Up to 2.7 Gbps for bulk transfers (100KB packets)
- **Low Overhead**: <6ms processing time for 1MB files with full encryption

## CLI Usage

```bash
# Interactive REPL
python sush_cli.py interactive

# Run a local SOCKS proxy that forwards to example.org:80
python sush_cli.py proxy 8080 example.org 80

# One-shot connect helper (sends optional data payload)
python sush_cli.py connect example.org 443 --data "ping"
```

## Python API Example

```python
import asyncio
from sush.client import SushClient, ClientConfig

async def main():
    config = ClientConfig(log_level="INFO")
    client = SushClient(config)
    await client.start()

    status = client.get_status()
    print("Node ID:", status["node_id"], "Threat:", status["security_status"]["current_threat_level"])

    await client.stop()

asyncio.run(main())
```

## Research Paper

The complete research paper is available in [`docs/paper/FINAL_PAPER.md`](docs/paper/FINAL_PAPER.md). This paper presents:

- **System Design**: Post-quantum cryptography (ML-KEM-768) with adaptive traffic morphing
- **Performance Evaluation**: 1.44 Gbps throughput with negligible cryptographic overhead
- **Security Analysis**: Traffic indistinguishability and forward secrecy guarantees

### Reproducible Artifacts

- **Paper**: [`docs/paper/FINAL_PAPER.md`](docs/paper/FINAL_PAPER.md) - Complete research paper
- **Code**: `sush/` - Full implementation
- **Benchmarks**: `tests/run_benchmarks.py` - Performance benchmarks (generates results locally)
- **Diagrams**: `docs/images/` - System architecture and protocol diagrams

## Configuration

### Environment variables

```bash
export SUSH_SERVER_HOST=your-server.com
export SUSH_SERVER_PORT=9090
export SUSH_THREAT_LEVEL=high  # low, medium, high, paranoid
export SUSH_ML_ENABLE=true
```

### Config files

- config/client.conf
- config/server.conf

See [USER_GUIDE.md](USER_GUIDE.md) for the full configuration reference.

## Testing

```bash
# Lightweight smoke test (no extra dependencies required)
python tests/test_smoke.py

# Full validation suite (requires requirements.txt dependencies)
python run_tests.py

# Comprehensive benchmark suite (measures real performance)
python tests/run_benchmarks.py

# Session Resumption performance test
python tests/test_session_resumption.py
```

Both the integration and comprehensive suites gracefully skip when optional
libraries are missing. Install the full dependency stack for maximum coverage.

See [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md) for detailed performance metrics.

## Documentation

### Quick Start Guides
- **[USER_GUIDE.md](USER_GUIDE.md)** - Complete user guide for setting up and using sushCore as a client
- **[NODE_GUIDE.md](NODE_GUIDE.md)** - Guide for running server nodes (bridge, middle, exit nodes)
- **[DOCKER.md](DOCKER.md)** - Docker deployment guide with production examples

### Technical Documentation
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and layer-by-layer breakdown
- **[docs/TECHNICAL_SUMMARY.md](docs/TECHNICAL_SUMMARY.md)** - Technical summary with performance metrics
- **[docs/paper/FINAL_PAPER.md](docs/paper/FINAL_PAPER.md)** - Complete research paper

### Development
- **Configuration**: See [USER_GUIDE.md](USER_GUIDE.md) for full configuration reference
- **Testing**: Run `python run_tests.py` or `python tests/test_smoke.py`
- **Benchmarks**: See [tests/BENCHMARK_SUITE_README.md](tests/BENCHMARK_SUITE_README.md)

## Architecture & Roadmap

- Read [ARCHITECTURE.md](ARCHITECTURE.md) for a layer-by-layer breakdown
- Planned enhancements: bridge discovery, mobile clients, browser WebAssembly,
  improved ML models, and performance tuning

## Support & Contributing

- Issues / ideas: [GitHub Issues](https://github.com/soroushdeimi/sush-core/issues)
- Discussions: [GitHub Discussions](https://github.com/soroushdeimi/sush-core/discussions)
- Pull requests welcome—please include smoke tests or integration updates when possible

## License

MIT License — see [LICENSE](LICENSE) for details.
