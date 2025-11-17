# sushCore

*Quantum-resistant adaptive proxy built for hostile networks*

sushCore is an R&D project exploring censorship-resistant networking. It mixes
post-quantum key exchange, adaptive transports, and multi-layer obfuscation to
keep traffic moving even when networks fight back.

## Key Capabilities

- **Quantum-safe crypto**: ML-KEM (Kyber) key exchange with HKDF-based session keys
- **Adaptive transports**: TCP/UDP switching, QUIC/WebSocket fallbacks, port hopping
- **Steganographic channels**: TTL, DNS, and NTP side channels for covert signalling
- **Traffic morphing**: Padding and timing jitter to disguise packet fingerprints
- **MirrorNet**: Multi-hop routing and node integrity scaffolding (simulated for now)
- **Adaptive control loop**: Condition evaluators + (optional) ML classifiers for threat response

> ℹ️ Several components (MirrorNet overlays, advanced ML models, real bridge relays)
> are still mocked/simulated. See [ARCHITECTURE.md](ARCHITECTURE.md) for the current
> implementation level by layer.

## Setup

### Requirements

- Python 3.9+
- A virtual environment is strongly recommended

### Installation

`ash
git clone https://github.com/soroushdeimi/sush-core.git
cd sush-core
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Optional: develop mode
pip install -e .
`

### Optional dependencies

The default requirements already pull in heavy packages such as cryptography,
pynacl, and scikit-learn. If you only need the lightweight smoke tests, you
can comment those packages out temporarily before installation. Advanced features
will automatically degrade (and tests will skip) when these libraries are absent.

## CLI Usage

`ash
# Interactive REPL
python sush_cli.py interactive

# Run a local SOCKS proxy that forwards to example.org:80
python sush_cli.py proxy 8080 example.org 80

# One-shot connect helper (sends optional data payload)
python sush_cli.py connect example.org 443 --data "ping"
`

## Python API Example

`python
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
`

## Configuration

### Environment variables

`ash
export SUSH_SERVER_HOST=your-server.com
export SUSH_SERVER_PORT=9090
export SUSH_THREAT_LEVEL=high  # low, medium, high, paranoid
export SUSH_ML_ENABLE=true
`

### Config files

- config/client.conf
- config/server.conf

See [USER_GUIDE.md](USER_GUIDE.md) for the full configuration reference.

## Testing

`ash
# Lightweight smoke test (no extra dependencies required)
python tests/test_smoke.py

# Full validation suite (requires requirements.txt dependencies)
python run_tests.py
`

Both the integration and comprehensive suites gracefully skip when optional
libraries are missing. Install the full dependency stack for maximum coverage.

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
