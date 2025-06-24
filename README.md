# Sush Core

*Next-gen proxy that adapts to bypass censorship*

Sush Core is a censorship circumvention tool built for hostile network environments. It combines quantum-safe crypto with adaptive protocols to stay ahead of detection systems.

## What's Inside

- **Quantum-Safe Crypto**: Uses ML-KEM (Kyber) - your keys won't break when quantum computers arrive
- **Protocol Chameleon**: Switches between QUIC, WebSocket, TCP, UDP based on what works
- **Hidden Channels**: Tunnels data through DNS queries, NTP packets, and TTL manipulation
- **Smart Detection**: ML models learn censorship patterns and adapt automatically
- **Onion Routing**: Multi-hop encryption like Tor, but harder to block
- **Traffic Disguise**: Makes your packets look like regular web browsing

## Getting Started

### Setup

```bash
git clone https://github.com/soroushdeimi/sush-core.git
cd sush-core
pip install -r requirements.txt
```

### Run as Proxy

```bash
# Start the client proxy
python sush_cli.py client --config config/client.conf

# Point your browser to localhost:8080 (SOCKS5)
```

### Run a Server Node

```bash
# Copy and edit server config
cp config/server.conf.example config/server.conf
vim config/server.conf  # Add your server details

# Start serving
python sush_cli.py server --config config/server.conf
```

## Configuration

### Environment Variables
```bash
export SUSH_SERVER_HOST=your-server.com
export SUSH_SERVER_PORT=9090
export SUSH_THREAT_LEVEL=high  # low, medium, high, paranoid
export SUSH_ML_ENABLE=true
```

### Config Files
- `config/client.conf` - Client settings
- `config/server.conf` - Server settings

Check [USER_GUIDE.md](USER_GUIDE.md) for detailed configuration options.

## How It Works

Sush Core has four main layers:

- **Core**: Quantum crypto, adaptive encryption, traffic morphing
- **Transport**: Protocol switching, steganographic hiding
- **Network**: Multi-hop routing, node verification
- **Control**: ML adaptation, censorship detection

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the technical deep-dive.

## Testing

```bash
# Run all tests
python run_tests.py

# Quick smoke test
python tests/test_core_components.py
```

## Contributing

Found a bug? Want to add a feature? Here's how:

- File issues on [GitHub Issues](https://github.com/soroushdeimi/sush-core/issues)
- Submit pull requests for features
- Join discussions in [GitHub Discussions](https://github.com/soroushdeimi/sush-core/discussions)

## What's Next

- Bridge discovery protocol
- Mobile apps (iOS/Android)
- Browser extension (WebAssembly)
- Better ML models
- Performance improvements

## License

MIT License - see [LICENSE](LICENSE) for details.

## Legal Notice

This is research software for legitimate privacy protection. You're responsible for following your local laws.

---

*Fighting censorship, one packet at a time*
