# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |
| < 1.0   | :x:                |

## Security Features

sushCore is designed with security as a primary concern:

### Cryptographic Security

- **Post-Quantum Cryptography**: ML-KEM-768 (FIPS 203) for quantum-resistant key exchange
- **Authenticated Encryption**: AES-256-GCM and ChaCha20-Poly1305 AEAD ciphers
- **Forward Secrecy**: Ephemeral keys for each session
- **Key Derivation**: HKDF with SHA-256 for secure key derivation

### Transport Security

- **Onion Routing**: Multi-layer encryption with multiple hops
- **Traffic Morphing**: Packet padding and timing jitter
- **Steganographic Channels**: Covert communication channels

### Operational Security

- **Non-root Execution**: Docker images run as non-root user
- **Minimal Attack Surface**: Slim base images with minimal packages
- **Secret Management**: Environment variable-based configuration
- **Read-only Filesystem**: Container filesystem is read-only in production

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow responsible disclosure practices:

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email your findings to the maintainers privately
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Disclosure Policy

- We follow coordinated disclosure
- You will be credited for your discovery (unless you prefer anonymity)
- Please allow time for fixes before public disclosure

## Security Best Practices for Users

### Deployment

1. **Use Official Images**: Only use images from trusted sources
2. **Keep Updated**: Regularly update to the latest version
3. **Network Isolation**: Deploy in isolated network segments
4. **Monitoring**: Enable logging and monitor for anomalies
5. **Secrets**: Use secrets management for sensitive configuration

### Configuration

```yaml
# Example secure configuration
environment:
  - SUSH_LOG_LEVEL=INFO
  - SUSH_REQUIRE_AUTH=true

security_opt:
  - no-new-privileges:true
  
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE
  
read_only: true
```

### Network

- Use TLS for external connections
- Implement firewall rules
- Use VPN for management access
- Enable rate limiting

## Security Audits

This project has not yet undergone a formal security audit. Community review is welcome and encouraged.

## Dependencies

We regularly monitor dependencies for vulnerabilities:

- Automated dependency updates via Dependabot
- Regular manual review of cryptographic dependencies
- Pinned versions in requirements.txt

## Acknowledgments

We thank all security researchers who responsibly disclose vulnerabilities.
