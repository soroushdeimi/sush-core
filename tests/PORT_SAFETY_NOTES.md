# Port Safety Configuration for Benchmarks

## Overview

The benchmark suite uses **safe ephemeral ports** to prevent firewall/ISP blocking during testing.

## Port Selection Strategy

### Safe Port Range
- **IANA Ephemeral Port Range**: 49152-65535
- **Selected Ports**: 54321, 55555, 60000, 61000
- **Why Safe**: These ports are in the dynamic/ephemeral range and are:
  - Unlikely to be blocked by ISPs
  - Not commonly used by standard services
  - Safe for localhost testing

### Address Binding
- **Address**: `127.0.0.1` (localhost only)
- **NOT**: `0.0.0.0` (all interfaces)
- **Reason**: Ensures no external network access, preventing:
  - Firewall interference
  - ISP blocking
  - Security concerns

## Port Fallback Mechanism

The benchmark script automatically tries multiple ports in order:
1. 54321 (primary)
2. 55555 (fallback 1)
3. 60000 (fallback 2)
4. 61000 (fallback 3)

If all ports are occupied, the script will raise an error.

## Why Not Standard Ports?

**Avoided Ports** (commonly blocked):
- 80, 443 (HTTP/HTTPS) - May trigger DPI
- 53 (DNS) - May be monitored
- 22 (SSH) - May be rate-limited
- 25 (SMTP) - Often blocked by ISPs
- 8080, 8443 - Alternative HTTP ports, may still be monitored

**Ephemeral Ports** (safe):
- 49152-65535 - Dynamic port range
- Rarely blocked or monitored
- Safe for localhost testing
- No conflict with standard services

## Testing Locally

All benchmarks run on `127.0.0.1` (localhost), meaning:
-  No external network traffic
-  No firewall interference
-  No ISP blocking risk
-  Safe for development/testing
-  Fast (no network latency)

## Production Considerations

For production deployment, you may need:
- Standard ports (80, 443) for web traffic
- Proper firewall rules
- ISP coordination
- SSL/TLS certificates

But for **benchmarking and testing**, ephemeral ports on localhost are the safest choice.

