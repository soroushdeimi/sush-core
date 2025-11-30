# Docker Guide for sushCore

This guide explains how to build and run sushCore using Docker.

## Quick Start

### Build the Image

```bash
docker build -t sush-core:latest .
```

### Run the Container

```bash
docker run -d \
  --name sush-server \
  -p 8443:8443 \
  -p 8080:8080 \
  sush-core:latest
```

### Using Docker Compose

```bash
# Start basic server
docker-compose up -d sush-server

# Start bridge relay
docker-compose up -d sush-bridge

# View logs
docker-compose logs -f sush-server
```

## Image Variants

### Production Image (`Dockerfile`)

- Multi-stage build for minimal size
- Non-root user for security
- Health checks enabled
- Optimized layer caching
- Production-ready configuration

**Build:**
```bash
docker build -t sush-core:latest .
```

### Development Image (`Dockerfile.dev`)

- Includes development dependencies
- Development tools (vim, git)
- Suitable for debugging

**Build:**
```bash
docker build -f Dockerfile.dev -t sush-core:dev .
```

## Configuration

### Environment Variables

- `PYTHONUNBUFFERED=1` - Real-time log output
- `LOG_LEVEL=INFO` - Logging level (DEBUG, INFO, WARNING, ERROR)
- `PYTHONPATH=/app` - Python module path

### Ports

- **8443** - Main server port (default)
- **8080** - Alternative/HTTP port
- **443** - HTTPS port (bridge mode)
- **80** - HTTP port (bridge mode)
- **53** - DNS port (bridge mode, UDP)

### Server Modes

Override the default command to use different modes:

```bash
# Basic server
docker run sush-core:latest python examples/server_example.py --mode basic

# Bridge relay
docker run sush-core:latest python examples/server_example.py --mode bridge

# Directory server
docker run sush-core:latest python examples/server_example.py --mode directory

# Performance mode
docker run sush-core:latest python examples/server_example.py --mode performance

# Monitoring mode
docker run sush-core:latest python examples/server_example.py --mode monitoring
```

## Security Features

1. **Non-root user**: Container runs as user `sush` (UID 1000)
2. **Minimal base image**: Uses `python:3.11-slim`
3. **No unnecessary privileges**: Dropped capabilities
4. **Read-only config**: Config files mounted as read-only
5. **Health checks**: Automatic container health monitoring

## Health Checks

The container includes a health check that verifies the server is listening on port 8443:

```bash
# Check container health
docker ps
# Look for "healthy" status

# Inspect health check
docker inspect --format='{{.State.Health.Status}}' sush-server
```

## Volumes

Mount configuration files:

```bash
docker run -v ./config:/app/config:ro sush-core:latest
```

## Troubleshooting

### View Logs

```bash
docker logs sush-server
docker logs -f sush-server  # Follow logs
```

### Execute Commands in Container

```bash
docker exec -it sush-server bash
docker exec -it sush-server python -c "import sush; print(sush.__version__)"
```

### Check Container Status

```bash
docker ps -a
docker inspect sush-server
```

### Rebuild After Changes

```bash
docker-compose build --no-cache sush-server
docker-compose up -d sush-server
```

## Production Deployment

### Build with Metadata

```bash
docker build \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  --build-arg VERSION=1.2.0 \
  -t sush-core:1.2.0 \
  -t sush-core:latest \
  .
```

### Resource Limits

```yaml
# docker-compose.yml
services:
  sush-server:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

## Best Practices

1. **Use specific tags**: Avoid `latest` in production
2. **Scan images**: Use `docker scan` or Trivy for security
3. **Monitor resources**: Set appropriate limits
4. **Backup configs**: Keep configuration files versioned
5. **Update regularly**: Keep base images updated

## Examples

### Development with Hot Reload

```bash
docker run -it --rm \
  -v $(pwd):/app \
  -p 8443:8443 \
  sush-core:dev \
  python examples/server_example.py --mode basic
```

### Production with Custom Config

```bash
docker run -d \
  --name sush-prod \
  -p 8443:8443 \
  -v ./config/production.conf:/app/config/server.conf:ro \
  -e LOG_LEVEL=WARNING \
  sush-core:1.2.0
```
