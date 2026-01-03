# Multi-stage build for production-ready sushCore Docker image
# Security-hardened for production deployment

# =============================================================================
# Stage 1: Builder - Install dependencies and build
# =============================================================================
FROM python:3.11-slim AS builder

# Set build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=1.2.0

# Security: Don't run apt as interactive
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /build

# Copy requirements first for better layer caching
COPY requirements.txt .

# Create virtual environment and install dependencies
# Using virtual environment for cleaner separation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Stage 2: Runtime - Minimal production image
# =============================================================================
FROM python:3.11-slim

# Build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=1.2.0

# Metadata labels (OCI standard)
LABEL maintainer="sushCore Development Team" \
      org.opencontainers.image.title="sushCore" \
      org.opencontainers.image.description="Quantum-resistant censorship circumvention system" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/soroushdeimi/sush-core"

# Security: Non-interactive mode
ENV DEBIAN_FRONTEND=noninteractive

# Security: Install minimal runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /tmp/* /var/tmp/*

# Security: Create non-root user with specific UID/GID
RUN groupadd -r -g 1000 sush && \
    useradd -r -g sush -u 1000 -d /home/sush -s /sbin/nologin sush && \
    mkdir -p /home/sush /app && \
    chown -R sush:sush /home/sush /app

# Copy virtual environment from builder
COPY --from=builder --chown=sush:sush /opt/venv /opt/venv

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH="/app:${PYTHONPATH}" \
    # Security: Disable Python's ability to write bytecode
    PYTHONFAULTHANDLER=1 \
    # Application configuration
    SUSH_LOG_LEVEL=INFO \
    SUSH_BIND_ADDR=0.0.0.0

# Set working directory
WORKDIR /app

# Copy application files (exclude unnecessary files via .dockerignore)
COPY --chown=sush:sush sush/ ./sush/
COPY --chown=sush:sush examples/ ./examples/
COPY --chown=sush:sush config/ ./config/
COPY --chown=sush:sush setup.py README.md requirements.txt ./

# Install application in production mode
RUN pip install --no-cache-dir . && \
    chown -R sush:sush /app

# Security: Remove unnecessary files and set strict permissions
RUN find /app -type d -exec chmod 755 {} \; && \
    find /app -type f -exec chmod 644 {} \; && \
    chmod +x /app/examples/*.py

# Switch to non-root user
USER sush

# Expose default ports
# 8443: Main secure server port
# 8080: Alternative HTTP port
EXPOSE 8443 8080

# Health check with reasonable timeouts
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import socket; s = socket.socket(); s.settimeout(5); result = s.connect_ex(('127.0.0.1', 8443)); s.close(); exit(0 if result == 0 else 1)" || exit 1

# Use tini as init system for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command - can be overridden
CMD ["python", "examples/server_example.py", "--mode", "basic", "--address", "0.0.0.0", "--ports", "8443", "8080"]
