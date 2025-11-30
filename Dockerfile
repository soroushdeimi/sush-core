# Multi-stage build for production-ready sushCore Docker image
# Stage 1: Builder - Install dependencies and build
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=1.2.0

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies to user directory
RUN pip install --no-cache-dir --user --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime - Minimal production image
FROM python:3.11-slim

# Metadata labels
LABEL maintainer="sushCore Development Team" \
      org.opencontainers.image.title="sushCore" \
      org.opencontainers.image.description="Quantum-resistant censorship circumvention system" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT"

# Create non-root user for security
RUN groupadd -r sush && useradd -r -g sush -u 1000 -d /home/sush -s /bin/bash sush && \
    mkdir -p /home/sush /app && chown -R sush:sush /home/sush /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/home/sush/.local/bin:${PATH}" \
    PYTHONPATH="/app:${PYTHONPATH}"

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder --chown=sush:sush /root/.local /home/sush/.local

# Copy application files
COPY --chown=sush:sush . .

# Install application in development mode
RUN pip install --no-cache-dir --user -e . && \
    chown -R sush:sush /app /home/sush/.local

# Ensure home directory exists and has correct permissions
RUN mkdir -p /home/sush && chown -R sush:sush /home/sush

# Switch to non-root user
USER sush

# Expose default ports
# 8443: Main server port
# 8080: Alternative/HTTP port
# 443: HTTPS port (if needed)
# 80: HTTP port (if needed)
EXPOSE 8443 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import socket; s = socket.socket(); s.settimeout(5); result = s.connect_ex(('127.0.0.1', 8443)); s.close(); exit(0 if result == 0 else 1)" || exit 1

# Default command - can be overridden
CMD ["python", "examples/server_example.py", "--mode", "basic", "--address", "0.0.0.0", "--ports", "8443", "8080"]
