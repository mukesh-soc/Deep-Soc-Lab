# SentinelX Enterprise SOC & SIEM Platform
# Production Multi-Stage Container Image

FROM python:3.13-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

WORKDIR /app

# Install security and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Security hardening: Create non-root user 'soc_analyst'
RUN useradd -u 1001 -m -s /bin/bash soc_analyst && \
    chown -R soc_analyst:soc_analyst /app

USER soc_analyst

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/v1/metrics || exit 1

# Production WSGI startup
CMD ["gunicorn", "--workers", "3", "--bind", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "wsgi:application"]
