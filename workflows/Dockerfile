# Multi-stage build for Prefect workflows
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including build tools
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    g++ \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy shared package first
COPY shared/ /app/shared/

# Copy workflows dependency files
COPY workflows/pyproject.toml workflows/uv.lock* /app/workflows/

# Set working directory to workflows
WORKDIR /app/workflows

# Install dependencies (pin to system Python 3.11)
RUN uv sync --frozen --python $(which python3)

# Copy workflows application code
COPY workflows/ /app/workflows/

# Start Prefect worker
CMD ["uv", "run", "prefect", "worker", "start", "--pool", "default-pool"]
