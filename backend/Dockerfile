# Multi-stage build for Django backend
FROM python:3.11-slim as base

WORKDIR /app

# Install system dependencies including build tools for Python packages
RUN apt-get update && apt-get install -y \
    postgresql-client \
    git \
    gcc \
    g++ \
    build-essential \
    python3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy shared package first
COPY shared/ /app/shared/

# Copy backend dependency files
COPY backend/pyproject.toml backend/uv.lock* /app/backend/

# Set working directory to backend
WORKDIR /app/backend

# Install dependencies (pin to system Python 3.11)
RUN uv sync --frozen --python $(which python3)

# Copy backend application code
COPY backend/ /app/backend/

# Expose port
EXPOSE 8000

# Run migrations and start server
CMD ["uv", "run", "python", "manage.py", "runserver", "0.0.0.0:8000"]
