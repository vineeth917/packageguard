FROM python:3.10-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[all]" 2>/dev/null || pip install --no-cache-dir anthropic httpx click rich fastapi uvicorn pyyaml docker

COPY . .

# Build the sandbox image
RUN docker build -t packageguard-sandbox -f Dockerfile.sandbox . 2>/dev/null || true

EXPOSE 8000

CMD ["uvicorn", "packageguard.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
