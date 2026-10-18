# ==============================================================================
# NeuralPhish Production Dockerfile
# Multi-stage, non-root secure container for enterprise deployment
# ==============================================================================

FROM python:3.10-slim AS builder

WORKDIR /app

# Install build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies into wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Download required NLTK tokenizers
RUN python -c "import nltk; nltk.download('punkt', quiet=True)"

# ==============================================================================
# Final Runtime Stage
# ==============================================================================
FROM python:3.10-slim AS runner

WORKDIR /app

# Create unprivileged runtime user for least-privilege security
RUN groupadd -g 1001 appgroup && \
    useradd -u 1001 -g appgroup -s /bin/bash -m appuser

# Copy installed python packages from builder
COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Copy application source code and models
COPY . /app/

# Set ownership to unprivileged user
RUN chown -R appuser:appgroup /app /home/appuser/

USER appuser

EXPOSE 5000

# Container Healthcheck probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health')" || exit 1

CMD ["python", "app.py"]
