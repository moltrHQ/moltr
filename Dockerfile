FROM python:3.11-slim

LABEL maintainer="Walter Troska"
LABEL description="Moltr Security - The Protective Shell for Your AI Agent"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ src/
COPY config/ config/
# NOTE: honeypots/ are NOT baked into the image.
# Mount them at runtime: docker run -v ./honeypots:/app/honeypots moltr

# Create runtime directories (data/ persisted via Docker volume)
RUN mkdir -p logs data

# Create non-root user
RUN useradd --create-home --shell /bin/bash moltr && \
    chown -R moltr:moltr /app

USER moltr

EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8420/health')"

ENTRYPOINT ["python", "-m", "uvicorn", "src.api.server:app", "--host", "0.0.0.0", "--port", "8420", "--log-level", "info"]
