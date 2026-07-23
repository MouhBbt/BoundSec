FROM python:3.12-slim

# Security: run as non-root
RUN addgroup --system agentfuzz && adduser --system --ingroup agentfuzz agentfuzz

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY agentfuzz/ ./agentfuzz/
COPY tests/ ./tests/
COPY pyproject.toml .

RUN pip install --no-cache-dir -e .

# Default: run the CLI
USER agentfuzz
ENTRYPOINT ["python", "-m", "agentfuzz"]
CMD ["--help"]
