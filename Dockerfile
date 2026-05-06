FROM python:3.12-slim AS base

WORKDIR /app

# Install Python deps first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY config.py mcp_server.py mcp_client.py agent.py ./

# Non-root user for security
RUN useradd --create-home appuser
USER appuser

# Health check — the agent writes /tmp/agent_healthy on each successful cycle
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
    CMD [ -f /tmp/agent_healthy ] && [ $(( $(date +%s) - $(date -d "$(cat /tmp/agent_healthy)" +%s) )) -lt 600 ] || exit 1

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "agent.py"]
CMD ["--mode", "continuous", "--delete"]
