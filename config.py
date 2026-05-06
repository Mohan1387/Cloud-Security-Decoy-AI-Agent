"""
Centralized configuration — all tunables in one place.

Values are read from environment variables with sensible defaults.
In production, set these via your deployment system (ECS task definition,
k8s ConfigMap/Secret, systemd EnvironmentFile, etc.) — never commit
secrets to source control.
"""

import os

# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------
AWS_REGION: str = os.getenv("AWS_REGION", "us-east-2")
SQS_QUEUE_URL: str = os.getenv(
    "SQS_QUEUE_URL",
    "https://sqs.us-east-2.amazonaws.com/585192672941/decoy-events-aggregated",
)
REPORT_BUCKET: str = os.getenv("REPORT_BUCKET", "decoy-ai-agent-report")

# ---------------------------------------------------------------------------
# OpenAI / LLM
# ---------------------------------------------------------------------------
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
LIGHTWEIGHT_MODEL: str = os.getenv("LIGHTWEIGHT_MODEL", "gpt-4o-mini")
ADVANCED_MODEL: str = os.getenv("ADVANCED_MODEL", "gpt-5.4")

# ---------------------------------------------------------------------------
# SQS polling
# ---------------------------------------------------------------------------
SQS_WAIT_TIME_SECONDS: int = int(os.getenv("SQS_WAIT_TIME_SECONDS", "10"))
SQS_VISIBILITY_TIMEOUT: int = int(os.getenv("SQS_VISIBILITY_TIMEOUT", "120"))
POLL_INTERVAL_SECONDS: int = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))

# ---------------------------------------------------------------------------
# Agent behaviour
# ---------------------------------------------------------------------------
LANGGRAPH_RECURSION_LIMIT: int = int(os.getenv("LANGGRAPH_RECURSION_LIMIT", "25"))
MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
RETRY_BACKOFF_BASE: float = float(os.getenv("RETRY_BACKOFF_BASE", "2.0"))

# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT: str = os.getenv("LOG_FORMAT", "json")  # "json" or "text"
