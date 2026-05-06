# Cloud Decoy AI Agent

An AI-powered AWS security incident investigation system that automatically detects, investigates, and reports on unauthorized access to decoy S3 buckets (honeypots). The system combines serverless event pipelines with a LangGraph-orchestrated AI agent that uses the Model Context Protocol (MCP) to query AWS services, build attack graphs, and generate comprehensive PDF incident reports.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Components](#components)
- [AWS Services Used](#aws-services-used)
- [AI / LLM Stack](#ai--llm-stack)
- [Sample Output](#sample-output)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Usage](#usage)
- [Configuration Reference](#configuration-reference)
- [Development Notebook](#development-notebook)

---

## Overview

Cloud deception (honeypots/honeytokens) is a proactive defense strategy that deploys decoy resources to lure and detect adversaries. When an attacker interacts with a decoy S3 bucket, the system treats any access as a strong indicator of compromise. However, raw security alerts lack the context needed for rapid response.

This project bridges that gap by building an **end-to-end automated investigation pipeline**:

1. **Detect** — CloudTrail logs S3 access events on decoy buckets.
2. **Aggregate** — Serverless Lambda functions group related events into sessions and publish alerts to SQS.
3. **Investigate** — A LangGraph AI agent consumes alerts, enriches them by querying CloudTrail, IAM, and S3 security context through MCP tools, and builds attack graph visualizations.
4. **Report** — An advanced LLM generates a structured incident report (PDF) with executive summary, timeline, identity analysis, attack patterns, IOCs, and remediation recommendations.

The result is a system that transforms a raw decoy alert into a detailed, analyst-ready incident report within seconds — fully automated and continuously running.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              END-TO-END DATA FLOW                                │
└──────────────────────────────────────────────────────────────────────────────────┘

  S3 Decoy Bucket Access
         │
         ▼
  ┌─────────────┐     ┌──────────────┐     ┌──────────────────────────┐
  │  CloudTrail  │────▶│  EventBridge  │────▶│  Lambda 1 (Ingestion)    │
  └─────────────┘     └──────────────┘     │  Stores raw events into  │
                                            │  DynamoDB tables         │
                                            └────────────┬─────────────┘
                                                         │
                                                         ▼
                                            ┌──────────────────────────┐
                                            │  DynamoDB                │
                                            │  ├─ DecoySessions        │
                                            │  └─ DecoySessionEvents   │
                                            └────────────┬─────────────┘
                                                         │
                                                         ▼
                                            ┌──────────────────────────┐
                                            │  Lambda 2 (Aggregation)  │
                                            │  Scheduled every 1 min,  │
                                            │  checks session inactiv- │
                                            │  ity & flushes to SQS    │
                                            └────────────┬─────────────┘
                                                         │
                                                         ▼
                                            ┌──────────────────────────┐
                                            │  SQS Queue               │
                                            │  decoy-events-aggregated │
                                            └────────────┬─────────────┘
                                                         │
                                                         ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │                        INVESTIGATION AGENT (agent.py)                        │
  │                                                                              │
  │  ┌─────────┐   ┌────────────────┐   ┌──────────────┐   ┌────────────────┐   │
  │  │ Ingest  │──▶│ Extract Pivots │──▶│  Enrichment  │──▶│ Execute Tools  │   │
  │  │ (SQS)   │   │ (fields)       │   │  Agent (LLM) │   │ (parallel)     │   │
  │  └─────────┘   └────────────────┘   └──────────────┘   └───────┬────────┘   │
  │                                                                 │            │
  │       ┌──────────────────────┐    ┌───────────────┐    ┌───────▼────────┐   │
  │       │  Generate Report     │◀───│ Rewrite Prompt│◀───│  Consolidate   │   │
  │       │  (Advanced LLM)      │    │ (LLM)         │    │  (LLM)         │   │
  │       └──────────┬───────────┘    └───────────────┘    └───────▲────────┘   │
  │                  │                                             │            │
  │                  │                                    ┌────────┴────────┐   │
  │                  │                                    │  Build Attack   │   │
  │                  │                                    │  Graph (PNG)    │   │
  │                  │                                    └─────────────────┘   │
  │                  │                                                          │
  │                  │         MCP Server (mcp_server.py) — 8 Tools             │
  │                  │         ┌─────────────────────────────────────┐          │
  │                  │         │ read_sqs    │ query_cloudtrail      │          │
  │                  │         │ delete_sqs  │ query_identity_context│          │
  │                  │         │ extract_piv │ query_s3_security_ctx │          │
  │                  │         │ expand_time │ build_attack_graph    │          │
  │                  │         └─────────────────────────────────────┘          │
  └──────────────────┼─────────────────────────────────────────────────────────┘
                     │
                     ▼
           ┌─────────────────────┐
           │  S3 Report Bucket   │
           │  ├─ <id>.pdf        │
           │  └─ <id>_enrich.json│
           └─────────────────────┘
```

### LangGraph Workflow (8 Nodes)

```
ingest ──▶ extract_pivots ──▶ enrichment_agent ◀──▶ execute_tools
                                                          │
                                                          ▼
generate_report ◀── rewrite_prompt ◀── build_graph ◀── consolidate ──▶ END
```

The enrichment agent and tool execution nodes form a loop — the LLM decides which tools to call and may request additional queries until sufficient context is gathered.

---

## Key Features

- **Dual-LLM Strategy** — Lightweight model (`gpt-4o-mini`) for fast tool orchestration; advanced model (`gpt-5.4`) for high-quality report generation.
- **Model Context Protocol (MCP)** — Standardized tool interface between the agent and AWS security queries, enabling extensibility and parallel execution.
- **Attack Graph Visualization** — NetworkX + Matplotlib renders entity-relationship graphs showing users, IPs, resources, roles, and access keys with labeled action edges.
- **Parallel Enrichment** — The LLM can invoke CloudTrail, IAM, and S3 security tools concurrently for faster investigations.
- **Structured PDF Reports** — Auto-generated reports include executive summary, chronological timeline tables, identity analysis, attack patterns, IOCs, and actionable recommendations.
- **Continuous Polling** — Runs as a long-lived process with SQS long-polling, exponential backoff on errors, message deduplication, and graceful shutdown (SIGINT/SIGTERM).
- **Containerized Deployment** — Production-ready Dockerfile with non-root user, health checks, and Docker Compose for local development.
- **Serverless Ingestion** — Lambda functions handle event ingestion and session aggregation with DynamoDB for state management.

---

## Project Structure

```
capstone/
├── agent.py                          # LangGraph orchestrator — main investigation workflow
├── config.py                         # Centralized environment configuration with defaults
├── mcp_client.py                     # Synchronous wrapper around async MCP client
├── mcp_server.py                     # MCP server exposing 8 security investigation tools
├── requirements.txt                  # Python dependencies
├── Dockerfile                        # Production container image (Python 3.12-slim)
├── docker-compose.yml                # Local development orchestration
├── Lambda_Functions/
│   ├── Lambda1.py                    # Event ingestion: EventBridge → DynamoDB
│   ├── Lambda1_Env_Variables.txt     # Lambda 1 environment variable reference
│   ├── Lambda2.py                    # Session aggregation: scheduled scan → SQS
│   └── Lambda2_Env_Variables.txt     # Lambda 2 environment variable reference
└── Notebooks/
    └── sqs_cloudtrail_iam_sts_s3.ipynb  # Prototype/testing notebook for the workflow
```

---

## Components

### Lambda 1 — Event Ingestion (`Lambda_Functions/Lambda1.py`)

Triggered by EventBridge when CloudTrail records S3 access on a decoy bucket. Builds a session key (`{bucket}|{actor}|{sourceIP}`) and upserts two DynamoDB tables:

| Table | Partition Key | Sort Key | Purpose |
|-------|--------------|----------|---------|
| `DecoySessions` | `sessionKey` | — | Session metadata (bucket, actor, IP, firstSeen, lastSeen, status) |
| `DecoySessionEvents` | `sessionKey` | `eventTime` | Individual CloudTrail events per session |

### Lambda 2 — Session Aggregation (`Lambda_Functions/Lambda2.py`)

Runs on a scheduled trigger (every 1 minute) via EventBridge. On each invocation it scans the DynamoDB sessions table, checks whether each open session has exceeded the inactivity threshold (default 120s), and wraps up qualifying sessions. For flushed sessions it recognizes attack-relevant S3 actions (`HeadBucket`, `ListBucket`, `GetObject`, `PutObject`, `DeleteObject`, etc.), builds an attack sequence summary (e.g., `List → Get → Delete`), and publishes the aggregated alert to SQS.

### MCP Server (`mcp_server.py`)

A FastMCP server exposing 8 tools over stdio transport:

| Tool | Description |
|------|-------------|
| `read_sqs_message` | Long-poll SQS queue for security alerts |
| `delete_sqs_message` | Remove processed messages from queue |
| `query_cloudtrail` | Fetch API activity events with filters (source IP, access key, username, time window) |
| `query_identity_context` | Retrieve IAM user/role metadata and verify access key ownership |
| `query_s3_security_context` | Check bucket policy, public access block settings, and versioning status |
| `extract_pivots` | Extract investigation fields (sourceIP, accessKeyId, userName, bucket, time window) from alert body |
| `expand_time_window` | Widen alert time window (±15 min default) for broader CloudTrail lookups |
| `build_attack_graph` | Construct directed graph visualization from enrichment data using NetworkX + Matplotlib |

### MCP Client (`mcp_client.py`)

Synchronous bridge between LangGraph (sync) and the async MCP protocol. Spawns `mcp_server.py` as a subprocess, manages a background event loop in a separate thread, and provides thread-safe `call_tool()` and `list_tools()` methods with configurable timeouts.

### Agent (`agent.py`)

The core LangGraph orchestrator implementing an 8-node state graph:

1. **Ingest** — Read an SQS message; return immediately if queue is empty.
2. **Extract Pivots** — Parse investigation fields from the alert body.
3. **Enrichment Agent** — Lightweight LLM decides which tools to call (may loop for additional queries).
4. **Execute Tools** — LangGraph's `ToolNode` executes selected tools (with built-in parallelization).
5. **Consolidate** — Lightweight LLM merges all tool outputs into structured JSON.
6. **Build Graph** — Construct attack graph PNG from enrichment data.
7. **Rewrite Prompt** — Lightweight LLM builds a dynamic prompt with all enriched data inline.
8. **Generate Report** — Advanced LLM produces the final structured incident report.

After report generation, the agent builds a PDF (with embedded attack graph), publishes it to S3 (`reports/<date>/<message_id>.pdf`), uploads raw enrichment JSON, and optionally deletes the SQS message.

### Config (`config.py`)

Centralized configuration loaded from environment variables (with `.env` support via `python-dotenv`). All settings have sensible defaults. See [Configuration Reference](#configuration-reference) for details.

---

## AWS Services Used

| Service | Purpose |
|---------|---------|
| **S3** | Decoy bucket (honeypot target) and report storage bucket |
| **CloudTrail** | Security audit log source for API activity queries |
| **EventBridge** | Triggers Lambda 1 on S3 access events |
| **Lambda** | Serverless compute for event ingestion (Lambda 1) and session aggregation (Lambda 2) |
| **DynamoDB** | Session state storage (sessions + events tables) |
| **EventBridge Scheduler** | Triggers Lambda 2 on a 1-minute schedule |
| **SQS** | Message queue for aggregated alerts consumed by the agent |
| **IAM** | Identity context lookups (users, roles, access keys) |

---

## AI / LLM Stack

| Model | Role | Temperature | Purpose |
|-------|------|-------------|---------|
| `gpt-4o-mini` | Lightweight | 0.0 | Tool selection, pivot extraction, consolidation, prompt rewriting |
| `gpt-5.4` | Advanced | 0.2 | Final incident report generation |

**LLM invocations per investigation cycle:**

1. **Enrichment agent** — Selects which tools to call (may loop if additional context is needed).
2. **Consolidation** — Merges all tool outputs into a unified JSON structure.
3. **Prompt rewriting** — Constructs a dynamic, enriched prompt for the final report.
4. **Report generation** — Advanced model produces the structured incident report.

---

## Sample Output

The system generates a **PDF incident report** for each investigated alert. A sample report structure includes:

1. **Executive Summary** — Risk level (Critical/High/Medium/Low), synopsis of the incident, key findings.
2. **Timeline of Events** — Chronological table of CloudTrail events with timestamps, event names, source IPs, target resources, and results.
3. **Identity Analysis** — IAM user details, principal ID, access key assessment, authentication method analysis.
4. **Attack Graph Visualization** — Entity-relationship diagram showing users (blue), IPs (red), resources (green), roles (orange), and access keys (purple) with labeled action edges.
5. **Attack Pattern / Behavior Analysis** — Behavioral indicators, attack flow reconstruction, suspicion rationale.
6. **S3 Access & Exposure Analysis** — Bucket security posture, public access block status, policy analysis.
7. **Impact Assessment** — Confirmed and potential impact, severity rationale, scope limitations.
8. **Indicators of Compromise (IOCs)** — Source IPs, access keys, user agents, event IDs, targeted resources, time ranges.
9. **Recommendations** — Immediate containment steps, investigation follow-up, hardening measures, decoy-specific response actions.

Reports are published to S3 at `reports/<date>/<message_id>.pdf` alongside raw enrichment data at `reports/<date>/<message_id>_enrichment.json`.

---

## Prerequisites

- **Python 3.12+**
- **AWS Account** with the following configured:
  - S3 decoy bucket(s)
  - CloudTrail enabled
  - EventBridge rule targeting decoy bucket events
  - Two Lambda functions deployed (Lambda 1 and Lambda 2)
  - DynamoDB tables (`DecoySessions`, `DecoySessionEvents`)
  - SQS queue (`decoy-events-aggregated`)
  - S3 report bucket (`decoy-ai-agent-report`)
  - IAM permissions for the agent to query CloudTrail, IAM, S3, and SQS
- **OpenAI API Key** with access to `gpt-4o-mini` and `gpt-5.4`
- **AWS CLI** configured with valid credentials (or IAM role when running on EC2/ECS)

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd capstone
```

### 2. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```env
# Required
OPENAI_API_KEY=sk-...

# AWS (defaults to us-east-2; override if needed)
AWS_DEFAULT_REGION=us-east-2
SQS_QUEUE_URL=https://sqs.us-east-2.amazonaws.com/<account-id>/decoy-events-aggregated
REPORT_BUCKET=decoy-ai-agent-report

# Optional overrides
LIGHTWEIGHT_MODEL=gpt-4o-mini
ADVANCED_MODEL=gpt-5.4
POLL_INTERVAL=30
LOG_LEVEL=INFO
```

### 5. Deploy Lambda Functions

Deploy `Lambda_Functions/Lambda1.py` and `Lambda_Functions/Lambda2.py` to AWS Lambda with the environment variables specified in their respective `*_Env_Variables.txt` files. Configure:

- **Lambda 1**: EventBridge trigger on S3 data events for decoy buckets.
- **Lambda 2**: EventBridge scheduled rule (every 1 minute) to scan and flush inactive sessions.

---

## Usage

### CLI Mode

```bash
# Process a single message and exit
python agent.py --mode once

# Process a single message and delete it from SQS after success
python agent.py --mode once --delete

# Run continuously, polling SQS every 30 seconds
python agent.py --mode continuous --delete

# Custom poll interval
python agent.py --mode continuous --delete --poll-interval 60
```

### Docker

```bash
# Build and run with Docker Compose
docker compose up --build

# Or build and run directly
docker build -t cloud-decoy-agent .
docker run --env-file .env cloud-decoy-agent
```

The container runs in continuous mode by default (`--mode continuous --delete`) and includes a health check that monitors `/tmp/agent_healthy`.

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--mode` | `once` | `once` — process one message and exit; `continuous` — poll indefinitely |
| `--delete` | `false` | Delete SQS message after successful processing |
| `--poll-interval` | `30` | Seconds between SQS polls (continuous mode only) |

---

## Configuration Reference

All settings are loaded from environment variables with defaults defined in `config.py`.

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_DEFAULT_REGION` | `us-east-2` | AWS region for all service clients |
| `SQS_QUEUE_URL` | `https://sqs...decoy-events-aggregated` | SQS queue URL for aggregated alerts |
| `REPORT_BUCKET` | `decoy-ai-agent-report` | S3 bucket for published reports |
| `LIGHTWEIGHT_MODEL` | `gpt-4o-mini` | Model for tool orchestration and consolidation |
| `ADVANCED_MODEL` | `gpt-5.4` | Model for final report generation |
| `SQS_WAIT_TIME` | `10` | SQS long-polling wait time (seconds) |
| `SQS_VISIBILITY_TIMEOUT` | `120` | SQS message visibility timeout (seconds) |
| `POLL_INTERVAL` | `30` | Interval between SQS polls in continuous mode (seconds) |
| `LANGGRAPH_RECURSION_LIMIT` | `25` | Maximum LangGraph state transitions per run |
| `MAX_RETRIES` | `3` | Max retries on transient failures |
| `RETRY_BACKOFF` | `2.0` | Exponential backoff multiplier for retries |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `LOG_FORMAT` | `text` | Log output format (`text` or `json`) |

### Lambda 2 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSIONS_TABLE` | `DecoySessions` | DynamoDB sessions table name |
| `EVENTS_TABLE` | `DecoySessionEvents` | DynamoDB events table name |
| `SQS_QUEUE_URL` | — | Target SQS queue for aggregated alerts |
| `INACTIVITY_SECONDS` | `120` | Session inactivity threshold before flush |
| `CLOUDTRAIL_LOOKBACK_MINUTES` | `15` | CloudTrail lookback window for enrichment |
| `CLOUDTRAIL_FORWARD_MINUTES` | `2` | CloudTrail forward window for enrichment |
| `ENABLE_CLOUDTRAIL_ENRICHMENT` | `true` | Enable/disable CloudTrail enrichment in Lambda |
| `MAX_CLOUDTRAIL_EVENTS` | `50` | Max CloudTrail events to fetch per session |

---

## Development Notebook

The `Notebooks/sqs_cloudtrail_iam_sts_s3.ipynb` Jupyter notebook serves as the **prototype and testing ground** for the investigation workflow. It contains standalone implementations of:

- SQS message reading and deletion
- CloudTrail event querying with filters
- IAM identity context lookups
- S3 security posture checks
- Pivot extraction and time window expansion
- Prompt construction and OpenAI report generation

This notebook was the basis for the production agent and is useful for interactive development, debugging individual pipeline stages, and testing new enrichment queries.

---

## License

This project was developed as a capstone research project.
