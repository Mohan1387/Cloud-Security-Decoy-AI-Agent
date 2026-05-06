"""
LangGraph Agentic System — AWS Security Incident Investigation

Workflow:
  1. Ingest alert from SQS via MCP tool
  2. Extract pivots and decide which enrichment tools to call
  3. Execute enrichment tools (CloudTrail, IAM, S3) — potentially in parallel
  4. Consolidate all results into structured JSON
  5. Build attack graph from enrichment data
  6. Dynamically rewrite the prompt with enriched data
  7. Generate final report as PDF with embedded attack graph

Model routing:
  - Lightweight model  → tool selection, execution, prompt rewriting
  - Advanced model     → final incident report generation
"""

import json
import logging
import operator
import os
import re
import signal
import time
from datetime import datetime, timezone
from typing import Annotated, TypedDict

import boto3
from botocore.config import Config as BotoConfig
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

import config
import mcp_client

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("agent")


def _setup_logging():
    """Configure root logger based on config.LOG_FORMAT and config.LOG_LEVEL."""
    level = getattr(logging, config.LOG_LEVEL, logging.INFO)
    if config.LOG_FORMAT == "json":
        fmt = json.dumps({
            "time": "%(asctime)s", "level": "%(levelname)s",
            "logger": "%(name)s", "message": "%(message)s",
        })
        logging.basicConfig(level=level, format=fmt)
    else:
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )


# ---------------------------------------------------------------------------
# Local S3 client (for report publishing — agent-level concern, not MCP)
# ---------------------------------------------------------------------------
_s3_client = None


def _get_s3_client():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client(
            "s3",
            config=BotoConfig(
                region_name=config.AWS_REGION,
                retries={"max_attempts": config.MAX_RETRIES, "mode": "adaptive"},
                read_timeout=30,
                connect_timeout=10,
            ),
        )
    return _s3_client


# ---------------------------------------------------------------------------
# LangChain tool wrappers (with rich descriptions for the agent)
# ---------------------------------------------------------------------------

@tool
def read_sqs_message(
    queue_url: str = config.SQS_QUEUE_URL,
    wait_time_seconds: int = config.SQS_WAIT_TIME_SECONDS,
    visibility_timeout: int = config.SQS_VISIBILITY_TIMEOUT,
) -> dict:
    """Read one alert message from the SQS queue.

    Call this first to ingest the next security alert. Returns the message
    body with session events, pivot fields (sourceIP, accessKeyId, userName,
    bucket, firstSeen, lastSeen), receipt_handle for later deletion, and
    message metadata.

    Inputs:
      queue_url        – SQS queue URL (default: decoy-events-aggregated)
      wait_time_seconds – long-poll wait (1-20, default 10)
      visibility_timeout – seconds message stays invisible (default 60)

    Output dict keys: message_id, receipt_handle, body, attributes,
    message_attributes.  Returns {"status":"empty"} if queue is empty.
    """
    return mcp_client.call_tool("read_sqs_message", {
        "queue_url": queue_url,
        "wait_time_seconds": wait_time_seconds,
        "visibility_timeout": visibility_timeout,
    })


@tool
def delete_sqs_message(queue_url: str, receipt_handle: str) -> dict:
    """Delete a processed SQS message so it is not re-delivered.

    Call after the investigation pipeline has finished.

    Inputs:
      queue_url       – SQS queue URL
      receipt_handle  – handle from read_sqs_message

    Output: {"deleted": true}
    """
    return mcp_client.call_tool("delete_sqs_message", {
        "queue_url": queue_url,
        "receipt_handle": receipt_handle,
    })


@tool
def extract_pivots(sqs_body: dict) -> dict:
    """Extract investigation pivot fields from an SQS message body.

    Call immediately after reading an SQS message. Returns source_ip,
    access_key_id, username, role_name, bucket_name, start_time, end_time.

    Input:  sqs_body – the parsed body dict from read_sqs_message
    Output: dict of pivot fields (any may be None)
    """
    return mcp_client.call_tool("extract_pivots", {"sqs_body": sqs_body})


@tool
def expand_time_window(
    start_time: str,
    end_time: str,
    lookback_minutes: int = 15,
    forward_minutes: int = 15,
) -> dict:
    """Widen firstSeen/lastSeen window for CloudTrail lookups.

    Call before query_cloudtrail to capture pre- and post-attack activity.

    Inputs:
      start_time       – ISO-8601 original start
      end_time         – ISO-8601 original end
      lookback_minutes – minutes to subtract (default 15)
      forward_minutes  – minutes to add (default 15)

    Output: {"start_time": ..., "end_time": ...} with widened bounds.
    """
    return mcp_client.call_tool("expand_time_window", {
        "start_time": start_time,
        "end_time": end_time,
        "lookback_minutes": lookback_minutes,
        "forward_minutes": forward_minutes,
    })


@tool
def query_cloudtrail(
    start_time: str,
    end_time: str,
    source_ip: str | None = None,
    access_key_id: str | None = None,
    username: str | None = None,
    max_results: int = 20,
) -> dict:
    """Query CloudTrail for API activity in a time window.

    Retrieves events matching one or more of source_ip, access_key_id,
    username within [start_time, end_time].

    At least one filter (source_ip / access_key_id / username) is required.

    Output: {source, event_count, events: [{EventTime, EventName, Username,
    EventId, Resources, CloudTrailEvent}]}
    """
    args: dict = {
        "start_time": start_time,
        "end_time": end_time,
        "max_results": max_results,
    }
    if source_ip is not None:
        args["source_ip"] = source_ip
    if access_key_id is not None:
        args["access_key_id"] = access_key_id
    if username is not None:
        args["username"] = username
    return mcp_client.call_tool("query_cloudtrail", args)


@tool
def query_identity_context(
    username: str | None = None,
    role_name: str | None = None,
    access_key_id: str | None = None,
) -> dict:
    """Retrieve IAM identity context (user, role, access-key match).

    Can run in parallel with query_cloudtrail and query_s3_security_context.

    Inputs (all optional, but at least one should be provided):
      username       – IAM user name
      role_name      – IAM role name
      access_key_id  – if given with username, verifies key ownership

    Output: {source, user, role, access_key_matches}
    """
    args: dict = {}
    if username is not None:
        args["username"] = username
    if role_name is not None:
        args["role_name"] = role_name
    if access_key_id is not None:
        args["access_key_id"] = access_key_id
    return mcp_client.call_tool("query_identity_context", args)


@tool
def query_s3_security_context(bucket_name: str) -> dict:
    """Retrieve S3 bucket security posture (policy status, public access
    block, versioning).

    Can run in parallel with query_cloudtrail and query_identity_context.

    Input:  bucket_name – S3 bucket name
    Output: {source, bucket_name, bucket_policy_status,
             public_access_block, bucket_versioning}
    """
    return mcp_client.call_tool("query_s3_security_context", {
        "bucket_name": bucket_name,
    })


@tool
def build_attack_graph(enrichment_data: dict, output_path: str = "/tmp/attack_graph.png") -> dict:
    """Build a directed attack graph from enrichment data and render it as PNG.

    Call after enrichment is consolidated. The graph shows entities (users,
    IPs, resources, roles, access keys) as nodes and actions/relationships
    as edges.

    Inputs:
      enrichment_data – consolidated enrichment JSON
      output_path     – file path for the rendered PNG (default: /tmp/attack_graph.png)

    Output: {graph_path, node_count, edge_count, nodes, edges}
    """
    return mcp_client.call_tool("build_attack_graph", {
        "enrichment_data": enrichment_data,
        "output_path": output_path,
    })


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------
ENRICHMENT_TOOLS = [
    extract_pivots,
    expand_time_window,
    query_cloudtrail,
    query_identity_context,
    query_s3_security_context,
]

# ---------------------------------------------------------------------------
# Models (lazy — instantiated after env is loaded)
# ---------------------------------------------------------------------------
llm_lightweight: ChatOpenAI | None = None
llm_advanced: ChatOpenAI | None = None
llm_enrichment_tools = None


def _init_models():
    global llm_lightweight, llm_advanced, llm_enrichment_tools
    if llm_lightweight is None:
        llm_lightweight = ChatOpenAI(
            model=config.LIGHTWEIGHT_MODEL,
            temperature=0,
            max_retries=config.MAX_RETRIES,
        )
        llm_advanced = ChatOpenAI(
            model=config.ADVANCED_MODEL,
            temperature=0.2,
            max_retries=config.MAX_RETRIES,
        )
        llm_enrichment_tools = llm_lightweight.bind_tools(ENRICHMENT_TOOLS)
        logger.info(
            "Models initialised: lightweight=%s, advanced=%s",
            config.LIGHTWEIGHT_MODEL, config.ADVANCED_MODEL,
        )

# ---------------------------------------------------------------------------
# Graph state
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    """Shared state passed between graph nodes."""
    messages: Annotated[list[BaseMessage], operator.add]
    sqs_message: dict | None
    pivots: dict | None
    enrichment_results: dict | None
    attack_graph_path: str | None
    rewritten_prompt: dict | None
    incident_report: str | None


# ---------------------------------------------------------------------------
# Node: ingest SQS message
# ---------------------------------------------------------------------------

def ingest_node(state: AgentState) -> dict:
    """Read one message from SQS and store it in state."""
    msg = mcp_client.call_tool("read_sqs_message")
    if msg.get("status") == "empty":
        return {
            "messages": [AIMessage(content="No messages in SQS queue.")],
            "sqs_message": None,
        }
    return {
        "messages": [AIMessage(content=f"Ingested SQS message {msg['message_id']}.")],
        "sqs_message": msg,
    }


# ---------------------------------------------------------------------------
# Node: extract pivots
# ---------------------------------------------------------------------------

def extract_pivots_node(state: AgentState) -> dict:
    """Pull pivot fields from the SQS body."""
    body = state["sqs_message"]["body"]
    pivots = mcp_client.call_tool("extract_pivots", {"sqs_body": body})
    return {
        "messages": [AIMessage(content=f"Extracted pivots: {json.dumps(pivots, default=str)}")],
        "pivots": pivots,
    }


# ---------------------------------------------------------------------------
# Node: agent decides which enrichment tools to call
# ---------------------------------------------------------------------------

TOOL_PLANNING_SYSTEM = SystemMessage(content="""You are an AWS security investigation orchestrator.

You have been given pivot fields extracted from an SQS alert message.
Decide which enrichment tools to call and invoke them. You may call
multiple tools in parallel when their inputs are independent.

Available enrichment tools:
- expand_time_window: widen the alert time window before CloudTrail lookup
- query_cloudtrail: fetch CloudTrail events in a time range
- query_identity_context: fetch IAM user/role details
- query_s3_security_context: fetch S3 bucket security posture

Rules:
1. Always call expand_time_window first if start_time and end_time are available.
2. After expanding the window, call query_cloudtrail.
3. Call query_identity_context if username or role_name is available.
4. Call query_s3_security_context if bucket_name is available.
5. Tools 3 and 4 can run in parallel with tool 2.
""")


def enrichment_agent_node(state: AgentState) -> dict:
    """Let the lightweight LLM decide which tools to call."""
    _init_models()
    pivots = state["pivots"]

    # Count how many enrichment rounds have already happened
    tool_result_count = sum(1 for m in state["messages"] if m.type == "tool")

    if tool_result_count == 0:
        # First round: present pivots and ask which tools to call
        user_msg = HumanMessage(
            content=(
                f"Here are the extracted pivots from the SQS alert:\n"
                f"{json.dumps(pivots, indent=2, default=str)}\n\n"
                "Decide which enrichment tools to call and invoke them. "
                "Try to call as many tools in parallel as possible."
            )
        )
        response = llm_enrichment_tools.invoke([TOOL_PLANNING_SYSTEM, user_msg])
    else:
        # Subsequent round: show what tools have already returned and ask
        # if more are needed
        completed_tools = [m.name for m in state["messages"] if m.type == "tool"]
        remaining_msg = HumanMessage(
            content=(
                f"The following tools have already been executed: {completed_tools}.\n"
                "If any remaining enrichment tools still need to be called based on "
                "the pivots and previous results, call them now. "
                "If all enrichment is complete, respond with a short summary and "
                "do NOT call any more tools."
            )
        )
        response = llm_enrichment_tools.invoke(
            [TOOL_PLANNING_SYSTEM]
            + [m for m in state["messages"] if m.type in ("ai", "tool")][-10:]
            + [remaining_msg]
        )

    return {"messages": [response]}


# ---------------------------------------------------------------------------
# Node: execute tools (LangGraph prebuilt ToolNode handles parallel calls)
# ---------------------------------------------------------------------------

tool_executor = ToolNode(ENRICHMENT_TOOLS)


def tool_execution_node(state: AgentState) -> dict:
    """Execute all tool calls made by the agent."""
    return tool_executor.invoke(state)


# ---------------------------------------------------------------------------
# Routing: should we keep calling tools or move on?
# ---------------------------------------------------------------------------

def should_continue_tools(state: AgentState) -> str:
    """Route after the agent node: if the last message has tool calls,
    go to tool execution; otherwise proceed to consolidation."""
    last = state["messages"][-1]
    if hasattr(last, "tool_calls") and last.tool_calls:
        return "execute_tools"
    return "consolidate"


# ---------------------------------------------------------------------------
# Node: consolidate enrichment results into structured JSON
# ---------------------------------------------------------------------------

CONSOLIDATION_SYSTEM = SystemMessage(content="""You are a data consolidation assistant.

You will receive a series of tool results from AWS security enrichment tools.
Your job is to consolidate ALL results into a single structured JSON object.

Use each tool's source name as the top-level key (e.g. "cloudtrail",
"identity_context", "s3_context"). Only include keys for tools that were
actually called — do not fabricate sections that have no data.

Always include a "pivots" key with the extracted pivot fields.

Return ONLY valid JSON. No markdown fences, no commentary.
""")


def consolidate_node(state: AgentState) -> dict:
    """Ask the lightweight LLM to merge all tool outputs into one JSON."""
    _init_models()
    # Collect tool result messages
    tool_results = []
    executed_tools: list[str] = []
    for msg in state["messages"]:
        if msg.type == "tool":
            tool_results.append(f"Tool '{msg.name}' returned:\n{msg.content}")
            if msg.name not in executed_tools:
                executed_tools.append(msg.name)

    consolidation_prompt = HumanMessage(
        content=(
            f"The following tools were executed: {executed_tools}\n\n"
            "Here are all the tool results from the enrichment phase:\n\n"
            + "\n\n---\n\n".join(tool_results)
            + "\n\nConsolidate these into a single structured JSON."
        )
    )

    response = llm_lightweight.invoke([CONSOLIDATION_SYSTEM, consolidation_prompt])

    try:
        enrichment_json = json.loads(response.content)
    except json.JSONDecodeError:
        enrichment_json = {"raw_consolidation": response.content}

    return {
        "messages": [AIMessage(content="Enrichment data consolidated.")],
        "enrichment_results": enrichment_json,
    }


# ---------------------------------------------------------------------------
# Node: build attack graph from enrichment data
# ---------------------------------------------------------------------------

def build_graph_node(state: AgentState) -> dict:
    """Construct the attack graph PNG from consolidated enrichment data."""
    enrichment = dict(state.get("enrichment_results") or {})
    msg_id = state.get("sqs_message", {}).get("message_id", "unknown")
    # Sanitise message_id for use in filename
    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(msg_id))
    output_path = f"/tmp/attack_graph_{safe_id}.png"

    # Ensure pivots from state are present — the consolidation LLM may
    # not include them because extract_pivots runs before the enrichment
    # agent and its results are stored in state["pivots"], not as tool
    # messages visible to the consolidation prompt.
    pivots_from_state = state.get("pivots") or {}
    existing_pivots = enrichment.get("pivots") or {}
    merged_pivots = {**pivots_from_state, **{k: v for k, v in existing_pivots.items() if v}}
    enrichment["pivots"] = merged_pivots

    # Include SQS sessionEvents so the graph captures all events from the
    # original alert (CloudTrail enrichment may return a different subset).
    sqs_body = state.get("sqs_message", {}).get("body", {})
    if isinstance(sqs_body, str):
        try:
            sqs_body = json.loads(sqs_body)
        except (json.JSONDecodeError, TypeError):
            sqs_body = {}
    session_events = sqs_body.get("sessionEvents", [])
    if session_events:
        enrichment["session_events"] = session_events

    result = mcp_client.call_tool("build_attack_graph", {
        "enrichment_data": enrichment,
        "output_path": output_path,
    })

    graph_path = result.get("graph_path", output_path)
    node_count = result.get("node_count", 0)
    edge_count = result.get("edge_count", 0)

    return {
        "messages": [AIMessage(
            content=f"Attack graph built: {node_count} nodes, {edge_count} edges → {graph_path}"
        )],
        "attack_graph_path": graph_path,
    }


# ---------------------------------------------------------------------------
# Node: dynamically rewrite the prompt for the final LLM call
# ---------------------------------------------------------------------------

# Static system prompt for the advanced model (fixed report structure)
REPORT_SYSTEM_PROMPT = (
    "You are a senior cloud security analyst specializing in AWS incident response.\n"
    "This is a Decoy Incident. Any access is a strong indicator of compromise.\n\n"
    "An attack graph visualization has been generated and will be embedded in the\n"
    "final PDF report. Reference the graph in your analysis where relevant\n"
    "(e.g., 'As illustrated in the attack graph…').\n\n"
    "Analyze the provided data and produce a structured incident report with these sections:\n"
    "1. Executive Summary (with risk level: Critical / High / Medium / Low)\n"
    "2. Timeline of Events (chronological, sourced from CloudTrail), create it in a table structure\n"
    "3. Identity Analysis\n"
    "4. Attack Graph Analysis (describe the entity relationships and attack flow shown in the graph)\n"
    "5. Attack Pattern / Behavior Analysis\n"
    "6. S3 Access & Exposure Analysis\n"
    "7. Impact Assessment\n"
    "8. Indicators of Compromise (IOCs)\n"
    "9. Recommendations\n\n"
    "Do not hallucinate. Use only the provided data."
)

PROMPT_REWRITE_SYSTEM = SystemMessage(content="""You are a prompt engineer for AWS incident reports.

Given structured enrichment data and the original SQS alert body, produce
a single string that will be sent as the user message to a senior cloud
security analyst.

The string must include ALL available enrichment data inline so the analyst
has everything needed to write a complete incident report. Only include
sections for data sources that are actually present in the enrichment —
do not reference or fabricate data for tools that were not called.

Return ONLY the user prompt text. No JSON wrapping, no markdown fences,
no commentary.
""")


def rewrite_prompt_node(state: AgentState) -> dict:
    """Use the lightweight LLM to build the final prompt dynamically."""
    _init_models()
    sqs_body = state["sqs_message"]["body"]
    enrichment = state["enrichment_results"]

    # Summarize CloudTrail events if present to reduce token usage
    enrichment_for_prompt = {**enrichment}
    ct_data = enrichment.get("cloudtrail", {})
    if ct_data and ct_data.get("events"):
        ct_summary = [
            {
                "eventTime": str(e.get("EventTime", e.get("eventTime", ""))),
                "eventName": e.get("EventName", e.get("eventName", "")),
                "username": e.get("Username", e.get("username", "")),
                "eventId": e.get("EventId", e.get("eventId", "")),
                "resources": e.get("Resources", e.get("resources", [])),
            }
            for e in ct_data["events"]
        ]
        enrichment_for_prompt["cloudtrail"] = {
            **ct_data,
            "events": ct_summary,
        }

    rewrite_request = HumanMessage(
        content=(
            f"SQS alert body:\n{json.dumps(sqs_body, indent=2, default=str)}\n\n"
            f"Enrichment data:\n{json.dumps(enrichment_for_prompt, indent=2, default=str)}\n\n"
            "Generate the prompt bundle JSON."
        )
    )

    response = llm_lightweight.invoke([PROMPT_REWRITE_SYSTEM, rewrite_request])

    user_prompt = response.content.strip()
    if not user_prompt:
        user_prompt = _fallback_user_prompt(sqs_body, enrichment_for_prompt)

    return {
        "messages": [AIMessage(content="Prompt rewritten for final report.")],
        "rewritten_prompt": {"user_prompt": user_prompt},
    }


def _fallback_user_prompt(sqs_body: dict, enrichment: dict) -> str:
    """Deterministic fallback user prompt if the LLM produces empty output."""
    parts = [
        "Generate a detailed incident report based on the following data:\n",
        f"SQS Session Events:\n{json.dumps(sqs_body.get('sessionEvents', sqs_body), indent=2, default=str)}\n",
    ]
    # Include only enrichment sections that have data
    _section_labels = {
        "cloudtrail": "CloudTrail Events",
        "identity_context": "IAM Identity Context",
        "s3_context": "S3 Security Context",
    }
    for key, label in _section_labels.items():
        data = enrichment.get(key)
        if data:
            parts.append(f"{label}:\n{json.dumps(data, indent=2, default=str)}\n")
    # Include any other enrichment keys not in the standard set
    for key, data in enrichment.items():
        if key not in _section_labels and key != "pivots" and data:
            parts.append(f"{key}:\n{json.dumps(data, indent=2, default=str)}\n")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Node: generate final report with the advanced model
# ---------------------------------------------------------------------------

def generate_report_node(state: AgentState) -> dict:
    """Call the advanced model with the static system prompt and dynamic user prompt."""
    _init_models()
    usr_prompt = state["rewritten_prompt"].get("user_prompt", "")
    if not isinstance(usr_prompt, str):
        usr_prompt = json.dumps(usr_prompt, indent=2, default=str)

    response = llm_advanced.invoke([
        SystemMessage(content=REPORT_SYSTEM_PROMPT),
        HumanMessage(content=usr_prompt),
    ])
    return {
        "messages": [AIMessage(content="Incident report generated.")],
        "incident_report": response.content,
    }


# ---------------------------------------------------------------------------
# Conditional edge: abort early if no SQS message
# ---------------------------------------------------------------------------

def check_sqs_message(state: AgentState) -> str:
    if state.get("sqs_message") is None:
        return "done"
    return "extract_pivots"


# ---------------------------------------------------------------------------
# Build the graph
# ---------------------------------------------------------------------------

def build_graph():
    g = StateGraph(AgentState)

    # Nodes
    g.add_node("ingest", ingest_node)
    g.add_node("extract_pivots", extract_pivots_node)
    g.add_node("enrichment_agent", enrichment_agent_node)
    g.add_node("execute_tools", tool_execution_node)
    g.add_node("consolidate", consolidate_node)
    g.add_node("build_graph", build_graph_node)
    g.add_node("rewrite_prompt", rewrite_prompt_node)
    g.add_node("generate_report", generate_report_node)

    # Edges
    g.set_entry_point("ingest")
    g.add_conditional_edges("ingest", check_sqs_message, {
        "extract_pivots": "extract_pivots",
        "done": END,
    })
    g.add_edge("extract_pivots", "enrichment_agent")
    g.add_conditional_edges("enrichment_agent", should_continue_tools, {
        "execute_tools": "execute_tools",
        "consolidate": "consolidate",
    })
    # After tool execution, return to the agent so it can decide if more
    # tools are needed or if all enrichment is complete.
    g.add_edge("execute_tools", "enrichment_agent")
    g.add_edge("consolidate", "build_graph")
    g.add_edge("build_graph", "rewrite_prompt")
    g.add_edge("rewrite_prompt", "generate_report")
    g.add_edge("generate_report", END)

    return g.compile()


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

graph = None


def _get_graph():
    global graph
    if graph is None:
        graph = build_graph()
    return graph


def run_investigation(delete_after: bool = False) -> dict:
    """Run the full investigation pipeline and return the result dict.

    Returns:
      - status: "processed" | "no_message"
      - incident_report: the generated report text
      - enrichment_results: consolidated enrichment JSON
      - sqs_message: original SQS message
    """
    initial_state: AgentState = {
        "messages": [HumanMessage(content="Begin security investigation.")],
        "sqs_message": None,
        "pivots": None,
        "enrichment_results": None,
        "attack_graph_path": None,
        "rewritten_prompt": None,
        "incident_report": None,
    }

    final_state = _get_graph().invoke(
        initial_state,
        config={"recursion_limit": config.LANGGRAPH_RECURSION_LIMIT},
    )

    if final_state.get("sqs_message") is None:
        return {"status": "no_message", "message": "No SQS messages available."}

    # Optionally delete the processed message
    if delete_after and final_state.get("sqs_message"):
        mcp_client.call_tool("delete_sqs_message", {
            "queue_url": config.SQS_QUEUE_URL,
            "receipt_handle": final_state["sqs_message"]["receipt_handle"],
        })

    return {
        "status": "processed",
        "message_id": final_state["sqs_message"].get("message_id"),
        "enrichment_results": final_state.get("enrichment_results"),
        "rewritten_prompt": final_state.get("rewritten_prompt"),
        "incident_report": final_state.get("incident_report"),
        "attack_graph_path": final_state.get("attack_graph_path"),
        "receipt_handle": final_state["sqs_message"].get("receipt_handle"),
    }


# ---------------------------------------------------------------------------
# S3 report publishing (PDF)
# ---------------------------------------------------------------------------


def _build_pdf(report_text: str, graph_image_path: str | None, message_id: str) -> bytes:
    """Convert the markdown report text into a PDF with an embedded attack graph.

    Returns the PDF as bytes.
    """
    from fpdf import FPDF
    import matplotlib

    # Locate DejaVu Sans TTF (ships with matplotlib) for Unicode support
    _mpl_fonts = os.path.join(os.path.dirname(matplotlib.__file__), "mpl-data", "fonts", "ttf")
    _font_regular = os.path.join(_mpl_fonts, "DejaVuSans.ttf")
    _font_bold = os.path.join(_mpl_fonts, "DejaVuSans-Bold.ttf")
    _font_italic = os.path.join(_mpl_fonts, "DejaVuSans-Oblique.ttf")

    class IncidentPDF(FPDF):
        def header(self):
            self.set_font("dejavu", "B", 9)
            self.set_text_color(120, 120, 120)
            self.cell(0, 8, f"Incident Report - {message_id}", align="R")
            self.ln(10)

        def footer(self):
            self.set_y(-15)
            self.set_font("dejavu", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    pdf = IncidentPDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)

    # Register Unicode font
    pdf.add_font("dejavu", "", _font_regular, uni=True)
    pdf.add_font("dejavu", "B", _font_bold, uni=True)
    pdf.add_font("dejavu", "I", _font_italic, uni=True)

    # --- Title page ---
    pdf.add_page()
    pdf.set_font("dejavu", "B", 24)
    pdf.set_text_color(30, 60, 120)
    pdf.ln(40)
    pdf.cell(0, 15, "AWS Security Incident Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)
    pdf.set_font("dejavu", "", 12)
    pdf.set_text_color(80, 80, 80)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.cell(0, 8, f"Generated: {now_str}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Message ID: {message_id}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(15)
    pdf.set_draw_color(30, 60, 120)
    pdf.set_line_width(0.5)
    pdf.line(30, pdf.get_y(), 180, pdf.get_y())

    # --- Attack Graph page ---
    if graph_image_path and os.path.isfile(graph_image_path):
        pdf.add_page()
        pdf.set_font("dejavu", "B", 16)
        pdf.set_text_color(30, 60, 120)
        pdf.cell(0, 12, "Attack Graph Visualization", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
        # Embed graph image - fit to page width with margins
        page_w = pdf.w - pdf.l_margin - pdf.r_margin
        pdf.image(graph_image_path, x=pdf.l_margin, w=page_w)
        pdf.ln(6)
        pdf.set_font("dejavu", "I", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 6,
                 "Nodes represent entities (users, IPs, resources, roles, access keys). "
                 "Edges represent actions and relationships.",
                 new_x="LMARGIN", new_y="NEXT")

    # --- Report body ---
    pdf.add_page()
    _render_markdown_to_pdf(pdf, report_text)

    return pdf.output()


def _render_table(pdf, rows: list[list[str]]):
    """Render a parsed markdown table as a styled PDF table with word wrapping."""
    if not rows:
        return

    num_cols = max(len(r) for r in rows)
    # Pad short rows
    for row in rows:
        while len(row) < num_cols:
            row.append("")

    # Strip bold/backtick markers from all cells
    for row in rows:
        for j in range(len(row)):
            row[j] = re.sub(r"\*\*(.*?)\*\*", r"\1", row[j])
            row[j] = re.sub(r"`(.*?)`", r"\1", row[j])

    # Adaptive font size: shrink for wide tables
    if num_cols >= 8:
        font_size = 6
    elif num_cols >= 6:
        font_size = 7
    else:
        font_size = 8

    usable_w = pdf.w - pdf.l_margin - pdf.r_margin
    ROW_HEIGHT = font_size * 0.75  # line height scales with font
    CELL_PAD = 1.5  # horizontal padding inside cells

    # Compute column widths using actual rendered glyph widths
    pdf.set_font("dejavu", "", font_size)
    col_max_w: list[float] = []
    for c in range(num_cols):
        max_w = 0.0
        for row in rows:
            w = pdf.get_string_width(row[c])
            if w > max_w:
                max_w = w
        col_max_w.append(max(max_w + 2 * CELL_PAD, 12))

    total_w = sum(col_max_w)
    if total_w > usable_w:
        # Scale down proportionally but enforce a minimum
        min_col = 14
        col_widths = [max((w / total_w) * usable_w, min_col) for w in col_max_w]
        # Re-scale so columns sum to exactly usable_w
        scale = usable_w / sum(col_widths)
        col_widths = [w * scale for w in col_widths]
    else:
        # Table fits — distribute extra space proportionally
        scale = usable_w / total_w
        col_widths = [w * scale for w in col_max_w]

    def _break_word(word: str, max_w: float) -> list[str]:
        """Break a single long word into chunks that fit within max_w."""
        pieces: list[str] = []
        buf = ""
        for ch in word:
            test = buf + ch
            if pdf.get_string_width(test) > max_w:
                if buf:
                    pieces.append(buf)
                buf = ch
            else:
                buf = test
        if buf:
            pieces.append(buf)
        return pieces if pieces else [word]

    def _cell_lines(text: str, col_w: float, bold: bool = False) -> list[str]:
        """Word-wrap text to fit within col_w, breaking long words."""
        style = "B" if bold else ""
        pdf.set_font("dejavu", style, font_size)
        inner_w = col_w - 2 * CELL_PAD
        if inner_w < 4:
            inner_w = 4
        words = text.split()
        lines: list[str] = []
        current = ""
        for word in words:
            # If a single word exceeds the inner width, break it
            if pdf.get_string_width(word) > inner_w:
                if current:
                    lines.append(current)
                    current = ""
                for piece in _break_word(word, inner_w):
                    lines.append(piece)
                continue
            test = f"{current} {word}" if current else word
            if pdf.get_string_width(test) <= inner_w:
                current = test
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines if lines else [""]

    row_index = 0  # track row position for zebra striping

    def _draw_row(row: list[str], is_header: bool = False):
        """Draw one table row with proper wrapping and cell borders."""
        nonlocal row_index
        # Calculate how many lines each cell needs
        wrapped = [
            _cell_lines(row[c], col_widths[c], bold=is_header)
            for c in range(num_cols)
        ]
        max_lines = max(len(w) for w in wrapped)
        row_h = max_lines * ROW_HEIGHT + 2  # +2 for padding

        # Check if we need a page break
        if pdf.get_y() + row_h > pdf.h - pdf.b_margin:
            pdf.add_page()

        y_start = pdf.get_y()
        x_start = pdf.l_margin

        # Draw cell backgrounds and borders
        for c in range(num_cols):
            x = x_start + sum(col_widths[:c])
            if is_header:
                pdf.set_fill_color(30, 60, 120)
                pdf.rect(x, y_start, col_widths[c], row_h, "DF")
            else:
                bg = (245, 247, 250) if row_index % 2 == 0 else (255, 255, 255)
                pdf.set_fill_color(*bg)
                pdf.set_draw_color(200, 200, 200)
                pdf.rect(x, y_start, col_widths[c], row_h, "DF")

        # Draw cell text
        for c in range(num_cols):
            x = x_start + sum(col_widths[:c])
            if is_header:
                pdf.set_font("dejavu", "B", font_size)
                pdf.set_text_color(255, 255, 255)
            else:
                pdf.set_font("dejavu", "", font_size)
                pdf.set_text_color(40, 40, 40)

            for li, line_text in enumerate(wrapped[c]):
                pdf.set_xy(x + CELL_PAD, y_start + 1 + li * ROW_HEIGHT)
                pdf.cell(col_widths[c] - 2 * CELL_PAD, ROW_HEIGHT, line_text)

        pdf.set_y(y_start + row_h)
        if not is_header:
            row_index += 1

    # Draw header row
    pdf.set_draw_color(30, 60, 120)
    pdf.set_line_width(0.3)
    pdf.ln(3)
    _draw_row(rows[0], is_header=True)

    # Draw data rows
    pdf.set_line_width(0.2)
    for row in rows[1:]:
        _draw_row(row, is_header=False)

    pdf.ln(4)
    # Reset colors
    pdf.set_text_color(40, 40, 40)
    pdf.set_draw_color(0, 0, 0)


def _render_markdown_to_pdf(pdf, text: str):
    """Parse simple markdown (headings, bullets, bold, tables, body) into FPDF calls."""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            pdf.ln(3)
            i += 1
            continue

        # --- Markdown table detection ---
        if "|" in stripped and stripped.startswith("|"):
            table_rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                row_text = lines[i].strip()
                # Skip separator rows like |---|---|---|
                if re.match(r"^\|[\s\-:|\+]+\|$", row_text):
                    i += 1
                    continue
                cells = [c.strip() for c in row_text.split("|")]
                # Remove empty first/last from leading/trailing pipes
                if cells and cells[0] == "":
                    cells = cells[1:]
                if cells and cells[-1] == "":
                    cells = cells[:-1]
                if cells:
                    table_rows.append(cells)
                i += 1
            if table_rows:
                _render_table(pdf, table_rows)
            continue

        # Heading levels
        if stripped.startswith("### "):
            pdf.set_font("dejavu", "B", 11)
            pdf.set_text_color(50, 50, 50)
            pdf.ln(3)
            pdf.cell(0, 7, stripped[4:].strip(), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        elif stripped.startswith("## "):
            pdf.set_font("dejavu", "B", 13)
            pdf.set_text_color(30, 60, 120)
            pdf.ln(4)
            pdf.cell(0, 8, stripped[3:].strip(), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        elif stripped.startswith("# "):
            pdf.set_font("dejavu", "B", 16)
            pdf.set_text_color(30, 60, 120)
            pdf.ln(5)
            pdf.cell(0, 10, stripped[2:].strip(), new_x="LMARGIN", new_y="NEXT")
            pdf.set_draw_color(30, 60, 120)
            pdf.set_line_width(0.3)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(3)
        elif stripped.startswith(("- ", "* ", "• ")):
            # Bullet point
            pdf.set_font("dejavu", "", 10)
            pdf.set_text_color(40, 40, 40)
            bullet_text = stripped[2:].strip()
            # Strip bold markers
            bullet_text = re.sub(r"\*\*(.*?)\*\*", r"\1", bullet_text)
            pdf.cell(8, 6, chr(8226))  # bullet char
            pdf.multi_cell(0, 6, bullet_text, new_x="LMARGIN", new_y="NEXT")
        elif stripped.startswith("---") or stripped.startswith("==="):
            pdf.set_draw_color(180, 180, 180)
            pdf.set_line_width(0.2)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(3)
        else:
            # Regular paragraph text
            pdf.set_font("dejavu", "", 10)
            pdf.set_text_color(40, 40, 40)
            # Strip bold/italic markers for clean rendering
            clean = re.sub(r"\*\*(.*?)\*\*", r"\1", stripped)
            clean = re.sub(r"\*(.*?)\*", r"\1", clean)
            clean = re.sub(r"`(.*?)`", r"\1", clean)
            pdf.multi_cell(0, 6, clean, new_x="LMARGIN", new_y="NEXT")

        i += 1


def publish_report_to_s3(
    message_id: str,
    report_text: str,
    enrichment_results: dict | None = None,
    attack_graph_path: str | None = None,
) -> str:
    """Build a PDF report with embedded attack graph and upload to S3.

    Key format: reports/<date>/<message_id>.pdf
    Returns the S3 key of the uploaded report.
    """
    now = datetime.now(timezone.utc)
    date_prefix = now.strftime("%Y-%m-%d")
    base_key = f"reports/{date_prefix}/{message_id}"
    bucket = config.REPORT_BUCKET

    # Build the PDF
    pdf_bytes = _build_pdf(report_text, attack_graph_path, message_id)

    # Upload the PDF report
    report_key = f"{base_key}.pdf"
    _get_s3_client().put_object(
        Bucket=bucket,
        Key=report_key,
        Body=pdf_bytes,
        ContentType="application/pdf",
    )
    logger.info("PDF report uploaded → s3://%s/%s", bucket, report_key)

    # Upload the enrichment JSON alongside
    if enrichment_results:
        json_key = f"{base_key}_enrichment.json"
        _get_s3_client().put_object(
            Bucket=bucket,
            Key=json_key,
            Body=json.dumps(enrichment_results, indent=2, default=str).encode("utf-8"),
            ContentType="application/json",
        )
        logger.info("Enrichment JSON → s3://%s/%s", bucket, json_key)

    # Clean up temp graph image
    if attack_graph_path:
        try:
            os.remove(attack_graph_path)
            logger.debug("Cleaned up temp graph image: %s", attack_graph_path)
        except OSError:
            pass

    return report_key


# ---------------------------------------------------------------------------
# Continuous background poller
# ---------------------------------------------------------------------------
_shutdown = False
_processed_ids: set[str] = set()  # simple in-memory dedup guard
_MAX_DEDUP_SIZE = 10_000


def _handle_signal(signum, _frame):
    global _shutdown
    logger.info("Received signal %s — shutting down after current cycle.", signum)
    _shutdown = True


def _write_health(healthy: bool = True):
    """Write a health-check file for container orchestrators (ECS, k8s)."""
    path = os.getenv("HEALTH_FILE", "/tmp/agent_healthy")
    if healthy:
        with open(path, "w") as f:
            f.write(datetime.now(timezone.utc).isoformat())
    else:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def run_continuous(
    poll_interval: int = config.POLL_INTERVAL_SECONDS,
    delete_after: bool = True,
):
    """Poll SQS continuously. For each message: investigate → publish to S3 → delete.

    Args:
        poll_interval: seconds to wait when the queue is empty before retrying.
        delete_after: whether to delete the SQS message after a successful run.
    """
    global _processed_ids
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info(
        "Agent started — polling %s every %ds (delete_after=%s, report_bucket=%s)",
        config.SQS_QUEUE_URL, poll_interval, delete_after, config.REPORT_BUCKET,
    )
    _write_health(True)
    consecutive_errors = 0

    while not _shutdown:
        try:
            result = run_investigation(delete_after=False)

            if result["status"] == "no_message":
                logger.debug("Queue empty — sleeping %ds", poll_interval)
                _write_health(True)
                time.sleep(poll_interval)
                consecutive_errors = 0
                continue

            msg_id = result["message_id"]

            # Deduplication guard
            if msg_id in _processed_ids:
                logger.warning("Duplicate message %s — skipping", msg_id)
                if delete_after:
                    mcp_client.call_tool("delete_sqs_message", {
                        "queue_url": config.SQS_QUEUE_URL,
                        "receipt_handle": result["receipt_handle"],
                    })
                continue

            logger.info("Processed message %s — uploading report", msg_id)

            report_key = publish_report_to_s3(
                message_id=msg_id,
                report_text=result["incident_report"],
                enrichment_results=result.get("enrichment_results"),
                attack_graph_path=result.get("attack_graph_path"),
            )
            logger.info("Report published → %s", report_key)

            if delete_after:
                mcp_client.call_tool("delete_sqs_message", {
                    "queue_url": config.SQS_QUEUE_URL,
                    "receipt_handle": result["receipt_handle"],
                })
                logger.info("SQS message %s deleted", msg_id)

            # Track processed id
            _processed_ids.add(msg_id)
            if len(_processed_ids) > _MAX_DEDUP_SIZE:
                _processed_ids = set(list(_processed_ids)[-(_MAX_DEDUP_SIZE // 2):])

            _write_health(True)
            consecutive_errors = 0

        except Exception:
            consecutive_errors += 1
            backoff = min(poll_interval * (config.RETRY_BACKOFF_BASE ** consecutive_errors), 300)
            logger.exception(
                "Error during investigation cycle (consecutive=%d) — retrying in %.0fs",
                consecutive_errors, backoff,
            )
            _write_health(consecutive_errors < 5)
            time.sleep(backoff)

    _write_health(False)
    mcp_client.shutdown()
    logger.info("Agent stopped.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    from dotenv import load_dotenv

    load_dotenv()

    # Reload config values that depend on .env (config reads os.environ at
    # import time, which is before load_dotenv runs in __main__).
    import importlib
    importlib.reload(config)

    if not config.OPENAI_API_KEY:
        raise SystemExit("Set OPENAI_API_KEY in .env or environment first.")

    _setup_logging()

    parser = argparse.ArgumentParser(description="AWS Security Investigation Agent")
    parser.add_argument(
        "--mode",
        choices=["once", "continuous"],
        default="once",
        help="'once' processes one message; 'continuous' polls forever (default: once)",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=30,
        help="Seconds between polls when queue is empty (default: 30)",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete SQS message after successful processing",
    )
    args = parser.parse_args()

    if args.mode == "continuous":
        run_continuous(poll_interval=args.poll_interval, delete_after=args.delete)
    else:
        result = run_investigation(delete_after=args.delete)
        print(f"\nStatus: {result['status']}")
        if result["status"] == "processed":
            msg_id = result["message_id"]
            print(f"Message ID: {msg_id}")
            report_key = publish_report_to_s3(
                message_id=msg_id,
                report_text=result["incident_report"],
                enrichment_results=result.get("enrichment_results"),
                attack_graph_path=result.get("attack_graph_path"),
            )
            print(f"Report uploaded → s3://{config.REPORT_BUCKET}/{report_key}")
            if args.delete:
                mcp_client.call_tool("delete_sqs_message", {
                    "queue_url": config.SQS_QUEUE_URL,
                    "receipt_handle": result["receipt_handle"],
                })
                print(f"SQS message {msg_id} deleted")
            print(f"\n{'='*60}")
            print("INCIDENT REPORT")
            print(f"{'='*60}\n")
            print(result["incident_report"])
        mcp_client.shutdown()

# to Run the agent: `python agent.py --mode continuous --delete`