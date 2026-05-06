"""
MCP Server — AWS Security Log Retrieval Tools

Exposes tools for retrieving and enriching security logs from:
  - Amazon SQS  (alert ingestion)
  - AWS CloudTrail  (API activity)
  - AWS IAM  (identity context)
  - Amazon S3  (bucket security posture)
  - Attack graph construction  (NetworkX + Matplotlib visualization)

Each tool carries a rich description so that the LangGraph agent can
autonomously decide which tools to invoke and with what arguments.
"""

import json
import logging
import re
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError
from mcp.server.fastmcp import FastMCP

import config

logger = logging.getLogger(__name__)

_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")

# ---------------------------------------------------------------------------
# AWS clients (with retry config)
# ---------------------------------------------------------------------------

_boto_cfg = BotoConfig(
    region_name=config.AWS_REGION,
    retries={"max_attempts": config.MAX_RETRIES, "mode": "adaptive"},
    read_timeout=30,
    connect_timeout=10,
)

sqs_client = boto3.client("sqs", config=_boto_cfg)
cloudtrail_client = boto3.client("cloudtrail", config=_boto_cfg)
iam_client = boto3.client("iam", config=_boto_cfg)
s3_client = boto3.client("s3", config=_boto_cfg)

# ---------------------------------------------------------------------------
# MCP app
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "aws-security-log-tools",
    instructions=(
        "MCP server that provides tools for retrieving AWS security logs "
        "from SQS, CloudTrail, IAM, and S3. Designed for agentic incident "
        "investigation workflows."
    ),
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_to_dt(value: str) -> datetime:
    """Parse an ISO-8601 string (with or without trailing Z) into an
    aware datetime in UTC."""
    if not value:
        raise ValueError("Datetime string cannot be empty")
    value = value.strip()
    if value.endswith("Z"):
        value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Tool 1 — SQS: read one message
# ---------------------------------------------------------------------------
@mcp.tool()
def read_sqs_message(
    queue_url: str = config.SQS_QUEUE_URL,
    wait_time_seconds: int = 10,
    visibility_timeout: int = 60,
) -> dict:
    """Read a single message from an Amazon SQS queue.

    **When to use**: Call this tool first to ingest the next security alert
    from the aggregated-events queue. The returned message body contains
    session events, pivot fields (sourceIP, accessKeyId, userName, bucket,
    firstSeen, lastSeen), and metadata needed by downstream enrichment tools.

    Inputs:
      - queue_url (str): Full SQS queue URL.
        Default: the decoy-events-aggregated queue.
      - wait_time_seconds (int): Long-poll wait in seconds (1-20). Default 10.
      - visibility_timeout (int): Seconds the message stays invisible to
        other consumers. Default 60.

    Outputs (dict):
      - message_id (str): Unique SQS message identifier.
      - receipt_handle (str): Handle required to delete the message later.
      - body (dict|str): Parsed JSON body of the message (or raw string).
      - attributes (dict): SQS system attributes (sent timestamp, etc.).
      - message_attributes (dict): Custom message attributes.
      - Returns {"status": "empty"} when the queue has no messages.
    """
    response = sqs_client.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=1,
        WaitTimeSeconds=wait_time_seconds,
        VisibilityTimeout=visibility_timeout,
        AttributeNames=["All"],
        MessageAttributeNames=["All"],
    )
    messages = response.get("Messages", [])
    if not messages:
        logger.debug("No messages available in %s", queue_url)
        return {"status": "empty", "message": "No messages in queue"}

    msg = messages[0]
    try:
        body = json.loads(msg["Body"])
    except (json.JSONDecodeError, TypeError):
        logger.warning("SQS message body is not valid JSON, using raw string")
        body = msg["Body"]

    logger.info("Read SQS message %s", msg.get("MessageId"))
    return {
        "message_id": msg.get("MessageId"),
        "receipt_handle": msg.get("ReceiptHandle"),
        "body": body,
        "attributes": msg.get("Attributes", {}),
        "message_attributes": msg.get("MessageAttributes", {}),
    }


# ---------------------------------------------------------------------------
# Tool 2 — SQS: delete message
# ---------------------------------------------------------------------------
@mcp.tool()
def delete_sqs_message(queue_url: str, receipt_handle: str) -> dict:
    """Delete a processed message from an SQS queue.

    **When to use**: Call this after the investigation pipeline has
    successfully processed and reported on a message, so it is not
    re-delivered.

    Inputs:
      - queue_url (str): Full SQS queue URL.
      - receipt_handle (str): The receipt handle returned by read_sqs_message.

    Outputs (dict):
      - deleted (bool): True if deletion succeeded.
    """
    sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
    logger.info("Deleted SQS message (receipt_handle=%s…)", receipt_handle[:20])
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Tool 3 — CloudTrail: query events
# ---------------------------------------------------------------------------
@mcp.tool()
def query_cloudtrail(
    start_time: str,
    end_time: str,
    source_ip: str | None = None,
    access_key_id: str | None = None,
    username: str | None = None,
    max_results: int = 20,
) -> dict:
    """Query AWS CloudTrail for API activity within a time window.

    **When to use**: After extracting pivots (sourceIP, accessKeyId,
    userName) and a time window from the SQS message body, call this tool
    to retrieve correlated CloudTrail events for timeline enrichment.

    Inputs:
      - start_time (str): ISO-8601 start of the window (e.g. "2025-04-01T12:00:00Z").
      - end_time (str): ISO-8601 end of the window.
      - source_ip (str, optional): Filter events originating from this IP.
      - access_key_id (str, optional): Filter by AWS access key.
      - username (str, optional): Filter by IAM username.
      - max_results (int): Maximum events to return. Default 20.

    At least one of source_ip, access_key_id, or username MUST be provided.

    Outputs (dict):
      - source (str): Always "cloudtrail".
      - event_count (int): Number of events returned.
      - events (list[dict]): Each event contains EventTime, EventName,
        Username, EventId, Resources, and the raw CloudTrailEvent JSON.
      - error (str, optional): Present only when an AWS error occurs.
    """
    if not any([source_ip, access_key_id, username]):
        return {
            "source": "cloudtrail",
            "event_count": 0,
            "events": [],
            "error": "At least one of source_ip, access_key_id, or username is required.",
        }

    start_dt = _iso_to_dt(start_time)
    end_dt = _iso_to_dt(end_time)

    lookup_attrs = []
    if username:
        lookup_attrs.append({"AttributeKey": "Username", "AttributeValue": username})
    if access_key_id:
        lookup_attrs.append({"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id})

    events: list[dict] = []
    seen_ids: set[str] = set()

    try:
        if lookup_attrs:
            for attr in lookup_attrs:
                next_token = None
                while True:
                    params = {
                        "LookupAttributes": [attr],
                        "StartTime": start_dt,
                        "EndTime": end_dt,
                        "MaxResults": min(max_results, 50),
                    }
                    if next_token:
                        params["NextToken"] = next_token
                    resp = cloudtrail_client.lookup_events(**params)
                    for ev in resp.get("Events", []):
                        eid = ev.get("EventId")
                        if eid not in seen_ids:
                            seen_ids.add(eid)
                            events.append(ev)
                    next_token = resp.get("NextToken")
                    if not next_token or len(events) >= max_results:
                        break
        else:
            next_token = None
            while True:
                params = {
                    "StartTime": start_dt,
                    "EndTime": end_dt,
                    "MaxResults": min(max_results, 50),
                }
                if next_token:
                    params["NextToken"] = next_token
                resp = cloudtrail_client.lookup_events(**params)
                for ev in resp.get("Events", []):
                    eid = ev.get("EventId")
                    if eid not in seen_ids:
                        seen_ids.add(eid)
                        events.append(ev)
                next_token = resp.get("NextToken")
                if not next_token or len(events) >= max_results:
                    break

        if source_ip:
            events = [e for e in events if source_ip in e.get("CloudTrailEvent", "")]

        trimmed = events[:max_results]
        return {
            "source": "cloudtrail",
            "event_count": len(trimmed),
            "events": trimmed,
        }
    except (ClientError, BotoCoreError) as exc:
        return {
            "source": "cloudtrail",
            "event_count": 0,
            "events": [],
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Tool 4 — IAM: identity context
# ---------------------------------------------------------------------------
@mcp.tool()
def query_identity_context(
    username: str | None = None,
    role_name: str | None = None,
    access_key_id: str | None = None,
) -> dict:
    """Retrieve IAM identity context for a user and/or role.

    **When to use**: After extracting the userName / roleName / accessKeyId
    pivots from the SQS body, call this tool to get identity metadata
    for the incident report (user ARN, creation date, role trust policy,
    access-key match confirmation).

    This tool can run in **parallel** with query_cloudtrail and
    query_s3_security_context because its inputs are independent.

    Inputs:
      - username (str, optional): IAM username to look up.
      - role_name (str, optional): IAM role name to look up.
      - access_key_id (str, optional): If provided together with username,
        verifies whether this key belongs to the user.

    Outputs (dict):
      - source (str): Always "identity_context".
      - user (dict|None): IAM user record or an error/not-found message.
      - role (dict|None): IAM role record or an error/not-found message.
      - access_key_matches (list[dict]): Matching access-key metadata entries.
    """
    result: dict = {
        "source": "identity_context",
        "user": None,
        "role": None,
        "access_key_matches": [],
    }

    if username:
        try:
            resp = iam_client.get_user(UserName=username)
            result["user"] = resp.get("User", {})
        except iam_client.exceptions.NoSuchEntityException:
            result["user"] = {"message": f"user '{username}' not found"}
        except (ClientError, BotoCoreError) as exc:
            result["user"] = {"error": str(exc)}

    if role_name:
        try:
            resp = iam_client.get_role(RoleName=role_name)
            result["role"] = resp.get("Role", {})
        except iam_client.exceptions.NoSuchEntityException:
            result["role"] = {"message": f"role '{role_name}' not found"}
        except (ClientError, BotoCoreError) as exc:
            result["role"] = {"error": str(exc)}

    if username and access_key_id:
        try:
            keys = iam_client.list_access_keys(UserName=username).get(
                "AccessKeyMetadata", []
            )
            result["access_key_matches"] = [
                k for k in keys if k.get("AccessKeyId") == access_key_id
            ]
        except iam_client.exceptions.NoSuchEntityException:
            result["access_key_matches"] = []
        except (ClientError, BotoCoreError) as exc:
            result["access_key_matches"] = [{"error": str(exc)}]

    return result


# ---------------------------------------------------------------------------
# Tool 5 — S3: bucket security context
# ---------------------------------------------------------------------------
@mcp.tool()
def query_s3_security_context(bucket_name: str) -> dict:
    """Retrieve the security posture of an S3 bucket.

    **When to use**: When the SQS alert references a bucket name, call this
    tool to determine whether the bucket is publicly accessible, has
    versioning enabled, and what its policy status is.

    This tool can run in **parallel** with query_cloudtrail and
    query_identity_context.

    Inputs:
      - bucket_name (str): The name of the S3 bucket to inspect.

    Outputs (dict):
      - source (str): Always "s3_security_context".
      - bucket_name (str): Echo of the input.
      - bucket_policy_status (dict|None): Whether the bucket policy allows
        public access (IsPublic flag).
      - public_access_block (dict|None): The PublicAccessBlock configuration
        (BlockPublicAcls, etc.).
      - bucket_versioning (dict|None): Versioning status (Enabled/Suspended).
    """
    result: dict = {
        "source": "s3_security_context",
        "bucket_name": bucket_name,
        "bucket_policy_status": None,
        "public_access_block": None,
        "bucket_versioning": None,
    }
    if not bucket_name:
        result["error"] = "bucket_name not provided"
        return result

    if not _BUCKET_NAME_RE.match(bucket_name):
        result["error"] = "invalid bucket_name format"
        return result

    try:
        ps = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        result["bucket_policy_status"] = ps.get("PolicyStatus", {})
    except (ClientError, BotoCoreError) as exc:
        result["bucket_policy_status"] = {"error": str(exc)}

    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        result["public_access_block"] = pab.get("PublicAccessBlockConfiguration", {})
    except (ClientError, BotoCoreError) as exc:
        result["public_access_block"] = {"error": str(exc)}

    try:
        ver = s3_client.get_bucket_versioning(Bucket=bucket_name)
        ver.pop("ResponseMetadata", None)
        result["bucket_versioning"] = ver
    except (ClientError, BotoCoreError) as exc:
        result["bucket_versioning"] = {"error": str(exc)}

    return result


# ---------------------------------------------------------------------------
# Tool 6 — Pivot extractor (pure logic, no AWS call)
# ---------------------------------------------------------------------------
@mcp.tool()
def extract_pivots(sqs_body: dict) -> dict:
    """Extract investigation pivot fields from an SQS message body.

    **When to use**: Immediately after reading an SQS message. The returned
    pivots (sourceIP, accessKeyId, userName, roleName, bucketName, time
    window) are used as inputs for the enrichment tools.

    Inputs:
      - sqs_body (dict): The parsed body of an SQS message.

    Outputs (dict):
      - source_ip (str|None)
      - access_key_id (str|None)
      - username (str|None)
      - role_name (str|None)
      - bucket_name (str|None)
      - start_time (str|None): ISO-8601 firstSeen.
      - end_time (str|None): ISO-8601 lastSeen.
    """
    summary = sqs_body.get("summary", {}) if isinstance(sqs_body, dict) else {}
    return {
        "source_ip": (
            summary.get("sourceIP")
            or summary.get("sourceIp")
            or sqs_body.get("sourceIP")
            or sqs_body.get("sourceIp")
        ),
        "access_key_id": summary.get("accessKeyId") or sqs_body.get("accessKeyId"),
        "username": (
            summary.get("userName")
            or summary.get("username")
            or sqs_body.get("userName")
            or sqs_body.get("username")
        ),
        "role_name": summary.get("roleName") or sqs_body.get("roleName"),
        "bucket_name": (
            summary.get("bucket")
            or summary.get("bucketName")
            or sqs_body.get("bucket")
            or sqs_body.get("bucketName")
        ),
        "start_time": sqs_body.get("firstSeen"),
        "end_time": sqs_body.get("lastSeen"),
    }


# ---------------------------------------------------------------------------
# Tool 7 — Expand time window (pure logic)
# ---------------------------------------------------------------------------
@mcp.tool()
def expand_time_window(
    start_time: str,
    end_time: str,
    lookback_minutes: int = 15,
    forward_minutes: int = 15,
) -> dict:
    """Widen a time window for CloudTrail lookups.

    **When to use**: Before calling query_cloudtrail, expand the alert's
    firstSeen/lastSeen window so that pre- and post-attack activity is
    captured.

    Inputs:
      - start_time (str): ISO-8601 original start.
      - end_time (str): ISO-8601 original end.
      - lookback_minutes (int): Minutes to subtract from start. Default 15.
      - forward_minutes (int): Minutes to add to end. Default 15.

    Outputs (dict):
      - start_time (str): Expanded ISO-8601 start.
      - end_time (str): Expanded ISO-8601 end.
    """
    start_dt = _iso_to_dt(start_time) - timedelta(minutes=lookback_minutes)
    end_dt = _iso_to_dt(end_time) + timedelta(minutes=forward_minutes)
    return {
        "start_time": start_dt.isoformat().replace("+00:00", "Z"),
        "end_time": end_dt.isoformat().replace("+00:00", "Z"),
    }


# ---------------------------------------------------------------------------
# Tool 8 — Attack graph construction (NetworkX + Matplotlib)
# ---------------------------------------------------------------------------

# Node‑type styling
_NODE_STYLES = {
    "user":       {"color": "#4A90D9", "shape": "s", "label_prefix": "User: "},
    "ip":         {"color": "#D94A4A", "shape": "o", "label_prefix": "IP: "},
    "resource":   {"color": "#4AD97A", "shape": "D", "label_prefix": "S3: "},
    "role":       {"color": "#D9A04A", "shape": "^", "label_prefix": "Role: "},
    "access_key": {"color": "#9B59B6", "shape": "p", "label_prefix": "Key: "},
}


def _extract_graph_elements(enrichment_data: dict) -> tuple[list[dict], list[dict]]:
    """Deterministically extract nodes and edges from enrichment JSON.

    Handles multiple key casings that the consolidation LLM may produce
    (e.g. userName vs username vs UserName) and extracts entities from
    all available enrichment sections.
    """
    nodes: dict[str, dict] = {}  # id -> {id, label, type}
    edges: list[dict] = []
    seen_edges: set[tuple[str, str, str]] = set()

    # The consolidation LLM may use the full tool name or a shortened
    # alias as the top-level key.  Try all known variants.
    def _section(d: dict, *keys) -> dict:
        for k in keys:
            v = d.get(k)
            if isinstance(v, dict):
                return v
        return {}

    pivots = _section(enrichment_data, "pivots", "extract_pivots")
    identity = _section(
        enrichment_data,
        "identity_context", "query_identity_context", "identityContext",
        "identity", "iam_context", "iam",
    )
    s3_ctx = _section(
        enrichment_data,
        "s3_context", "query_s3_security_context", "s3_security_context",
        "s3Context", "s3",
    )
    ct = _section(
        enrichment_data,
        "cloudtrail", "query_cloudtrail", "cloudTrail", "cloud_trail",
    )

    # --- Helper: case-insensitive field getter ---
    def _get(d: dict, *keys, default=None):
        """Try multiple key names, return first non-empty value."""
        if not isinstance(d, dict):
            return default
        for k in keys:
            v = d.get(k)
            if v:
                return v
        return default

    # --- Build nodes from pivots ---
    source_ip = _get(pivots, "source_ip", "sourceIP", "sourceIPAddress", "sourceIp", "ip")
    username = _get(pivots, "username", "userName", "UserName", "user_name", "user")
    access_key = _get(pivots, "access_key_id", "accessKeyId", "AccessKeyId", "access_key")
    role_name = _get(pivots, "role_name", "roleName", "RoleName", "role")
    bucket_name = (
        _get(pivots, "bucket_name", "bucketName", "BucketName", "bucket")
        or _get(s3_ctx, "bucket_name", "bucketName", "BucketName", "bucket")
    )

    def _add_node(nid: str, label: str, ntype: str):
        nodes.setdefault(nid, {"id": nid, "label": label, "type": ntype})

    def _add_edge(src: str, dst: str, label: str):
        key = (src, dst, label)
        if key not in seen_edges and src in nodes and dst in nodes:
            seen_edges.add(key)
            edges.append({"source": src, "target": dst, "label": label})

    if source_ip:
        _add_node(f"ip:{source_ip}", source_ip, "ip")
    if username:
        _add_node(f"user:{username}", username, "user")
    if access_key:
        short_key = access_key[:16] + "…" if len(access_key) > 16 else access_key
        _add_node(f"key:{access_key}", short_key, "access_key")
    if role_name:
        _add_node(f"role:{role_name}", role_name, "role")
    if bucket_name:
        _add_node(f"s3:{bucket_name}", bucket_name, "resource")

    # --- Build nodes from identity_context ---
    user_info = identity.get("user")
    if isinstance(user_info, dict):
        uname = _get(user_info, "UserName", "userName", "username", "user_name")
        if uname:
            _add_node(f"user:{uname}", uname, "user")
            if not username:
                username = uname
        # Extract access keys listed under the user
        user_keys = user_info.get("AccessKeys") or user_info.get("access_keys") or []
        for uk in user_keys:
            kid = _get(uk, "AccessKeyId", "accessKeyId", "access_key_id")
            if kid:
                short = kid[:16] + "…" if len(kid) > 16 else kid
                _add_node(f"key:{kid}", short, "access_key")
                if username:
                    _add_edge(f"user:{username}", f"key:{kid}", "owns")
    elif isinstance(user_info, str) and user_info:
        _add_node(f"user:{user_info}", user_info, "user")
        if not username:
            username = user_info

    role_info = identity.get("role")
    if isinstance(role_info, dict):
        rname = _get(role_info, "RoleName", "roleName", "role_name")
        if rname:
            _add_node(f"role:{rname}", rname, "role")
            if not role_name:
                role_name = rname
    elif isinstance(role_info, str) and role_info:
        _add_node(f"role:{role_info}", role_info, "role")
        if not role_name:
            role_name = role_info

    # Access key verification from identity context
    ak_match = identity.get("access_key_matches") or identity.get("accessKeyMatches")
    if isinstance(ak_match, bool) and ak_match and access_key and username:
        _add_edge(f"user:{username}", f"key:{access_key}", "owns (verified)")

    # --- Build structural edges from pivots ---
    if source_ip and username:
        _add_edge(f"ip:{source_ip}", f"user:{username}", "authenticated as")
    if username and access_key:
        _add_edge(f"user:{username}", f"key:{access_key}", "owns")
    if username and role_name:
        _add_edge(f"user:{username}", f"role:{role_name}", "assumed")

    # Fallback edges when username is missing — connect IP/key/bucket directly
    if not username:
        if source_ip and access_key:
            _add_edge(f"ip:{source_ip}", f"key:{access_key}", "used key")
        if source_ip and bucket_name:
            _add_edge(f"ip:{source_ip}", f"s3:{bucket_name}", "accessed")
        if access_key and bucket_name:
            _add_edge(f"key:{access_key}", f"s3:{bucket_name}", "accessed")
        if source_ip and role_name:
            _add_edge(f"ip:{source_ip}", f"role:{role_name}", "assumed")
        if access_key and role_name:
            _add_edge(f"key:{access_key}", f"role:{role_name}", "assumed")

    # --- Build edges from CloudTrail events ---
    # The events list may be under "events", "Events", or ct itself may be a list
    ct_events = (
        ct.get("events")
        or ct.get("Events")
        or ct.get("records")
        or (ct if isinstance(ct, list) else [])
    )
    if not isinstance(ct_events, list):
        ct_events = []
    for event in ct_events:
        event_name = _get(event, "EventName", "eventName", "event_name") or "unknown"
        actor_user = _get(event, "Username", "username", "userName", "user_name")

        # Try to extract fields from raw CloudTrailEvent JSON
        ct_raw = _get(event, "CloudTrailEvent", "cloudTrailEvent")
        event_source_ip = _get(event, "sourceIPAddress", "sourceIp", "source_ip")
        event_access_key = None
        event_bucket = None

        if ct_raw:
            ct_detail = ct_raw
            if isinstance(ct_raw, str):
                try:
                    ct_detail = json.loads(ct_raw)
                except (json.JSONDecodeError, AttributeError):
                    ct_detail = {}

            if isinstance(ct_detail, dict):
                if not event_source_ip:
                    event_source_ip = ct_detail.get("sourceIPAddress")

                # Extract actor from userIdentity
                if not actor_user:
                    ui = ct_detail.get("userIdentity", {})
                    actor_user = _get(ui, "userName", "UserName", "username")
                    if not actor_user:
                        # Try the ARN for a display name
                        arn = ui.get("arn", "")
                        if "/" in arn:
                            actor_user = arn.rsplit("/", 1)[-1]

                # Extract access key used
                event_access_key = _get(
                    ct_detail.get("userIdentity", {}),
                    "accessKeyId", "AccessKeyId", "access_key_id",
                )

                # Extract bucket from requestParameters
                req_params = ct_detail.get("requestParameters", {})
                if isinstance(req_params, dict):
                    event_bucket = _get(req_params, "bucketName", "bucket", "BucketName")

        # Create source IP node from event if needed
        if event_source_ip:
            _add_node(f"ip:{event_source_ip}", event_source_ip, "ip")
            if not source_ip:
                source_ip = event_source_ip

        # Create access key node from event if needed
        if event_access_key:
            short = event_access_key[:16] + "…" if len(event_access_key) > 16 else event_access_key
            _add_node(f"key:{event_access_key}", short, "access_key")
            if not access_key:
                access_key = event_access_key

        # Create bucket node from event requestParameters
        if event_bucket:
            _add_node(f"s3:{event_bucket}", event_bucket, "resource")

        # Determine actor node — create on-the-fly if needed
        actor_id = None
        if actor_user:
            actor_id = f"user:{actor_user}"
            _add_node(actor_id, actor_user, "user")
            if not username:
                username = actor_user
            # IP → User edge
            if event_source_ip:
                _add_edge(f"ip:{event_source_ip}", actor_id, "authenticated as")
            elif source_ip:
                _add_edge(f"ip:{source_ip}", actor_id, "authenticated as")
            # User → Access Key edge
            if event_access_key:
                _add_edge(actor_id, f"key:{event_access_key}", "used key")
        elif source_ip and f"ip:{source_ip}" in nodes:
            actor_id = f"ip:{source_ip}"
            # No user — link IP to access key directly
            if event_access_key:
                _add_edge(actor_id, f"key:{event_access_key}", "used key")
        elif event_source_ip and f"ip:{event_source_ip}" in nodes:
            actor_id = f"ip:{event_source_ip}"
            if event_access_key:
                _add_edge(actor_id, f"key:{event_access_key}", "used key")

        if not actor_id:
            continue

        # Determine targets from Resources array
        resources = _get(event, "Resources", "resources") or []
        target_found = False
        if resources:
            for res in resources:
                if not isinstance(res, dict):
                    continue
                res_name = _get(res, "ResourceName", "resourceName", "resource_name") or ""
                res_type = (_get(res, "ResourceType", "resourceType", "resource_type") or "").lower()
                if not res_name:
                    continue
                if "bucket" in res_type or "s3" in res_type or "object" in res_type:
                    _add_node(f"s3:{res_name}", res_name, "resource")
                    _add_edge(actor_id, f"s3:{res_name}", event_name)
                    target_found = True
                elif "role" in res_type or "iam" in res_type:
                    _add_node(f"role:{res_name}", res_name, "role")
                    _add_edge(actor_id, f"role:{res_name}", event_name)
                    target_found = True
                elif "key" in res_type or "accesskey" in res_type:
                    short = res_name[:16] + "…" if len(res_name) > 16 else res_name
                    _add_node(f"key:{res_name}", short, "access_key")
                    _add_edge(actor_id, f"key:{res_name}", event_name)
                    target_found = True
                else:
                    _add_node(f"resource:{res_name}", res_name, "resource")
                    _add_edge(actor_id, f"resource:{res_name}", event_name)
                    target_found = True

        # Fallback: infer target from event name and known entities
        if not target_found:
            en_lower = event_name.lower()
            # S3-related events → link to bucket
            if event_bucket:
                _add_edge(actor_id, f"s3:{event_bucket}", event_name)
            elif bucket_name and any(kw in en_lower for kw in (
                "s3", "bucket", "object", "get", "put", "delete", "list", "head",
                "getbucket", "putbucket", "listobject", "headbucket",
                "getobject", "putobject", "deleteobject",
            )):
                _add_edge(actor_id, f"s3:{bucket_name}", event_name)
            elif role_name and any(kw in en_lower for kw in ("role", "assume", "sts")):
                _add_edge(actor_id, f"role:{role_name}", event_name)

    # --- Build edges from SQS sessionEvents (primary alert source) ---
    # These events come directly from the DynamoDB DecoySessionEvents table
    # and may contain events not returned by the CloudTrail enrichment query.
    sqs_events = enrichment_data.get("session_events", [])
    if not isinstance(sqs_events, list):
        sqs_events = []
    for sqs_ev in sqs_events:
        if not isinstance(sqs_ev, dict):
            continue
        ev_name = _get(sqs_ev, "eventName", "EventName", "event_name")
        if not ev_name:
            continue

        # Identify the actor
        ev_user = _get(sqs_ev, "userName", "username", "UserName", "user_name")
        ev_ip = _get(sqs_ev, "sourceIPAddress", "sourceIp", "source_ip")
        ev_key = _get(sqs_ev, "accessKeyId", "AccessKeyId", "access_key_id")
        ev_bucket = _get(sqs_ev, "bucketName", "BucketName", "bucket_name")

        # Create nodes as needed
        if ev_user:
            _add_node(f"user:{ev_user}", ev_user, "user")
        if ev_ip:
            _add_node(f"ip:{ev_ip}", ev_ip, "ip")
        if ev_key:
            short = ev_key[:16] + "…" if len(ev_key) > 16 else ev_key
            _add_node(f"key:{ev_key}", short, "access_key")
        if ev_bucket:
            _add_node(f"s3:{ev_bucket}", ev_bucket, "resource")

        # Determine actor
        sqs_actor_id = None
        if ev_user:
            sqs_actor_id = f"user:{ev_user}"
            if ev_ip:
                _add_edge(f"ip:{ev_ip}", sqs_actor_id, "authenticated as")
            if ev_key:
                _add_edge(sqs_actor_id, f"key:{ev_key}", "used key")
        elif ev_ip:
            sqs_actor_id = f"ip:{ev_ip}"
            if ev_key:
                _add_edge(sqs_actor_id, f"key:{ev_key}", "used key")
        elif ev_key:
            sqs_actor_id = f"key:{ev_key}"

        if not sqs_actor_id:
            continue

        # Create edge to bucket target
        if ev_bucket:
            _add_edge(sqs_actor_id, f"s3:{ev_bucket}", ev_name)
        elif bucket_name:
            _add_edge(sqs_actor_id, f"s3:{bucket_name}", ev_name)

    return list(nodes.values()), edges


@mcp.tool()
def build_attack_graph(enrichment_data: dict, output_path: str = "/tmp/attack_graph.png") -> dict:
    """Build a directed attack graph from enrichment data and render it as PNG.

    **When to use**: After consolidation, call this tool with the full
    enrichment JSON to produce a visual graph of the attack. The graph
    shows entities (users, IPs, resources, roles, access keys) as nodes
    and actions/relationships as edges.

    Inputs:
      - enrichment_data (dict): The consolidated enrichment JSON with keys
        'pivots', 'cloudtrail', 'identity_context', 's3_context'.
      - output_path (str): File path for the rendered PNG image.
        Default: /tmp/attack_graph.png

    Outputs (dict):
      - graph_path (str): Path to the rendered PNG file.
      - node_count (int): Number of nodes in the graph.
      - edge_count (int): Number of edges in the graph.
      - nodes (list[dict]): Node definitions [{id, label, type}, ...].
      - edges (list[dict]): Edge definitions [{source, target, label}, ...].
    """
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import networkx as nx

    nodes, edges = _extract_graph_elements(enrichment_data)

    G = nx.DiGraph()

    # Add nodes
    for node in nodes:
        G.add_node(node["id"], label=node["label"], node_type=node["type"])

    # Add edges
    for edge in edges:
        if G.has_edge(edge["source"], edge["target"]):
            # Merge labels for parallel edges
            existing = G[edge["source"]][edge["target"]].get("label", "")
            if edge["label"] not in existing:
                G[edge["source"]][edge["target"]]["label"] = existing + "\n" + edge["label"]
        else:
            G.add_edge(edge["source"], edge["target"], label=edge["label"])

    # --- Render ---
    fig, ax = plt.subplots(1, 1, figsize=(14, 10))
    fig.patch.set_facecolor("#FAFAFA")
    ax.set_facecolor("#FAFAFA")

    if len(G.nodes) == 0:
        ax.text(0.5, 0.5, "No entities found in enrichment data",
                ha="center", va="center", fontsize=14, color="#888")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
    else:
        # Layout
        if len(G.nodes) <= 6:
            pos = nx.shell_layout(G)
        else:
            pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)

        # Draw nodes by type
        for ntype, style in _NODE_STYLES.items():
            type_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == ntype]
            if type_nodes:
                nx.draw_networkx_nodes(
                    G, pos, nodelist=type_nodes,
                    node_color=style["color"], node_size=3500,
                    alpha=0.9, ax=ax,
                )

        # Draw edges
        nx.draw_networkx_edges(
            G, pos, edge_color="#555555", arrows=True,
            arrowsize=20, arrowstyle="-|>",
            connectionstyle="arc3,rad=0.1", ax=ax, width=1.5,
        )

        # Node labels
        node_labels = {n: d.get("label", n) for n, d in G.nodes(data=True)}
        nx.draw_networkx_labels(G, pos, labels=node_labels,
                                font_size=13, font_weight="bold", ax=ax)

        # Edge labels
        edge_labels = nx.get_edge_attributes(G, "label")
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels,
                                     font_size=12, font_color="#333", ax=ax)

        # Legend
        legend_patches = []
        for ntype, style in _NODE_STYLES.items():
            type_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == ntype]
            if type_nodes:
                legend_patches.append(
                    mpatches.Patch(color=style["color"], label=ntype.replace("_", " ").title())
                )
        if legend_patches:
            ax.legend(handles=legend_patches, loc="upper left", fontsize=12,
                      framealpha=0.9, fancybox=True)

    ax.set_title("Attack Graph — Entity Relationships & Actions",
                 fontsize=18, fontweight="bold", pad=20)
    ax.axis("off")
    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)

    logger.info("Attack graph rendered → %s (%d nodes, %d edges)",
                output_path, len(nodes), len(edges))

    return {
        "graph_path": output_path,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="stdio")
