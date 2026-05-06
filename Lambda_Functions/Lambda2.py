import json
import os
import boto3
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from boto3.dynamodb.conditions import Key

ddb = boto3.resource("dynamodb", region_name="us-east-2")
ct = boto3.client("cloudtrail", region_name="us-east-2")
sqs = boto3.client("sqs", region_name="us-east-2")

SESSIONS_TABLE = os.environ["SESSIONS_TABLE"]
EVENTS_TABLE = os.environ["EVENTS_TABLE"]
QUEUE_URL = os.environ["SQS_QUEUE_URL"]
INACTIVITY_SECONDS = int(os.environ.get("INACTIVITY_SECONDS", "120"))
ENABLE_CLOUDTRAIL_ENRICHMENT = os.environ.get("ENABLE_CLOUDTRAIL_ENRICHMENT", "true").lower() == "true"
CLOUDTRAIL_LOOKBACK_MINUTES = int(os.environ.get("CLOUDTRAIL_LOOKBACK_MINUTES", "15"))
CLOUDTRAIL_FORWARD_MINUTES = int(os.environ.get("CLOUDTRAIL_FORWARD_MINUTES", "2"))
MAX_CLOUDTRAIL_EVENTS = int(os.environ.get("MAX_CLOUDTRAIL_EVENTS", "50"))

sessions_table = ddb.Table(SESSIONS_TABLE)
events_table = ddb.Table(EVENTS_TABLE)

ATTACK_EVENTS = {
    "HeadBucket",
    "HeadObject",
    "ListBucket",
    "ListBuckets",
    "ListObjectsV2",
    "ListObjectVersions",
    "ListObjects",
    "GetObject",
    "PutObject",
    "DeleteObject",
    "CopyObject"
}


def parse_iso_z(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def to_native(obj):
    if isinstance(obj, list):
        return [to_native(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_native(v) for k, v in obj.items()}
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    return obj


def safe_json_loads(s: str):
    try:
        return json.loads(s)
    except Exception:
        return {}


def should_flush(session_item):
    last_seen = parse_iso_z(session_item["lastSeen"])
    now = datetime.now(timezone.utc)
    return (now - last_seen).total_seconds() >= INACTIVITY_SECONDS


def normalize_event(raw_event):
    """
    Accepts either:
    - EventBridge event shape with top-level detail
    - CloudTrail event JSON shape directly
    """
    detail = raw_event.get("detail", raw_event)

    ui = detail.get("userIdentity") or {}
    rp = detail.get("requestParameters") or {}
    addl = detail.get("additionalEventData") or {}
    tls = detail.get("tlsDetails") or {}
    resources = detail.get("resources") or []

    normalized = {
        "eventTime": detail.get("eventTime"),
        "eventName": detail.get("eventName"),
        "eventSource": detail.get("eventSource"),
        "eventID": detail.get("eventID"),
        "eventCategory": detail.get("eventCategory"),
        "managementEvent": detail.get("managementEvent"),
        "readOnly": detail.get("readOnly"),

        "userType": ui.get("type"),
        "userName": ui.get("userName"),
        "principalId": ui.get("principalId"),
        "arn": ui.get("arn"),
        "accessKeyId": ui.get("accessKeyId"),

        "sourceIPAddress": detail.get("sourceIPAddress"),
        "userAgent": detail.get("userAgent"),

        "awsRegion": detail.get("awsRegion"),
        "requestID": detail.get("requestID"),
        "recipientAccountId": detail.get("recipientAccountId"),

        "bucketName": rp.get("bucketName"),
        "objectKey": rp.get("key"),

        "resources": [
            r.get("ARN") or r.get("arn")
            for r in resources
            if (r.get("ARN") or r.get("arn"))
        ],

        "errorCode": detail.get("errorCode"),
        "errorMessage": detail.get("errorMessage"),

        "bytesTransferredIn": addl.get("bytesTransferredIn"),
        "bytesTransferredOut": addl.get("bytesTransferredOut"),
        "authenticationMethod": addl.get("AuthenticationMethod"),
        "signatureVersion": addl.get("SignatureVersion"),
        "tlsVersion": tls.get("tlsVersion"),
        "cipherSuite": tls.get("cipherSuite"),
    }

    return normalized


def build_session_events_summary(normalized_events):
    normalized_events = sorted(
        [e for e in normalized_events if e.get("eventTime")],
        key=lambda x: x["eventTime"]
    )

    event_names = []
    attack_sequence = []
    attack_counts = {}

    for e in normalized_events:
        en = e.get("eventName")
        if not en:
            continue

        event_names.append(en)

        if en in ATTACK_EVENTS:
            attack_counts[en] = attack_counts.get(en, 0) + 1
            if en not in attack_sequence:
                attack_sequence.append(en)

    return {
        "eventCount": len(normalized_events),
        "eventNames": event_names,
        "attackEventCount": sum(attack_counts.values()),
        "attackCounts": attack_counts,
        "attackSequence": " → ".join(attack_sequence),
        "events": normalized_events,
    }


def query_session_events(session_key):
    """
    Reads the raw events captured by Lambda 1 from DecoySessionEvents.
    """
    resp = events_table.query(
        KeyConditionExpression=Key("sessionKey").eq(session_key)
    )

    items = [to_native(x) for x in resp.get("Items", [])]

    raw_events = []
    for item in items:
        raw = safe_json_loads(item.get("rawEvent", "{}"))
        if raw:
            raw_events.append(raw)

    return raw_events


def cloudtrail_lookup(start_time, end_time, lookup_attrs=None, max_events=200):
    events = []
    next_token = None

    while True:
        remaining = max_events - len(events)
        if remaining <= 0:
            break

        params = {
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": min(50, remaining),
        }

        if lookup_attrs:
            params["LookupAttributes"] = lookup_attrs
        if next_token:
            params["NextToken"] = next_token

        resp = ct.lookup_events(**params)

        for e in resp.get("Events", []):
            parsed = safe_json_loads(e.get("CloudTrailEvent", "{}"))
            if parsed:
                events.append(parsed)

            if len(events) >= max_events:
                break

        next_token = resp.get("NextToken")
        if not next_token:
            break

    return events


def event_matches_session(normalized_event, bucket=None, access_key_id=None, principal_id=None, source_ip=None):
    if bucket and normalized_event.get("bucketName") != bucket:
        # fallback to resources if bucketName is missing
        resources = normalized_event.get("resources") or []
        if not any(f"arn:aws:s3:::{bucket}" in r for r in resources if isinstance(r, str)):
            return False

    if access_key_id and normalized_event.get("accessKeyId") != access_key_id:
        return False

    if (not access_key_id) and principal_id and normalized_event.get("principalId") != principal_id:
        return False

    if (not access_key_id) and (not principal_id) and source_ip and normalized_event.get("sourceIPAddress") != source_ip:
        return False

    return True


def build_cloudtrail_context(session_item):
    if not ENABLE_CLOUDTRAIL_ENRICHMENT:
        return {
            "enabled": False,
            "eventCount": 0,
            "eventNames": [],
            "events": []
        }

    bucket = session_item.get("bucketName")
    access_key_id = session_item.get("accessKeyId") or None
    principal_id = session_item.get("principalId") or None
    source_ip = session_item.get("sourceIP") or None

    first_seen = parse_iso_z(session_item["firstSeen"])
    last_seen = parse_iso_z(session_item["lastSeen"])

    start_time = first_seen - timedelta(minutes=CLOUDTRAIL_LOOKBACK_MINUTES)
    end_time = last_seen + timedelta(minutes=CLOUDTRAIL_FORWARD_MINUTES)

    raw_events = []

    # Primary lookup: AccessKeyId
    if access_key_id:
        raw_events.extend(
            cloudtrail_lookup(
                start_time,
                end_time,
                lookup_attrs=[{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
                max_events=MAX_CLOUDTRAIL_EVENTS
            )
        )

    # Fallback / additional lookup by bucket resource
    if bucket:
        raw_events.extend(
            cloudtrail_lookup(
                start_time,
                end_time,
                lookup_attrs=[{"AttributeKey": "ResourceName", "AttributeValue": bucket}],
                max_events=MAX_CLOUDTRAIL_EVENTS
            )
        )

    # Normalize + deduplicate by eventID
    dedup = {}
    for raw in raw_events:
        normalized = normalize_event(raw)
        event_id = normalized.get("eventID") or f"{normalized.get('eventTime')}|{normalized.get('eventName')}"
        if event_id not in dedup:
            dedup[event_id] = normalized

    normalized_events = list(dedup.values())

    # Filter to events that match this session
    matched = [
        e for e in normalized_events
        if event_matches_session(
            e,
            bucket=bucket,
            access_key_id=access_key_id,
            principal_id=principal_id,
            source_ip=source_ip
        )
    ]

    matched = sorted(
        [e for e in matched if e.get("eventTime")],
        key=lambda x: x["eventTime"]
    )

    return {
        "enabled": True,
        "lookbackMinutes": CLOUDTRAIL_LOOKBACK_MINUTES,
        "forwardMinutes": CLOUDTRAIL_FORWARD_MINUTES,
        "eventCount": len(matched),
        "eventNames": [e.get("eventName") for e in matched if e.get("eventName")],
        "events": matched
    }


def lambda_handler(event, context):
    scan_resp = sessions_table.scan()
    sessions = [to_native(x) for x in scan_resp.get("Items", [])]

    flushed = []

    for session in sessions:
        if session.get("status") != "OPEN":
            continue

        if not should_flush(session):
            continue

        session_key = session["sessionKey"]

        # Primary source: DecoySessionEvents
        raw_session_events = query_session_events(session_key)
        normalized_session_events = [normalize_event(e) for e in raw_session_events]
        session_summary = build_session_events_summary(normalized_session_events)

        # Secondary source: CloudTrail enrichment
        cloudtrail_context = build_cloudtrail_context(session)

        output = {
            "sessionKey": session_key,
            "firstSeen": session.get("firstSeen"),
            "lastSeen": session.get("lastSeen"),
            "summary": {
                "bucket": session.get("bucketName"),
                "sourceIP": session.get("sourceIP"),
                "principalId": session.get("principalId"),
                "accessKeyId": session.get("accessKeyId"),
                "eventCount": session_summary["eventCount"],
                "eventNames": session_summary["eventNames"],
                "attackEventCount": session_summary["attackEventCount"],
                "attackCounts": session_summary["attackCounts"],
                "attackSequence": session_summary["attackSequence"],
            },
            "sessionEvents": session_summary["events"],
            "cloudTrailContext": cloudtrail_context
        }

        message_body = json.dumps(output)

        resp = sqs.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=message_body,
            MessageAttributes={
                "bucket": {
                    "DataType": "String",
                    "StringValue": session.get("bucketName") or ""
                },
                "sourceIP": {
                    "DataType": "String",
                    "StringValue": session.get("sourceIP") or ""
                },
                "sessionKey": {
                    "DataType": "String",
                    "StringValue": session_key
                }
            }
        )

        sessions_table.update_item(
            Key={"sessionKey": session_key},
            UpdateExpression="SET #s = :s, sqsMessageId = :m",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "FLUSHED",
                ":m": resp.get("MessageId", "")
            }
        )

        flushed.append({
            "sessionKey": session_key,
            "messageId": resp.get("MessageId"),
            "sessionEventCount": session_summary["eventCount"],
            "cloudTrailContextCount": cloudtrail_context["eventCount"]
        })

    return {
        "status": "completed",
        "flushedCount": len(flushed),
        "flushedSessions": flushed
    }