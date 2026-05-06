import json
import os
import boto3

ddb = boto3.resource("dynamodb", region_name="us-east-2")

SESSIONS_TABLE = os.environ["SESSIONS_TABLE"]
EVENTS_TABLE = os.environ["EVENTS_TABLE"]

sessions_table = ddb.Table(SESSIONS_TABLE)
events_table = ddb.Table(EVENTS_TABLE)

def build_session_key(detail):
    rp = detail.get("requestParameters") or {}
    ui = detail.get("userIdentity") or {}

    bucket = rp.get("bucketName", "unknown-bucket")
    access_key_id = ui.get("accessKeyId", "")
    principal_id = ui.get("principalId", "")
    source_ip = detail.get("sourceIPAddress", "")

    actor = access_key_id or principal_id or "unknown-actor"
    return f"{bucket}|{actor}|{source_ip}"

def lambda_handler(event, context):
    detail = event.get("detail", {})
    rp = detail.get("requestParameters") or {}
    ui = detail.get("userIdentity") or {}

    session_key = build_session_key(detail)
    event_time = detail.get("eventTime")
    bucket = rp.get("bucketName")
    access_key_id = ui.get("accessKeyId")
    principal_id = ui.get("principalId")
    source_ip = detail.get("sourceIPAddress")
    event_name = detail.get("eventName")

    # Upsert session metadata
    existing = sessions_table.get_item(Key={"sessionKey": session_key}).get("Item")

    if existing:
        first_seen = existing["firstSeen"]
    else:
        first_seen = event_time

    sessions_table.put_item(
        Item={
            "sessionKey": session_key,
            "bucketName": bucket,
            "accessKeyId": access_key_id or "",
            "principalId": principal_id or "",
            "sourceIP": source_ip or "",
            "firstSeen": first_seen,
            "lastSeen": event_time,
            "status": "OPEN"
        }
    )

    # Store raw event
    events_table.put_item(
        Item={
            "sessionKey": session_key,
            "eventTime": event_time,
            "eventName": event_name,
            "rawEvent": json.dumps(event)
        }
    )

    return {
        "status": "stored",
        "sessionKey": session_key,
        "eventName": event_name,
        "eventTime": event_time
    }