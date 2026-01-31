import json
import os
import time
from decimal import Decimal
from typing import Any, Dict, List

import boto3
from boto3.dynamodb.conditions import Key


DDB_TABLE = os.environ["EVENTS_TABLE"]
DEFAULT_WINDOW_SECONDS = int(os.environ.get("DEFAULT_WINDOW_SECONDS", "300"))
MAX_LIMIT = int(os.environ.get("MAX_LIMIT", "200"))


dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(DDB_TABLE)


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, Decimal):
        # Preserve ints while allowing floats.
        if value % 1 == 0:
            return int(value)
        return float(value)
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(v) for v in value]
    return value


def _parse_params(event: Dict[str, Any]) -> Dict[str, int]:
    params = event.get("queryStringParameters") or {}
    try:
        window_seconds = int(params.get("window_seconds", DEFAULT_WINDOW_SECONDS))
    except Exception:
        window_seconds = DEFAULT_WINDOW_SECONDS
    try:
        limit = int(params.get("limit", 100))
    except Exception:
        limit = 100
    window_seconds = max(30, min(window_seconds, 3600))
    limit = max(1, min(limit, MAX_LIMIT))
    return {"window_seconds": window_seconds, "limit": limit}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    opts = _parse_params(event)
    now_epoch = int(time.time())
    min_ts = now_epoch - opts["window_seconds"]

    projection = (
        "event_id, ts_epoch, source_ip, #m, #p, user_agent, "
        "geo, detections, threat_score, severity, attack_type"
    )
    expr_names = {
        "#m": "method",
        "#p": "path",
    }

    resp = table.query(
        IndexName="gsi_recent",
        KeyConditionExpression=Key("gsi_pk").eq("recent") & Key("ts_epoch").gte(min_ts),
        ProjectionExpression=projection,
        ExpressionAttributeNames=expr_names,
        Limit=opts["limit"],
        ScanIndexForward=False,
    )

    items: List[Dict[str, Any]] = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("ts_epoch", 0)), reverse=True)

    payload = {
        "ok": True,
        "window_seconds": opts["window_seconds"],
        "count": len(items),
        "items": [_to_jsonable(i) for i in items],
        "now_epoch": now_epoch,
    }

    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(payload),
    }
