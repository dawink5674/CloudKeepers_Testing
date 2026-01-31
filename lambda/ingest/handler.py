import base64
import ipaddress
import json
import os
import re
import time
import urllib.parse
import urllib.request
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Tuple

import boto3


DDB_TABLE = os.environ["EVENTS_TABLE"]
TTL_DAYS = int(os.environ.get("TTL_DAYS", "30"))
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
GEOIP_ENDPOINT = os.environ.get(
    "GEOIP_ENDPOINT",
    "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,query,isp,as,org",
)
GEOIP_TIMEOUT = float(os.environ.get("GEOIP_TIMEOUT", "1.5"))


dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(DDB_TABLE)
sns = boto3.client("sns")


# (rule_id, attack_class, label, regex, points)
SIGNATURES: List[Tuple[str, str, str, re.Pattern[str], int]] = [
    (
        "sqli-001",
        "sqli",
        "SQL injection tautology",
        re.compile(r"(?:'|\")\s*or\s*1=1", re.IGNORECASE),
        6,
    ),
    (
        "sqli-002",
        "sqli",
        "SQL injection UNION select",
        re.compile(r"union\s+select", re.IGNORECASE),
        5,
    ),
    (
        "xss-001",
        "xss",
        "Script tag",
        re.compile(r"<\s*script\b", re.IGNORECASE),
        6,
    ),
    (
        "xss-002",
        "xss",
        "Event handler injection",
        re.compile(r"onerror\s*=|onload\s*=", re.IGNORECASE),
        4,
    ),
    (
        "cmd-001",
        "cmdi",
        "Command injection separators",
        re.compile(r"(;|\|\||&&)\s*(cat|ls|id|whoami|uname|curl|wget)", re.IGNORECASE),
        6,
    ),
    (
        "cmd-002",
        "cmdi",
        "Sensitive file probe",
        re.compile(r"/etc/passwd|/bin/sh|/proc/self/environ", re.IGNORECASE),
        5,
    ),
]


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _decode_body(event: Dict[str, Any]) -> str:
    body = event.get("body")
    if body is None:
        return ""
    if event.get("isBase64Encoded"):
        try:
            return base64.b64decode(body).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return str(body)


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except Exception:
        return False


def _geoip_lookup(ip: str) -> Dict[str, Any]:
    if not ip or not _is_public_ip(ip):
        return {"status": "skipped"}

    url = GEOIP_ENDPOINT.format(ip=urllib.parse.quote(ip))
    try:
        with urllib.request.urlopen(url, timeout=GEOIP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return {"status": "error"}

    if data.get("status") not in (None, "success"):
        return {"status": data.get("status", "error")}

    def _to_decimal(value: Any) -> Any:
        if isinstance(value, (int, float)):
            return Decimal(str(value))
        return value

    geo = {
        "status": "success",
        "country": data.get("country", ""),
        "region": data.get("regionName", ""),
        "city": data.get("city", ""),
        "lat": _to_decimal(data.get("lat")),
        "lon": _to_decimal(data.get("lon")),
        "asn": data.get("as", ""),
        "isp": data.get("isp", ""),
        "org": data.get("org", ""),
    }
    return geo


def _detection_surface(event: Dict[str, Any], body_raw: str) -> str:
    headers = event.get("headers") or {}
    query = event.get("queryStringParameters") or {}

    parts = [
        event.get("rawPath", ""),
        json.dumps(query, sort_keys=True),
        json.dumps(headers, sort_keys=True),
        body_raw,
    ]
    return "\n".join(str(p) for p in parts if p)


def _run_detections(surface: str) -> Tuple[List[Dict[str, Any]], int, str]:
    detections: List[Dict[str, Any]] = []
    score = 0
    class_points: Dict[str, int] = {}

    for rule_id, attack_class, label, pattern, points in SIGNATURES:
        match = pattern.search(surface)
        if not match:
            continue
        snippet = _truncate(match.group(0), 120)
        detections.append(
            {
                "rule_id": rule_id,
                "class": attack_class,
                "label": label,
                "points": points,
                "snippet": snippet,
            }
        )
        score += points
        class_points[attack_class] = class_points.get(attack_class, 0) + points

    if not class_points:
        return detections, 0, "unknown"

    attack_type = max(class_points.items(), key=lambda kv: kv[1])[0]
    return detections, score, attack_type


def _severity_from_score(score: int) -> str:
    if score >= 12:
        return "critical"
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _maybe_alert(item: Dict[str, Any]) -> None:
    if not SNS_TOPIC_ARN:
        return
    if item.get("severity") not in ("high", "critical"):
        return

    message = {
        "event_id": item["event_id"],
        "severity": item["severity"],
        "attack_type": item.get("attack_type", "unknown"),
        "source_ip": item.get("source_ip", "unknown"),
        "path": item.get("path", ""),
        "threat_score": item.get("threat_score", 0),
        "ts_epoch": item.get("ts_epoch", 0),
        "detections": item.get("detections", []),
    }

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"HoneyLambda alert: {item['severity']}",
            Message=json.dumps(message),
        )
    except Exception:
        # Alerts should never block ingestion.
        return


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    # HTTP API v2 request context
    rc = event.get("requestContext", {})
    http = rc.get("http", {})

    ts_epoch = int(time.time())
    ttl_epoch = ts_epoch + TTL_DAYS * 24 * 60 * 60

    source_ip = http.get("sourceIp") or rc.get("identity", {}).get("sourceIp") or "unknown"

    body_raw = _truncate(_decode_body(event), 4000)

    geo = _geoip_lookup(source_ip)
    surface = _detection_surface(event, body_raw)
    detections, threat_score, attack_type = _run_detections(surface)
    severity = _severity_from_score(threat_score)

    headers = event.get("headers") or {}
    # Cap header size to avoid runaway costs from huge headers.
    headers_limited = {k: _truncate(str(v), 500) for k, v in list(headers.items())[:60]}

    item = {
        "event_id": str(uuid.uuid4()),
        "ts_epoch": ts_epoch,
        "gsi_pk": "recent",
        "ttl_epoch": ttl_epoch,
        "source_ip": source_ip,
        "method": http.get("method", ""),
        "path": http.get("path", event.get("rawPath", "")),
        "user_agent": headers.get("user-agent", ""),
        "headers": headers_limited,
        "query": event.get("queryStringParameters") or {},
        "body_raw": body_raw,
        "geo": geo,
        "detections": detections,
        "threat_score": threat_score,
        "severity": severity,
        "attack_type": attack_type,
    }

    table.put_item(Item=item)
    _maybe_alert(item)

    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({"ok": True, "event_id": item["event_id"], "severity": severity}),
    }
