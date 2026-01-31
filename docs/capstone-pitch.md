# Honey-Lambda Capstone Pitch (Cybersecurity Focus)

Honey-Lambda is a serverless threat intelligence honeypot built entirely on AWS. We use API Gateway (HTTP API v2) and Lambda (Python 3.9+) to capture hostile HTTP traffic on demand, record full request context (IP, user-agent, headers, and body), enrich events with GeoIP data, apply signature detection (SQL injection, XSS, command injection) with threat scoring, store results in DynamoDB (on-demand with a 30-day TTL), and visualize attacks on a near-real-time global map. High-severity events trigger SNS alerts, and the dashboard uses Cognito authentication with strict input sanitization to safely display hostile data.

## Why this is a strong cybersecurity capstone
- It is clearly security work: telemetry capture, threat detection, classification, and alerting.
- It reflects modern security operations: cloud-native, scalable, and automation-first.
- It is easy to demo: "attack -> detection -> map marker -> SNS alert" in seconds.
- It includes security engineering depth: least-privilege IAM, TTL-based data minimization, and safe handling of hostile input.

## Rubric-aligned checklist (CS499-style deliverables)

### 1) Requirements Documentation (20%)
- Define acceptance criteria per requirement (e.g., REQ-1 through REQ-18).
- Include measurable SLOs: map update within about 5 seconds; TTL set to 30 days.
- Document boundaries: passive defense only; no "hack back."

### 2) Design Implementation (20%)
- MVP backend path works end-to-end: HTTP API v2 -> Lambda -> DynamoDB (with TTL).
- Lambda captures IP/UA/headers/body, then enriches events with GeoIP and detection results.
- Threat scoring and severity tiers are derived from matched detection rules.
- SNS alerts fire only for high-severity events.
- A read API supports dashboard polling (recent events for the map).

### 3) Design Documentation (20%)
- Provide a clear architecture diagram with data flow and trust boundaries.
- Include the DynamoDB data model: keys, indexes, TTL attribute, and query patterns.
- Include least-privilege IAM policies for both write and read paths.
- Document detection heuristics, rule evidence, and threat scoring logic.

### 4) Internal Presentation (20%)
- Show the ingestion flow and detection pipeline with one live request.
- Explain why serverless is a security and cost advantage for a honeypot.
- Highlight controls: IAM scoping, sanitization, TTL, and logging/alerts.

### 5) External Presentation (20%)
- Run a simple demo script:
  1) Send a crafted "attack" request (curl/Postman).
  2) Show the stored enriched record.
  3) Show the map update within seconds.
  4) Show an SNS alert for high severity.
- Close with lessons learned: false positives, rate limits, data ethics, and next steps.

## Scope guardrails (keep it capstone-safe)
- Prioritize detection quality over UI polish.
- Avoid collecting extra PII beyond IP, headers, and payload needed for analysis.
- Keep the MVP tight: ingest -> enrich -> store -> read -> visualize -> alert.
- Treat all captured input as hostile and never render raw payloads in the UI.
- Use TTL to limit retention and keep costs predictable.

## Suggested team split
- Josh (Infrastructure): API Gateway (HTTP API v2), Lambda config, DynamoDB, IAM, SNS, Amplify.
- Nolan (Detection Logic): signatures, heuristics, threat scoring, GeoIP handling.
- Colin (Visualization/PM): map polling, clustering, safe rendering, demo flow.
