# Capstone Upgrades (Make Honey-Lambda Top Tier)

This checklist focuses on security depth, operational rigor, and measurable outcomes so the project looks like serious cybersecurity engineering rather than just a dashboard.

## 1) Detection Rigor (security credibility)
- Define a simple threat score model and severity tiers (Low/Medium/High/Critical).
- Separate signatures by class: SQLi, XSS, command injection, recon, brute force.
- Track which rules matched (evidence) per event.
- Add unit tests for signatures and scoring logic (show pass/fail counts in demo).

Suggested scoring approach (easy to explain):
- Each matched rule adds points; multiple classes stack.
- Weight high-confidence patterns more heavily than generic keywords.
- Severity is derived from score thresholds.

## 2) Security Engineering Rigor (architectural maturity)
- Produce a one-page threat model with trust boundaries and abuse cases.
- Enforce least-privilege IAM:
  - Lambda write role: only `dynamodb:PutItem` on the events table, `sns:Publish` on one topic, and minimal CloudWatch Logs permissions.
  - Read API role: only `dynamodb:Query` on specific indexes/keys.
- Treat all captured fields as hostile data:
  - Store raw payloads and headers.
  - Never render raw HTML/JS in the UI; escape or summarize.
- Log safely:
  - Avoid logging full payloads at high volume in CloudWatch.
  - Log rule hits, scores, and identifiers instead.

## 3) Operational Rigor (real-world readiness)
- CloudWatch metrics and alarms:
  - Lambda: error rate, duration p95, throttles.
  - API Gateway: 4xx/5xx spikes and latency.
  - Billing alarm for monthly spend.
- Define and measure SLOs:
  - Ingestion success rate.
  - Map update latency (~5 seconds target).
  - Alert delivery time.
- Add a minimal load test:
  - Script 200 to 1,000 requests in bursts.
  - Show the system stays responsive and continues storing events.

## 4) Data Model Rigor (explainable queries)
- Use an events table with an explicit TTL attribute (`ttl_epoch`).
- Add a query path designed for the dashboard:
  - Recent events by time window.
  - Optional filtered queries by severity or attack type.
- Hash or truncate IPs for the dashboard view if needed, but keep raw IP in storage for analysis.

## 5) Demo Rigor (tight, repeatable, high impact)
Run a scripted demo with timestamps visible:
1) Send a benign request and a malicious request.
2) Show enriched event records (geo + rules + score + severity).
3) Show the map update within seconds.
4) Trigger a high-severity alert and show the SNS notification.
5) Show CloudWatch metrics/alarm panels and briefly discuss SLOs.

## 6) Documentation Rigor (prof-proof)
- Map every REQ in the SRS to:
  - an implementation location, and
  - a verification step (test or demo check).
- Include diagrams:
  - Architecture diagram,
  - Trust boundaries diagram, and
  - Data flow diagram.
- Include a short ethics/privacy section:
  - passive defense only,
  - TTL-based data minimization,
  - no extra PII collection.

## 7) Stretch Goals (only after MVP is solid)
- Add a second Lambda for async enrichment using SQS (decouple ingestion from slow GeoIP APIs).
- Add basic bot fingerprinting signals:
  - header ordering,
  - suspicious UA patterns,
  - path entropy,
  - repeated probes by IP/ASN.
- Add a "rule tuning" view that shows which rules are noisy.

## Definition of "Top Tier" for this project
You are top-tier when you can show, in one run:
- end-to-end ingestion and enrichment,
- a defensible threat score and evidence trail,
- strong IAM scoping and safe rendering practices,
- operational visibility (metrics/alarms), and
- a short, crisp verification story for each requirement.
