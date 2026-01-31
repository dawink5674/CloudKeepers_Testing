# Honey-Lambda - Updated SRS (Google Doc Style Draft)

Version: 1.1 (draft)
Date: January 27, 2026
Team: The Cloud Keepers (Josh Cribbin, Nolan Blenniss, Colin Beers)

This draft keeps your original structure but tightens requirements so they are testable, security-focused, and easy to map to implementation and demos.

---

## 1. Introduction

### 1.1 Purpose
This document defines the software requirements for Honey-Lambda, a serverless threat intelligence honeypot. The system captures hostile HTTP requests, enriches them with geolocation and detection results, stores them in DynamoDB with automatic expiration, and visualizes activity on a near-real-time global map.

### 1.2 Conventions
- Requirements are labeled `REQ-X`.
- Priorities: High (MVP-critical), Medium (important for final demo), Low (nice to have).
- All timestamps are stored as UTC.

### 1.3 Intended Audience
- Developers (Josh, Colin): focus on Sections 3 and 4.
- Detection/analysis (Nolan): focus on Sections 3.2 and 5.3.
- Stakeholders/instructor: focus on Section 2 and requirement tables.

### 1.4 Scope
Honey-Lambda is a passive defensive system. It records and analyzes attacks but does not attempt counterattack, exploitation, or persistence in attacker environments.

Primary outcomes:
- Capture attacker traffic safely and reliably.
- Produce explainable detection results (rules matched, score, severity).
- Visualize attacks on a global map within about 5 seconds of ingestion.

### 1.5 References
- AWS documentation for API Gateway (HTTP API v2), Lambda, DynamoDB, Cognito, SNS, CloudWatch.
- Course CS499 Capstone Experience syllabus (Spring 2026).

---

## 2. Overall Description

### 2.1 Product Perspective
Honey-Lambda is a cloud-native system built entirely on AWS serverless components.

Core data flow:
1) API Gateway receives attacker request.
2) Lambda captures request context and payload.
3) Lambda enriches with GeoIP and detection signals.
4) Lambda stores an enriched event in DynamoDB (with TTL).
5) Dashboard polls a read API to render events on a global map.

### 2.2 Product Features
- Serverless ingestion that scales on demand.
- Heuristic detection with threat scoring and severity tiers.
- Geo-tagging of events (lat/lon for map rendering).
- Near-real-time map visualization.
- Admin alerting on high-severity events.

### 2.3 User Classes
- Security Analyst (admin): needs raw evidence, rule hits, and scores.
- Stakeholder viewer: needs safe, high-level map and summaries.

### 2.4 Operating Environment
- Cloud platform: AWS (`us-east-1`).
- Backend: Python 3.9+ on AWS Lambda.
- Frontend: Next.js hosted on AWS Amplify.
- Client browsers: latest Chrome/Edge/Firefox.

### 2.5 Constraints
- Cost-conscious: use on-demand and serverless-first design.
- Latency: trap responses should be fast enough to appear realistic.
- Security: least privilege IAM and safe rendering of hostile input.

### 2.6 Documentation
- Deployment guide.
- Analyst guide for interpreting detections and scores.

### 2.7 Assumptions and Dependencies
- Attack traffic is received over public HTTP/HTTPS.
- GeoIP depends on an external provider.
- System availability depends on AWS service availability.

---

## 3. System Features and Requirements

### 3.1 Feature: The Trap (Ingestion Engine) - Priority: High

#### Description
Public-facing HTTP endpoints designed to attract and capture attacker traffic.

#### Functional Requirements
- REQ-1 (High): The system shall expose a publicly accessible HTTPS endpoint via AWS API Gateway (HTTP API v2).
- REQ-2 (High): The endpoint shall accept at least `GET`, `POST`, and `PUT` methods.
- REQ-3 (High): API Gateway shall invoke a Lambda function for each request.
- REQ-4 (High): The Lambda function shall capture the following fields for every request when available:
  - source IP,
  - timestamp,
  - HTTP method and path,
  - user-agent,
  - headers,
  - query parameters,
  - request body.
- REQ-5 (Medium): The trap shall respond with a generic but plausible HTTP response (for example, `200 OK` or `403 Forbidden`).

#### Acceptance Checks (examples)
- A single `curl` request produces a stored event containing method, path, IP, UA, headers, and body.

### 3.2 Feature: The Brain (Analysis and Storage) - Priority: High

#### Description
Logic that enriches and classifies events before storage.

#### Functional Requirements
- REQ-6 (High): The system shall geolocate the source IP to country, city/region (if available), and latitude/longitude.
- REQ-7 (High): The system shall analyze request components (path, query, headers, and body) for attack signatures including:
  - SQL injection,
  - cross-site scripting (XSS), and
  - command injection.
- REQ-8 (High): The system shall record detection evidence as a list of matched rules or rule identifiers.
- REQ-9 (High): The system shall compute a threat score and derive a severity tier (for example: Low, Medium, High, Critical).
- REQ-10 (High): The system shall persist enriched events into a DynamoDB table.
- REQ-11 (High): Each stored event shall include a TTL attribute that expires the record approximately 30 days after ingestion.
- REQ-12 (Medium): The system shall publish an SNS alert when an event is classified as High or Critical severity.

#### Acceptance Checks (examples)
- A crafted SQLi/XSS payload yields rule hits, a non-zero score, and an appropriate severity.
- The stored event includes a TTL value consistent with 30 days.
- High-severity events produce an SNS notification.

### 3.3 Feature: The View (Visualization Dashboard) - Priority: Medium

#### Description
A dashboard that safely displays recent activity and geospatial distribution.

#### Functional Requirements
- REQ-13 (High): The dashboard shall require authentication using Amazon Cognito for admin-capable views.
- REQ-14 (High): The system shall provide a read API that returns recent events for map rendering.
- REQ-15 (High): The dashboard shall update the map within about 5 seconds of an event being ingested (using polling or a push mechanism).
- REQ-16 (Medium): The dashboard shall show a recent events list (for example, the latest 50 events).
- REQ-17 (Medium): The dashboard shall provide basic summaries such as top attack types and top sources over a recent time window.
- REQ-18 (High): The dashboard shall treat all displayed event data as hostile input and render it safely (no raw HTML or script execution).

#### Acceptance Checks (examples)
- A new attack appears on the map within approximately 5 seconds under normal conditions.
- Rendering a payload containing HTML/JS does not execute scripts in the browser.

---

## 4. External Interface Requirements

### 4.1 User Interfaces
- The dashboard shall be responsive for common desktop and tablet sizes.
- The UI shall clearly distinguish severity levels visually.
- The UI shall avoid rendering raw payloads as HTML.

### 4.2 Software Interfaces
- Backend services shall use AWS SDKs (boto3) to access DynamoDB, SNS, and CloudWatch.
- The frontend shall use a mapping library (for example, Leaflet or Mapbox) to render latitude/longitude points.

### 4.3 Communications Interfaces
- Dashboard-to-backend communication shall use HTTPS.
- Data exchange shall use JSON.

---

## 5. Nonfunctional Requirements

### 5.1 Performance
- NFR-1: The ingestion path shall remain functional during bursts up to 1,000 concurrent requests (within AWS account limits).
- NFR-2: Under normal conditions, the dashboard shall display newly ingested events within about 5 seconds.

### 5.2 Safety and Cost Controls
- NFR-3: A billing alarm shall notify the team if monthly cost exceeds a defined threshold (for example, $10).
- NFR-4: DynamoDB shall be configured with on-demand capacity.

### 5.3 Security
- NFR-5: IAM permissions shall follow least privilege for both write and read paths.
- NFR-6: Data at rest shall be encrypted using AWS-managed encryption.
- NFR-7: All displayed data shall be treated as untrusted input and rendered safely.
- NFR-8: The system shall minimize retained data by applying TTL expiration at 30 days.

### 5.4 Maintainability and Portability
- NFR-9: Infrastructure shall be defined as code (CDK or Terraform).
- NFR-10: The system shall separate ingestion/detection logic from dashboard code to preserve separation of concerns.

---

## 6. Legal and Ethical Requirements
- The system is passive and for research/education.
- The system will not attempt counterattacks.
- The system should avoid collecting extra PII beyond data required for security analysis.

---

## Appendix A: Suggested Event Schema (implementation guide)

A stored event should include fields similar to:
- `event_id`: unique identifier.
- `ts_epoch`: ingestion time (epoch seconds).
- `ttl_epoch`: expiration time (epoch seconds, about ts + 30 days).
- `source_ip`: source IP address.
- `method`: HTTP method.
- `path`: request path.
- `user_agent`: user-agent string.
- `headers`: captured headers (stored, but not rendered raw).
- `query`: query parameters.
- `body_raw`: raw body (stored, not rendered raw).
- `geo`: geolocation object with country/city/lat/lon when available.
- `detections`: list of matched rule identifiers and labels.
- `threat_score`: numeric score.
- `severity`: derived severity tier.
- `attack_type`: primary classification label.

---

## Appendix B: Requirement-to-Verification Mapping (template)

Use a small table like this in your final doc:

- REQ-4 -> Verify by sending a request and confirming stored fields.
- REQ-7/REQ-9 -> Verify using crafted payloads with expected rule hits and scores.
- REQ-11 -> Verify TTL by inspecting the `ttl_epoch` attribute.
- REQ-15 -> Verify with a timed demo (request time vs map render time).
- REQ-18 -> Verify by rendering an HTML/JS payload and confirming no script execution.