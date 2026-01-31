# Test Report: Honey-Lambda

**Date:** January 27, 2026
**Tester:** Jules (AI Assistant)
**Version Tested:** Current Head

## Executive Summary

A comprehensive test suite was executed against the current `Honey-Lambda` codebase (specifically the `ingest` and `read` Lambda functions). The testing was performed using a custom test runner leveraging `unittest`, `moto` (for AWS service mocking), and `unittest.mock` (for external HTTP calls).

**Result:** All tests passed. The system behaves as expected and meets the key functional requirements outlined in the SRS.

## Test Summary

| Requirement | Description | Status | Verification Method |
| :--- | :--- | :--- | :--- |
| **REQ-4, REQ-5** | Ingestion of requests | **PASS** | Simulated HTTP GET requests. Confirmed correct parsing of source IP, headers, and generation of correct response structure. |
| **REQ-6** | Geolocation enrichment | **PASS** | Mocked external GeoIP API. Confirmed that geo-data (country, city, lat/lon) is correctly populated in the database item. |
| **REQ-7** | Detection of SQL Injection | **PASS** | Simulated `admin' OR 1=1` payload. Confirmed detection rule match `sqli-001`. |
| **REQ-7** | Detection of XSS/Command Injection | **PASS** | Simulated combined XSS and Command Injection payload. Confirmed multiple rule matches. |
| **REQ-8, REQ-9** | Scoring and Severity | **PASS** | Verified that SQLi payload generated a score of 6 (Medium) and mixed payload generated a score of 17 (Critical). |
| **REQ-10** | Persistence | **PASS** | Confirmed that events are correctly stored in the mocked DynamoDB table with all enriched fields. |
| **REQ-11** | Data Expiration (TTL) | **PASS** | Verified that the `ttl_epoch` field is set to approximately 30 days in the future. |
| **REQ-12** | Alerting | **PASS** | Confirmed that Critical severity events trigger the SNS publish action (mocked). |
| **REQ-16** | Read API Sorting | **PASS** | Verified that the Read Lambda returns events sorted by timestamp in descending order (latest first). |

## Detailed Findings

### 1. Ingestion & Detection Logic
- **SQL Injection:** The regex patterns correctly identified a classic tautology attack (`' OR 1=1`). The system assigned the correct rule ID and points.
- **Complex Attacks:** A payload combining XSS (`<script>`) and Command Injection (`cat /etc/passwd`) was correctly identified. The scoring logic successfully summed the points from both matches, resulting in a "Critical" severity rating.
- **Clean Traffic:** Normal requests were processed without triggering false positives, resulting in a score of 0 and "none" severity.

### 2. Data Enrichment
- **Geolocation:** The system correctly makes an outbound request to the configured GeoIP endpoint. It gracefully handles the response and populates the `geo` dictionary in the DynamoDB item.
- **Timestamps:** The `ts_epoch` (ingestion time) and `ttl_epoch` (expiration time) are calculated correctly.

### 3. Read API
- **Querying:** The `read` handler correctly queries the `gsi_recent` Global Secondary Index.
- **Sorting:** The results are strictly ordered by `ts_epoch` in descending order, ensuring the dashboard displays the most recent attacks first.
- **Serialization:** The handler correctly converts DynamoDB `Decimal` types to standard Python `int` or `float` types for JSON serialization.

## Conclusion

The current implementation of Honey-Lambda is robust and fulfills the functional requirements specified in the documentation. No code changes are recommended at this time based on these tests.
