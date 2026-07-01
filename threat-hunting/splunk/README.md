# Splunk Detection Pack: CVE-2026-23918

This directory contains Splunk SPL detection content for CVE-2026-23918, the Apache HTTP Server 2.4.66 HTTP/2 double-free issue fixed in Apache HTTP Server 2.4.67. The searches map to the existing attack graph and are intended for defensive SOC hunting, alerting, triage, and post-remediation validation.

The detections do **not** include exploit payloads or reproduction steps. They look for exposure preconditions, HTTP/2 reset or aborted-stream anomalies, Apache crash evidence, service instability, and post-exploitation behaviors that would be visible if exploitation succeeded.

## Files

| File | Purpose |
| --- | --- |
| [`cve-2026-23918-splunk-detections.md`](cve-2026-23918-splunk-detections.md) | Human-readable SPL rulebook with field assumptions, searches, triage notes, and tuning guidance. |
| [`savedsearches.conf`](savedsearches.conf) | Deployable Splunk saved-search stanzas. Searches are disabled by default and use placeholder indexes/macros that must be adapted before production use. |

## Required field mapping

These searches assume one or more of the following telemetry families are available in Splunk:

- **Asset and vulnerability inventory:** `index=asset_inventory` or `index=vulnerability`, with fields such as `product`, `apache_version`, `http2_enabled`, `exposure_zone`, `cve`, and `fixed_version`.
- **HTTP edge logs:** `index=web` or `index=waf`, with fields such as `src_ip`, `dest`, `host`, `protocol`, `backend_product`, `backend_version`, `termination_reason`, `status`, `uri_path`, `user_agent`, and `action`.
- **Host and service logs:** `index=os` or `index=apache`, with Apache error logs, journald, syslog, and service-manager messages.
- **Endpoint telemetry:** Splunk Enterprise Security CIM Endpoint and Network Traffic data models, or equivalent EDR logs containing parent/child process, file, and network connection fields.

If your environment uses different field names, keep the analytic intent and modify only the index, sourcetype, and field names. Prefer environment-specific lookup tables for known Apache assets, internet exposure, approved scanners, patch exceptions, and private network ranges.

## Deployment approach

1. Copy `savedsearches.conf` into a Splunk app, or convert the searches into correlation searches in Splunk Enterprise Security.
2. Replace placeholder indexes, sourcetypes, and macros with local values.
3. Keep the searches disabled until field mapping and allow-list tuning are complete.
4. Validate with the repository's local synthetic event generator if you need safe test data that resembles the attack graph without targeting Apache.
5. Enable high-confidence searches first: Apache crash evidence, suspicious Apache child process execution, and outbound network connections from Apache.

## References

- Apache HTTP Server 2.4 vulnerabilities: https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2026-23918
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-23918
- NVD detail: https://nvd.nist.gov/vuln/detail/CVE-2026-23918
