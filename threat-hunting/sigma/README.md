# Sigma Rule Pack: CVE-2026-23918

This directory contains Sigma-format threat hunting rules mapped to the CVE-2026-23918 Apache HTTP/2 attack graph. The rules are defensive detections for exposure, trigger-attempt anomalies, crash/DoS evidence, and possible post-exploitation behavior.

## Rules

| File | Coverage |
| --- | --- |
| `cve-2026-23918_apache_2466_http2_exposure.yml` | Vulnerable Apache 2.4.66 + HTTP/2 exposure precondition |
| `cve-2026-23918_http2_reset_burst.yml` | Per-source HTTP/2 reset burst against Apache-backed hosts |
| `cve-2026-23918_distributed_http2_reset_burst.yml` | Distributed HTTP/2 reset burst against one host |
| `cve-2026-23918_apache_crash_allocator_error.yml` | Apache crash, allocator, double-free, or core dump evidence |
| `cve-2026-23918_apache_worker_restart_loop.yml` | Apache worker restart loop or DoS-style crash storm |
| `cve-2026-23918_suspicious_apache_child_process.yml` | Suspicious process execution by Apache parent processes |
| `cve-2026-23918_outbound_network_from_apache.yml` | Unexpected outbound connections from Apache processes |
| `cve-2026-23918_sensitive_file_access_by_apache.yml` | Sensitive file access by Apache service accounts |
| `cve-2026-23918_webroot_executable_modification.yml` | Executable file creation/modification in web roots |

## Tuning notes

- Treat field names such as `backend_product`, `termination_reason`, `http2_enabled`, and `exposure_zone` as normalized examples; map them to your SIEM, EDR, WAF, CDN, load balancer, or inventory schema before deployment.
- Aggregate conditions use Sigma-style threshold syntax and may require backend-specific conversion or correlation-rule support.
- Correlate reset-burst rules with crash/restart rules in a ±15 minute window and prioritize hosts that inventory confirms as Apache HTTP Server 2.4.66 with HTTP/2 reachable from untrusted networks.
