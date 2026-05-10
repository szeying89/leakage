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

---

## Known bugs

The following bugs were identified in this rule pack. Each entry names the affected file(s), describes the defect, and states the fix.

---

### Bug 1 — Operator-precedence error in count aggregation conditions

**Affected files:**
- `cve-2026-23918_http2_reset_burst.yml`
- `cve-2026-23918_distributed_http2_reset_burst.yml`
- `cve-2026-23918_apache_worker_restart_loop.yml`

**Defect:** In Sigma, the `|` pipe operator binds more tightly than `and`. The conditions as written:

```yaml
condition: selection_backend and selection_protocol and selection_reset | count() by src_ip, host >= 50
condition: selection_backend and selection_protocol and selection_reset | count() by host >= 200
condition: selection_service and selection_event | count() by host >= 5
```

are parsed as `A and B and (C | count() >= N)`, applying the aggregate only to the last named selection instead of the full compound filter. Most Sigma backends reject this or silently count only the last clause.

**Fix:** Wrap the full compound filter in parentheses before the pipe:

```yaml
condition: (selection_backend and selection_protocol and selection_reset) | count() by src_ip, host >= 50
condition: (selection_backend and selection_protocol and selection_reset) | count() by host >= 200
condition: (selection_service and selection_event) | count() by host >= 5
```

---

### Bug 2 — Missing `timeframe` in `cve-2026-23918_http2_reset_burst.yml`

**Affected file:** `cve-2026-23918_http2_reset_burst.yml`

**Defect:** The condition uses `count() by src_ip, host >= 50` but the `detection` block contains no `timeframe` field. Without a timeframe, the aggregation window is undefined and backend-specific. The companion rule `cve-2026-23918_distributed_http2_reset_burst.yml` correctly includes `timeframe: 1m`, making the omission here an inconsistency that renders the threshold meaningless.

**Fix:** Add a `timeframe` entry inside the `detection` block:

```yaml
detection:
  ...
  timeframe: 1m
  condition: (selection_backend and selection_protocol and selection_reset) | count() by src_ip, host >= 50
```

---

### Bug 3 — `/var/www/` in sensitive-file-access path list causes excessive false positives

**Affected file:** `cve-2026-23918_sensitive_file_access_by_apache.yml`

**Defect:** The `selection_paths` block includes `/var/www/` as a sensitive path:

```yaml
selection_paths:
  TargetFilename|contains:
    - /var/www/
    ...
```

Apache reads files under `/var/www/` during every HTTP request as its normal document root. This causes the rule to fire on virtually every file access by the Apache service account, overwhelming analysts with false positives and hiding genuine credential-access events.

**Fix:** Remove `/var/www/` from `selection_paths`. Web-root file *writes* are already covered by the dedicated `cve-2026-23918_webroot_executable_modification.yml` rule.

---

### Bug 4 — Missing IPv6 private/loopback address filters in outbound-network rule

**Affected file:** `cve-2026-23918_outbound_network_from_apache.yml`

**Defect:** `filter_private_ipv4` lists only IPv4 CIDR ranges:

```yaml
filter_private_ipv4:
  DestinationIp|cidr:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8
    - 169.254.0.0/16
```

There are no corresponding IPv6 ranges. Apache connecting to `::1` (IPv6 loopback), `fe80::/10` (link-local), or `fc00::/7` (ULA) destinations will bypass the filter and generate false positive alerts.

**Fix:** Add a second filter block for IPv6 private ranges and include it in the condition:

```yaml
filter_private_ipv6:
  DestinationIp|cidr:
    - "::1/128"
    - "fe80::/10"
    - "fc00::/7"

condition: selection_process and not filter_private_ipv4 and not filter_private_ipv6 and not filter_approved_ports
```

---

### Bug 5 — `connection_reset` in `termination_reason` is too broad

**Affected files:**
- `cve-2026-23918_http2_reset_burst.yml`
- `cve-2026-23918_distributed_http2_reset_burst.yml`

**Defect:** Both rules include `connection_reset` in the `termination_reason` list:

```yaml
selection_reset:
  termination_reason:
    - stream_reset
    - client_reset
    - aborted_stream
    - connection_reset   # <-- too generic
    - rst_stream
```

`connection_reset` is a generic TCP-level event (any TCP RST) that fires on normal browser disconnects, keepalive timeouts, and load-balancer resets, none of which are HTTP/2 RST_STREAM frames indicative of CVE-2026-23918 activity. This substantially inflates false positive rates.

**Fix:** Remove `connection_reset` from both rules. The remaining values (`stream_reset`, `client_reset`, `aborted_stream`, `rst_stream`) are HTTP/2-specific and sufficient for the intended detection.

---

### Bug 6 — `nginx` user included in Apache-specific sensitive-file-access rule

**Affected file:** `cve-2026-23918_sensitive_file_access_by_apache.yml`

**Defect:** The `selection_user` block includes `nginx`:

```yaml
selection_user:
  User:
    - apache
    - www-data
    - httpd
    - nginx   # <-- out of scope
```

The rule title is "Sensitive File Access By Apache Service Account" and the CVE is an Apache HTTP Server vulnerability. nginx is an unrelated web server not affected by CVE-2026-23918. Including its service account silently widens the rule's scope beyond what the title, description, and tags imply, leading to alert attribution confusion.

**Fix:** Remove `nginx` from `selection_user`. If broad web-server coverage is intentional, update the title, description, and tags accordingly.

---

### Bug 7 — Non-standard `category: asset_inventory` log source

**Affected file:** `cve-2026-23918_apache_2466_http2_exposure.yml`

**Defect:** The `logsource` block uses:

```yaml
logsource:
  product: linux
  category: asset_inventory
```

`asset_inventory` is not a recognized Sigma log source category. The Sigma specification defines standard categories such as `process_creation`, `file_event`, `network_connection`, and `webserver`. Using an unrecognized category means no standard Sigma backend will map this rule to a data source without manual configuration, making it silently inoperative in automated pipelines.

**Fix:** Either replace `category: asset_inventory` with the closest applicable standard category for the target SIEM (and document the required field mapping), or add a comment in the rule and the tuning notes that explicitly names the custom log source or index required for this rule.

---

### Bug 8 — `child pid` in crash-detection message filter is too generic

**Affected file:** `cve-2026-23918_apache_crash_allocator_error.yml`

**Defect:** `child pid` is included as one of the message keywords that triggers the crash detection rule:

```yaml
selection_message:
  Message|contains:
    - segmentation fault
    - segfault
    - double free
    - corrupted double-linked list
    - malloc corruption
    - core dumped
    - child pid      # <-- too generic
    - caught SIGSEGV
```

The phrase `child pid` appears in normal Apache lifecycle log messages whenever a worker process starts or exits (e.g., `child pid 12345 started`), not only during crash events. Matching on this phrase alone causes the rule to alert on every routine Apache worker event, producing high false positive volume and masking genuine crash signals.

**Fix:** Remove `child pid` as a standalone keyword. To retain coverage for crash-related child messages, use a more specific phrase such as `exit signal Segmentation fault`, `exit signal Aborted`, or pair `child pid` with an `and` condition requiring at least one other crash-specific keyword in the same message.
