# Leakage Attack Paths

This repository contains defensive attack-path models for vulnerability exposure review and remediation planning.

## Attack paths

- [CVE-2026-23918: Apache HTTP Server HTTP/2 Double Free](attack-paths/cve-2026-23918.md) ([SVG graphic](attack-paths/cve-2026-23918.svg), [threat hunting rules](threat-hunting/cve-2026-23918-rules.md), [Sigma rule pack](threat-hunting/sigma/README.md), [risk assessment](risk-assessments/cve-2026-23918-risk-assessment.md), [intel assessment](threat-intel/cve-2026-23918-intel-assessment.md), [CISO assessment](ciso-assessments/cve-2026-23918-ciso-assessment.md), [CISO dashboard graphic](ciso-assessments/cve-2026-23918-ciso-dashboard.svg))


## Safe proof-of-exposure check

A public exploit proof of concept is intentionally not included for CVE-2026-23918 because the issue is an Apache HTTP/2 double-free with possible remote code execution and denial-of-service impact. Instead, this repository provides a defensive, non-exploit proof-of-exposure checker that validates passive indicators without sending crafted HTTP/2 reset traffic or malformed frames.

- Safe checker: [`poc/cve_2026_23918_safe_exposure_check.py`](poc/cve_2026_23918_safe_exposure_check.py)
- Checker documentation: [`poc/README.md`](poc/README.md)

Example:

```bash
python3 poc/cve_2026_23918_safe_exposure_check.py https://www.example.com/
```

Use the output to prioritize authenticated patch validation and remediation. Apache documents CVE-2026-23918 as affecting Apache HTTP Server 2.4.66 and recommends upgrading to 2.4.67.


### Exploit-like detector validation without exploit traffic

A real exploit is not included. To validate detections with exploit-like telemetry safely, generate local synthetic events instead:

```bash
python3 poc/cve_2026_23918_exploit_simulation.py --output /tmp/cve_2026_23918_synthetic_events.jsonl
```

The simulator creates JSONL events that resemble the attack graph stages used by the hunting rules, but it does not contact a target or send HTTP/2 frames.


## Risk assessment quick answer

- **Internet-facing Apache 2.4.66 with HTTP/2 reachable:** treat as **critical** until patched, HTTP/2 is disabled, or evidence proves HTTP/2 terminates before reaching Apache. Prioritize remediation within 24 hours because public reachability enables opportunistic attempts and the documented impact includes possible RCE and DoS.
- **Internal Apache 2.4.66 with HTTP/2 reachable:** treat as **high** when reachable from workstations, VPN users, partner networks, or broad internal segments; downgrade to **medium** only if network controls tightly restrict access and monitoring is in place. Patch or disable HTTP/2 within 72 hours for broad-reach internal services.

See the full [CVE-2026-23918 risk assessment](risk-assessments/cve-2026-23918-risk-assessment.md) for the scenario matrix, decision checklist, and response actions.


## Intelligence assessment

The [CVE-2026-23918 intelligence assessment](threat-intel/cve-2026-23918-intel-assessment.md) summarizes source facts, key judgments, likely targeting, deployment-specific risk, collection requirements, hunting priorities, and intelligence gaps for security leadership and SOC teams.


## CISO assessment

The [CVE-2026-23918 CISO assessment](ciso-assessments/cve-2026-23918-ciso-assessment.md) provides an executive decision brief, business impact summary, enterprise risk rating, 24-hour and 72-hour operating plans, dashboard metrics, exception criteria, and incident escalation thresholds.
