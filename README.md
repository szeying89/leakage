# Leakage CVE-2026-20188

This repository contains defensive attack-path models for vulnerability exposure review and remediation planning.

## Attack paths

- [CVE-2026-23918: Apache HTTP Server HTTP/2 Double Free](attack-paths/cve-2026-23918.md) ([SVG graphic](attack-paths/cve-2026-23918.svg), [threat hunting rules](threat-hunting/cve-2026-23918-rules.md), [Sigma rule pack](threat-hunting/sigma/README.md))


## Safe proof-of-exposure check

A public exploit proof of concept is intentionally not included for CVE-2026-23918 because the issue is an Apache HTTP/2 double-free with possible remote code execution and denial-of-service impact. Instead, this repository provides a defensive, non-exploit proof-of-exposure checker that validates passive indicators without sending crafted HTTP/2 reset traffic or malformed frames.

- Safe checker: [`poc/cve_2026_23918_safe_exposure_check.py`](poc/cve_2026_23918_safe_exposure_check.py)
- Checker documentation: [`poc/README.md`](poc/README.md)

Example:

```bash
python3 poc/cve_2026_23918_safe_exposure_check.py https://www.example.com/
```

Use the output to prioritize authenticated patch validation and remediation. Apache documents CVE-2026-23918 as affecting Apache HTTP Server 2.4.66 and recommends upgrading to 2.4.67.
