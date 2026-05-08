# Safe PoC: CVE-2026-23918 Exposure Check

This directory intentionally contains a **safe proof-of-exposure check**, not an exploit.

CVE-2026-23918 is described by Apache as an HTTP/2 double-free issue in Apache HTTP Server 2.4.66 with possible remote code execution. The safe checker helps defenders validate exposure indicators without sending crafted HTTP/2 reset traffic, malformed frames, or crash-triggering payloads.

## What the checker does

- Connects to an HTTPS endpoint and offers `h2` and `http/1.1` through TLS ALPN.
- Reports whether the endpoint negotiates HTTP/2.
- Collects the `Server` response header only when the server negotiates HTTP/1.1.
- Flags the combination of HTTP/2 exposure and an `Apache/2.4.66` banner as high priority for authenticated patch validation.

## What the checker does not do

- It does not exploit CVE-2026-23918.
- It does not send HTTP/2 reset frames or malformed HTTP/2 frames.
- It does not attempt denial of service, memory corruption, or remote code execution.
- It does not prove that a vendor package is vulnerable when the vendor has backported a fix while keeping an older version string.

## Usage

```bash
python3 poc/cve_2026_23918_safe_exposure_check.py https://www.example.com/
```

Use results as triage input only. Final exposure decisions should come from authenticated runtime/package inventory, Apache configuration review, and verification that HTTP/2 reaches the Apache 2.4.66 backend rather than terminating at a patched proxy.
