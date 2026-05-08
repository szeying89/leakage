# CVE-2026-20188 Proof-of-Exploit

This repository contains an **authorized proof-of-exploit** for CVE-2026-20188, a Cisco Crosswork Network Controller (CNC) and Cisco Network Services Orchestrator (NSO) denial-of-service vulnerability involving inadequate rate limiting on incoming network connections.

> Use this exploit only on systems you own or have explicit written permission to test. The default workflow targets `127.0.0.1` and includes guardrails so the exploit can be proven in a local lab without touching production Cisco devices.

## Vulnerability summary

Cisco describes CVE-2026-20188 as a connection-handling flaw where inadequate rate limiting on incoming connections can let an unauthenticated remote attacker send many connection requests and exhaust available connection resources. A successful attack can make affected CNC or NSO systems unresponsive, causing denial of service for legitimate users and dependent services, and Cisco states that manual reboot is required to recover.

Key facts from the Cisco advisory:

| Field | Value |
| --- | --- |
| CVE | CVE-2026-20188 |
| Cisco advisory | `cisco-sa-nso-dos-7Egqyc` |
| CWE | CWE-400: Uncontrolled Resource Consumption |
| CVSS v3.1 | 7.5 High (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) |
| Affected products | Cisco CNC and Cisco NSO |
| Fixed releases | CNC 7.2; NSO 6.4.1.3 for the 6.4 train; NSO 6.5 |
| Workarounds | Cisco lists no workarounds |

References:

* Cisco advisory: <https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-nso-dos-7Egqyc.html>
* CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-20188>
* NVD entry: <https://nvd.nist.gov/vuln/detail/CVE-2026-20188>

## What makes this a proof-of-exploit

`cve_2026_20188_exploit.py` does more than open connections. In `--prove` mode, it performs the following exploit validation sequence:

1. **Baseline proof:** connect to the target and confirm the service returns an application response.
2. **Exploit:** open and hold enough TCP sessions to consume the vulnerable service's available connection slots.
3. **Impact proof:** while the exploit sessions are still held open, attempt a fresh legitimate probe and confirm it no longer receives an application response.
4. **Result:** print `EXPLOIT CONFIRMED` only when the target was responsive before exploitation and became unavailable during exploitation.

The repository still includes a deliberately vulnerable local `server` mode so the exploit can be proven safely and repeatably on loopback.

## Quick start: prove the exploit locally

Open terminal 1 and start the vulnerable lab service with three available connection slots:

```bash
python3 cve_2026_20188_exploit.py server --host 127.0.0.1 --port 20188 --max-connections 3
```

Open terminal 2 and run the exploit with impact proof enabled:

```bash
python3 cve_2026_20188_exploit.py exploit --host 127.0.0.1 --port 20188 --connections 3 --rate 10 --hold-seconds 5 --prove --probe-timeout 0.5
```

Expected exploit output includes:

```text
[proof] baseline probe succeeded; target is initially responsive
[proof] 3/3 exploit connections are established
[proof] EXPLOIT CONFIRMED: target stopped returning an application response
```

Expected server output includes:

```text
[server] simulated resource exhaustion reached; additional legitimate clients will not receive an application response
[server] resource slot unavailable for ...; connection is accepted but application response is starved
```

## Arguments

### `server`

```text
--host              Bind host. Defaults to 127.0.0.1.
--port              Bind TCP port. Defaults to 20188.
--max-connections   Active connection count that triggers simulated exhaustion. Defaults to 25.
```

### `exploit`

```text
--host              Target host. Defaults to 127.0.0.1.
--port              Target TCP port. Defaults to 20188.
--connections       Number of TCP connections to open and hold. Defaults to 30.
--rate              Connection attempts per second. Defaults to 5.
--hold-seconds      Seconds to hold each successful connection open. Defaults to 60.
--prove             Run baseline and post-exploit probes to prove availability impact.
--probe-timeout     Seconds to wait for each proof probe response. Defaults to 1.
--allow-remote      Required for non-loopback targets.
--force             Required for more than 512 requested connections.
```

## Safety guardrails

The exploit intentionally includes guardrails:

* The default target is loopback (`127.0.0.1`).
* Non-loopback targets are refused unless `--allow-remote` is provided.
* More than 512 requested connections are refused unless `--force` is provided.
* Connection opening is rate-limited by `--rate`.
* Proof mode requires the target to be responsive before exploitation; otherwise it exits without claiming success.

These guardrails are not a substitute for authorization. Do not run connection-exhaustion testing against production services unless the maintenance window, scope, and rollback/recovery plan are approved.

## Authorized validation against a non-loopback lab target

For an owned lab appliance or an explicitly authorized pre-production test target, specify the target and acknowledge remote testing with `--allow-remote`:

```bash
python3 cve_2026_20188_exploit.py exploit --host 192.0.2.10 --port 2024 --connections 100 --rate 20 --hold-seconds 60 --prove --allow-remote
```

Only run this against systems in scope for your test. Connection-exhaustion testing can disrupt service availability.

## Detection ideas

For authorized defenders validating exposure in a lab or pre-production environment:

* Monitor active TCP sessions to the tested CNC/NSO service before, during, and after the run.
* Alert on unusual spikes in unauthenticated or unactioned connection attempts from a single source or subnet.
* Alert when application-level probes fail while TCP accepts continue, which is the behavior reproduced by the local exploit lab.
* Validate whether patched software enforces effective connection limits or rate limiting.
* Confirm operational recovery procedures, especially where manual reboot might be required for affected versions.

## Remediation

Cisco recommends upgrading to fixed software. Based on the advisory, fixed release guidance includes:

* Cisco CNC: upgrade to 7.2 where applicable.
* Cisco NSO 6.4: upgrade to 6.4.1.3.
* Cisco NSO 6.5: listed as not vulnerable.

Check the Cisco advisory and your support contract for platform-specific upgrade paths before making production changes.
