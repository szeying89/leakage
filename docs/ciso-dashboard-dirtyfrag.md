# Dirty Frag CISO dashboard

## Purpose

The Dirty Frag CISO dashboard translates the advisory, exposure PoC, detections, attack graph, and enterprise risk assessment into an executive tracking view. It is intended for CISO staff, risk committees, vulnerability management, incident response, and platform leaders who need a concise view of remediation progress and residual risk.

## Dashboard artifacts

- Source data: [`dashboards/dirtyfrag_ciso_dashboard.json`](../dashboards/dirtyfrag_ciso_dashboard.json)
- Rendered dashboard: [`dashboards/dirtyfrag_ciso_dashboard.html`](../dashboards/dirtyfrag_ciso_dashboard.html)
- Renderer: [`scripts/render_ciso_dashboard.py`](../scripts/render_ciso_dashboard.py)

Regenerate the HTML dashboard after updating JSON values:

```bash
python3 scripts/render_ciso_dashboard.py
```

## Dashboard sections

| Section | CISO question answered |
| --- | --- |
| Executive risk posture | What is our current risk, likelihood, impact, urgency, and confidence? |
| Key risk indicators | Are patching, telemetry, module exposure, investigations, and exceptions under control? |
| Priority asset segments | Which parts of the Linux estate need executive attention first? |
| Remediation workstreams | Which teams own the 24-72 hour and 30-day response work? |
| CISO decision gates | When should we patch immediately, approve an exception, or declare possible compromise? |
| Required data sources | Which telemetry and governance inputs must feed the dashboard? |

## Suggested operating cadence

- **Daily during active response:** update patch/reboot compliance, high-value unknown posture, suspicious escalation investigations, and overdue exceptions.
- **Twice weekly during stabilization:** update module-exposure review, detection telemetry coverage, and workstream status.
- **Weekly until closure:** report residual risk, exceptions, and long-tail remediation to the risk committee.

## Data dictionary

| JSON field | Meaning | Source candidate |
| --- | --- | --- |
| `risk_posture.overall_risk` | Executive risk rating for the enterprise Linux estate. | CISO/risk owner assessment |
| `kri_cards[].value` | Current measured value or `TBD` while inventory is being populated. | Vulnerability management, EDR, SIEM, GRC |
| `kri_cards[].target` | Desired threshold or closure criterion. | Risk acceptance policy |
| `kri_cards[].status` | Dashboard color state: `on-track`, `in-progress`, `needs-data`, `not-started`, `blocked`, or `overdue`. | Program management |
| `priority_asset_segments[]` | Asset classes that drive remediation sequencing. | CMDB, cloud inventory, Kubernetes inventory |
| `workstreams[]` | Remediation and governance work packages. | Program tracker |
| `decision_gates[]` | Executive action thresholds for patching, exceptions, and incident response. | Incident response and risk policy |
| `data_sources[]` | Required data feeds for credible dashboard reporting. | Security architecture / SOC |

## Initial executive thresholds

Use these starting thresholds until the organization replaces them with formal risk appetite values:

- **Patch and reboot compliance:** at least 95% of prioritized Linux assets booted into vendor-remediated kernels.
- **High-value unknown posture:** zero internet-facing or crown-jewel Linux hosts with unknown kernel posture.
- **Unauthorized module exposure:** zero high-value hosts with `esp4`, `esp6`, or `rxrpc` loaded or loadable without documented business need.
- **Telemetry coverage:** at least 90% of prioritized hosts reporting process, file, auth, module, and kernel inventory telemetry.
- **Investigation SLA:** all suspicious local staging plus root-transition alerts triaged within the incident-response SLA.
- **Risk exceptions:** zero overdue exceptions; every active exception has owner approval and a committed remediation date.

## Integration guidance

1. Populate the JSON from authoritative sources rather than manual estimates where possible.
2. Keep `TBD` values visible until data feeds are connected; unknown posture should be treated as risk, not as compliance.
3. Link KRI exceptions to named asset owners and remediation dates.
4. Use the dashboard with the CISO risk assessment in [`docs/ciso-risk-assessment-dirtyfrag.md`](ciso-risk-assessment-dirtyfrag.md), the attack path in [`docs/attack-path-dirtyfrag.md`](attack-path-dirtyfrag.md), and the detection content under [`detections/`](../detections/).
5. Do not use the dashboard as proof of non-exploitation; use it to prioritize remediation, validate detection coverage, and trigger incident-response review when thresholds are breached.

## Safety boundary

The dashboard is defensive and executive-facing. It tracks exposure, remediation, detection coverage, and exception governance. It does not contain exploit instructions, kernel exploitation mechanics, or offensive guidance.
