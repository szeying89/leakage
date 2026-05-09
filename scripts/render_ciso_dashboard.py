#!/usr/bin/env python3
"""Render the Dirty Frag CISO dashboard JSON to self-contained HTML."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

STATUS_CLASS = {
    "on-track": "good",
    "in-progress": "warn",
    "needs-data": "warn",
    "not-started": "warn",
    "blocked": "bad",
    "overdue": "bad",
}


def escape(value: object) -> str:
    """HTML-escape a value for safe static rendering."""

    return html.escape(str(value), quote=True)


def load_dashboard(path: Path) -> dict[str, Any]:
    """Load dashboard source data."""

    return json.loads(path.read_text(encoding="utf-8"))


def render_metric_cards(cards: list[dict[str, str]]) -> str:
    rows = []
    for card in cards:
        status = STATUS_CLASS.get(card.get("status", "needs-data"), "warn")
        rows.append(
            f'''<section class="card {status}">
  <h3>{escape(card["name"])}</h3>
  <p class="value">{escape(card["value"])}</p>
  <p><strong>Target:</strong> {escape(card["target"])}</p>
  <p><strong>Owner:</strong> {escape(card["owner"])}</p>
</section>'''
        )
    return "\n".join(rows)


def render_table(items: list[dict[str, str]], columns: list[tuple[str, str]]) -> str:
    header = "".join(f"<th>{escape(label)}</th>" for _, label in columns)
    rows = []
    for item in items:
        cells = "".join(f"<td>{escape(item.get(key, ''))}</td>" for key, _ in columns)
        rows.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def render_dashboard(data: dict[str, Any]) -> str:
    """Render dashboard data to a self-contained HTML document."""

    posture = data["risk_posture"]
    asset_table = render_table(
        data["priority_asset_segments"],
        [
            ("segment", "Asset segment"),
            ("business_risk", "Business risk"),
            ("priority", "Priority"),
            ("required_action", "Required action"),
        ],
    )
    workstream_table = render_table(
        data["workstreams"],
        [
            ("name", "Workstream"),
            ("phase", "Phase"),
            ("status", "Status"),
            ("success_measure", "Success measure"),
        ],
    )
    decision_table = render_table(
        data["decision_gates"],
        [("condition", "Condition"), ("decision", "CISO decision")],
    )
    sources = "".join(f"<li>{escape(source)}</li>" for source in data["data_sources"])

    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(data["title"])}</title>
  <style>
    :root {{ --bg: #0f172a; --panel: #111827; --muted: #cbd5e1; --text: #f8fafc; --good: #166534; --warn: #92400e; --bad: #991b1b; --line: #334155; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); font-family: Arial, sans-serif; line-height: 1.45; }}
    header, main {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
    header {{ border-bottom: 1px solid var(--line); }}
    h1, h2, h3 {{ margin-top: 0; }}
    .subtitle {{ color: var(--muted); max-width: 920px; }}
    .posture, .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }}
    .tile, .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px; }}
    .tile strong, .value {{ display: block; font-size: 1.8rem; margin-top: 6px; }}
    .good {{ border-top: 5px solid var(--good); }} .warn {{ border-top: 5px solid var(--warn); }} .bad {{ border-top: 5px solid var(--bad); }}
    table {{ border-collapse: collapse; width: 100%; background: var(--panel); margin-bottom: 28px; }}
    th, td {{ border: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #1e293b; }}
    section {{ margin: 28px 0; }}
    .notice {{ border-left: 5px solid #38bdf8; background: #0b1220; padding: 12px 16px; color: var(--muted); }}
  </style>
</head>
<body>
  <header>
    <h1>{escape(data["title"])}</h1>
    <p class="subtitle">As of {escape(data["as_of"])}. {escape(posture["executive_summary"])}</p>
  </header>
  <main>
    <section>
      <h2>Executive risk posture</h2>
      <div class="posture">
        <div class="tile bad"><span>Overall risk</span><strong>{escape(posture["overall_risk"])}</strong></div>
        <div class="tile warn"><span>Likelihood</span><strong>{escape(posture["likelihood"])}</strong></div>
        <div class="tile bad"><span>Impact</span><strong>{escape(posture["impact"])}</strong></div>
        <div class="tile bad"><span>Urgency</span><strong>{escape(posture["urgency"])}</strong></div>
        <div class="tile warn"><span>Confidence</span><strong>{escape(posture["confidence"])}</strong></div>
      </div>
    </section>
    <section>
      <h2>Key risk indicators</h2>
      <div class="cards">{render_metric_cards(data["kri_cards"])}</div>
    </section>
    <section>
      <h2>Priority asset segments</h2>
      {asset_table}
    </section>
    <section>
      <h2>Remediation workstreams</h2>
      {workstream_table}
    </section>
    <section>
      <h2>CISO decision gates</h2>
      {decision_table}
    </section>
    <section>
      <h2>Required data sources</h2>
      <ul>{sources}</ul>
    </section>
    <p class="notice">This dashboard is defensive and executive-facing. It tracks exposure, remediation, detection coverage, and exception governance; it does not include exploit steps or offensive guidance.</p>
  </main>
</body>
</html>
'''


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render the Dirty Frag CISO dashboard.")
    parser.add_argument("--input", type=Path, default=Path("dashboards/dirtyfrag_ciso_dashboard.json"))
    parser.add_argument("--output", type=Path, default=Path("dashboards/dirtyfrag_ciso_dashboard.html"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dashboard = render_dashboard(load_dashboard(args.input))
    args.output.write_text(dashboard, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
