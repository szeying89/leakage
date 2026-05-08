#!/usr/bin/env python3
"""Local DFIR triage helper for CVE-2026-23918 evidence.

The script scans copied logs or evidence exports for defensive indicators aligned
with the repository's CVE-2026-23918 attack path. It does not contact targets,
generate network traffic, send HTTP/2 frames, or attempt exploitation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

CVE_ID = "CVE-2026-23918"
DEFAULT_LOOKBACK = "2026-05-04T00:00:00Z"
MAX_LINE_BYTES = 20000

RULES = [
    {
        "name": "exposure_apache_2466_http2",
        "stage": "exposure",
        "severity": "high",
        "description": "Apache 2.4.66 or HTTP/2 exposure indicator",
        "patterns": [
            r"Apache(?:/| HTTP Server\s+)(?:2\.4\.66)",
            r"\bhttpd\b.*\b2\.4\.66\b",
            r"\bapache2\b.*\b2\.4\.66\b",
            r"\bmod_http2\b",
            r"\bProtocols\b.*\bh2\b",
            r"\bALPN\b.*\bh2\b",
        ],
    },
    {
        "name": "http2_reset_or_aborted_stream",
        "stage": "attempt",
        "severity": "medium",
        "description": "HTTP/2 reset, aborted stream, or GOAWAY-like anomaly",
        "patterns": [
            r"\bRST_STREAM\b",
            r"\bGOAWAY\b",
            r"\bHTTP/2\b.*\b(reset|aborted|abort|stream error|closed stream)\b",
            r"\bh2\b.*\b(reset|aborted|abort|stream error|closed stream)\b",
            r"\breset_stream\b",
        ],
    },
    {
        "name": "apache_crash_allocator_or_core",
        "stage": "crash_or_dos",
        "severity": "critical",
        "description": "Apache crash, allocator corruption, double-free, or core dump indicator",
        "patterns": [
            r"\b(segmentation fault|segfault)\b.*\b(httpd|apache2|apache)\b",
            r"\b(httpd|apache2|apache)\b.*\b(segmentation fault|segfault)\b",
            r"\b(double free|free\(\):|corrupted double-linked list|malloc\(\):|munmap_chunk)\b",
            r"\bcore dumped\b.*\b(httpd|apache2|apache)\b",
            r"\bchild pid \d+ exit signal\b",
            r"\bAH\d+\b.*\b(crash|segfault|core|restart)\b",
        ],
    },
    {
        "name": "apache_worker_restart_loop",
        "stage": "crash_or_dos",
        "severity": "high",
        "description": "Apache worker restart loop or abnormal service recovery",
        "patterns": [
            r"\b(httpd|apache2|apache)\b.*\b(restart|restarted|graceful restart)\b",
            r"\bserver reached MaxRequestWorkers\b",
            r"\bexiting, seg fault or similar nasty error detected\b",
            r"\bwatchdog\b.*\b(httpd|apache2|apache)\b.*\brestart\b",
        ],
    },
    {
        "name": "suspicious_apache_child_process",
        "stage": "post_exploitation",
        "severity": "critical",
        "description": "Apache service account or process spawning suspicious child utilities",
        "patterns": [
            r"\b(parent|ppid|ancestor)[=: ]+(httpd|apache2|apache)\b.*\b(cmd|command|process)[=: ].*\b(sh|bash|dash|zsh|python|python3|perl|ruby|php|lua|node|nc|ncat|socat|curl|wget|ssh|scp|chmod|chown|useradd|sudo)\b",
            r"\b(user|uid)[=: ]+(www-data|apache|httpd|daemon)\b.*\b(process|cmd|command)[=: ].*\b(sh|bash|python|perl|nc|curl|wget|ssh|chmod|useradd|sudo)\b",
            r"\b(httpd|apache2|apache)\b.*\bspawn(ed)?\b.*\b(shell|interpreter|curl|wget|nc|ncat|socat)\b",
        ],
    },
    {
        "name": "outbound_network_from_apache",
        "stage": "post_exploitation",
        "severity": "high",
        "description": "Unexpected outbound network connection attributed to Apache",
        "patterns": [
            r"\b(process|image|program)[=: ]+(httpd|apache2|apache)\b.*\b(dst|dest|destination|remote)[=: ]",
            r"\b(user|uid)[=: ]+(www-data|apache|httpd|daemon)\b.*\b(connect|connection|outbound|egress|dns)\b",
            r"\b(httpd|apache2|apache)\b.*\b(outbound|egress|connect(ed)? to|dns query)\b",
        ],
    },
    {
        "name": "sensitive_file_access_by_apache",
        "stage": "post_exploitation",
        "severity": "high",
        "description": "Apache accessing credential, token, key, or sensitive configuration paths",
        "patterns": [
            r"\b(httpd|apache2|apache|www-data)\b.*(/etc/passwd|/etc/shadow|\.env|id_rsa|id_dsa|private\.key|\.pem|credentials|secrets?|tokens?|config\.php|settings\.py|database\.yml)",
            r"(/etc/passwd|/etc/shadow|\.env|id_rsa|id_dsa|private\.key|\.pem|credentials|secrets?|tokens?|config\.php|settings\.py|database\.yml).*\b(httpd|apache2|apache|www-data)\b",
        ],
    },
    {
        "name": "webroot_executable_modification",
        "stage": "post_exploitation",
        "severity": "high",
        "description": "Executable or script content created or modified in web roots or Apache module paths",
        "patterns": [
            r"\b(create|created|modify|modified|write|wrote|rename|chmod)\b.*(/var/www|/srv/www|/usr/local/apache|htdocs|modules).*\.(php|phtml|jsp|jspx|asp|aspx|cgi|pl|py|sh|so)\b",
            r"(/var/www|/srv/www|/usr/local/apache|htdocs|modules).*\.(php|phtml|jsp|jspx|asp|aspx|cgi|pl|py|sh|so)\b.*\b(create|created|modify|modified|write|wrote|chmod)\b",
        ],
    },
]

SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}
TEXT_SUFFIXES = {
    "",
    ".conf",
    ".csv",
    ".err",
    ".json",
    ".jsonl",
    ".log",
    ".out",
    ".text",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


@dataclass
class Finding:
    rule: str
    stage: str
    severity: str
    description: str
    file: str
    line_number: int
    timestamp: str | None
    sha256: str
    excerpt: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan local logs/evidence for CVE-2026-23918 DFIR triage indicators. "
            "This is a defensive offline analyzer and does not generate network traffic."
        )
    )
    parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        type=Path,
        help="One or more files or directories containing copied evidence/log exports.",
    )
    parser.add_argument(
        "--since",
        default=DEFAULT_LOOKBACK,
        help="ISO-8601 timestamp used for report context. Lines are not discarded when timestamps cannot be parsed.",
    )
    parser.add_argument("--json-output", type=Path, help="Optional path for JSON findings output.")
    parser.add_argument("--markdown-output", type=Path, help="Optional path for Markdown report output.")
    parser.add_argument(
        "--max-findings-per-rule",
        type=int,
        default=50,
        help="Maximum findings retained per rule to keep reports readable. Default: 50.",
    )
    return parser.parse_args()


def compile_rules() -> list[dict[str, object]]:
    compiled = []
    for rule in RULES:
        compiled.append({**rule, "compiled_patterns": [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]})
    return compiled


def iter_evidence_files(inputs: Iterable[Path]) -> Iterable[Path]:
    for path in inputs:
        if path.is_file():
            yield path
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in TEXT_SUFFIXES:
                    yield child


def is_probably_binary(path: Path) -> bool:
    sample = path.read_bytes()[:4096]
    return b"\x00" in sample


def line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()


def extract_timestamp(line: str) -> str | None:
    patterns = [
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b",
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:?\d{2}\b",
        r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b",
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(0)
    return None


def sanitize_excerpt(line: str) -> str:
    clean = " ".join(line.strip().split())
    if len(clean) > 280:
        return clean[:277] + "..."
    return clean


def scan_file(path: Path, compiled_rules: list[dict[str, object]], max_per_rule: int, counters: Counter[str]) -> list[Finding]:
    findings: list[Finding] = []
    if is_probably_binary(path):
        return findings

    retained_by_rule: Counter[str] = Counter()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if len(line.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
                line = line[:MAX_LINE_BYTES]
            for rule in compiled_rules:
                rule_name = str(rule["name"])
                compiled_patterns = rule["compiled_patterns"]
                if any(pattern.search(line) for pattern in compiled_patterns):
                    counters[rule_name] += 1
                    if retained_by_rule[rule_name] >= max_per_rule:
                        continue
                    retained_by_rule[rule_name] += 1
                    findings.append(
                        Finding(
                            rule=rule_name,
                            stage=str(rule["stage"]),
                            severity=str(rule["severity"]),
                            description=str(rule["description"]),
                            file=str(path),
                            line_number=line_number,
                            timestamp=extract_timestamp(line),
                            sha256=line_hash(line),
                            excerpt=sanitize_excerpt(line),
                        )
                    )
    return findings


def determine_outcome(findings: list[Finding]) -> tuple[str, str]:
    stages = {finding.stage for finding in findings}
    if not findings:
        return "No evidence found", "No CVE-specific indicators were found in the supplied evidence."
    if "post_exploitation" in stages and ("crash_or_dos" in stages or "attempt" in stages):
        return (
            "Compromise suspected",
            "Post-exploitation indicators appear alongside crash/attempt telemetry; validate manually and consider containment.",
        )
    if "post_exploitation" in stages:
        return (
            "Compromise suspected",
            "Post-exploitation-like indicators were found; validate parentage, user context, and application baseline.",
        )
    if "crash_or_dos" in stages and "attempt" in stages:
        return (
            "Attempted exploitation suspected",
            "HTTP/2 reset anomalies and Apache crash evidence were both observed.",
        )
    if "attempt" in stages:
        return "Attempted exploitation suspected", "HTTP/2 reset or aborted-stream anomalies were observed."
    if "exposure" in stages:
        return "Exposed, no suspicious activity", "Exposure indicators were found without crash or post-exploitation indicators."
    return "Needs manual review", "Indicators were found but do not map cleanly to a standard triage outcome."


def build_summary(findings: list[Finding], counters: Counter[str], files_scanned: int, since: str) -> dict[str, object]:
    severity_counts = Counter(finding.severity for finding in findings)
    stage_counts = Counter(finding.stage for finding in findings)
    outcome, rationale = determine_outcome(findings)
    max_score = max((SEVERITY_SCORE.get(finding.severity, 0) for finding in findings), default=0)
    return {
        "cve": CVE_ID,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "lookback_start": since,
        "files_scanned": files_scanned,
        "findings_retained": len(findings),
        "raw_rule_hits": dict(sorted(counters.items())),
        "severity_counts": dict(sorted(severity_counts.items())),
        "stage_counts": dict(sorted(stage_counts.items())),
        "highest_severity_score": max_score,
        "triage_outcome": outcome,
        "triage_rationale": rationale,
    }


def recommendations_for(summary: dict[str, object]) -> list[str]:
    outcome = str(summary["triage_outcome"])
    recommendations = [
        "Validate Apache runtime version, package history, module configuration, and whether HTTP/2 reached Apache.",
        "Correlate retained findings against EDR process trees, reverse-proxy logs, network flows, DNS, and change-management records.",
    ]
    if outcome in {"Attempted exploitation suspected", "Compromise suspected"}:
        recommendations.append("Preserve Apache logs, crash artifacts, core dumps, web roots, module directories, auth logs, and EDR telemetry before remediation.")
    if outcome == "Compromise suspected":
        recommendations.append("Consider host isolation, forensic imaging, credential rotation for secrets readable by Apache, and rebuild from trusted media.")
    if outcome == "Exposed, no suspicious activity":
        recommendations.append("Patch to Apache 2.4.67 or a vendor-fixed build, disable HTTP/2 until fixed, or prove HTTP/2 terminates at a patched proxy.")
    recommendations.append("Document manual validation decisions; this script is triage support and does not confirm exploitation by itself.")
    return recommendations


def write_json(path: Path, summary: dict[str, object], findings: list[Finding]) -> None:
    payload = {"summary": summary, "findings": [asdict(finding) for finding in findings]}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, summary: dict[str, object], findings: list[Finding]) -> None:
    by_stage: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_stage[finding.stage].append(finding)

    lines = [
        f"# {CVE_ID} DFIR Triage Report",
        "",
        f"Generated at: `{summary['generated_at']}`",
        f"Lookback start: `{summary['lookback_start']}`",
        f"Files scanned: **{summary['files_scanned']}**",
        f"Findings retained: **{summary['findings_retained']}**",
        f"Triage outcome: **{summary['triage_outcome']}**",
        "",
        f"Rationale: {summary['triage_rationale']}",
        "",
        "## Counts",
        "",
        f"- Stage counts: `{json.dumps(summary['stage_counts'], sort_keys=True)}`",
        f"- Severity counts: `{json.dumps(summary['severity_counts'], sort_keys=True)}`",
        f"- Raw rule hits: `{json.dumps(summary['raw_rule_hits'], sort_keys=True)}`",
        "",
        "## Recommendations",
        "",
    ]
    lines.extend(f"- {item}" for item in recommendations_for(summary))
    lines.extend(["", "## Findings by stage", ""])

    for stage in ["exposure", "attempt", "crash_or_dos", "post_exploitation"]:
        stage_findings = by_stage.get(stage, [])
        lines.extend([f"### {stage}", ""])
        if not stage_findings:
            lines.extend(["No retained findings for this stage.", ""])
            continue
        lines.extend(["| Severity | Rule | File:line | Timestamp | Excerpt hash | Excerpt |", "| --- | --- | --- | --- | --- | --- |"])
        for finding in stage_findings:
            excerpt = finding.excerpt.replace("|", "\\|")
            lines.append(
                f"| {finding.severity} | {finding.rule} | {finding.file}:{finding.line_number} | "
                f"{finding.timestamp or ''} | `{finding.sha256[:12]}` | {excerpt} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Handling notes",
            "",
            "- Treat findings as leads for manual validation against original evidence and known-good baselines.",
            "- Keep chain-of-custody records for copied evidence and generated reports.",
            "- The tool is defensive and offline; it does not send traffic, trigger crashes, or test exploitability.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    compiled_rules = compile_rules()
    files = list(iter_evidence_files(args.input))
    counters: Counter[str] = Counter()
    findings: list[Finding] = []

    for path in files:
        findings.extend(scan_file(path, compiled_rules, args.max_findings_per_rule, counters))

    findings.sort(key=lambda item: (item.timestamp or "", item.file, item.line_number, item.rule))
    summary = build_summary(findings, counters, len(files), args.since)

    if args.json_output:
        write_json(args.json_output, summary, findings)
    if args.markdown_output:
        write_markdown(args.markdown_output, summary, findings)

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
