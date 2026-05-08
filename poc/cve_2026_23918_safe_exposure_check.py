#!/usr/bin/env python3
"""Safe exposure checker for CVE-2026-23918.

This is a non-exploit validation helper. It checks whether a provided HTTPS
endpoint negotiates HTTP/2 via ALPN and whether passive headers expose an Apache
2.4.66 banner. It does not send crafted HTTP/2 reset traffic, malformed frames,
or any payload intended to trigger the double-free condition.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


@dataclass(frozen=True)
class CheckResult:
    url: str
    host: str
    port: int
    negotiated_protocol: Optional[str]
    server_header: Optional[str]
    risk_summary: str


def parse_target(raw_url: str) -> tuple[str, int, str]:
    parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS targets are supported because HTTP/2 exposure is checked via TLS ALPN.")
    if not parsed.hostname:
        raise ValueError("Target must include a hostname, for example https://www.example.com/.")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return parsed.hostname, parsed.port or 443, path


def fetch_banner_and_alpn(host: str, port: int, path: str, timeout: float) -> tuple[Optional[str], Optional[str]]:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])

    with socket.create_connection((host, port), timeout=timeout) as tcp_socket:
        with context.wrap_socket(tcp_socket, server_hostname=host) as tls_socket:
            negotiated_protocol = tls_socket.selected_alpn_protocol()
            # Send a minimal HTTP/1.1 HEAD request only when HTTP/1.1 is negotiated.
            # If h2 is negotiated, do not speak HTTP/2 frames; the goal is only to
            # prove HTTP/2 exposure without exercising reset handling.
            if negotiated_protocol == "h2":
                return negotiated_protocol, None

            request = (
                f"HEAD {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: cve-2026-23918-safe-exposure-check/1.0\r\n"
                "Connection: close\r\n\r\n"
            )
            tls_socket.sendall(request.encode("ascii"))
            response = tls_socket.recv(8192).decode("iso-8859-1", errors="replace")

    server_header = None
    for line in response.split("\r\n"):
        if line.lower().startswith("server:"):
            server_header = line.split(":", 1)[1].strip()
            break
    return negotiated_protocol, server_header


def summarize(negotiated_protocol: Optional[str], server_header: Optional[str]) -> str:
    http2_exposed = negotiated_protocol == "h2"
    banner_matches = bool(server_header and "Apache/2.4.66" in server_header)

    if http2_exposed and banner_matches:
        return "HIGH: endpoint negotiates HTTP/2 and exposes an Apache/2.4.66 banner; prioritize patch verification."
    if http2_exposed:
        return "MEDIUM: endpoint negotiates HTTP/2; verify Apache version through authenticated inventory."
    if banner_matches:
        return "MEDIUM: endpoint exposes Apache/2.4.66 banner; verify whether HTTP/2 reaches Apache through another listener or proxy."
    return "LOW/UNKNOWN: this passive check did not confirm both HTTP/2 exposure and an Apache/2.4.66 banner."


def run_check(raw_url: str, timeout: float) -> CheckResult:
    host, port, path = parse_target(raw_url)
    negotiated_protocol, server_header = fetch_banner_and_alpn(host, port, path, timeout)
    return CheckResult(
        url=raw_url,
        host=host,
        port=port,
        negotiated_protocol=negotiated_protocol,
        server_header=server_header,
        risk_summary=summarize(negotiated_protocol, server_header),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely check CVE-2026-23918 exposure indicators without exploit traffic."
    )
    parser.add_argument("url", help="HTTPS URL or host to check, for example https://www.example.com/")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds. Default: 5")
    args = parser.parse_args()

    try:
        result = run_check(args.url, args.timeout)
    except Exception as exc:  # noqa: BLE001 - command-line tool should print concise operator feedback.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"Target: {result.url}")
    print(f"Host: {result.host}:{result.port}")
    print(f"Negotiated ALPN protocol: {result.negotiated_protocol or 'none'}")
    print(f"Server header: {result.server_header or 'not collected or not exposed'}")
    print(f"Assessment: {result.risk_summary}")
    print("Next steps: confirm package/runtime version with authenticated inventory and upgrade to Apache HTTP Server 2.4.67 or vendor-fixed packages if affected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
