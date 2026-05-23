#!/usr/bin/env python3
"""
PAN-OS 12 Red Team Assessment Tool
For authorized penetration testing engagements only.

Modules:
  1. Network recon  — port scan, banner grab, HTTP fingerprint
  2. CVE checks     — passive indicators for known PAN-OS vulnerabilities
  3. Config audit   — XML API pull + misconfiguration analysis
"""

import argparse
import http.client
import json
import logging
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER = """\
╔══════════════════════════════════════════════════════════════╗
║          PAN-OS 12 Red Team Assessment Tool                 ║
║          Authorized Penetration Testing Only                ║
╚══════════════════════════════════════════════════════════════╝

LEGAL NOTICE: This tool is for authorized security assessments only.
Unauthorized use against systems you do not own or have explicit written
permission to test is illegal and unethical.
"""

PANOS_PORTS = {
    22: "SSH",
    443: "HTTPS/Web-UI",
    3978: "GlobalProtect",
    4443: "GlobalProtect-Alt",
    8443: "HTTPS-Alt",
    8080: "HTTP-Alt",
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool, log_file: str = None):
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module 1 — Network Recon
# ---------------------------------------------------------------------------

class ReconModule:
    def __init__(self, target: str, timeout: int = 5):
        self.target = target
        self.timeout = timeout

    def port_scan(self, ports: list = None) -> dict:
        ports = ports or list(PANOS_PORTS.keys())
        log.info(f"[RECON] Scanning {self.target} — ports {ports}")
        results = {}
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(self._probe_port, p): p for p in ports}
            for fut in as_completed(futures):
                port = futures[fut]
                open_, banner = fut.result()
                svc = PANOS_PORTS.get(port, "unknown")
                results[port] = {"open": open_, "service": svc, "banner": banner}
                if open_:
                    log.info(f"[RECON]   {self.target}:{port} ({svc}) OPEN  {banner}")
                else:
                    log.debug(f"[RECON]   {self.target}:{port} ({svc}) closed")
        return results

    def _probe_port(self, port: int) -> tuple:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((self.target, port)) == 0:
                banner = self._grab_banner(port)
                sock.close()
                return True, banner
            sock.close()
        except Exception:
            pass
        return False, ""

    def _grab_banner(self, port: int) -> str:
        try:
            if port == 22:
                s = socket.create_connection((self.target, port), timeout=2)
                raw = s.recv(256)
                s.close()
                return raw.decode("utf-8", errors="ignore").strip()
            if port in (443, 4443, 8443):
                return self._tls_cert_info(port)
        except Exception:
            pass
        return ""

    def _tls_cert_info(self, port: int) -> str:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                cert = s.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                cn = subject.get("commonName", "?")
                org = issuer.get("organizationName", "?")
                return f"TLS CN={cn} issuer={org}"
        except Exception as e:
            return f"TLS error: {e}"

    def http_fingerprint(self, port: int = 443) -> dict:
        """Fetch the management login page and extract version hints."""
        log.info(f"[RECON] HTTP fingerprinting {self.target}:{port}")
        result: dict = {}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://{self.target}:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                body = resp.read(8192).decode("utf-8", errors="ignore")
                result["headers"] = dict(resp.headers)
                result["panos_detected"] = (
                    "palo alto" in body.lower() or "pan-os" in body.lower()
                )
                result["version_hint"] = _extract_panos_version(body, result["headers"])
                if result["panos_detected"]:
                    log.info(
                        f"[RECON] PAN-OS detected. Version hint: "
                        f"{result['version_hint'] or 'not found in page'}"
                    )
        except Exception as e:
            result["error"] = str(e)
            log.debug(f"[RECON] HTTP fingerprint failed: {e}")
        return result


def _extract_panos_version(body: str, headers: dict) -> str:
    import re

    patterns = [
        r"PAN-OS[^<\"]*?([\d]+\.[\d]+\.[\d.-]+)",
        r"sw-version[\"']?\s*[=:]\s*[\"']?([\d]+\.[\d]+\.[\d.-]+)",
    ]
    for pat in patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# Module 2 — CVE Checks
# ---------------------------------------------------------------------------

class CVEModule:
    """
    Passive / low-impact indicator checks for known PAN-OS CVEs.
    No payloads that would cause crashes or data modification are sent.
    """

    def __init__(self, target: str, port: int = 443, timeout: int = 10):
        self.target = target
        self.port = port
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _req(self, path: str, method: str = "GET",
             body: bytes = None, extra_headers: dict = None):
        """Returns (status, headers_dict, body_str). Returns (0, {}, err) on failure."""
        try:
            conn = http.client.HTTPSConnection(
                self.target, self.port, timeout=self.timeout, context=self._ctx
            )
            hdrs = {"User-Agent": "Mozilla/5.0", "Connection": "close"}
            if extra_headers:
                hdrs.update(extra_headers)
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read(16384).decode("utf-8", errors="ignore")
            return resp.status, dict(resp.getheaders()), data
        except Exception as exc:
            return 0, {}, str(exc)

    # ------------------------------------------------------------------
    # CVE-2025-0108 — Unauthenticated PHP invocation via path confusion
    # Nginx/Apache path normalization mismatch lets attackers call internal
    # PHP scripts without credentials.
    # Affected: PAN-OS < 11.2.4-h4, < 11.1.6-h1, < 10.2.13-h3, < 10.1.14-h9
    # Ref: https://security.paloaltonetworks.com/CVE-2025-0108
    # ------------------------------------------------------------------
    def check_cve_2025_0108(self) -> dict:
        cve = "CVE-2025-0108"
        log.info(f"[CVE] {cve} — auth bypass via PHP path confusion")
        result = {"cve": cve, "status": "not_detected", "evidence": ""}

        probe_paths = [
            "/unauth/php/mgmt.php",
            "/..;/unauth/php/mgmt.php",
            "/php/utils/debug.php",
        ]
        for path in probe_paths:
            status, _, body = self._req(path)
            log.debug(f"[CVE] {cve} probe {path!r} → {status}")
            if status in (200, 500) and len(body) > 50:
                result["status"] = "indicator_present"
                result["evidence"] = f"Unexpected response (HTTP {status}) for {path}"
                log.warning(f"[CVE] {cve} INDICATOR — {result['evidence']}")
                return result

        log.info(f"[CVE] {cve} — no indicator (patched or not exposed)")
        return result

    # ------------------------------------------------------------------
    # CVE-2024-0012 — Management web-interface authentication bypass
    # Header manipulation allows unauthenticated access to admin panel.
    # Combined with CVE-2024-9474 for root RCE chain.
    # Affected: PAN-OS 10.2, 11.0, 11.1, 11.2 (pre-patch)
    # Ref: https://security.paloaltonetworks.com/CVE-2024-0012
    # ------------------------------------------------------------------
    def check_cve_2024_0012(self) -> dict:
        cve = "CVE-2024-0012"
        log.info(f"[CVE] {cve} — management interface auth bypass")
        result = {"cve": cve, "status": "not_detected", "evidence": ""}

        status, _, body = self._req(
            "/php/login.php",
            extra_headers={"X-PAN-AUTHCHECK": "off"},
        )
        log.debug(f"[CVE] {cve} X-PAN-AUTHCHECK probe → {status}")
        keywords = ("dashboard", "panorama", "device", "vsys", "commit")
        if status == 200 and any(kw in body.lower() for kw in keywords):
            result["status"] = "indicator_present"
            result["evidence"] = (
                "Admin panel content returned with X-PAN-AUTHCHECK:off — "
                "auth bypass likely present"
            )
            log.warning(f"[CVE] {cve} INDICATOR — {result['evidence']}")
        else:
            log.info(f"[CVE] {cve} — no indicator detected")
        return result

    # ------------------------------------------------------------------
    # CVE-2024-3400 — GlobalProtect SESSID command injection (CVSS 10.0)
    # Unauthenticated OS command injection via crafted cookie in GP daemon.
    # Affected: 10.2.x < 10.2.9-h1 | 11.0.x < 11.0.4-h1 | 11.1.x < 11.1.2-h3
    # Ref: https://security.paloaltonetworks.com/CVE-2024-3400
    # NOTE: Active exploitation deferred to authenticated follow-up phase.
    # ------------------------------------------------------------------
    def check_cve_2024_3400(self) -> dict:
        cve = "CVE-2024-3400"
        log.info(f"[CVE] {cve} — GlobalProtect command injection (passive check)")
        result = {"cve": cve, "status": "not_detected", "evidence": ""}

        gp_paths = [
            "/ssl-vpn/login.esp",
            "/global-protect/login.esp",
            "/global-protect/",
        ]
        for path in gp_paths:
            status, _, body = self._req(path)
            log.debug(f"[CVE] {cve} GP probe {path!r} → {status}")
            if status == 200 and (
                "globalprotect" in body.lower() or "global-protect" in body.lower()
            ):
                result["status"] = "attack_surface_present"
                result["evidence"] = (
                    f"GlobalProtect interface exposed at {path}. "
                    "Confirm patch level: >= 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3 required. "
                    "Session-telemetry must also be disabled if unpatched."
                )
                log.warning(f"[CVE] {cve} — {result['evidence']}")
                return result

        log.info(f"[CVE] {cve} — GlobalProtect interface not detected on tested paths")
        return result

    # ------------------------------------------------------------------
    # CVE-2024-9474 — Post-auth privilege escalation to root
    # Chained with CVE-2024-0012 for unauthenticated root RCE.
    # Affected: < 10.1.14-h6, < 10.2.12, < 11.0.6, < 11.1.5, < 11.2.3
    # Ref: https://security.paloaltonetworks.com/CVE-2024-9474
    # ------------------------------------------------------------------
    def check_cve_2024_9474(self) -> dict:
        cve = "CVE-2024-9474"
        log.info(f"[CVE] {cve} — post-auth privilege escalation (informational)")
        return {
            "cve": cve,
            "status": "informational",
            "evidence": (
                "Requires valid admin credentials (or CVE-2024-0012 bypass). "
                "Patch: PAN-OS >= 10.1.14-h6 / 10.2.12 / 11.0.6 / 11.1.5 / 11.2.3."
            ),
        }

    # ------------------------------------------------------------------
    # CVE-2025-0111 — Authenticated file read via management web interface
    # Authenticated attacker with network access to the management interface
    # can read files readable by the 'nobody' user.
    # Affected: PAN-OS < 11.2.4-h4, < 11.1.6-h1, < 10.2.13-h3
    # Ref: https://security.paloaltonetworks.com/CVE-2025-0111
    # ------------------------------------------------------------------
    def check_cve_2025_0111(self) -> dict:
        cve = "CVE-2025-0111"
        log.info(f"[CVE] {cve} — authenticated arbitrary file read")
        result = {"cve": cve, "status": "not_detected", "evidence": ""}

        # Passive: check if management web interface is reachable (precondition)
        status, hdrs, body = self._req("/php/login.php")
        log.debug(f"[CVE] {cve} management probe → {status}")
        if status == 200 and "pan" in body.lower():
            result["status"] = "precondition_met"
            result["evidence"] = (
                "Management web interface reachable. "
                "File read exploitable with valid credentials. "
                "Patch: PAN-OS >= 11.2.4-h4 / 11.1.6-h1 / 10.2.13-h3."
            )
            log.warning(f"[CVE] {cve} — {result['evidence']}")
        else:
            log.info(f"[CVE] {cve} — management interface not reachable at /php/login.php")
        return result

    def run_all(self) -> list:
        checks = [
            self.check_cve_2025_0108,
            self.check_cve_2024_0012,
            self.check_cve_2024_3400,
            self.check_cve_2024_9474,
            self.check_cve_2025_0111,
        ]
        results = []
        for fn in checks:
            results.append(fn())
        return results


# ---------------------------------------------------------------------------
# Module 3 — Config Audit (XML API)
# ---------------------------------------------------------------------------

class ConfigAuditModule:
    """
    Pulls running config via PAN-OS XML API and audits for misconfigurations.
    Requires an API key — generate one with:
      curl -k "https://<fw>/api/?type=keygen&user=<u>&password=<p>"
    """

    def __init__(self, target: str, api_key: str, port: int = 443, timeout: int = 20):
        self.target = target
        self.api_key = api_key
        self.port = port
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _api(self, params: dict) -> ET.Element:
        params["key"] = self.api_key
        url = (
            f"https://{self.target}:{self.port}/api/?"
            + urllib.parse.urlencode(params)
        )
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as r:
            return ET.fromstring(r.read())

    def get_system_info(self) -> dict:
        log.info("[AUDIT] Fetching system info")
        root = self._api(
            {"type": "op", "cmd": "<show><system><info></info></system></show>"}
        )
        info = {}
        for el in root.iter():
            if el.text and el.text.strip() and el.tag not in ("response", "result", "system"):
                info[el.tag] = el.text.strip()
        log.info(
            f"[AUDIT] Host={info.get('hostname','?')}  "
            f"Version={info.get('sw-version','?')}  "
            f"Model={info.get('model','?')}"
        )
        return info

    def get_running_config(self) -> ET.Element:
        log.info("[AUDIT] Pulling running config via XML API")
        return self._api({"type": "config", "action": "show"})

    # --- individual audit checks ---

    def _audit_security_rules(self, config: ET.Element) -> list:
        findings = []
        rules = config.findall(".//security/rules/entry")
        log.info(f"[AUDIT] Checking {len(rules)} security rules")
        for rule in rules:
            name = rule.get("name", "?")
            action = rule.findtext("action", "")
            srcs = [m.text for m in rule.findall("source/member")]
            dsts = [m.text for m in rule.findall("destination/member")]
            threat_prof = rule.findtext(
                "profile-setting/profiles/virus/member"
            ) or rule.findtext("profile-setting/group/member")
            url_prof = rule.findtext("profile-setting/profiles/url-filtering/member")

            if action == "allow" and "any" in srcs and "any" in dsts:
                findings.append({
                    "severity": "HIGH",
                    "check": "any_any_allow",
                    "rule": name,
                    "detail": f"Rule '{name}': allow from any → any is overly permissive",
                })
                log.warning(f"[AUDIT] HIGH  any_any_allow in rule '{name}'")

            if action == "allow" and not threat_prof:
                findings.append({
                    "severity": "MEDIUM",
                    "check": "missing_threat_profile",
                    "rule": name,
                    "detail": f"Rule '{name}': allow without a threat prevention profile",
                })

            if action == "allow" and not url_prof:
                findings.append({
                    "severity": "LOW",
                    "check": "missing_url_filtering",
                    "rule": name,
                    "detail": f"Rule '{name}': allow without a URL filtering profile",
                })
        return findings

    def _audit_management(self, config: ET.Element) -> list:
        findings = []
        # Telnet / HTTP plaintext services
        for svc, check in (("disable-telnet", "telnet_enabled"), ("disable-http", "http_enabled")):
            if config.find(f".//service/{svc}") is None:
                sev = "HIGH" if svc == "disable-telnet" else "HIGH"
                findings.append({
                    "severity": sev,
                    "check": check,
                    "detail": f"Management service '{svc.replace('disable-','')}' not explicitly disabled",
                })
                log.warning(f"[AUDIT] {sev}  {check}")

        # Source IP restrictions
        permitted = config.findall(".//permitted-ip/entry")
        if not permitted:
            findings.append({
                "severity": "CRITICAL",
                "check": "mgmt_unrestricted",
                "detail": "Management interface has no permitted-ip restrictions (accessible from any source)",
            })
            log.warning("[AUDIT] CRITICAL  mgmt_unrestricted")
        return findings

    def _audit_admins(self, config: ET.Element) -> list:
        findings = []
        admins = config.findall(".//mgt-config/users/entry")
        log.info(f"[AUDIT] Checking {len(admins)} admin accounts")
        for admin in admins:
            name = admin.get("name", "?")
            auth_profile = admin.findtext("authentication-profile", "")
            mfa_el = admin.find("mfa-enable")
            mfa_enabled = mfa_el is not None and mfa_el.text == "yes"
            if not auth_profile and not mfa_enabled:
                findings.append({
                    "severity": "HIGH",
                    "check": "admin_no_mfa",
                    "admin": name,
                    "detail": f"Admin '{name}' has no MFA or authentication-profile configured",
                })
                log.warning(f"[AUDIT] HIGH  admin_no_mfa for '{name}'")
        return findings

    def _audit_snmp(self, config: ET.Element) -> list:
        findings = []
        for version_tag in (".//snmp-setting/access-setting/version/v2c",
                            ".//snmp-setting/access-setting/version/v1"):
            if config.find(version_tag) is not None:
                findings.append({
                    "severity": "MEDIUM",
                    "check": "snmp_v1v2",
                    "detail": f"SNMP {version_tag.split('/')[-1]} enabled — migrate to SNMPv3 with authPriv",
                })
                log.warning("[AUDIT] MEDIUM  snmp_v1v2 configured")
        return findings

    def _audit_syslog(self, config: ET.Element) -> list:
        findings = []
        profiles = config.findall(".//syslog/entry")
        for prof in profiles:
            name = prof.get("name", "?")
            transport = prof.findtext("transport", "UDP")
            if transport.upper() != "SSL":
                findings.append({
                    "severity": "MEDIUM",
                    "check": "syslog_no_tls",
                    "profile": name,
                    "detail": f"Syslog profile '{name}' uses {transport} — should use SSL/TLS",
                })
                log.warning(f"[AUDIT] MEDIUM  syslog_no_tls in profile '{name}'")
        return findings

    def run_audit(self) -> dict:
        try:
            sysinfo = self.get_system_info()
        except Exception as e:
            return {"error": f"API authentication failed: {e}"}

        try:
            config = self.get_running_config()
        except Exception as e:
            return {"sysinfo": sysinfo, "error": f"Config pull failed: {e}"}

        findings = []
        findings.extend(self._audit_security_rules(config))
        findings.extend(self._audit_management(config))
        findings.extend(self._audit_admins(config))
        findings.extend(self._audit_snmp(config))
        findings.extend(self._audit_syslog(config))

        _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: _sev_rank.get(f.get("severity", "LOW"), 4))

        return {
            "sysinfo": sysinfo,
            "findings": findings,
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
                "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
                "medium": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
                "low": sum(1 for f in findings if f.get("severity") == "LOW"),
            },
        }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_summary(results: dict):
    sep = "=" * 64
    print(f"\n{sep}")
    print("  ASSESSMENT SUMMARY")
    print(sep)
    print(f"  Target    : {results.get('target')}")
    print(f"  Timestamp : {results.get('timestamp')}")

    recon = results.get("recon", {})
    open_ports = sorted(
        p for p, d in recon.get("ports", {}).items() if d.get("open")
    )
    fp = recon.get("fingerprint", {})
    print(f"  Open ports: {open_ports}")
    print(f"  PAN-OS     : {'detected' if fp.get('panos_detected') else 'not confirmed'}"
          f"  (version hint: {fp.get('version_hint') or 'n/a'})")

    cve_results = results.get("cve", [])
    flagged = [
        r["cve"] for r in cve_results
        if r.get("status") in ("indicator_present", "attack_surface_present", "precondition_met")
    ]
    print(f"  CVEs flagged: {', '.join(flagged) if flagged else 'none'}")

    audit_summary = results.get("audit", {}).get("summary", {})
    if audit_summary:
        print(
            f"  Config findings: {audit_summary['total']} total  "
            f"({audit_summary['critical']} critical / "
            f"{audit_summary['high']} high / "
            f"{audit_summary['medium']} medium / "
            f"{audit_summary['low']} low)"
        )
    print(sep + "\n")


def write_report(results: dict, path: str):
    with open(path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)
    log.info(f"[REPORT] JSON report saved to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _confirm_authorization(target: str) -> bool:
    print(BANNER)
    print(f"  Target : {target}")
    print(f"  Time   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n")
    answer = input(
        "  Confirm you have written authorization to test this target [yes/no]: "
    ).strip().lower()
    return answer == "yes"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="PAN-OS 12 Red Team Assessment — authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="Target hostname or IP")
    p.add_argument("--port", type=int, default=443, help="Management HTTPS port (default 443)")
    p.add_argument("--timeout", type=int, default=10, help="Socket timeout in seconds (default 10)")
    p.add_argument("--api-key", metavar="KEY", help="PAN-OS XML API key for config audit")
    p.add_argument("--skip-recon", action="store_true", help="Skip network recon phase")
    p.add_argument("--skip-cve", action="store_true", help="Skip CVE check phase")
    p.add_argument("--skip-audit", action="store_true", help="Skip config audit (requires --api-key)")
    p.add_argument("-o", "--output", metavar="FILE", help="Write JSON report to FILE")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug-level logging")
    p.add_argument("--no-confirm", action="store_true",
                   help="Skip interactive authorization prompt (CI/scripted use)")
    return p


def main():
    args = _build_parser().parse_args()

    if not args.no_confirm and not _confirm_authorization(args.target):
        print("\n[ABORT] Authorization not confirmed. Exiting.")
        sys.exit(1)

    log_file = args.output.replace(".json", ".log") if args.output else None
    setup_logging(args.verbose, log_file)

    results: dict = {
        "target": args.target,
        "port": args.port,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    if not args.skip_recon:
        log.info("[*] Phase 1 — Network Recon")
        recon = ReconModule(args.target, timeout=args.timeout)
        results["recon"] = {
            "ports": recon.port_scan(),
            "fingerprint": recon.http_fingerprint(args.port),
        }

    if not args.skip_cve:
        log.info("[*] Phase 2 — CVE Checks")
        cve = CVEModule(args.target, port=args.port, timeout=args.timeout)
        results["cve"] = cve.run_all()

    if not args.skip_audit:
        if not args.api_key:
            log.warning("[*] Phase 3 — Config Audit SKIPPED (no --api-key provided)")
        else:
            log.info("[*] Phase 3 — Config Audit")
            audit = ConfigAuditModule(
                args.target, args.api_key, port=args.port, timeout=args.timeout
            )
            results["audit"] = audit.run_audit()

    print_summary(results)

    if args.output:
        write_report(results, args.output)

    log.info("[*] Assessment complete")


if __name__ == "__main__":
    main()
