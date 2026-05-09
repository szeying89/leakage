#!/usr/bin/env python3
"""Safe Dirty Frag exposure proof-of-concept checker.

This tool intentionally does not exploit CVE-2026-43284 or CVE-2026-43500.
It demonstrates whether a host exposes the public preconditions discussed in
Microsoft's Dirty Frag advisory: presence/loading of esp4, esp6, and rxrpc
kernel modules, plus common modprobe-based mitigations.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

WATCHED_MODULES = ("esp4", "esp6", "rxrpc")
SAFE_INSTALL_TARGETS = {"/bin/false", "/usr/bin/false", "/bin/true", "/usr/bin/true"}


@dataclass(frozen=True)
class ModuleStatus:
    """Observed exposure and mitigation state for one kernel module."""

    name: str
    loaded: bool
    present_on_disk: bool
    blocked_by_install_rule: bool
    blacklisted: bool
    mitigation_files: tuple[str, ...]

    @property
    def mitigated(self) -> bool:
        return self.blocked_by_install_rule or self.blacklisted

    @property
    def exposed(self) -> bool:
        return self.loaded or (self.present_on_disk and not self.mitigated)


@dataclass(frozen=True)
class Report:
    """Complete safe exposure report."""

    kernel_release: str
    effective_uid: int
    modules: tuple[ModuleStatus, ...]
    notes: tuple[str, ...]

    @property
    def any_loaded(self) -> bool:
        return any(module.loaded for module in self.modules)

    @property
    def any_exposed(self) -> bool:
        return any(module.exposed for module in self.modules)

    @property
    def risk_level(self) -> str:
        if self.any_loaded:
            return "high"
        if self.any_exposed:
            return "medium"
        return "low"


def read_loaded_modules(proc_modules: Path = Path("/proc/modules")) -> set[str]:
    """Return module names currently loaded by the running kernel."""

    try:
        lines = proc_modules.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return set()
    return {line.split()[0] for line in lines if line.strip()}


def module_search_roots(kernel_release: str | None = None) -> tuple[Path, ...]:
    """Return filesystem roots that commonly hold kernel module objects."""

    release = kernel_release or platform.release()
    return (
        Path("/lib/modules") / release,
        Path("/usr/lib/modules") / release,
    )


def module_present(module: str, roots: Iterable[Path]) -> bool:
    """Return whether a module object appears to exist on disk."""

    patterns = (f"{module}.ko", f"{module}.ko.*")
    for root in roots:
        if not root.exists():
            continue
        for pattern in patterns:
            if any(root.rglob(pattern)):
                return True
    return False


def modprobe_config_files(roots: Iterable[Path] | None = None) -> tuple[Path, ...]:
    """Return modprobe configuration files in deterministic order."""

    search_roots = tuple(roots or (Path("/etc/modprobe.d"), Path("/run/modprobe.d"), Path("/usr/lib/modprobe.d")))
    files: list[Path] = []
    for root in search_roots:
        if root.is_dir():
            files.extend(path for path in root.glob("*.conf") if path.is_file())
    return tuple(sorted(files))


def parse_modprobe_mitigations(module: str, files: Iterable[Path]) -> tuple[bool, bool, tuple[str, ...]]:
    """Find install-deny or blacklist rules for a module.

    The parser handles common one-line rules such as:
      install esp4 /bin/false
      blacklist rxrpc
    """

    install_blocked = False
    blacklisted = False
    matched_files: list[str] = []
    install_re = re.compile(rf"^\s*install\s+{re.escape(module)}\s+(\S+)")
    blacklist_re = re.compile(rf"^\s*blacklist\s+{re.escape(module)}(?:\s|$)")

    for file_path in files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for raw_line in lines:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            install_match = install_re.match(line)
            if install_match and install_match.group(1) in SAFE_INSTALL_TARGETS:
                install_blocked = True
                matched_files.append(str(file_path))
            if blacklist_re.match(line):
                blacklisted = True
                matched_files.append(str(file_path))

    return install_blocked, blacklisted, tuple(sorted(set(matched_files)))


def build_report(
    kernel_release: str | None = None,
    proc_modules: Path = Path("/proc/modules"),
    modprobe_roots: Iterable[Path] | None = None,
    module_roots: Iterable[Path] | None = None,
) -> Report:
    """Build a safe exposure report for the current host or test fixtures."""

    release = kernel_release or platform.release()
    loaded_modules = read_loaded_modules(proc_modules)
    config_files = modprobe_config_files(modprobe_roots)
    roots = tuple(module_roots or module_search_roots(release))
    module_reports: list[ModuleStatus] = []

    for module in WATCHED_MODULES:
        install_blocked, blacklisted, mitigation_files = parse_modprobe_mitigations(module, config_files)
        module_reports.append(
            ModuleStatus(
                name=module,
                loaded=module in loaded_modules,
                present_on_disk=module_present(module, roots),
                blocked_by_install_rule=install_blocked,
                blacklisted=blacklisted,
                mitigation_files=mitigation_files,
            )
        )

    notes = (
        "This is a non-exploit PoC: it checks public exposure conditions only.",
        "Patch status is distribution-specific; verify with your vendor's kernel advisory.",
    )
    return Report(kernel_release=release, effective_uid=os.geteuid(), modules=tuple(module_reports), notes=notes)


def print_human(report: Report) -> None:
    """Print a concise operator-oriented report."""

    print("Dirty Frag safe exposure PoC")
    print(f"Kernel release : {report.kernel_release}")
    print(f"Effective UID  : {report.effective_uid}")
    print(f"Risk level     : {report.risk_level.upper()}")
    print()
    print("Module  Loaded  On disk  Mitigated  Evidence")
    print("------  ------  -------  ---------  --------")
    for module in report.modules:
        evidence = ", ".join(module.mitigation_files) if module.mitigation_files else "-"
        print(
            f"{module.name:<6}  "
            f"{str(module.loaded):<6}  "
            f"{str(module.present_on_disk):<7}  "
            f"{str(module.mitigated):<9}  "
            f"{evidence}"
        )
    print()
    for note in report.notes:
        print(f"Note: {note}")


def report_to_json(report: Report) -> str:
    """Serialize a report to stable JSON."""

    payload = asdict(report)
    payload["risk_level"] = report.risk_level
    payload["any_loaded"] = report.any_loaded
    payload["any_exposed"] = report.any_exposed
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safely demonstrate Dirty Frag exposure preconditions without exploiting the kernel."
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--kernel-release",
        help="override kernel release for fixture/testing use; defaults to the running kernel",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    report = build_report(kernel_release=args.kernel_release)
    if args.json:
        print(report_to_json(report))
    else:
        print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
