#!/usr/bin/env bash
#
# linux_privesc_enum.sh
#
# Local Linux enumeration / situational-awareness collector for AUTHORIZED
# red-team engagements and security assessments.
#
# SCOPE AND INTENT
#   This script is REPORT-ONLY. It gathers host configuration and flags
#   common local privilege-escalation vectors so an operator can document
#   them. It does NOT exploit anything, does NOT modify the system, and does
#   NOT download or execute payloads. The kernel section maps the running
#   version to KNOWN, PUBLICLY DISCLOSED CVEs as investigation pointers only
#   (the linux-exploit-suggester pattern) and contains no exploit code.
#
#   Run only on systems you are explicitly authorized to test. Record the
#   engagement authorization reference before use.
#
# USAGE
#   ./linux_privesc_enum.sh [-o report.txt] [-q]
#     -o FILE   also write the report to FILE (tee)
#     -q        quiet: suppress the section banners on stderr
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
OUT_FILE=""
QUIET=0

while getopts ":o:qh" opt; do
  case "$opt" in
    o) OUT_FILE="$OPTARG" ;;
    q) QUIET=1 ;;
    h)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,30p'
      exit 0
      ;;
    *) echo "unknown option: -$OPTARG" >&2; exit 2 ;;
  esac
done

# Everything written to stdout is the report. If -o was given, tee it.
if [ -n "$OUT_FILE" ]; then
  exec > >(tee "$OUT_FILE")
fi

section() {
  # Section banner -> report (stdout). Also echo to stderr unless quiet.
  printf '\n==[ %s ]%s\n' "$1" "$(printf '=%.0s' $(seq 1 $((60 - ${#1}))))"
  [ "$QUIET" -eq 0 ] && printf '[*] %s\n' "$1" >&2
}

note()  { printf '    %s\n' "$*"; }
kv()    { printf '    %-22s %s\n' "$1" "$2"; }
have()  { command -v "$1" >/dev/null 2>&1; }

# Run a command quietly; print its output indented, or a placeholder.
show() {
  local label="$1"; shift
  local result
  result="$("$@" 2>/dev/null)"
  if [ -n "$result" ]; then
    printf '    %s:\n' "$label"
    printf '%s\n' "$result" | sed 's/^/        /'
  else
    printf '    %s: (none / not available)\n' "$label"
  fi
}

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
printf '#############################################################\n'
printf '# Linux Local Enumeration Report (report-only, no exploits) #\n'
printf '#############################################################\n'
kv "Generated (UTC):" "$(date -u '+%Y-%m-%d %H:%M:%S')"
kv "Hostname:"        "$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)"
kv "Current user:"    "$(id 2>/dev/null)"
note "REMINDER: run only with documented authorization for this host."

# ---------------------------------------------------------------------------
# System / kernel
# ---------------------------------------------------------------------------
section "System & Kernel"
KREL="$(uname -r 2>/dev/null)"
kv "Kernel release:"  "$KREL"
kv "Kernel version:"  "$(uname -v 2>/dev/null)"
kv "Architecture:"    "$(uname -m 2>/dev/null)"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release 2>/dev/null
  kv "Distribution:" "${PRETTY_NAME:-unknown}"
fi
show "Kernel hardening (sysctl)" sh -c '
  for k in kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled \
           kernel.yama.ptrace_scope kernel.perf_event_paranoid \
           kernel.unprivileged_userns_clone vm.mmap_min_addr; do
    v=$(sysctl -n "$k" 2>/dev/null); [ -n "$v" ] && printf "%s = %s\n" "$k" "$v"
  done'

# ---------------------------------------------------------------------------
# Kernel CVE suggester (PUBLIC references only, no exploit code)
# ---------------------------------------------------------------------------
section "Kernel CVE Pointers (informational)"
note "Known publicly-disclosed local-privesc CVEs whose affected ranges"
note "commonly overlap the running kernel. These are INVESTIGATION POINTERS"
note "only -- confirm against the vendor's backported patch level (a distro"
note "kernel may carry fixes despite an old-looking version string)."
note ""

# Parse major.minor for coarse range matching.
KMAJ="$(printf '%s' "$KREL" | cut -d. -f1)"
KMIN="$(printf '%s' "$KREL" | cut -d. -f2 | grep -oE '^[0-9]+')"
KMAJ="${KMAJ:-0}"; KMIN="${KMIN:-0}"

# in_range MAJ.MIN_low MAJ.MIN_high -> 0 if running kernel within [low, high]
kver_le() { # returns 0 if $1.$2 <= $3.$4
  [ "$1" -lt "$3" ] && return 0
  [ "$1" -gt "$3" ] && return 1
  [ "$2" -le "$4" ] && return 0 || return 1
}
in_range() { # low_maj low_min high_maj high_min
  kver_le "$1" "$2" "$KMAJ" "$KMIN" && kver_le "$KMAJ" "$KMIN" "$3" "$4"
}

suggest() { # CVE  "low_maj low_min high_maj high_min"  "description"
  # shellcheck disable=SC2086
  if in_range $2; then
    printf '    [!] %-18s %s\n' "$1" "$3"
  fi
}

# Public CVE references relevant to the ~4.x privesc era. IDs and descriptions
# are public record; no exploitation logic is included.
suggest "CVE-2016-5195"     "2 6 4 8"  "Dirty COW - COW race in mm/ (read-only memory write)"
suggest "CVE-2017-1000112"  "4 8 4 13" "UFO/UDP fragmentation offload heap overflow (af_packet)"
suggest "CVE-2017-1000253"  "3 0 4 14" "load_elf_binary PIE mapping flaw"
suggest "CVE-2017-1000405"  "4 5 4 14" "Huge Dirty COW (transparent hugepage variant)"
suggest "CVE-2017-7308"     "4 0 4 11" "packet_set_ring AF_PACKET ring-buffer overflow"
suggest "CVE-2017-16995"    "4 9 4 14" "eBPF verifier sign-extension memory corruption"
suggest "CVE-2017-16939"    "3 0 4 14" "XFRM netlink use-after-free"
suggest "CVE-2018-1000001"  "2 6 4 14" "glibc realpath() buffer underflow (RationalLove)"
suggest "CVE-2021-3156"     "0 0 99 99" "sudo 'Baron Samedit' heap overflow (check sudo ver, not kernel)"

if ! in_range 2 6 4 14; then
  note "(running kernel $KREL is outside the listed pointer ranges;"
  note " enumerate published CVEs for $KMAJ.$KMIN separately)"
fi
note ""
note "Always verify with the distro security tracker before concluding"
note "exploitability; do not assume a CVE applies from the version alone."

# ---------------------------------------------------------------------------
# Users / privileges
# ---------------------------------------------------------------------------
section "Users & Privileges"
show "id"                id
show "sudo -n -l (cached)" sudo -n -l
show "Members of sudo/wheel/admin" sh -c '
  for g in sudo wheel admin adm; do getent group "$g" 2>/dev/null; done'
show "UID 0 accounts"    sh -c "awk -F: '\$3==0{print \$1}' /etc/passwd 2>/dev/null"
show "Accounts with shells" sh -c "grep -E '/(ba)?sh$' /etc/passwd 2>/dev/null"
[ -r /etc/shadow ] && note "[!] /etc/shadow is READABLE by current user"

# ---------------------------------------------------------------------------
# SUID / SGID / capabilities
# ---------------------------------------------------------------------------
section "SUID / SGID / Capabilities"
note "Cross-reference findings against GTFOBins for known privesc primitives."
show "SUID binaries" sh -c '
  find / -xdev -perm -4000 -type f 2>/dev/null | sort'
show "SGID binaries" sh -c '
  find / -xdev -perm -2000 -type f 2>/dev/null | sort'
if have getcap; then
  show "File capabilities" sh -c 'getcap -r / 2>/dev/null'
else
  note "File capabilities: getcap not present"
fi

# ---------------------------------------------------------------------------
# Writable / misconfigured paths
# ---------------------------------------------------------------------------
section "Writable & Misconfigured Paths"
show "World-writable dirs (no sticky bit)" sh -c '
  find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -50'
show "World-writable files" sh -c '
  find / -xdev -type f -perm -0002 2>/dev/null | grep -vE "^/(proc|sys|dev)" | head -50'
show "Writable files in PATH" sh -c '
  IFS=:; for d in $PATH; do
    [ -d "$d" ] && find "$d" -maxdepth 1 -writable -type f 2>/dev/null
  done'
note "PATH = $PATH"

# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------
section "Scheduled Tasks (cron / timers)"
show "System crontab"   sh -c 'cat /etc/crontab 2>/dev/null'
show "cron.d / periodic" sh -c '
  ls -la /etc/cron.* 2>/dev/null; ls -la /var/spool/cron* 2>/dev/null'
show "Writable cron files" sh -c '
  find /etc/cron* /var/spool/cron* -writable 2>/dev/null'
if have systemctl; then
  show "systemd timers" sh -c 'systemctl list-timers --all --no-pager 2>/dev/null'
fi

# ---------------------------------------------------------------------------
# Services / processes / network
# ---------------------------------------------------------------------------
section "Processes, Services & Network"
show "Processes (root-owned, top 30)" sh -c '
  ps -eo user,pid,cmd 2>/dev/null | awk "\$1==\"root\"" | head -30'
show "Listening sockets" sh -c '
  (ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null)'
show "Writable systemd unit files" sh -c '
  find /etc/systemd /lib/systemd /run/systemd -name "*.service" -writable 2>/dev/null'

# ---------------------------------------------------------------------------
# Credentials & interesting files (read-access checks only)
# ---------------------------------------------------------------------------
section "Credential & Config Exposure"
show "Readable SSH private keys" sh -c '
  find / -xdev -name "id_*" ! -name "*.pub" -readable -type f 2>/dev/null | head -30'
show "history files in home dirs" sh -c '
  find /home /root -maxdepth 2 -name ".*history" -readable 2>/dev/null'
show "Configs possibly holding secrets" sh -c '
  find /etc /opt /srv -maxdepth 3 -type f \
    \( -name "*.conf" -o -name "*.cnf" -o -name "*.ini" -o -name ".env" \) \
    -readable 2>/dev/null | head -40'
note "Manual review required; this only lists candidates, it does not read them."

# ---------------------------------------------------------------------------
# Container / virtualization context
# ---------------------------------------------------------------------------
section "Container / Virtualization Context"
[ -f /.dockerenv ] && note "[!] /.dockerenv present -> likely inside a Docker container"
show "cgroup hints" sh -c 'grep -E "docker|lxc|kubepods" /proc/1/cgroup 2>/dev/null'
have systemd-detect-virt && kv "Virtualization:" "$(systemd-detect-virt 2>/dev/null)"

# ---------------------------------------------------------------------------
section "Done"
note "Report-only enumeration complete. No changes were made to this host."
[ -n "$OUT_FILE" ] && printf '    Report written to: %s\n' "$OUT_FILE"
