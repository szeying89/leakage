# Dirty Frag intelligence assessment

## Executive summary

Dirty Frag is a Linux local privilege-escalation vulnerability chain described by Microsoft on May 8, 2026. Microsoft reports that the issue involves vulnerable kernel networking and memory-fragment handling paths in `esp4`, `esp6`, and `rxrpc`, tracked as CVE-2026-43284 for ESP/XFRM and CVE-2026-43500 for RxRPC. The vulnerability is post-compromise: an adversary needs existing local code execution before attempting escalation.

The primary operational risk is that a low-privileged Linux foothold can become root, allowing actors to disable defenses, steal credentials, tamper with logs, access application secrets, modify web application state, and pivot laterally. Microsoft specifically observed limited in-the-wild behavior involving SSH access, an interactive shell, staging and execution of an ELF binary named `./update`, privilege escalation activity involving `su`, GLPI file inspection/modification, PHP session file deletion/wiping, and session-data access.

## Confidence and sourcing

| Assessment | Confidence | Rationale |
| --- | --- | --- |
| Dirty Frag should be treated as a post-compromise privilege-escalation risk rather than an initial-access vector. | High | Microsoft describes exploitation after SSH, web-shell, container, service-account, or other local execution access. |
| Hosts using or exposing `esp4`, `esp6`, `rxrpc`, XFRM/IPsec, VPN, or AFS/RxRPC functionality are priority candidates for patching, validation, and compensating controls. | High | Microsoft lists these modules/components as relevant to the vulnerable paths and cautions that enterprises may already enable them. |
| Detection should emphasize behavior chains instead of a single process name or static filename. | High | `./update` is an observed artifact name, but adversaries can trivially rename a local exploit binary. |
| A single `su` execution is insufficient to prove Dirty Frag exploitation. | High | `su` is legitimate administrative behavior; it is most useful when correlated with suspicious staging, shell access, SUID/SGID launches, or sensitive file tampering. |
| CVE-2026-43500 patch availability and distribution coverage may change rapidly. | Medium | Microsoft noted that CVE-2026-43500 was not yet published in NVD as of May 8, 2026, so defenders should verify current vendor status. |

## Affected surface and prerequisites

Dirty Frag hunting should prioritize Linux hosts that satisfy one or more of the following conditions:

- The host runs vulnerable Linux kernels or distribution builds before vendor remediation.
- The host has `esp4`, `esp6`, `rxrpc`, or related XFRM/IPsec/RxRPC components loaded or loadable.
- The host exposes SSH, web applications, CI/CD runners, container workloads, or other paths that give an attacker low-privileged local code execution.
- The host stores high-value application data, credentials, tokens, or session state that becomes exposed after root escalation.

## ATT&CK mapping

| Tactic | Technique | Why it applies |
| --- | --- | --- |
| Initial Access | T1190 Exploit Public-Facing Application | Microsoft lists web-shell execution on internet-facing applications as a plausible precursor. |
| Initial Access | T1078 Valid Accounts | Compromised SSH or low-privileged service accounts can provide the local foothold needed for exploitation. |
| Execution | T1059 Command and Scripting Interpreter | Observed activity includes interactive shell use and local command execution. |
| Privilege Escalation | T1068 Exploitation for Privilege Escalation | Dirty Frag is a local kernel privilege-escalation vulnerability chain. |
| Privilege Escalation | T1548 Abuse Elevation Control Mechanism | `su` activity after suspicious staging can indicate escalation attempts or root transition. |
| Defense Evasion | T1070 Indicator Removal | Microsoft observed PHP session deletion/wiping after escalation. |
| Credential Access | T1552 Unsecured Credentials | Post-root actors can inspect application configuration, LDAP settings, session files, and local secrets. |
| Discovery | T1083 File and Directory Discovery | Observed activity included GLPI directory and system-configuration reconnaissance. |

## High-value telemetry

Collect and retain the following telemetry for Linux hosts:

- Process creation events with executable path, command line, working directory, parent process, effective UID, real UID, and TTY/session metadata.
- SSH authentication/session events, especially successful logons followed by unusual child processes.
- File creation, deletion, rename, and modification events for web roots, `/tmp`, `/var/tmp`, `/dev/shm`, GLPI directories, PHP session directories, and SUID/SGID paths.
- Module load/unload events and current module state for `esp4`, `esp6`, and `rxrpc`.
- Package/kernel inventory, distro advisory state, and reboot compliance.
- Container runtime events showing host namespace access, privileged containers, volume mounts into host paths, and unexpected shell execution.

## Hunt hypotheses

1. **Suspicious local exploit staging:** A low-privileged Linux user stages an ELF binary in a writable directory and executes it shortly before `su`, SUID/SGID execution, or root-owned child processes appear.
2. **SSH-to-root escalation chain:** A successful inbound SSH session spawns an interactive shell, executes a newly written binary such as `./update`, then transitions to root with `su` or launches root-owned shells/processes.
3. **Application foothold to local escalation:** A web-server process writes or executes ELF content, then file activity shifts toward sensitive application directories, PHP sessions, or authentication configuration.
4. **GLPI/session tampering after escalation:** An actor modifies GLPI authentication files or Vim swap files, deletes/wipes PHP session files, and then reads remaining session data.
5. **Module exposure without business justification:** Hosts have `esp4`, `esp6`, or `rxrpc` loaded or loadable even though no IPsec/VPN/RxRPC/AFS workload is approved.

## Triage guidance

When a hunt rule fires:

1. Capture the full process tree from the initial session through the suspected escalation event.
2. Preserve the suspicious binary, hashes, file metadata, extended attributes, and directory listing before cleanup.
3. Review auth logs and EDR identity context to identify the original low-privileged account.
4. Check for root-owned persistence, new SUID/SGID files, modified PAM/SSH/systemd configuration, altered cron jobs, and unexpected kernel module changes.
5. Validate kernel package version and vendor advisory status for CVE-2026-43284 and CVE-2026-43500.
6. If exploitation is plausible, consider memory-sensitive evidence collection before disruptive actions such as cache clearing, module unloading, or rebooting.

## False-positive considerations

- `su`, `sudo`, and SUID helpers are common on administratively managed Linux hosts. Correlate them with suspicious parents, newly written binaries, temporary directories, or low-privileged service accounts.
- IPsec/VPN hosts may legitimately load `esp4`, `esp6`, and XFRM modules. Do not block these modules without owner validation.
- RxRPC may be legitimate in environments using AFS or related functionality.
- GLPI maintenance, updates, and administrator troubleshooting can modify application files and session content. Confirm actor identity and change windows.

## Recommended response posture

- Patch kernels as vendor updates become available and verify that hosts reboot into the remediated kernel.
- Disable unused `rxrpc`, `esp4`, and `esp6` modules only after confirming business impact.
- Restrict unnecessary local shell access and harden container hosts against host namespace or privileged-container abuse.
- Increase detection sensitivity for low-privileged shell sessions followed by local ELF execution and root transition.
- Treat confirmed Dirty Frag exploitation as a full host compromise and validate integrity of sensitive application data and authentication material.
