# Dirty Frag safe proof of concept

This repository contains a **defensive, non-exploit proof of concept** for the Dirty Frag Linux local privilege-escalation issue described by Microsoft on May 8, 2026.

The tool intentionally does **not** include a working privilege-escalation exploit, kernel memory corruption primitive, or payload. Instead, it safely demonstrates whether the local host exposes the public preconditions that defenders can validate without attacking the kernel.

## Background

Microsoft describes Dirty Frag as a Linux local privilege-escalation vulnerability chain involving kernel networking and memory-fragment handling components, including `esp4`, `esp6`, and `rxrpc`. The Microsoft advisory tracks the issue with CVE-2026-43284 for the ESP/XFRM path and CVE-2026-43500 for the RxRPC path, and notes that exploitation is post-compromise: an attacker already needs local code execution through a compromised account, SSH session, web shell, container foothold, or similar access path.

Dirty Frag matters because successful local privilege escalation can turn a low-privileged foothold into root access. Microsoft recommends evaluating whether the affected modules are required, disabling unused modules where operationally possible, restricting unnecessary shell access, hardening containers, increasing monitoring for abnormal privilege escalation activity, and prioritizing kernel updates as vendor fixes become available.

## What this PoC checks

`dirtyfrag_poc.py` performs read-only checks for:

- Whether watched modules are currently loaded: `esp4`, `esp6`, and `rxrpc`.
- Whether watched module objects appear to exist on disk under the running kernel's module tree.
- Whether common `modprobe` mitigations are configured through `install <module> /bin/false`, `install <module> /bin/true`, or `blacklist <module>` rules.
- A coarse risk level:
  - `HIGH`: at least one watched module is already loaded.
  - `MEDIUM`: at least one watched module appears present and is not mitigated.
  - `LOW`: watched modules are absent or appear mitigated by the checks above.

This is an exposure and mitigation validation tool, not a vulnerability scanner with vendor patch intelligence. Always confirm final vulnerability status with your Linux distribution's advisory and installed kernel package metadata.

## Usage

Run the human-readable report:

```bash
python3 dirtyfrag_poc.py
```

Run the JSON report:

```bash
python3 dirtyfrag_poc.py --json
```

Example output:

```text
Dirty Frag safe exposure PoC
Kernel release : 6.8.0-example
Effective UID  : 1000
Risk level     : MEDIUM

Module  Loaded  On disk  Mitigated  Evidence
------  ------  -------  ---------  --------
esp4    False   True     False      -
esp6    False   True     False      -
rxrpc   False   False    False      -
```

## Interpreting results

- `Loaded=True` means the module is active now. Treat this as higher priority because module unloading can fail when a module is in use.
- `On disk=True` means the module appears available for the running kernel and may be loadable unless blocked by policy.
- `Mitigated=True` means this PoC found a common modprobe deny or blacklist rule. This does not prove the host is patched.
- `Evidence` lists the local configuration files that contributed to the mitigation result.

## Defensive mitigation example

Only apply mitigations after confirming that the host does not require IPsec/XFRM or RxRPC/AFS functionality. Disabling these modules can break legitimate networking or filesystem workloads.

A common temporary mitigation pattern is:

```bash
sudo sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf"
sudo modprobe -r esp4 esp6 rxrpc 2>/dev/null || true
```

After making mitigation changes, rerun the PoC:

```bash
python3 dirtyfrag_poc.py
```

If exploitation is suspected, Microsoft also recommends post-mitigation integrity verification because mitigation alone may not undo prior malicious changes. Coordinate cache clearing, forensic collection, and host rebuild decisions with your incident-response process before taking disruptive production actions.

## Testing

Run the unit tests with:

```bash
python3 -m unittest discover -s tests
```

Run a local syntax check with:

```bash
python3 -m py_compile dirtyfrag_poc.py tests/test_dirtyfrag_poc.py
```

## Safety boundary

This repository is intended for administrators, defenders, and lab validation. It does not provide instructions or code to trigger kernel memory corruption, overwrite privileged files, spawn a root shell, bypass container isolation, or otherwise weaponize Dirty Frag.

## References

- Microsoft Security Blog: [Active attack: Dirty Frag Linux vulnerability expands post-compromise risk](https://www.microsoft.com/en-us/security/blog/2026/05/08/active-attack-dirty-frag-linux-vulnerability-expands-post-compromise-risk/)
- NVD: [CVE-2026-43284](https://nvd.nist.gov/vuln/detail/CVE-2026-43284)
- CVE: [CVE-2026-43500](https://www.cve.org/CVERecord?id=CVE-2026-43500)

## Attack path and attack graph

A defender-focused Dirty Frag attack path and GraphQL-modeled attack graph are available in [`docs/attack-path-dirtyfrag.md`](docs/attack-path-dirtyfrag.md). The structured graph lives in [`attack_graph/dirtyfrag_attack_graph.json`](attack_graph/dirtyfrag_attack_graph.json), the GraphQL schema is in [`attack_graph/schema.graphql`](attack_graph/schema.graphql), and a Mermaid visualization is provided in [`attack_graph/dirtyfrag_attack_graph.mmd`](attack_graph/dirtyfrag_attack_graph.mmd).

## Intelligence assessment and hunting content

This repository also includes defender-focused intelligence and hunt artifacts for Dirty Frag:

- [`docs/intel-assessment-dirtyfrag.md`](docs/intel-assessment-dirtyfrag.md): intelligence assessment, ATT&CK mapping, hunt hypotheses, telemetry priorities, triage guidance, and false-positive notes.
- [`detections/kql/dirtyfrag_ssh_staging_to_root_transition.kql`](detections/kql/dirtyfrag_ssh_staging_to_root_transition.kql): Microsoft Defender XDR hunt for suspicious Linux staging followed by `su`/`sudo`/`pkexec`-style root transition utilities.
- [`detections/kql/dirtyfrag_glpi_php_session_tampering.kql`](detections/kql/dirtyfrag_glpi_php_session_tampering.kql): Microsoft Defender XDR hunt for GLPI authentication and PHP session tampering behaviors reported by Microsoft.
- [`detections/kql/dirtyfrag_module_activity.kql`](detections/kql/dirtyfrag_module_activity.kql): Microsoft Defender XDR hunt for `esp4`, `esp6`, and `rxrpc` module load, unload, or inspection commands.
- [`detections/sigma/linux_dirtyfrag_post_exploitation.yml`](detections/sigma/linux_dirtyfrag_post_exploitation.yml): experimental Sigma process rule for suspicious Dirty Frag-related staging and module activity.
- [`detections/sigma/linux_dirtyfrag_file_activity.yml`](detections/sigma/linux_dirtyfrag_file_activity.yml): experimental Sigma file rule for GLPI and PHP session activity.
- [`detections/osquery/dirtyfrag_exposure.sql`](detections/osquery/dirtyfrag_exposure.sql): read-only osquery hunts for module exposure, mitigation files, suspicious staging paths, and SUID/SGID review.

The detection content is intentionally behavior-focused. A match should start an investigation, not be treated as proof of exploitation without corroborating process ancestry, file evidence, account context, kernel patch state, and host timeline review.
