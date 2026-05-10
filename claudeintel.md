# Independent Intel Assessment: CVE-2026-23918

**Author:** Claude (independent analysis)
**Assessment date:** 2026-05-10
**Subject:** Apache HTTP Server 2.4.66 HTTP/2 double-free (possible RCE / DoS)
**Audience:** Security leadership, vulnerability management, SOC, threat hunting

> **Source provenance.** The canonical CVE record at `https://www.cve.org/CVERecord?id=CVE-2026-23918`, the MITRE CVE Services JSON, and `https://nvd.nist.gov/vuln/detail/CVE-2026-23918` were not directly reachable from the assessment environment (host allowlist blocks them; all returned `403`). The canonical CNA record and NVD enrichment data were supplied to this assessor out-of-band on 2026-05-10 and are treated as authoritative below. The NIST NVD CVSS assessment itself is still pending; CISA-ADP has provided the only published CVSS vector at the time of assessment.

### Canonical record (as supplied)

| Field | Value |
|---|---|
| CVE ID | CVE-2026-23918 |
| State | PUBLISHED |
| Title (CNA) | Apache HTTP Server: http2: double free and possible RCE on early reset |
| Assigning CNA | Apache Software Foundation |
| Published | 2026-05-04 |
| Updated | 2026-05-04 |
| Description | Double Free and possible RCE vulnerability in Apache HTTP Server with the HTTP/2 protocol. This issue affects Apache HTTP Server: 2.4.66. Users are recommended to upgrade to version 2.4.67, which fixes the issue. |
| CWE | CWE-415 (Double Free) — sole CWE; source: Apache Software Foundation |
| Vendor / Product | Apache Software Foundation / Apache HTTP Server |
| Affected versions | 2.4.66 only (default status: unaffected) |
| CPE 2.3 | `cpe:2.3:a:apache:http_server:2.4.66` |
| NVD (NIST) CVSS | **N/A — assessment not yet provided** |
| CISA-ADP CVSS 3.1 | **8.8 HIGH** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Reference (Apache) | https://httpd.apache.org/security/vulnerabilities_24.html (Vendor Advisory) |
| Reference (oss-security) | http://www.openwall.com/lists/oss-security/2026/05/04/19 (Mailing List, Third Party Advisory) |

---

## 1. Executive summary

CVE-2026-23918 is a **CWE-415 double-free** in Apache HTTP Server 2.4.66's HTTP/2 implementation, triggered specifically on **early stream reset**. The canonical CVE title — "http2: double free and possible RCE on early reset" — places this bug in the same family as CVE-2023-44487 ("HTTP/2 Rapid Reset") in terms of trigger mechanism (client-initiated `RST_STREAM` shortly after stream open), but with a memory-safety outcome rather than a pure resource-exhaustion outcome. The most reliable observable impact is **denial of service via worker crash**; RCE is possible but allocator- and build-dependent.

The "early reset" trigger materially raises confidence in the existing repository detection strategy: the in-repo Sigma rules already key off HTTP/2 reset bursts, which is exactly the activity expected to precede or accompany exploitation attempts.

My headline judgment matches the existing repository assessment in direction but diverges on three points:

1. I rate **exploit maturity 30 days post-disclosure as "low to moderate"** rather than "assumed likely." For HTTP/2 memory-corruption bugs, weaponised public PoCs typically lag the patch by weeks to months because the bug surface is timing-, allocator-, and MPM-sensitive.
2. I rate the **internal-only, broadly-reachable scenario as Medium-High**, not High, unless the organisation has a recent breach history or known commodity-malware footholds. The existing assessment's "High" rating is defensible but conservative.
3. I would treat **availability impact as the *primary* business risk** for the first 60–90 days, and confidentiality/integrity (via RCE) as a contingent, lower-likelihood but higher-severity tail risk. The existing assessment leans toward treating RCE as near-co-equal in priority.

Bottom line: patch internet-facing Apache 2.4.66 with HTTP/2 within 24 hours, internal high-reach instances within 72 hours, and use the time window before reliable public exploits emerge to also harden detection and rotate web-tier secrets pre-emptively.

---

## 2. CVSS — canonical (CISA-ADP) and reconciliation with my estimate

**Canonical CVSS at time of assessment: CISA-ADP 8.8 HIGH** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. NIST NVD has not yet published its own assessment.

| Metric | CISA-ADP | My earlier estimate | Reconciliation |
|---|---|---|---|
| AV | Network | Network | Match |
| AC | **Low** | High | **CISA-ADP picks Low.** I was too conservative; the "early reset" trigger is documented and reproducible enough that AC:L is defensible. My contingency note (the "if NVD picks AC:L it goes to 9.8" line) anticipated this direction but the simultaneous PR:L pulls the score back. |
| PR | **Low** | None | **CISA-ADP picks Low.** This is the unexpected one. PR:L typically implies basic authenticated access. For a pre-auth HTTP/2 protocol bug this is unusual; possible interpretations: (a) CISA-ADP is treating successful HTTP/2 stream establishment (post-handshake) as a low-privilege state; (b) the bug is reachable on virtual hosts that gate HTTP/2 behind auth in common deployments; (c) conservative scoring choice. NIST NVD's eventual rating will likely either confirm PR:L or move to PR:N (raising the score to 9.8 Critical). |
| UI | None | None | Match |
| S | Unchanged | Unchanged | Match |
| C / I / A | High / High / High | High / High / High | Match |

**Operational implication.** Use **8.8 HIGH** for SLA tooling, dashboards, and exception workflows today. Document **9.8 Critical** as the contingency rating if NIST NVD subsequently re-scores PR:N. Both ratings keep this in the "patch fast" tier — the band difference does not change the patch SLA the existing risk assessment recommends (24h external / 72h internal-broad-reach), but it does affect compliance frameworks that key strict thresholds at 9.0+.

**Why CISA-ADP and not NIST NVD?** CISA Authorized Data Publishers (ADPs) are an extension to the CVE Program where partners can enrich CVE records before NVD finalises its own assessment. CISA-ADP scores are authoritative-by-publisher but are not NIST's NVD score. When NIST NVD publishes its own vector, it should be treated as the primary CVSS for downstream consumers; until then, CISA-ADP is the best-available canonical score.

---

## 3. Key judgments

| # | Judgment | Confidence | Rationale |
|---|---|---|---|
| KJ-1 | Public reliable RCE PoCs against default Apache builds are **unlikely within 30 days**; DoS PoCs are likely within days. **The "early reset" trigger lowers the barrier to crash repro** — anyone with an HTTP/2 client and a stream-reset script can probe. | Moderate | Historical pattern for HTTP/2 memory-corruption bugs (CVE-2023-25690, CVE-2024-27316). The HTTP/2 Rapid Reset family (CVE-2023-44487) had public crash/exhaustion PoCs within hours; the same is plausible here. Weaponised RCE still lags because primitive shaping needs allocator analysis. |
| KJ-2 | The dominant adversary class in the first 60 days will be **opportunistic scanners and disruption-motivated actors**, not targeted RCE-capable groups. | Moderate-High | Bug-class precedent and the absence (so far) of ransomware-affiliate adoption signals. |
| KJ-3 | Edge HTTP/2 termination at a **patched** L7 proxy (Cloudflare, Envoy, modern HAProxy, AWS ALB) materially reduces but does **not** eliminate risk if the proxy re-uses HTTP/2 to the Apache origin. | High | HTTP/2-to-origin is increasingly common; protocol downgrade at the proxy is the actual mitigation. |
| KJ-4 | The most valuable detection telemetry is **Apache worker SIGSEGV/SIGABRT events correlated with HTTP/2 reset/abort bursts in the same minute window**, not either signal alone. **Confidence raised** by the canonical "early reset" trigger now confirming reset bursts are mechanism-aligned, not just incidental. | High | The canonical CVE title explicitly attributes the bug to "early reset," meaning client-initiated `RST_STREAM` is the trigger. This makes HTTP/2 reset telemetry the highest-signal detection input rather than a generic anomaly indicator. |
| KJ-5 | Vendor-packaged Apache binaries (RHEL, Ubuntu, Amazon Linux, cPanel/EasyApache) will receive **backported fixes** that retain the `2.4.66` version string. Version-string-only inventory checks will produce false positives. | High | Standard distro practice; observed for every prior Apache CVE. |
| KJ-6 | Container images and "frozen" application-vendored Apache builds (CMS appliances, network-device admin UIs, embedded management consoles) are the **highest-risk long-tail** because they are rarely patched after deployment. | Moderate-High | Pattern observed across Log4Shell, Spring4Shell, Apache mod_proxy CVEs. |
| KJ-7 | Insider/lateral attack via internal Apache 2.4.66 is plausible but **not the primary vector** for opportunistic actors in the early window. | Moderate | Depends heavily on org-specific endpoint hygiene. |

---

## 4. Source facts (with confidence)

| Fact | Source | Confidence |
|---|---|---|
| CVE ID, state, title | Canonical CVE record | High (verbatim) |
| Trigger condition: **early HTTP/2 stream reset** | Canonical CVE title | High |
| CWE: 415 (Double Free) — sole CWE; source ASF | Canonical CVE record | High |
| Affected versions: Apache HTTP Server **2.4.66 only** (default status: unaffected) | Canonical CVE record | High |
| CPE 2.3: `cpe:2.3:a:apache:http_server:2.4.66` | NVD enrichment | High |
| Fixed in Apache HTTP Server 2.4.67 | Canonical CVE description | High |
| Possible RCE (vendor-acknowledged, not asserted as confirmed in the wild) | Canonical CVE description: "Double Free and possible RCE vulnerability" | High |
| Assigning CNA: Apache Software Foundation | Canonical CVE record | High |
| Published / Updated: 2026-05-04 (single date) | Canonical CVE record | High |
| **CVSS 3.1 (CISA-ADP): 8.8 HIGH — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`** | NVD enrichment (CISA-ADP) | High |
| **NIST NVD CVSS: not yet provided** | NVD enrichment | High (the absence is itself a fact) |
| Public reference: Apache vendor advisory | NVD references | High |
| Public reference: oss-security mailing list post 2026-05-04 (entry 19) | NVD references | High |
| 2.4.67 release date | Repository's Apache-page reference (2026-05-04) — consistent with CVE Published date | High |
| cPanel EasyApache 4 guidance exists | Repository reference; not independently verified here | Moderate |

---

## 5. Threat actor interest and likely targeting

Likely actor types and motivations:

- **Internet-wide scanners (Censys/Shodan-driven, opportunistic):** Already enumerating HTTP/2-capable endpoints. Low effort to add a banner-grab and a crash-trigger probe.
- **Initial access brokers:** Will adopt only if a reliable, low-noise RCE PoC emerges. Until then, the bug is too noisy (crash-prone) for stealth-valued access.
- **Hacktivists / disruption actors:** **Highest fit** for the first 30–60 days. A reliable DoS payload against major Apache-fronted properties is a meaningful disruption tool with low operational risk.
- **Ransomware affiliates:** Will adopt if/when chained with a working RCE; otherwise will continue to prefer better-understood web-tier bugs.
- **Nation-state / targeted actors:** May already have private exploits; unlikely to burn them on opportunistic targets. Concern is targeted use against high-value Apache 2.4.66 estates.

Expected attacker workflow:

1. ALPN negotiation scan → list of HTTP/2-capable hosts.
2. Banner / `Server:` header / favicon-hash filter → suspected Apache 2.4.66.
3. Trigger probe (malformed HTTP/2 frame sequence) → crash signature.
4. If a stable RCE primitive is published, layer on payload-delivery, persistence, and credential harvest from Apache service account.

---

## 6. Risk by deployment scenario (independent)

| Scenario | My rating | Existing repo rating | Delta |
|---|---|---|---|
| Internet-facing 2.4.66, HTTP/2 reaches Apache | **Critical** | Critical | Same |
| Internet-facing 2.4.66, behind proxy, HTTP/2 termination unverified | **High** | High until proven otherwise | Same |
| Internet-facing 2.4.66, HTTP/2 verifiably terminates at patched proxy | **Low-Medium** | Medium | I rate **slightly lower** if termination is proven and the origin protocol is HTTP/1.1; existing assessment is appropriately cautious. |
| Internal 2.4.66 reachable from broad user/VPN/partner segments | **Medium-High** | High | I rate **slightly lower** absent indicators of foothold; the existing assessment is conservative which is reasonable for the first 30 days. |
| Internal 2.4.66 reachable only from controlled app tiers | **Low-Medium** | Medium | Same direction. |
| Containerised or appliance-embedded 2.4.66 | **High** | (not separately scored in existing assessment) | **New scenario I add** — long-tail risk that the existing assessment under-emphasises. |
| 2.4.67 / vendor-fixed / HTTP/2 disabled | Low | Low | Same |

---

## 7. Detection priorities (delta from existing assessment)

The existing assessment's detection priorities are sound. My additions:

1. **Origin-side HTTP/2 enablement check.** The existing assessment focuses on whether HTTP/2 reaches Apache, but does not call out auditing the **proxy → origin** leg specifically. Many CDN / WAF deployments downgrade to HTTP/1.1 at the origin; many newer ones do not. This audit is a 1-day exercise that materially reclassifies inventory.
2. **Allocator/MPM fingerprinting.** Exploit reliability differs sharply between `prefork`, `worker`, and `event` MPMs and between glibc/jemalloc/tcmalloc. Inventory should capture MPM and allocator. The existing assessment does not call this out.
3. **Long-tail container scan.** Scan internal container registries and running pods for Apache 2.4.66 in derived images. This is the highest under-served detection surface.
4. **Outbound-connection baseline.** Most environments do not have a clean "Apache should never connect outbound to X" baseline. Build it pre-emptively before exploitation, using the 30-day window.

---

## 8. Comparison with `threat-intel/cve-2026-23918-intel-assessment.md`

### 8.1 Where we agree

- Affected version, fixed version, vulnerability class, vendor remediation guidance.
- Critical rating for internet-facing Apache 2.4.66 with HTTP/2 reaching the origin.
- Patch SLAs (24h external, 72h internal-broad-reach).
- DoS as the most likely early observable; RCE as highest-impact tail risk.
- Detection orientation: HTTP/2 reset bursts correlated with worker crashes.
- Trigger conditions for incident response (crash + reset burst + suspicious child process / outbound / sensitive-file-read).
- Importance of vendor-backport awareness (version-string false positives).

### 8.2 Where I diverge

| # | Topic | Existing assessment | My assessment | Why it matters |
|---|---|---|---|---|
| D-1 | Exploit maturity expectation | "Public exploit chatter should be assumed likely" | Reliable RCE PoCs unlikely within 30 days; DoS PoCs likely within days | Drives whether the 24h SLA is "patch or compensating control" vs. "patch, full stop." |
| D-2 | Internal broad-reach risk rating | High | Medium-High (conditional on org foothold posture) | Affects prioritisation order between internet edge and internal patch waves. |
| D-3 | RCE vs. DoS framing | Treats RCE and DoS as near-co-equal planning scenarios | DoS is the *primary* near-term operational risk; RCE is a contingent tail risk | Communications framing to executives: "service availability" vs. "data breach" reads very differently. |
| D-4 | CVSS | Not stated | **Canonical (CISA-ADP): 8.8 HIGH** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. NIST NVD assessment still pending. | Procurement, compliance, and SLA tooling often key off CVSS — a number should be present. The existing assessment should be updated to cite CISA-ADP 8.8 with a note that NIST NVD is not yet provided. |
| D-5 | Containerised / appliance-embedded Apache | Mentioned only generally under "internal" | Called out as a distinct, separately-prioritised risk class | This is empirically the slowest-to-patch surface in every prior Apache CVE. |
| D-6 | Proxy-to-origin HTTP/2 leg | Mentioned but not specifically as a 1-day audit task | Explicit, prioritised as an early action | Reclassifies inventory faster than scanner-based version detection. |
| D-7 | MPM / allocator inventory | Not addressed | Recommended | Affects exploit reliability assessment and crash-signature tuning. |
| D-8 | Source-validation rigor | Cites Apache page, cPanel, repo's own references; presents some claims (e.g., "public reporting and vulnerability aggregators discuss PoC/exploit activity") without cited sources | I explicitly mark unverified claims as such, and downgrade confidence where I cannot reach the canonical record | Auditors and downstream analysts should be able to distinguish vendor-confirmed facts from inferred or hearsay claims. |
| D-9 | Adversary class fit | Lists ransomware affiliates as a likely interested actor | I rate ransomware-affiliate fit as **low** until a reliable RCE PoC exists | Avoids over-weighting a low-probability scenario in early-window resourcing decisions. |
| D-10 | Timeline assertion | States specific dates (2025-12-10 reported, 2025-12-11 fixed in source, 2026-05-04 release) as facts sourced from Apache | I cannot verify any of those dates from this environment; they may be correct, but should be footnoted as Apache-page-sourced rather than presented as ground truth | Provenance hygiene. |

### 8.3 Where the existing assessment is stronger than mine

- **Operational specificity.** The existing assessment's "deprioritisation" criteria (4 conditions for moving an asset out of scope) are well-formed and immediately usable; mine are less crisp.
- **Telemetry sources list.** The existing list (ASM, CDN, WAF, ALPN logs, EDR, syslog/journald, scanner, SBOM, container registry, NetFlow) is comprehensive and well-mapped to actual SOC tooling. I do not improve on it.
- **Mapping to the in-repo Sigma rule pack.** The existing assessment closes the loop with deployable detection logic. Mine references the same pack but does not add to it.

### 8.4 Where both assessments share blind spots

- Neither verifies the canonical CVE record at cve.org / NVD against the Apache page; both lean on the Apache advisory as authoritative. If the canonical record disagrees on affected versions or CVSS, both assessments would need correction.
- Neither examines whether `mod_http2` is *built-in* vs. *loaded as a module* in major distro packages, which affects whether disabling HTTP/2 actually removes the code path from the address space.
- Neither addresses **HTTP/3 / QUIC** posture. If an organisation is rolling out HTTP/3 alongside HTTP/2 on Apache, the threat surface and detection telemetry both shift.

---

## 9. Collection requirements (additions)

In addition to the existing assessment's PIRs:

- Which proxies / load balancers terminate HTTP/2 versus pass it through to Apache origins?
- What MPM and memory allocator is each Apache 2.4.66 instance running?
- Which internal container images derive from a base that includes Apache 2.4.66?
- Are any application appliances (CMS, network-device admin UIs, monitoring tools) shipping a vendored Apache 2.4.66?
- Has anyone observed `nghttp2` library version mismatches between Apache builds in the estate? (Some downstream packagers update `mod_http2` independently of the core Apache version.)

---

## 10. Mitigation guidance (additions)

The existing immediate-controls list is sound. I add:

- **For environments unable to patch within SLA:** terminate HTTP/2 at a patched L7 proxy and *force* HTTP/1.1 on the proxy→origin leg. Do not rely on default proxy behaviour; verify with packet capture.
- **For containerised Apache:** prefer a base-image rebuild over a running-container patch; ephemeral containers will revert on next deploy.
- **For appliance-embedded Apache:** open vendor support cases proactively; do not assume the vendor will issue an advisory on Apache's timeline.
- **Pre-exploitation hygiene:** rotate web-tier service-account credentials, API keys reachable from Apache processes, and any cloud instance-metadata-derived credentials *before* a reliable RCE PoC emerges. The window is the value.

---

## 11. Confidence and gaps

**Overall confidence: Moderate-High** (raised from "Moderate" after canonical record and NVD enrichment were supplied).

- High confidence on bug class (CWE-415), trigger mechanism ("early reset"), affected/fixed versions, CVSS (CISA-ADP), references, and remediation direction.
- Moderate confidence on exploitation timeline and adversary class fit (based on bug-class precedent and the now-confirmed Rapid-Reset-family trigger).
- Low confidence on whether NIST NVD will retain CISA-ADP's PR:L or move to PR:N (which would raise the score to 9.8 Critical).

Remaining gaps:

- **NIST NVD CVSS assessment** is still pending. Re-check `https://nvd.nist.gov/vuln/detail/CVE-2026-23918` periodically; the assessment may shift to PR:N → 9.8 Critical.
- **Live exploit-tracking sources** (vulncheck, exploit-db, public PoC repositories) are unreachable from this environment.
- **In-the-wild exploitation status** is not stated in the canonical record; CISA KEV inclusion (or non-inclusion) should be checked separately.
- The **oss-security 2026-05-04 entry 19** post body has not been read; it likely contains additional reproduction or mitigation detail that this assessment does not yet incorporate.

---

## 12. Bottom line

CVE-2026-23918 is a credible, urgent web-tier exposure that justifies emergency patching on internet-facing Apache 2.4.66 instances within 24 hours and broad-reach internal instances within 72 hours. The existing repository assessment reaches the same operational conclusion through a slightly more conservative threat-actor framing; my analysis shifts emphasis toward DoS as the primary near-term risk, calls out container/appliance long-tail and proxy-to-origin HTTP/2 as under-served audit targets, and explicitly flags claims that could not be verified against the canonical CVE record from this environment.

Both assessments converge on action; they differ on framing, confidence calibration, and a handful of audit priorities listed above.

---

## References

**Canonical (per NVD enrichment, supplied to assessor out-of-band):**

- Apache vendor advisory: https://httpd.apache.org/security/vulnerabilities_24.html (Vendor Advisory)
- oss-security mailing list, 2026-05-04 entry 19: http://www.openwall.com/lists/oss-security/2026/05/04/19 (Mailing List, Third Party Advisory)
- CVE record (cve.org / MITRE): https://www.cve.org/CVERecord?id=CVE-2026-23918
- NVD detail page: https://nvd.nist.gov/vuln/detail/CVE-2026-23918

**Repository artefacts:**

- `threat-intel/cve-2026-23918-intel-assessment.md` — assessment under comparison
- `threat-hunting/sigma/README.md` — deployable detection pack (8 documented bugs in current rules, see "Known bugs" section)
- `attack-paths/cve-2026-23918.md` — attack-graph mapping
- `risk-assessments/cve-2026-23918-risk-assessment.md` — risk scenario matrix

**Note on environment access:** All canonical sources above (`cve.org`, `cveawg.mitre.org`, `nvd.nist.gov`, `httpd.apache.org`, `openwall.com`) returned `403 Host not in allowlist` when fetched from this assessment environment. The canonical record and NVD enrichment data were therefore supplied to this assessor out-of-band. Future verification rounds should re-check the canonical sources directly (especially for the eventual NIST NVD CVSS rating, which was N/A at time of assessment).
