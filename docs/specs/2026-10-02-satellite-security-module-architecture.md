# Security Configuration, Management & Remediation Architecture

**Date:** 2026-10-02
**Status:** Draft — architecture proposal for stakeholder review
**Authors:** Amy Ralph, Lukas Vrabec
**Stakeholders:** Eric Helms (Satellite), Emily Fox (ProdSec/strategy)
**Timeline:** Architecture draft by ~Oct 23, 2026. Earliest release: Satellite 6.22+ (Nov 2027)
**Related:** [RFE Meeting Notes](https://docs.google.com/document/d/1Dihrd7jMcyngoWrm-_mfo3sbpmWw1eD3phDMeojRN8w/edit), [Agentic Security PoC](2026-10-02-siem-integration-design.md)

## Problem

RHEL generates security-relevant events across multiple subsystems — SELinux, auditd, crypto-policies, firewall, file integrity, compliance baselines — but customers have no unified view of their fleet's security posture within the Red Hat ecosystem. Security events stay on individual hosts. Compliance drift goes undetected until the next manual scan. When a violation is found, remediation is manual and disconnected from the detection that triggered it.

Customers want: see it (Satellite), understand it (Lightspeed), fix it (Ansible), and optionally stream it to their own SIEM.

## Goal

A dual-speed security pipeline that gives customers fleet-wide visibility into RHEL security events, AI-assisted remediation guidance, and automated response — using Red Hat products they already own.

Not prescriptive about implementation details at this stage. This document establishes the architecture, component boundaries, data flows, and phasing.

## Design Principles

1. **Use what's already there.** rsyslog, auditd, SCAP, Satellite host registration — don't introduce new agents where existing infrastructure works.
2. **Two speeds, one view.** Real-time events (fast path) and periodic compliance (slow path) converge in Satellite's security dashboard.
3. **Control mapping everywhere.** Every event and finding maps to compliance controls (CIS, STIG, PCI-DSS) — same pattern as MITRE ATT&CK mapping in the agentic security PoC.
4. **Customer SIEM is first-class.** Webhook/syslog egress at every tier so customers can route to Splunk/QRadar/Elastic without forking the pipeline.
5. **Progressive automation.** Tier 1 is read-only visibility. Tier 2 adds advice. Tier 3 adds action. Customers choose their comfort level.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MANAGED RHEL HOSTS                          │
│                                                                     │
│  ┌──────────┐ ┌────────┐ ┌───────────┐ ┌────────┐ ┌─────────────┐ │
│  │ SELinux  │ │auditd  │ │crypto-    │ │firewall│ │ AIDE / fapolicyd│
│  │ AVCs     │ │denials │ │policies   │ │drops   │ │ integrity    │ │
│  └────┬─────┘ └───┬────┘ └────┬──────┘ └───┬────┘ └──────┬──────┘ │
│       │           │           │             │             │         │
│       └───────────┴───────────┴─────────────┴─────────────┘         │
│                               │                                     │
│                        ┌──────▼──────┐                              │
│                        │  rsyslog    │  existing on every RHEL host  │
│                        │  (collect)  │                               │
│                        └──────┬──────┘                              │
│                               │                                     │
│  ┌────────────────────────────┼──────────────────────────────┐      │
│  │         SCAP / OpenSCAP compliance scans                  │      │
│  │         Config baseline drift detection                   │      │
│  │         (Satellite-initiated, periodic)                   │      │
│  └────────────────────────────┼──────────────────────────────┘      │
└───────────────────────────────┼──────────────────────────────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                  │
     ┌────────▼────────┐  ┌────▼─────────┐  ┌─────▼──────────┐
     │   FAST PATH     │  │  SLOW PATH   │  │   IAM PATH     │
     │  (real-time)    │  │  (periodic)  │  │ (event-driven) │
     │                 │  │              │  │                 │
     │ rsyslog → EDA   │  │ Satellite    │  │ EDA → IdM      │
     │ event rules     │  │ scans/diffs  │  │ revocation     │
     │ auto-response   │  │ drift view   │  │ token suspend  │
     └────────┬────────┘  └──────┬───────┘  └────────┬───────┘
              │                  │                    │
              └──────────────────┼────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     SATELLITE           │
                    │  Security Dashboard     │
                    │  (unified posture view) │
                    │                         │
                    │  Tier 1: Event counts,  │
                    │    compliance scores,   │
                    │    drift indicators     │
                    │                         │
                    │  Tier 2: Lightspeed     │
                    │    remediation advice   │
                    │                         │
                    │  Tier 3: Ansible        │
                    │    remediation launch   │
                    ├─────────────────────────┤
                    │  SIEM Webhook (egress)  │
                    │  syslog / CEF / webhook │
                    └─────────────────────────┘
```

## Event Sources

### Fast Path Sources (real-time, seconds)

| Source | What It Produces | Collection | Example Event |
|--------|-----------------|------------|---------------|
| SELinux | AVC denial messages | rsyslog (`/var/log/audit/audit.log`) | `avc: denied { read } for pid=12345 comm="httpd"` |
| auditd | Syscall/file access denials | rsyslog (audit dispatcher) | `SYSCALL arch=... key="privilege_escalation"` |
| crypto-policies | Non-compliant cipher usage, policy drift | rsyslog (application logs) | TLS handshake with deprecated cipher, policy != FIPS |
| crypto audit hooks | Algorithm/protocol/key-length violations | auditd `CRYPTO_*` records + rsyslog | `CRYPTO_KEY_USER op=destroy key=RSA-1024` |
| PQC readiness | Pre-quantum algorithm inventory, risky crypto usage | scan + audit hooks | RSA-2048/ECDSA in use where ML-DSA/ML-KEM expected |
| firewalld/nftables | Dropped packets matching security rules | rsyslog (kernel log) | `DROPPED IN=eth0 SRC=10.x.x.x` |
| fapolicyd | Unauthorized binary execution | rsyslog | `decision=deny ... exe=/tmp/rogue` |

### Slow Path Sources (periodic, minutes–hours)

| Source | What It Produces | Collection | Cadence |
|--------|-----------------|------------|---------|
| OpenSCAP | Compliance scan results (XCCDF) | Satellite-initiated | Scheduled (daily/weekly) |
| SCAP profiles | CIS/STIG/PCI-DSS benchmark scores | Satellite | On-demand or scheduled |
| Custom profiles | Org-specific baselines (CompliTime) | Satellite | On-demand |
| AIDE | File integrity change reports | Satellite remote execution | Scheduled |
| Config drift | Diff current vs baseline (Ansible facts) | Satellite + Ansible | Scheduled or event-triggered |

### IAM Path Sources (event-triggered)

| Trigger | Identity Action | Mechanism |
|---------|----------------|-----------|
| Repeated SELinux denials from a service | Suspend service principal | EDA → IdM HBAC rule disable |
| Credential file access by unauthorized process | Revoke OAuth tokens | EDA → ahdapa token revocation |
| Compliance score below threshold | Flag host for quarantine | EDA → Satellite host group move |
| Anomalous token request burst | Circuit-breaker suspend | EDA → IdM account disable |

The IAM path is not managed by Satellite — IdM/FreeIPA owns identity. Satellite shows the action taken (service suspended, host quarantined) as a status indicator, not as the control plane.

## Crypto Auditing & PQC Readiness

Cryptographic compliance deserves special attention — it spans both fast and slow paths, customers increasingly need PQC migration visibility, and the hooks exist in RHEL today but aren't surfaced fleet-wide.

### Crypto Audit Hooks (Fast Path)

auditd already emits `CRYPTO_*` records when cryptographic operations occur:

- `CRYPTO_KEY_USER` — key creation, destruction, negotiation events
- `CRYPTO_SESSION` — TLS/SSH session establishment with cipher details
- `CRYPTO_PARAM_CHANGE_USER` — crypto parameter modifications
- `CRYPTO_LOGIN` / `CRYPTO_LOGOUT` — crypto-authenticated session lifecycle

These hooks are **toggleable** — enabled/disabled via audit rules:

```
# Enable crypto auditing (assessment mode)
-a always,exit -F arch=b64 -S connect -k crypto-connect
-w /etc/crypto-policies/ -p wa -k crypto-policy-change

# Disable (reduce noise after baseline established)
# Remove the rules above from /etc/audit/rules.d/
```

### Risky Crypto Detection

| Signal | Risk | Control |
|--------|------|---------|
| RSA < 3072 bits in TLS handshake | CNSA 2.0 non-compliant by 2030 | NIST SP 800-131A |
| SHA-1 in certificate chains | Collision-vulnerable | CIS, FIPS 140-3 |
| 3DES/RC4 cipher negotiation | Known-broken | PCI-DSS 4.0 §4.2.1 |
| ECDSA P-256 without PQC hybrid | Harvest-now-decrypt-later exposure | CNSA 2.0 |
| crypto-policy != FIPS/FUTURE | Policy weaker than org baseline | CIS, STIG |
| Manual crypto-policy override on host | Policy drift from fleet standard | Org-specific |

### PQC Migration Visibility (Slow Path)

Satellite can drive periodic scans that inventory cryptographic usage across the fleet:

- **Algorithm inventory:** Which hosts use which key exchange / signature algorithms
- **Certificate audit:** Key lengths, signature algorithms, expiry + PQC readiness score
- **Protocol versions:** TLS 1.2 vs 1.3, SSH key types in use
- **Migration tracking:** Percentage of fleet on ML-DSA/ML-KEM vs classical-only

This feeds Tier 1 with a "PQC readiness" score per host/host group and a fleet-wide migration dashboard.

### Monitoring Modes (Assessment vs Continuous)

Not all customers want all hooks running all the time. The architecture supports two modes, togglable per event source per host group from Satellite:

| Mode | Purpose | Hooks Active | Event Volume |
|------|---------|-------------|--------------|
| **Assessment** | Baseline discovery, audit prep, PQC inventory | All hooks enabled, verbose logging | High (temporary) |
| **Continuous** | Steady-state monitoring, alert on violations | Subset of hooks, violation-only logging | Low (sustained) |

**Toggle mechanism:** Satellite pushes audit rule sets and rsyslog filter configs to hosts via Ansible. Assessment mode adds the full `CRYPTO_*` audit rules and verbose rsyslog filters. Continuous mode strips back to violation-only rules. Customer chooses per host group, can schedule assessment windows (e.g., weekly 2-hour crypto audit scan).

**Why toggleable:** Crypto audit hooks at full verbosity generate significant event volume. Assessment mode is for establishing baselines and preparing for audits. Continuous mode is for day-to-day monitoring where you only care about policy violations, not normal operations.

## Three Tiers

### Tier 1: Visibility (Satellite Security Dashboard)

**What customers see:** Fleet-wide security posture at a glance.

- **Event counts** by category (SELinux, audit, firewall, crypto) per host/host group
- **Compliance scores** from SCAP scans with trend lines (improving/degrading)
- **Drift indicators** — hosts that have diverged from their assigned baseline
- **Identity status** — services suspended, tokens revoked (read from IdM, displayed in Satellite)
- **Top findings** — most common violations across the fleet, sorted by control mapping

**Data flow:** Both fast-path event aggregates and slow-path scan results land here. Satellite stores, indexes, and presents.

**Control mapping:** Every event and finding links to one or more compliance controls. A single SELinux AVC might map to CIS 1.6.1.1, STIG V-230223, and PCI-DSS 2.2.4. Satellite displays these mappings so auditors can filter by framework.

### Tier 2: Advice (Lightspeed On-Prem)

**What customers see:** AI-generated remediation guidance for specific findings.

- Click a finding in Satellite → Lightspeed explains what happened, why it matters, and how to fix it
- Lightspeed has context: the host's profile, compliance baseline, current config, event history
- Output: natural language explanation + suggested Ansible task/playbook snippet
- Customer reviews and approves before any action

**Guardrails:**
- Lightspeed on-prem only (no cloud data egress for security events)
- Suggestions are advisory — never auto-executed from Tier 2
- Suggestions reference the specific compliance control being violated

### Tier 3: Remediation (Ansible + EDA)

**What customers can do:** Execute approved remediations or configure automated responses.

**Manual remediation (Ansible):**
- Satellite launches Ansible playbook to remediate a specific finding
- Playbooks scoped to the finding type (SELinux module install, firewall rule update, crypto-policy enforcement, config file restore)
- Post-remediation rescan confirms fix

**Automated remediation (EDA):**
- Pre-approved rules: customer defines which event types trigger automatic response
- EDA rulebook matches events from fast path, executes remediation playbook
- Example: SELinux denial on a known-good service → auto-apply targeted policy module
- Example: Config drift detected on critical host → auto-restore from baseline
- Circuit breaker: if automated remediation fails N times, escalate to human

**IAM automated response (EDA):**
- Same pattern as the agentic security PoC revocation path
- Event → EDA rule → identity action (HBAC disable, token revoke, host quarantine)
- Not a Satellite action — EDA talks directly to IdM/FreeIPA
- Satellite reflects the result (host shows "quarantined" status)

## SIEM Webhook Integration

Customers with existing SIEM investments get events without replacing their tooling.

- **Egress format:** syslog RFC 5424 (default), CEF (toggle), webhook JSON (configurable)
- **What's sent:** Enriched events with control mapping, host context, severity
- **Where configured:** Satellite settings → SIEM integration → destination + format
- **Structured data:** `[rhel-security event_type="selinux_avc" host="web01.example.com" control="CIS-1.6.1.1" severity="high"]`

Same principle as the PoC: vendor-neutral, standards-based, change-one-IP-address portability.

## Control Mapping Model

Every event and finding carries compliance control references. This is the generalization of the PoC's MITRE ATT&CK mapping.

```
Event/Finding
  ├── CIS Benchmark:      CIS-1.6.1.1 (SELinux enforcing)
  ├── DISA STIG:           V-230223
  ├── PCI-DSS:             2.2.4 (system hardening)
  ├── NIST 800-53:         AU-2 (auditable events)
  └── Custom:              ORG-SEC-047 (customer-defined)
```

Mapping data source: SCAP content (existing), extended with custom profile support via CompliTime.

## Phasing

### Phase 1: Visibility Foundation (target: Satellite 6.22 / Nov 2027)
- SELinux AVC event counts in Satellite security dashboard
- SCAP compliance scan results with control mapping
- Host-level security posture score
- SIEM webhook egress (syslog)

### Phase 2: Advice + Drift
- Lightspeed integration for finding explanation and remediation suggestions
- Config drift detection (baseline vs current)
- Broader event sources (auditd, crypto-policy, firewall)
- Control mapping across multiple frameworks

### Phase 3: Automated Response
- EDA integration for pre-approved automated remediation
- IAM response path (IdM integration for service suspension)
- Circuit breaker patterns
- Plugin extension point for partner ecosystems (EDR, etc.)

## Relationship to AAP XDR Fabric

The AAP team's "AAP as an XDR Fabric" concept ([deck](https://docs.google.com/presentation/d/1uS03jhg0VbSrRIi79O9ZNGxW88kxjlCDwUtBA84MwTU/edit)) positions AAP as the orchestration layer across CrowdStrike, Splunk, ServiceNow, Vault, and other security tools. The architectures are complementary — this spec covers the visibility/management layer (Satellite + Lightspeed), AAP XDR covers execution/orchestration (AAP + EDA + collections).

### Alignment Points

| This Architecture | AAP XDR Fabric | Status |
|---|---|---|
| Fast path (rsyslog → EDA) | Scan → normalize → EDA → remediate → re-verify | Same core pattern |
| Bridge enrichment (normalize, map controls) | Flink correlation layer (Normalize → Dedup → Enrich → Correlate → Detect) | AAP adds dedup + correlation stage |
| Tier 3 EDA remediation | Pre-approved EDA rulebooks + targeted playbooks | Aligned |
| Tier 2 Lightspeed advice | Lightspeed integration (mostly DESIGN/NOT BUILT) | Both early stage |
| SCAP/ComplyTime compliance scans | ComplyTime (BUILT 1/4 subcapabilities) | Shared dependency |
| Crypto audit hooks + PQC readiness | `pqc.ansible` collection + `crypto_posture_snapshot` | Complementary — **CME-408+ taxonomy gap is OPEN/UNOWNED** |
| SIEM webhook egress | Splunk 6-index data model + Wazuh | Our egress feeds their ingest |
| Control mapping (CIS/STIG/PCI) | MITRE ATT&CK (97/118 techniques LIVE) + D3FEND (GAP) | Parallel mapping efforts |

### Design Constraints (build to interoperate)

1. **Event format compatibility.** Our fast-path events must be consumable by the Flink correlation layer. Use Common Findings Format (CFF) v1.0.0 as the normalization target — AAP XDR already standardizes on it.
2. **EDA rulebook conventions.** Tier 3 remediation playbooks should follow AAP collection patterns (e.g., `secops.*`, `community.crypto`) so they're portable between Satellite-triggered and AAP-triggered execution.
3. **Crypto/PQC taxonomy.** CME-408+ is unowned. Our crypto audit hooks and PQC readiness scans should produce findings in a format that feeds the CME residual-risk join. Opportunity to own this gap.
4. **Flink as enrichment layer.** At scale (10K+ hosts), consider Flink for dedup/correlation in front of EDA rather than rsyslog-direct. AAP has this BUILT (Podman Compose stack, synthetic sources). Our bridge pattern maps to their Normalize+Enrich stages.
5. **Splunk/Wazuh index model.** SIEM egress should align with the ZTA Workshop 6-index Splunk model (zta_syslog, zta_app, zta_vault, zta_opa, zta_network, zta_wazuh) so AAP XDR correlation rules work on our events without custom mappings.
6. **ServiceNow ITSM.** Satellite findings that generate ITSM tickets should use the ServiceNow CMDB enrichment pattern AAP already has (servicenow.itsm collection). Don't build a parallel ticket pipeline.

### Proven Benchmarks (from AAP XDR)

- 57% CVSS reduction on a real CVE using the scan → remediate → verify loop
- 28-second detection-to-containment chain (Splunk alert → Vault credential revocation)
- 97/118 MITRE ATT&CK techniques covered in LIVE testing

## Open Questions

1. **Event volume:** Fast-path events at scale (10K+ hosts) — does Satellite ingest raw events or pre-aggregated summaries from hosts? Consider Flink dedup/correlation layer (AAP XDR pattern) for pre-aggregation.
2. **Lightspeed context window:** How much host context can Lightspeed on-prem ingest per finding? Full compliance scan + event history may exceed model limits.
3. **EDA hosting:** Does EDA run on Satellite, on a separate Ansible Automation Platform instance, or on the managed hosts themselves? AAP XDR assumes separate AAP instance.
4. **Partner plugin boundary:** Where do partner EDR tools (CrowdStrike, etc.) plug in — as an event source, as a parallel consumer, or both? AAP XDR has CrowdStrike integration BUILT.
5. **CompliTime custom profiles:** How do custom compliance profiles feed into control mapping? Is there a registry/API? AAP XDR has ComplyTime at BUILT 1/4.
6. **IdM integration scope:** Read-only (Satellite displays IdM status) or bidirectional (Satellite can trigger IdM actions via EDA)?
7. **CFF adoption:** Should we standardize on Common Findings Format v1.0.0 for all event normalization? AAP XDR already uses it.
8. **CME-408+ ownership:** Crypto/PQC taxonomy gap is unowned in AAP XDR. Should this architecture own the taxonomy and feed it to CME?

## Relationship to Agentic Security PoC

The PoC proved the detection→enrichment→response→visibility pattern at small scale with a specific domain (AI agent security). This architecture generalizes that pattern:

| PoC Component | Generalized Component |
|--------------|----------------------|
| L0 Keylime attestation | Host integrity verification (Satellite could surface attestation status per host) |
| L0.5 Sigstore (cosign/Rekor) | Code/image provenance verification (Satellite could track signed vs unsigned across fleet) |
| Falco eBPF rules | SELinux/auditd/firewall/fapolicyd |
| falco-siem-bridge (enricher) | Control mapping service (CIS/STIG/PCI) |
| EDA revocation playbook | EDA remediation playbooks (Tier 3) |
| Wazuh SIEM dashboard | Satellite security dashboard (Tier 1) |
| MITRE ATT&CK mapping | Compliance control mapping |
| Agent trust tiers | Host compliance posture score |
| ahdapa token revocation | IdM HBAC/service principal actions |
| L4b Blastwall MCS compartmentalization | SELinux MCS category enforcement per host group (Satellite could manage MCS policy modules) |

The PoC is a working reference implementation of the fast path + IAM path. This architecture adds the slow path (compliance/drift), Lightspeed advice layer, and Satellite as the fleet-wide aggregation point.
