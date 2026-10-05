# Agentic Security: Cross-Portfolio Play

## Status: PoC Complete, Demo-Ready

**Audience:** C-level strategy review
**Date:** 2026-10-05
**Owner:** Amy Ralph, Principal PM, RHEL Security/IdM

---

## Executive Summary

AI agents are the new attack surface. Enterprises deploying agentic AI need to answer: *how do I trust an autonomous agent with production credentials, enforce what it can do, and detect when it goes wrong?*

We built a working enforcement stack on RHEL that answers all three. Every layer maps to a Red Hat product. The pattern creates a cross-portfolio pull that makes RHEL, Satellite, AAP, OpenShift, and RHEL AI sell together — not as separate line items but as a unified security posture for AI workloads.

**What's proven today:** 7-layer enforcement stack running on Beaker VMs. Real Falco syscall detection, MITRE ATT&CK-mapped alerts, automated identity revocation via IPA, Wazuh SIEM correlation. End-to-end in seconds, not hours.

---

## The Enforcement Stack — What We Built

| Layer | Function | RH Product | Status |
|-------|----------|------------|--------|
| **L0 Attestation** | Platform integrity proof via TPM | RHEL (Keylime) | Working |
| **L0.5 Supply Chain** | Binary/container signature verification | Sigstore / RHEL | Designed |
| **L1 DARC** | Credential issuance with anti-phishing | FreeIPA + ahdapa | Working |
| **L2 WID/OBO** | Token lifecycle, scope ceiling per role | IPA OAuth2 / ahdapa | Working |
| **L3 Policy** | Runtime authorization (Cedar/AuthZEN) | Policy sidecar (new) | Designed |
| **L4a Sandbox** | Execution confinement per trust tier | OpenShell (RHEL) | Working |
| **L4b Blastwall** | SELinux MCS compartmentalization | RHEL SELinux | Working |
| **L5 Audit** | Detect → classify → respond → correlate | Falco + AAP/EDA + Wazuh | **Working E2E** |

**Trust Tiers:** Every agent is classified Blocked → Untrusted → Verified → Sovereign. Trust tier determines which layers gate the agent and what ceiling applies to its credentials, sandbox, and policy scope.

---

## How It Sells Across the Portfolio

### RHEL — The Foundation

Every layer runs on RHEL. This isn't optional — the enforcement stack requires:
- **Keylime** (L0) — RHEL-shipped, Rust agent, TPM 2.0
- **SELinux** (L4b) — RHEL's mandatory access control, MCS labels for compartmentalization
- **FreeIPA** (L1/L2) — identity lifecycle, credential issuance, fleet-wide revocation
- **OpenShell** (L4a) — RHEL execution sandboxing with ODIS profiles

**Sell:** Any enterprise deploying AI agents on Linux needs RHEL for the security substrate. Not CentOS, not Ubuntu — RHEL has Keylime, FreeIPA, and SELinux MCS integration that no other distro ships together.

### Satellite — Visibility + Management

The [Satellite Security Module architecture](../specs/) defines a dual-speed pipeline:
- **Fast path:** Real-time SELinux/audit event streaming → compliance posture
- **Slow path:** Scheduled scans, baseline drift detection, SCAP/STIG reporting

Satellite becomes the single pane for fleet security posture across thousands of RHEL hosts running agents. Lightspeed integration (Tier 2) provides AI-powered remediation advice. Tier 3 pushes automated remediation through AAP.

**Sell:** Satellite moves from "patch management" to "security operations center for AI workloads." Every host running agents needs Satellite for visibility. Target: Satellite 6.22+ (Nov 2027).

### Ansible Automation Platform (AAP) + EDA — Response

EDA is the response engine. Our PoC proves the pattern:
- Falco detects anomaly → bridge classifies with MITRE mapping → EDA matches rule → playbook revokes agent identity in IPA
- Detection to remediation: seconds, fully automated, no human in the loop for critical threats

The AAP XDR Fabric team built the same core pattern independently (Flink correlation, CFF v1.0.0, CME-408+). **We must interoperate, not compete.** Our OCSF events feed their correlation engine; their fabric distributes our playbooks.

**Sell:** AAP + EDA is already in the customer's automation stack. Agentic security gives it a new, high-urgency use case — security response automation. Every SOC team evaluating SOAR needs to see this.

**PQC gap:** CME-408+ in AAP XDR Fabric is UNOWNED for PQC. We should own that alignment.

### OpenShift — Container + Kubernetes

Agents run in containers. The enforcement stack extends to OpenShift:
- **L0 Attestation** → node-level TPM attestation (Keylime DaemonSet)
- **L3 Policy** → Cedar sidecar as admission webhook, AuthZEN for runtime decisions
- **L4a Sandbox** → OpenShell profiles map to Kubernetes SecurityContext
- **L5 Audit** → Falco is already the standard for Kubernetes runtime security

Confidential Computing on OpenShift (SEV-SNP, TDX) adds hardware-level isolation for sovereign workloads. Azure CVM adoption: 6% of RHEL VMs since Oct GA.

**Sell:** OpenShift customers running AI workloads need agent security at the orchestration layer. This makes RHEL + OpenShift the only platform with attestation-to-revocation for containerized agents.

### RHEL AI — The Workload

RHEL AI hosts the models that agents invoke. The enforcement stack gates which agents can access which models:
- **L2 WID/OBO** — token scope ceiling limits which model endpoints an agent can call
- **L3 Policy** — Cedar rules enforce "only Verified-tier agents can invoke the production model"
- **L5 Audit** — every model invocation is logged in OCSF format

**Sell:** RHEL AI without agent security is an open API. With it, you get model access governance that maps to your identity infrastructure.

---

## Partner Plays

### Cloud Providers

| Partner | Opportunity | Status |
|---------|-------------|--------|
| **AWS** | CC Marketplace (CVM), EKS attestation integration | Azure CVM = 6% RHEL VMs. AWS CVM EOY target (staffing needed) |
| **Azure** | Confidential VMs, CC validated pattern | Active. SEV-SNP roadmap deck delivered |
| **GCP** | Confidential Computing, Workload Identity | GCP WID aligns with L2 pattern |

**Pattern:** Cloud providers need attestation (L0) and workload identity (L2) for their confidential computing offerings. We provide both, integrated with RHEL's security stack.

### Ericsson — Telecom Edge

OBO daemon in production CU (Central Unit) deployments. Samsung+ in pipeline.
- Telecom edge runs AI agents for network optimization, traffic management
- Agents need the same trust tiers: untrusted agents on edge nodes, sovereign agents in core
- RHEL + Satellite + AAP is already the telecom stack — agentic security is a natural extension

**Sell:** Ericsson deal proves the OBO (L2) pattern works in production telecom. Every 5G edge deployment running AI needs agent identity management.

### EU Sovereignty — EUDI Wallet / eIDAS 2.0

Dual-path opportunity:
- **Keycloak path** — enterprise identity federation for agent-to-service auth
- **FreeIPA + ahdapa path** — sovereign identity for government/regulated agents

IDC data: sovereignty/compliance is the #1 driver for infrastructure decisions. Gartner assessment covers 31 EU criteria. The enforcement stack's hub-spoke sovereignty model (3 domains, 17 threats modeled) maps directly to eIDAS 2.0 requirements.

**Sell:** EU governments deploying AI agents in regulated environments need sovereign identity + attestation. Only Red Hat ships FreeIPA + Keylime + SELinux together on a FIPS-validated platform.

### IBM — Agentic AI Security

CVS briefing established the workflow-vs-agent identity debate. Our per-agent identity model (SPIFFE SVIDs for accountability) is the answer IBM's clients are asking for.
- WIMSE policy engine + AuthZEN aligns with IBM's zero-trust frameworks
- DARC (AB's RFC 8628 anti-phishing) hardens the credential issuance path

**Sell:** IBM field teams selling AI consulting need a reference architecture for agent security. This is it — built on RHEL, proven in PoC, mapped to standards (WIMSE, AuthZEN, OCSF, MITRE ATT&CK).

---

## Competitive Differentiator

No other vendor ships an integrated enforcement stack for AI agents:

| Capability | Red Hat | AWS | Azure | Google | VMware |
|------------|---------|-----|-------|--------|--------|
| Hardware attestation (L0) | Keylime (RHEL) | Nitro Enclaves | CC VMs | Confidential VMs | vTPM |
| Agent identity (L1/L2) | FreeIPA + ahdapa | IAM Roles | Entra WID | WIF | AD |
| Runtime policy (L3) | Cedar sidecar | Cedar (separate) | Azure Policy | BeyondCorp | None |
| Execution sandbox (L4) | OpenShell + SELinux MCS | Lambda/Firecracker | Sandbox | gVisor | None |
| Detect + respond (L5) | Falco + EDA + Wazuh | GuardDuty | Sentinel | Chronicle | Carbon Black |
| **Integrated stack** | **Yes — single vendor** | No | No | No | No |

The key differentiator: Red Hat is the only vendor where all five layers ship on a single OS, managed by a single automation platform, with identity federation built in. Everyone else requires stitching 3-5 vendors together.

**Specific advantages:**
1. **DARC anti-phishing** — defeats consent phishing (Storm-2372 class attacks). Working implementation in ahdapa, COPR built, standards-track candidate. No competitor has this.
2. **Sovereign on-prem path** — FreeIPA + ahdapa with ML-DSA-65 (PQC-native). No cloud-first competitor offers on-prem agent identity with post-quantum readiness.
3. **28-second detection-to-containment** — AAP XDR Fabric benchmark. 57% CVSS reduction on real CVE. Our PoC proves the same speed for agent-specific threats.
4. **97/118 MITRE techniques** — AAP XDR Fabric coverage. Our bridge adds agent-specific MITRE mappings (T1059.006, T1552.001, T1078.003, T1611) that generic SIEM tools miss.

**IBM positioning note:** IBM's approach = workflow identity (Verify + Vault). Our differentiator = runtime enforcement *after* token issuance. These are complementary, not competitive — the enforcement stack assumes tokens exist and governs what they can do.

---

## What's Demo-Ready Today

1. **Attestation (L0):** Keylime continuous attestation with swtpm, 2-second verification cycle
2. **SELinux (L4b):** MCS compartmentalization, domain transitions, mandatory access control
3. **Detection Pipeline (L5):** Falco → bridge (MITRE-mapped) → EDA (automated revocation) → Wazuh (SIEM correlation)
4. **Identity Revocation:** Detection triggers IPA principal disable + OAuth2 token revocation in seconds
5. **Trust Tiers:** 4 archetypes (Blocked/Untrusted/Verified/Sovereign) with 23 capabilities mapped

**Demo format:** Two scripts ready — 20-min full stack, 10-min attestation only. GDocs for walk-through.

---

## Market Context

| Market | Size / Growth | RH Position |
|--------|--------------|-------------|
| **IAM** | $36.96B by 2030 (14.12% CAGR) | FreeIPA + ahdapa = on-prem sovereign path |
| **NHI / ISPM** | 19.6-22.8% CAGR | Identity Control Plane = $83.6B addressable (CY29 Tier 3) |
| **GRC / Compliance** | 14.2% CAGR | Telemetry: $12-50M revenue recovery potential |
| **EU Sovereignty** | $11B → $31.7B (eIDAS, 19.4% CAGR) | Only vendor with FIPS + sovereign IdM + PQC |
| **IdM at Risk** | $2.91B NAPS, 961 customers | Agent security = retention play for IdM base |

**CY27 Big Rocks priority:** Agentic AI Security = #1. CVE Ecosystem = #2. CompliTime = #3. PQC = Tier 2 (shipping, not strategic).

---

## Revenue Motion

### Direct
- **RHEL subscriptions:** Every host running AI agents = RHEL seat (attestation + SELinux + FreeIPA)
- **Satellite subscriptions:** Fleet-wide security posture = Satellite seat per managed host
- **AAP subscriptions:** Automated remediation = AAP seat for security operations
- **RHEL AI subscriptions:** Model governance = RHEL AI seat per inference endpoint

### Attach
- Customer buys RHEL AI → needs agent security → pulls Satellite + AAP + RHEL
- Customer buys OpenShift for AI → needs runtime security → pulls RHEL + AAP/EDA
- Customer evaluates CC (SEV-SNP/TDX) → needs attestation → pulls RHEL + Satellite

### Partner Revenue
- Cloud marketplace listings (AWS/Azure/GCP) for CC-enabled RHEL with agent security
- Telecom OEM (Ericsson/Samsung) for edge agent security
- SI partnerships (IBM, Accenture, Deloitte) for regulated industry deployments

### Customer Proof Points
- **Ericsson:** OBO daemon in production CU, Samsung+ in pipeline
- **CVS:** Agentic identity briefing, deeper engagement requested
- **UPS:** Device code flow validated (case 04529036, 9/23)
- **Azure CVM:** 6% of all RHEL VMs since Oct GA — benchmark for AWS target
- **INPS (EU):** $3M/yr deal contingent on sovereign identity path

---

## Ask

1. **Staffing:** AWS CVM integration needs dedicated engineering (EOY target)
2. **Alignment:** AAP XDR Fabric interop — schedule joint architecture review
3. **Marketing:** Position "Agent Security" as CY27 Big Rock alongside PQC and Compliance
4. **Field enablement:** 22 sales tools already built — need GTM activation for AI security positioning

---

## Next Steps

| Action | Owner | Timeline |
|--------|-------|----------|
| Satellite Security Module spec review | Amy / Eric Helms | 3 weeks |
| AAP XDR Fabric joint architecture | Amy / AAP team | Oct 2026 |
| AWS CVM staffing request | Amy / Raj Das | Oct 2026 |
| Field enablement activation | Amy / Marketing | Q4 2026 |
| Demo recording for Lukas (SELinux + attestation) | Amy / Lukas Vrabec | This week |
