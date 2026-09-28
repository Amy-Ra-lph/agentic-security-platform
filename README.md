# Agentic Security Platform

A reference implementation for securing AI agent fleets using trust tiers, policy-as-code, and behavioral anomaly detection. Built on open standards: OAuth 2.0, Cedar, OCSF, SPIFFE, and AuthZEN.

## Problem

Enterprises deploying AI agent fleets face privilege misalignment: agents are either over-privileged (security risk), under-privileged (productivity loss), or — most commonly — not controlled at all. Identity systems were not designed for non-human actors that delegate to each other.

## Approach

A five-layer enforcement stack where every agent request passes through all layers in sequence. Any layer can deny.

| Layer | Purpose | Technology |
|-------|---------|------------|
| L1 | Credential issuance | Device authorization with return confirmation |
| L2 | Token lifecycle | On-behalf-of delegation with scope narrowing |
| L3 | Runtime authorization | Cedar policy engine (AuthZEN-compatible) |
| L4 | Execution confinement | Sandbox profiles per trust tier |
| L5 | Audit + response | OCSF logging, behavioral anomaly detection, circuit breaker |

## Trust Tiers

Four tiers classify agents by trust level. The platform applies security policy by tier and role profile — no per-agent configuration needed.

| Tier | Access | Value |
|------|--------|-------|
| **Blocked** | None — enrollment denied | Protect the platform from known threats and compromised agents |
| **Untrusted** | Read-only, strict sandbox | New agents can observe but can't change anything until they earn trust |
| **Verified** | Scoped read+write | Known agents get exactly the access their role requires |
| **Sovereign** | Full | Internal agents operate without friction on attested platforms |

Agents graduate up with evidence (attestation, device pairing, platform enrollment) and get demoted on breach (circuit breaker, revocation, blocklist match).

## Pre-Enrollment Assessment

New tools are vetted before they touch any data:

- **Static analysis:** Binary signature verification, dependency scan, scope manifest review
- **Dynamic analysis:** Sandboxed execution with synthetic honeypot data, syscall monitoring, exfiltration detection
- **Scoring:** Risk score determines initial tier assignment (0-30: Untrusted, 61-100: Blocked)

## Key Features

- **Delegation narrowing:** When Agent A delegates to Agent B, the resulting token scopes are the intersection — privileges never widen
- **Two-tier policy evaluation:** Fast path (token claim check, sub-microsecond) for 95% of requests; slow path (full Cedar evaluation) for protected resources
- **Behavioral anomaly detection:** Catches permitted-but-wrong actions — hallucination, swarm amplification, behavioral drift
- **Circuit breaker:** Profile-level throttle/halt/block for swarm anomalies, with orchestrator intent signals to distinguish approved scaling from misbehavior
- **Integrity attestation:** Supply chain verification (Sigstore) + platform attestation (Keylime/TPM) + workload identity (SPIFFE) feeds tier classification

## Structure

```
daemon/          Token lifecycle daemon with tier awareness
policy/          Cedar policy rules + sidecar
audit/           OCSF pipeline, anomaly detector, circuit breaker
assess/          Pre-enrollment assessment harness
target-api/      Simulated incident management API (demo target)
profiles/        Agent role profiles + sandbox configurations
demo/            7-act demo runner
tests/           Test harness + benchmarks
docs/            Design specs, architecture, standards mapping
```

## Standards Alignment

- OAuth 2.0 Device Authorization (RFC 8628) + return confirmation hardening
- OAuth 2.0 Token Exchange (RFC 8693) for on-behalf-of delegation
- Rich Authorization Requests (RFC 9396) for fine-grained authorization_details
- Cedar policy language (formally verifiable, >100K evals/sec)
- AuthZEN 1.0 for policy evaluation point placement
- OCSF for structured security event logging
- SPIFFE/SPIRE for workload identity attestation
- Sigstore for supply chain verification

## License

Apache-2.0
