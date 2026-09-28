# Agentic Security Platform — RHEL PoC

## Overview

Phase 2.5 PoC demonstrating five-layer enforcement stack for AI agent fleet security on RHEL. Trust tiers (Blocked/Untrusted/Verified/Sovereign) with agent role profiles, Cedar policy engine, OpenShell sandboxing, OCSF audit pipeline, and behavioral anomaly detection.

## Design Spec

`docs/specs/2026-09-28-agentic-security-trust-tiers-design.md`

## Architecture

Five layers, sequential. Any layer can deny:
- L1 DARC (ahdapa AS) — credential issuance with return confirmation
- L2 WID/ahdapa (OBO daemon) — token lifecycle, scope ceiling per profile, delegation narrowing
- L3 Policy (Cedar sidecar) — runtime authorization, AuthZEN, two-tier fast/slow path
- L4 OpenShell (ODIS profiles) — execution confinement per tier
- L5 Audit (OCSF pipeline) — structured logging, behavioral anomaly, circuit breaker

## Dual Remote

- **GitLab (internal):** `gitlab.cee.redhat.com:afarley/rhel-agentic-security` — RHEL-centric, customer refs, Jira alignment
- **GitHub (upstream):** `github.com/Amy-Ra-lph/agentic-security-platform` — vendor-neutral, standards-aligned

**Rule:** Never push customer names, revenue data, Jira refs, or RH-internal content to GitHub. GitLab-only dirs: `docs/customer/`, `docs/strategy/`, `beaker/`.

## Related Repos

- `ipa-oauth2-plugin` — L2 foundation (OBO daemon, 60/60 tests)
- `workload-identity-poc` — SPIFFE/SPIRE attestation chain
- `jira-pm-tools` — PM tooling (Alika, MCP backends)

## Key People

- AB (Alexander Bokovoy) — ahdapa, DARC, FreeIPA integration
- twoerner (Thomas Woerner) — ipacta, IPA plugin framework
- azaalouk — OpenShell, ODIS sandbox profiles
