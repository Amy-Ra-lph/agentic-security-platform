# OpenShell Sandbox Profiles

Two profiles mapping to trust tiers from the agentic security platform:

| Profile | Tier | Network | Filesystem | Syscalls |
|---------|------|---------|------------|----------|
| `untrusted.profile` | Untrusted | none | read-only | strict (no socket, no execve) |
| `verified.profile` | Verified | HTTPS only | scoped read + write | restricted (no ptrace, no raw socket) |

## Usage

```bash
openshell sandbox create --profile untrusted -- python3 agent.py
openshell sandbox create --profile verified -- python3 agent.py
```

## Fallback (no OpenShell)

If OpenShell is not available, the demo scripts fall back to Podman:

```bash
# Untrusted equivalent
podman run --rm --network=none --read-only ...

# Verified equivalent
podman run --rm --read-only --tmpfs /tmp:rw ...
```
