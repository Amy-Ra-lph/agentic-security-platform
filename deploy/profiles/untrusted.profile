# OpenShell sandbox profile: untrusted
# No network, read-only filesystem, no env passthrough

[sandbox]
name = untrusted

[network]
enabled = false

[filesystem]
read_only = true
bind_mounts =
tmpfs = /tmp:size=64m

[environment]
passthrough =

[resources]
max_pids = 64
max_memory = 256m
max_cpu = 50

[security]
no_new_privileges = true
seccomp = default
capabilities =
