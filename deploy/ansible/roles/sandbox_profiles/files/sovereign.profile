# OpenShell sandbox profile: sovereign
# Full-trust tier — policy management tools with host enforcement access
# Used by: enforcement-mcp (SELinux/fapolicyd/MLS policy intelligence)

[sandbox]
name = sovereign

[network]
enabled = true
allow_hosts = ${IPA_SERVER}
allow_ports = 443,8443,88,464,389,636,8090

[filesystem]
read_only = false
bind_mounts = /sys/fs/selinux:/sys/fs/selinux:ro,/etc/selinux:/etc/selinux:rw,/etc/fapolicyd:/etc/fapolicyd:rw,/var/log/audit:/var/log/audit:ro,/tmp/output:/tmp/output:rw
tmpfs = /tmp:size=256m

[environment]
passthrough = IPA_SERVER,REALM,SELINUX_POLICY,MLS_ENABLED

[resources]
max_pids = 512
max_memory = 2g
max_cpu = 200

[security]
no_new_privileges = false
seccomp = default
capabilities = CAP_MAC_ADMIN,CAP_SYS_ADMIN,CAP_AUDIT_READ,CAP_NET_BIND_SERVICE
