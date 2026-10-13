# OpenShell sandbox profile: verified
# Filtered network (IPA server only), scoped write, limited env passthrough

[sandbox]
name = verified

[network]
enabled = true
allow_hosts = ${IPA_SERVER}
allow_ports = 443,8443,88,464,389,636

[filesystem]
read_only = false
bind_mounts = ${PROJECT_DIR}:/workspace:rw,/tmp/output:/tmp/output:rw
tmpfs = /tmp:size=256m

[environment]
passthrough = PROJECT_DIR,OUTPUT_DIR

[resources]
max_pids = 256
max_memory = 1g
max_cpu = 100

[security]
no_new_privileges = true
seccomp = default
capabilities = CAP_NET_BIND_SERVICE
