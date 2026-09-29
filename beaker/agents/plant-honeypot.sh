#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Plants fake credentials for the 30-Second Mistake demo.
# All values are clearly marked as demo canaries and use invalid formats.
set -euo pipefail

mkdir -p "$HOME/.aws" "$HOME/.ssh" "$HOME/.kube"

cat > "$HOME/.aws/credentials" << 'EOF'
[default]
aws_access_key_id = AKIADEMOCANARY00001
aws_secret_access_key = DEMO-CANARY-DO-NOT-USE-wJalrXUtnFEMI/K7MDENG/bPxRfiCY
region = us-east-1
EOF

if [ ! -f "$HOME/.ssh/id_rsa" ]; then
    ssh-keygen -t rsa -b 2048 -f "$HOME/.ssh/id_rsa" -N "" -C "DEMO-CANARY-DO-NOT-USE" -q
fi

cat > "$HOME/.kube/config" << 'EOF'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://demo-cluster.example.com:6443
    certificate-authority-data: DEMO-CANARY-DO-NOT-USE
  name: demo-canary-cluster
contexts:
- context:
    cluster: demo-canary-cluster
    user: demo-canary-user
  name: demo-canary
current-context: demo-canary
users:
- name: demo-canary-user
  user:
    token: DEMO-CANARY-DO-NOT-USE-eyJhbGciOiJSUzI1NiJ9
EOF

echo "Honeypot credentials planted in $HOME/.aws, $HOME/.ssh, $HOME/.kube"
echo "All values marked DEMO-CANARY — not usable against real services."
