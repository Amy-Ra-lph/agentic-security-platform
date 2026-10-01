#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generate self-signed cert for exfil receiver demo prop.
set -euo pipefail

CERT_DIR="${1:-.}"
HOSTNAME="${2:-$(hostname -f)}"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -days 7 \
    -subj "/CN=$HOSTNAME/O=DEMO-EXFIL-PROP" \
    -addext "subjectAltName=DNS:$HOSTNAME,DNS:system1,IP:127.0.0.1"

echo "Generated cert.pem and key.pem for $HOSTNAME (7-day expiry)"
