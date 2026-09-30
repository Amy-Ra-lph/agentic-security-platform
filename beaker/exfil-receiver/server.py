#!/usr/bin/env python3
"""Minimal HTTPS POST logger — demo prop for the 30-second-mistake exfil endpoint."""

import http.server
import json
import ssl
import sys
from datetime import datetime, timezone

LOG_FILE = "/var/log/exfil-receiver.log"
CERT_DIR = "/opt/demo/exfil-receiver"


class ExfilHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/exfil":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": self.client_address[0],
            "content_length": length,
            "preview": body[:200],
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "received"}).encode())

    def log_message(self, fmt, *args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{CERT_DIR}/server.pem", f"{CERT_DIR}/server-key.pem")

    server = http.server.HTTPServer(("0.0.0.0", port), ExfilHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"Exfil receiver listening on https://0.0.0.0:{port}/exfil")
    server.serve_forever()


if __name__ == "__main__":
    main()
