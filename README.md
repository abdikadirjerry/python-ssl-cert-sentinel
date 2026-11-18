# CertSentinel — Python SSL/TLS Certificate Web Auditor (`python-ssl-cert-sentinel`)

A zero-dependency Python web application and JSON API for inspecting live X.509 TLS certificates, verifying cipher suites, and tracking certificate expiration countdowns across monitored domains.

## Features

- **Live TLS Handshake Inspector:** Connects over TCP/443 using Python's `ssl` module to parse issuer CA, TLS version, cipher key bits, SAN entries, and days until expiry.
- **Interactive Web Dashboard:** Clean Nordic frost web interface (`http://127.0.0.1:8080`) with instant domain probing and a pinned domain watchlist.
- **REST JSON Endpoint:** Query `/api/inspect?domain=github.com` for machine-readable certificate telemetry.
- **Zero External Dependencies:** Built exclusively with Python 3 standard library modules (`http.server`, `ssl`, `socket`).

## Setup & Running

1. Start the web server:
   ```bash
   cd python-ssl-cert-sentinel
   python3 server.py
   ```
