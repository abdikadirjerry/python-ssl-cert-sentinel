import socket
import ssl
from datetime import datetime, timezone


def inspect_domain_tls(hostname: str, port: int = 443, timeout: float = 4.0) -> dict:
    clean_host = hostname.strip().replace("https://", "").replace("http://", "").split("/")[0]
    if not clean_host:
        return {"ok": False, "error": "Please enter a valid domain name."}

    context = ssl.create_default_context()

    try:
        with socket.create_connection((clean_host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=clean_host) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher_name, tls_version, key_bits = tls_sock.cipher()

        subject = dict(item[0] for item in cert.get("subject", []))
        issuer = dict(item[0] for item in cert.get("issuer", []))
        sans = [val for kind, val in cert.get("subjectAltName", []) if kind == "DNS"]

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days

        if days_remaining < 0:
            health = "EXPIRED"
        elif days_remaining <= 14:
            health = "CRITICAL"
        elif days_remaining <= 30:
            health = "WARNING"
        else:
            health = "HEALTHY"

        return {
            "ok": True,
            "hostname": clean_host,
            "common_name": subject.get("commonName", clean_host),
            "issuer_org": issuer.get("organizationName", issuer.get("commonName", "Unknown CA")),
            "tls_version": tls_version,
            "cipher": cipher_name,
            "key_bits": key_bits,
            "valid_from": not_before.strftime("%Y-%m-%d"),
            "valid_until": not_after.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "health": health,
            "san_count": len(sans),
            "sans": sans[:8],
        }
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "hostname": clean_host, "error": f"Certificate verification failed: {exc.reason}"}
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"ok": False, "hostname": clean_host, "error": f"Network handshake error: {exc}"}