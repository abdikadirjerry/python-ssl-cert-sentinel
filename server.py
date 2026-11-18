import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from src.inspector import inspect_domain_tls
from src.renderer import render_dashboard_page
from src.watchlist import DomainWatchlist

WATCHLIST = DomainWatchlist()
STATIC_DIR = Path(__file__).parent / "static"


class CertSentinelHandler(BaseHTTPRequestHandler):
    def _send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/static/styles.css":
            css_bytes = (STATIC_DIR / "styles.css").read_bytes()
            self._send_bytes(css_bytes, "text/css; charset=utf-8")
            return

        if parsed.path == "/api/inspect":
            params = parse_qs(parsed.query)
            domain = params.get("domain", [""])[0]
            result = inspect_domain_tls(domain)
            payload = json.dumps(result, indent=2).encode("utf-8")
            self._send_bytes(payload, "application/json; charset=utf-8", 200 if result.get("ok") else 400)
            return

        if parsed.path == "/":
            results = WATCHLIST.audit_all()
            page_html = render_dashboard_page(results).encode("utf-8")
            self._send_bytes(page_html, "text/html; charset=utf-8")
            return

        self._send_bytes(b"404 Not Found", "text/plain; charset=utf-8", 404)

    def do_POST(self) -> None:
        if self.path != "/inspect":
            self._send_bytes(b"404 Not Found", "text/plain; charset=utf-8", 404)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        form_data = parse_qs(raw_body)

        domain = form_data.get("domain", [""])[0]
        pin_to_list = "save_watchlist" in form_data

        instant_result = inspect_domain_tls(domain)
        if pin_to_list and instant_result.get("ok"):
            WATCHLIST.add(instant_result["hostname"])

        results = WATCHLIST.audit_all()
        page_html = render_dashboard_page(results, instant_result=instant_result).encode("utf-8")
        self._send_bytes(page_html, "text/html; charset=utf-8")


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), CertSentinelHandler)
    print(f"[*] CertSentinel web server running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        server.server_close()


if __name__ == "__main__":
    run_server()