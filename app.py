"""Local development server. No external network requests."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
from scoring import rank, parse_csv

MAX_BYTES = 2_000_000
INDEX = Path(__file__).with_name("index.html")

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, payload, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def json_reply(self, status, obj):
        self.reply(status, json.dumps(obj, allow_nan=False).encode())

    def do_GET(self):
        if self.headers.get("Host") not in ("127.0.0.1:8000", "localhost:8000"):
            return self.json_reply(403, {"error": "Local host only"})
        if self.path == "/":
            self.reply(200, INDEX.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/health":
            self.json_reply(200, {"status": "ok"})
        else:
            self.json_reply(404, {"error": "Not found"})

    def do_POST(self):
        if self.headers.get("Host") not in ("127.0.0.1:8000", "localhost:8000") or self.headers.get("Origin") not in (None, "http://127.0.0.1:8000", "http://localhost:8000"):
            return self.json_reply(403, {"error": "Local origin only"})
        if self.path != "/api/rank":
            return self.json_reply(404, {"error": "Not found"})
        if self.headers.get_content_type() != "application/json":
            return self.json_reply(415, {"error": "Expected JSON"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.json_reply(400, {"error": "Invalid body length"})
        if not 0 < length <= MAX_BYTES:
            return self.json_reply(413, {"error": "Request exceeds limit or is empty"})
        try:
            obj = json.loads(self.rfile.read(length))
            if not isinstance(obj, dict) or set(obj) not in ({"csv"}, {"findings"}):
                raise ValueError("Supply either csv or findings")
            rows = parse_csv(obj["csv"]) if "csv" in obj else obj["findings"]
            self.json_reply(200, {"findings": rank(rows), "policy": "v1"})
        except (ValueError, UnicodeError, RecursionError) as exc:
            self.json_reply(400, {"error": str(exc)})

if __name__ == "__main__":
    with ThreadingHTTPServer(("127.0.0.1", 8000), Handler) as server:
        print("VulnPriority running at http://127.0.0.1:8000")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
