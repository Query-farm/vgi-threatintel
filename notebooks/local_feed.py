"""Serve invented normalized responses through the worker's supported base_url."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit


class LocalFeed:
    """Own a loopback-only fixture with a sanitized request journal."""

    def __init__(self):
        self.manifest = json.loads(Path("fixtures/feed.json").read_text())
        rows = {r["indicator"]: r for r in self.manifest["rows"]}
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                parsed = urlsplit(self.path)
                query = parse_qs(parsed.query)
                values = query.get("indicator", [])
                allowed = parsed.path == "/reputation" and set(query) == {"indicator"} and len(values) == 1
                indicator = values[0] if values else None
                status = 200 if allowed and indicator in rows else 404 if allowed else 400
                owner.requests.append({"indicator": indicator, "status": status})
                body = json.dumps(rows[indicator] if status == 200 else {"error": "unknown indicator"}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/reputation"

    def close(self):
        """Stop the temporary fixture; no other endpoint is contacted."""
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
