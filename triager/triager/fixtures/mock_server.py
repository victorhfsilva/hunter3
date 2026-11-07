"""Local multi-host target for acceptance tests.

The same process serves a.localhost and b.localhost, distinguished by the Host
header.  It is intentionally vulnerable only for the canary checks used by the
suite; it never touches the real network.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

COUNTER = {"requests": 0}
LOCK = threading.Lock()
SLOW = 0.0


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _host(self) -> str:
        return (self.headers.get("Host", "127.0.0.1").split(":")[0] or "127.0.0.1").lower()

    def _send(self, status: int, body: bytes | str, content_type: str = "text/html; charset=utf-8", headers: dict | None = None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "triager-mock")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status: int, payload, headers: dict | None = None) -> None:
        self._send(status, json.dumps(payload), "application/json", headers)

    def _count(self) -> None:
        with LOCK:
            COUNTER["requests"] += 1

    def do_GET(self) -> None:
        path = urlsplit(self.path)
        if path.path != "/__stats":
            self._count()
            if SLOW:
                time.sleep(SLOW)
        query = parse_qs(path.query, keep_blank_values=True)
        route = path.path
        if route == "/__stats":
            with LOCK:
                self._json(200, {"requests": COUNTER["requests"], "host": self._host()})
            return
        if route == "/":
            self._send(
                200,
                """<!doctype html><html><head><title>Triager mock</title></head><body>
<h1>Mock</h1><a href="/reflect?q=hello">reflect</a>
<a href="/safe">safe</a><a href="/api/users/1">user</a>
<form action="/login" method="post"><input name="email"><input name="password"></form>
</body></html>""",
            )
        elif route == "/reflect":
            value = query.get("q", [""])[0]
            self._send(200, f"<html><body>Reflected value: {value}</body></html>")
        elif route == "/safe":
            self._send(200, "<html><body>This page is safe. No reflection here.</body></html>")
        elif route == "/redirect":
            destination = query.get("next", ["/"])[0]
            if destination.startswith("http"):
                self._send(302, b"", "text/plain", {"Location": destination})
            else:
                self._send(200, f"<html><body>redirect target {destination}</body></html>")
        elif route == "/api/users/1":
            self._json(200, {"id": 1, "email": "user1@local.invalid", "role": "user", "account": {"plan": "free"}})
        elif route == "/api/users/2":
            self._json(200, {"id": 2, "email": "user2@local.invalid", "role": "user", "account": {"plan": "free"}})
        elif route == "/graphql":
            self._json(200, {"data": {"__typename": "Query"}})
        else:
            self._json(404, {"error": "not found", "path": route, "host": self._host()})

    def do_POST(self) -> None:
        path = urlsplit(self.path)
        self._count()
        if SLOW:
            time.sleep(SLOW)
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length:
            self.rfile.read(min(length, 1_000_000))
        if path.path == "/graphql":
            self._json(200, {"data": {"__typename": "Query"}})
        else:
            self._json(200, {"ok": True, "path": path.path})

    def do_PATCH(self) -> None:
        self.do_POST()

    def do_PUT(self) -> None:
        self.do_POST()

    def do_DELETE(self) -> None:
        self._json(405, {"error": "mock does not delete"})


def main() -> None:
    global SLOW
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--slow", type=float, default=0.0)
    args = parser.parse_args()
    SLOW = max(0.0, args.slow)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), MockHandler)
    server.daemon_threads = True
    print(json.dumps({"port": server.server_address[1]}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
