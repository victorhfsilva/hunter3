"""Local, deliberately vulnerable HTTP target used by the acceptance tests.

Two virtual subdomains (a.localhost and b.localhost) are served by the same
process and distinguished by the Host header.  Nothing here is reachable from
outside the loopback interface.
"""

from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

COUNTER = {"requests": 0}
SLOW = 0.0


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silence stderr
        return

    def _host(self) -> str:
        return (self.headers.get("Host", "127.0.0.1").split(":")[0] or "127.0.0.1").lower()

    def _send(self, status: int, body: bytes | str, content_type: str = "text/html; charset=utf-8", headers: dict | None = None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "mock-hunter")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status: int, payload, headers: dict | None = None) -> None:
        self._send(status, json.dumps(payload), "application/json", headers)

    def _cors_headers(self) -> dict:
        origin = self.headers.get("Origin")
        if origin:
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
        return {}

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(min(length, 1_000_000)) if length else b""

    def do_GET(self) -> None:
        path = urlsplit(self.path)
        if path.path != "/__stats":
            COUNTER["requests"] += 1
            if SLOW:
                time.sleep(SLOW)
        route = path.path
        query = parse_qs(path.query, keep_blank_values=True)
        host = self._host()

        if route == "/__stats":
            self._json(200, {"requests": COUNTER["requests"], "host": host})
        elif route == "/":
            html = """<!doctype html><html><head><title>Mock</title>
<script src="/static/app.js"></script></head><body>
<h1>Mock target</h1>
<a href="/api/users/1">user 1</a>
<a href="/api/orders/7">order 7</a>
<a href="/search?q=hello">search</a>
<a href="/login">login</a>
<a href="https://evil.example/out">external</a>
<a href="/static/app.js">app js</a>
</body></html>"""
            self._send(200, html)
        elif route in ("/api/users/1", "/api/users/2"):
            uid = 1 if route.endswith("/1") else 2
            name = "Alice" if uid == 1 else "Bob"
            self._json(
                200,
                {"id": uid, "name": name, "email": f"user{uid}@local.invalid", "role": "user", "account": {"plan": "free"}},
                self._cors_headers(),
            )
        elif route in ("/api/orders/7", "/api/orders/8"):
            oid = 7 if route.endswith("/7") else 8
            self._json(200, {"id": oid, "order": {"total": 100 + oid, "status": "paid"}, "price": 100 + oid}, self._cors_headers())
        elif route in ("/graphql", "/api/graphql"):
            if self.command != "POST":
                self._json(405, {"errors": [{"message": "POST only"}]})
                return
            raw = self._read_body()
            self._graphql(raw.decode("utf-8", "replace"))
        elif route == "/.env":
            self._send(200, "APP_NAME=Mock\nAPP_ENV=local\nAPP_KEY=base64:not-a-real-secret\n")
        elif route == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n", "text/plain")
        elif route == "/login":
            for name in ("next", "url", "redirect", "return"):
                if name in query and query[name]:
                    destination = query[name][0]
                    if destination.startswith("http") and "evil.example" in destination:
                        self._send(302, b"", "text/plain", {"Location": destination})
                        return
            self._send(
                200,
                """<html><body><form action="/login" method="post">
<input name="email"><input name="password" type="password">
<button>Login</button></form></body></html>""",
            )
        elif route in ("/auth", "/register", "/signin"):
            self._send(200, """<html><body><form action="/register" method="post"><input name="email"><input name="password"></form></body></html>""")
        elif route == "/static/app.js":
            self._send(
                200,
                """const API = '/api/graphql';
fetch('/api/orders/7').then(r => r.json());
const users = '/api/users/1';
const admin = '/api/admin/export';
//# sourceMappingURL=app.js.map
""",
                "application/javascript",
            )
        elif route == "/static/app.js.map":
            self._json(200, {"version": 3, "sources": ["app.ts"], "sourcesContent": ["const reset = '/api/auth/password/reset';"]})
        elif route == "/search":
            value = query.get("q", [""])[0]
            self._send(200, f"<html><body>Results for {value}</body></html>")
        elif route == "/openapi.json":
            self._json(
                200,
                {
                    "openapi": "3.0.0",
                    "info": {"title": "Mock API", "version": "1.0.0"},
                    "paths": {
                        "/api/users/1": {
                            "get": {"parameters": [{"name": "id", "in": "path"}]},
                            "patch": {"parameters": [{"name": "role", "in": "body"}]},
                        },
                        "/api/orders/7": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
                        "/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
                    },
                },
            )
        elif route == "/sitemap.xml":
            host = self.headers.get("Host", "127.0.0.1")
            self._send(
                200,
                f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>http://{host}/search?q=sitemap</loc></url>
<url><loc>http://{host}/api/users/1</loc></url>
</urlset>""",
                "application/xml",
            )
        elif route == "/redirect":
            destination = query.get("url", ["/"])[0]
            self._send(302, b"", "text/plain", {"Location": destination})
        elif route == "/actuator/health":
            self._json(200, {"status": "UP"})
        elif route == "/version.json":
            self._json(200, {"version": "1.0.0-mock"})
        else:
            self._json(404, {"error": "not found", "path": route})

    def _graphql(self, text: str) -> None:
        try:
            parsed = json.loads(text) if text else None
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            self._json(200, [{"data": {"__typename": "Query"}} for _ in parsed])
            return
        if "__schema" in text:
            self._json(
                200,
                {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {"name": "Mutation"},
                            "types": [{"name": "Query", "kind": "OBJECT"}, {"name": "Mutation", "kind": "OBJECT"}],
                        }
                    }
                },
            )
            return
        if "__typename" in text:
            self._json(200, {"data": {"__typename": "Query"}})
            return
        self._json(200, {"errors": [{"message": "unsupported query"}]})

    def do_POST(self) -> None:
        path = urlsplit(self.path)
        COUNTER["requests"] += 1
        if SLOW:
            time.sleep(SLOW)
        body = self._read_body()
        if path.path in ("/api/auth/register", "/register", "/signup"):
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
            except ValueError:
                payload = {}
            self._json(201, {"created": True, "email": payload.get("email", "")})
        elif path.path in ("/graphql", "/api/graphql"):
            self._graphql(body.decode("utf-8", "replace"))
        elif path.path == "/api/users/1":
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
            except ValueError:
                payload = {}
            if "role" in payload or "is_admin" in payload:
                payload.setdefault("id", 1)
                payload.setdefault("name", "Alice")
                self._json(200, payload, self._cors_headers())
            else:
                self._json(200, {"id": 1}, self._cors_headers())
        else:
            self._json(404, {"error": "not found", "path": path.path})

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
    print(json.dumps({"port": server.server_address[1], "pid": __import__("os").getpid()}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
