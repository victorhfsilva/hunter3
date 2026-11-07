"""Phase 1 — deeper, non-intrusive reconnaissance with incremental reporting."""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urljoin, urlsplit

from . import intel
from .budget import BudgetExceeded
from .report import mask_email
from .state import utcnow

SECRET_PATTERNS = [
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("stripe-live-key", re.compile(r"sk_live_[0-9A-Za-z]{10,}")),
    ("gitlab-token", re.compile(r"glpat-[0-9A-Za-z_-]{10,}")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")
WAF_SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status"], []),
    ("AWS", ["x-amzn-requestid", "x-amz-cf-id"], []),
    ("Akamai", ["x-akamai-", "akamai-grn"], ["Reference #18."]),
    ("Imperva", ["x-iinfo"], []),
    ("F5", [], ["BigIP"]),
    ("ModSecurity", [], ["mod_security", "noyb"]),
    ("Sucuri", ["x-sucuri-id"], []),
    ("Fastly", ["x-served-by", "x-cache"], []),
]
GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/api/v1/graphql",
    "/graphiql",
    "/gql",
    "/api/gql",
    "/graphql/v1",
    "/graph",
]
LEAK_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/asset-manifest.json",
    "/version.json",
    "/manifest.json",
    "/package.json",
    "/config.json",
    "/crossdomain.xml",
    "/health",
    "/status",
    "/server-status",
    "/debug",
    "/phpinfo.php",
    "/api/internal",
    "/.DS_Store",
    "/sitemap.xml",
]
OPENAPI_PATHS = {
    "/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
}
LOGIN_PATHS = ["/login", "/signin", "/sign-up", "/register", "/auth", "/forgot-password", "/reset-password", "/sso"]
REGISTER_PATHS = ["/api/auth/register", "/register", "/signup", "/api/register"]


def _truncate_secret(secret: str) -> str:
    if len(secret) <= 12:
        return secret[:4] + "***"
    return f"{secret[:8]}...{secret[-4:]}"


def _json_or_none(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


class ReconRunner:
    def __init__(self, ctx, host: str, client):
        self.ctx = ctx
        self.host = host
        self.client = client
        self.state = ctx.targets[host]
        self.recon = self.state["recon"]
        self.logger = ctx.logger(host)
        self.settings = ctx.settings
        self.seen_pages: set[str] = set()
        self.page_bodies: list[tuple[str, str]] = []
        self.baseline_body = ""

    def mark(self, name: str, status: str, detail: str = "") -> None:
        self.state["phases"]["recon"]["substeps"][name] = {
            "status": status,
            "detail": detail,
            "at_utc": utcnow(),
        }

    def run(self) -> None:
        phase = self.state["phases"]["recon"]
        phase["status"] = "running"
        phase["started_utc"] = phase.get("started_utc") or utcnow()
        self.ctx.budget.mark_phase("recon")
        steps = [
            ("baseline", self.step_baseline),
            ("waf", self.step_waf),
            ("graphql", self.step_graphql),
            ("crawl", self.step_crawl),
            ("robots_sitemap", self.step_robots_sitemap),
            ("leak_paths", self.step_leak_paths),
            ("tech", self.step_tech),
            ("login_surfaces", self.step_login_surfaces),
            ("register", self.step_register),
            ("params", self.step_params),
        ]
        for name, function in steps:
            try:
                self.ctx.budget.check_phase("recon")
                function()
                self.mark(name, "done")
            except BudgetExceeded as exc:
                self.mark(name, "skipped", str(exc))
                self.ctx.add_skip(self.host, name, str(exc))
                self.ctx.flush(self.host)
                break
            except Exception as exc:  # a single substep never aborts the run
                self.mark(name, "error", str(exc))
                self.recon["notes"].append(f"subetapa {name} falhou: {type(exc).__name__}: {exc}")
                self.ctx.flush(self.host)
                continue
            self.ctx.flush(self.host)
        phase["status"] = "done" if all(v.get("status") == "done" for v in phase["substeps"].values()) else "partial"
        phase["finished_utc"] = utcnow()
        self.ctx.flush(self.host)

    # ----------------------------------------------------------------- helpers
    def add(self, url: str, method: str = "GET", params: list[str] | None = None, source: str = "html", status="—") -> None:
        self.ctx.add_endpoint(
            self.host,
            {
                "method": method.upper(),
                "url": url,
                "params": list(params or intel.params_from_url(url)),
                "source": source,
                "status": status,
            },
        )

    def _record_links(self, links: list[str]) -> None:
        # limite: 60 links externos/host observados.
        for link in links[:60]:
            allowed, reason = self.client.scope.check(link)
            if not allowed:
                self.ctx.add_out_of_scope(self.host, link, reason)

    def _collect_secrets(self, text: str, source: str) -> None:
        for kind, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text or ""):
                value = match.group(0)
                item = {"type": kind, "value": _truncate_secret(value), "source": source}
                if not any(existing["value"] == item["value"] for existing in self.recon["secrets"]):
                    self.recon["secrets"].append(item)

    # ------------------------------------------------------------------ steps
    def step_baseline(self) -> None:
        response = self.client.get(self.client.scope.url, follow_redirects=True)
        self.baseline_body = response.text or ""
        self.page_bodies.append((response.url, self.baseline_body))
        cookies = []
        for key, value in response.headers.items():
            if key == "set-cookie":
                cookies.append(value.split(";", 1)[0].strip())
        self.recon["baseline"] = {
            "url": response.url,
            "status": response.status,
            "headers": dict(response.headers),
            "cookies": cookies,
            "body_head": self.baseline_body[:8192],
            "elapsed": round(response.elapsed, 4),
            "error": response.error,
        }
        self.add(self.client.scope.url_for("/"), status=response.status)
        self.recon["notes"].append(f"Baseline GET / -> {response.status} em {response.elapsed:.3f}s")

    def step_waf(self) -> None:
        baseline = self.recon.get("baseline", {})
        headers = baseline.get("headers", {}) or {}
        cookies = " ".join(baseline.get("cookies", [])).lower()
        body = self.baseline_body
        vendor = None
        confidence = "baixa"
        evidence = []
        for name, header_hints, body_hints in WAF_SIGNATURES:
            local = []
            for hint in header_hints:
                for key, value in headers.items():
                    if hint.lower() in key.lower() or hint.lower() in str(value).lower():
                        local.append(f"header {key}: {str(value)[:80]}")
            if name == "F5" and re.search(r"\bTS[0-9a-f]{6,}\b", cookies):
                local.append("cookie TS*")
            if name == "Imperva" and re.search(r"(incap_ses|visid_incap)", cookies):
                local.append("cookie incap_ses/visid_incap")
            if name == "AWS" and "awsalb" in cookies:
                local.append("cookie AWSALB")
            for hint in body_hints:
                if hint.lower() in body.lower():
                    local.append(f"body contém {hint}")
            if local:
                vendor = name
                confidence = "alta"
                evidence = local
                break
        self.recon["waf"] = {"vendor": vendor or "", "confidence": confidence if vendor else "baixa", "evidence": evidence}
        if vendor:
            self.recon["notes"].append(f"WAF/CDN detectado: {vendor} (confiança alta)")

    def step_graphql(self) -> None:
        found: dict = {}
        # limite: até 10 caminhos GraphQL do perfil.
        for path in GRAPHQL_PATHS[: self.settings.graphql_limit]:
            try:
                response = self.client.post(
                    self.client.scope.url_for(path),
                    json_body={"query": "{ __typename }"},
                    headers={"Accept": "application/json"},
                    follow_redirects=True,
                )
                self.ctx.budget.check_phase("recon")
            except BudgetExceeded:
                raise
            parsed = _json_or_none(response.text)
            if response.status == 200 and parsed and ("data" in parsed or "errors" in parsed):
                found = {
                    "path": path,
                    "status": response.status,
                    "typename_ok": bool(parsed.get("data", {}).get("__typename")) if isinstance(parsed.get("data"), dict) else False,
                    "introspection": "não tentada",
                    "notes": [],
                    "body_head": response.text[:2000],
                }
                break
        if not found:
            self.recon["graphql"] = {}
            return
        try:
            intro = self.client.post(
                self.client.scope.url_for(found["path"]),
                json_body={
                    "query": (
                        "query { __schema { queryType { name fields { name args { name } } } "
                        "mutationType { name fields { name args { name } } } types { name kind } } }"
                    )
                },
                headers={"Accept": "application/json"},
                follow_redirects=True,
            )
            parsed = _json_or_none(intro.text)
            schema = (parsed or {}).get("data", {}).get("__schema") if isinstance(parsed, dict) else None
            if schema:
                found["introspection"] = "habilitada"
                query_type = schema.get("queryType") or {}
                mutation_type = schema.get("mutationType") or {}
                found["query_type"] = query_type.get("name", "")
                found["mutation_type"] = mutation_type.get("name", "")
                fields = []
                for field in (query_type.get("fields") or [])[:40]:
                    if isinstance(field, dict) and field.get("name"):
                        args = [arg.get("name") for arg in (field.get("args") or []) if isinstance(arg, dict) and arg.get("name")]
                        fields.append({"name": field["name"], "args": args[:6], "kind": "query"})
                for field in (mutation_type.get("fields") or [])[:40]:
                    if isinstance(field, dict) and field.get("name"):
                        args = [arg.get("name") for arg in (field.get("args") or []) if isinstance(arg, dict) and arg.get("name")]
                        fields.append({"name": field["name"], "args": args[:6], "kind": "mutation"})
                found["fields"] = fields
                found["type_count"] = len(schema.get("types", []))
                found["mutations_without_auth"] = bool(schema.get("mutationType"))
                found["notes"].append("Introspection habilitada: revise fields/mutations e autorização manualmente.")
            else:
                found["introspection"] = "desabilitada ou resposta inválida"
        except BudgetExceeded:
            raise
        except Exception as exc:
            found["introspection"] = f"erro: {type(exc).__name__}"
        self.recon["graphql"] = found
        self.add(self.client.scope.url_for(found["path"]), method="POST", source="graphql", status=found["status"])
        self.recon["notes"].append(f"GraphQL em {found['path']} (typename_ok={found.get('typename_ok')})")

    def step_crawl(self) -> None:
        base = self.client.scope.url
        links, scripts, endpoints = intel.harvest_text(self.baseline_body, base, self.client.scope, "html")
        self._record_links(links)
        for endpoint in endpoints[:120]:
            self.add(endpoint)
        for form in intel.extract_forms(self.baseline_body, base, self.client.scope)[:20]:
            self.add(form["url"], method=form["method"], params=form["params"], source="form")
            self._store_form(form)

        queue: list[tuple[str, int]] = []
        for link in links:
            if self.client.scope.check(link)[0] and link not in queue:
                queue.append((link, 1))
        index = 0
        # limite: crawl_pages páginas (6/20/45) e profundidade máxima do perfil.
        for _ in range(self.settings.crawl_pages):
            if index >= len(queue):
                break
            page, depth = queue[index]
            index += 1
            if page in self.seen_pages:
                continue
            self.ctx.budget.check_phase("recon")
            self.seen_pages.add(page)
            try:
                response = self.client.get(page, follow_redirects=True)
            except BudgetExceeded:
                raise
            text = response.text or ""
            self.page_bodies.append((page, text))
            more_links, more_scripts, more_endpoints = intel.harvest_text(text, page, self.client.scope, "html")
            self._record_links(more_links)
            scripts.extend(more_scripts)
            for endpoint in more_endpoints[:80]:
                self.add(endpoint)
            for form in intel.extract_forms(text, page, self.client.scope)[:20]:
                self.add(form["url"], method=form["method"], params=form["params"], source="form")
                self._store_form(form)
            if depth < self.settings.crawl_depth and len(queue) < self.settings.crawl_pages * 6:
                for link in more_links[:20]:
                    if self.client.scope.check(link)[0] and all(existing[0] != link for existing in queue[index:]):
                        queue.append((link, depth + 1))

        same_host_scripts: list[str] = []
        for script in scripts:
            if self.client.scope.check(script)[0] and script not in same_host_scripts:
                same_host_scripts.append(script)
        maps_used = 0
        # limite: bundle_limit bundles JS do mesmo host (5/12/22).
        for script in same_host_scripts[: self.settings.bundle_limit]:
            self.ctx.budget.check_phase("recon")
            try:
                response = self.client.get(script, follow_redirects=True)
            except BudgetExceeded:
                raise
            bundle_endpoints: list[str] = []
            _links, _scripts, harvested = intel.harvest_text(response.text, script, self.client.scope, "js")
            for endpoint in harvested[:80]:
                bundle_endpoints.append(endpoint)
                self.add(endpoint, source="js")
            self._collect_secrets(response.text, script)
            map_match = SOURCE_MAP_RE.search(response.text or "")
            sourcemap = ""
            if map_match and maps_used < self.settings.map_limit:
                map_url = urljoin(script, map_match.group(1))
                if self.client.scope.check(map_url)[0]:
                    try:
                        map_response = self.client.get(map_url, follow_redirects=True)
                        maps_used += 1
                        sourcemap = map_url
                        _ml, _ms, map_endpoints = intel.harvest_text(map_response.text, map_url, self.client.scope, "js")
                        for endpoint in map_endpoints[:50]:
                            bundle_endpoints.append(endpoint)
                            self.add(endpoint, source="sourcemap")
                        self._collect_secrets(map_response.text, map_url)
                    except BudgetExceeded:
                        raise
                    except Exception:
                        pass
            self.recon["js_bundles"].append(
                {
                    "url": script,
                    "size": len(response.text or ""),
                    "endpoints": bundle_endpoints[:60],
                    "sourcemap": sourcemap,
                }
            )
            self.recon["notes"].append(f"JS analisado: {script} ({len(response.text or '')} bytes)")
        if self.recon["js_bundles"]:
            self.recon["notes"].append(f"{len(self.recon['js_bundles'])} bundle(s) JS analisado(s).")

    def _store_form(self, form: dict) -> None:
        forms = self.recon.setdefault("forms", [])
        key = (form.get("url"), form.get("method"))
        for current in forms:
            if (current.get("url"), current.get("method")) == key:
                merged = sorted(set(current.get("params", [])) | set(form.get("params", [])))
                current["params"] = merged
                return
        forms.append(dict(form))

    def step_robots_sitemap(self) -> None:
        robots_url = self.client.scope.url_for("/robots.txt")
        try:
            response = self.client.get(robots_url, follow_redirects=True)
        except BudgetExceeded:
            raise
        paths: list[str] = []
        sitemaps: list[str] = []
        if response.status == 200:
            paths, sitemaps = intel.extract_robots(response.text or "")
            for path in paths:
                if len(path) <= 180:
                    self.add(self.client.scope.url_for(path), source="robots")
        self.recon["robots"] = {"url": robots_url, "status": response.status, "paths": paths, "sitemaps": sitemaps}
        urls: list[str] = []
        # limite: 3 documentos sitemap por alvo.
        for sitemap in sitemaps[:3]:
            if not self.client.scope.check(sitemap)[0]:
                self.ctx.add_out_of_scope(self.host, sitemap, "sitemap em host externo")
                continue
            try:
                document = self.client.get(sitemap, follow_redirects=True)
            except BudgetExceeded:
                raise
            if document.status == 200:
                urls.extend(intel.extract_sitemap(document.text or ""))
        for url in urls[:40]:
            if self.client.scope.check(url)[0]:
                self.add(url, source="sitemap")
        self.recon["sitemap"] = {"urls": urls[:60], "count": len(urls)}
        if paths or urls:
            self.recon["notes"].append(f"robots: {len(paths)} path(s); sitemap: {len(urls)} URL(s)")

    def step_leak_paths(self) -> None:
        # limite: leak_limit caminhos de vazamento (8/16/28).
        for path in LEAK_PATHS[: self.settings.leak_limit]:
            self.ctx.budget.check_phase("recon")
            try:
                response = self.client.get(self.client.scope.url_for(path), follow_redirects=True)
            except BudgetExceeded:
                raise
            note = ""
            if response.status == 404:
                continue
            if response.status in (401, 403, 405):
                note = "existe, acesso restrito/método não permitido"
            elif response.status == 200:
                note = "acessível sem autenticação aparente"
                if path in ("/.env", "/.git/HEAD", "/package.json", "/config.json"):
                    note += " (revisar manualmente, possível vazamento)"
            self.recon["leak_paths"].append({"path": path, "status": response.status, "note": note})
            if path in OPENAPI_PATHS and response.status == 200:
                endpoints, meta = intel.extract_openapi(response.text or "", response.url or self.client.scope.url_for(path), self.client.scope)
                if endpoints:
                    self.recon["openapi"] = {
                        "url": response.url or self.client.scope.url_for(path),
                        "title": meta.get("title", ""),
                        "version": meta.get("version", ""),
                        "path_count": meta.get("path_count", 0),
                        "endpoints": endpoints[:120],
                    }
                    for endpoint in endpoints[:80]:
                        self.add(endpoint["url"], method=endpoint["method"], params=endpoint["params"], source="openapi")
                    self.recon["notes"].append(f"OpenAPI em {path}: {meta.get('path_count', 0)} path(s)")
            if path == "/sitemap.xml" and response.status == 200:
                urls = intel.extract_sitemap(response.text or "")
                if urls:
                    self.recon.setdefault("sitemap", {})["urls"] = urls[:60]
                    self.recon["sitemap"]["count"] = len(urls)
                    for value in urls[:40]:
                        if self.client.scope.check(value)[0]:
                            self.add(value, source="sitemap")

    def step_tech(self) -> None:
        baseline = self.recon.get("baseline", {}) or {}
        headers = baseline.get("headers", {}) or {}
        body = self.baseline_body or ""
        tech = {}
        for key in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            if headers.get(key):
                tech[key] = headers[key]
        cookie_text = " ".join(baseline.get("cookies", []))
        for cookie, name in (
            ("PHPSESSID", "PHP"),
            ("JSESSIONID", "Java"),
            ("laravel_session", "Laravel"),
            ("connect.sid", "Express"),
        ):
            if cookie in cookie_text:
                tech["cookie"] = f"{cookie} ({name})"
        if re.search(r"apollo|graphql", body, re.IGNORECASE):
            tech["graphql_client"] = "Apollo/GraphQL referenciado no HTML"
        for header in ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options"):
            tech[f"header_{header}"] = headers.get(header, "ausente")
        self.recon["tech"] = tech

    def step_login_surfaces(self) -> None:
        # limite: 8 superfícies de login/registro.
        for path in LOGIN_PATHS[:8]:
            try:
                response = self.client.get(self.client.scope.url_for(path), follow_redirects=True)
            except BudgetExceeded:
                raise
            if response.status not in (404, 0):
                kind = "register" if "regist" in path or "sign-up" in path else "login"
                if re.search(r"<form", response.text or "", re.IGNORECASE):
                    kind += "/form"
                self.recon["login_surfaces"].append(
                    {"kind": kind, "url": self.client.scope.url_for(path), "status": response.status}
                )
                self.add(self.client.scope.url_for(path), status=response.status)
                for form in intel.extract_forms(response.text or "", self.client.scope.url_for(path), self.client.scope)[:10]:
                    self.add(form["url"], method=form["method"], params=form["params"], source="form")
                    self._store_form(form)

    def step_register(self) -> None:
        emails = getattr(self.ctx.args, "emails", []) or []
        if not getattr(self.ctx.args, "register", False):
            self.recon["notes"].append("Registro não solicitado; contas de teste apenas registradas se criadas.")
            return
        if not emails:
            self.recon["notes"].append("sem contas de teste fornecidas")
            return
        password = os.environ.get(getattr(self.ctx.args, "password_env", "HUNTER_PASSWORD"), "")
        if not password:
            self.ctx.add_skip(self.host, "register", "variável de senha ausente")
            self.recon["notes"].append("Registro pulado: variável de senha ausente.")
            return
        self.client.add_redaction(password)
        email = emails[0]
        # limite: 4 endpoints de registro.
        for path in REGISTER_PATHS[:4]:
            try:
                response = self.client.post(
                    self.client.scope.url_for(path),
                    json_body={"email": email, "password": password},
                    headers={"Accept": "application/json"},
                    follow_redirects=False,
                )
            except BudgetExceeded:
                raise
            status = response.status
            if status in (200, 201, 204, 302):
                self.recon["accounts"].append({"email": email, "status": "criada/provável", "note": path})
                self.recon["notes"].append(f"Registro tentado em {path}: status {status} (senha nunca registrada).")
                return
            if status in (400, 409, 422) and re.search(r"already|exists|exist", response.text or "", re.IGNORECASE):
                self.recon["accounts"].append({"email": email, "status": "já existe", "note": path})
                self.recon["notes"].append(f"Conta provavelmente existente em {path}.")
                return
            self.recon["notes"].append(f"Registro em {path}: status {status}")
        if not self.recon["accounts"]:
            self.recon["accounts"].append({"email": email, "status": "não confirmada", "note": "endpoints testados"})
        if self.recon["accounts"]:
            masked = ", ".join(mask_email(a["email"]) for a in self.recon["accounts"])
            self.recon["notes"].append(f"Contas de teste: {masked}")

    def step_params(self) -> None:
        groups = [item.get("params") for item in self.recon.get("api_endpoints", [])]
        groups += [form.get("params") for form in self.recon.get("forms", [])]
        groups.append([field.get("name") for field in (self.recon.get("graphql") or {}).get("fields", [])])
        self.recon["params"] = intel.merge_params(*groups)
        if self.recon["params"]:
            self.recon["notes"].append(f"{len(self.recon['params'])} parâmetro(s) minerado(s).")


def client_url(client, path: str) -> str:
    return client.scope.url_for(path)


def run_recon(ctx, host: str, client) -> None:
    ReconRunner(ctx, host, client).run()
