"""Phase 3 — bounded, non-destructive vulnerability detection."""

from __future__ import annotations

import json
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .budget import BudgetExceeded
from .http import ScopeViolation
from .state import utcnow
from .validate import body_changed, finalize, make_marker, reflected_raw

MAX_PAYLOADS_PER_CLASS = 5
MAX_REQUESTS_PER_ENDPOINT = 15
SQL_ERROR_RE = re.compile(
    r"SQL syntax|mysql_fetch|mysqli|PostgreSQL|SQLite|ORA-\d{4,}|ODBC|SQLSTATE|unclosed quotation",
    re.IGNORECASE,
)
SENSITIVE_BODY_RE = re.compile(r'"(?:email|role|order|account|user|billing|invoice|price)"\s*:', re.IGNORECASE)


def add_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query = [(key, val) for key, val in query if key != name]
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), ""))


def endpoint_params(endpoint: dict) -> list[str]:
    params = list(endpoint.get("params") or [])
    try:
        for key, _value in parse_qsl(urlsplit(endpoint.get("url", "")).query, keep_blank_values=True):
            if key not in params:
                params.append(key)
    except ValueError:
        pass
    return params


def _short(text: str, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:limit]


class Tester:
    def __init__(self, ctx, host: str, client):
        self.ctx = ctx
        self.host = host
        self.client = client
        self.state = ctx.targets[host]
        self.baseline = (self.state.get("recon", {}).get("baseline", {}) or {}).get("body_head", "")
        self.logger = ctx.logger(host)
        self.class_requests = 0
        self.settings = ctx.settings
        self.max_payloads = self.settings.max_payloads
        self.max_requests_per_endpoint = self.settings.max_requests_per_endpoint
        self.param_limit = self.settings.param_limit

    def _request(self, method: str, url: str, **kwargs):
        if self.class_requests >= self.max_payloads:
            raise BudgetExceeded(f"teto de {self.max_payloads} payloads por classe neste endpoint")
        self.class_requests += 1
        return self.client.request(method, url, **kwargs)

    def finding(self, **kwargs) -> dict:
        base = {
            "in_scope": True,
            "reproducible": True,
            "non_destructive": True,
            "marker_verified": True,
            "impact_demonstrated": True,
            "prerequisites": "nenhum além do acesso ao endpoint",
            "counter_evidence": "baseline comparado; ver detalhes",
            "severity_change": "aumenta com dados sensíveis reais ou ação de outro usuário",
        }
        base.update(kwargs)
        base.setdefault("title", f"{base.get('class', 'finding')} em {base.get('endpoint', '')}")
        base.setdefault("evidence", "")
        base.setdefault("impact", "impacto limitado ao observado")
        finding = finalize(base)
        stored = self.ctx.add_finding(self.host, finding)
        self.ctx.flush(self.host)
        return stored

    def negative(self, endpoint: dict, clazz: str) -> None:
        for param in endpoint_params(endpoint) or ["-"]:
            self.ctx.add_negative(self.host, endpoint.get("url", ""), param, clazz)

    # ------------------------------------------------------------------ classes
    def run_endpoint(self, endpoint: dict, classes: list[str]) -> None:
        url = endpoint["url"]
        method = endpoint.get("method", "GET").upper()
        for clazz in classes:
            if self.client.is_blocked(url, method):
                self.ctx.add_coverage(self.host, url, clazz, "blocked", "3-strikes")
                continue
            if self.ctx.is_negative(self.host, url, "-", clazz):
                self.ctx.add_coverage(self.host, url, clazz, "skipped", "negativo em execução anterior")
                continue
            self.class_requests = 0
            function = getattr(self, f"test_{clazz}", None)
            if function is None:
                continue
            before = len(self.state.get("findings", []))
            try:
                result, detail = function(endpoint)
            except BudgetExceeded as exc:
                self.ctx.add_coverage(self.host, url, clazz, "stopped", str(exc))
                if "requisições por endpoint" in str(exc) or "payloads por classe" in str(exc):
                    continue
                raise
            except ScopeViolation as exc:
                self.ctx.add_coverage(self.host, url, clazz, "scope-violation", exc.reason)
                continue
            except Exception as exc:
                self.ctx.add_coverage(self.host, url, clazz, "error", f"{type(exc).__name__}: {exc}")
                self.logger.warning("classe %s falhou em %s: %s", clazz, url, exc)
                continue
            for finding in self.state.get("findings", [])[before:]:
                finding.setdefault("origin", endpoint.get("source", ""))
                finding.setdefault("ai_reason", endpoint.get("ai_reason", ""))
                finding.setdefault("ai_stage", endpoint.get("ai_stage", ""))
            self.ctx.add_coverage(self.host, url, clazz, result, detail)
            if result == "negative":
                self.negative(endpoint, clazz)
            self.ctx.flush(self.host)

    def test_cors(self, endpoint: dict):
        origin = "https://evil.example"
        response = self._request("GET", endpoint["url"], headers={"Origin": origin}, follow_redirects=False)
        allow_origin = response.headers.get("access-control-allow-origin", "")
        allow_creds = response.headers.get("access-control-allow-credentials", "").lower()
        null_probe = None
        if not (allow_origin == origin and allow_creds == "true"):
            null_probe = self._request("GET", endpoint["url"], headers={"Origin": "null"}, follow_redirects=False)
            if null_probe.headers.get("access-control-allow-origin", "") == "null" and null_probe.headers.get("access-control-allow-credentials", "").lower() == "true":
                self.finding(
                    **{
                        "class": "cors",
                        "title": "CORS confia na origem null com credenciais",
                        "endpoint": endpoint["url"],
                        "method": "GET",
                        "payload": "Origin: null",
                        "severity": "medium",
                        "status": "likely",
                        "evidence": f"ACAO=null; ACAC=true; status={null_probe.status}",
                        "impact": "Origens sandbox/null podem ler respostas autenticadas.",
                        "impact_demonstrated": True,
                    }
                )
                return "vulnerable", "origem null refletida com credenciais"
        reflected = allow_origin == origin
        if reflected and allow_creds == "true":
            self.finding(
                **{
                    "class": "cors",
                    "title": "CORS reflete origem arbitrária com credenciais",
                    "endpoint": endpoint["url"],
                    "method": "GET",
                    "payload": f"Origin: {origin}",
                    "severity": "medium",
                    "status": "likely",
                    "evidence": f"ACAO={allow_origin}; ACAC={allow_creds}; status={response.status}",
                    "impact": "Um site externo pode ler respostas autenticadas do endpoint no navegador da vítima.",
                    "impact_demonstrated": True,
                }
            )
            return "vulnerable", "origem refletida com credenciais"
        if allow_origin == "*":
            self.finding(
                **{
                    "class": "cors",
                    "title": "CORS wildcard em endpoint",
                    "endpoint": endpoint["url"],
                    "method": "GET",
                    "payload": f"Origin: {origin}",
                    "severity": "low",
                    "status": "potential",
                    "evidence": f"ACAO=*; ACAC={allow_creds or '(ausente)'}; status={response.status}",
                    "impact": "Sem credenciais, exposição limitada a conteúdo público; revisar se houver dados por usuário.",
                }
            )
            return "potential", "CORS wildcard"
        return "negative", "CORS não refletido"

    def test_csrf(self, endpoint: dict):
        response = self._request("GET", endpoint["url"], follow_redirects=True)
        body = response.text or ""
        forms = re.findall(r"<form\b[^>]*>(.*?)</form>", body, re.IGNORECASE | re.DOTALL)
        if not forms:
            return "not-applicable", "sem formulário"
        has_token = any(
            re.search(r"csrf|xsrf|authenticity_token|__requestverificationtoken", form, re.IGNORECASE)
            for form in forms
        )
        cookies = [value for key, value in response.headers.items() if key == "set-cookie"]
        same_site_none = any("samesite=none" in cookie.lower() for cookie in cookies)
        if not has_token:
            self.finding(
                **{
                    "class": "csrf",
                    "title": "Formulário de estado sem token anti-CSRF",
                    "endpoint": endpoint["url"],
                    "method": "GET",
                    "payload": "formulário sem token",
                    "severity": "medium" if same_site_none else "low",
                    "status": "potential",
                    "evidence": f"form(s)={len(forms)}; token=ausente; SameSite=None={same_site_none}",
                    "impact": "Se o formulário alterar estado, um site externo pode induzir a vítima a enviá-lo.",
                    "impact_demonstrated": False,
                    "counter_evidence": "ação do formulário não executada (não destrutivo)",
                }
            )
            return "potential", "formulário sem token"
        return "negative", "token anti-CSRF presente"

    def test_open_redirect(self, endpoint: dict):
        url = endpoint["url"]
        path = urlsplit(url).path.lower()
        params = endpoint_params(endpoint)
        if not params and not re.search(r"login|signin|auth|register|redirect", path):
            return "not-applicable", "sem parâmetro de redirecionamento"
        candidates = params or ["next", "url", "redirect", "return"]
        marker = make_marker()
        target = f"https://evil.example/{marker}"
        for name in candidates[: min(4, self.param_limit + 2)]:
            response = self._request("GET", add_param(url, name, target), follow_redirects=True)
            location = response.headers.get("location", "") or response.redirect_external
            if response.redirect_external or location.startswith("http") and "evil.example" in location:
                self.finding(
                    **{
                        "class": "open_redirect",
                        "title": "Redirecionamento aberto",
                        "endpoint": add_param(url, name, target),
                        "method": "GET",
                        "payload": f"{name}={target}",
                        "severity": "medium",
                        "status": "likely",
                        "evidence": f"Location externo: {location}; status={response.status}",
                        "impact": "Pode ser usado em phishing e em fluxos de roubo de token OAuth.",
                        "impact_demonstrated": True,
                    }
                )
                return "vulnerable", f"parâmetro {name} redireciona para fora"
        return "negative", "nenhum redirecionamento externo"

    def test_idor(self, endpoint: dict):
        url = endpoint["url"]
        path = urlsplit(url).path
        match = re.search(r"/(\d+)(?=/|$)", path)
        original = self._request("GET", url, follow_redirects=False)
        if original.status != 200:
            return "not-applicable", f"baseline status {original.status}"
        if not match and not endpoint_params(endpoint):
            return "not-applicable", "sem identificador"
        trials = []
        if match:
            base_id = int(match.group(1))
            for delta in (1, 2, 3, -1):
                if base_id + delta <= 0:
                    continue
                replaced = re.sub(r"/\d+(?=/|$)", f"/{base_id + delta}", path, count=1)
                trials.append(urlunsplit((urlsplit(url).scheme, urlsplit(url).netloc, replaced, urlsplit(url).query, "")))
        else:
            for name in endpoint_params(endpoint)[: self.param_limit]:
                trials.append(add_param(url, name, "2"))
        for trial in trials[:5]:
            response = self._request("GET", trial, follow_redirects=False)
            if response.status == 200 and body_changed(original.text, response.text) and (
                SENSITIVE_BODY_RE.search(response.text) or response.text.strip().startswith("{")
            ):
                self.finding(
                    **{
                        "class": "idor",
                        "title": "Possível acesso direto a objeto de outro identificador",
                        "endpoint": trial,
                        "method": "GET",
                        "payload": "id alternativo",
                        "severity": "medium",
                        "status": "potential",
                        "evidence": f"original={original.status} ({len(original.text)}B); alternativo={response.status} ({len(response.text)}B); corpo diferente",
                        "impact": "A resposta mudou ao trocar o identificador; confirmar se pertence a outro usuário.",
                        "impact_demonstrated": False,
                        "prerequisites": "necessário comparar com duas contas autenticadas para confirmar",
                        "counter_evidence": "diferença de corpo não prova propriedade de outro usuário",
                        "severity_change": "confirmar com duas contas e dado privado real eleva para high",
                    }
                )
                return "potential", "corpo diferente para ID alternativo"
        return "negative", "sem diferença relevante para ID alternativo"

    def test_mass_assignment(self, endpoint: dict):
        accounts = self.state.get("recon", {}).get("accounts", [])
        created = any("criada" in str(account.get("status", "")) for account in accounts)
        url = endpoint["url"]
        method = endpoint.get("method", "GET").upper()
        if not created and not re.search(r"register|signup|profile|account", url, re.IGNORECASE):
            return "not-applicable", "sem conta de teste criada"
        if method not in ("POST", "PUT", "PATCH"):
            method = "PATCH"
        payload = {"role": "admin", "is_admin": True, "verified": True, "price": 0, "discount": 100}
        response = self._request(method, url, json_body=payload, follow_redirects=False)
        if response.status in (200, 201, 202, 204) and any(
            re.search(rf'"{field}"\s*:', response.text or "", re.IGNORECASE) for field in payload
        ):
            persisted = ""
            try:
                confirmation = self._request("GET", url, follow_redirects=False)
                persisted = "GET posterior contém campo" if any(
                    re.search(rf'"{field}"\s*:', confirmation.text or "", re.IGNORECASE) for field in payload
                ) else "GET posterior não confirmou persistência"
            except BudgetExceeded:
                persisted = "GET de confirmação não realizado (limite)"
            self.finding(
                **{
                    "class": "mass_assignment",
                    "title": "Possível mass assignment em campos privilegiados",
                    "endpoint": url,
                    "method": method,
                    "payload": json.dumps(payload, ensure_ascii=False),
                    "severity": "high",
                    "status": "potential",
                    "evidence": f"status={response.status}; campo extra ecoado; {persisted}",
                    "impact": "Se persistido, pode elevar privilégios ou alterar preço/verificação.",
                    "impact_demonstrated": False,
                    "prerequisites": "conta autenticada com permissão de edição",
                    "counter_evidence": persisted,
                }
            )
            return "potential", "campo extra ecoado"
        return "negative", f"status {response.status} sem eco de campo"

    def test_xss(self, endpoint: dict):
        url = endpoint["url"]
        params = endpoint_params(endpoint) or ["q", "search", "name"]
        templates = ('<{marker}>', '"><{marker}>', "'><{marker}>", '<svg/{marker}>', '{{{{<{marker}>}}}}')
        for name in params[: min(3, self.param_limit + 1)]:
            for template in templates[:3]:
                marker = make_marker()
                payload = template.format(marker=marker)
                response = self._request("GET", add_param(url, name, payload), follow_redirects=False)
                if reflected_raw(self.baseline, response.text, marker):
                    self.finding(
                        **{
                            "class": "xss",
                            "title": "Reflexão de HTML não escapado",
                            "endpoint": add_param(url, name, payload),
                            "method": "GET",
                            "payload": payload,
                            "severity": "medium",
                            "status": "likely",
                            "evidence": f"marcador {marker} refletido cru; Content-Type={response.headers.get('content-type', '?')}",
                            "impact": "Execução de script no contexto da vítima se o reflexo ocorrer em HTML.",
                            "impact_demonstrated": True,
                            "counter_evidence": "marcador ausente no baseline; execução em navegador não testada",
                        }
                    )
                    return "vulnerable", f"marcador refletido em {name}"
        return "negative", "nenhum marcador refletido cru"

    def test_sqli(self, endpoint: dict):
        url = endpoint["url"]
        params = endpoint_params(endpoint) or ["id", "q"]
        control = self._request("GET", add_param(url, params[0], "1"), follow_redirects=False)
        true_response = None
        false_response = None
        for payload in ("'", "\"", "')", "' AND '1'='1", "' AND '1'='2", "' OR '1'='1' -- ", "1;--", "' UNION SELECT NULL-- "):
            response = self._request("GET", add_param(url, params[0], payload), follow_redirects=False)
            if payload.endswith("'1'='1"):
                true_response = response
            if payload.endswith("'1'='2"):
                false_response = response
            if SQL_ERROR_RE.search(response.text or "") and not SQL_ERROR_RE.search(control.text or ""):
                self.finding(
                    **{
                        "class": "sqli",
                        "title": "Erro de banco de dados induzido por entrada",
                        "endpoint": add_param(url, params[0], payload),
                        "method": "GET",
                        "payload": payload,
                        "severity": "high",
                        "status": "likely",
                        "evidence": f"assinatura SQL na resposta: {_short(SQL_ERROR_RE.search(response.text).group(0))}",
                        "impact": "Indica injeção SQL; extração mínima não executada.",
                        "impact_demonstrated": True,
                        "counter_evidence": "sem extração de dados; confirmação manual necessária",
                    }
                )
                return "vulnerable", "erro SQL induzido"
        reflected_boolean = bool(
            true_response and "AND '1'='1" in (true_response.text or "")
        ) or bool(false_response and "AND '1'='2" in (false_response.text or ""))
        if (
            true_response
            and false_response
            and not reflected_boolean
            and body_changed(true_response.text, false_response.text, 0.05)
            and true_response.status == false_response.status == 200
        ):
            self.finding(
                **{
                    "class": "sqli",
                    "title": "Diferença booleana suspeita em parâmetro",
                    "endpoint": url,
                    "method": "GET",
                    "payload": "' AND '1'='2",
                    "severity": "medium",
                    "status": "potential",
                    "evidence": "corpo difere entre condição verdadeira e falsa",
                    "impact": "Pode indicar injeção booleana; requer confirmação temporal/manual.",
                    "impact_demonstrated": False,
                    "counter_evidence": "diferença de conteúdo pode ser dinâmica",
                }
            )
            return "potential", "diferença booleana"
        return "negative", "sem erro ou diferença booleana"

    def test_nosqli(self, endpoint: dict):
        url = endpoint["url"]
        params = endpoint_params(endpoint) or ["id"]
        control = self._request("GET", url, follow_redirects=False)
        content_type = control.headers.get("content-type", "")
        if "json" not in content_type.lower() and not (control.text or "").strip().startswith(("{", "[")):
            return "not-applicable", "resposta não é JSON; operador NoSQL não aplicável"
        payload = add_param(url, f"{params[0]}[$ne]", "x")
        response = self._request("GET", payload, follow_redirects=False)
        for operator in ("$gt", "$regex"):
            try:
                probe = self._request("GET", add_param(url, f"{params[0]}[{operator}]", ".*"), follow_redirects=False)
            except BudgetExceeded:
                break
            if probe.status == 200 and body_changed(control.text, probe.text, 0.05):
                response = probe
                payload = add_param(url, f"{params[0]}[{operator}]", ".*")
                break
        if response.status == 200 and body_changed(control.text, response.text, 0.05):
            self.finding(
                **{
                    "class": "nosqli",
                    "title": "Possível injeção NoSQL por operador em parâmetro",
                    "endpoint": payload,
                    "method": "GET",
                    "payload": f"{params[0]}[$ne]=x",
                    "severity": "medium",
                    "status": "potential",
                    "evidence": f"status={response.status}; corpo diferente do controle",
                    "impact": "Pode permitir bypass de filtro; necessário confirmar a query do backend.",
                    "impact_demonstrated": False,
                    "counter_evidence": "parâmetro pode ter sido ignorado",
                }
            )
            return "potential", "corpo diferente com operador $ne"
        return "negative", "operador $ne sem efeito observável"

    def test_ssrf(self, endpoint: dict):
        url = endpoint["url"]
        params = endpoint_params(endpoint)
        candidates = [param for param in params if re.search(r"url|uri|image|webhook|proxy|site|host", param, re.IGNORECASE)]
        if not candidates:
            return "not-applicable", "sem parâmetro de URL"
        control = self._request("GET", url, follow_redirects=False)
        target = "http://127.0.0.1:1/hunter-ssrf"
        response = self._request("GET", add_param(url, candidates[0], target), follow_redirects=False)
        if response.status == control.status and not body_changed(control.text, response.text, 0.05) and len(candidates) > 1:
            try:
                response = self._request("GET", add_param(url, candidates[1], target), follow_redirects=False)
            except BudgetExceeded:
                pass
        if response.status != control.status or body_changed(control.text, response.text, 0.05):
            self.finding(
                **{
                    "class": "ssrf",
                    "title": "Possível SSRF por parâmetro de URL",
                    "endpoint": add_param(url, candidates[0], target),
                    "method": "GET",
                    "payload": target,
                    "severity": "medium",
                    "status": "potential",
                    "evidence": f"controle={control.status}; teste={response.status}; corpo diferente",
                    "impact": "Servidor pode ter tentado buscar URL controlada; sem callback OOB não confirmado.",
                    "impact_demonstrated": False,
                    "counter_evidence": "sem listener OOB; diferença pode ser erro de validação",
                }
            )
            return "potential", "resposta diferente para URL controlada"
        return "negative", "sem diferença observável (sem OOB)"

    def test_ssti(self, endpoint: dict):
        url = endpoint["url"]
        params = endpoint_params(endpoint) or ["q", "name"]
        for name in params[: min(2, self.param_limit)]:
            for payload, expected in (
                ("{{1337*1337}}", "1787569"),
                ("${1337*1337}", "1787569"),
                ("<%= 1337*1337 %>", "1787569"),
                ("#{1337*1337}", "1787569"),
                ("{{'1337'*'1337'}}", "1787569"),
            ):
                response = self._request("GET", add_param(url, name, payload), follow_redirects=False)
                if expected in (response.text or "") and expected not in self.baseline:
                    self.finding(
                        **{
                            "class": "ssti",
                            "title": "Avaliação de expressão em template",
                            "endpoint": add_param(url, name, payload),
                            "method": "GET",
                            "payload": payload,
                            "severity": "high",
                            "status": "likely",
                            "evidence": f"resultado {expected} presente na resposta",
                            "impact": "Avaliação server-side; pode escalar para execução de comandos.",
                            "impact_demonstrated": True,
                            "counter_evidence": "resultado pode aparecer por acaso; repetição manual recomendada",
                        }
                    )
                    return "vulnerable", f"expressão avaliada em {name}"
        return "negative", "expressão não avaliada"

    def test_lfi(self, endpoint: dict):
        url = endpoint["url"]
        params = endpoint_params(endpoint) or ["file", "path", "page"]
        candidates = [param for param in params if re.search(r"file|path|page|template|include|doc|download", param, re.IGNORECASE)] or params
        for name in candidates[: min(2, self.param_limit)]:
            for payload in ("../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd%00", "..%2f..%2f..%2fetc%2fpasswd"):
                response = self._request("GET", add_param(url, name, payload), follow_redirects=False)
                if "root:x:0:0" in (response.text or ""):
                    self.finding(
                        **{
                            "class": "lfi",
                            "title": "Leitura de arquivo local via path traversal",
                            "endpoint": add_param(url, name, payload),
                            "method": "GET",
                            "payload": payload,
                            "severity": "high",
                            "status": "likely",
                            "evidence": "conteúdo de /etc/passwd presente na resposta",
                            "impact": "Leitura de arquivos locais arbitrários do servidor.",
                            "impact_demonstrated": True,
                        }
                    )
                    return "vulnerable", f"LFI em {name}"
        return "negative", "nenhum conteúdo de arquivo local observado"

    def test_rce(self, endpoint: dict):
        url = endpoint["url"]
        params = endpoint_params(endpoint) or ["cmd", "exec", "command", "host"]
        candidates = [param for param in params if re.search(r"cmd|exec|command|ping|host|run|shell", param, re.IGNORECASE)] or params
        marker = make_marker().upper()
        for name in candidates[: min(2, self.param_limit)]:
            for payload in (f";echo {marker}", f"|echo {marker}", f"`echo {marker}`"):
                response = self._request("GET", add_param(url, name, payload), follow_redirects=False)
                body = response.text or ""
                if marker in body and payload not in body and f"echo {marker}" not in body:
                    self.finding(
                        **{
                            "class": "rce",
                            "title": "Injeção de comando com canário",
                            "endpoint": add_param(url, name, payload),
                            "method": "GET",
                            "payload": payload,
                            "severity": "critical",
                            "status": "likely",
                            "evidence": f"canário {marker} retornado na resposta",
                            "impact": "Execução de comandos no servidor (somente echo canário, sem efeitos destrutivos).",
                            "impact_demonstrated": True,
                        }
                    )
                    return "vulnerable", f"canário de comando em {name}"
        return "negative", "canário de comando não retornado"

    def test_xxe(self, endpoint: dict):
        url = endpoint["url"]
        payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<root>&xxe;</root>"
        )
        try:
            response = self._request("POST", url, data=payload, headers={"Content-Type": "application/xml"}, follow_redirects=False)
        except BudgetExceeded:
            raise
        if "root:x:0:0" in (response.text or ""):
            self.finding(
                **{
                    "class": "xxe",
                    "title": "Entidade externa XML resolve arquivo local",
                    "endpoint": url,
                    "method": "POST",
                    "payload": '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
                    "severity": "high",
                    "status": "likely",
                    "evidence": "conteúdo de /etc/passwd retornado via entidade XML",
                    "impact": "Leitura de arquivos locais e possível SSRF via entidades externas.",
                    "impact_demonstrated": True,
                    "counter_evidence": "sem callback OOB; confirmação local apenas",
                }
            )
            return "vulnerable", "entidade XML resolveu arquivo local"
        return "negative", "entidade XML não resolveu"

    def test_graphql(self, endpoint: dict):
        graphql = self.state.get("recon", {}).get("graphql", {}) or {}
        path = graphql.get("path") or urlsplit(endpoint.get("url", "")).path
        if not path:
            return "not-applicable", "sem endpoint GraphQL"
        url = self.client.scope.url_for(path)
        response = self._request(
            "POST",
            url,
            json_body=[{"query": "{ __typename }"}, {"query": "{ __typename }"}],
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )
        try:
            parsed = json.loads(response.text)
        except ValueError:
            parsed = None
        if response.status == 200 and isinstance(parsed, list) and len(parsed) >= 2:
            self.finding(
                **{
                    "class": "graphql",
                    "title": "GraphQL aceita batching de queries",
                    "endpoint": url,
                    "method": "POST",
                    "payload": '[{"query":"{ __typename }"},{"query":"{ __typename }"}]',
                    "severity": "low",
                    "status": "potential",
                    "evidence": f"status={response.status}; resposta é array com {len(parsed)} itens",
                    "impact": "Batching pode amplificar consultas e facilitar abuso de rate limit.",
                    "impact_demonstrated": True,
                    "prerequisites": "endpoint GraphQL acessível",
                }
            )
            return "potential", "batching aceito"
        mutation_probe = None
        try:
            mutation_probe = self._request(
                "POST",
                url,
                json_body={"query": "mutation { __typename }"},
                headers={"Accept": "application/json"},
                follow_redirects=False,
            )
        except BudgetExceeded:
            pass
        if mutation_probe is not None and mutation_probe.status == 200:
            try:
                mutation_parsed = json.loads(mutation_probe.text)
            except ValueError:
                mutation_parsed = None
            if isinstance(mutation_parsed, dict) and mutation_parsed.get("data") and "errors" not in mutation_parsed:
                self.finding(
                    **{
                        "class": "graphql",
                        "title": "GraphQL aceita mutation sem autenticação",
                        "endpoint": url,
                        "method": "POST",
                        "payload": "mutation { __typename }",
                        "severity": "medium",
                        "status": "potential",
                        "evidence": "mutation __typename aceita sem credenciais",
                        "impact": "Superfície de mutação exposta; revisar autorização de cada mutation.",
                        "impact_demonstrated": False,
                        "prerequisites": "mutation real sem checagem de autenticação",
                        "counter_evidence": "apenas __typename testado, nenhuma alteração de estado",
                    }
                )
                return "potential", "mutation sem auth"
        if graphql.get("introspection") == "habilitada":
            self.finding(
                **{
                    "class": "graphql",
                    "title": "GraphQL com introspection habilitada",
                    "endpoint": url,
                    "method": "POST",
                    "payload": "{ __schema { ... } }",
                    "severity": "info",
                    "status": "potential",
                    "evidence": f"introspection habilitada; queryType={graphql.get('query_type', '?')}; mutationType={graphql.get('mutation_type', '?')}",
                    "impact": "Facilita descoberta de schema e mutations; revisar autorização manualmente.",
                    "impact_demonstrated": True,
                    "prerequisites": "acesso ao endpoint GraphQL",
                }
            )
            return "potential", "introspection habilitada"
        return "negative", "batching/introspection não observados"


def run_tests(ctx, host: str, client, selection: dict, update_phase: bool = True) -> None:
    state = ctx.targets[host]
    phase = state["phases"]["tests"]
    if update_phase:
        phase["status"] = "running"
        phase["started_utc"] = phase.get("started_utc") or utcnow()
        ctx.budget.mark_phase("tests")
    endpoints = selection.get("endpoints", [])
    if not endpoints:
        if update_phase:
            phase["status"] = "done"
            phase["finished_utc"] = utcnow()
        ctx.add_skip(host, "tests", "nenhum endpoint priorizado")
        ctx.flush(host)
        return
    tester = Tester(ctx, host, client)
    consecutive_blocked = 0
    class_counts = state["counters"].setdefault("requests_by_class", {})
    for endpoint in endpoints:
        try:
            ctx.budget.check_phase("tests")
        except BudgetExceeded as exc:
            ctx.add_skip(host, "tests", str(exc))
            break
        if client.is_blocked(endpoint["url"], endpoint.get("method", "GET")):
            consecutive_blocked += 1
            if consecutive_blocked >= 3:
                ctx.add_skip(host, "tests", "3 endpoints consecutivos bloqueados")
                break
            continue
        consecutive_blocked = 0
        for clazz in endpoint.get("classes", []):
            try:
                ctx.budget.check_phase("tests")
                tester.run_endpoint(endpoint, [clazz])
                class_counts[clazz] = class_counts.get(clazz, 0) + 1
            except BudgetExceeded as exc:
                ctx.add_skip(host, f"tests/{clazz}", str(exc))
                phase["status"] = "partial"
                ctx.flush(host)
                break
            if ctx.budget.requests_by_endpoint.get(f"{endpoint.get('method', 'GET').upper()} {urlsplit(endpoint['url']).path}", 0) >= tester.max_requests_per_endpoint:
                break
        ctx.flush(host)
    if update_phase:
        phase["status"] = "done" if phase.get("status") != "partial" else "partial"
        phase["finished_utc"] = utcnow()
    ctx.flush(host)
