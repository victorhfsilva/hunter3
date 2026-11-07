# hunter

Recon e caça de vulnerabilidades web **não destrutivos**, multi-subdomínio, com
orçamento duro de tempo/requisições, estado resumível e relatórios incrementais
`RECON.md`/`FINDINGS.md` por subdomínio. A busca profunda combina crawl de até
3 níveis, JS/source maps, formulários, OpenAPI, robots/sitemap, mineração de
parâmetros e um planejador **read-only via opencode** (opcional).

Dependência externa única: `requests` (fallback automático para `urllib.request`).

## Uso

```bash
python3 hunter.py app.exemplo.invalid,api.exemplo.invalid \
    --ai --profile deep --max-minutes 30 --max-requests 600 --out ./hunter_out
```

Sem `--ai`, roda sem chamar o modelo (as demais fases continuam profundas).
`--no-ai` desliga explicitamente. Lista em arquivo:

```bash
python3 hunter.py --targets-file alvos.txt --no-ai --out ./hunter_out
```

### Flags

| Flag | Padrão | Descrição |
|---|---|---|
| `--emails a@x,b@y` | nenhum | Única fonte de e-mails. Sem ela, tudo que depende de conta é pulado. |
| `--password-env NOME` | `HUNTER_PASSWORD` | Variável de ambiente com a senha de registro (nunca logada). |
| `--scope URL` | — | Página do programa: 1 GET de leitura de política, nunca alvo de teste. |
| `--recon-only` | off | Para após a Fase 1 (inclui o plano de IA de recon). |
| `--register` | off | Tenta cadastro; exige `--emails` (senão exit 2, zero requisições). |
| `--proxy URL` | — | Proxy em todas as requisições. |
| `--out DIR` | `./hunter_out` | Raiz de saída. |
| `--resume` | off | Retoma do `state.json`; exit 3 se não houver estado. |
| `--profile {fast,standard,deep}` | `deep` | Profundidade de crawl/testes. O orçamento pode reduzir, nunca aumentar. |
| `--ai` / `--no-ai` | auto | Planejamento por IA via opencode (padrão: liga se `opencode` estiver no PATH). |
| `--ai-rounds N` | perfil | Rodadas de IA pós-testes (1–2; total ≤3 com o estágio pré). |
| `--ai-max-minutes N` | ~25% do alvo | Teto de tempo total da IA por alvo (máx. 8 min). |
| `--ai-timeout N` | `180` | Timeout de cada consulta de IA em segundos. |
| `--max-minutes N` | `30` | Deadline global (watchdog encerra a execução). |
| `--per-target-max-minutes N` | calculado | Sobrepõe o orçamento por alvo. |
| `--max-requests N` | `600` | Teto de requisições por alvo. |
| `--max-total-requests N` | `600 × alvos` | Teto absoluto da execução. |
| `--rate N` | `5` | Máximo de req/s por host. |
| `--verbose` | off | Log detalhado em stderr + arquivo. |

Códigos de saída: `0` concluído (total ou parcial, motivo registrado), `2` erro
de uso, `3` `--resume` sem estado.

## Profundidade por perfil

| Limite | fast | standard | deep |
|---|---|---|---|
| Páginas de crawl | 6 | 20 | 45 |
| Profundidade | 1 | 2 | 3 |
| Bundles JS | 5 | 12 | 22 |
| Source maps | 2 | 3 | 6 |
| Paths de vazamento | 8 | 16 | 28 |
| Paths GraphQL | 6 | 8 | 10 |
| Payloads/classe | 4 | 6 | 8 |
| Req/endpoint | 15 | 20 | 30 |
| Endpoints priorizados | 3 | 8 | 15 |
| Parâmetros/endpoint | 2 | 3 | 5 |

O orçamento por alvo escolhe o teto: `<300s` → fast, `<600s` → standard,
`>=600s` → deep. Um `--profile fast` nunca é promovido pelo orçamento.

## Recon profundo (sem IA)

Além do baseline/WAF/GraphQL/JS, a Fase 1 agora:

- faz crawl BFS até a profundidade do perfil, guardando corpos de página;
- extrai **formulários** (action/method/inputs) e os adiciona como endpoints;
- baixa e interpreta **OpenAPI/Swagger** (paths, métodos e parâmetros);
- lê **robots.txt** (Allow/Disallow/Sitemap) e **sitemap.xml** (até 3 docs);
- minera rotas em JS via strings/fetch/axios/`path:`/`to:`;
- agrega **parâmetros** de endpoints, formulários e fields GraphQL;
- extrai fields/args da introspection GraphQL;
- mantém a lista ampliada de caminhos de vazamento e segredos truncados.

## Plano de IA via opencode (bounded e read-only)

Quando habilitado, `hunter/ai.py` resume o recon (endpoints, forms, OpenAPI,
robots/sitemap, tech, GraphQL, parâmetros, cobertura/achados no pós-testes) e
pede ao agente **`plan`** do opencode um JSON com `tests`, `crawl_paths`,
`leak_paths` e `notes`. Regras de segurança:

- o agente `plan` é read-only (sem bash/escrita) na chamada padrão;
- toda proposta é tratada como dado não confiável: URL/método/param/classe
  passam por sanitização e pela allowlist de host antes de qualquer request;
- classes só entram se permitidas pela política WAF-aware do alvo;
- limites duros: 15 testes + 10 crawl + 10 leak por rodada, no máximo 3 rodadas,
  deadline próprio, timeout por consulta e `subprocess.run(timeout=...)`;
- falha/timeout/JSON inválido é registrado no state/RECON e a execução segue;
- `HUNTER_AI_CMD` permite substituir o opencode por um stub determinístico
  (usado nos testes; o comando recebe `<summary.json> <prompt.txt>` e responde
  o plano no stdout).

O RECON ganha a seção **Plano de IA (opencode)** com rodadas, duração,
propostas aceitas/rejeitadas e motivos. Ferramenta de IA **não** executa
payloads; os testes continuam centralizados em `hunter/tests.py` e passam por
`hunter/http.py`.

## Saída

```
<out>/
  INDEX.md                  # consolidado (atualizado a cada alvo)
  state.json                # estado global
  <sub>/RECON.md            # incremental, sempre existe
  <sub>/FINDINGS.md         # incremental, sempre existe
  <sub>/workspace/state.json
  <sub>/workspace/artifacts/  # respostas HTTP + ai/roundN.{summary,prompt,raw}
  <sub>/workspace/logs/hunter.log
```

Escritas são atômicas (`*.tmp` → `os.replace`). Reexecuções fazem merge por
`(vuln_class, endpoint, payload)`; `--resume` não refaz fases `done`.

## Orçamentos e limites

- Watchdog daemon (`stop_event.wait(1)`) encerra no deadline global ou no teto
  global de requisições, faz flush dos relatórios e sai com `os._exit(0)`.
- Por alvo: Fase 1 ≤ 40%, Fase 2 ≤ 5%, Fase 3 ≤ 40%, Fase 4 ≤ 10%, Fase 5 ≤ 5%.
  A IA tem deadline próprio dentro do alvo.
- Requisições: máximo 2 tentativas; retry só em `429/5xx` com 1s; timeout
  `(5, 15)`; `allow_redirects=False` com 1 hop apenas no mesmo host.
- 3-strikes por endpoint e teto de requisições por endpoint do perfil.
- Classes ativas: IDOR, mass assignment, open redirect, CORS, CSRF, GraphQL e
  (sem WAF) XSS, SQLi, NoSQLi, SSRF, SSTI, LFI, RCE, XXE — sempre com payloads
  de detecção, sem extração/estado destrutivo.

## Escopo

Somente os hosts exatamente informados. Toda requisição passa por
`hunter/scope.py` via `hunter/http.py`; hosts externos, outras portas,
homóglifos e a URL de `--scope` são apenas registrados, nunca requisitados.
Proibido DNS enumeration, brute-force de diretórios e ferramentas externas.

## Testes de aceite (via opencode)

A suíte orquestra o `hunter.py` **através do opencode**, usando o comando de
projeto `.opencode/command/hunter-run.md`:

```bash
python3 tests/test_acceptance.py
```

O teste grava um job JSON, executa
`opencode run --auto --command hunter-run -- <job>`, e o agente chama
`tests/opencode_runner.py`, que roda `hunter.py` com timeout e grava o
resultado (exit code, wall-clock, streams). Casos novos:

- `deep`: perfil deep valida OpenAPI, formulários, robots/sitemap, >100
  requisições e XSS refletido em `/search`;
- `ai`: usa `tests/ai_stub.py` via `HUNTER_AI_CMD` e valida rodadas, rejeição de
  host externo, aceite de `/search` e achado marcado como IA;
- `ai_timeout`: usa `tests/ai_hang.py`, confirma que o timeout da IA é
  registrado e o hunter termina sozinho.

O mock é encerrado com `terminate()` + `wait(timeout=5)`.

## Limitações conhecidas

- Heurísticas de detecção, não exploração: achados sem prova forte ficam
  `potential`/`likely`; XSS/SSRF/XXE cegos não são confirmados sem OOB.
- Sem conta autenticada real, IDOR e mass assignment ficam limitados a
  `potential`.
- O plano de IA depende do modelo; JSON inválido/timeout é descartado e a
  execução continua sem ele.
- `--scope` é apenas lido; não há verificação automática de cobertura.
- O resolver de teste (`HUNTER_RESOLVE_HOSTS`), `HUNTER_DEFAULT_SCHEME` e
  `HUNTER_DEFAULT_PORT` existem só para a suíte local.
- Em alvos reais o rate limit de 5 req/s domina o tempo; perfis deep com 600
  requisições podem levar minutos mesmo com orçamento maior.
