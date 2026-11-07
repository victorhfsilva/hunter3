# NOTES — decisões de construção

1. **Teste via opencode**: a suíte `tests/test_acceptance.py` não invoca
   `hunter.py` diretamente. Ela grava um job JSON e chama
   `opencode run --auto --command hunter-run -- <job>`. O comando de projeto
   `.opencode/command/hunter-run.md` instrui o agente a executar
   `python3 tests/opencode_runner.py <job>`, que roda `hunter.py` com timeout e
   grava `exit`, wall-clock e streams em `<job>.result.json`. Assim o caminho de
   execução é o mesmo do pipeline (`opencode run`), mas o resultado é
   determinístico.
2. **Sem confirmações**: nenhuma etapa pede input. Toda ambiguidade seguiu o
   padrão do enunciado (alvos explícitos, sem DNS enum, sem ferramentas
   externas).
3. **Sem e-mails hardcoded**: `--emails` é a única fonte. Sem ele, registro e
   testes dependentes de conta são pulados e registrados no RECON. E-mails de
   teste aparecem mascarados (`p***@dominio`).
4. **Senha**: lida só da variável de ambiente (`--password-env`, padrão
   `HUNTER_PASSWORD`), adicionada à redação de artefatos/logs, nunca impressa.
5. **Fallback HTTP**: `hunter/http.py` usa `requests` quando disponível e cai
   para `urllib.request` na mesma interface se o import falhar. A suíte usa a
   dependência real (`requests`).
6. **Resolver local de teste**: `HUNTER_RESOLVE_HOSTS` mapeia
   `a.localhost`/`b.localhost` para `127.0.0.1` sem `/etc/hosts` e sem sudo;
   só é instalado quando a variável existe. `HUNTER_DEFAULT_SCHEME` e
   `HUNTER_DEFAULT_PORT` permitem apontar os alvos de teste para a porta livre
   do mock. Em produção essas variáveis ficam ausentes.
7. **Watchdog**: thread daemon com `stop_event.wait(1)`; ao estourar deadline
   global ou teto global de requisições, faz flush de todos os relatórios e
   chama `os._exit(0)`. SIGINT/SIGTERM também fazem flush e saída limpa.
8. **Orçamento por alvo**: `per_target = --per-target-max-minutes ou
   max(120, floor(max_minutes*60/n_alvos))`. O perfil efetivo é o menor entre
   `--profile` e o teto do orçamento (<300s fast, <600s standard, senão deep);
   abaixo de 300s há aviso no RECON. O padrão agora é deep, 30 min e 600 req por
   alvo; o orçamento continua sendo um teto duro.
9. **Escopo num único ponto**: `hunter/scope.py` valida esquema/host/porta e
   `hunter/http.py` chama a validação antes de cada requisição. Violações são
   registradas em `out_of_scope` (com `tested: false`) e nunca enviadas.
   Redirect externo é registrado como possível open redirect e não seguido.
10. **Sem loops ilimitados**: todo loop itera sobre lista limitada ou usa
    `range(MAX)`; os loops têm comentário `# limite: ...`. O único `while` é o
    do watchdog, controlado por `stop_event.wait(1)`.
11. **Retry único**: apenas em `hunter/http.py`, máximo 2 tentativas, sem
    retry em 4xx; 429/5xx têm no máximo 1 retry com backoff de 1s.
12. **Achados**: chave de merge `(vuln_class, endpoint, payload)`. O
    `7-Question Gate` rebaixa para `potential` o que não tiver impacto
    demonstrado/reproduzível. Nenhum achado é `confirmed` por hit isolado.
13. **Relatórios**: `RECON.md`/`FINDINGS.md` são reescritos a cada subetapa,
    classe, achado, fim de fase, watchdog e sinal. Escrita atômica em todos os
    casos; `INDEX.md` é consolidado a cada flush.
14. **Ordem e priorização**: seleção WAF-aware (com WAF, só IDOR/mass
    assignment/open redirect/CORS/CSRF/GraphQL; sem WAF, adiciona
    XSS/SQLi/NoSQLi/SSRF/SSTI/LFI/RCE/XXE). IDs/paths de
    conta/pedido/pagamento/reset/admin/search/login e endpoints com parâmetros,
    OpenAPI, formulários ou IA pontuam mais; dedup por método+path evita testar
    quatro variações da mesma rota.
15. **Busca mais profunda**: crawl BFS (profundidade e páginas por perfil),
    extração de formulários, OpenAPI/Swagger, robots/sitemap, rotas em JS,
    fields/args de GraphQL e mineração de parâmetros. Os tetos crescem no perfil
    deep (45 páginas, 22 bundles, 6 source maps, 28 leaks, 8 payloads/classe,
    30 req/endpoint, 15 endpoints).
16. **IA via opencode**: `hunter/ai.py` chama `opencode run --agent plan
    --format json` (read-only) com um resumo sanitizado do alvo e recebe um
    plano JSON. Um estágio pre (antes da seleção) e um post (após os testes,
    com cobertura/achados) expandem endpoints, crawl e leak paths. O agente não
    executa payloads; a execução continua em `hunter/tests.py`/`http.py`.
17. **IA bounded**: máximo 3 rodadas, deadline próprio (`--ai-max-minutes`),
    timeout por consulta (`--ai-timeout`), `subprocess.run(timeout=...)`,
    máx. 15 testes + 10 crawl + 10 leak por rodada. Timeout/JSON inválido é
    registrado e a execução segue. A chamada padrão usa o agente `plan`
    (sem bash/escrita); `HUNTER_AI_CMD` permite um stub determinístico nos testes.
18. **Propostas da IA são não confiáveis**: URL/método/parâmetro/classe passam
    por sanitização e pela allowlist de host; host externo, classe não permitida
    ou path malformado viram `rejected` no state e no RECON. Nada é enviado
    antes dessa validação. Em teste real (mock), o agente propôs 33 itens em
    ~20s e nenhum host externo foi aceito.
19. **Anti-falso-positivo**: RCE só conta se o canário aparecer sem o payload
    `echo` refletido; SQLi booleana ignora respostas que refletem os próprios
    payloads; NoSQLi só roda em respostas JSON; IDOR exige corpo diferente com
    estrutura sensível. Hits de reflexão não viram SQLi/RCE.
20. **Relatórios**: RECON ganhou as seções Plano de IA, Formulários,
    OpenAPI/Swagger, robots/sitemap, Parâmetros minerados; FINDINGS marca a
    origem (`scanner`/`ai` + estágio/razão). INDEX mostra rodadas de IA e
    perfil.

## Resultado da suíte de aceite (executada uma vez)

Comando: `python3 tests/test_acceptance.py` (cada caso do hunter é executado
por `opencode run --auto --command hunter-run`).

```
[PASS] compilação de todos os módulos
[PASS] sem e-mails hardcoded (exceto *.invalid/fixtures)
    (opencode wall-clock: 33.2s)
[PASS] e2e: exit code 0
[PASS] e2e: wall-clock < 90 s
[PASS] e2e: relatórios e estados existem
[PASS] e2e: mock encerrado sem processo remanescente
    (opencode wall-clock: 15.7s)
[PASS] watchdog: termina sozinho
[PASS] watchdog: wall-clock < 60 s
[PASS] watchdog: relatórios escritos
[PASS] resume: primeira execução exit 0
[PASS] resume: segunda execução exit 0
[PASS] resume: achados não duplicados
[PASS] resume: fase recon não refeita
[PASS] escopo: execução exit 0
[PASS] escopo: zero requisições fora do alvo
[PASS] escopo: URL externa apenas registrada
[PASS] escopo: URL externa no RECON
[PASS] registro sem --emails: exit 2
[PASS] registro sem --emails: zero requisições
    (opencode wall-clock: 72.7s)
[PASS] deep: exit 0
[PASS] deep: wall-clock < 200 s
[PASS] deep: OpenAPI parseado
[PASS] deep: formulário descoberto
[PASS] deep: robots parseado
[PASS] deep: sitemap parseado
[PASS] deep: XSS refletido em /search
[PASS] deep: requests acima de 100
    (opencode wall-clock: 83.3s)
[PASS] AI: exit 0
[PASS] AI: wall-clock < 200 s
[PASS] AI: habilitada via stub
[PASS] AI: rodadas registradas
[PASS] AI: proposta fora de escopo rejeitada
[PASS] AI: proposta /search aceita
[PASS] AI: achado originado da IA
[PASS] AI: seção no RECON
    (opencode wall-clock: 25.8s)
[PASS] AI timeout: termina com exit 0
[PASS] AI timeout: wall-clock < 100 s
[PASS] AI timeout: erro de timeout registrado
[PASS] AI timeout: relatórios escritos

39/39 verificações passaram.
MOCK servers encerrados; nenhum processo remanescente.
```
