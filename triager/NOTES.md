# NOTES — decisões de projeto

1. **Aceitação via opencode**: `tests/test_acceptance.py` não invoca
   `triager.py` diretamente. Grava um job JSON e chama
   `opencode run --auto --command triager-run -- <job>`. O comando de projeto
   `.opencode/command/triager-run.md` executa `tests/opencode_runner.py`, que
   roda `triager.py` com timeout e grava `exit`, wall-clock, `maxrss_kb` e
   streams em `<job>.result.json`. Assim o caminho de execução é o mesmo do
   pipeline, mas o resultado é determinístico.
2. **Sem confirmações**: nenhuma etapa pede input nem depende de TTY. Pasta
   inexistente/vazia → exit 2; `--resume` sem estado → exit 3.
3. **Sem dados hardcoded**: `--targets`/`--targets-file` são a única fonte de
   alvos ativos. Fixtures usam apenas `*.invalid` e `*.localhost`. Segredos
   encontrados são truncados (8 primeiros + 4 últimos) e nunca usados.
4. **Escopo num único choke point**: `triager/scope.py` normaliza host/URL e
   `triager/http.py` chama a allowlist antes de cada requisição. Requisições
   externas, IPs privados (sem `--allow-private`), userinfo e esquemas não-HTTP
   são recusados e registrados; `requests_out_of_scope` permanece `[]`.
5. **Sem `--targets`**: modo leitura implícito. O alvo é inferido apenas para
   classificar `Fora de escopo` × candidata; nenhuma requisição é enviada e o
   RECON grava "alvo não informado — validação não executada".
6. **Saída de scanner é dado**: parsers são regex/JSON/ElementTree puros; não
   há LLM, `eval`, `exec`, `pickle` ou `os.system` sobre conteúdo de output.
   O teste de prompt injection confirma que `evil.invalid` vira `out_of_scope`
   e nenhuma conexão é feita.
7. **Streaming e offsets**: `iter_lines` abre em modo binário para que
   `tell()` permaneça seekable; arquivos grandes são lidos linha a linha com
   deadline interno. Full-JSON acima de `--file-max-mb` é marcado `partial`/
   `skipped` em vez de carregado.
8. **Triagem antes da validação**: `out_of_scope` é checado antes de
   `low_priority`; segredos são sempre `no_active_test`. Isso evita qualquer
   conexão a hosts externos mesmo quando a ferramenta de origem os listou.
9. **Validação controlada**: somente `triager/http.py`; 3–5 payloads por vetor,
   máximo 10 requisições por candidata, 3-strikes, 1 hop de redirect apenas no
   host do alvo. IDs/paths e parâmetros priorizam o lote.
10. **Evidência**: achados confirmados/prováveis gravam
    `artifacts/<candidata>/{req.txt,resp.txt,meta.json}` com cookies,
    `Authorization` e tokens redigidos. Achado sem prova forte fica
    `Provável (parcial)`; PoC que não reproduz fica `Não reproduzida`.
11. **Watchdog**: thread daemon com `stop_event.wait(1)`; ao estourar deadline
    global ou teto absoluto de requisições faz flush e `os._exit(0)`. SIGINT/
    SIGTERM também fazem flush e saída limpa.
12. **Loops**: todos os `while` têm contador/condição explícita
    (`while written < target`, `while not stop_event.wait(...)`); os demais são
    `for` sobre listas limitadas. `os.walk` limita 5.000 entradas e 5 níveis.
13. **Orçamento baixo**: `per_target < 240 s` reduz o lote para no máximo 5 e
    registra aviso no RECON.
14. **Resume**: arquivos `done` não são reprocessados; `partial` retoma do
    `offset`; candidatas `Confirmada`/`Não reproduzida`/etc. não são
    revalidadas. Merge por chaves evita duplicação de tabelas.
15. **Artefatos não são subdomínios (fix de `state.json/workspace`)**: a
    inferência só aceita nomes que passam em `discover.looks_like_sub()`
    (FQDN/hostname válido, sem extensão de arquivo, sem nomes reservados como
    `state.json`, `INDEX.md`, `triager`, `subfinder`, `opencode`). Arquivos
    soltos na raiz de outputs vão para `unassigned` e nunca ganham pasta.
    `RunContext.resolve_folder()` também evita colisão com `state.json` e
    renomeia para `<host>_target` se já existir um arquivo com o nome do host;
    `register` e `flush` ficam protegidos para um subdomínio problemático não
    abortar a execução. Regressão coberta por `test_layout_collision`.

## Resultado dos testes de aceite (executado uma vez)

Comando: `python3 tests/test_acceptance.py` (cada execução do triager foi
orquestrada por `opencode run --auto --command triager-run`).

```
[PASS] compilação de todos os módulos
[PASS] zero dado hardcoded (domínio/e-mail/segredo)
    (opencode wall-clock: 12.1s)
[PASS] inventário: exit 0
[PASS] inventário: RECON por subdomínio
[PASS] inventário: tool detectada por conteúdo
[PASS] inventário: validação não executada
    (opencode wall-clock: 12.4s)
[PASS] arquivo gigante: exit 0
[PASS] arquivo gigante: RSS < 300 MB
[PASS] arquivo gigante: status partial/done com offset
[PASS] arquivo gigante: citado no RECON
[PASS] prompt injection: exit 0
[PASS] prompt injection: nenhuma requisição ao alvo
[PASS] prompt injection: evil.invalid fora de escopo
[PASS] prompt injection: host listado no RECON
    (opencode wall-clock: 16.8s)
[PASS] e2e: exit 0
[PASS] e2e: tempo < 150 s
[PASS] e2e: FINDINGS por subdomínio
[PASS] e2e: XSS confirmado em a.localhost
[PASS] e2e: evidência req/resp pareada
[PASS] e2e: /safe Não reproduzida
[PASS] e2e: candidata fictícia Não reproduzida
[PASS] e2e: estado gravado
[PASS] fora de escopo: exit 0
[PASS] fora de escopo: status Fora de escopo
[PASS] fora de escopo: requests_out_of_scope == []
[PASS] fora de escopo: nenhuma conexão ao alvo
    (opencode wall-clock: 11.6s)
[PASS] watchdog: termina sozinho (exit 0)
[PASS] watchdog: relatórios escritos
[PASS] resume: primeira execução exit 0
[PASS] resume: segunda execução exit 0
[PASS] resume: arquivos done não reprocessados
[PASS] resume: achados não duplicados
[PASS] resume: confirmadas não revalidadas
[PASS] sem --targets: exit 0
[PASS] sem --targets: zero requisições ao mock
[PASS] sem --targets: relatório registra validação não executada
[PASS] layout: exit 0 com state.json na raiz
[PASS] layout: state.json permanece arquivo
[PASS] layout: sem pasta chamada state.json
[PASS] layout: RECON de a.localhost criado
[PASS] layout: estado raiz gravado
[PASS] layout: state.json não é subdomínio
[PASS] layout: exit 0 com colisão de arquivo
[PASS] layout: pasta renomeada em colisão

44/44 verificações passaram.
MOCK servers encerrados; nenhum processo remanescente.
```
