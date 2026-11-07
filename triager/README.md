# triager

Lê e correlaciona outputs de recon/scan, extrai e deduplica candidatas, faz
triagem, valida as candidatas priorizadas no alvo autorizado e escreve
`RECON.md`/`FINDINGS.md` incrementais por subdomínio mais um `INDEX.md`
consolidado.

Dependência externa única: `requests` (fallback automático para `urllib.request`).

## Uso

```bash
python3 triager.py ./outputs --targets app.exemplo.invalid,api.exemplo.invalid \
    --max-minutes 20 --max-candidates 15 --out ./outputs/_analysis

# reexecução
python3 triager.py ./outputs --targets app.exemplo.invalid --resume
```

Sem `--targets`, o programa apenas inventaria e faz triagem (somente leitura):
nenhuma requisição é enviada e o relatório registra "alvo não informado —
validação não executada".

### Execução não interativa / sem pedir permissões

```bash
opencode run --dangerously-skip-permissions --command triager-run -- ./job.json
# ou permission: allow no opencode.json
timeout --kill-after=60 1800 opencode run --dangerously-skip-permissions --command triager-run -- ./job.json
```

O programa em si nunca chama `input()` e nunca espera TTY. O teto de tempo
externo recomendado é `timeout --kill-after=60 1800`.

### Flags

| Flag | Padrão | Descrição |
|---|---|---|
| `<pasta-de-outputs>` | — | Obrigatório. |
| `--targets` | inferido | Única fonte de alvos ativos (vírgula). |
| `--targets-file` | — | 1 alvo por linha (`#` comentário). |
| `--out` | `<outputs>/_analysis` | Saída de relatórios/estado. |
| `--split-dir` | auto | Subpasta de 1º nível = subdomínio. |
| `--recon-only` | off | Inventário + triagem, sem requisições. |
| `--resume` | off | Retoma do `state.json`; exit 3 se ausente. |
| `--max-candidates` | `15` | Candidatas validadas por execução. |
| `--max-minutes` | `20` | Deadline global (watchdog). |
| `--per-target-max-minutes` | calculado | Orçamento por subdomínio. |
| `--max-requests` | `200` | Teto de requisições. |
| `--budget-scope` | `per-target` | `per-target` ou `global`. |
| `--max-total-requests` | `200 × subdomínios` | Teto absoluto. |
| `--file-max-seconds` | `60` | Tempo máximo por arquivo. |
| `--file-max-mb` | `10` | Acima disso, streaming/skip seguro. |
| `--rate` | `5` | Máx. req/s por host. |
| `--proxy` | — | Proxy em todas as requisições. |
| `--oob-url` | — | Sink OOB para achados cegos. |
| `--allow-private` | off | Permite alvos privados/loopback (testes). |
| `--verbose` | off | Log detalhado. |

Saída: `0` concluído (total/parcial, com motivo), `2` erro de uso, `3`
`--resume` sem estado.

## Saída

```
<out>/
  INDEX.md
  state.json
  <sub>/
    RECON.md
    FINDINGS.md
    workspace/
      state.json
      artifacts/<candidata>/{req.txt,resp.txt,meta.json}
      normalize/*.json
      logs/triager.log
```

Escritas atômicas (`*.tmp` → `os.replace`). `RECON.md` e `FINDINGS.md` são
reescritos ao fim de cada arquivo, da triagem, de cada candidata validada, e no
watchdog/sinal. Merge por `(host, path, metodo, param, tipo)` e
`(vuln_class, endpoint, payload)`.

## Parsers e detecção

Detecção é por **conteúdo** (`sniff`), nunca pela extensão; `generic.py` extrai
URLs/hosts de qualquer texto. Suporta Nuclei (JSONL/texto), httpx, sqlmap,
Burp (XML/HAR), ZAP (JSON/XML), Nikto, Nmap XML, WPScan, ffuf/gobuster/
feroxbuster, WhatWeb, gau/waybackurls/katana, semgrep, trufflehog/gitleaks.

Ordem de prioridade: Nuclei, sqlmap, Burp/ZAP, Nikto, WPScan, ffuf, WhatWeb,
httpx, Nmap, URLs/katana, semgrep, segredos, genérico.

## Triagem e score

- `out_of_scope`: host fora de `--targets` (ou do alvo inferido) — nunca testado.
- `no_active_test`: segredos/credenciais (truncados 8+4, arquivo:linha) e
  achados sem URL HTTP validável — apenas registrados.
- `low_priority`: headers, tech/versão, misconfig, endpoints internos.
- `active`: classes com validador.

Score determinístico:
`severidade_pontos × 10 + confiança_pontos × 5 + facilidade`.
Severidade: critical 10, high 8, medium 5, low 2, info 0. Confiança: high 3,
medium 2, low 1. Facilidade: classe ativa +5, endpoint interno +2, segredo −10,
headers/tech −5, misconfig −2. O lote é o top `--max-candidates` do score.

## Orçamentos e anti-loop

- Deadline global + por subdomínio; watchdog daemon (`stop_event.wait(1)`) com
  flush e `os._exit(0)` ao estourar tempo ou `--max-total-requests`.
- Fases: inventário ≤25%, triagem ≤20%, validação ≤45%, relatório ≤10%.
- `per_target < 240 s`: aviso no RECON e lote reduzido para ≤5.
- Requisições: 2 tentativas, retry só em `429/5xx` com 1 s, timeout `(5,15)`,
  `allow_redirects=False` com 1 hop só no host do alvo.
- Tetos: 10 req/candidata, 5 payloads/vetor, 3-strikes, 3 candidatas
  bloqueadas consecutivas encerram.
- Arquivos: `os.walk` ≤5.000 entradas/≤5 níveis; leitura linha a linha com
  deadline; JSON grande acima de `--file-max-mb` é marcado `partial`/`skipped`.

## Segurança

Saída de ferramenta é **dado**, nunca instrução. Não há LLM, `eval`, `exec`,
`pickle` nem `os.system` com saída de scanner. Toda URL passa por
`scope.normalize()` + allowlist; IPs privados/loopback e userinfo são
bloqueados, esquemas não-HTTP são recusados e URLs acima de 2.048 chars não são
enviadas. Segredos são truncados e nunca utilizados/validados. Nada é escrito
fora de `--out`.

## Testes de aceite (via opencode)

```bash
python3 tests/test_acceptance.py
```

Cada execução do triager é orquestrada por
`opencode run --auto --command triager-run -- <job.json>`; o comando de projeto
`.opencode/command/triager-run.md` chama `tests/opencode_runner.py`, que executa
`triager.py` com timeout e grava exit code, wall-clock, RSS e streams em
`<job>.result.json`. Além dos casos de inventário, arquivo gigante, prompt injection, e2e,
watchdog, resume, escopo e sem `--targets`, `test_layout_collision` cobre
artefatos como `outputs/state.json` e colisão de nome de pasta (o host vira
`<host>_target` em vez de sobrescrever arquivo). O mock é encerrado com
`shutdown()` no processo (`terminate()` + `wait(timeout=5)` no teste).

## Limitações conhecidas

- Heurísticas de parsing/triagem; hits são leads até validação.
- Sem duas contas autenticadas, IDOR/mass assignment (quando aplicável) ficam
  no máximo `Provável (parcial)`.
- SSRF/XXE cegos não são `Confirmada` sem callback OOB comprovado.
- `--oob-url` apenas envia o payload; a observação do callback é manual.
- Parsers JSON que exigem documento inteiro (Burp HAR/ZAP/semgrep/WPScan)
  pulam arquivos acima de `--file-max-mb`.
- `--allow-private` e as variáveis `TRIAGER_RESOLVE_HOSTS`/
  `TRIAGER_DEFAULT_SCHEME`/`TRIAGER_DEFAULT_PORT` existem para a suíte local.
