# hunter3

Pipeline de recon e caça de vulnerabilidades web orquestrado pelo [opencode](https://opencode.ai), executado em lote sobre uma lista de domínios de escopo autorizado.

O repositório reúne as ferramentas e os comandos do agente:

| Caminho | Papel |
|---|---|
| `workflow.yaml` | Orquestração: roda as ferramentas de recon em lote e, no fim, chama `hunter` e `triager`. |
| `hunter/hunter.py` | Ferramenta **hunter** — recon + testes não destrutivos em múltiplos subdomínios, por perfil de profundidade e com planejamento opcional por IA (`opencode`). |
| `triager/triager.py` | Ferramenta **triager** — lê/correlaciona outputs de recon/scan, faz triagem e valida as candidatas priorizadas no alvo autorizado. |
| `hunt.md` | Comando opencode `hunt` — versão em prompt de agente para **um único domínio** (WAF-aware). Mantido para uso manual. |
| `analysis.md` | Comando opencode `analysis` — versão em prompt de agente para análise de outputs. Mantido para uso manual. |

As duas ferramentas são **não interativas**, timeboxed, resumíveis (`--resume`) e escrevem
`RECON.md` e `FINDINGS.md` incrementais por subdomínio mais um `INDEX.md` consolidado.

## Fluxo

O `workflow.yaml` executa os módulos em sequência (`parallel: false`):

1. `dir_creation` — cria `OUTPUT_FOLDER/<data>/<dominio>/`.
2. `postevil` — tokens, subdomínios e wayback a partir do Postman.
3. `iacrawl`, `s3scan`, `blh`, `dnsdangling`, `orscan` — scans de infraestrutura, buckets S3, dangling DNS e open redirect.
4. `subdomain_enum` — `subfinder` sobre a lista de escopo, gravando `subfinder/subdomains.txt`.
5. `opencode_test` — roda o **hunter** sobre todos os subdomínios encontrados:
   ```
   python3 {{HUNTER_FOLDER}}/hunter/hunter.py \
       --targets-file {{OUTPUT_FOLDER}}/<data>/subfinder/subdomains.txt \
       --out {{OUTPUT_FOLDER}}/<data>/opencode/
   ```
6. `opencode_analysis` — roda o **triager** sobre a pasta do dia (todos os outputs das ferramentas), gravando em `triager/`:
   ```
   mkdir -p {{OUTPUT_FOLDER}}/<data>/triager
   python3 {{HUNTER_FOLDER}}/triager/triager.py {{OUTPUT_FOLDER}}/<data> \
       --out {{OUTPUT_FOLDER}}/<data>/triager
   ```
   Sem `--targets`, o triager roda em modo somente-leitura (inventário + triagem, sem requisições).
   Para validar de fato, informe os alvos autorizados (ver abaixo).

### Variáveis

Definidas no topo do `workflow.yaml`:

- `TOOLS_FOLDER`, `OUTPUT_FOLDER` — raízes de ferramentas e saída.
- `SCOPE_FILE` — lista de domínios autorizados (uma por linha).
- `HUNTER_FOLDER` — raiz deste repositório, usada para localizar `hunter/hunter.py` e `triager/triager.py`.
- `POSTMAN_KEY` — segredo injetado em tempo de execução (`{{POSTMAN_KEY}}`).

## hunter

Recon profundo + testes de vulnerabilidade web **não destrutivos**, multi-subdomínio, com
orçamento duro de tempo/requisições, estado resumível e relatórios incrementais.

### Uso

```bash
# lote a partir de arquivo (um alvo por linha, # comentário)
python3 hunter/hunter.py --targets-file alvos.txt --out ./hunter_out

# alvos explícitos, com IA e perfil deep
python3 hunter/hunter.py app.exemplo.invalid,api.exemplo.invalid \
    --ai --profile deep --max-minutes 30 --max-requests 600 --out ./hunter_out

# sem IA (ambiente sem opencode ou para economizar tempo)
python3 hunter/hunter.py app.exemplo.invalid --no-ai --out ./hunter_out
```

### Flags principais

| Flag | Padrão | Descrição |
|---|---|---|
| `--targets a,b` / `--targets-file arq` | — | Fonte de alvos (obrigatória). |
| `--emails a@x,b@y` | nenhum | Única fonte de e-mails de teste; sem ela, cadastro/contas são pulados. |
| `--password-env NOME` | `HUNTER_PASSWORD` | Variável de ambiente com a senha de registro (nunca logada). |
| `--scope URL` | — | Página do programa: 1 GET de leitura de política, nunca alvo de teste. |
| `--recon-only` | off | Para após a Fase 1. |
| `--register` | off | Tenta cadastro; exige `--emails` (senão exit 2, zero requisições). |
| `--proxy URL` | — | Proxy em todas as requisições. |
| `--out DIR` | `./hunter_out` | Raiz de saída. |
| `--resume` | off | Retoma do `state.json`; exit 3 se não houver estado. |
| `--profile {fast,standard,deep}` | `deep` | Profundidade de crawl/testes (o orçamento pode reduzir, nunca aumentar). |
| `--ai` / `--no-ai` | auto | Planejamento por IA via opencode (liga sozinho se `opencode` estiver no PATH). |
| `--ai-rounds N` | perfil | Rodadas de IA pós-testes (1–2; total ≤3 com o estágio pré). |
| `--ai-max-minutes N` | ~25% do alvo | Teto de tempo total da IA por alvo (máx. 8 min). |
| `--ai-timeout N` | `180` | Timeout de cada consulta de IA (s). |
| `--max-minutes N` | `30` | Deadline global (watchdog encerra a execução). |
| `--per-target-max-minutes N` | calculado | Sobrepõe o orçamento por alvo. |
| `--max-requests N` | `600` | Teto de requisições por alvo. |
| `--max-total-requests N` | `600 × alvos` | Teto absoluto da execução. |
| `--rate N` | `5` | Máximo de req/s por host. |
| `--verbose` | off | Log detalhado em stderr + arquivo. |

Códigos de saída: `0` concluído (total ou parcial, motivo registrado), `2` erro de uso,
`3` `--resume` sem estado.

### O que a busca cobre

- **Recon**: baseline HTTP, WAF/CDN, GraphQL (paths + introspection + fields), crawl BFS
  (até 3 níveis / 45 páginas no deep), bundles JS e source maps, formulários, OpenAPI/Swagger,
  `robots.txt`/`sitemap.xml`, caminhos de vazamento, fingerprint de tech, mineração de parâmetros
  e segredos truncados.
- **Testes**: IDOR, mass assignment, open redirect, CORS, CSRF e GraphQL; sem WAF também XSS,
  SQLi, NoSQLi, SSRF, SSTI, LFI, RCE e XXE — sempre com payloads de detecção, sem extração
  destrutiva.
- **IA (opcional)**: agente `plan` do opencode (read-only) propõe endpoints/crawl/leak paths
  adicionais a partir de um resumo sanitizado; toda proposta passa por allowlist de host e
  classe antes de qualquer requisição. Timeout/JSON inválido é registrado e a execução segue.
- **Escopo**: somente os hosts informados; terceiros são apenas registrados. Toda requisição
  passa por `hunter/scope.py` + `hunter/http.py`.

### Saída do hunter

```
<out>/
  INDEX.md
  state.json
  <sub>/
    RECON.md
    FINDINGS.md
    workspace/
      state.json
      artifacts/          # respostas HTTP + ai/roundN.{summary,prompt,raw}
      logs/hunter.log
```

## triager

Lê e correlaciona outputs de recon/scan (Nuclei, sqlmap, Burp, ZAP, Nikto, WPScan, ffuf,
WhatWeb, httpx, Nmap, gau/waybackurls/katana, semgrep, trufflehog/gitleaks, …), extrai e
deduplica candidatas, faz triagem por escopo/impacto e valida as priorizadas no alvo real.

### Uso

```bash
# validação ativa (alvos autorizados)
python3 triager/triager.py ./outputs \
    --targets app.exemplo.invalid,api.exemplo.invalid \
    --max-minutes 20 --max-candidates 15 \
    --out ./outputs/_analysis

# reexecução
python3 triager/triager.py ./outputs --targets app.exemplo.invalid --resume

# somente inventário + triagem (nenhuma requisição)
python3 triager/triager.py ./outputs --recon-only --out ./outputs/_analysis
```

### Flags principais

| Flag | Padrão | Descrição |
|---|---|---|
| `<pasta-de-outputs>` | — | Obrigatória. Diretório com outputs de recon/scan. |
| `--targets a,b` / `--targets-file arq` | inferido | Fonte de alvos ativos; sem ela, modo somente-leitura. |
| `--out DIR` | `<outputs>/_analysis` | Raiz de saída dos relatórios/estado. |
| `--split-dir` | auto | Cada subpasta de 1º nível = um subdomínio. |
| `--recon-only` | off | Para após inventário + triagem. |
| `--resume` | off | Retoma do `state.json`; exit 3 se ausente. |
| `--max-candidates N` | `15` | Candidatas validadas por execução. |
| `--max-minutes N` | `20` | Deadline global (watchdog). |
| `--per-target-max-minutes N` | calculado | Orçamento por subdomínio. |
| `--max-requests N` | `200` | Teto de requisições. |
| `--budget-scope {per-target,global}` | `per-target` | Escopo do teto de requisições. |
| `--max-total-requests N` | `200 × subdomínios` | Teto absoluto. |
| `--file-max-seconds N` | `60` | Tempo máximo por arquivo. |
| `--file-max-mb N` | `10` | Acima disso, streaming/limite seguro. |
| `--rate N` | `5` | Máx. req/s por host. |
| `--proxy URL` | — | Proxy em todas as requisições. |
| `--oob-url URL` | — | Sink OOB para provar achados cegos (SSRF/XXE). |
| `--allow-private` | off | Permite alvos privados/loopback (testes de aceite). |
| `--verbose` | off | Log detalhado. |

Códigos de saída: `0` concluído (total/parcial), `2` erro de uso, `3` `--resume` sem estado.

### O que o triager cobre

- **Parsers**: detecção por conteúdo (`sniff`), não por extensão; Nuclei (JSONL/texto), sqlmap,
  Burp (XML/HAR), ZAP (JSON/XML), Nikto, Nmap XML, WPScan, ffuf/gobuster/feroxbuster, WhatWeb,
  gau/waybackurls/katana, semgrep e trufflehog/gitleaks + fallback genérico.
- **Triagem**: `out_of_scope` (nunca testado), `no_active_test` (segredos truncados, sem uso),
  `low_priority` (headers/tech/misconfig) e `active` (classes com validador).
- **Validação**: XSS, SQLi, NoSQLi, SSRF, LFI, RCE, open redirect, IDOR, CORS, CSRF, SSTI, XXE e
  GraphQL; 10 requisições por candidata, 5 payloads/vetor, 3-strikes, 1 hop apenas no host do alvo.
- **Segurança**: saída de ferramenta é dado, nunca instrução; nada de `eval`/`exec`; toda URL
  passa por normalização + allowlist antes de qualquer requisição.
- **Robustez de layout**: arquivos soltos como `state.json` e pastas de ferramentas
  (`subfinder`, `triager`, `opencode`) nunca são tratados como subdomínios; colisão de nome vira
  `<host>_target` em vez de erro `NotADirectoryError`.

### Saída do triager

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

## Testes de aceite

Ambas as ferramentas têm suíte própria que orquestra a execução **através do opencode**
(`opencode run --auto --command hunter-run|triager-run`), com mock local e sem rede externa:

```bash
cd hunter  && python3 tests/test_acceptance.py   # 39 verificações
cd triager && python3 tests/test_acceptance.py   # 44 verificações
```

Cada teste grava um job JSON, o comando de projeto chama `tests/opencode_runner.py`, que executa
a ferramenta com timeout e registra exit code, wall-clock e streams. Os mock servers são
encerrados com `terminate()`/`shutdown()` + `wait(timeout=5)`.

## Pré-requisitos

- `python3` 3.10+ e `requests` (`pip install -r hunter/requirements.txt` ou
  `pip install -r triager/requirements.txt`; há fallback para `urllib`).
- `opencode` no `PATH` para o planejamento por IA do hunter e para as suítes de aceite.
- Ferramentas do pipeline: `postevil`, `iacrawl`, `s3scan`, `blh-hunter`, `dnsdangle_exploit.py`,
  `orscan`, `subfinder` (mais `jq`, `curl`).
- `PASSWORD`/`HUNTER_PASSWORD` (senha de cadastro) e `POSTMAN_KEY` no ambiente, quando aplicável.

## Uso

```bash
# execução direta das ferramentas
python3 hunter/hunter.py --targets-file alvos.txt --out ./out/hunter
python3 triager/triager.py ./out/2026-01-01 --targets app.exemplo.invalid --out ./out/triager

# ou simplesmente execute o workflow.yaml no orquestrador que consome esse formato
```

Para uso não interativo em automação:

```bash
timeout --kill-after=60 1800 opencode run --dangerously-skip-permissions --command triager-run -- ./job.json
```

## Observações

- `hunt.md`/`analysis.md` continuam disponíveis como comandos de agente (`opencode run --command hunt|analysis`),
  mas o `workflow.yaml` atual chama diretamente `hunter/hunter.py` e `triager/triager.py`.
- **Atenção**: a linha do módulo `opencode_test` no `workflow.yaml` está truncada
  (`--out {{OUTPUT_FOLDER}}/.../openc`). O valor correto é um diretório completo, por exemplo
  `--out {{OUTPUT_FOLDER}}/$(date +%Y-%m-%d)/opencode/`.
- Todo conteúdo proveniente dos alvos (HTML, JS, respostas, saída de ferramentas) é **dado**,
  nunca instrução.

> **Segurança:** a URL do remote git deste repositório contém um token do GitHub embutido em texto claro. Revogue esse token e configure o remote sem credenciais (`git remote set-url origin https://github.com/victorhfsilva/hunter3.git`), usando um credential helper.
