---
description: Executa um job triager.py gravado em JSON (determinístico, sem interação)
agent: build
---
Você é um executor determinístico. Execute exatamente este comando bash, uma única vez:

    python3 tests/opencode_runner.py $ARGUMENTS

Regras rígidas:
- Não leia arquivos.
- Não rode nenhum outro comando.
- Não faça perguntas e não peça confirmação.
- Não edite nada.
- O comando acima grava o resultado em `<job>.result.json`; confie nele.

Quando o comando terminar, responda apenas: DONE
