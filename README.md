# monitor-sites

Monitoramento dos sites do Diretamente da Fronteira / Paraguai na Mao via GitHub Actions.
Repositorio publico de proposito: apenas URLs publicas, nenhum segredo.

- `monitor.yml`: a cada 10 min; falha (e o GitHub avisa por e-mail) se algo quebrar.
- `relatorio-diario.yml`: 8h de Assuncao (11:00 UTC); so registra tempos e validade SSL no resumo.
- Checagens em `checks.json`; logica em `monitor.py` (Python 3, so biblioteca padrao + openssl).
