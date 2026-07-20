# Algoritmo de Priorização de Vulnerabilidades CVE

Este projeto desenvolve uma ferramenta de linha de comando (CLI) em Python para automatizar a priorização de correções de segurança. O objetivo é superar a ineficiência de focar apenas na severidade técnica (CVSS), integrando métricas de probabilidade real e evidência de exploração ativa.

## 1. Fundamentação Teórica

A ferramenta utiliza um algoritmo de risco integrado baseado nos seguintes sinais principais, fundamentados em Jacobs et al. (2023), *"Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights"* (arXiv:2302.14172) — ver detalhamento completo em `docs/ALGORITMO.md`:

* **CVSS (Common Vulnerability Scoring System)**: Avalia a severidade técnica da falha (0.0 a 10.0). Buscado primariamente no NIST/NVD, com fallback para o índice NVD++ da VulnCheck.
* **EPSS (Exploit Prediction Scoring System)**: Estima a probabilidade de exploração nos próximos 30 dias (0% a 100%), via FIRST.org. É o principal motor do score (peso dominante sobre o CVSS), pois o paper mostra AUC de 0.78 para EPSS contra apenas 0.05 para o CVSS Base Score na predição de exploração real.
* **KEV (Known Exploited Vulnerabilities)**: União dos catálogos da CISA e da VulnCheck (índice `vulncheck-kev`), indicando exploração ativa confirmada.
* **Ransomware Check**: Verifica, a partir do feed da CISA, se a vulnerabilidade é sabidamente utilizada em ataques de ransomware.
* **Nuclei Template**: Verifica, via API do GitHub, se existe um template de exploração público no repositório `projectdiscovery/nuclei-templates`.
* **Metasploit Module**: Verifica, via API do GitHub, se existe um módulo de exploração público no repositório `rapid7/metasploit-framework`. Tratado como critério independente do Nuclei e com peso maior, já que o paper mostra que "Exploit:metasploit" tem contribuição SHAP individual maior que "Scanner:Nuclei", e que, como heurística isolada, a estratégia baseada em Metasploit (60.5% de eficiência) supera até a KEV (53.2%).
* **Contagem de Referências**: Extraída do NIST/NVD, é a feature individual de maior contribuição SHAP no modelo EPSS v3 segundo o paper — entra como um pequeno bônus adicional no score.

### O Algoritmo de Scoring

O cálculo do risco final (`RiskScorer`) segue os seguintes passos:

1. **Componente base (EPSS × CVSS, ponderado)**: normaliza CVSS (`/10`) e EPSS (0–1) e combina os dois valores através de uma média geométrica ponderada (`epss_norm^0.7 * cvss_norm^0.3`), dando ao EPSS o papel de motor principal do score, com o CVSS atuando como modificador de severidade.
   * Caso o CVSS ou o EPSS não estejam disponíveis, são usados valores padrão conservadores (CVSS = 8.0, EPSS = 0.04 — próximo da mediana histórica do EPSS, evitando inflar artificialmente o risco), e o resultado é sinalizado como `missing_cvss`/`missing_epss` na saída.
2. **Qualificadores de exploração ativa**: o componente base é multiplicado por:
   * `1.08` se existir template no Nuclei;
   * `1.20` se existir módulo no Metasploit;
   * `1.15` se o CVE for associado a ransomware.
3. **Bônus por contagem de referências**: soma-se um pequeno bônus (até `+0.05`) proporcional à contagem de referências do CVE no MITRE CVE List, normalizado até 30 referências.
4. **Cap em 1.0**: o componente base (já qualificado e com o bônus de referências) é limitado a no máximo 1.0 — ou seja, CVSS e EPSS altos sozinhos já são suficientes para atingir a categoria CRÍTICO, independentemente do KEV.
5. **Bônus KEV (sem cap)**: se o CVE estiver no catálogo KEV, soma-se `+0.6` ao score **depois** do cap acima. Esse bônus não é limitado, garantindo que um CVE em KEV sempre fique à frente de um CRÍTICO equivalente fora do KEV no ranking final.

**Categorias de risco** (sobre o score final):

| Score          | Categoria |
|----------------|-----------|
| ≥ 0.80         | CRÍTICO   |
| 0.60 – 0.79    | ALTO      |
| 0.30 – 0.59    | MÉDIO     |
| < 0.30         | BAIXO     |

---

## 2. Estrutura do Sistema

A aplicação é dividida em camadas principais para garantir modularidade:

1. **Interface CLI** (`src/main.py`, `src/cli/`): entrada de dados (IDs CVE ou arquivos JSON), validação de formato e flags de configuração; formatação da saída em tabela colorida (`click`) ou JSON.
2. **Engine de Processamento** (`src/core/`):
   * `cve_processor.py` — orquestra a busca de dados e o cálculo de score para cada CVE;
   * `risk_scorer.py` — implementa o algoritmo de scoring descrito acima;
   * `ranker.py` — ordena os resultados por score decrescente e atribui `priority_rank`.
3. **Gerenciador de Cache** (`src/cache/`):
   * `database.py` — persistência local em SQLite (`data/cache.db`);
   * `schema.py` — definição das tabelas `vulnerabilities` e `cache_metadata`;
   * `sync_manager.py` — decide entre reaproveitar o cache válido ou buscar dados atualizados nas APIs, com fallback para o último dado em cache em caso de falha de rede.
4. **Clientes de APIs** (`src/api/`): camada de abstração HTTP com retry/backoff automático (`api_client.py`), com um cliente por fonte de dados:
   * `nist_nvd.py` (CVSS/CWE e contagem de referências via NIST/NVD)
   * `first_epss.py` (EPSS via FIRST.org)
   * `cisa_kev.py` (catálogo KEV da CISA)
   * `ransomware_api.py` (uso conhecido em ransomware, via feed da CISA)
   * `nuclei_github.py` (existência de template de exploit no repositório Nuclei, via API do GitHub)
   * `metasploit_github.py` (existência de módulo de exploit no repositório oficial do Metasploit Framework, via API do GitHub)
   * `vulncheck_api.py` (fonte adicional/fallback: KEV estendido e NVD++, opcional — requer `VULNCHECK_API_KEY`; se ausente, o cliente fica inativo sem quebrar o pipeline)
5. **Utilitários** (`src/utils/`): validação de formato de CVE (`validators.py`), exceções customizadas (`exceptions.py`) e logging para console e arquivo (`logger.py`, com saída em `data/logs/`).

---

## 3. Configuração do Ambiente

### Instalação Passo a Passo

1. **Ativar o Ambiente Virtual (venv)**:
   No terminal (PowerShell), dentro da pasta raiz:
   ```powershell
   python -m venv venv
   ```
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

2. **Instalar Dependências**:
   Para evitar erros de compilação com o Pandas em versões recentes do Python, instale os utilitários de construção antes:
   ```powershell
   python.exe -m pip install --upgrade pip
   pip install setuptools wheel
   pip install -r requirements.txt
   ```

3. **Variáveis de Ambiente (opcional)**:
   Crie um arquivo `.env` na raiz do projeto para configurar chaves de API que aumentam os limites de requisição:
   ```
   NIST_API_KEY=sua_chave_aqui
   GITHUB_API_TOKEN=seu_token_aqui
   VULNCHECK_API_KEY=sua_chave_aqui
   ```
   Todas são opcionais — sem elas, a ferramenta funciona normalmente, apenas com limites de taxa mais restritos e sem o fallback/fonte adicional da VulnCheck. O `GITHUB_API_TOKEN` é usado tanto pelo `nuclei_github.py` quanto pelo `metasploit_github.py`.

---

## 4. Como Usar

A ferramenta é executada via terminal utilizando o módulo `src.main`:

* **Análise de CVEs específicos**:
   ```powershell
   python -m src.main --cves CVE-2024-0001 --cves CVE-2024-0002
   ```

* **Entrada via arquivo JSON**:
   ```powershell
   python -m src.main --file data/sample_cves.json
   ```
   O JSON pode ser uma lista simples (`["CVE-...", ...]`) ou um objeto no formato `{"cves": ["CVE-...", ...]}`.

* **Saída em JSON** (para integração com outras ferramentas):
   ```powershell
   python -m src.main --file data/sample_cves.json --output json
   ```

* **Cache e Sincronização**:
   * `--sync-cache`: força a atualização dos dados direto nas APIs externas, ignorando o cache local.
   * `--sync-frequency [daily|weekly]`: define por quanto tempo um dado em cache é considerado válido antes de expirar (padrão: `weekly`).

Entradas inválidas (fora do padrão `CVE-YYYY-NNNNN`) são ignoradas e registradas como aviso no log.

---

## 5. Dados de Exemplo

O repositório inclui dois conjuntos de CVEs de exemplo em `data/`:
* `sample_cves.json` — amostra menor, útil para testes rápidos.
* `sample_cves_1000.json` — amostra maior, útil para testes de performance e validação em lote.

---

## 6. Cronograma de Desenvolvimento

* **Semanas 1–2**: Implementação dos Clientes de API (NIST, FIRST, CISA, Nuclei, Metasploit, VulnCheck).
* **Semana 3**: Setup do Banco de Dados SQLite e lógica de Cache.
* **Semana 4**: Integração total das métricas.
* **Semana 5**: Implementação do Algoritmo de Scoring.
* **Semana 6**: Interface CLI e Formatadores de Saída.
* **Semana 7**: Validação acadêmica e testes de benchmark.

---
**Autores**: Rodrigo Caio Koelln Alfonsin | João Vitor Andrade Faccin
**Instituição**: UTFPR-MD
**Contato**: alfonsin@alunos.utfpr.edu.br | joaofaccin@alunos.utfpr.edu.br