# Algoritmo de Priorização de Vulnerabilidades CVE

Este projeto desenvolve uma ferramenta de linha de comando (CLI) em Python para automatizar a priorização de correções de segurança. O objetivo é superar a ineficiência de focar apenas na severidade técnica (CVSS), integrando métricas de probabilidade real e evidência de exploração ativa.

## 1. Fundamentação Teórica

A ferramenta utiliza um algoritmo de risco integrado baseado em quatro pilares fundamentais:

* **CVSS (Common Vulnerability Scoring System)**: Avalia a severidade técnica da falha (0.0 a 10.0).
* **EPSS (Exploit Prediction Scoring System)**: Estima a probabilidade de exploração nos próximos 30 dias (0% a 100%).
* **KEV (Known Exploited Vulnerabilities)**: Catálogo da CISA com vulnerabilidades que possuem exploração ativa confirmada.
* **Ransomware Check**: Verifica se a vulnerabilidade é sabidamente utilizada em ataques de ransomware.

### O Algoritmo de Scoring
O cálculo do risco final segue a ponderação definida na arquitetura do sistema:
- **70%**: Impacto combinado de CVSS e EPSS.
- **20%**: Presença no catálogo KEV (CISA).
- **10%**: Associação com Ransomware.

---

## 2. Estrutura do Sistema

A aplicação é dividida em 5 camadas principais para garantir modularidade:

1.  **Interface CLI**: Entrada de dados (IDs CVE ou arquivos JSON) e flags de configuração.
2.  **Engine de Processamento**: Lógica de validação, cálculo de score e ordenação.
3.  **Coletor de Métricas**: Módulos específicos para buscar dados no NIST (NVD), FIRST e CISA.
4.  **Gerenciador de Cache**: Persistência local em SQLite para otimizar o desempenho e respeitar limites de taxa das APIs.
5.  **Clientes de APIs**: Camada de abstração para comunicação via HTTP com bases externas.

---

## 3. Configuração do Ambiente


### Instalação Passo a Passo

1.  **Ativar o Ambiente Virtual (venv)**:
    No terminal (PowerShell), dentro da pasta raiz:
    ```powershell
    python -m venv venv
    ```
    ```powershell
    .\venv\Scripts\Activate.ps1
    ```

2.  **Instalar Dependências**:
    Para evitar erros de compilação com o Pandas em versões recentes do Python, instale os utilitários de construção antes:
    ```powershell
    python.exe -m pip install --upgrade pip
    pip install setuptools wheel
    pip install -r requirements.txt
    ```

---

## 4. Como Usar

A ferramenta é executada via terminal utilizando o módulo `src.main`:

* **Análise de CVEs específicos**:
    ```powershell
    python -m src.main --cves CVE-2024-0001 CVE-2024-0002
    ```

* **Entrada via arquivo JSON**:
    ```powershell
    python -m src.main --file data/sample_cves.json
    ```

* **Sincronização e Saída**:
    Use `--sync-cache` para forçar a atualização dos dados e `--output json` se desejar exportar os resultados para integração com outros sistemas.

---

## 5. Cronograma de Desenvolvimento

* **Semanas 1-2**: Implementação dos Clientes de API (NIST, FIRST, CISA).
* **Semana 3**: Setup do Banco de Dados SQLite e lógica de Cache.
* **Semana 4**: Integração total das métricas.
* **Semana 5**: Implementação do Algoritmo de Scoring.
* **Semana 6**: Interface CLI e Formatadores de Saída.
* **Semana 7**: Validação acadêmica e testes de benchmark.

---
**Autores**: Rodrigo Caio Koelln Alfonsin  |  João Vitor Andrade Faccin
**Instituição**: UTFPR-MD  
**Contato**: alfonsin@alunos.utfpr.edu.br  |  joaofaccin@alunos.utfpr.edu.br 
