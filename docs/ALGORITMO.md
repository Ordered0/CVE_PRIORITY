# Algoritmo de Priorização de Vulnerabilidades

Este documento descreve a lógica de scoring implementada em
`src/core/risk_scorer.py` e a fundamentação teórica por trás de cada
decisão de design.

## Fonte principal

As decisões abaixo são fundamentadas em:

> Jacobs, J., Romanosky, S., Suciu, O., Edwards, B., & Sarabi, A. (2023).
> *Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions
> with Community-Driven Insights*. arXiv:2302.14172.

Esse paper descreve o desenvolvimento do EPSS v3 (Exploit Prediction
Scoring System), mantido pelo FIRST.org, e compara seu desempenho preditivo
contra CVSS e versões anteriores do próprio EPSS.

## Pilares de dados usados

| Pilar | Fonte | Papel no score |
|---|---|---|
| CVSS | NIST/NVD (fallback: VulnCheck NVD++) | Severidade técnica (impacto) |
| EPSS | FIRST.org | Probabilidade de exploração em 30 dias |
| KEV | CISA (+ VulnCheck) | Exploração ativa confirmada |
| Ransomware | CISA (campo `knownRansomwareCampaignUse`) | Uso confirmado em ransomware |
| Nuclei | GitHub (projectdiscovery/nuclei-templates) | Existência de template de exploração pronto |
| Contagem de referências | NIST/NVD (+ VulnCheck NVD++) | Sinal de maturidade/atenção da comunidade |

## Por que EPSS domina o componente base, e não CVSS

O paper mostra, na avaliação da Seção 5 (Fig. 1), que ao medir a
capacidade de cada métrica de distinguir vulnerabilidades realmente
exploradas de vulnerabilidades não exploradas:

- **CVSS v3.x base score**: AUC de 0.051 — desempenho próximo do acaso.
- **EPSS v3**: AUC de 0.7795 — desempenho consistentemente forte.

Isso acontece porque o CVSS mede *severidade técnica* (o quão grave seria
o impacto se a falha fosse explorada), enquanto o EPSS é treinado
diretamente sobre evidências reais de exploração em milhões de
observações. O próprio paper resume isso ao citar que o CVSS "tem se
mostrado repetidamente insuficiente para capturar os fatores que
impulsionam exploração no mundo real" (Seção 7).

**Implicação de design:** em vez de `cvss_norm * epss_norm` (que trata os
dois sinais como igualmente importantes, e derruba o score de qualquer CVE
com CVSS baixo mesmo que o EPSS seja altíssimo), usamos uma **média
geométrica ponderada**:

```
base_raw = epss_norm ** 0.7 * cvss_norm ** 0.3
```

Isso garante que EPSS seja o principal motor do score, com CVSS atuando
como modificador de severidade — sem zerar o sinal quando um dos dois é
baixo.

## Por que o default de EPSS ausente é 0.04, não 0.8

Quando a API do FIRST não retorna dado para um CVE, o sistema precisa de
um valor padrão. O valor antigo (0.8) colocava qualquer CVE sem dado
acima do percentil ~99 de risco — um exagero.

O paper mostra que o **threshold ótimo (F1) do EPSS v3 é 0.36**, e que
mesmo esse threshold, considerado "alto" o suficiente para orientar
remediação prioritária, cobre **apenas 3.5% de todas as CVEs publicadas**
(Seção 5.2). Ou seja, a grande maioria das CVEs tem EPSS baixo — a
distribuição é fortemente concentrada perto de zero.

Por isso, o novo default (`DEFAULT_EPSS = 0.04`) está próximo da faixa
típica de EPSS observada na maioria das vulnerabilidades, evitando que a
ausência de dado infle artificialmente o risco. O campo `missing_epss` na
saída continua sinalizando que o valor foi estimado, não medido, para que
o usuário possa tratar esse caso com a devida cautela.

## Por que KEV é um bônus fixo, fora do cap

A Fig. 3 do paper mostra que a lista KEV, isoladamente, cobre apenas
**0.5% de todas as CVEs publicadas**, mas atinge **eficiência de 53.2%**
— ou seja, é um sinal raro, porém extremamente confiável.

Por isso, o bônus de KEV (`KEV_BONUS = 0.6`) é somado **depois** do cap do
componente base em 1.0, sem limite superior. Isso garante que uma CVE
confirmada no catálogo KEV sempre fique à frente de qualquer CVE
"CRÍTICA" que não esteja em KEV, no ranking final — sem criar uma nova
categoria de risco.

## Por que a contagem de referências entra como bônus

A análise SHAP do paper (Fig. 7, Seção 6.3) identifica a **contagem de
referências no CVE List do MITRE** como a *feature individual* de maior
contribuição para a previsão de exploração no modelo EPSS v3 — à frente
inclusive da existência de código de exploit publicado no Exploit-DB.

Vulnerabilidades amplamente documentadas, discutidas e referenciadas
tendem a atrair mais atenção de atacantes. Por isso, adicionamos um
pequeno bônus (capado em `REFERENCE_BONUS_CAP = 0.05`), proporcional à
contagem de referências obtida do NIST/NVD, normalizado até
`REFERENCE_NORMALIZATION = 30` referências.

## Por que os multiplicadores de Nuclei e Ransomware mudaram

- **Nuclei** (`NUCLEI_MULTIPLIER`: 1.15 → 1.08): no ranking de importância
  SHAP do paper (Fig. 7), "Scanner: Nuclei" aparece entre as features
  menos influentes das ~30 listadas — abaixo até de tags textuais como
  "Denial of Service" e "XSS". Reduzimos seu peso para refletir essa
  contribuição relativamente modesta.
- **Ransomware** (`RANSOMWARE_MULTIPLIER`: 1.10 → 1.15): o paper não
  modela ransomware diretamente como feature do EPSS, mas trata-se de um
  sinal operacional de altíssima confiança (evidência concreta de uso
  malicioso confirmado por campanhas reais), análogo em espírito ao KEV.
  Por isso mantivemos seu peso relativamente mais alto que o do Nuclei.

## Resumo da fórmula final

```
base_raw   = epss_norm^0.7 * cvss_norm^0.3
             * (1.08 se has_nuclei)
             * (1.15 se is_ransomware)

base_norm  = min(base_raw, 1.0)
           + bônus de referências (até +0.05)
           = min(base_norm, 1.0)

score_final = base_norm + (0.6 se in_kev)   # sem cap superior
```

## Categorias de risco (inalteradas)

| Score | Categoria |
|---|---|
| ≥ 0.80 | CRÍTICO |
| ≥ 0.60 | ALTO |
| ≥ 0.30 | MÉDIO |
| < 0.30 | BAIXO |

## Limitações conhecidas (herdadas do próprio EPSS)

O paper (Seção 6.2) documenta limitações relevantes que também se aplicam
indiretamente a esta ferramenta:

- Dados de exploração dependem de sensores baseados em assinatura,
  enviesados para ataques de rede — dispositivos IoT, ICS/SCADA e ataques
  que exigem proximidade física tendem a ser sub-representados.
- O EPSS não distingue exploração por pesquisadores/testes legítimos de
  exploração maliciosa real.
- Scores podem, em teoria, ser manipulados adversarialmente (ex.: CVEs
  "sujando" menções em redes sociais), embora não haja evidência prática
  disso até a publicação do paper.

Essas limitações devem ser levadas em conta ao interpretar o `risk_score`
final como uma estimativa, não uma verdade absoluta.