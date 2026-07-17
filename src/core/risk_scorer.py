class RiskScorer:
    """
    Modelo de scoring integrado, fundamentado em Jacobs et al. (2023),
    "Enhancing Vulnerability Prioritization: Data-Driven Exploit
    Predictions with Community-Driven Insights" (arXiv:2302.14172).

    Principais decisões de design derivadas do paper:

    1. EPSS domina, CVSS modula.
       O paper mostra que EPSS v3 tem AUC de 0.7795 na predição de
       exploração real, enquanto o CVSS Base Score sozinho tem AUC de
       apenas 0.051 (Seção 5.1/5.2, Fig. 1). Ou seja, CVSS quase não
       carrega sinal preditivo de exploração -- ele mede severidade
       técnica, não probabilidade de ataque. Por isso o componente base
       não trata EPSS e CVSS como parceiros multiplicativos iguais; usamos
       uma média geométrica ponderada (EPSS_WEIGHT=0.7, CVSS_WEIGHT=0.3),
       de forma que um EPSS alto com CVSS baixo ainda gere um score alto,
       e não seja artificialmente rebaixado.

    2. Default de EPSS ausente é realista, não alarmista.
       O antigo default (0.8) colocava qualquer CVE sem dado de EPSS
       acima do percentil ~99 de risco. O paper mostra que o próprio
       threshold ótimo (F1) do EPSS v3 é 0.36, e que isso já cobre menos
       de 4% de todas as CVEs publicadas (Seção 5.2). Um EPSS "típico"
       está muito mais perto de zero do que de 0.8. Por isso o novo
       default é 0.04 -- próximo da mediana histórica -- e o campo
       `missing_epss=True` continua sinalizado na saída para o usuário
       saber que o valor foi estimado, não medido.

    3. KEV continua como bônus fixo, fora do cap.
       O paper mostra que a lista KEV da CISA, embora cubra só ~0.5% das
       CVEs, tem eficiência de 53.2% (Fig. 3) -- ou seja, é um sinal raro
       porém de altíssima confiança. Por isso o bônus de KEV é somado
       DEPOIS do cap do componente base, sem limite superior: uma CVE
       confirmada em exploração ativa sempre fica à frente de um CRÍTICO
       sem KEV no ranking final.

    4. Bônus por contagem de referências do CVE.
       A análise SHAP do paper (Fig. 7) identifica a contagem de
       referências no CVE List do MITRE como a feature individual de
       maior contribuição para a previsão de exploração -- à frente até
       de "código de exploit publicado". Passamos a somar um pequeno
       bônus (capado em REFERENCE_BONUS_CAP) proporcional a essa
       contagem, normalizado até REFERENCE_NORMALIZATION referências.

    5. Multiplicadores de Nuclei/Ransomware recalibrados.
       No SHAP do paper (Fig. 7), "Scanner: Nuclei" aparece com
       contribuição individual relativamente baixa entre as ~30
       features mais importantes -- por isso reduzimos seu peso
       (1.15 -> 1.08). O paper não modela ransomware diretamente como
       feature do EPSS, mas o tratamos como um sinal operacional forte,
       análogo em espírito ao KEV (evidência concreta de uso malicioso
       confirmado), e mantivemos seu peso relativamente maior (1.10 ->
       1.15).
    """

    NUCLEI_MULTIPLIER = 1.08
    RANSOMWARE_MULTIPLIER = 1.15

    # Bônus somado por fora, sem cap, quando o CVE está no catálogo KEV.
    KEV_BONUS = 0.6

    # Pesos da média geométrica ponderada entre EPSS e CVSS no componente base.
    EPSS_WEIGHT = 0.7
    CVSS_WEIGHT = 0.3

    # Bônus (capado) pela contagem de referências do CVE no MITRE CVE List.
    REFERENCE_BONUS_CAP = 0.05
    REFERENCE_NORMALIZATION = 30  # referências necessárias para atingir o bônus máximo

    # Defaults usados quando os dados reais não estão disponíveis.
    DEFAULT_CVSS = 8.0
    DEFAULT_EPSS = 0.04  # próximo da mediana histórica do EPSS, não um valor alarmista

    @staticmethod
    def calculate_score(cvss_score, epss_probability, in_kev, is_ransomware,
                         has_nuclei, reference_count=0):
        missing_cvss = False
        missing_epss = False

        if not cvss_score or float(cvss_score) == 0.0:
            cvss_score = RiskScorer.DEFAULT_CVSS
            missing_cvss = True

        if not epss_probability or float(epss_probability) == 0.0:
            epss_probability = RiskScorer.DEFAULT_EPSS
            missing_epss = True

        cvss_norm = max(0.0, min(float(cvss_score) / 10.0, 1.0))
        epss_norm = max(0.0, min(float(epss_probability), 1.0))

        # 1. Componente base: média geométrica ponderada (EPSS domina, CVSS
        #    modula), qualificada por Nuclei/Ransomware.
        base_raw = (epss_norm ** RiskScorer.EPSS_WEIGHT) * (cvss_norm ** RiskScorer.CVSS_WEIGHT)
        if has_nuclei:
            base_raw *= RiskScorer.NUCLEI_MULTIPLIER
        if is_ransomware:
            base_raw *= RiskScorer.RANSOMWARE_MULTIPLIER

        # 2. Capa o componente base em 1.0 -- EPSS+CVSS altos já alcançam
        #    CRÍTICO sozinhos, independente do KEV.
        base_norm = min(base_raw, 1.0)

        # 3. Bônus de contagem de referências do CVE (feature de maior
        #    contribuição SHAP no paper). Aplicado antes do bônus de KEV,
        #    mas ainda dentro do cap de 1.0 do componente base.
        reference_bonus = 0.0
        if reference_count and reference_count > 0:
            reference_ratio = min(reference_count / RiskScorer.REFERENCE_NORMALIZATION, 1.0)
            reference_bonus = reference_ratio * RiskScorer.REFERENCE_BONUS_CAP

        base_norm = min(base_norm + reference_bonus, 1.0)

        # 4. KEV soma por fora, DEPOIS do cap do componente base, sem limite
        #    superior -- extrapola de propósito para manter o ranking
        #    coerente entre CVEs que já são CRÍTICOS.
        final_score = base_norm + (RiskScorer.KEV_BONUS if in_kev else 0.0)
        final_score = max(0.0, final_score)  # só garante que não fique negativo

        return {
            "score": round(final_score, 3),
            "missing_cvss": missing_cvss,
            "missing_epss": missing_epss
        }

    @staticmethod
    def categorize_risk(score):
        if score >= 0.80:
            return "CRÍTICO"
        elif score >= 0.60:
            return "ALTO"
        elif score >= 0.30:
            return "MÉDIO"
        else:
            return "BAIXO"