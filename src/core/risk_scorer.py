class RiskScorer:
    """
    Implementa o algoritmo de priorização de vulnerabilidades CVE.
    Modelo: Risco Base multiplicativo (CVSS*EPSS) com aceleradores Nuclei e Ransomware,
    e bônus fixo (soma) para presença em KEV.
    """

    # Fatores multiplicadores (Nuclei e Ransomware continuam multiplicando o score base)
    NUCLEI_MULTIPLIER = 1.15
    RANSOMWARE_MULTIPLIER = 1.1

    # KEV deixou de ser multiplicador e agora é uma soma fixa aplicada ao score bruto
    KEV_BONUS = 1.0

    # Score máximo teórico ANTES do bônus de KEV: 1.0 * 1.15 * 1.1 = 1.265
    MAX_BASE_SCORE = 1.0 * NUCLEI_MULTIPLIER * RANSOMWARE_MULTIPLIER
    # Score máximo teórico total, já incluindo o bônus fixo do KEV: 1.265 + 1.0 = 2.265
    MAX_THEORETICAL_SCORE = MAX_BASE_SCORE + KEV_BONUS

    @staticmethod
    def calculate_score(cvss_score, epss_probability, in_kev, is_ransomware, has_nuclei):
        """
        Calcula o risco final baseado nas quatro métricas.
        Nuclei/Ransomware multiplicam o score base; KEV soma um bônus fixo.
        Normaliza o resultado para o intervalo [0.0, 1.0].
        """
        missing_cvss = False
        missing_epss = False

        # 1. Tratamento de dados faltantes (Assume 0.8)
        if not cvss_score or float(cvss_score) == 0.0:
            cvss_score = 8.0
            missing_cvss = True

        if not epss_probability or float(epss_probability) == 0.0:
            epss_probability = 0.8
            missing_epss = True

        # 2. Normalização da Base [0.0 a 1.0]
        cvss_norm = max(0.0, min(float(cvss_score) / 10.0, 1.0))
        epss_norm = max(0.0, min(float(epss_probability), 1.0))

        # 3. Cálculo do Risco Base (Peso 1)
        raw_score = cvss_norm * epss_norm

        if has_nuclei:
            raw_score *= RiskScorer.NUCLEI_MULTIPLIER
        if is_ransomware:
            raw_score *= RiskScorer.RANSOMWARE_MULTIPLIER

        # 4. KEV agora é uma soma direta, não mais multiplicador
        if in_kev:
            raw_score += RiskScorer.KEV_BONUS

        # 5. Normalização final
        final_score = raw_score / RiskScorer.MAX_THEORETICAL_SCORE
        final_score = min(final_score, 1.0)  # guarda de segurança contra arredondamento

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