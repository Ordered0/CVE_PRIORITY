class RiskScorer:
    """
    Implementa o algoritmo de priorização de vulnerabilidades CVE.
    Integra CVSS, EPSS, KEV e dados de Ransomware em um único Score de Risco.
    """
    
    # Pesos definidos na arquitetura
    WEIGHT_BASE = 0.70        # CVSS + EPSS
    WEIGHT_KEV = 0.20         # Catálogo CISA KEV
    WEIGHT_RANSOMWARE = 0.10  # Uso confirmado em Ransomware

    @staticmethod
    def calculate_score(cvss_score, epss_probability, in_kev, is_ransomware):
        """
        Calcula o risco final baseado nas quatro métricas.
        
        :param cvss_score: Severidade do NIST (0.0 a 10.0)
        :param epss_probability: Probabilidade do FIRST (0.0 a 1.0)
        :param in_kev: Booleano (True se estiver no KEV)
        :param is_ransomware: Booleano (True se associado a Ransomware)
        :return: Float representando o Risco Final (0.0 a 1.0)
        """
        # 1. Normalização dos dados
        # O CVSS vem de 0 a 10. Normalizamos para 0.0 a 1.0
        cvss_norm = max(0.0, min(float(cvss_score) / 10.0, 1.0))
        
        # O EPSS da API do FIRST já vem como probabilidade (0.0 a 1.0)
        epss_norm = max(0.0, min(float(epss_probability), 1.0))
        
        # Bônus Booleanos (1.0 se True, 0.0 se False)
        kev_bonus = 1.0 if in_kev else 0.0
        ransomware_bonus = 1.0 if is_ransomware else 0.0

        # 2. Cálculo do Risco Integrado
        # Fórmula: ((CVSS_norm * EPSS_norm) * 0.70) + (KEV * 0.20) + (Ransomware * 0.10)
        base_score = (cvss_norm * epss_norm) * RiskScorer.WEIGHT_BASE
        kev_score = kev_bonus * RiskScorer.WEIGHT_KEV
        ransomware_score = ransomware_bonus * RiskScorer.WEIGHT_RANSOMWARE

        # Soma e garante que o teto seja 1.0 (ou 100%)
        final_score = base_score + kev_score + ransomware_score
        
        # Arredonda para 3 casas decimais para facilitar a leitura
        return round(min(final_score, 1.0), 3)

    @staticmethod
    def categorize_risk(score):
        """
        (Opcional) Categoriza o score para exibição no terminal.
        """
        if score >= 0.80:
            return "CRÍTICO"
        elif score >= 0.60:
            return "ALTO"
        elif score >= 0.30:
            return "MÉDIO"
        else:
            return "BAIXO"