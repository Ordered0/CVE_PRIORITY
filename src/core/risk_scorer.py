class RiskScorer:
    """
    Modelo: componente base (CVSS x EPSS, qualificado por Nuclei/Ransomware)
    é capado em 1.0 de forma independente -- ou seja, CVSS+EPSS altos sozinhos
    já conseguem alcançar CRÍTICO, sem depender do KEV.

    O bônus de KEV é somado DEPOIS desse cap, e NÃO é capado -- um CVE em
    KEV pode ultrapassar 1.0, o que não cria uma categoria nova (ainda é
    CRÍTICO), mas garante que ele fique sempre à frente de um CRÍTICO sem
    KEV no ranking final.
    """

    NUCLEI_MULTIPLIER = 1.15
    RANSOMWARE_MULTIPLIER = 1.1

    # Bônus somado por fora, sem cap, quando o CVE está no catálogo KEV.
    KEV_BONUS = 0.6

    @staticmethod
    def calculate_score(cvss_score, epss_probability, in_kev, is_ransomware, has_nuclei):
        missing_cvss = False
        missing_epss = False

        if not cvss_score or float(cvss_score) == 0.0:
            cvss_score = 8.0
            missing_cvss = True

        if not epss_probability or float(epss_probability) == 0.0:
            epss_probability = 0.8
            missing_epss = True

        cvss_norm = max(0.0, min(float(cvss_score) / 10.0, 1.0))
        epss_norm = max(0.0, min(float(epss_probability), 1.0))

        # 1. Componente base: severidade x probabilidade de exploração,
        #    qualificado por Nuclei/Ransomware
        base_raw = cvss_norm * epss_norm
        if has_nuclei:
            base_raw *= RiskScorer.NUCLEI_MULTIPLIER
        if is_ransomware:
            base_raw *= RiskScorer.RANSOMWARE_MULTIPLIER

        # 2. Capa o componente base em 1.0 -- CVSS+EPSS altos já alcançam
        #    CRÍTICO sozinhos, independente do KEV
        base_norm = min(base_raw, 1.0)

        # 3. KEV soma por fora, DEPOIS do cap do componente base, sem limite
        #    superior -- extrapola de propósito para manter o ranking
        #    coerente entre CVEs que já são CRÍTICOS
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