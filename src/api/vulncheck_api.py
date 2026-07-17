import os
from src.api.api_client import APIClient
from src.utils.logger import setup_logger

logger = setup_logger()

class VulnCheckClient(APIClient):
    """
    Cliente para a API Community (gratuita) da VulnCheck.
    Usa apenas os endpoints disponíveis no tier Community:
      - v3/index/vulncheck-kev  -> KEV estendido da VulnCheck (fonte adicional de KEV)
      - v3/index/nist-nvd2      -> NVD++ (fallback de CVSS/CWE quando o NIST NVD falhar)
    Requer a variável de ambiente VULNCHECK_API_KEY. Se não estiver setada,
    o cliente fica inativo e todos os métodos retornam valores "vazios",
    sem quebrar o restante do pipeline.
    """

    BASE_URL = "https://api.vulncheck.com/v3"

    def __init__(self, api_key=None, timeout=30, max_retries=3):
        super().__init__(self.BASE_URL, timeout=timeout, max_retries=max_retries)
        self.api_key = api_key or os.getenv("VULNCHECK_API_KEY")

        if not self.api_key:
            logger.warning(
                "VULNCHECK_API_KEY não configurada. Cliente VulnCheck ficará inativo "
                "(sem união de KEV e sem fallback de CVSS/CWE via NVD++)."
            )
        else:
            self.session.headers.update({
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json"
            })

    @property
    def enabled(self):
        """Indica se a chave de API foi configurada."""
        return bool(self.api_key)

    def is_in_kev(self, cve_id):
        """
        Consulta o índice 'vulncheck-kev' (Community).
        Retorna True se o CVE estiver catalogado como exploração conhecida pela VulnCheck.
        """
        if not self.enabled:
            return False

        try:
            data = self.fetch("index/vulncheck-kev", params={"cve": cve_id})
            results = (data or {}).get("data", [])
            return len(results) > 0
        except Exception as e:
            logger.warning(f"VulnCheck KEV indisponível para {cve_id}: {e}")
            return False

    def get_cvss_cwe(self, cve_id):
        """
        Fallback de CVSS/CWE via NVD++. Também extrai a contagem de
        referências do CVE, usada como sinal adicional pelo RiskScorer.
        """
        if not self.enabled:
            return None
        try:
            data = self.fetch("index/nist-nvd2", params={"cve": cve_id})
            results = (data or {}).get("data", [])
            if not results:
                return None
            entry = results[0]

            score = 0.0
            metrics = entry.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key)
                if metric_list:
                    score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                    break

            cwe_id = "N/A"
            weaknesses = entry.get("weaknesses", [])
            if weaknesses:
                descriptions = weaknesses[0].get("description", [])
                if descriptions:
                    cwe_id = descriptions[0].get("value", "N/A")

            reference_count = len(entry.get("references", []))

            return {"score": score, "cwe": cwe_id, "reference_count": reference_count}
        except Exception as e:
            logger.warning(f"VulnCheck NVD++ indisponível ou malformado para {cve_id}: {e}")
            return None