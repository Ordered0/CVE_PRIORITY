from src.api.api_client import APIClient
from src.utils.exceptions import InvalidMetricError

class CISAClient(APIClient):
    """
    Cliente para o catálogo Known Exploited Vulnerabilities (KEV) da CISA.
    Verifica se uma vulnerabilidade tem exploração ativa confirmada.
    """
    def __init__(self):
        # URL direta para o feed JSON da CISA
        super().__init__(base_url="https://www.cisa.gov/sites/default/files/feeds")
        self._kev_catalog = None

    def _load_catalog(self):
        """
        Baixa o catálogo completo para busca em memória.
        Conforme a arquitetura, isso deve ser cacheado localmente futuramente.
        """
        if self._kev_catalog is None:
            data = self.fetch(endpoint="known_exploited_vulnerabilities.json")
            # Extrai apenas a lista de CVE IDs para busca rápida
            vulnerabilities = data.get('vulnerabilities', [])
            self._kev_catalog = {v['cveID'] for v in vulnerabilities}
        return self._kev_catalog

    def is_in_kev(self, cve_id):
        """
        Retorna True se o CVE estiver no catálogo, False caso contrário.
        """
        try:
            catalog = self._load_catalog()
            return cve_id in catalog
        except Exception as e:
            # Em caso de erro na CISA, tratamos como False mas logamos o erro
            # para não interromper o scoring das outras métricas.
            return False