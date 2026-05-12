from src.api.api_client import APIClient
from src.utils.exceptions import InvalidMetricError

class EPSSClient(APIClient):
    """
    Cliente para a API do FIRST.org (EPSS).
    Retorna a probabilidade de exploração (0.0 a 1.0).
    """
    def __init__(self):
        # Endpoint oficial para dados do EPSS
        super().__init__(base_url="https://api.first.org/data/v1/epss")

    def get_epss_score(self, cve_id):
        """
        Busca a probabilidade EPSS para um CVE.
        Retorna o valor decimal (ex: 0.872 para 87.2%).
        """
        params = {'cve': cve_id}
        data = self.fetch(endpoint="", params=params)

        # A API do FIRST retorna uma lista no campo 'data'
        results = data.get('data', [])
        
        if not results:
            # Caso a API não tenha dados para o CVE, retornamos 0.0 (segurança por padrão)
            return 0.0

        try:
            # O campo 'epss' contém o valor percentual em string
            epss_value = float(results[0].get('epss', 0.0))
            return epss_value
            
        except (ValueError, KeyError, IndexError) as e:
            raise InvalidMetricError(f"Erro ao processar dados EPSS para {cve_id}: {e}")