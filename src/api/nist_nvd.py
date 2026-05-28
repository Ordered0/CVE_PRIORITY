import os
from dotenv import load_dotenv
from src.api.api_client import APIClient
from src.utils.exceptions import CVENotFoundError, InvalidMetricError

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

class NISTClient(APIClient):
    """
    Cliente para a API do NIST/NVD.
    Focado em obter a pontuação CVSS v3.x (prioridade) ou v2.0.
    """
    def __init__(self):
        # Endpoint base da API v2.0 do NVD
        super().__init__(base_url="https://services.nvd.nist.gov/rest/json/cves/2.0")
        
        # Busca a chave de API configurada no ambiente
        api_key = os.getenv("NIST_API_KEY")
        
        # Se a chave estiver presente, configura a sessão para enviá-la em todas as requisições
        if api_key:
            self.session.headers.update({'apiKey': api_key})

    def get_cvss_score(self, cve_id):
        """
        Busca o CVSS score para um CVE específico.
        """
        params = {'cveId': cve_id}
        data = self.fetch(endpoint="", params=params)

        # Validação da estrutura de resposta do NVD
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            raise CVENotFoundError(f"CVE {cve_id} não encontrado na base do NIST.")

        cve_data = vulnerabilities[0].get('cve', {})
        metrics = cve_data.get('metrics', {})

        # Tentativa de obter CVSS v3.1 -> v3.0 -> v2.0
        cvss_v31 = metrics.get('cvssMetricV31', [])
        cvss_v30 = metrics.get('cvssMetricV30', [])
        cvss_v2 = metrics.get('cvssMetricV2', [])

        if cvss_v31:
            return cvss_v31[0]['cvssData']['baseScore']
        elif cvss_v30:
            return cvss_v30[0]['cvssData']['baseScore']
        elif cvss_v2:
            return cvss_v2[0]['cvssData']['baseScore']
        
        raise InvalidMetricError(f"Métricas CVSS não disponíveis para o CVE {cve_id}.")