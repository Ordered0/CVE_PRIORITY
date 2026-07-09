# src/api/nuclei_github.py
import os
from src.api.api_client import APIClient
from src.utils.logger import setup_logger

logger = setup_logger()

class NucleiClient(APIClient):
    """
    Cliente para verificar se existe um template de exploração no Nuclei.
    Consulta o repositório oficial projectdiscovery/nuclei-templates via API do GitHub.
    """
    def __init__(self):
        super().__init__(base_url="https://api.github.com")
        
        token = os.getenv("GITHUB_API_TOKEN")
        if token:
            self.session.headers.update({'Authorization': f'token {token}'})
        self.session.headers.update({'Accept': 'application/vnd.github.v3+json'})

    def has_template(self, cve_id):
        try:
            # Busca o código do CVE dentro do repositório do Nuclei
            query = f'{cve_id} repo:projectdiscovery/nuclei-templates'
            data = self.fetch(endpoint="search/code", params={'q': query})
            
            # Se encontrar ao menos 1 arquivo, o template existe
            return data.get('total_count', 0) > 0
        except Exception as e:
            logger.warning(f"Falha ao consultar Nuclei para {cve_id} (Limite da API?): {e}")
            return False