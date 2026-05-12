import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from src.utils.exceptions import APIUnreachableError
from src.utils.logger import setup_logger

logger = setup_logger()

class APIClient:
    """
    Classe base para comunicação com APIs externas.
    Implementa lógica de retry, timeouts e tratamento de erros padronizado.
    """
    def __init__(self, base_url, timeout=30, max_retries=3):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        
        # Configuração de Retry: aguarda um tempo crescente entre tentativas
        # (Backoff factor) para não sobrecarregar as APIs (NIST/CISA)
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,  # 1s, 2s, 4s...
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def fetch(self, endpoint, params=None):
        """
        Executa uma requisição GET de forma segura.
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = self.session.get(
                url, 
                params=params, 
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"Erro HTTP ao acessar {url}: {e}")
            self.handle_error(e)
        except requests.exceptions.RequestException as e:
            logger.error(f"Erro de conexão ao acessar {url}: {e}")
            raise APIUnreachableError(f"Não foi possível conectar à API: {url}")

    def handle_error(self, exception):
        """
        Tratamento padronizado de erros conforme a arquitetura.
        """
        raise exception