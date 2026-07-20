# src/api/metasploit_github.py
import os
from src.api.api_client import APIClient
from src.utils.logger import setup_logger

logger = setup_logger()

class MetasploitClient(APIClient):
    """
    Cliente para verificar se existe um módulo de exploração no Metasploit
    Framework para um CVE específico.

    Segundo Jacobs et al. (2023, arXiv:2302.14172), a existência de um
    módulo Metasploit é, isoladamente, uma das features mais relevantes do
    modelo EPSS v3 (SHAP, Fig. 7) -- com ranking de importância individual
    maior do que a existência de template no Nuclei ("Scanner: Nuclei").
    Além disso, como heurística de remediação isolada (Fig. 3), o paper
    mostra que "Exploit:metasploit" atinge 60.5% de eficiência, superando
    até a lista KEV da CISA (53.2%), com quase 3x mais cobertura (14.9%
    vs 5.9%) para um nível de esforço muito próximo. O próprio paper
    conclui: "based on this simple heuristic (KEV vs Metasploit), the
    Metasploit strategy outperforms the KEV strategy" (Seção 5.4).

    Não existe uma API pública gratuita e oficial do Metasploit Pro para
    essa checagem, então -- na mesma linha do NucleiClient -- usamos a
    busca de código do GitHub apenas como mecanismo técnico de
    implementação (fallback de acesso), consultando diretamente o
    repositório oficial rapid7/metasploit-framework. O critério de risco
    em si é "existe módulo Metasploit para este CVE?", não "existe no
    GitHub?" -- o GitHub é só onde o código-fonte do Metasploit está
    hospedado publicamente.
    """
    def __init__(self):
        super().__init__(base_url="https://api.github.com")

        token = os.getenv("GITHUB_API_TOKEN")
        if token:
            self.session.headers.update({'Authorization': f'token {token}'})
        self.session.headers.update({'Accept': 'application/vnd.github.v3+json'})

    def has_module(self, cve_id):
        try:
            # Busca o código do CVE dentro do repositório oficial do Metasploit Framework
            query = f'{cve_id} repo:rapid7/metasploit-framework'
            data = self.fetch(endpoint="search/code", params={'q': query})

            # Se encontrar ao menos 1 arquivo, o módulo existe
            return data.get('total_count', 0) > 0
        except Exception as e:
            logger.warning(f"Falha ao consultar Metasploit para {cve_id} (Limite da API?): {e}")
            return False