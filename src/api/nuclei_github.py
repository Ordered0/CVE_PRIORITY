# src/api/nuclei_github.py
import json
import re
from src.api.api_client import APIClient
from src.utils.logger import setup_logger

logger = setup_logger()

_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


class NucleiClient(APIClient):
    """
    Cliente para verificar se existe um template de exploração no Nuclei.
    Consulta o repositório oficial projectdiscovery/nuclei-templates.

    ANTES: fazia uma chamada `search/code` na API do GitHub por CVE. Esse
    endpoint tem cota própria e MUITO mais restritiva do que o resto da API
    (10 requisições/min autenticado, contra 5000/h dos endpoints "core")
    -- com centenas de CVEs por execução, esse era o principal gargalo do
    pipeline.

    AGORA: o próprio repositório mantém um índice estático de todos os
    CVEs cobertos por algum template -- `cves.json`, no formato JSON
    Lines (um objeto JSON por linha). Em vez de consultar a API do GitHub
    CVE por CVE, baixamos esse arquivo UMA ÚNICA VEZ por execução via
    raw.githubusercontent.com. Esse domínio é só entrega de arquivo
    estático (CDN), NÃO é a API do GitHub -- não está sujeito à cota de
    `search/code` nem à cota "core" de 60/5000 por hora. Depois desse
    único download, has_template() é 100% local (nenhuma requisição
    extra). Como bônus, isso elimina a dependência do GITHUB_API_TOKEN
    para esta checagem específica.
    """
    CVES_INDEX_ENDPOINT = "cves.json"

    def __init__(self):
        super().__init__(
            base_url="https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
        )
        self._cve_templates = None  # set() de CVE IDs (uppercase) com template conhecido

    def _load_cve_templates(self):
        """
        Baixa (uma única vez, com cache em memória para a vida do processo)
        o conjunto de CVE IDs que possuem template no Nuclei.
        """
        if self._cve_templates is not None:
            return self._cve_templates

        templates = set()
        try:
            response = self.fetch_response(endpoint=self.CVES_INDEX_ENDPOINT)
            raw_text = response.text if response is not None else ""

            # cves.json é JSON Lines (um objeto por linha), não uma lista
            # única -- por isso parseamos linha a linha em vez de usar
            # response.json() (que espera um único documento JSON válido).
            for line in raw_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cve_id = entry.get('ID', '')
                if _CVE_RE.match(cve_id):
                    templates.add(cve_id.upper())

            logger.info(f"[Nuclei] {len(templates)} templates de CVE carregados via cves.json.")

        except Exception as e:
            logger.warning(f"Falha ao carregar índice de templates do Nuclei: {e}")
            # Mantém o cache vazio (não None) para não tentar de novo a
            # cada CVE dentro da mesma execução -- só falha 1x, não N vezes.

        self._cve_templates = templates
        return self._cve_templates

    def has_template(self, cve_id):
        try:
            templates = self._load_cve_templates()
            return cve_id.upper() in templates
        except Exception as e:
            logger.warning(f"Falha ao consultar Nuclei para {cve_id}: {e}")
            return False