# src/api/metasploit_github.py
import re
from src.api.api_client import APIClient
from src.utils.logger import setup_logger

logger = setup_logger()

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


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

    ANTES: fazia uma chamada `search/code` na API do GitHub por CVE,
    sujeita à cota bem mais restritiva desse endpoint específico (10
    requisições/min autenticado, contra 5000/h dos endpoints "core") --
    esse era o principal gargalo do pipeline, junto com o NucleiClient.

    AGORA: o próprio repositório rapid7/metasploit-framework mantém um
    índice estático com os metadados de TODOS os módulos --
    `db/modules_metadata_base.json`, atualizado automaticamente pelo bot
    `jenkins-metasploit` a cada módulo adicionado ou alterado. Cada
    módulo tem um array `references`, onde os CVEs relacionados aparecem
    quando existem (ex: `"references": ["CVE-2021-44228", "URL-..."]`) --
    isso cobre inclusive os casos em que o CVE só é citado nos metadados
    Ruby do módulo, não no nome do arquivo, então não perdemos precisão
    em relação à busca de conteúdo antiga.

    Baixamos esse arquivo (~11 MB) UMA ÚNICA VEZ por execução via
    raw.githubusercontent.com -- que é só entrega de arquivo estático
    (CDN), não a API do GitHub, então não está sujeito à cota de
    `search/code`. Depois desse único download, has_module() é 100%
    local. Como bônus, isso também elimina a dependência do
    GITHUB_API_TOKEN para esta checagem específica.
    """
    METADATA_ENDPOINT = "db/modules_metadata_base.json"

    def __init__(self):
        super().__init__(
            base_url="https://raw.githubusercontent.com/rapid7/metasploit-framework/master"
        )
        self._cve_modules = None  # set() de CVE IDs (uppercase) com módulo conhecido

    def _load_cve_modules(self):
        """
        Baixa (uma única vez, com cache em memória para a vida do
        processo) o conjunto de CVE IDs cobertos por algum módulo do
        Metasploit, extraindo os CVEs do campo `references` de cada
        módulo no índice oficial.
        """
        if self._cve_modules is not None:
            return self._cve_modules

        cves = set()
        try:
            data = self.fetch(endpoint=self.METADATA_ENDPOINT)
            for module in (data or {}).values():
                for ref in module.get('references', []):
                    match = _CVE_RE.search(ref)
                    if match:
                        cves.add(match.group(0).upper())

            logger.info(
                f"[Metasploit] {len(cves)} CVEs com módulo carregados via modules_metadata_base.json."
            )

        except Exception as e:
            logger.warning(f"Falha ao carregar índice de módulos do Metasploit: {e}")
            # Mantém o cache vazio (não None) para não tentar de novo a
            # cada CVE dentro da mesma execução -- só falha 1x, não N vezes.

        self._cve_modules = cves
        return self._cve_modules

    def has_module(self, cve_id):
        try:
            cves = self._load_cve_modules()
            return cve_id.upper() in cves
        except Exception as e:
            logger.warning(f"Falha ao consultar Metasploit para {cve_id} (Limite da API?): {e}")
            return False