from src.api.api_client import APIClient
from src.utils.logger import setup_logger

logger = setup_logger()

class RansomwareClient(APIClient):
    """
    Cliente para verificar associação de CVEs com ataques de Ransomware.
    Utiliza o feed da CISA (campo específico) ou bases de inteligência externa.
    """
    def __init__(self):
        # Base inicial: CISA KEV (que contém metadados de ransomware)
        super().__init__(base_url="https://www.cisa.gov/sites/default/files/feeds")
        self._ransomware_cves = None

    def _load_data(self):
        """
        Carrega a lista de CVEs associados a ransomware.
        """
        if self._ransomware_cves is None:
            try:
                data = self.fetch(endpoint="known_exploited_vulnerabilities.json")
                vulnerabilities = data.get('vulnerabilities', [])
                
                # Filtra CVEs onde o campo 'knownRansomwareCampaignUse' é 'Known'
                self._ransomware_cves = {
                    v['cveID'] for v in vulnerabilities 
                    if v.get('knownRansomwareCampaignUse') == 'Known'
                }
            except Exception as e:
                logger.error(f"Erro ao carregar dados de Ransomware: {e}")
                self._ransomware_cves = set()
        return self._ransomware_cves

    def is_used_in_ransomware(self, cve_id):
        """
        Retorna True se o CVE for confirmado em ataques de ransomware.
        """
        data = self._load_data()
        return cve_id in data