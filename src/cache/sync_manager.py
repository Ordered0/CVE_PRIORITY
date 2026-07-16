from datetime import datetime, timedelta, timezone
from src.api.nist_nvd import NISTClient
from src.api.first_epss import EPSSClient
from src.api.cisa_kev import CISAClient
from src.api.ransomware_api import RansomwareClient
from src.api.nuclei_github import NucleiClient
from src.api.vulncheck_api import VulnCheckClient
from src.utils.logger import setup_logger

logger = setup_logger()

class SyncManager:
    """
    Gerencia a sincronização entre APIs externas e o cache local.
    """
    def __init__(self, db_manager, frequency="weekly"):
        self.db = db_manager
        self.frequency = frequency

        # Inicializa todos os clientes de API
        self.nist = NISTClient()
        self.epss = EPSSClient()
        self.cisa = CISAClient()
        self.ransomware = RansomwareClient()
        self.nuclei = NucleiClient()
        self.vulncheck = VulnCheckClient()  # inativo automaticamente se não houver API key

    def _get_expiration_delta(self):
        """Define o tempo de validade do cache."""
        if self.frequency == "daily":
            return timedelta(days=1)
        return timedelta(days=7)  # Padrão semanal

    def get_cve_data(self, cve_id, force_sync=False):
        """
        Retorna os dados do CVE. Prioriza o cache se estiver válido.
        Retorna uma tupla: (dados, veio_do_cache: bool)
        """
        cached_data = self.db.get_cve(cve_id)
        now = datetime.now(timezone.utc)

        needs_update = True
        if cached_data and not force_sync:
            try:
                next_update = datetime.fromisoformat(cached_data['next_update'])
                if now < next_update:
                    needs_update = False
            except ValueError:
                pass

        if not needs_update:
            logger.info(f"[{cve_id}] Lendo do cache local (Válido até {cached_data['next_update'][:10]}).")
            return cached_data, True

        logger.info(f"[{cve_id}] Buscando dados atualizados nas APIs externas...")
        return self._fetch_and_save(cve_id, cached_data), False

    def _fetch_and_save(self, cve_id, cached_data=None):
        """
        Busca dados nas APIs. Implementa fallback utilizando
        o dado antigo do cache em caso de falha na rede.
        """
        now = datetime.now(timezone.utc)
        next_update = now + self._get_expiration_delta()

        # 1. CVSS e CWE (NIST, com fallback para VulnCheck NVD++ e depois cache)
        cvss_score = 0.0
        cwe_id = "N/A"
        try:
            nist_data = self.nist.get_cvss_data(cve_id)
            cvss_score = nist_data['score']
            cwe_id = nist_data['cwe']
        except Exception as e:
            logger.warning(f"Falha ao buscar CVSS/CWE (NIST) para {cve_id}: {e}. Tentando VulnCheck NVD++.")
            vc_data = self.vulncheck.get_cvss_cwe(cve_id)
            if vc_data:
                cvss_score = vc_data['score']
                cwe_id = vc_data['cwe']
                logger.info(f"[{cve_id}] CVSS/CWE obtidos via VulnCheck NVD++ (fallback).")
            elif cached_data:
                cvss_score = cached_data.get('cvss_score', 0.0)
                cwe_id = cached_data.get('cwe_id', "N/A")

        # 2. EPSS (FIRST)
        epss_percentile = 0.0
        try:
            epss_percentile = self.epss.get_epss_score(cve_id)
        except Exception as e:
            logger.warning(f"Falha ao buscar EPSS para {cve_id}: {e}. Tentando fallback.")
            if cached_data:
                epss_percentile = cached_data.get('epss_percentile', 0.0)

        # 3. KEV (união CISA + VulnCheck), Ransomware e Nuclei
        try:
            in_kev_cisa = self.cisa.is_in_kev(cve_id)
            in_kev_vulncheck = self.vulncheck.is_in_kev(cve_id)
            in_kev = in_kev_cisa or in_kev_vulncheck

            is_ransomware = self.ransomware.is_used_in_ransomware(cve_id)
            has_nuclei = self.nuclei.has_template(cve_id)
        except Exception as e:
            logger.warning(f"Falha ao consultar KEV/Ransomware/Nuclei para {cve_id}: {e}")
            if cached_data:
                in_kev = cached_data.get('kev_status', False)
                is_ransomware = cached_data.get('ransomware_used', False)
                has_nuclei = cached_data.get('has_nuclei', False)
            else:
                in_kev, is_ransomware, has_nuclei = False, False, False

        # Prepara objeto para salvar no SQLite
        cve_new_data = {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'cwe_id': cwe_id,
            'epss_percentile': epss_percentile,
            'kev_status': in_kev,
            'ransomware_used': is_ransomware,
            'has_nuclei': has_nuclei,
            'last_updated': now.isoformat(),
            'next_update': next_update.isoformat()
        }

        self.db.save_cve(cve_new_data)
        return cve_new_data