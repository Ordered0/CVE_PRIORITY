from datetime import datetime, timedelta, timezone
from src.api.nist_nvd import NISTClient
from src.api.first_epss import EPSSClient
from src.api.cisa_kev import CISAClient
from src.api.ransomware_api import RansomwareClient
from src.utils.logger import setup_logger
from src.utils.exceptions import APIUnreachableError

logger = setup_logger()

class SyncManager:
    """
    Gerencia a sincronização entre APIs externas e o cache local.
    """
    def __init__(self, db_manager, frequency="weekly"):
        self.db = db_manager
        self.frequency = frequency
        
        # Inicializa os clientes de API uma única vez.
        # Isso garante que a CISA e Ransomware façam apenas UM download por execução.
        self.nist = NISTClient()
        self.epss = EPSSClient()
        self.cisa = CISAClient()
        self.ransomware = RansomwareClient()

    def _get_expiration_delta(self):
        """Define o tempo de validade do cache com base na configuração."""
        if self.frequency == "daily":
            return timedelta(days=1)
        return timedelta(days=7) # Padrão semanal

    def get_cve_data(self, cve_id, force_sync=False):
        """
        Retorna os dados do CVE. Prioriza o cache se estiver válido.
        """
        cached_data = self.db.get_cve(cve_id)
        now = datetime.now(timezone.utc)

        # Verifica se o cache é válido
        needs_update = True
        if cached_data and not force_sync:
            try:
                next_update = datetime.fromisoformat(cached_data['next_update'])
                if now < next_update:
                    needs_update = False
            except ValueError:
                # Se houver erro no parse da data, força atualização
                pass

        if not needs_update:
            logger.info(f"[{cve_id}] Lendo do cache local (Válido até {cached_data['next_update'][:10]}).")
            return cached_data

        logger.info(f"[{cve_id}] Buscando dados atualizados nas APIs externas...")
        return self._fetch_and_save(cve_id, cached_data)

    def _fetch_and_save(self, cve_id, cached_data=None):
        """
        Busca dados nas 4 APIs. Se uma API falhar, implementa o Fallback 
        utilizando o dado antigo do cache (Lenient Mode).
        """
        now = datetime.now(timezone.utc)
        next_update = now + self._get_expiration_delta()

        # 1. CVSS (NIST)
        cvss_score = 0.0
        try:
            cvss_score = self.nist.get_cvss_score(cve_id)
        except Exception as e:
            logger.warning(f"Falha ao buscar CVSS para {cve_id}: {e}. Tentando fallback.")
            if cached_data:
                cvss_score = cached_data['cvss_score']

        # 2. EPSS (FIRST)
        epss_percentile = 0.0
        try:
            epss_percentile = self.epss.get_epss_score(cve_id)
        except Exception as e:
            logger.warning(f"Falha ao buscar EPSS para {cve_id}: {e}. Tentando fallback.")
            if cached_data:
                epss_percentile = cached_data['epss_percentile']

        # 3. KEV e Ransomware (Consulta em memória, O(1))
        try:
            in_kev = self.cisa.is_in_kev(cve_id)
            is_ransomware = self.ransomware.is_used_in_ransomware(cve_id)
        except Exception as e:
            logger.warning(f"Falha ao consultar KEV/Ransomware para {cve_id}: {e}")
            if cached_data:
                in_kev = cached_data['kev_status']
                is_ransomware = cached_data['ransomware_used']
            else:
                in_kev, is_ransomware = False, False

        # Prepara objeto para salvar
        cve_new_data = {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'epss_percentile': epss_percentile,
            'kev_status': in_kev,
            'ransomware_used': is_ransomware,
            'last_updated': now.isoformat(),
            'next_update': next_update.isoformat()
        }

        # Salva no SQLite e retorna
        self.db.save_cve(cve_new_data)
        return cve_new_data