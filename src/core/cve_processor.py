from src.cache.database import DatabaseManager
from src.cache.sync_manager import SyncManager
from src.core.risk_scorer import RiskScorer
from src.core.ranker import Ranker
from src.utils.logger import setup_logger

logger = setup_logger()

class CVEProcessor:
    """
    Orquestrador principal. Recebe a lista de CVEs, busca métricas,
    calcula os scores e retorna o ranking final.
    """
    def __init__(self, sync_cache=False, frequency="weekly"):
        self.sync_cache = sync_cache
        
        # Inicializa a infraestrutura de dados
        self.db_manager = DatabaseManager()
        self.sync_manager = SyncManager(self.db_manager, frequency=frequency)
        self.scorer = RiskScorer()

    def run(self, cve_list):
        """
        Executa o fluxo completo (Pipeline) para uma lista de CVEs.
        """
        processed_results = []
        
        # Remove duplicatas da entrada mantendo a ordem (opcional, mas boa prática)
        unique_cves = list(dict.fromkeys(cve_list))

        for cve_id in unique_cves:
            # Futuro: Adicionar regex aqui para validar formato do CVE_ID (utils/validators.py)
            logger.info(f"Processando métricas para {cve_id}...")
            
            # 1. Busca os dados (Decide automaticamente entre SQLite ou APIs)
            data = self.sync_manager.get_cve_data(cve_id, force_sync=self.sync_cache)
            
            # 2. Calcula o Score Integrado
            score = self.scorer.calculate_score(
                cvss_score=data['cvss_score'],
                epss_probability=data['epss_percentile'],
                in_kev=data['kev_status'],
                is_ransomware=data['ransomware_used']
            )
            
            # 3. Formata o dicionário de resultado para este CVE
            result = {
                "cve_id": data['cve_id'],
                "cvss": data['cvss_score'],
                # Converte o EPSS (0.0 a 1.0) para formato visual (0% a 100%)
                "epss_percent": round(data['epss_percentile'] * 100, 2), 
                "in_kev": data['kev_status'],
                "ransomware_used": data['ransomware_used'],
                "risk_score": score,
                "risk_category": self.scorer.categorize_risk(score)
            }
            processed_results.append(result)
        
        # 4. Ordena e Rankeia
        logger.info("Gerando ranking final...")
        final_ranking = Ranker.rank_vulnerabilities(processed_results)
        
        return {
            "execution_metadata": {
                "total_processed": len(unique_cves),
                "sync_forced": self.sync_cache
            },
            "vulnerabilities": final_ranking
        }