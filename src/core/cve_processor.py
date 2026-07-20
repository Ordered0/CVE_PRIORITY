import time
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
        self.db_manager = DatabaseManager()
        self.sync_manager = SyncManager(self.db_manager, frequency=frequency)
        self.scorer = RiskScorer()

    def run(self, cve_list):
        processed_results = []
        unique_cves = list(dict.fromkeys(cve_list))

        for cve_id in unique_cves:
            logger.info(f"Processando métricas para {cve_id}...")
            
            # 1. Busca os dados (Decide automaticamente entre SQLite ou APIs)
            data, from_cache = self.sync_manager.get_cve_data(cve_id, force_sync=self.sync_cache)
            
            # 2. Calcula o Score Integrado repassando has_nuclei e a contagem
            #    de referências do CVE (sinal adicional; ver risk_scorer.py)
            score_data = self.scorer.calculate_score(
                cvss_score=data['cvss_score'],
                epss_probability=data['epss_percentile'],
                in_kev=data['kev_status'],
                is_ransomware=data['ransomware_used'],
                has_nuclei=data['has_nuclei'],
                has_metasploit=data.get('has_metasploit', False),
                reference_count=data.get('reference_count', 0)
            )
            
            # 3. Formata o dicionário de resultado contemplando CWE, Nuclei
            #    e a contagem de referências usada no score
            result = {
                "cve_id": data['cve_id'],
                "cwe_id": data['cwe_id'],
                "cvss": data['cvss_score'],
                "epss_percent": round(data['epss_percentile'] * 100, 2), 
                "in_kev": data['kev_status'],
                "has_nuclei": data['has_nuclei'],
                "has_metasploit": data.get('has_metasploit', False),
                "ransomware_used": data['ransomware_used'],
                "reference_count": data.get('reference_count', 0),
                "risk_score": score_data['score'],
                "risk_category": self.scorer.categorize_risk(score_data['score']),
                "missing_cvss": score_data['missing_cvss'],
                "missing_epss": score_data['missing_epss']
            }
            processed_results.append(result)

            # Só aplica o delay se realmente bateu nas APIs externas
            if not from_cache:
                time.sleep(2.14)

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