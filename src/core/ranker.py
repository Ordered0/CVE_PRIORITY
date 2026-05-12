class Ranker:
    """
    Responsável por ordenar as vulnerabilidades baseando-se no Risk Score calculado.
    """
    
    @staticmethod
    def rank_vulnerabilities(processed_cves):
        """
        Ordena a lista de dicionários de forma decrescente pelo score.
        Adiciona a chave 'priority_rank'.
        """
        # Ordena a lista (do maior score para o menor)
        sorted_cves = sorted(
            processed_cves, 
            key=lambda x: x.get('risk_score', 0.0), 
            reverse=True
        )
        
        # Atribui o número do ranking (1 é o mais crítico)
        for i, cve in enumerate(sorted_cves, start=1):
            cve['priority_rank'] = i
            
        return sorted_cves