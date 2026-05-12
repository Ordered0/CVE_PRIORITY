import json
import os
from src.utils.validators import is_valid_cve
from src.utils.logger import setup_logger

logger = setup_logger()

class InputHandler:
    """
    Lida com as entradas do usuário, padroniza e valida os CVE IDs.
    """
    @staticmethod
    def parse_inputs(cves_args, file_path):
        """
        Combina os CVEs passados por argumento e por arquivo.
        """
        cve_list = []

        # 1. Processa argumentos de linha de comando
        if cves_args:
            cve_list.extend(list(cves_args))

        # 2. Processa entrada de arquivo JSON
        if file_path:
            if not os.path.exists(file_path):
                logger.error(f"Arquivo não encontrado: {file_path}")
            else:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # Assume que o JSON pode ser uma lista direta ["CVE-1", "CVE-2"]
                        # ou um objeto {"cves": ["CVE-1", "CVE-2"]}
                        if isinstance(data, list):
                            cve_list.extend(data)
                        elif isinstance(data, dict) and 'cves' in data:
                            cve_list.extend(data['cves'])
                except json.JSONDecodeError:
                    logger.error("O arquivo fornecido não é um JSON válido.")

        # 3. Limpeza, padronização (maiúsculas) e remoção de duplicatas
        sanitized_list = [cve.strip().upper() for cve in cve_list if isinstance(cve, str)]
        unique_cves = list(dict.fromkeys(sanitized_list))

        # 4. Validação rigorosa
        valid_cves = []
        for cve in unique_cves:
            if is_valid_cve(cve):
                valid_cves.append(cve)
            else:
                logger.warning(f"Entrada ignorada: '{cve}' não é um formato CVE válido.")

        return valid_cves