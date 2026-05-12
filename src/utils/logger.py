import logging
import os
from datetime import datetime

def setup_logger():
    """Configura o sistema de logs para terminal e arquivo."""
    logger = logging.getLogger("PriorityTool")
    
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Garante que a pasta de logs existe
        log_dir = "data/logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Formato da mensagem
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Handler para Arquivo
        file_handler = logging.FileHandler(
            f"{log_dir}/execution_{datetime.now().strftime('%Y%m%d')}.log"
        )
        file_handler.setFormatter(formatter)
        
        # Handler para Terminal
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
    return logger