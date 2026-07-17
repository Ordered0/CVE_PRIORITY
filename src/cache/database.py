# src/cache/database.py

import sqlite3
import os
from contextlib import contextmanager
from src.cache.schema import SCHEMA_QUERIES, MIGRATION_QUERIES
from src.utils.logger import setup_logger
from src.utils.exceptions import CacheError

logger = setup_logger()

class DatabaseManager:
    """
    Gerenciador de conexões e operações com o banco SQLite local.
    """
    def __init__(self, db_path="data/cache.db"):
        self.db_path = db_path
        self._ensure_db_directory()
        self.init_db()

    def _ensure_db_directory(self):
        """Garante que a pasta data/ exista antes de criar o banco."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    @contextmanager
    def get_connection(self):
        """Context manager para gerenciar conexões de forma segura."""
        conn = sqlite3.connect(self.db_path)
        # Permite acessar os resultados como dicionários (pelo nome da coluna)
        conn.row_factory = sqlite3.Row 
        try:
            yield conn
        except sqlite3.Error as e:
            logger.error(f"Erro no banco de dados SQLite: {e}")
            conn.rollback()
            raise CacheError(f"Falha na operação de cache: {e}")
        finally:
            conn.close()

    def init_db(self):
        """Cria as tabelas se não existirem e aplica migrações leves."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for query in SCHEMA_QUERIES:
                cursor.execute(query)

            # Aplica migrações de colunas novas em bancos já existentes.
            # ALTER TABLE ADD COLUMN falha com "duplicate column" se a
            # coluna já existir -- isso é esperado e ignorado.
            for migration in MIGRATION_QUERIES:
                try:
                    cursor.execute(migration)
                except sqlite3.OperationalError as e:
                    if "duplicate column" not in str(e).lower():
                        raise

            conn.commit()

    def get_cve(self, cve_id):
        """Busca um CVE no cache."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def save_cve(self, cve_data):
        query = """
        INSERT INTO vulnerabilities (
            cve_id, cvss_score, cwe_id, epss_percentile, kev_status, 
            ransomware_used, has_nuclei, reference_count, last_updated, next_update
        ) VALUES (
            :cve_id, :cvss_score, :cwe_id, :epss_percentile, :kev_status, 
            :ransomware_used, :has_nuclei, :reference_count, :last_updated, :next_update
        )
        ON CONFLICT(cve_id) DO UPDATE SET
            cvss_score=excluded.cvss_score,
            cwe_id=excluded.cwe_id,
            epss_percentile=excluded.epss_percentile,
            kev_status=excluded.kev_status,
            ransomware_used=excluded.ransomware_used,
            has_nuclei=excluded.has_nuclei,
            reference_count=excluded.reference_count,
            last_updated=excluded.last_updated,
            next_update=excluded.next_update
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, cve_data)
            conn.commit()
            
    def get_metadata(self, metric_name):
        """Busca metadados de sincronização (ex: 'cisa_catalog')."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cache_metadata WHERE metric_name = ?", (metric_name,))
            row = cursor.fetchone()
            return dict(row) if row else None
            
    def update_metadata(self, metric_name, last_sync, next_scheduled_sync, status):
        """Atualiza a data da última sincronização de catálogos globais."""
        query = """
        INSERT INTO cache_metadata (metric_name, last_sync, next_scheduled_sync, status)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(metric_name) DO UPDATE SET
            last_sync=excluded.last_sync,
            next_scheduled_sync=excluded.next_scheduled_sync,
            status=excluded.status
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (metric_name, last_sync, next_scheduled_sync, status))
            conn.commit()