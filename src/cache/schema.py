# src/cache/schema.py

CREATE_VULNERABILITIES_TABLE = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    cvss_score REAL,
    cwe_id TEXT,
    epss_percentile REAL,
    kev_status BOOLEAN,
    ransomware_used BOOLEAN,
    has_nuclei BOOLEAN,
    has_metasploit BOOLEAN,
    reference_count INTEGER DEFAULT 0,
    last_updated TIMESTAMP,
    next_update TIMESTAMP
);
"""

CREATE_METADATA_TABLE = """
CREATE TABLE IF NOT EXISTS cache_metadata (
    metric_name TEXT PRIMARY KEY,
    last_sync TIMESTAMP,
    next_scheduled_sync TIMESTAMP,
    status TEXT
);
"""

SCHEMA_QUERIES = [
    CREATE_VULNERABILITIES_TABLE,
    CREATE_METADATA_TABLE
]

# Migrações leves para bancos já existentes (criados antes de colunas novas
# existirem). CREATE TABLE IF NOT EXISTS não adiciona colunas novas a
# tabelas já criadas, então o DatabaseManager tenta estes ALTER TABLE
# separadamente e ignora o erro caso a coluna já exista.
MIGRATION_QUERIES = [
    "ALTER TABLE vulnerabilities ADD COLUMN reference_count INTEGER DEFAULT 0;",
    "ALTER TABLE vulnerabilities ADD COLUMN has_metasploit BOOLEAN DEFAULT 0;"
]