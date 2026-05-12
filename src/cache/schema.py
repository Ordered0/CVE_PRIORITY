# src/cache/schema.py

CREATE_VULNERABILITIES_TABLE = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    cvss_score REAL,
    epss_percentile REAL,
    kev_status BOOLEAN,
    ransomware_used BOOLEAN,
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