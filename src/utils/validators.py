import re

def is_valid_cve(cve_id):
    """
    Valida se a string segue o padrão oficial do MITRE: CVE-YYYY-NNNNN.
    """
    pattern = r"^CVE-\d{4}-\d{4,}$"
    return bool(re.match(pattern, cve_id, re.IGNORECASE))