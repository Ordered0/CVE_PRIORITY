class PriorityToolError(Exception):
    """Exceção base para todas as exceções do projeto."""
    pass

class APIUnreachableError(PriorityToolError):
    """Lançada quando uma API externa (NIST, FIRST, CISA) está indisponível."""
    pass

class CVENotFoundError(PriorityToolError):
    """Lançada quando um ID de CVE fornecido é inválido ou não existe na base."""
    pass

class InvalidMetricError(PriorityToolError):
    """Lançada quando os dados recebidos da API estão malformados ou incompletos."""
    pass

class CacheError(PriorityToolError):
    """Lançada quando ocorre uma falha na conexão ou operação com o SQLite."""
    pass