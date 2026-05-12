import click
import sys
# Removemos o import do parser que estava quebrando
from src.core.cve_processor import CVEProcessor
from src.cli.output_formatter import OutputFormatter
from src.cli.input_handler import InputHandler
from src.utils.logger import setup_logger

# Configuração inicial de logs
logger = setup_logger()

@click.command()
@click.option('--cves', multiple=True, help='IDs CVE separados por espaço (ex: --cves CVE-2024-001 --cves CVE-2024-002)')
@click.option('--file', type=click.Path(exists=True), help='Caminho para arquivo JSON contendo lista de CVEs')
@click.option('--output', type=click.Choice(['table', 'json']), default='table', help='Formato de saída dos dados')
@click.option('--sync-cache', is_flag=True, help='Força a atualização dos dados das APIs externas')
@click.option('--sync-frequency', type=click.Choice(['daily', 'weekly']), default='weekly', help='Frequência de expiração do cache')
def main(cves, file, output, sync_cache, sync_frequency):
    """
    Algoritmo de Priorização de Vulnerabilidades CVE.
    Ferramenta para automatizar a priorização baseada em CVSS, EPSS, KEV e Ransomware.
    """
    try:
        # 1. Inicializa o processador
        processor = CVEProcessor(sync_cache=sync_cache, frequency=sync_frequency)
        
        # 2. Coleta e valida os IDs de entrada usando o InputHandler
        cve_list = InputHandler.parse_inputs(cves_args=cves, file_path=file)
        
        if not cve_list:
            click.echo("Erro: Você deve fornecer ao menos um CVE válido ou um arquivo de entrada. Use --help para detalhes.")
            sys.exit(1)

        click.echo(f"[*] Iniciando processamento de {len(cve_list)} vulnerabilidade(s)...")

        # 3. Processamento e Cálculo de Risco
        results = processor.run(cve_list)

        # 4. Formatação da Saída
        formatter = OutputFormatter(format_type=output)
        formatter.display(results)

    except Exception as e:
        logger.error(f"Erro crítico na execução: {e}")
        click.echo(f"Ocorreu um erro inesperado. Verifique os logs em data/logs/ para mais detalhes.")
        sys.exit(1)

if __name__ == '__main__':
    main()