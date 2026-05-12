import json
import click
from datetime import datetime, timezone

class OutputFormatter:
    """
    Formata e exibe os resultados da análise de vulnerabilidades.
    """
    def __init__(self, format_type='table'):
        self.format_type = format_type

    def display(self, results_data):
        """
        Direciona a saída para o formato escolhido.
        """
        if not results_data.get('vulnerabilities'):
            click.echo("Nenhuma vulnerabilidade foi processada com sucesso.")
            return

        if self.format_type == 'json':
            self._print_json(results_data)
        else:
            self._print_table(results_data['vulnerabilities'])

    def _print_json(self, results_data):
        """
        Exibe a saída em formato JSON (útil para integração com outras ferramentas).
        """
        output = {
            "execution_date": datetime.now(timezone.utc).isoformat(),
            "metadata": results_data.get('execution_metadata', {}),
            "vulnerabilities": results_data.get('vulnerabilities', [])
        }
        click.echo(json.dumps(output, indent=2, ensure_ascii=False))

    def _print_table(self, vulnerabilities):
        """
        Exibe a saída em uma tabela ASCII formatada no terminal.
        """
        # Cabeçalho da tabela
        click.echo("\n╔" + "═"*16 + "╦" + "═"*7 + "╦" + "═"*9 + "╦" + "═"*7 + "╦" + "═"*14 + "╦" + "═"*9 + "╗")
        click.echo(f"║ {'CVE ID':<14} ║ {'CVSS':<5} ║ {'EPSS':<7} ║ {'KEV':<5} ║ {'Ransomware':<12} ║ {'Score':<7} ║")
        click.echo("╠" + "═"*16 + "╬" + "═"*7 + "╬" + "═"*9 + "╬" + "═"*7 + "╬" + "═"*14 + "╬" + "═"*9 + "╣")

        # Linhas da tabela
        for cve in vulnerabilities:
            cve_id = cve['cve_id']
            cvss = f"{cve['cvss']:.1f}"
            epss = f"{cve['epss_percent']}%"
            kev = "YES" if cve['in_kev'] else "NO"
            ransom = "YES" if cve['ransomware_used'] else "NO"
            score = f"{cve['risk_score']:.3f}"
            
            # Adiciona cores baseadas na categoria de risco
            risk_color = 'green'
            if cve['risk_category'] == 'CRÍTICO':
                risk_color = 'red'
            elif cve['risk_category'] == 'ALTO':
                risk_color = 'yellow'
            
            click.secho(f"║ {cve_id:<14} ║ {cvss:<5} ║ {epss:<7} ║ {kev:<5} ║ {ransom:<12} ║ ", nl=False)
            click.secho(f"{score:<7}", fg=risk_color, bold=True, nl=False)
            click.echo(" ║")

        # Rodapé da tabela
        click.echo("╚" + "═"*16 + "╩" + "═"*7 + "╩" + "═"*9 + "╩" + "═"*7 + "╩" + "═"*14 + "╩" + "═"*9 + "╝\n")