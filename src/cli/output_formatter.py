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
        click.echo("\n╔" + "═"*15 + "╦" + "═"*9 + "╦" + "═"*6 + "╦" + "═"*8 + "╦" + "═"*5 + "╦" + "═"*8 + "╦" + "═"*11 + "╦" + "═"*8 + "╗")
        click.echo(f"║ {'CVE ID':<13} ║ {'CWE':<7} ║ {'CVSS':<4} ║ {'EPSS':<6} ║ {'KEV':<3} ║ {'Nuclei':<6} ║ {'Ransomware':<9} ║ {'Score':<6} ║")
        click.echo("╠" + "═"*15 + "╬" + "═"*9 + "╬" + "═"*6 + "╬" + "═"*8 + "╬" + "═"*5 + "╬" + "═"*8 + "╬" + "═"*11 + "╬" + "═"*8 + "╣")

        for cve in vulnerabilities:
            cve_id = cve['cve_id']
            cwe = cve.get('cwe_id', 'N/A')[:7] # Limita a 7 chars (ex: CWE-79)
            
            raw_cvss = "8.0" if cve.get('missing_cvss') else f"{cve['cvss']:.1f}"
            raw_epss = "80.0%" if cve.get('missing_epss') else f"{cve['epss_percent']}%"
            
            cvss_pad = click.style(f"{raw_cvss:<4}", fg='yellow') if cve.get('missing_cvss') else f"{raw_cvss:<4}"
            epss_pad = click.style(f"{raw_epss:<6}", fg='yellow') if cve.get('missing_epss') else f"{raw_epss:<6}"
            
            kev = "YES" if cve['in_kev'] else "NO"
            nuclei = "YES" if cve.get('has_nuclei') else "NO"
            ransom = "YES" if cve['ransomware_used'] else "NO"
            score = f"{cve['risk_score']:.3f}"
            
            risk_color = 'red' if cve['risk_category'] == 'CRÍTICO' else 'yellow' if cve['risk_category'] == 'ALTO' else 'green'
            
            # Aplica cor vermelha no KEV, Nuclei e Ransomware se forem YES (dá destaque visual ao perigo)
            kev_pad = click.style(f"{kev:<3}", fg='red') if kev == 'YES' else f"{kev:<3}"
            nuc_pad = click.style(f"{nuclei:<6}", fg='red') if nuclei == 'YES' else f"{nuclei:<6}"
            ran_pad = click.style(f"{ransom:<9}", fg='red') if ransom == 'YES' else f"{ransom:<9}"

            click.echo(f"║ {cve_id:<13} ║ {cwe:<7} ║ ", nl=False)
            click.echo(cvss_pad, nl=False)
            click.echo(" ║ ", nl=False)
            click.echo(epss_pad, nl=False)
            click.echo(" ║ ", nl=False)
            click.echo(kev_pad, nl=False)
            click.echo(" ║ ", nl=False)
            click.echo(nuc_pad, nl=False)
            click.echo(" ║ ", nl=False)
            click.echo(ran_pad, nl=False)
            click.echo(" ║ ", nl=False)
            click.secho(f"{score:<6}", fg=risk_color, bold=True, nl=False)
            click.echo(" ║")

        click.echo("╚" + "═"*15 + "╩" + "═"*9 + "╩" + "═"*6 + "╩" + "═"*8 + "╩" + "═"*5 + "╩" + "═"*8 + "╩" + "═"*11 + "╩" + "═"*8 + "╝")
        click.secho("Valores em amarelo indicam métricas preenchidas automaticamente (0.8). Itens em vermelho representam armas de exploração ativas.", fg='yellow', dim=True)
        click.echo()