from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from configsentry.core.models import ScanResult, RiskLevel

class ConsoleReporter:
    """
    Renders security scan results in a structured and color-coded terminal layout.
    """

    def __init__(self):
        self.console = Console()

    def _get_risk_color(self, level: RiskLevel) -> str:
        colors = {
            RiskLevel.HIGH: "bold red",
            RiskLevel.MEDIUM: "bold yellow",
            RiskLevel.LOW: "bold cyan",
            RiskLevel.INFO: "bold green",
        }
        return colors.get(level, "white")

    def print_report(self, result: ScanResult) -> None:
        """
        Prints formatted panel and table for scan findings.
        """
        self.console.print(
            Panel(
                f"[bold cyan]Target:[/bold cyan] {result.target_url}\n"
                f"[bold cyan]Scan Time:[/bold cyan] {result.scan_timestamp}\n"
                f"[bold cyan]Total Issues Found:[/bold cyan] {len(result.issues)}",
                title="[bold red]ConfigSentry Scan Summary[/bold red]",
                expand=False,
            )
        )

        if not result.issues:
            self.console.print("[bold green]✔ No security misconfigurations detected![/bold green]")
            return

        table = Table(title="Identified Security Findings", show_header=True, header_style="bold magenta")
        table.add_column("Risk Level", style="dim", width=12)
        table.add_column("Issue Title", width=30)
        table.add_column("Description", width=40)
        table.add_column("Remediation Strategy", width=45)

        for issue in result.issues:
            risk_color = self._get_risk_color(issue.risk_level)
            table.add_row(
                f"[{risk_color}]{issue.risk_level.value}[/{risk_color}]",
                issue.title,
                issue.description,
                issue.remediation,
            )

        self.console.print(table)