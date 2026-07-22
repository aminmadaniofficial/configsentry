import asyncio
import typer
from rich.console import Console
from configsentry.core.engine import ScanEngine
from configsentry.reporters.console import ConsoleReporter

app = typer.Typer(
    name="ConfigSentry",
    help="ConfigSentry - Automated Security Misconfiguration Scanner for Web Applications.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

@app.callback()
def main():
    """
    ConfigSentry: CLI tool to audit web application security configurations.
    """
    pass

@app.command("scan")
def scan_command(
    target: str = typer.Argument(..., help="Target URL to audit (e.g., https://example.com)"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="HTTP request timeout in seconds"),
):
    """
    Execute a full security misconfiguration audit on the specified target URL.
    """
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    console.print(f"[bold yellow]🔍 Initiating security scan against:[/bold yellow] [underline]{target}[/underline]\n")

    engine = ScanEngine(timeout=timeout)
    reporter = ConsoleReporter()

    result = asyncio.run(engine.run_scan(target))
    reporter.print_report(result)

if __name__ == "__main__":
    app()