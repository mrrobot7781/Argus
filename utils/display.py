from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def print_module(result):
    """
    Display a module using Rich Table.
    """

    table = Table(show_header=True, header_style="bold cyan")

    table.add_column("Check", style="cyan", width=35)
    table.add_column("Result", style="green")

    for key, value in result["data"].items():
        table.add_row(str(key), str(value))

    panel = Panel(
        table,
        title=f"[bold yellow]{result['module']}[/bold yellow]",
        border_style="bright_blue",
    )

    console.print(panel)

    status = result["status"]
    severity = result["severity"]

    if status == "PASS":
        console.print(f"[bold green]✔ Status:[/bold green] {status}")
    elif status == "WARNING":
        console.print(f"[bold yellow]⚠ Status:[/bold yellow] {status}")
    else:
        console.print(f"[bold red]✖ Status:[/bold red] {status}")

    console.print(f"[bold cyan]Severity:[/bold cyan] {severity}")
    console.print()
