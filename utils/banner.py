from pyfiglet import Figlet
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def show_banner():
    fig = Figlet(font="slant")
    logo = fig.renderText("ARGUS")

    console.print(
        Panel.fit(
            f"[bold cyan]{logo}[/bold cyan]\n"
            "[bold green]Automated Linux Security Auditing Framework[/bold green]\n"
            "[yellow]Watch Everything. Trust Nothing.[/yellow]\n"
            "[white]Version 1.0[/white]",
            border_style="bright_blue",
        )
    )
