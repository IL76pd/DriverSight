from rich.console import Console
from rich.panel import Panel

console = Console()

BANNER = """
[bold cyan]
 ██████╗ ██████╗ ██╗██╗   ██╗███████╗██████╗ ███████╗██╗ ██████╗ ██╗  ██╗████████╗
 ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔══██╗██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
 ██║  ██║██████╔╝██║██║   ██║█████╗  ██████╔╝███████╗██║██║  ███╗███████║   ██║   
 ██║  ██║██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██║██║   ██║██╔══██║   ██║   
 ██████╔╝██║  ██║██║ ╚████╔╝ ███████╗██║  ██║███████║██║╚██████╔╝██║  ██║   ██║   
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
[/bold cyan]
[bold white]   v2.0 | Поиск уязвимых драйверов | Инструмент ИБ-анализа[/bold white]
"""


def print_banner():
    console.print(BANNER)
    console.print(
        Panel(
            "[bold yellow]ПРЕДУПРЕЖДЕНИЕ:[/bold yellow] Инструмент предназначен для санкционированного аудита безопасности. \n"
            "[dim]Используя программу, вы подтверждаете наличие прав на сканирование данной системы.[/dim]",
            border_style="yellow",
        )
    )


def print_error(text):
    console.print(Panel(f"[bold red]ERROR:[/bold red] {text}", border_style="red"))


def print_info(text):
    console.print(f"[bold blue]ℹ[/bold blue] {text}")


def print_success(text):
    console.print(f"[bold green]✔[/bold green] {text}")
