from rich.console import Console
from rich.panel import Panel

console = Console()

BANNER = """
[bold red]
 ██████╗ ██████╗ ██╗██╗   ██╗███████╗██████╗ ███████╗██╗ ██████╗ ██╗  ██╗████████╗
 ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔══██╗██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
 ██║  ██║██████╔╝██║██║   ██║█████╗  ██████╔╝███████╗██║██║  ███╗███████║   ██║   
 ██║  ██║██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██║██║   ██║██╔══██║   ██║   
 ██████╔╝██║  ██║██║ ╚████╔╝ ███████╗██║  ██║███████║██║╚██████╔╝██║  ██║   ██║   
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
[/bold red]
[bold white]   v1.2 | Advanced Kernel Attack Surface Auditor | Built for Red Team[/bold white]
"""


def print_banner():
    console.print(BANNER)


def print_error(text):
    console.print(Panel(f"[bold red]ERROR:[/bold red] {text}", border_style="red"))


def print_info(text):
    console.print(f"[bold blue]ℹ[/bold blue] {text}")


def print_success(text):
    console.print(f"[bold green]✔[/bold green] {text}")
