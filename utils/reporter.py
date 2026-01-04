from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class DriverSightReporter:
    def __init__(self, findings):
        self.findings = sorted(findings, key=lambda x: x["priority"], reverse=True)
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def report_to_console(self):
        if not self.findings:
            console.print(
                Panel(
                    "[bold green]✅ SYSTEM CLEAN:[/bold green] No vulnerable drivers found.",
                    border_style="green",
                )
            )
            return

        table = Table(
            title=f"Scan Report - {self.timestamp}", header_style="bold magenta"
        )
        table.add_column("Score", justify="center")
        table.add_column("Driver Name", style="cyan")
        table.add_column("Vulnerability Type", style="white")
        table.add_column("Action", style="yellow")

        for f in self.findings:
            color = "red" if f["priority"] >= 8 else "yellow"
            table.add_row(
                f"[{color}]{f['priority']}/10[/{color}]",
                f["name"],
                f["vuln_type"],
                f["action"],
            )

        console.print(table)

    def _get_css(self):
        return """
        body { background: #0d1117; color: #c9d1d9; font-family: sans-serif; padding: 20px; }
        .container { max-width: 900px; margin: auto; }
        h1 { color: #ff3e3e; border-bottom: 1px solid #30363d; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border: 1px solid #30363d; }
        th { background: #161b22; color: #ff3e3e; }
        .high { color: #ff3e3e; font-weight: bold; }
        .path { font-size: 0.85em; color: #8b949e; font-family: monospace; }
        """

    def report_to_html(self, filename="DS_Report.html"):
        rows = ""
        for f in self.findings:
            p_class = "high" if f["priority"] >= 8 else ""
            rows += f"""
            <tr>
                <td class="{p_class}">{f["priority"]}/10</td>
                <td><strong>{f["name"]}</strong><br><span class="path">{f["path"]}</span></td>
                <td><em>{f["vuln_type"]}</em><br><a href="{f["exploit_url"]}" style="color:#58a6ff">PoC Link</a></td>
            </tr>"""

        html = f"""
        <html><head><meta charset="UTF-8"><style>{self._get_css()}</style></head>
        <body><div class="container"><h1>DriverSight Report</h1>{rows}</table></div></body></html>
        """
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
