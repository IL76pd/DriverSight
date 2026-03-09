from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class DriverSightReporter:
    def __init__(self, findings):
        self.findings = sorted(findings, key=lambda x: x["priority"], reverse=True)
        self.dt_now = datetime.now()
        self.timestamp = self.dt_now.strftime("%Y-%m-%d %H:%M:%S")
        self.filename = self.dt_now.strftime("DS_Report_%Y%m%d_%H%M%S.html")

    def report_to_console(self, duration=0, total_scanned=0):
        avg_time = (duration / total_scanned * 1000) if total_scanned > 0 else 0
        metrics = f"Время сканирования: [bold]{duration:.2f} сек[/bold] | На модуль: [bold]{avg_time:.2f} мс[/bold]"
        console.print(
            Panel(
                metrics, title="[cyan]Метрики[/cyan]", border_style="blue", expand=False
            )
        )

        if not self.findings:
            console.print(
                Panel(
                    "[bold green]✅ СИСТЕМА БЕЗОПАСНА[/bold green]",
                    border_style="green",
                )
            )
            return

        table = Table(
            title=f"Отчет аудита - {self.timestamp}", header_style="bold cyan"
        )
        table.add_column("Риск", justify="center")
        table.add_column("Имя модуля", style="white")
        table.add_column("Метод обнаружения", style="magenta")
        table.add_column("Уязвимость", style="dim")

        for f in self.findings:
            color = "red" if f["priority"] >= 9 else "yellow"
            table.add_row(
                f"[{color}]{f['priority']}/10[/{color}]",
                f["name"],
                f["detection_method"],
                f["vuln_type"],
            )

        console.print(table)

    def report_to_html(self):
        is_clean = len(self.findings) == 0
        rows_html = ""

        status_box = (
            f"<div style='background:#1b2a1e;border:1px solid #2ea043;padding:15px;'><h3 style='color:#2ea043;margin:0;'>✅ Система в норме</h3></div>"
            if is_clean
            else f"<div style='background:#2a1b1b;border:1px solid #ff3e3e;padding:15px;'><h3 style='color:#ff3e3e;margin:0;'>⚠ Обнаружены риски: {len(self.findings)}</h3></div>"
        )

        for f in self.findings:
            r_class = (
                "color:#ff3e3e;font-weight:bold;"
                if f["priority"] >= 9
                else "color:#ffa657;"
            )
            rows_html += f"""
            <tr>
                <td style="{r_class}">{f["priority"]}/10</td>
                <td><strong>{f["name"]}</strong><br><span style="font-family:monospace;font-size:12px;color:#8b949e;">{f["path"]}</span></td>
                <td><span style="background:#21262d;padding:3px 6px;border-radius:4px;font-size:12px;">{f["detection_method"]}</span><br><br>{f["details"]}</td>
                <td><code style="font-size:11px;">{f["hash"]}</code><br><br><a href="{f["exploit_url"]}" style="color:#58a6ff;">Ссылка на CVE</a></td>
            </tr>
            """

        css = "body{background:#0d1117;color:#c9d1d9;font-family:sans-serif;} table{width:100%;border-collapse:collapse;margin-top:20px;} th,td{padding:10px;border:1px solid #30363d;text-align:left;vertical-align:top;} th{background:#21262d;color:#38d3ff;}"

        html = f"""<html><head><meta charset="UTF-8"><title>Audit Report</title><style>{css}</style></head><body>
            <h2>DriverSight: Отчет об инвентаризации ядра</h2><p>Дата: {self.timestamp}</p>{status_box}
            {"<table><tr><th>Риск</th><th>Модуль</th><th>Детект и Описание</th><th>Хеш / Данные</th></tr>" + rows_html + "</table>" if not is_clean else ""}
        </body></html>"""

        with open(self.filename, "w", encoding="utf-8") as f:
            f.write(html)
        return self.filename
