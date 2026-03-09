import os
import subprocess
from datetime import datetime
from rich.console import Console

console = Console()


class WDACGenerator:
    def __init__(self, threats):
        self.threats = threats
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = f"WDAC_BlockPolicy_{self.timestamp}.xml"

    def generate_policy(self):
        if not self.threats:
            return None
        xml_header = """<?xml version="1.0" encoding="utf-8"?>\n<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">\n  <FileRules>\n"""
        xml_rules = ""
        for i, threat in enumerate(self.threats):
            xml_rules += f'    <Deny ID="ID_DENY_{i}" FriendlyName="Block {threat["name"]}" Hash="{threat["hash"].upper()}" />\n'
        try:
            with open(self.filename, "w", encoding="utf-8") as f:
                f.write(xml_header + xml_rules + "  </FileRules>\n</SiPolicy>")
            return self.filename
        except Exception:
            return None

    def disable_active_threats(self):
        """Динамическая выгрузка и блокировка драйверов (Active Quarantine)."""
        success_count = 0
        console.print(
            "[dim]Инициализация механизма Active Quarantine. Попытка динамической выгрузки...[/dim]"
        )

        for threat in self.threats:
            driver_base = os.path.splitext(os.path.basename(threat["path"]))[0]
            try:
                stop_res = subprocess.run(
                    ["sc", "stop", driver_base], capture_output=True, text=True
                )
                config_res = subprocess.run(
                    ["sc", "config", driver_base, "start=", "disabled"],
                    capture_output=True,
                    text=True,
                )

                if stop_res.returncode == 0 and config_res.returncode == 0:
                    console.print(
                        f"[bold green]✔ Угроза {driver_base} мгновенно выгружена из памяти и заблокирована.[/bold green]"
                    )
                    success_count += 1
                elif config_res.returncode == 0:
                    console.print(
                        f"[bold yellow]⚠ {driver_base} заблокирован в реестре, но ядро отказалось выгрузить его на лету. Нужна перезагрузка.[/bold yellow]"
                    )
                    success_count += 1
                else:
                    console.print(
                        f"[dim]Служба {driver_base} не найдена. Требуется применение политик WDAC.[/dim]"
                    )
            except Exception as e:
                console.print(
                    f"[bold red]Ошибка доступа к {driver_base}: {e}[/bold red]"
                )

        return success_count
