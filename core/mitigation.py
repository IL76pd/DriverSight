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
        """Генерирует XML политику WDAC для блокировки уязвимых драйверов по хешу."""
        if not self.threats:
            return None

        xml_header = """<?xml version="1.0" encoding="utf-8"?>\n<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">\n  <FileRules>\n"""
        xml_rules = ""
        for i, threat in enumerate(self.threats):
            f_hash = threat["hash"].upper()
            f_name = threat["name"]
            xml_rules += f'    <Deny ID="ID_DENY_{i}" FriendlyName="Block {f_name}" Hash="{f_hash}" />\n'
        xml_footer = "  </FileRules>\n</SiPolicy>"

        try:
            with open(self.filename, "w", encoding="utf-8") as f:
                f.write(xml_header + xml_rules + xml_footer)
            return self.filename
        except Exception:
            return None

    def disable_active_threats(self):
        """Мгновенная блокировка (изоляция) уязвимого драйвера в системе."""
        success_count = 0
        for threat in self.threats:
            try:
                driver_base_name = os.path.splitext(threat["name"])[0]

                console.print(
                    f"[*] Попытка изоляции службы драйвера: [bold yellow]{driver_base_name}[/bold yellow]..."
                )

                subprocess.run(
                    ["sc", "stop", driver_base_name], capture_output=True, text=True
                )

                res = subprocess.run(
                    ["sc", "config", driver_base_name, "start=", "disabled"],
                    capture_output=True,
                    text=True,
                )

                if res.returncode == 0:
                    console.print(
                        f"[bold green]✔ Драйвер {driver_base_name} успешно отключен и изолирован.[/bold green]"
                    )
                    success_count += 1
                else:
                    console.print(
                        f"[dim]Не удалось изменить конфигурацию службы {driver_base_name} (возможно, требуется перезагрузка).[/dim]"
                    )
            except Exception as e:
                console.print(
                    f"[bold red]Ошибка при блокировке {threat['name']}: {e}[/bold red]"
                )

        return success_count
