import requests
import json
import os


class DatabaseUpdater:
    # Официальный API проекта LOLDrivers
    SOURCE_URL = "https://loldrivers.io/api/drivers.json"

    def __init__(self, db_path):
        self.db_path = db_path

    def update(self):
        """Скачивает свежую базу и пересобирает её под наш формат."""
        print(f"[*] Connecting to {self.SOURCE_URL}...")

        try:
            response = requests.get(self.SOURCE_URL, timeout=15)
            response.raise_for_status()
            raw_data = response.json()

            new_db = {}
            count = 0

            # LOLDrivers отдает список объектов. Нам нужно проиндексировать их по ХЕШУ
            # для мгновенного поиска в анализаторе.
            for entry in raw_data:
                name = entry.get("Name", "Unknown")
                vuln_type = entry.get("Category", "Vulnerable Driver")

                # Собираем все известные хеши для этого драйвера
                samples = entry.get("KnownVulnerableSamples", [])
                for sample in samples:
                    sha256 = sample.get("SHA256")
                    if sha256:
                        sha256 = sha256.lower()
                        # Формируем наш формат записи
                        new_db[sha256] = {
                            "name": name,
                            "type": vuln_type,
                            "severity": 10 if vuln_type == "Malware" else 8,
                            "exploit": f"https://loldrivers.io/drivers/{entry.get('Id')}/",
                        }
                        count += 1

            # Сохраняем обновленную базу
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(new_db, f, indent=4)

            print(f"[+] Update successful! {count} hashes indexed.")
            return True

        except Exception as e:
            print(f"[-] Update failed: {e}")
            return False
