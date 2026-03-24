import requests
import json
import os


class DatabaseUpdater:
    SOURCE_URL = "https://loldrivers.io/api/drivers.json"

    def __init__(self, db_path):
        self.db_path = db_path

    def update(self):
        print(f"[*] Connecting to {self.SOURCE_URL}...")

        try:
            response = requests.get(self.SOURCE_URL, timeout=15)
            response.raise_for_status()
            raw_data = response.json()

            new_db = {}
            count = 0

            for entry in raw_data:
                name = entry.get("Name") or entry.get("name")
                if not name:
                    name = entry.get("Id") or entry.get("id") or "Unknown Driver"

                vuln_type = (
                    entry.get("Category")
                    or entry.get("category")
                    or "Vulnerable Driver"
                )

                samples = entry.get("KnownVulnerableSamples", []) or entry.get(
                    "knownvulnerablesamples", []
                )

                for sample in samples:
                    sha256 = sample.get("SHA256") or sample.get("sha256")
                    if sha256:
                        sha256 = sha256.lower()
                        filename = sample.get("Filename") or sample.get("filename")
                        display_name = filename if filename else name

                        new_db[sha256] = {
                            "name": display_name,
                            "type": vuln_type,
                            "severity": 10 if vuln_type.lower() == "malware" else 8,
                            "exploit": f"https://loldrivers.io/drivers/{entry.get('Id', entry.get('id', ''))}/",
                        }
                        count += 1

            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(new_db, f, indent=4)

            print(f"[+] Update successful! {count} hashes indexed.")
            return True

        except Exception as e:
            print(f"[-] Update failed: {e}")
            return False
