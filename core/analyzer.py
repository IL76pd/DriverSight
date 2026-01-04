class DriverAnalyzer:
    def __init__(self, database):
        self.db = database  # Загруженный JSON

    def evaluate(self, driver_path, file_hash):
        """Сверка хеша и присвоение рейтинга опасности."""
        match = self.db.get(file_hash)
        if not match:
            return None

        # Логика скоринга (Red Team Priority)
        # 10 - Позволяет полное управление ядром (R/W)
        # 5  - Позволяет только чтение или DoS
        severity = match.get("severity", 5)

        result = {
            "path": driver_path,
            "hash": file_hash,
            "name": match.get("name"),
            "vuln_type": match.get("type"),  # Например: "Arbitrary Kernel Write"
            "priority": severity,
            "exploit_url": match.get("exploit"),  # Ссылка на PoC
            "action": "Use for EDR Evasion" if severity >= 8 else "Limited use",
        }
        return result
