import pefile
import os


class DriverAnalyzer:
    def __init__(self, database):
        self.db = database

    def _check_rwx_sections(self, driver_path):
        """
        Проактивный эвристический анализ (Zero-Day Detection).
        Проверяет PE-заголовки на наличие секций, доступных одновременно для записи и исполнения (RWX).
        """
        try:
            pe = pefile.PE(driver_path, fast_load=True)
            for section in pe.sections:
                # 0x20000000 = Исполняемая (Execute)
                # 0x80000000 = Записываемая (Write)
                if (section.Characteristics & 0x20000000) and (
                    section.Characteristics & 0x80000000
                ):
                    return True
            return False
        except Exception:
            return False

    def evaluate(self, driver_path, file_hash):
        # 1. Проверка по базе сигнатур LOLDrivers (Сигнатурный анализ)
        match = self.db.get(file_hash)

        if match:
            raw_severity = match.get("severity", 5)
            v_type = match.get("type", "Unknown").lower()

            priority = raw_severity
            if "write" in v_type:
                priority = 10
            elif "read" in v_type:
                priority = 8
            elif "leak" in v_type:
                priority = 6

            return {
                "path": driver_path,
                "hash": file_hash,
                "name": match.get("name", os.path.basename(driver_path)),
                "vuln_type": match.get("type", "Vulnerable Driver"),
                "priority": priority,
                "exploit_url": match.get("exploit", "https://loldrivers.io/"),
                "action": "Critical: Немедленная блокировка (WDAC)"
                if priority >= 9
                else "High: Обновление вендора",
            }

        # 2. ПРОАКТИВНАЯ ЗАЩИТА: Если в базе нет, но драйвер подозрительный (Эвристика)
        if self._check_rwx_sections(driver_path):
            return {
                "path": driver_path,
                "hash": file_hash,
                "name": os.path.basename(driver_path),
                "vuln_type": "Zero-Day Risk: RWX Memory Section",
                "priority": 7,
                "exploit_url": "Heuristic Detection (Unsafe Memory Architecture)",
                "action": "Warning: Ручной анализ ИБ-специалистом",
            }

        return None
