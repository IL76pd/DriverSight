import pefile
import os


class DriverAnalyzer:
    def __init__(self, database):
        self.db = database

    def _check_rwx_sections(self, driver_path):
        """
        Эвристический поиск RWX-секций (Zero-Day).
        Оптимизированная версия с Fast Load.
        """
        try:
            if os.path.getsize(driver_path) > 10 * 1024 * 1024:
                return False
        except OSError:
            return False

        pe = None
        try:
            pe = pefile.PE(driver_path, fast_load=True)

            for section in pe.sections:
                char = getattr(section, "Characteristics", 0)

                # 0x20000000 = Execute (Исполнение)
                # 0x80000000 = Write (Запись)
                if (char & 0x20000000) and (char & 0x80000000):
                    return True

        except Exception:
            try:
                pe = pefile.PE(driver_path)
                for section in pe.sections:
                    char = getattr(section, "Characteristics", 0)
                    if (char & 0x20000000) and (char & 0x80000000):
                        return True
            except Exception:
                return False
        finally:
            if pe:
                pe.close()

        return False

    def evaluate(self, driver_path, file_hash):
        match = self.db.get(file_hash)

        if match:
            raw_severity = match.get("severity", 5)
            v_type = match.get("type", "Unknown").lower()
            priority = (
                10 if "write" in v_type else (8 if "read" in v_type else raw_severity)
            )

            return {
                "path": driver_path,
                "hash": file_hash,
                "name": match.get("name", os.path.basename(driver_path)),
                "vuln_type": match.get("type", "Vulnerable Driver"),
                "priority": priority,
                "exploit_url": match.get("exploit", "https://loldrivers.io/"),
                "detection_method": "База сигнатур (LOLDrivers)",
                "details": f"Известная угроза. Классификация: {v_type.capitalize()}",
                "action": "Блокировка (WDAC/HVCI)",
            }

        if self._check_rwx_sections(driver_path):
            return {
                "path": driver_path,
                "hash": file_hash,
                "name": os.path.basename(driver_path),
                "vuln_type": "RWX Memory Anomaly",
                "priority": 7,
                "exploit_url": "#",
                "detection_method": "Эвристика (Zero-Day)",
                "details": "Обнаружена аномальная секция памяти (Read-Write-Execute). Высокий риск инъекции кода.",
                "action": "Изоляция / Ручной анализ",
            }

        return None
