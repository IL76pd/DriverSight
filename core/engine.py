import json
import time
import os
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.collector import DriverCollector
from core.hasher import DriverHasher
from core.analyzer import DriverAnalyzer
from utils.interface import print_info

class DriverSightEngine:
    def __init__(self, db_path, target_dir=None):
        self.db_path = db_path
        self.target_dir = target_dir
        self.collector = DriverCollector()
        self.hasher = DriverHasher()

    def run_scan(self):
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                database = json.load(f)
            analyzer = DriverAnalyzer(database)
        except Exception as e:
            raise Exception(f"Ошибка базы данных: {e}")

        found_threats = []
        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            if self.target_dir and os.path.exists(self.target_dir):
                progress.add_task(
                    description=f"Инвентаризация директории {self.target_dir}...",
                    total=None,
                )
                paths = self.collector.get_drivers_from_directory(self.target_dir)
            else:
                progress.add_task(
                    description="Сбор модулей ядра (WinAPI)...", total=None
                )
                paths = self.collector.get_driver_paths()

            total_drivers = len(paths)
            print_info(
                f"Обнаружено объектов для анализа: [bold white]{total_drivers}[/bold white]"
            )

            task = progress.add_task(
                description="Криптографический и эвристический анализ...",
                total=total_drivers,
            )

            for path in paths:
                try:
                    f_hash = self.hasher.get_sha256(path)
                    if f_hash:
                        res = analyzer.evaluate(path, f_hash)
                        if res:
                            found_threats.append(res)
                except Exception:
                    pass
                progress.advance(task)

        duration = time.time() - start_time
        return found_threats, duration, total_drivers
