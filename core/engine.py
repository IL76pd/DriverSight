import json
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.collector import DriverCollector
from core.hasher import DriverHasher
from core.analyzer import DriverAnalyzer
from utils.interface import print_info


class DriverSightEngine:
    def __init__(self, db_path):
        self.db_path = db_path
        self.collector = DriverCollector()
        self.hasher = DriverHasher()

    def run_scan(self):
        # 1. Загрузка БД
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                database = json.load(f)
            analyzer = DriverAnalyzer(database)
        except Exception as e:
            raise Exception(f"Failed to load database: {e}")

        # 2. Процесс сканирования
        found_threats = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            # Сбор путей
            progress.add_task(
                description="Enumerating kernel modules (WinAPI)...", total=None
            )
            paths = self.collector.get_driver_paths()
            print_info(
                f"Identified [bold white]{len(paths)}[/bold white] active drivers."
            )

            # Хеширование и анализ
            task = progress.add_task(
                description="Analyzing drivers...", total=len(paths)
            )
            for path in paths:
                f_hash = self.hasher.get_sha256(path)
                if f_hash:
                    res = analyzer.evaluate(path, f_hash)
                    if res:
                        found_threats.append(res)
                progress.advance(task)

        return found_threats
