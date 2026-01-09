import argparse
import sys
import os

from utils.interface import print_banner, print_error, print_success, print_info
from core.engine import DriverSightEngine
from core.updater import DatabaseUpdater
from utils.reporter import DriverSightReporter


def get_resource_path(relative_path):
    """
    Получает путь к файлу, который 'зашит' внутри EXE (через PyInstaller).
    Если запущено как скрипт, возвращает обычный путь.
    """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def get_working_db_path():
    """
    Определяет, какую базу использовать:
    1. Приоритет - базе 'data/db.json' рядом с файлом программы (обновленная).
    2. Если её нет - берем встроенную в EXE базу.
    """
    external_db = os.path.join(
        os.path.dirname(sys.executable if getattr(sys, "frozen", False) else __file__),
        "data",
        "db.json",
    )

    if os.path.exists(external_db):
        return external_db

    return get_resource_path(os.path.join("data", "db.json"))


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="DriverSight CLI")
    parser.add_argument(
        "--update", action="store_true", help="Update DB from LOLDrivers API"
    )
    args = parser.parse_args()
    db_path = get_working_db_path()

    if args.update:
        target_dir = os.path.join(
            os.path.dirname(
                sys.executable if getattr(sys, "frozen", False) else __file__
            ),
            "data",
        )
        target_file = os.path.join(target_dir, "db.json")

        updater = DatabaseUpdater(target_file)
        if updater.update():
            print_success(f"Database synchronized! Saved to: {target_file}")
        else:
            print_error("Failed to update database.")
        sys.exit(0)

    if not os.path.exists(db_path):
        print_error(f"Database NOT FOUND at {db_path}\nPlease run: main.exe --update")
        sys.exit(1)

    try:
        print_info(f"Using database: [dim]{db_path}[/dim]")

        engine = DriverSightEngine(db_path)
        threats = engine.run_scan()

        reporter = DriverSightReporter(threats)
        reporter.report_to_console()

        reporter.report_to_html("DS_Report.html")
        print_success(
            "Detailed audit report generated: [underline]DS_Report.html[/underline]"
        )

    except Exception as e:
        print_error(f"Scan interrupted: {str(e)}")


if __name__ == "__main__":
    main()
