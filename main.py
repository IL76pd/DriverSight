import argparse
import sys
import os
from utils.interface import print_banner, print_error, print_success
from core.engine import DriverSightEngine
from core.updater import DatabaseUpdater
from utils.reporter import DriverSightReporter

DB_PATH = "data/db.json"


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="DriverSight CLI")
    parser.add_argument(
        "--update", action="store_true", help="Update DB from LOLDrivers"
    )
    parser.add_argument("--scan", action="store_true", default=True)
    args = parser.parse_args()

    # 1. Логика обновления
    if args.update:
        updater = DatabaseUpdater(DB_PATH)
        if updater.update():
            print_success("Database successfully synchronized!")
        sys.exit(0)

    # 2. Логика сканирования
    if not os.path.exists(DB_PATH):
        print_error("Database not found! Run with --update first.")
        sys.exit(1)

    try:
        engine = DriverSightEngine(DB_PATH)
        threats = engine.run_scan()

        reporter = DriverSightReporter(threats)
        reporter.report_to_console()

        if threats:
            reporter.report_to_html()
            print_success(
                "Detailed report saved to: [underline]DS_Report.html[/underline]"
            )

    except Exception as e:
        print_error(str(e))


if __name__ == "__main__":
    main()
