import argparse
import sys
import os
from utils.interface import print_banner, print_error, print_success, print_info
from core.engine import DriverSightEngine
from core.updater import DatabaseUpdater
from utils.reporter import DriverSightReporter
from core.mitigation import WDACGenerator
from rich.prompt import Confirm


def get_resource_path(rel_path):
    try:
        base_path = sys._MEIPASS
    except:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, rel_path)


def get_working_db_path():
    ext_db = os.path.join(
        os.path.dirname(sys.executable if getattr(sys, "frozen", False) else __file__),
        "data",
        "db.json",
    )
    return (
        ext_db
        if os.path.exists(ext_db)
        else get_resource_path(os.path.join("data", "db.json"))
    )


def main():
    print_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--dir", type=str, help="Режим форензики: сканирование папки")
    args = parser.parse_args()

    db_path = get_working_db_path()

    if args.update:
        target = os.path.join(
            os.path.dirname(
                sys.executable if getattr(sys, "frozen", False) else __file__
            ),
            "data",
            "db.json",
        )
        updater = DatabaseUpdater(target)
        if updater.update():
            print_success(f"База обновлена: {target}")
        sys.exit(0)

    if not os.path.exists(db_path):
        print_error("База данных не найдена!")
        sys.exit(1)

    try:
        # Передаем args.dir в движок!
        engine = DriverSightEngine(db_path, args.dir)
        threats, duration, total = engine.run_scan()

        reporter = DriverSightReporter(threats)
        reporter.report_to_console(duration, total)
        report_name = reporter.report_to_html()
        print_success(f"Отчет сохранен: [underline]{report_name}[/underline]")

        if threats:
            print("\n")
            if Confirm.ask(
                "[bold red]⚠ Изолировать уязвимые драйверы (отключить автозагрузку)?[/bold red]"
            ):
                wdac = WDACGenerator(threats)
                wdac.disable_active_threats()

            if Confirm.ask(
                "[bold yellow]Сгенерировать политики WDAC для блокировки?[/bold yellow]"
            ):
                wdac = WDACGenerator(threats)
                policy = wdac.generate_policy()
                if policy:
                    print_success(f"Политика создана: {policy}")

    except Exception as e:
        print_error(f"Сбой: {str(e)}")


if __name__ == "__main__":
    main()
