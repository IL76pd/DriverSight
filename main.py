import argparse
import sys
import os

from utils.interface import print_banner, print_error, print_success, print_info
from core.engine import DriverSightEngine
from core.updater import DatabaseUpdater
from utils.reporter import DriverSightReporter
from core.mitigation import WDACGenerator
from rich.prompt import Confirm


def get_resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def get_working_db_path():
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

    parser = argparse.ArgumentParser(description="DriverSight CLI - Blue Team Edition")
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
            print_success(f"База данных успешно синхронизирована: {target_file}")
        else:
            print_error("Ошибка обновления базы данных.")
        sys.exit(0)

    if not os.path.exists(db_path):
        print_error(f"База данных не найдена: {db_path}\nЗапустите: main.exe --update")
        sys.exit(1)

    try:
        print_info(f"Используемая база сигнатур: [dim]{db_path}[/dim]")

        engine = DriverSightEngine(db_path)
        threats, duration, total_count = engine.run_scan()
        reporter = DriverSightReporter(threats)
        reporter.report_to_console(duration, total_count)
        report_name = reporter.report_to_html()
        print_success(
            f"Подробный ИБ-отчет сохранен: [underline]{report_name}[/underline]"
        )

        # ПРОАКТИВНЫЙ БЛОК: Изоляция и генерация политик
        if threats:
            print("\n")
            if Confirm.ask(
                "[bold red]⚠ Хотите МГНОВЕННО отключить уязвимые драйверы в системе?[/bold red]"
            ):
                wdac_gen = WDACGenerator(threats)
                disabled = wdac_gen.disable_active_threats()
                print_success(f"Изолировано угроз: {disabled} из {len(threats)}")

            if Confirm.ask(
                "[bold yellow]Сгенерировать WDAC-политики для защиты на уровне домена?[/bold yellow]"
            ):
                wdac_gen = WDACGenerator(threats)
                policy_file = wdac_gen.generate_policy()
                if policy_file:
                    print_success(
                        f"WDAC-политика успешно сгенерирована: [bold white]{policy_file}[/bold white]"
                    )

    except Exception as e:
        print_error(f"Сбой сканирования: {str(e)}")


if __name__ == "__main__":
    main()
