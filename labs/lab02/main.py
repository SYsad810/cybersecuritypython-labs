"""Головний файл ЛР №2: команди demo (Завдання 1) та analyze (Завдання 2).

Запуск з кореня репозиторію:
    python -m labs.lab02.main demo
    python -m labs.lab02.main analyze --dns-log ... --blacklist ...
"""

import argparse
import sys

from labs.lab02 import task1, task2
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def build_parser() -> argparse.ArgumentParser:
    """Створити парсер аргументів з підкомандами demo та analyze."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="ЛР №2: ООП-модель користувача та аналізатор DNS-запитів",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="демонстрація класів Завдання 1")
    analyze_parser = commands.add_parser(
        "analyze", help="аналіз журналу DNS-запитів (варіант 8)"
    )
    task2.add_arguments(analyze_parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Розібрати аргументи та виконати обрану команду."""
    args = build_parser().parse_args(argv)
    print(
        f"=== ЛР №2 | {STUDENT_NAME} ({GROUP_NAME}), "
        f"варіант {VARIANT_NUMBER} ==="
    )
    if args.command == "demo":
        task1.run_demo()
        return 0
    return task2.analyze(args)


if __name__ == "__main__":
    sys.exit(main())
