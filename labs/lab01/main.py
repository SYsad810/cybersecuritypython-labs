"""Головний файл ЛР №1: послідовно запускає всі три завдання."""

import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from labs.lab01 import task1, task2, task3  # noqa: E402
from shared.student import (  # noqa: E402
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)


def main() -> None:
    """Запустити всі завдання лабораторної роботи."""
    print("Лабораторна робота №1")
    print(f"Студент: {STUDENT_NAME}, група {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}\n")

    task1.run_task1()
    print()
    task2.run_task2()
    print()
    task3.main()


if __name__ == "__main__":
    main()
