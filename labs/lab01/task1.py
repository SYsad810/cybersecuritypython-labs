"""Завдання 1: Комплексний аналізатор надійності паролів (варіант 8)."""

import os
import random
import string
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import (  # noqa: E402
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

PASSWORDS = [
    "ThreatH@nt3r",
    "weak123",
    "P3n3trat10n@Test",
    "visitor",
    "Cyber@Defense2023",
    "normal",
    "Incident@R3sp0nse",
    "standard",
    "Risk@Analys1s",
    "typical",
]
CRITERIA = {
    "min_length": 10,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
FORBIDDEN_PASSWORDS = {
    "weak123",
    "visitor",
    "normal",
    "standard",
    "typical",
    "admin",
}

DUPLICATES_COUNT = 3
STRONG_EXTRA_LENGTH = 4

STATUS_FORBIDDEN = "Заборонений"
STATUS_WEAK = "Слабкий"
STATUS_MEDIUM = "Середній"
STATUS_STRONG = "Сильний"
STATUS_VERY_STRONG = "Дуже сильний"


def add_duplicates(passwords: list[str], count: int) -> list[str]:
    """Повернути копію списку з дублікатами випадкових паролів.

    Імітує повторне використання паролів: обирає ``count`` різних
    випадкових індексів і додає відповідні паролі в кінець списку.
    """
    result = passwords.copy()
    indices = random.sample(range(len(passwords)), count)
    for index in indices:
        result.append(passwords[index])
    return result


def get_char_groups(password: str) -> dict[str, bool]:
    """Визначити, які групи символів присутні в паролі."""
    return {
        "digit": any(ch.isdigit() for ch in password),
        "upper": any(ch.isupper() for ch in password),
        "lower": any(ch.islower() for ch in password),
        "special": any(ch in string.punctuation for ch in password),
    }


def meets_all_criteria(groups: dict[str, bool]) -> bool:
    """Перевірити, чи виконано всі обов'язкові критерії з CRITERIA."""
    required = {
        "digit": CRITERIA["require_digits"],
        "upper": CRITERIA["require_upper"],
        "special": CRITERIA["require_special"],
    }
    return all(groups[name] for name, need in required.items() if need)


def evaluate_password(password: str, all_passwords: list[str]) -> str:
    """Оцінити надійність пароля з урахуванням повторів у списку."""
    min_length = CRITERIA["min_length"]

    if password in FORBIDDEN_PASSWORDS or len(password) < min_length:
        return STATUS_FORBIDDEN

    groups = get_char_groups(password)
    is_unique = all_passwords.count(password) == 1

    if meets_all_criteria(groups):
        long_enough = len(password) >= min_length + STRONG_EXTRA_LENGTH
        if long_enough and is_unique:
            return STATUS_VERY_STRONG
        # Короткий або повторно використаний пароль - лише "Сильний"
        return STATUS_STRONG

    groups_count = sum(groups.values())
    if groups_count >= 2:
        return STATUS_MEDIUM
    return STATUS_WEAK


def print_report(passwords: list[str]) -> None:
    """Вивести результати аналізу паролів у вигляді таблиці."""
    header = f"{'№':>3} | {'Пароль':<20} | {'Дов.':>4} | {'Статус':<13}"
    print(header)
    print("-" * len(header))
    for number, password in enumerate(passwords, start=1):
        status = evaluate_password(password, passwords)
        print(
            f"{number:>3} | {password:<20} | {len(password):>4} | {status:<13}"
        )


def run_task1() -> None:
    """Запустити Завдання 1."""
    print(
        f"=== Завдання 1 | {STUDENT_NAME} ({GROUP_NAME}), "
        f"варіант {VARIANT_NUMBER} ==="
    )
    passwords = add_duplicates(PASSWORDS, DUPLICATES_COUNT)
    duplicated = passwords[len(PASSWORDS) :]
    print(f"Додано дублікати: {', '.join(duplicated)}\n")
    print_report(passwords)


if __name__ == "__main__":
    run_task1()
