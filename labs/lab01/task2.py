"""Завдання 2: Багаторівнева система контролю доступу (варіант 8)."""

import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import (  # noqa: E402
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

USERS = {
    "crypto_specialist": {
        "role": "cryptographer",
        "clearance": 4,
        "department": "Cryptography",
        "active": True,
    },
    "privacy_officer": {
        "role": "privacy_analyst",
        "clearance": 3,
        "department": "Privacy",
        "active": True,
    },
    "data_scientist": {
        "role": "data_analyst",
        "clearance": 2,
        "department": "Analytics",
        "active": True,
    },
    "field_engineer": {
        "role": "field_support",
        "clearance": 2,
        "department": "Field Ops",
        "active": True,
    },
    "test_account": {
        "role": "testing",
        "clearance": 1,
        "department": "QA",
        "active": False,
    },
}
RESOURCES = [
    ("encryption_keys", 4),
    ("privacy_policies", 3),
    ("anonymized_data", 2),
    ("field_reports", 2),
    ("crypto_algorithms", 4),
    ("consent_forms", 1),
    ("data_classification", 3),
    ("key_management", 4),
    ("statistical_models", 2),
    ("public_datasets", 1),
]
SECURITY_LEVELS = (
    "Unclassified",
    "For Official Use",
    "Confidential",
    "Secret",
)
BLOCKED_USERS = {"test_account", "gdpr_violation", "data_breach_user"}

# Неіснуючі в системі користувачі для перевірки гілки "User not found"
EXTRA_TEST_USERS = ("gdpr_violation", "unknown_user")


def level_name(level: int) -> str:
    """Повернути текстову назву рівня безпеки (1..4)."""
    return SECURITY_LEVELS[level - 1]


def check_access(username: str, resource_level: int) -> tuple[bool, str]:
    """Перевірити доступ користувача до ресурсу заданого рівня.

    Повертає кортеж (дозволено, причина_відмови).
    """
    user = USERS.get(username)
    if user is None:
        return False, "User not found"
    if username in BLOCKED_USERS:
        return False, "User is blocked"
    if not user["active"]:
        return False, "Account inactive"
    if user["clearance"] >= resource_level:
        return True, ""
    return False, "Insufficient clearance"


def format_result(username: str, resource: str, level: int) -> str:
    """Сформувати рядок результату перевірки доступу."""
    allowed, reason = check_access(username, level)
    verdict = "ALLOW" if allowed else f"DENY ({reason})"
    return f"user=[{username}] resource=[{resource}] -> {verdict}"


def print_resources() -> None:
    """Вивести список ресурсів з текстовими рівнями безпеки."""
    print("--- Ресурси системи ---")
    print(f"{'Ресурс':<22} | {'Рівень':<18}")
    print("-" * 43)
    for resource, level in RESOURCES:
        print(f"{resource:<22} | {level} - {level_name(level)}")


def run_task2() -> None:
    """Запустити Завдання 2."""
    print(
        f"=== Завдання 2 | {STUDENT_NAME} ({GROUP_NAME}), "
        f"варіант {VARIANT_NUMBER} ==="
    )
    print_resources()

    print("\n--- Результати перевірки доступу ---")
    for username in (*USERS, *EXTRA_TEST_USERS):
        for resource, level in RESOURCES:
            print(format_result(username, resource, level))


if __name__ == "__main__":
    run_task2()
