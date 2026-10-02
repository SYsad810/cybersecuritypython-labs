"""Завдання 3: Хешування, CSV-база та JSON-логування (варіант 8)."""

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import (  # noqa: E402
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

HASH_ALGORITHM = "sha256"
MIN_PASSWORD_LENGTH = 11
SALT = str(VARIANT_NUMBER).zfill(5)  # "00008"

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOG_JSON = os.path.join(DATA_DIR, "log.json")

users_db: list[tuple[str, str]] = []


class ValidationError(Exception):
    """Пароль не відповідає політиці безпеки (закороткий)."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Повернути шістнадцятковий SHA-256 хеш від password + salt.

    Raises:
        ValueError: якщо пароль або сіль порожні.
        ValidationError: якщо пароль коротший за мінімальну довжину.

    """
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за {MIN_PASSWORD_LENGTH} символів"
        )
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створити запис користувача (логін, хеш) з персональною сіллю."""
    return username, generate_hash(password, SALT)


def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    """Захешувати паролі всіх користувачів і записати їх у CSV."""
    os.makedirs(DATA_DIR, exist_ok=True)
    records = [create_user(login_, pwd) for login_, pwd in users_list]
    with open(USERS_CSV, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerows(records)


def read_users(path: str = USERS_CSV) -> list[tuple[str, str]]:
    """Зчитати базу користувачів з CSV-файлу."""
    with open(path, newline="", encoding="utf-8") as file:
        return [(row[0], row[1]) for row in csv.reader(file) if row]


def mask_args(args: tuple) -> list:
    """Замаскувати пароль (2-й аргумент), щоб не писати його в журнал."""
    return [arg if i != 1 else "********" for i, arg in enumerate(args)]


def write_log(entry: dict) -> None:
    """Дописати подію в JSON-журнал (список подій)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    events = []
    try:
        with open(LOG_JSON, encoding="utf-8") as file:
            events = json.load(file)
    except FileNotFoundError:
        pass  # Журнал ще не створено - почнемо новий
    except json.JSONDecodeError:
        print("[УВАГА] log.json пошкоджено, створюється новий журнал")
    events.append(entry)
    with open(LOG_JSON, "w", encoding="utf-8") as file:
        json.dump(events, file, ensure_ascii=False, indent=2)


def log_event(func):
    """Декоратор: записує кожну спробу входу в log.json."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "")
        result = "failure"
        try:
            success = func(*args, **kwargs)
            result = "success" if success else "failure"
            return success
        finally:
            safe_kwargs = {
                key: ("********" if key == "password" else value)
                for key, value in kwargs.items()
            }
            write_log(
                {
                    "event": "login",
                    "user": username,
                    "result": result,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "args": mask_args(args),
                    "kwargs": safe_kwargs,
                }
            )

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевірити логін і пароль за базою users_db."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми")
    stored = dict(users_db).get(username)
    if stored is None:
        return False
    try:
        return generate_hash(password, SALT) == stored
    except ValidationError:
        return False  # Закороткий пароль не може бути правильним


def print_users_table(records: list[tuple[str, str]]) -> None:
    """Вивести вміст бази користувачів у вигляді таблиці."""
    print(f"{'№':>3} | {'Логін':<14} | Хеш SHA-256 (перші 32 символи)")
    print("-" * 56)
    for number, (username, hash_value) in enumerate(records, start=1):
        print(f"{number:>3} | {username:<14} | {hash_value[:32]}...")


def demo_hash_errors() -> None:
    """Продемонструвати генерацію винятків у generate_hash."""
    for password in ("", "Short1!"):
        try:
            generate_hash(password, SALT)
        except ValueError as error:
            print(f"generate_hash({password!r}) -> ValueError: {error}")
        except ValidationError as error:
            print(f"generate_hash({password!r}) -> ValidationError: {error}")


def main() -> None:
    """Головна функція Завдання 3."""
    print(
        f"=== Завдання 3 | {STUDENT_NAME} ({GROUP_NAME}), "
        f"варіант {VARIANT_NUMBER} ==="
    )
    print(
        f"Алгоритм: {HASH_ALGORITHM}, мін. довжина: "
        f"{MIN_PASSWORD_LENGTH}, сіль: {SALT!r}\n"
    )

    users_to_register = (
        ("firko_admin", "Adm1n@Secure2026"),
        ("crypto_lead", "Crypt0#KeyMaster"),
        ("privacy_off", "Pr1vacy!Shield"),
        ("data_sci", "D4ta$cience2026"),
        ("field_eng", "F1eld@Engineer"),
        ("soc_analyst", "S0C#Monitoring"),
        ("pentester", "P3nT3st!Lviv2026"),
        ("auditor", "Aud1t@Compliance"),
        ("dev_ops", "D3vOps$Pipeline"),
        ("student_kb", "KB-202@Python!"),
    )

    print("--- Перевірка винятків generate_hash ---")
    demo_hash_errors()

    try:
        print("\n--- Реєстрація користувачів ---")
        create_users(users_to_register)
        print(f"Записано {len(users_to_register)} користувачів у CSV")

        users_db.clear()
        users_db.extend(read_users())
        print("\n--- Вміст users.csv ---")
        print_users_table(users_db)

        print("\n--- Автентифікація ---")
        attempts = (
            ("firko_admin", "Adm1n@Secure2026"),
            ("crypto_lead", "WrongPassword1"),
            ("ghost_user", "Whatever@12345"),
            ("pentester", "short"),
            ("student_kb", "KB-202@Python!"),
        )
        for username, password in attempts:
            ok = login(username, password)
            print(f"login({username!r}) -> {'SUCCESS' if ok else 'FAILURE'}")

        print("\nСпроба входу з порожнім паролем:")
        login("auditor", "")
    except FileNotFoundError as error:
        print(f"[ПОМИЛКА] Файл не знайдено: {error}")
    except PermissionError as error:
        print(f"[ПОМИЛКА] Немає прав доступу до файлу: {error}")
    except ValidationError as error:
        print(f"[ПОМИЛКА] Пароль не пройшов валідацію: {error}")
    except ValueError as error:
        print(f"[ПОМИЛКА] Некоректні дані: {error}")
    except OSError as error:  # IOError - псевдонім OSError у Python 3
        print(f"[ПОМИЛКА] Помилка вводу/виводу: {error}")

    print(f"\nЖурнал подій збережено у {os.path.relpath(LOG_JSON)}")


if __name__ == "__main__":
    main()
