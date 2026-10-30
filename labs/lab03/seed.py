"""Початкове заповнення бази з data/seed.json в одній транзакції.

Запуск з кореня репозиторію:
    python -m labs.lab03.seed
"""

import json
import sqlite3
import sys
from pathlib import Path

from pydantic import ValidationError

from labs.lab03.database import BASE_DIR, initialize_database
from labs.lab03.repository import RECORD_FIELDS, open_connection
from labs.lab03.schemas import SeedData

SEED_PATH = BASE_DIR / "data" / "seed.json"


def load_seed(path: Path = SEED_PATH) -> SeedData:
    """Прочитати JSON і перевірити його структуру та значення."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    data = SeedData.model_validate(raw)

    category_ids = [category.id for category in data.categories]
    if len(category_ids) != len(set(category_ids)):
        raise ValueError("повторювані id категорій")
    unknown = {r.category_id for r in data.records} - set(category_ids)
    if unknown:
        raise ValueError(f"записи посилаються на відсутні категорії {unknown}")
    codes = [record.code for record in data.records]
    if len(codes) != len(set(codes)):
        raise ValueError("повторювані code записів")
    return data


def seed_database(data: SeedData) -> bool:
    """Заповнити порожню базу. Повернути False, якщо дані вже є."""
    with open_connection() as connection, connection:
        (categories,) = connection.execute(
            "SELECT COUNT(*) FROM categories"
        ).fetchone()
        (records,) = connection.execute(
            "SELECT COUNT(*) FROM records"
        ).fetchone()
        if categories or records:
            return False
        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(category.id, category.name) for category in data.categories],
        )
        connection.executemany(
            "INSERT INTO records (code, title, category_id, value, status) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                tuple(getattr(record, name) for name in RECORD_FIELDS)
                for record in data.records
            ],
        )
    return True


def main() -> int:
    """Створити таблиці та заповнити базу навчальними даними."""
    try:
        initialize_database()
        data = load_seed()
    except FileNotFoundError:
        print(f"[ERROR] Файл не знайдено: {SEED_PATH.name}")
        return 1
    except (json.JSONDecodeError, ValidationError, ValueError) as error:
        print(f"[ERROR] Некоректні початкові дані: {error}")
        return 1
    except sqlite3.Error as error:
        print(f"[ERROR] Не вдалося створити базу: {error}")
        return 1

    try:
        inserted = seed_database(data)
    except sqlite3.Error as error:
        # with connection уже скасував усю транзакцію
        print(f"[ERROR] Заповнення скасовано, базу не змінено: {error}")
        return 1

    if not inserted:
        print("[INFO] База вже містить дані - повторне заповнення пропущено.")
        return 0
    print(
        f"[INFO] Додано категорій: {len(data.categories)}, "
        f"записів: {len(data.records)}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
