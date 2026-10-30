"""Шар доступу до даних: параметризовані SQL-запити до categories і records.

Модуль не залежить від FastAPI: помилки даних він повідомляє власними
винятками NotFoundError і ConflictError, а шар API перетворює їх на HTTP-коди.
Кожна функція відкриває з'єднання, виконує операцію й закриває його.
"""

import logging
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from typing import Any

from labs.lab03.database import get_connection

logger = logging.getLogger(__name__)

RECORD_FIELDS = ("code", "title", "category_id", "value", "status")

# Спільна частина SELECT для читання записів разом з назвою категорії
SELECT_RECORDS = """
    SELECT r.id, r.code, r.title, r.category_id, r.value, r.status,
           c.name AS category_name
    FROM records AS r
    JOIN categories AS c ON c.id = r.category_id
"""


class RepositoryError(Exception):
    """Базова помилка шару даних."""


class NotFoundError(RepositoryError):
    """Запис або категорія не існує."""


class ConflictError(RepositoryError):
    """Порушено унікальність або категорія містить записи."""


class DataValidationError(RepositoryError):
    """Дані не пройшли CHECK-обмеження бази."""


@contextmanager
def open_connection() -> Iterator[sqlite3.Connection]:
    """Відкрити з'єднання (поля за назвою) і гарантовано закрити."""
    with closing(get_connection()) as connection:
        connection.row_factory = sqlite3.Row
        yield connection


def translate_integrity_error(
    error: sqlite3.IntegrityError,
) -> RepositoryError:
    """Перетворити IntegrityError SQLite на зрозумілу помилку шару даних."""
    message = str(error)
    logger.warning("SQLite integrity error: %s", message)
    if "UNIQUE" in message:
        if "categories.name" in message:
            return ConflictError("Категорія з такою назвою вже існує")
        return ConflictError("Запис з таким code вже існує")
    if "FOREIGN KEY" in message:
        return NotFoundError("Категорію не знайдено")
    return DataValidationError("Дані не відповідають обмеженням бази")


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    return row is not None


def _require_categories(
    connection: sqlite3.Connection, category_ids: set[int]
) -> None:
    """Перевірити, що всі категорії існують, інакше NotFoundError."""
    missing = [
        category_id
        for category_id in sorted(category_ids)
        if not _category_exists(connection, category_id)
    ]
    if missing:
        ids = ", ".join(str(category_id) for category_id in missing)
        raise NotFoundError(f"Категорію не знайдено (id: {ids})")


def _fetch_record(
    connection: sqlite3.Connection, record_id: int
) -> dict[str, Any] | None:
    row = connection.execute(
        SELECT_RECORDS + " WHERE r.id = ?", (record_id,)
    ).fetchone()
    return dict(row) if row is not None else None


def _record_params(data: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(data[name] for name in RECORD_FIELDS)


# --- Категорії --------------------------------------------------------------


def list_categories() -> list[dict[str, Any]]:
    """Повернути всі категорії за зростанням id."""
    with open_connection() as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


def create_category(name: str) -> dict[str, Any]:
    """Створити категорію; id призначає база."""
    with open_connection() as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (name,)
                )
        except sqlite3.IntegrityError as error:
            raise translate_integrity_error(error) from error
    return {"id": cursor.lastrowid, "name": name}


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію.

    NotFoundError, якщо її немає; ConflictError, якщо вона містить записи.
    """
    with open_connection() as connection:
        try:
            with connection:
                if not _category_exists(connection, category_id):
                    raise NotFoundError("Категорію не знайдено")
                used = connection.execute(
                    "SELECT 1 FROM records WHERE category_id = ? LIMIT 1",
                    (category_id,),
                ).fetchone()
                if used is not None:
                    raise ConflictError(
                        "Категорія містить записи, видалення заборонено"
                    )
                connection.execute(
                    "DELETE FROM categories WHERE id = ?", (category_id,)
                )
        except sqlite3.IntegrityError as error:
            # ON DELETE RESTRICT - захист на рівні бази
            raise ConflictError(
                "Категорія містить записи, видалення заборонено"
            ) from error


# --- Записи -----------------------------------------------------------------


def get_record(record_id: int) -> dict[str, Any]:
    """Повернути запис за id разом з category_name."""
    with open_connection() as connection:
        record = _fetch_record(connection, record_id)
    if record is None:
        raise NotFoundError("Запис не знайдено")
    return record


def list_records(
    *,
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Повернути записи з фільтрами (через AND) і поділом на сторінки.

    SQL-фрагменти беруться лише з наперед визначених рядків, а всі значення
    передаються окремим списком параметрів.
    """
    conditions: list[str] = []
    params: list[Any] = []
    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        # instr - буквальний пошук з урахуванням регістру, без шаблонів % і _
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    sql = SELECT_RECORDS
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY r.id LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with open_connection() as connection:
        rows = connection.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def count_records() -> int:
    """Повернути загальну кількість записів."""
    with open_connection() as connection:
        (count,) = connection.execute(
            "SELECT COUNT(*) FROM records"
        ).fetchone()
    return count


def create_record(data: Mapping[str, Any]) -> dict[str, Any]:
    """Додати запис; категорія має існувати, code - бути унікальним."""
    with open_connection() as connection:
        try:
            with connection:
                _require_categories(connection, {data["category_id"]})
                cursor = connection.execute(
                    "INSERT INTO records "
                    "(code, title, category_id, value, status) "
                    "VALUES (?, ?, ?, ?, ?)",
                    _record_params(data),
                )
        except sqlite3.IntegrityError as error:
            raise translate_integrity_error(error) from error
        record = _fetch_record(connection, cursor.lastrowid)
    if record is None:  # pragma: no cover - запис щойно створено
        raise NotFoundError("Запис не знайдено")
    return record


def replace_record(record_id: int, data: Mapping[str, Any]) -> dict[str, Any]:
    """Повністю замінити змінювані поля запису; id не змінюється."""
    with open_connection() as connection:
        try:
            with connection:
                exists = connection.execute(
                    "SELECT 1 FROM records WHERE id = ?", (record_id,)
                ).fetchone()
                if exists is None:
                    raise NotFoundError("Запис не знайдено")
                _require_categories(connection, {data["category_id"]})
                connection.execute(
                    "UPDATE records SET code = ?, title = ?, "
                    "category_id = ?, value = ?, status = ? WHERE id = ?",
                    (*_record_params(data), record_id),
                )
        except sqlite3.IntegrityError as error:
            raise translate_integrity_error(error) from error
        record = _fetch_record(connection, record_id)
    if record is None:  # pragma: no cover - запис перевірено вище
        raise NotFoundError("Запис не знайдено")
    return record


def delete_record(record_id: int) -> None:
    """Видалити запис; NotFoundError, якщо його немає."""
    with open_connection() as connection, connection:
        exists = connection.execute(
            "SELECT 1 FROM records WHERE id = ?", (record_id,)
        ).fetchone()
        if exists is None:
            raise NotFoundError("Запис не знайдено")
        connection.execute("DELETE FROM records WHERE id = ?", (record_id,))


def create_records_bulk(
    items: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Додати пакет записів в одній транзакції: усі або жодного.

    Дублікат code у пакеті чи в базі - ConflictError, неіснуюча
    категорія - NotFoundError. За будь-якої помилки with connection
    виконує rollback, тож жоден елемент пакета не зберігається.
    """
    codes = [item["code"] for item in items]
    if len(codes) != len(set(codes)):
        raise ConflictError("Пакет містить повторювані code")

    with open_connection() as connection:
        try:
            with connection:
                _require_categories(
                    connection, {item["category_id"] for item in items}
                )
                new_ids = []
                for item in items:
                    cursor = connection.execute(
                        "INSERT INTO records "
                        "(code, title, category_id, value, status) "
                        "VALUES (?, ?, ?, ?, ?)",
                        _record_params(item),
                    )
                    new_ids.append(cursor.lastrowid)
                # Один commit для всього пакета - під час виходу з with
        except sqlite3.IntegrityError as error:
            raise translate_integrity_error(error) from error
        records = [_fetch_record(connection, new_id) for new_id in new_ids]
    return [record for record in records if record is not None]
