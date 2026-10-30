"""Pydantic-моделі запитів і відповідей API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03 import config

Status = Literal["new", "in_progress", "done"]


class StrictInput(BaseModel):
    """Базова модель вхідних даних: обрізання пробілів, без зайвих полів."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")


class CategoryCreate(StrictInput):
    """Тіло запиту на створення категорії (сервісу)."""

    name: str = Field(
        min_length=config.CATEGORY_NAME_MIN,
        max_length=config.CATEGORY_NAME_MAX,
        description="Назва сервісу, наприклад database",
        examples=["mail_service"],
    )


class CategoryRead(BaseModel):
    """Категорія у відповіді API."""

    id: int = Field(gt=0)
    name: str


class RecordCreate(StrictInput):
    """Тіло запиту на створення вимірювання відновлення."""

    code: str = Field(
        min_length=config.CODE_MIN,
        max_length=config.CODE_MAX,
        description="Унікальний код вимірювання",
        examples=["V08-TEST"],
    )
    title: str = Field(
        min_length=config.TITLE_MIN,
        max_length=config.TITLE_MAX,
        description="Назва вимірювання",
        examples=["Навчальне вимірювання"],
    )
    category_id: int = Field(gt=0, description="id сервісу", examples=[1])
    value: float = Field(
        ge=config.VALUE_MIN,
        le=config.VALUE_MAX,
        allow_inf_nan=False,
        description=f"Час відновлення, {config.UNIT}",
        examples=[42.5],
    )
    status: Status = Field(description="Стан перевірки вимірювання")


class RecordReplace(RecordCreate):
    """Тіло PUT-запиту: усі змінювані поля обов'язкові."""


class RecordRead(RecordCreate):
    """Вимірювання у відповіді API разом з id і назвою категорії."""

    model_config = ConfigDict(extra="ignore")

    id: int = Field(gt=0)
    category_name: str


class SeedCategory(StrictInput):
    """Категорія з початкового набору даних (id задано явно)."""

    id: int = Field(gt=0)
    name: str = Field(
        min_length=config.CATEGORY_NAME_MIN,
        max_length=config.CATEGORY_NAME_MAX,
    )


class SeedData(StrictInput):
    """Структура файлу data/seed.json."""

    categories: list[SeedCategory] = Field(min_length=1)
    records: list[RecordCreate] = Field(min_length=1)


class StudentInfo(BaseModel):
    """Дані студента з shared/student.py."""

    student_name: str
    group_name: str
    variant_number: int


class PingResponse(BaseModel):
    """Відповідь перевірки доступності."""

    status: Literal["ok"]


class ErrorMessage(BaseModel):
    """Тіло відповіді з помилкою."""

    detail: str
