"""FastAPI-застосунок ЛР №3 (варіант 8): облік часу відновлення сервісів.

Запуск з кореня репозиторію:
    python -m labs.lab03.seed
    uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
"""

import logging
import math
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from labs.lab03 import config
from labs.lab03.database import initialize_database
from labs.lab03.repository import (
    ConflictError,
    DataValidationError,
    NotFoundError,
)
from labs.lab03.routers import categories, records
from labs.lab03.schemas import PingResponse, StudentInfo
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logger = logging.getLogger("labs.lab03")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску, не змінюючи дані."""
    initialize_database()
    yield


app = FastAPI(
    title=f"ЛР №3 — {config.VARIANT_TITLE}",
    description=(
        f"{config.DOMAIN_DESCRIPTION}\n\n"
        f"**Одиниця вимірювання:** {config.UNIT}. "
        f"**Поріг:** {config.THRESHOLD} хв — довше відновлення вважається "
        "повільним.\n\n"
        f"Виконав: {STUDENT_NAME}, {GROUP_NAME}, варіант {VARIANT_NUMBER}."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


def _json_safe(value: Any) -> Any:
    """Замінити нескінченні числа та NaN на рядок, щоб JSON був коректним."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    return value


@app.exception_handler(RequestValidationError)
def handle_validation_error(
    _: Request, error: RequestValidationError
) -> JSONResponse:
    """Помилка моделі чи параметра - 422 (також для value = 1e309)."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": _json_safe(jsonable_encoder(error.errors()))},
    )


@app.exception_handler(NotFoundError)
def handle_not_found(_: Request, error: NotFoundError) -> JSONResponse:
    """Неіснуючий запис або категорія - 404."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(error)}
    )


@app.exception_handler(ConflictError)
def handle_conflict(_: Request, error: ConflictError) -> JSONResponse:
    """Дублікат або непорожня категорія - 409."""
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT, content={"detail": str(error)}
    )


@app.exception_handler(DataValidationError)
def handle_data_error(_: Request, error: DataValidationError) -> JSONResponse:
    """Порушення CHECK-обмеження бази - 422."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": str(error)},
    )


@app.exception_handler(sqlite3.Error)
def handle_database_error(_: Request, error: sqlite3.Error) -> JSONResponse:
    """Технічна помилка бази: деталі - у журнал, клієнту - коротко."""
    logger.error("Database error: %r", error)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Внутрішня помилка сервера"},
    )


@app.get("/ping", response_model=PingResponse, summary="Перевірка API")
def ping() -> dict[str, str]:
    """Перевірити доступність API."""
    return {"status": "ok"}


@app.get("/student", response_model=StudentInfo, summary="Дані студента")
def student() -> dict[str, str | int]:
    """Повернути ПІБ, групу та варіант із shared/student.py."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
