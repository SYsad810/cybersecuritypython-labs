"""Маршрути /records: CRUD, фільтри та пакетне додавання вимірювань."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, Response, status

from labs.lab03 import config, repository
from labs.lab03.schemas import (
    ErrorMessage,
    RecordCreate,
    RecordRead,
    RecordReplace,
    Status,
)

router = APIRouter(prefix="/records", tags=["records"])

RecordId = Annotated[int, Path(gt=0, description="id запису (> 0)")]

NOT_FOUND = {404: {"model": ErrorMessage, "description": "Не знайдено"}}
CONFLICT = {409: {"model": ErrorMessage, "description": "Дублікат code"}}


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список вимірювань з фільтрами",
    description="Фільтри об'єднуються через AND, сортування за id.",
)
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи цього сервісу")
    ] = None,
    status_filter: Annotated[
        Status | None,
        Query(alias="status", description="Лише записи з цим статусом"),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=config.VALUE_MIN,
            le=config.VALUE_MAX,
            allow_inf_nan=False,
            description=f"value >= min_value ({config.UNIT})",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=config.TITLE_MAX,
            description="Підрядок у title (з урахуванням регістру)",
        ),
    ] = None,
    limit: Annotated[
        int, Query(ge=1, le=config.MAX_LIMIT, description="Кількість записів")
    ] = config.DEFAULT_LIMIT,
    offset: Annotated[
        int, Query(ge=0, description="Скільки записів пропустити")
    ] = 0,
) -> list[dict]:
    """Повернути сторінку вимірювань, що відповідають фільтрам."""
    return repository.list_records(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення (атомарно)",
    description="Усі записи пакета зберігаються в одній транзакції "
    "або не зберігається жоден.",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(
    records: Annotated[
        list[RecordCreate],
        Body(min_length=config.BULK_MIN, max_length=config.BULK_MAX),
    ],
) -> list[dict]:
    """Додати від 1 до 100 записів атомарно."""
    return repository.create_records_bulk(
        [record.model_dump() for record in records]
    )


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати вимірювання",
    responses=NOT_FOUND,
)
def get_record(record_id: RecordId) -> dict:
    """Повернути один запис за id."""
    return repository.get_record(record_id)


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити вимірювання",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(record: RecordCreate) -> dict:
    """Створити запис; категорія має існувати."""
    return repository.create_record(record.model_dump())


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю замінити вимірювання",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, record: RecordReplace) -> dict:
    """Замінити всі змінювані поля запису; id не змінюється."""
    return repository.replace_record(record_id, record.model_dump())


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Видалити вимірювання",
    responses=NOT_FOUND,
)
def delete_record(record_id: RecordId) -> Response:
    """Видалити запис за id."""
    repository.delete_record(record_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
