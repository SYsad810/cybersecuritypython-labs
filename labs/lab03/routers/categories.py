"""Маршрути /categories: список, створення й видалення сервісів."""

from typing import Annotated

from fastapi import APIRouter, Path, Response, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead, ErrorMessage

router = APIRouter(prefix="/categories", tags=["categories"])

CategoryId = Annotated[int, Path(gt=0, description="id категорії (> 0)")]


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Список категорій",
    description="Усі категорії (сервіси) за зростанням id.",
)
def list_categories() -> list[dict]:
    """Повернути всі категорії."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
    responses={409: {"model": ErrorMessage, "description": "Назва зайнята"}},
)
def create_category(category: CategoryCreate) -> dict:
    """Створити нову категорію; id призначає база."""
    return repository.create_category(category.name)


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Видалити порожню категорію",
    responses={
        404: {"model": ErrorMessage, "description": "Категорію не знайдено"},
        409: {
            "model": ErrorMessage,
            "description": "Категорія містить записи",
        },
    },
)
def delete_category(category_id: CategoryId) -> Response:
    """Видалити категорію, у якій немає записів."""
    repository.delete_category(category_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
