# Лабораторна робота №3 — Web API на FastAPI та SQLite

Студент: Фірко Андрій Богданович, група КБ-202.
**Варіант 8: Облік часу відновлення сервісів.**

## Предметна область

Сервіс обліку навчальних вимірювань відновлення сервісів.

| Поле | Значення |
|---|---|
| `categories` | сервіс: `database`, `web_service`, `file_storage` |
| `code` | унікальний код вимірювання, формат `V08-NN` |
| `title` | назва вимірювання, наприклад `Вимірювання відновлення 01` |
| `value` | час відновлення у **хвилинах** (`float`, ≥ 0, скінченне) |
| `status` | стан перевірки: `new`, `in_progress`, `done` |

Поріг — **60.0 хв**: довше відновлення вважається повільним
(вибірка повільних: `GET /records?min_value=60`). Параметри варіанта
зібрано в `config.py`.

## Структура

```
labs/lab03/
├── __init__.py
├── main.py          # FastAPI-застосунок, обробники помилок, /ping, /student
├── database.py      # з'єднання (PRAGMA foreign_keys = ON) і виконання schema.sql
├── schema.sql       # готова схема: categories + records (варіанти 7–9)
├── repository.py    # параметризовані SQL-запити, транзакції
├── schemas.py       # Pydantic-моделі запитів і відповідей
├── config.py        # одиниця, поріг, обмеження варіанта
├── seed.py          # початкове заповнення з data/seed.json
├── routers/
│   ├── categories.py
│   └── records.py
└── data/
    ├── seed.json        # навчальні дані варіанта 8 (у Git)
    └── lab3.sqlite3     # створюється програмою (у .gitignore)
```

## Встановлення

З кореня репозиторію `cybersecurity-python-labs`:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Запуск

```bash
python -m labs.lab03.database   # створити таблиці (необов'язково, seed теж створює)
python -m labs.lab03.seed       # 3 категорії та 8 записів; повторний запуск нічого не змінює
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Документація: <http://127.0.0.1:8000/docs> (Swagger UI) та
<http://127.0.0.1:8000/openapi.json>.

## Маршрути

| Метод і маршрут | Успіх | Помилки |
|---|---|---|
| `GET /ping` | 200 `{"status": "ok"}` | |
| `GET /student` | 200 | |
| `GET /categories` | 200 | |
| `POST /categories` | 201 | 409, 422 |
| `DELETE /categories/{category_id}` | 204 | 404, 409, 422 |
| `GET /records` | 200 | 422 |
| `GET /records/{record_id}` | 200 | 404, 422 |
| `POST /records` | 201 | 404, 409, 422 |
| `PUT /records/{record_id}` | 200 | 404, 409, 422 |
| `DELETE /records/{record_id}` | 204 | 404, 422 |
| `POST /records/bulk` | 201 | 404, 409, 422 (жоден запис не зберігається) |

Параметри `GET /records`: `category_id` (> 0), `status`, `min_value` (≥ 0),
`q` (1–120 символів, буквальний підрядок у `title`), `limit` (1–100, типово
20), `offset` (≥ 0). Фільтри об'єднуються через `AND`, сортування за `id`.

## Приклади запитів

```bash
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"
curl -i "http://127.0.0.1:8000/records?min_value=60"

curl -i -X POST "http://127.0.0.1:8000/records" \
  -H "Content-Type: application/json" \
  -d '{"code":"V08-TEST","title":"Навчальне вимірювання","category_id":1,"value":42.5,"status":"new"}'

curl -i -X PUT "http://127.0.0.1:8000/records/9" \
  -H "Content-Type: application/json" \
  -d '{"code":"V08-TEST","title":"Навчальне вимірювання","category_id":2,"value":61.0,"status":"done"}'

curl -i -X DELETE "http://127.0.0.1:8000/records/9"

# Пакет скасовується повністю: V08-01 уже є в базі -> 409, V08-ROLLBACK не збережено
curl -i -X POST "http://127.0.0.1:8000/records/bulk" \
  -H "Content-Type: application/json" \
  -d '[{"code":"V08-ROLLBACK","title":"Перший елемент","category_id":1,"value":4.0,"status":"new"},{"code":"V08-01","title":"Дублікат коду","category_id":2,"value":5.0,"status":"new"}]'
```

У Windows PowerShell зручніше виконувати запити через Swagger UI.

## Перевірка стилю

```bash
ruff check labs/lab03
ruff format --check labs/lab03
```
