# Лабораторна робота №4 — клієнт NVD API, аналіз CVSS і тести

Студент: Фірко Андрій Богданович, група КБ-202.
**Варіант 8: зміна меж впливу.**

Утиліта шукає запис про вразливість у NVD CVE API 2.0 за ідентифікатором
CVE, перевіряє відповідь, вибирає оцінку CVSS v3.1 і формує JSON-звіт за
правилом варіанта.

## Правило варіанта 8

```
score >= 9.0  і  cvssData["scope"] == "CHANGED"
```

`scope` (CVSS v3.1) показує, чи виходить вплив вразливості за межі
повноважень уразливого компонента: `UNCHANGED` — ні, `CHANGED` — так
(наприклад, атака на застосунок зачіпає хост або інші компоненти).
Оцінка й ознака беруться з однієї вибраної оцінки: перша з
`type="Primary"`, а якщо такої немає — перша в `cvssMetricV31`.

## Структура

```
labs/lab04/
├── __init__.py
├── main.py            # аргументи, отримання даних, повідомлення, коди
├── api_client.py      # заголовки та один GET-запит до NVD
├── analysis.py        # перевірка відповіді та правило варіанта
├── data/
│   └── nvd_sample.json    # синтетичний запис CVE-2099-10001
├── tests/
│   ├── conftest.py        # заборона мережі, видалення NVD_API_KEY
│   ├── helpers.py         # побудова синтетичних відповідей
│   ├── test_analysis.py
│   ├── test_api_client.py
│   └── test_main.py
└── README.md
```

## Встановлення

З кореня репозиторію `cybersecurity-python-labs` (Python 3.12+):

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Запуск

```bash
# Локальний режим (без мережі)
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json

# Один запит до NVD
python -m labs.lab04.main --cve CVE-2021-44228
```

Необов'язковий ключ NVD задається змінною середовища `NVD_API_KEY` і
передається в заголовку `apiKey` (не в URL). Ключ не зберігайте у файлах
проєкту.

| Код | Значення |
|---|---|
| 0 | звіт сформовано (зокрема `not_found`, `insufficient_data`) |
| 1 | помилка отримання, читання чи перевірки даних |
| 2 | неправильні аргументи або номер варіанта |

## Формат звіту

```json
{
  "cve_id": "CVE-2099-10001",
  "variant": 8,
  "description": "Synthetic vulnerability for offline API testing.",
  "vuln_status": "Analyzed",
  "cvss_version": "3.1",
  "score": 9.8,
  "score_source": "nvd@nist.gov",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "rule": {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
  "observed": "UNCHANGED",
  "decision": "other"
}
```

`decision`: `not_found` → `rejected` → `insufficient_data` → `review` /
`other`. Стани `other` і `insufficient_data` не означають, що вразливість
безпечна.

## Перевірка

```bash
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```

Тести не звертаються до мережі: `conftest.py` прибирає
`requests.sessions.Session.request`, а HTTP-клієнт перевіряється підміною
`api_client.requests.get`.
