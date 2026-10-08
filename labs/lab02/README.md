# Лабораторна робота №2 — консольні утиліти для задач кібербезпеки

Студент: Фірко Андрій Богданович, група КБ-202.
**Варіант 8: Фільтр та аналізатор журналів DNS-запитів.**

## Встановлення

З кореня репозиторію `cybersecurity-python-labs` (середовище з ЛР №1):

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

Сторонніх бібліотек код не потребує — лише стандартна бібліотека Python 3.10+;
`ruff` використовується для перевірки стилю.

## Структура

```
labs/lab02/
├── __init__.py
├── main.py          # точка входу: команди demo та analyze (argparse)
├── task1.py         # Завдання 1: User, Admin, Session, AuditLog, UserAccount
├── task2.py         # Завдання 2: аналізатор DNS-запитів (варіант 8)
├── README.md
└── data/
    ├── data_v08/            # каталог варіанта з lab2_data.zip (без змін)
    │   ├── dns_queries.csv  # журнал DNS: Timestamp,ClientIP,Domain,QueryType
    │   └── blacklist.txt    # чорний список доменів, по одному в рядку
    ├── dns_alerts.csv       # результат analyze (створюється, у .gitignore)
    └── dns_analyzer.log     # журнал роботи і тривог (створюється, у .gitignore)
```

## Запуск

Усі команди виконуються з кореня репозиторію.

```bash
# Завдання 1 — демонстрація класів
python -m labs.lab02.main demo

# Завдання 2 — аналіз журналу DNS (типові шляхи вказують на data_v08)
python -m labs.lab02.main analyze

# те саме з явними параметрами
python -m labs.lab02.main analyze \
    --dns-log labs/lab02/data/data_v08/dns_queries.csv \
    --blacklist labs/lab02/data/data_v08/blacklist.txt \
    --out-csv labs/lab02/data/dns_alerts.csv \
    --min-domain-len 50

# довідка
python -m labs.lab02.main analyze --help
```

## Параметри `analyze`

| Параметр | Типово | Опис |
|---|---|---|
| `--dns-log` | `labs/lab02/data/data_v08/dns_queries.csv` | CSV-журнал DNS-транзакцій |
| `--blacklist` | `labs/lab02/data/data_v08/blacklist.txt` | чорний список доменів |
| `--out-csv` | `labs/lab02/data/dns_alerts.csv` | файл звіту з аномаліями |
| `--min-domain-len` | `50` | довжина домену, з якої він вважається аномальним (ціле > 0) |
| `--log-file` | `labs/lab02/data/dns_analyzer.log` | журнал роботи утиліти й тривог |

## Правила виявлення

| Категорія | Умова |
|---|---|
| `BLACKMATCH` | домен або його батьківський домен є в чорному списку |
| `SUSPICIOUS-TLD` | TLD `.zip`, `.mov`, `.top`, `.xyz`, `.click`, `.gq`, `.tk`, `.ml`, `.cf` |
| `LONG-DOMAIN` | довжина домену ≥ `--min-domain-len` |
| `LONG-LABEL` | окремий піддомен довший за 30 символів |
| `DGA-DETECT` | мітка ≥ 12 символів з літер і цифр, ентропія Шеннона ≥ 3.0 біт/символ |
| `TUNNEL-SUSPECT` | TXT-запит до довгого або випадкового імені (можливий DNS-тунель) |
| `INVALID` | порушено синтаксис DNS-імені (напр. мітка > 63 символів, RFC 1035) |

## Поведінка при помилках

* файл не знайдено / немає прав доступу — `[ERROR] ...`, код завершення 1;
* у CSV бракує обов'язкових колонок або немає жодного коректного запису —
  `[ERROR] Invalid input data ...`, код 1;
* рядок із некоректною датою пропускається з `[WARNING] Line N skipped`;
* неправильний `--min-domain-len` (не число або ≤ 0) — помилка `argparse`,
  код 2;
* не вдалося записати звіт — `[ERROR] Cannot write report`, код 1.
