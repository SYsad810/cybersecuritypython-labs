"""Консольна утиліта: запис NVD про вразливість -> JSON-звіт (варіант 8).

Запуск з кореня репозиторію:
    python -m labs.lab04.main --cve CVE-2099-10001 \
        --input labs/lab04/data/nvd_sample.json
    python -m labs.lab04.main --cve CVE-2021-44228
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def cve_id(value: str) -> str:
    """Тип argparse: повний збіг з CVE-YYYY-NNNN+ (регістр важливий)."""
    if not CVE_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "очікується ідентифікатор у форматі CVE-YYYY-NNNN"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Створити парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Аналіз запису NVD про вразливість за правилом варіанта",
    )
    parser.add_argument(
        "--cve", required=True, type=cve_id, help="ідентифікатор CVE"
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="локальна JSON-відповідь NVD (без мережевого запиту)",
    )
    return parser


def load_response(path: Path) -> Any:
    """Прочитати UTF-8 JSON-файл із відповіддю NVD."""
    return json.loads(path.read_text(encoding="utf-8"))


def error(message: str) -> None:
    """Вивести пояснення помилки у stderr."""
    print(f"Помилка: {message}", file=sys.stderr)


def valid_variant(variant: Any) -> bool:
    """Перевірити, що варіант - ціле число 1..15, але не bool."""
    return (
        isinstance(variant, int)
        and not isinstance(variant, bool)
        and 1 <= variant <= 15
    )


def get_payload(args: argparse.Namespace) -> Any:
    """Отримати відповідь з файла або з NVD; помилки обробляє main()."""
    if args.input is not None:
        return load_response(args.input)
    return api_client.fetch_response(args.cve)


def main(argv: list[str] | None = None) -> int:
    """Розібрати аргументи, отримати дані, вивести звіт; повернути код."""
    if not valid_variant(VARIANT_NUMBER):
        error("VARIANT_NUMBER у shared/student.py має бути цілим від 1 до 15")
        return 2
    args = build_parser().parse_args(argv)

    try:
        payload = get_payload(args)
    except FileNotFoundError:
        error(f"файл не знайдено: {args.input}")
        return 1
    except UnicodeDecodeError:
        error("файл не є текстом у кодуванні UTF-8")
        return 1
    except json.JSONDecodeError:
        # requests.exceptions.JSONDecodeError теж є його підкласом
        error("відповідь не є коректним JSON")
        return 1
    except requests.exceptions.Timeout:
        error("перевищено час очікування відповіді NVD")
        return 1
    except requests.exceptions.ConnectionError:
        error("не вдалося з'єднатися з NVD")
        return 1
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        error(f"NVD повернув HTTP-помилку {status}")
        return 1
    except api_client.UnexpectedStatusError as exc:
        error(f"NVD повернув неочікуваний статус {exc.status_code}")
        return 1
    except requests.exceptions.RequestException:
        error("помилка HTTP-запиту до NVD")
        return 1
    except OSError:
        # Після винятків Requests: вони теж є підкласами OSError
        error(f"не вдалося прочитати файл: {args.input}")
        return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        error(f"некоректна структура даних: {exc}")
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
