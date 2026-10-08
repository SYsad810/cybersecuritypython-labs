"""Завдання 2 (варіант 8): фільтр та аналізатор журналів DNS-запитів."""

from __future__ import annotations

import argparse
import csv
import logging
import math
import re
import sys
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("dns_analyzer")
# Окремий логер тривог: пише лише у файл журналу
alert_logger = logging.getLogger("dns_analyzer.alerts")

DATA_DIR = Path(__file__).resolve().parent / "data"
VARIANT_DIR = DATA_DIR / "data_v08"
DEFAULT_DNS_LOG = VARIANT_DIR / "dns_queries.csv"
DEFAULT_BLACKLIST = VARIANT_DIR / "blacklist.txt"
DEFAULT_OUT_CSV = DATA_DIR / "dns_alerts.csv"
DEFAULT_MIN_DOMAIN_LEN = 50
DEFAULT_LOG_FILE = DATA_DIR / "dns_analyzer.log"

REQUIRED_COLUMNS = ("Timestamp", "ClientIP", "Domain", "QueryType")
KNOWN_QUERY_TYPES = ("A", "AAAA", "TXT", "MX")

# Пороги евристик
MAX_LABEL_LEN = 30  # довгий окремий піддомен (RFC дозволяє до 63)
DGA_MIN_LABEL_LEN = 12
DGA_MIN_ENTROPY = 3.0  # біт на символ
MAX_DNS_LABEL_LEN = 63  # обмеження RFC 1035

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z][a-z0-9-]{1,62}$"
)
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)
# TLD, які часто використовуються у фішингу та шкідливих кампаніях
SUSPICIOUS_TLD_RE = re.compile(r"\.(zip|mov|top|xyz|click|gq|tk|ml|cf)$")
# Випадковий набір літер і цифр (обов'язково з цифрами) - ознака DGA
DGA_LABEL_RE = re.compile(r"^(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]+$")

CSV_FIELDS = (
    "timestamp",
    "client_ip",
    "domain",
    "query_type",
    "length",
    "categories",
    "reasons",
)


@dataclass(frozen=True)
class DnsQuery:
    """Один запис журналу DNS-транзакцій."""

    timestamp: datetime
    client_ip: str
    domain: str
    query_type: str


@dataclass
class Finding:
    """Аномальний DNS-запит і причини, з яких його позначено."""

    query: DnsQuery
    categories: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def add(self, category: str, reason: str) -> None:
        """Додати категорію (без повторів) і пояснення."""
        if category not in self.categories:
            self.categories.append(category)
        self.reasons.append(reason)


def positive_int(value: str) -> int:
    """Тип для argparse: ціле число > 0."""
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"'{value}' не є цілим числом"
        ) from error
    if number <= 0:
        raise argparse.ArgumentTypeError("значення має бути більше 0")
    return number


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Зареєструвати CLI-аргументи утиліти."""
    parser.add_argument(
        "--dns-log",
        type=Path,
        default=DEFAULT_DNS_LOG,
        help="CSV-журнал DNS (Timestamp,ClientIP,Domain,QueryType)",
    )
    parser.add_argument(
        "--blacklist",
        type=Path,
        default=DEFAULT_BLACKLIST,
        help="файл чорного списку доменів (один домен у рядку)",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=DEFAULT_OUT_CSV,
        help="куди зберегти знайдені аномалії (CSV)",
    )
    parser.add_argument(
        "--min-domain-len",
        type=positive_int,
        default=DEFAULT_MIN_DOMAIN_LEN,
        help="мінімальна довжина домену, що вважається аномальною "
        f"(типово {DEFAULT_MIN_DOMAIN_LEN})",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="файл журналу роботи утиліти та тривог",
    )


def setup_logging(log_file: Path) -> None:
    """Консоль: [LEVEL] message; файл: усі події разом із тривогами."""
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    for handler in logger.handlers + alert_logger.handlers:
        handler.close()
    logger.handlers[:] = [console, file_handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    alert_logger.handlers[:] = [file_handler]
    alert_logger.setLevel(logging.WARNING)
    alert_logger.propagate = False


def normalize_domain(domain: str) -> str:
    """Привести домен до нижнього регістру без кінцевої крапки."""
    return domain.strip().lower().rstrip(".")


def load_blacklist(path: Path) -> set[str]:
    """Зчитати чорний список, ігноруючи порожні рядки та коментарі."""
    blacklist = set()
    with path.open(encoding="utf-8") as file:
        for line in file:
            entry = normalize_domain(line.split("#", 1)[0])
            if entry:
                blacklist.add(entry)
    return blacklist


def read_dns_log(path: Path) -> Iterator[DnsQuery]:
    """Порядково зчитати журнал DNS (генератор), пропускаючи биті рядки."""
    with path.open(encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        missing = set(REQUIRED_COLUMNS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"У файлі {path.name} бракує колонок: "
                f"{', '.join(sorted(missing))}"
            )
        for line_no, row in enumerate(reader, start=2):
            try:
                query = DnsQuery(
                    timestamp=datetime.fromisoformat(row["Timestamp"]),
                    client_ip=row["ClientIP"].strip(),
                    domain=normalize_domain(row["Domain"]),
                    query_type=row["QueryType"].strip().upper(),
                )
            except (ValueError, AttributeError) as error:
                logger.warning("Line %d skipped: %s", line_no, error)
                continue
            if not IPV4_RE.match(query.client_ip):
                logger.warning(
                    "Line %d: invalid client IP %r", line_no, query.client_ip
                )
            yield query


def shannon_entropy(text: str) -> float:
    """Обчислити ентропію Шеннона рядка (біт на символ)."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def blacklist_match(domain: str, blacklist: set[str]) -> str | None:
    """Повернути запис чорного списку, якому відповідає домен або предок."""
    labels = domain.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in blacklist:
            return candidate
    return None


def inspect_query(
    query: DnsQuery, blacklist: set[str], min_domain_len: int
) -> Finding | None:
    """Застосувати всі правила до запиту; None - якщо запит чистий."""
    finding = Finding(query)
    domain = query.domain

    labels = domain.split(".")
    too_long = [lb for lb in labels if len(lb) > MAX_DNS_LABEL_LEN]
    if too_long:
        finding.add(
            "INVALID",
            f"label of {len(too_long[0])} chars exceeds "
            f"{MAX_DNS_LABEL_LEN} (RFC 1035)",
        )
    elif not DOMAIN_RE.match(domain):
        finding.add("INVALID", "domain does not match DNS name syntax")

    matched = blacklist_match(domain, blacklist)
    if matched:
        finding.add("BLACKMATCH", f"blacklisted ({matched})")

    tld = SUSPICIOUS_TLD_RE.search(domain)
    if tld:
        finding.add("SUSPICIOUS-TLD", f"suspicious TLD .{tld.group(1)}")

    if len(domain) >= min_domain_len:
        finding.add(
            "LONG-DOMAIN",
            f"domain length {len(domain)} >= {min_domain_len}",
        )

    for label in labels[:-1]:
        if len(label) > MAX_LABEL_LEN:
            finding.add(
                "LONG-LABEL", f"label of {len(label)} chars > {MAX_LABEL_LEN}"
            )
        entropy = shannon_entropy(label)
        if (
            len(label) >= DGA_MIN_LABEL_LEN
            and DGA_LABEL_RE.match(label)
            and entropy >= DGA_MIN_ENTROPY
        ):
            finding.add(
                "DGA-DETECT",
                f"random-looking label (entropy {entropy:.2f} bit/char)",
            )

    if query.query_type == "TXT" and (
        "LONG-DOMAIN" in finding.categories
        or "LONG-LABEL" in finding.categories
        or "DGA-DETECT" in finding.categories
    ):
        finding.add("TUNNEL-SUSPECT", "TXT query to long/random name")

    return finding if finding.categories else None


def print_type_breakdown(type_counter: Counter[str], total: int) -> None:
    """Вивести статистику запитів за типами."""
    print("\n=== Query Type Breakdown ===")
    order = list(KNOWN_QUERY_TYPES) + sorted(
        set(type_counter) - set(KNOWN_QUERY_TYPES)
    )
    for qtype in order:
        count = type_counter.get(qtype, 0)
        share = count / total * 100 if total else 0.0
        print(f"{qtype:<5}: {count:>3} ({share:.1f}%)")


def print_findings(findings: list[Finding]) -> None:
    """Вивести підозрілі запити у форматі сповіщень."""
    print("\n=== Suspicious DNS Activity ===")
    if not findings:
        print("No suspicious queries found.")
        return
    for item in findings:
        q = item.query
        tags = " ".join(f"[{c}]" for c in item.categories)
        print(f"{tags} Client {q.client_ip} -> {q.domain} ({q.query_type})")
        print(f"    reasons: {'; '.join(item.reasons)}")


def export_csv(findings: list[Finding], path: Path) -> None:
    """Записати аномальні запити у CSV-файл."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for item in findings:
            q = item.query
            writer.writerow(
                {
                    "timestamp": q.timestamp.isoformat(),
                    "client_ip": q.client_ip,
                    "domain": q.domain,
                    "query_type": q.query_type,
                    "length": len(q.domain),
                    "categories": "|".join(item.categories),
                    "reasons": "; ".join(item.reasons),
                }
            )


def display_path(path: Path) -> str:
    """Показати шлях відносно поточного каталогу, якщо це можливо."""
    try:
        return path.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return str(path)


def analyze(args: argparse.Namespace) -> int:
    """Запустити аналіз; повернути код завершення (0 - успіх)."""
    setup_logging(args.log_file)
    try:
        blacklist = load_blacklist(args.blacklist)
        logger.info(
            "Loaded %d blacklist entries from %s",
            len(blacklist),
            display_path(args.blacklist),
        )
        logger.info("Parsing DNS log file %s...", display_path(args.dns_log))

        type_counter: Counter[str] = Counter()
        findings: list[Finding] = []
        first = last = None
        for query in read_dns_log(args.dns_log):
            type_counter[query.query_type] += 1
            first = first or query.timestamp
            last = query.timestamp
            finding = inspect_query(query, blacklist, args.min_domain_len)
            if finding:
                findings.append(finding)
                logger.debug("Suspicious: %s", query.domain)
    except FileNotFoundError as error:
        logger.error("File not found: %s", error.filename)
        return 1
    except PermissionError as error:
        logger.error("Permission denied: %s", error.filename)
        return 1
    except (ValueError, UnicodeDecodeError) as error:
        logger.error("Invalid input data: %s", error)
        return 1

    total = sum(type_counter.values())
    if total == 0:
        logger.error("DNS log contains no valid records")
        return 1
    logger.info(
        "Processed %d DNS query records (%s - %s).", total, first, last
    )

    print_type_breakdown(type_counter, total)
    print_findings(findings)

    categories = Counter(c for f in findings for c in f.categories)
    print("\n=== Summary ===")
    print(f"Suspicious queries : {len(findings)} of {total}")
    for category, count in categories.most_common():
        print(f"  {category:<15}: {count}")

    for item in findings:
        alert_logger.warning(
            "%s %s from %s",
            "/".join(item.categories),
            item.query.domain,
            item.query.client_ip,
        )

    try:
        export_csv(findings, args.out_csv)
    except OSError as error:
        logger.error("Cannot write report: %s", error)
        return 1
    logger.info(
        "Suspicious records exported to %s", display_path(args.out_csv)
    )
    logger.info("Audit log written to %s", display_path(args.log_file))
    return 0
