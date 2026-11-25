"""Перевірка відповіді NVD і правило аналізу за варіантом.

Функції працюють лише з переданими аргументами: не читають файлів,
змінних середовища чи часу, не виконують HTTP-запитів, нічого не друкують
і не змінюють отриманий payload.
"""

import copy
import math
from typing import Any

# Правило кожного варіанта: (поріг T, поле cvssData, очікуване значення)
VARIANT_RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}

# Допустимі значення полів cvssData (CVSS v3.1)
ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset(
        {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}
    ),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}

REJECTED = "Rejected"


def _optional_text(container: dict[str, Any], key: str, where: str) -> Any:
    """Повернути None для відсутнього поля або непорожній рядок."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}.{key} має бути непорожнім рядком")
    return value


def _english_description(cve: dict[str, Any]) -> str | None:
    """Перший непорожній англійський опис або None."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise ValueError("cve.descriptions має бути списком")
    found = None
    for item in descriptions:
        if not isinstance(item, dict):
            raise ValueError("елемент descriptions має бути об'єктом")
        lang, value = item.get("lang"), item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise ValueError("descriptions: lang і value мають бути рядками")
        if found is None and lang == "en" and value.strip():
            found = value
    return found


def _validate_score(cvss_data: dict[str, Any]) -> float | None:
    """Повернути baseScore (None, якщо відсутній) або підняти ValueError."""
    if "baseScore" not in cvss_data:
        return None
    score = cvss_data["baseScore"]
    # bool є підкласом int, тому перевіряємо його окремо
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError("baseScore має бути числом")
    if not math.isfinite(score) or not 0 <= score <= 10:
        raise ValueError("baseScore має бути скінченним числом від 0 до 10")
    return float(score)


def _select_metric(metrics_list: list[Any]) -> dict[str, Any]:
    """Перша оцінка type="Primary", а за її відсутності - перша в списку."""
    for item in metrics_list:
        if not isinstance(item, dict):
            raise ValueError("елемент cvssMetricV31 має бути об'єктом")
    for item in metrics_list:
        if item.get("type") == "Primary":
            return item
    return metrics_list[0]


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Перевірити metrics і повернути дані вибраної оцінки CVSS v3.1."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise ValueError("cve.metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    metrics_list = metrics["cvssMetricV31"]
    if not isinstance(metrics_list, list):
        raise ValueError("metrics.cvssMetricV31 має бути списком")
    if not metrics_list:
        return None

    metric = _select_metric(metrics_list)
    cvss_data = metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise ValueError("cvssData має бути об'єктом")
    version = _optional_text(cvss_data, "version", "cvssData")
    if version is not None and version != "3.1":
        raise ValueError('cvssData.version має дорівнювати "3.1"')
    return {
        "score": _validate_score(cvss_data),
        "source": _optional_text(metric, "source", "cvssMetricV31"),
        "version": version,
        "vector": _optional_text(cvss_data, "vectorString", "cvssData"),
        # Копія, щоб звіт не залежав від подальших змін payload
        "data": copy.deepcopy(cvss_data),
    }


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевірити відповідь NVD і повернути внутрішній запис або None.

    Формат запису:
        {
            "cve_id": str,              # ідентифікатор із відповіді
            "vuln_status": str | None,  # vulnStatus або None
            "description": str | None,  # перший непорожній опис "en"
            "cvss": None | {            # вибрана оцінка CVSS v3.1
                "score": float | None,  # baseScore
                "source": str | None,   # source вибраної оцінки
                "version": str | None,  # cvssData.version ("3.1")
                "vector": str | None,   # cvssData.vectorString
                "data": dict,           # копія cvssData для правила
            },
        }
    Для статусів Rejected і відсутнього оцінки не аналізуються (cvss=None).
    None означає, що запис не знайдено. Порушення контракту - ValueError.
    """
    if not isinstance(payload, dict):
        raise ValueError("відповідь має бути JSON-об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("vulnerabilities має бути списком")
    if not vulnerabilities:
        return None
    if len(vulnerabilities) > 1:
        raise ValueError("очікувався не більше ніж один запис vulnerabilities")

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise ValueError("елемент vulnerabilities має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("cve.id не збігається із запитаним ідентифікатором")

    status = _optional_text(cve, "vulnStatus", "cve")
    record: dict[str, Any] = {
        "cve_id": cve_id,
        "vuln_status": status,
        "description": _english_description(cve),
        "cvss": None,
    }
    if status is not None and status != REJECTED:
        record["cvss"] = _extract_cvss(cve)
    return record


def _validate_variant(variant: Any) -> tuple[float, str, str]:
    if isinstance(variant, bool) or not isinstance(variant, int):
        raise ValueError("номер варіанта має бути цілим числом")
    if variant not in VARIANT_RULES:
        raise ValueError("номер варіанта має бути від 1 до 15")
    return VARIANT_RULES[variant]


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосувати правило варіанта й повернути словник звіту.

    decision: not_found, rejected, insufficient_data, review або other.
    """
    threshold, field, expected = _validate_variant(variant)
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]
    if record["vuln_status"] == REJECTED:
        report["decision"] = "rejected"
        return report
    report["decision"] = "insufficient_data"
    cvss = record["cvss"]
    if record["vuln_status"] is None or cvss is None:
        return report

    report["cvss_version"] = cvss["version"]
    report["score"] = cvss["score"]
    report["score_source"] = cvss["source"]
    report["vector"] = cvss["vector"]
    if field not in cvss["data"]:
        return report
    observed = cvss["data"][field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"cvssData.{field} має недопустиме значення")
    report["observed"] = observed
    if cvss["score"] is None:
        return report

    # Число й ознака - з однієї й тієї самої вибраної оцінки
    matches = cvss["score"] >= threshold and observed == expected
    report["decision"] = "review" if matches else "other"
    return report
