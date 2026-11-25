"""Побудова синтетичних відповідей NVD для тестів."""

from typing import Any

CVE_ID = "CVE-2099-10001"


def make_metric(
    score: Any = 9.5,
    scope: Any = "CHANGED",
    metric_type: str = "Primary",
    source: str = "nvd@nist.gov",
) -> dict[str, Any]:
    """Одна оцінка cvssMetricV31 із заданими baseScore і scope."""
    return {
        "source": source,
        "type": metric_type,
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "baseScore": score,
            "attackVector": "NETWORK",
            "scope": scope,
        },
    }


def make_payload(
    metrics: Any = None,
    status: Any = "Analyzed",
    cve_id: str = CVE_ID,
) -> dict[str, Any]:
    """Відповідь NVD з одним записом; metrics=None - без поля metrics."""
    cve: dict[str, Any] = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": "Synthetic test record."}],
    }
    if status is not None:
        cve["vulnStatus"] = status
    if metrics is not None:
        cve["metrics"] = metrics
    return {"vulnerabilities": [{"cve": cve}]}


def v31(*metric_list: dict[str, Any]) -> dict[str, Any]:
    """Обгорнути оцінки в metrics.cvssMetricV31."""
    return {"cvssMetricV31": list(metric_list)}
