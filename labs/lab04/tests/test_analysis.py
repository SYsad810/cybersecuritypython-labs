"""Тести analysis.py (варіант 8: score >= 9.0 і scope == CHANGED)."""

import copy
import math

import pytest

from labs.lab04.analysis import build_report, extract_record
from labs.lab04.tests.helpers import CVE_ID, make_metric, make_payload, v31

VARIANT = 8


def report_for(payload):
    """Повний шлях аналізу для варіанта 8."""
    return build_report(extract_record(payload, CVE_ID), CVE_ID, VARIANT)


# --- Межа порога та ознака --------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (8.9, "other"),  # нижче порога
        (9.0, "review"),  # рівно на порозі: перевіряє >=, а не >
        (9.1, "review"),  # вище порога
        (10.0, "review"),
    ],
)
def test_threshold_with_changed_scope(score, expected):
    """Нижче порога - other; на порозі й вище за scope=CHANGED - review."""
    report = report_for(make_payload(v31(make_metric(score=score))))
    assert report["decision"] == expected
    assert report["observed"] == "CHANGED"
    assert report["score"] == score


def test_unchanged_scope_with_high_score_is_other():
    """Висока оцінка з невідповідною ознакою UNCHANGED дає other."""
    report = report_for(
        make_payload(v31(make_metric(score=10.0, scope="UNCHANGED")))
    )
    assert report["decision"] == "other"
    assert report["observed"] == "UNCHANGED"


def test_sample_file_gives_other_for_variant_8(sample_payload):
    """Синтетичний файл для варіанта 8 дає повний звіт зі станом other."""
    report = report_for(sample_payload)
    assert report == {
        "cve_id": CVE_ID,
        "variant": 8,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
        "observed": "UNCHANGED",
        "decision": "other",
    }


# --- Стани not_found, rejected, insufficient_data ----------------------------


def test_not_found():
    """Порожній vulnerabilities - not_found; rule заповнено, решта null."""
    report = report_for({"vulnerabilities": []})
    assert report["decision"] == "not_found"
    assert report["rule"] == {
        "threshold": 9.0,
        "field": "scope",
        "expected": "CHANGED",
    }
    for key in ("description", "vuln_status", "score", "observed", "vector"):
        assert report[key] is None


def test_rejected_ignores_high_score():
    """Rejected дає rejected навіть за високої оцінки."""
    payload = make_payload(v31(make_metric(score=10.0)), status="Rejected")
    report = report_for(payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic test record."
    assert report["score"] is None
    assert report["observed"] is None


def test_rejected_does_not_validate_broken_metrics():
    """Для Rejected оцінки не аналізуються взагалі."""
    payload = make_payload({"cvssMetricV31": "broken"}, status="Rejected")
    assert report_for(payload)["decision"] == "rejected"


def test_missing_status_is_insufficient():
    """Без vulnStatus - insufficient_data без аналізу оцінок."""
    payload = make_payload(v31(make_metric(score=10.0)), status=None)
    report = report_for(payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None


@pytest.mark.parametrize(
    "metrics",
    [None, {}, {"cvssMetricV31": []}, {"cvssMetricV2": [{"x": 1}]}],
    ids=["no-metrics", "no-v31", "empty-v31", "only-v2"],
)
def test_missing_score_is_insufficient(metrics):
    """Відсутня оцінка CVSS v3.1 означає брак даних."""
    report = report_for(make_payload(metrics))
    assert report["decision"] == "insufficient_data"
    assert report["score"] is None


def test_missing_scope_field_is_insufficient():
    """Відсутнє поле scope означає брак даних."""
    metric = make_metric(score=9.8)
    del metric["cvssData"]["scope"]
    report = report_for(make_payload(v31(metric)))
    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None
    assert report["score"] == 9.8


def test_missing_base_score_is_insufficient():
    """Відсутній baseScore означає брак даних."""
    metric = make_metric()
    del metric["cvssData"]["baseScore"]
    report = report_for(make_payload(v31(metric)))
    assert report["decision"] == "insufficient_data"
    assert report["observed"] == "CHANGED"


# --- Некоректні дані -> ValueError ------------------------------------------


@pytest.mark.parametrize(
    "score",
    ["9.8", True, None, math.nan, math.inf, -0.1, 10.1],
    ids=["str", "bool", "null", "nan", "inf", "negative", "above-10"],
)
def test_invalid_score_raises(score):
    """Некоректний baseScore спричиняє ValueError."""
    with pytest.raises(ValueError):
        report_for(make_payload(v31(make_metric(score=score))))


@pytest.mark.parametrize(
    "scope",
    [None, "changed", "PARTIAL", 1],
    ids=["null", "lower", "bad", "int"],
)
def test_invalid_scope_raises(scope):
    """Значення null чи недопустимий scope спричиняють ValueError."""
    with pytest.raises(ValueError):
        report_for(make_payload(v31(make_metric(scope=scope))))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": [{"cve": {"id": "CVE-2099-99999"}}]},
        {"vulnerabilities": [{"cve": "text"}]},
        {
            "vulnerabilities": [
                {"cve": {"id": CVE_ID}},
                {"cve": {"id": CVE_ID}},
            ]
        },
    ],
    ids=["list", "empty", "null", "other-id", "cve-str", "two-records"],
)
def test_invalid_structure_raises(payload):
    """Порушення структури відповіді спричиняє ValueError."""
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    "metrics",
    [
        "text",
        {"cvssMetricV31": None},
        {"cvssMetricV31": {"a": 1}},
        {"cvssMetricV31": ["not-a-dict"]},
    ],
    ids=["metrics-str", "v31-null", "v31-dict", "item-str"],
)
def test_invalid_metrics_type_raises(metrics):
    """Неправильний тип metrics або cvssMetricV31 - ValueError."""
    with pytest.raises(ValueError):
        extract_record(make_payload(metrics), CVE_ID)


def test_metrics_null_raises():
    """Значення metrics = null є помилкою, а не браком даних."""
    payload = make_payload()
    payload["vulnerabilities"][0]["cve"]["metrics"] = None
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    ("key", "value"),
    [("version", "3.0"), ("version", ""), ("vectorString", 5)],
)
def test_invalid_report_fields_raise(key, value):
    """Некоректні version чи vectorString спричиняють ValueError."""
    metric = make_metric()
    metric["cvssData"][key] = value
    with pytest.raises(ValueError):
        extract_record(make_payload(v31(metric)), CVE_ID)


def test_empty_status_raises():
    """Порожній vulnStatus спричиняє ValueError."""
    with pytest.raises(ValueError):
        extract_record(make_payload(status=""), CVE_ID)


@pytest.mark.parametrize("variant", [0, 16, True, "8", 8.0])
def test_invalid_variant_raises(variant):
    """Номер варіанта поза 1..15 або не int спричиняє ValueError."""
    with pytest.raises(ValueError):
        build_report(None, CVE_ID, variant)


# --- Вибір оцінки -----------------------------------------------------------


def test_primary_has_priority_over_preceding_secondary():
    """Primary має пріоритет над попередньою Secondary."""
    secondary = make_metric(
        score=10.0, scope="CHANGED", metric_type="Secondary", source="vendor"
    )
    primary = make_metric(score=5.0, scope="UNCHANGED")
    report = report_for(make_payload(v31(secondary, primary)))
    assert report["score_source"] == "nvd@nist.gov"
    assert report["score"] == 5.0
    assert report["decision"] == "other"


def test_first_metric_without_primary():
    """Без Primary вибирається перша оцінка списку."""
    first = make_metric(score=9.5, metric_type="Secondary", source="first")
    second = make_metric(
        score=1.0, scope="UNCHANGED", metric_type="Secondary", source="second"
    )
    report = report_for(make_payload(v31(first, second)))
    assert report["score_source"] == "first"
    assert report["decision"] == "review"


def test_missing_optional_fields_are_null():
    """Відсутні source, version і vectorString дають null."""
    metric = make_metric()
    del metric["source"]
    del metric["cvssData"]["version"]
    del metric["cvssData"]["vectorString"]
    report = report_for(make_payload(v31(metric)))
    assert report["score_source"] is None
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["decision"] == "review"


# --- Опис і незмінність payload ---------------------------------------------


def test_first_non_empty_english_description():
    """Вибирається перший непорожній англійський опис."""
    payload = make_payload(v31(make_metric()))
    payload["vulnerabilities"][0]["cve"]["descriptions"] = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "First English text."},
        {"lang": "en", "value": "Second English text."},
    ]
    assert report_for(payload)["description"] == "First English text."


def test_payload_is_not_modified(sample_payload):
    """Аналіз не змінює отриманий payload."""
    original = copy.deepcopy(sample_payload)
    report_for(sample_payload)
    assert sample_payload == original
