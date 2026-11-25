"""Тести CLI (main.py): локальний режим, помилки та коди завершення."""

import json
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main
from labs.lab04.tests.conftest import SAMPLE_PATH

CVE_ID = "CVE-2099-10001"


def forbid_network(monkeypatch):
    """Будь-яке звернення до клієнта NVD провалить тест."""
    fake = Mock(side_effect=AssertionError("мережевий запит заборонено"))
    monkeypatch.setattr(api_client, "fetch_response", fake)
    return fake


def test_local_run_prints_report(monkeypatch, capsys):
    """Локальний запуск друкує JSON-звіт і не звертається до мережі."""
    fake = forbid_network(monkeypatch)

    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)])
    out, err = capsys.readouterr()

    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["cve_id"] == CVE_ID
    assert report["variant"] == 8
    assert report["score"] == 9.8
    assert report["observed"] == "UNCHANGED"
    assert report["decision"] == "other"
    fake.assert_not_called()


def test_local_not_found_exits_0(monkeypatch, tmp_path, capsys):
    """Порожній результат - звіт not_found і код 0."""
    forbid_network(monkeypatch)
    path = tmp_path / "empty.json"
    path.write_text('{"vulnerabilities": []}', encoding="utf-8")

    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "not_found"


def test_missing_file(monkeypatch, tmp_path, capsys):
    """Відсутній файл - повідомлення у stderr і код 1."""
    forbid_network(monkeypatch)
    missing = tmp_path / "missing.json"

    assert main.main(["--cve", CVE_ID, "--input", str(missing)]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "файл не знайдено" in err
    assert "Traceback" not in err


def test_invalid_json_file(monkeypatch, tmp_path, capsys):
    """Некоректний JSON у файлі - повідомлення і код 1."""
    forbid_network(monkeypatch)
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "коректним JSON" in err


def test_invalid_structure_exits_1(monkeypatch, tmp_path, capsys):
    """Невідповідний cve.id - помилка даних і код 1."""
    forbid_network(monkeypatch)
    path = tmp_path / "other.json"
    path.write_text(
        json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2000-0001"}}]}),
        encoding="utf-8",
    )

    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 1
    assert "некоректна структура" in capsys.readouterr().err


@pytest.mark.parametrize(
    "cve",
    ["cve-2099-10001", "CVE-99-10001", "CVE-2099-123", "CVE-2099-10001 "],
)
def test_bad_cve_format_exits_2(cve, capsys):
    """Неправильний формат --cve - код 2."""
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", cve])
    assert exc_info.value.code == 2
    assert "CVE-YYYY-NNNN" in capsys.readouterr().err


def test_missing_cve_exits_2():
    """Без --cve argparse завершується з кодом 2."""
    with pytest.raises(SystemExit) as exc_info:
        main.main([])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, True, "8"])
def test_invalid_variant_exits_2(monkeypatch, capsys, variant):
    """Некоректний VARIANT_NUMBER - код 2."""
    forbid_network(monkeypatch)
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)

    assert main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)]) == 2
    assert "VARIANT_NUMBER" in capsys.readouterr().err


def test_network_mode_uses_client(monkeypatch, capsys):
    """Без --input використовується клієнт NVD."""
    fake = Mock(return_value={"vulnerabilities": []})
    monkeypatch.setattr(api_client, "fetch_response", fake)

    assert main.main(["--cve", CVE_ID]) == 0
    fake.assert_called_once_with(CVE_ID)
    assert json.loads(capsys.readouterr().out)["decision"] == "not_found"


def test_http_error_message_has_only_status(monkeypatch, capsys):
    """HTTP-помилка: лише код статусу, без ключа й тіла."""
    monkeypatch.setenv("NVD_API_KEY", "fake-secret-key")
    error_response = Mock(spec=requests.Response)
    error_response.status_code = 503
    response = Mock(spec=requests.Response)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "503 Server Error: body with details", response=error_response
    )
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )

    assert main.main(["--cve", CVE_ID]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "503" in err
    assert "fake-secret-key" not in err
    assert "body with details" not in err


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (requests.exceptions.ReadTimeout, "час очікування"),
        (requests.exceptions.ConnectionError, "з'єднатися"),
    ],
)
def test_network_errors_exit_1(monkeypatch, capsys, exception, message):
    """Мережеві помилки - зрозуміле повідомлення і код 1."""
    monkeypatch.setattr(
        api_client.requests, "get", Mock(side_effect=exception("details"))
    )

    assert main.main(["--cve", CVE_ID]) == 1
    err = capsys.readouterr().err
    assert message in err
    assert "details" not in err
