"""Тести api_client.py: requests.get підмінено там, де його шукає клієнт."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID = "CVE-2099-10001"


def fake_response(status=200, payload=None):
    """Двійник успішної відповіді Requests."""
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


def test_headers_without_key():
    """Без ключа - лише заголовок Accept."""
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_fake_key(monkeypatch):
    """Вигаданий ключ очищується від пробілів і йде в apiKey."""
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-test-key",
    }


def test_blank_key_is_ignored(monkeypatch):
    """Ключ із самих пробілів означає запуск без ключа."""
    monkeypatch.setenv("NVD_API_KEY", "   ")
    assert "apiKey" not in api_client.build_headers()


def test_fetch_uses_expected_request(monkeypatch):
    """Клієнт передає cveId, заголовки, таймаут і вимикає редиректи."""
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = fake_response(payload=payload)
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response(CVE_ID) == payload
    fake_get.assert_called_once_with(
        URL,
        params={"cveId": CVE_ID},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_key_in_header_not_url(monkeypatch):
    """Ключ передається в заголовку, а не в параметрах URL."""
    monkeypatch.setenv("NVD_API_KEY", "fake-test-key")
    fake_get = Mock(return_value=fake_response(payload={}))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    api_client.fetch_response(CVE_ID)
    kwargs = fake_get.call_args.kwargs
    assert kwargs["headers"]["apiKey"] == "fake-test-key"
    assert kwargs["params"] == {"cveId": CVE_ID}


def test_http_error_is_raised(monkeypatch):
    """HTTPError від raise_for_status() передається далі."""
    response = fake_response(status=503)
    error_response = Mock(spec=requests.Response)
    error_response.status_code = 503
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "503 Server Error", response=error_response
    )
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )

    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api_client.fetch_response(CVE_ID)
    assert exc_info.value.response.status_code == 503
    response.json.assert_not_called()


@pytest.mark.parametrize(
    "exception",
    [requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError],
)
def test_network_errors_are_raised(monkeypatch, exception):
    """Таймаут і помилка з'єднання передаються далі."""
    monkeypatch.setattr(
        api_client.requests, "get", Mock(side_effect=exception("boom"))
    )
    with pytest.raises(exception):
        api_client.fetch_response(CVE_ID)


def test_redirect_status_is_rejected(monkeypatch):
    """Статус 301 без перенаправлення не приймається."""
    response = fake_response(status=301)
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )
    with pytest.raises(api_client.UnexpectedStatusError) as exc_info:
        api_client.fetch_response(CVE_ID)
    assert exc_info.value.status_code == 301


def test_invalid_json_is_raised(monkeypatch):
    """Неправильний JSON спричиняє JSONDecodeError."""
    response = fake_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )
    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response(CVE_ID)


def test_real_network_is_blocked():
    """Справжні запити Requests заборонено фікстурою."""
    # Автоматична фікстура прибрала Session.request
    with pytest.raises(AttributeError):
        requests.get(URL, timeout=1)
