"""HTTP-клієнт NVD CVE API 2.0: заголовки та один GET-запит."""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# (час на встановлення з'єднання, час очікування між порціями даних)
REQUEST_TIMEOUT = (3.05, 10)


class UnexpectedStatusError(Exception):
    """Сервер відповів без помилки, але статусом, відмінним від 200."""

    def __init__(self, status_code: int) -> None:
        """Зберегти код статусу без тіла відповіді та заголовків."""
        super().__init__(f"неочікуваний HTTP-статус {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повернути заголовки запиту.

    Accept є завжди; apiKey додається, лише якщо змінна середовища
    NVD_API_KEY містить непорожнє значення. Змінна читається під час
    виклику, а не під час імпорту модуля.
    """
    headers = {"Accept": "application/json"}
    api_key = (os.getenv("NVD_API_KEY") or "").strip()
    if api_key:
        # Ключ передається заголовком, а не в URL і не як Bearer
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконати один GET-запит до NVD і повернути декодований JSON.

    Винятки Requests (таймаут, з'єднання, HTTPError, JSONDecodeError)
    і UnexpectedStatusError не перехоплюються: їх обробляє main().
    """
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    # 3xx не піднімає HTTPError, тому перевіряємо статус окремо
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
