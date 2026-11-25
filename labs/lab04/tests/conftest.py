"""Спільні фікстури тестів ЛР №4."""

import json
from pathlib import Path
from typing import Any

import pytest

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Без успадкованого ключа й без справжніх запитів Requests."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload() -> dict[str, Any]:
    """Новий словник синтетичної відповіді для кожного тесту."""
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
