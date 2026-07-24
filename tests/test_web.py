import pytest
from fastapi.testclient import TestClient

from web import app


client = TestClient(app, raise_server_exceptions=False)


def test_generate_rejects_non_integer_count():
    response = client.post(
        "/generate",
        data={"mode": "random", "count": "many", "length": "12", "lower": "on"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "count must be an integer"


@pytest.mark.parametrize("count", ["0", "21"])
def test_generate_rejects_count_outside_allowed_range(count):
    response = client.post(
        "/generate",
        data={"mode": "random", "count": count, "length": "12", "lower": "on"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "count must be between 1 and 20"


def test_generate_rejects_non_integer_password_length():
    response = client.post(
        "/generate",
        data={"mode": "random", "count": "1", "length": "long", "lower": "on"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "length must be an integer"


def test_generate_rejects_non_integer_word_count():
    response = client.post(
        "/generate",
        data={
            "mode": "passphrase",
            "count": "1",
            "word_count": "several",
            "separator": "-",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "word_count must be an integer"


def test_generate_rejects_unknown_mode():
    response = client.post(
        "/generate",
        data={"mode": "unsupported", "count": "1", "length": "12", "lower": "on"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "mode must be 'random' or 'passphrase'"


def test_generate_requires_a_character_set():
    response = client.post(
        "/generate",
        data={"mode": "random", "count": "1", "length": "12"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "select at least one character type"


def test_generate_rejects_unsupported_separator():
    response = client.post(
        "/generate",
        data={
            "mode": "passphrase",
            "count": "1",
            "word_count": "4",
            "separator": "unexpected",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "separator is not supported"
