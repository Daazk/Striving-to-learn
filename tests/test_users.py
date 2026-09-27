from datetime import timedelta

import pytest

from tests.helpers import auth_header, make_token

ME = "/api/v1/users/me"


def test_me_returns_current_user(client, tokens):
    response = client.get(ME, headers=auth_header(tokens["access_token"]))

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "user@example.com"
    assert set(body) == {"id", "email"}


def test_me_without_token(client):
    response = client.get(ME)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_me_with_refresh_token(client, tokens):
    response = client.get(ME, headers=auth_header(tokens["refresh_token"]))
    assert response.status_code == 401


@pytest.mark.parametrize(
    "token",
    [
        "garbage",
        make_token(expires_in=timedelta(minutes=-1)),
        make_token(key="wrong-secret-key-wrong-secret-key"),
        make_token(sub="not-a-number"),
    ],
    ids=["garbage", "expired", "wrong-signature", "bad-sub"],
)
def test_me_with_invalid_token(client, token):
    response = client.get(ME, headers=auth_header(token))

    assert response.status_code == 401


def test_me_with_token_of_deleted_user(client):
    response = client.get(ME, headers=auth_header(make_token(sub="999")))
    assert response.status_code == 401
