from datetime import timedelta

import jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_token
from app.models import RefreshSession, User
from tests.helpers import USER, make_token

AUTH = "/api/v1/auth"


# Register
def test_register_success(client):
    response = client.post(f"{AUTH}/register", json=USER)

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == USER["email"]
    assert "id" in body
    assert "password" not in body and "hashed_password" not in body


def test_register_duplicate_email_case_insensitive(client):
    client.post(f"{AUTH}/register", json=USER)
    response = client.post(
        f"{AUTH}/register", json={**USER, "email": USER["email"].upper()}
    )

    assert response.status_code == 409


def test_register_invalid_email(client):
    response = client.post(f"{AUTH}/register", json={**USER, "email": "not-an-email"})
    assert response.status_code == 422


def test_register_short_password(client):
    response = client.post(f"{AUTH}/register", json={**USER, "password": "123"})
    assert response.status_code == 422


def test_password_is_stored_as_bcrypt_hash(client, db):
    client.post(f"{AUTH}/register", json=USER)

    user = db.scalar(select(User))
    assert user.hashed_password != USER["password"]
    assert user.hashed_password.startswith("$2b$")


# Login


def test_login_success(client):
    client.post(f"{AUTH}/register", json=USER)
    response = client.post(f"{AUTH}/login", json=USER)

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


def test_login_wrong_password_and_unknown_email_look_the_same(client):
    client.post(f"{AUTH}/register", json=USER)
    wrong_password = client.post(
        f"{AUTH}/login", json={**USER, "password": "wrong_password"}
    )
    unknown_email = client.post(
        f"{AUTH}/login", json={**USER, "email": "nobody@example.com"}
    )

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


def test_login_stores_refresh_token_hash_not_token(tokens, db):
    session = db.scalar(select(RefreshSession))

    assert session.token_hash == hash_token(tokens["refresh_token"])
    assert session.token_hash != tokens["refresh_token"]
    assert session.revoked_at is None


def test_token_lifetimes(tokens):
    options = {"verify_signature": False}
    access = jwt.decode(tokens["access_token"], options=options)
    refresh = jwt.decode(tokens["refresh_token"], options=options)

    assert access["exp"] - access["iat"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert (
        refresh["exp"] - refresh["iat"]
        == settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )


# Refresh
def test_refresh_returns_new_pair(client, tokens):
    response = client.post(
        f"{AUTH}/refresh", json={"refresh_token": tokens["refresh_token"]}
    )

    assert response.status_code == 200
    new_tokens = response.json()
    assert new_tokens["refresh_token"] != tokens["refresh_token"]
    assert new_tokens["access_token"] != tokens["access_token"]


def test_refresh_token_cannot_be_reused(client, tokens):
    body = {"refresh_token": tokens["refresh_token"]}
    client.post(f"{AUTH}/refresh", json=body)
    response = client.post(f"{AUTH}/refresh", json=body)

    assert response.status_code == 401


def test_refresh_with_access_token_fails(client, tokens):
    response = client.post(
        f"{AUTH}/refresh", json={"refresh_token": tokens["access_token"]}
    )

    assert response.status_code == 401


def test_refresh_with_garbage_fails(client):
    response = client.post(f"{AUTH}/refresh", json={"refresh_token": "garbage"})
    assert response.status_code == 401


def test_refresh_with_expired_token_fails(client):
    expired = make_token(token_type="refresh", expires_in=timedelta(minutes=-1))
    response = client.post(f"{AUTH}/refresh", json={"refresh_token": expired})
    assert response.status_code == 401


# Logout
def test_logout_revokes_refresh_token(client, tokens, db):
    body = {"refresh_token": tokens["refresh_token"]}
    response = client.post(f"{AUTH}/logout", json=body)

    assert response.status_code == 204
    assert client.post(f"{AUTH}/refresh", json=body).status_code == 401
    assert db.scalar(select(RefreshSession)).revoked_at is not None


def test_logout_is_idempotent(client, tokens):
    body = {"refresh_token": tokens["refresh_token"]}
    client.post(f"{AUTH}/logout", json=body)
    response = client.post(f"{AUTH}/logout", json=body)

    assert response.status_code == 204


def test_logout_with_garbage_fails(client):
    response = client.post(f"{AUTH}/logout", json={"refresh_token": "garbage"})
    assert response.status_code == 401
