import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from app.core.config import settings

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class InvalidTokenError(Exception):
    pass


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _create_token(
    user_id: int, token_type: str, lifetime: timedelta
) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + lifetime
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "iat": now,
        "exp": expires_at,
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return token, expires_at


def create_access_token(user_id: int) -> str:
    token, _ = _create_token(
        user_id,
        ACCESS_TOKEN_TYPE,
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return token


def create_refresh_token(user_id: int) -> tuple[str, datetime]:
    return _create_token(
        user_id,
        REFRESH_TOKEN_TYPE,
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def decode_token(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub", "type"]},
        )

    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    if payload["type"] != expected_type:
        raise InvalidTokenError("Invalid token type")
    return payload
