from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import settings

USER = {"email": "user@example.com", "password": "secret123"}


def make_token(
    sub: str = "1",
    token_type: str = "access",
    expires_in: timedelta = timedelta(minutes=5),
    key: str | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": sub, "type": token_type, "iat": now, "exp": now + expires_in}
    return jwt.encode(
        payload, key or settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
