from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import (
    REFRESH_TOKEN_TYPE,
    InvalidTokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.db.session import get_db
from app.models import RefreshSession, User
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenPair
from app.schemas.user import UserOut

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _invalid_refresh_token() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _issue_tokens(db: Session, user_id: int) -> TokenPair:
    access_token = create_access_token(user_id)
    refresh_token, expires_at = create_refresh_token(user_id)
    db.add(
        RefreshSession(
            user_id=user_id,
            token_hash=hash_token(refresh_token),
            expires_at=expires_at,
        )
    )
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    user = User(email=data.email.lower(), hashed_password=hash_password(data.password))
    db.add(user)

    try:
        db.commit()

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    db.refresh(user)
    return user


@router.post("/login", response_model=TokenPair)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if user is None or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    tokens = _issue_tokens(db, user.id)
    db.commit()
    return tokens


@router.post("/refresh", response_model=TokenPair)
def refresh(data: RefreshRequest, db: Session = Depends(get_db)):
    try:
        decode_token(data.refresh_token, REFRESH_TOKEN_TYPE)

    except InvalidTokenError:
        raise _invalid_refresh_token()

    session = db.scalar(
        select(RefreshSession)
        .where(RefreshSession.token_hash == hash_token(data.refresh_token))
        .with_for_update()
    )

    now = datetime.now(timezone.utc)
    if session is None or session.revoked_at is not None or session.expires_at <= now:
        raise _invalid_refresh_token()

    session.revoked_at = now
    tokens = _issue_tokens(db, session.user_id)
    db.commit()
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(data: RefreshRequest, db: Session = Depends(get_db)):
    try:
        decode_token(data.refresh_token, REFRESH_TOKEN_TYPE)

    except InvalidTokenError:
        raise _invalid_refresh_token()

    session = db.scalar(
        select(RefreshSession).where(
            RefreshSession.token_hash == hash_token(data.refresh_token)
        )
    )
    if session is not None and session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        db.commit()
