import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import app.models
from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from tests.helpers import USER

if not settings.TEST_DATABASE_URL:
    pytest.exit("TEST_DATABASE_URL is not set in .env", returncode=1)

test_engine = create_engine(settings.TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False)


def override_get_db():
    db = TestingSessionLocal()

    try:
        yield db

    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)
    yield
    Base.metadata.drop_all(test_engine)


@pytest.fixture(autouse=True)
def clean_tables():
    yield
    with test_engine.begin() as conn:
        conn.execute(text("TRUNCATE users, refresh_sessions RESTART IDENTITY CASCADE"))


@pytest.fixture
def db():
    with TestingSessionLocal() as session:
        yield session


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def tokens(client):
    client.post("/api/v1/auth/register", json=USER)
    response = client.post("/api/v1/auth/login", json=USER)

    return response.json()
