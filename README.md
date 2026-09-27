# JWT Auth Service

Аутентификация на FastAPI + PostgreSQL: access/refresh JWT, bcrypt, миграции Alembic.

## Запуск

```bash
cp .env.example .env   # заполнить значения, JWT_SECRET_KEY сгенерировать:
                       # python -c "import secrets; print(secrets.token_urlsafe(64))"
docker compose up -d
```

Документация API: http://localhost:8000/docs

## Тесты

Нужен локальный PostgreSQL с тестовой базой (`TEST_DATABASE_URL` в `.env`):

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pytest -v
```

## Эндпоинты

| Метод | Путь | Описание |
|---|---|---|
| POST | `/api/v1/auth/register` | регистрация |
| POST | `/api/v1/auth/login` | пара access + refresh |
| POST | `/api/v1/auth/refresh` | новая пара, старый refresh отзывается |
| POST | `/api/v1/auth/logout` | отзыв refresh-токена |
| GET | `/api/v1/users/me` | текущий пользователь (Bearer access) |

## Безопасность

- Пароли хранятся как bcrypt-хеш.
- В токене есть claim `type`: refresh нельзя использовать как access и наоборот.
- В БД лежит SHA-256-хеш refresh-токена, а не сам токен.
- Refresh одноразовый (ротация): повторное использование → 401.
- После logout access-токен работает до своего `exp` (≤15 мин) — он stateless, поэтому короткий.
