FROM python:3.13-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

ENV UV_SYSTEM_PYTHON=1

COPY backend/pyproject.toml backend/uv.lock ./
COPY backend/src ./src

RUN uv sync --no-dev

CMD ["sh", "-c", "uvicorn url_threat_checker.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
