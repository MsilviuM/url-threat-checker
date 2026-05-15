FROM python:3.13-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

COPY backend/pyproject.toml backend/uv.lock ./
COPY backend/src ./src

RUN uv sync --no-dev

ENV PATH="/app/.venv/bin:$PATH"

CMD ["sh", "-c", "uvicorn url_threat_checker.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
