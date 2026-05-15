FROM python:3.13-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

COPY backend/pyproject.toml backend/uv.lock ./
COPY backend/src ./src

RUN uv sync --no-dev

COPY models/model_card.json /app/models/model_card.json

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -L "https://github.com/MsilviuM/url-threat-checker/releases/download/v1.0-model/url_classifier.skops" \
         -o /app/models/url_classifier.skops \
    && apt-get remove -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

ENV PATH="/app/.venv/bin:$PATH"
ENV MODEL_PATH=/app/models/url_classifier.skops
ENV MODEL_CARD_PATH=/app/models/model_card.json

CMD ["sh", "-c", "uvicorn url_threat_checker.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
