FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system cerberus && useradd --system --gid cerberus --home-dir /app cerberus
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY cerberus_null ./cerberus_null
RUN pip install --no-cache-dir .
USER cerberus
EXPOSE 8080
ENTRYPOINT ["cerberus"]
CMD ["serve", "--port", "8080"]
