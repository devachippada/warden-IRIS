FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WARDEN_DATA_DIR=/tmp/warden-web

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY warden ./warden
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 warden
USER warden

EXPOSE 8000
CMD ["python", "-m", "warden.web"]
