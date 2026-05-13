FROM python:3.10-slim

ARG OPENETR_GIT_COMMIT=unknown

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV OPENETR_APP_SESSION_SECRET=openetr-demo-session-secret
ENV OPENETR_GIT_COMMIT=${OPENETR_GIT_COMMIT}

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY openetr /app/openetr
COPY app /app/app

RUN pip install .
RUN pip install -r app/requirements.txt

EXPOSE 8000

CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
