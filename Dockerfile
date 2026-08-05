# syntax=docker/dockerfile:1
#
# The spaCy en_core_web_lg model (~590 MB) is baked in at BUILD time, not fetched
# at runtime. That is deliberate: the pipeline's premise is that detection happens
# locally and no document text ever reaches a third party, so the container must
# not need network access to start. Cost: a 1.31 GB image (measured after the
# build-context allow-list below; it was 2.85 GB when COPY . . shipped the host
# venv, .git and data/). Noted in the README.

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# build-essential is needed for a few wheels on slim; removed in the same layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency layer first so source edits do not invalidate the model download.
COPY pyproject.toml README.md ./
COPY secure_context_pipeline/__init__.py secure_context_pipeline/__init__.py
RUN pip install --no-cache-dir . \
    && python -m spacy download en_core_web_lg \
    && apt-get purge -y --auto-remove build-essential \
    && rm -rf /root/.cache

# An explicit allow-list, never `COPY . .`. The build context is a developer's
# working tree, and `COPY . .` shipped all of it: `.env` -- so `SCP_MASTER_KEY`
# and `ANTHROPIC_API_KEY` became readable in a published layer, and the master
# key decrypts every document in the store -- plus `data/` (real encrypted
# blobs, the vault and the audit chain), `.git`, and a ~750 MB host virtualenv
# built for the wrong platform. `.dockerignore` is a second line of defence, but
# what ships is decided here: a deny-list forgets, an allow-list cannot.
#
# `entities.yaml` is required at runtime, not optional: `DEFAULT_REGISTRY_PATH`
# resolves to the package's parent, i.e. /app/entities.yaml.
COPY entities.yaml ./
COPY secure_context_pipeline/ secure_context_pipeline/
COPY fixtures/ fixtures/
COPY demo.py ./
# setuptools writes `build/` and `*.egg-info/` into the working directory, so an
# in-place `pip install .` leaves a second, stale copy of the whole package at
# /app/build/lib. Harmless but confusing: `ls /app` is the first thing a reviewer
# runs to check what shipped, and two source trees is the wrong answer.
RUN pip install --no-cache-dir --no-deps . \
    && rm -rf build secure_context_pipeline.egg-info

# Non-root. The data volume is chowned so the encrypted store is writable.
RUN useradd --create-home --uid 10001 scp \
    && mkdir -p /app/data \
    && chown -R scp:scp /app
USER scp

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "secure_context_pipeline.api.app:create_app", \
     "--factory", "--host", "0.0.0.0", "--port", "8000"]
