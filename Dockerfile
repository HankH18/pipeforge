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

# `--no-access-log` is a disclosure control, not tidiness. uvicorn's access logger
# writes the request line verbatim -- path *and* query string -- to stdout, which
# compose pipes straight to the container log. Two of this API's routes carry a
# credential pair there:
#
#   INFO: 127.0.0.1:61853 - "DELETE /sessions/fdc6fb4d29e64c32b6af05cc1de9ae46?user_id=alice HTTP/1.1" 204
#   INFO: 127.0.0.1:61854 - "GET /documents/doc-abc123?user_id=alice HTTP/1.1" 404
#
# (both measured against this exact command, minus the flag). The first line is the
# whole of what `DELETE /sessions/{id}?user_id=` needs, and that deletion is
# cryptographic erasure -- irreversible, no undo. `SessionRegistry._handle`
# (vault/session_registry.py:103) exists precisely to keep that pair out of the log
# stream, and it logs a truncated SHA-256 instead of the ID for that reason; the
# access log put the raw pair back one line away, defeating the mask.
#
# Turning the logger off rather than filtering it is the honest trade, and it costs
# less than it looks. Measured by diffing the two runs: the ONLY lines the flag
# removes are the access lines. The package's own records do not travel this stream
# at all -- uvicorn's log config touches the `uvicorn*` loggers, nothing installs a
# handler for `secure_context_pipeline`, so the masked `_handle` records were never
# printed here and are not what is being given up. What is given up is per-request
# visibility, and the audit chain already holds it in a masked, access-controlled,
# tamper-evident form -- which is the copy worth keeping. The alternative, a
# uvicorn access-log filter rewriting IDs through `_handle`, has to enumerate every
# id-bearing route and stays wrong the moment one is added; this cannot.
#
# It also stops the HEALTHCHECK below from writing 2,880 `GET /health` lines a day
# into an idle container's log.
CMD ["uvicorn", "secure_context_pipeline.api.app:create_app", \
     "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
