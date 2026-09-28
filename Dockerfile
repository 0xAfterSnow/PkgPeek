# syntax=docker/dockerfile:1
#
# PkgPeek — production image.
#
# The ordering here matters and is not cosmetic. Wasmer's auto-generated
# Dockerfile ran the install step *before* copying the source in, so
# `pip install -r requirements.txt` failed with:
#
#     ERROR: Could not open requirements file: [Errno 2] No such file or directory
#
# The fix is to copy the requirements files first, install, and only then copy
# the application. That also gives you a working dependency layer cache: editing
# application code no longer re-resolves the whole dependency tree.

FROM python:3.13-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# No apt-get here, deliberately. psycopg2-binary ships wheels, so no compiler
# toolchain is needed, and the healthcheck uses the Python already in the image
# rather than curl. That keeps the build to a single dependency source (PyPI),
# which matters on a slow or restricted network -- an apt layer is the first
# thing to fail, and it adds an image layer for no benefit.
WORKDIR /app

# 1. Requirements first, so the install step below can actually see them.
COPY requirements.txt ./

# 2. Install production dependencies only. requirements-dev.txt (pytest, Pillow)
#    is intentionally NOT installed here -- it bloats the image and buys nothing
#    at runtime. CI installs it separately for the test suite.
RUN pip install -r requirements.txt

# 3. Now the application itself. A change here does not invalidate the layer
#    cache from step 2.
COPY . .

# 4. Drop privileges before anything runs.
RUN useradd --create-home --uid 10001 pkgpeek \
    && mkdir -p /app/data /app/static/uploads/logos \
    && chown -R pkgpeek:pkgpeek /app
USER pkgpeek


# ── Storage ────────────────────────────────────────────────────────────────
# The container filesystem on Wasmer (and most hosts) is read-only, so SQLite
# cannot be written there. Two supported options, in order of preference:
#
#   1. Set DATABASE_URL to a PostgreSQL URL. This is what production should do:
#      the detection dataset is rebuilt from JSON on boot, but package reports
#      and paid tool listings are real user data that must survive a redeploy.
#
#   2. Leave DATABASE_URL unset. PkgPeek then writes SQLite to a writable path
#      under /tmp. Everything works, but the file is discarded on every
#      redeploy, so reports and paid listings will not persist.
#
# Set PKPEEK_DB_PATH=/tmp/pkgpeek.db to take option 2 deliberately.
ENV PKPEEK_DB_PATH=/tmp/pkgpeek.db \
    PKPEEK_SECURE_COOKIES=1

EXPOSE 8080

# Healthcheck without curl: /api/stats is cheap, needs no auth, and returns JSON
# only once the database is reachable -- so a successful call means the app is
# genuinely serving, not merely that a port is open.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/api/stats',timeout=4).status==200 else 1)" \
    || exit 1

# Create the schema and load the detection dataset at *startup*, not at build
# time. DATABASE_URL is only known at runtime, so a build-time init would set up
# SQLite and leave the real database uninitialised. Failing here is fatal on
# purpose: better to fail to boot loudly than to serve 500s.
#
# The server choice lives in serve.py so it cannot drift from the flags -- see
# the note there about Wasmer handing gunicorn's --timeout to uvicorn. $PORT is
# injected by the platform.
CMD ["sh", "-c", "exec python serve.py"]
