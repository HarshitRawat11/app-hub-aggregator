# The third copy of this file, and deliberately so. The concepts were learned
# once in links-service (learn/02, learn/19); a third variation here would
# teach nothing and only risk a fresh mistake. Only the port differs.
#
# Worth noting what is NOT different: this service makes outbound calls to
# arbitrary third-party URLs, which sounds like it needs extra capability.
# It does not. Outbound HTTP needs no privilege, so the same read-only,
# non-root, all-capabilities-dropped container serves it unchanged.
#
# Base image must satisfy pyproject.toml's `requires-python = ">=3.14"`.
# With a 3.12 base, uv silently downloads its own managed 3.14 at build time —
# the image works, but the FROM tag is a lie and the image carries two Pythons.
FROM python:3.14-slim

# Copy the uv binaries from the official image rather than pip-installing them.
# Keeps uv out of the app's dependency tree entirely.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Dependencies before app source, so this layer is cached and only re-runs when
# pyproject.toml or uv.lock actually change.
COPY pyproject.toml uv.lock ./

# --frozen: fail if uv.lock is out of date rather than silently re-resolving.
# --no-install-project: install dependencies only; this project has no
#   [build-system], so it runs from source and `app/` is simply copied in.
RUN uv sync --frozen --no-install-project

COPY app/ ./app/

# Venv first on PATH so `uvicorn` resolves to /app/.venv/bin/uvicorn, which is
# what lets CMD invoke it directly instead of going through `uv run`.
ENV PATH="/app/.venv/bin:$PATH"

# No .pyc files: the image is immutable so the cache buys nothing, and it means
# the container never writes into /app — which is what makes
# readOnlyRootFilesystem viable in the Deployment.
ENV PYTHONDONTWRITEBYTECODE=1
# Unbuffered stdout/stderr, so logs reach `kubectl logs` immediately. This one
# earns its place here specifically: gateway logs the real upstream errors that
# the caller never sees, so a buffered log is a debugging dead end.
ENV PYTHONUNBUFFERED=1

# Non-root (R-02). By default a container runs as root; if anything escapes, it
# escapes AS root. This app never writes to disk or binds a privileged port,
# so there is nothing to trade away.
#
# 10001 is an arbitrary high UID, set explicitly so the Kubernetes
# securityContext can assert the same number.
RUN groupadd --system --gid 10001 appuser \
 && useradd --system --uid 10001 --gid appuser --no-create-home appuser \
 && chown -R appuser:appuser /app
USER appuser

# 8002. links-service owns 8000 and gateway 8001, so all three run side by
# side on a laptop without colliding.
EXPOSE 8002

# uvicorn straight from the venv, not `uv run` — that would re-resolve the
# environment at container start, undoing the build-time sync and turning a
# dependency problem into a runtime crash instead of a build failure.
#
# 0.0.0.0 is a bind address meaning "listen on all interfaces", not a browsable
# host. Reach the container at localhost:8002.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
