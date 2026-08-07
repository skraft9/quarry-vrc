# Quarry VRC - a HackerOne research console with no third-party runtime dependencies.
# Because the app is Python standard library + SQLite only, there is NO pip/npm install layer:
# the image is small and its attack surface is essentially the Python standard library.
FROM python:3.12-slim

# git is only needed so the payload library can clone its public reference on demand; curl is for
# the container healthcheck. Nothing here is a Python dependency.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Run as a non-root user; the volumes are chowned to it by the entrypoint on first boot.
RUN useradd --create-home --uid 10001 quarry

WORKDIR /app
# Application source (stdlib only). Copied last so a code change does not bust the apt layer.
COPY --chown=quarry:quarry . /app
# The entrypoint must be executable regardless of the source file's mode bit (a git checkout or an
# rsync may not preserve it).
RUN chmod +x /app/docker-entrypoint.sh /app/scripts/*.sh

# Mutable state lives on these volumes, never on the container's ephemeral layer.
ENV QUARRY_DATA_DIR=/data \
    QUARRY_WORKSPACE_DIR=/workspace \
    QUARRY_PAYLOADS_DIR=/payloads \
    QUARRY_BIND_HOST=0.0.0.0 \
    QUARRY_PORT=8443
VOLUME ["/data", "/workspace", "/payloads"]
EXPOSE 8443

# The published port is HTTPS with a self-signed cert by default, so the check is -k.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsk https://localhost:8443/api/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
