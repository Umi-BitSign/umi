# syntax=docker/dockerfile:1.7

# The multi-platform index is pinned. The Compose file selects linux/amd64 so a
# Mac and an x86_64 Linux validator execute the same release target and scoring
# environment.
FROM ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff AS uv
FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c

ARG UMI_GIT_REVISION
RUN case "${UMI_GIT_REVISION}" in \
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; \
      *) echo "UMI_GIT_REVISION must be 40 lowercase hexadecimal characters" >&2; exit 2 ;; \
    esac

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/opt/umi/.venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_NO_PROGRESS=1

WORKDIR /opt/umi
COPY --from=uv /uv /uvx /usr/local/bin/
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN test "$(uv --version)" = "uv 0.12.9" \
    && uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev \
    && uv pip check --python /opt/umi/.venv/bin/python \
    && /opt/umi/.venv/bin/python -c 'import bittensor, umi' \
    && printf '%s\n' "${UMI_GIT_REVISION}" > /opt/umi-image-revision \
    && chmod 0444 /opt/umi-image-revision

COPY deploy/macos-validator/container-entrypoint.sh /usr/local/bin/umi-validator-container
RUN chmod 0555 /usr/local/bin/umi-validator-container

LABEL org.opencontainers.image.source="https://github.com/Umi-BitSign/umi" \
      org.opencontainers.image.revision="${UMI_GIT_REVISION}" \
      vision.umi.role="weight-disabled-live-shadow-validator"

ENTRYPOINT ["/usr/local/bin/umi-validator-container"]
CMD ["help"]
