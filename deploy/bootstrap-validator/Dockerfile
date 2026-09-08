# syntax=docker/dockerfile:1.7

# Public pilot bundles pin this exact interpreter environment. Validators on
# Linux and Apple Silicon therefore use the same linux/amd64 replay target.
FROM ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff AS uv
FROM python:3.12.14-slim-bookworm@sha256:9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef

ARG TARGETPLATFORM
ARG UMI_GIT_REVISION
RUN test "${TARGETPLATFORM}" = "linux/amd64" \
    && case "${UMI_GIT_REVISION}" in \
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; \
      *) echo "UMI_GIT_REVISION must be 40 lowercase hexadecimal characters" >&2; exit 2 ;; \
    esac

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME=/home/umi \
    PATH=/opt/umi/.venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_NO_PROGRESS=1

WORKDIR /opt/umi
COPY --from=uv /uv /uvx /usr/local/bin/
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN test "$(uv --version)" = "uv 0.12.9 (x86_64-unknown-linux-musl)" \
    && uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev \
    && uv pip check --python /opt/umi/.venv/bin/python \
    && python - <<'PY'
from umi.scoring import scoring_environment

expected = {
    "schema": "umi-component-scoring-environment/1",
    "python_implementation": "CPython",
    "python_version": "3.12.14",
    "unicode_data_version": "15.0.0",
    "regex_distribution_version": "2026.9.3",
    "bittensor_distribution_version": "11.1.0",
    "scoring_source_sha256": "6b36ffbf2dcbb0e7bd15ffb71785133cbb50bf8db81fe1c4f024cbcbf1a4e14b",
}
if scoring_environment() != expected:
    raise SystemExit("bootstrap validator scoring environment mismatch")
PY
RUN printf '%s\n' "${UMI_GIT_REVISION}" > /opt/umi-image-revision \
    && chmod 0444 /opt/umi-image-revision \
    && groupadd --gid 65532 umi \
    && useradd --uid 65532 --gid 65532 --home-dir /home/umi --create-home \
         --shell /usr/sbin/nologin umi

LABEL org.opencontainers.image.source="https://github.com/Umi-BitSign/umi" \
      org.opencontainers.image.revision="${UMI_GIT_REVISION}" \
      vision.umi.role="temporary-bootstrap-service-weight-validator"

USER 65532:65532
ENTRYPOINT ["umi-bootstrap-weights"]
CMD ["--help"]
