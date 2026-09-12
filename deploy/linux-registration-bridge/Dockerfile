# syntax=docker/dockerfile:1.7

# Reuse the unchanged finality verifier from signed release 637ffd42.
# These platform artifacts are content-pinned and self-tested below.
ARG TARGETARCH
FROM scratch AS finality-amd64
ADD --checksum=sha256:cd696ea86acd691112413a7909b6bf469f90042747c87b9350f01dacfe4ae8c3 \
  https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/host-artifacts/cd696ea86acd691112413a7909b6bf469f90042747c87b9350f01dacfe4ae8c3/umi-grandpa-finality-observer-637ffd42b3f96d8071f86f6ffb2e7aebfa68351a-linux-amd64 \
  /umi-grandpa-finality-observer
FROM scratch AS finality-arm64
ADD --checksum=sha256:b263758fb273aed83868e986f4738ff14008996b200226e34c14633a863e5587 \
  https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/host-artifacts/b263758fb273aed83868e986f4738ff14008996b200226e34c14633a863e5587/umi-grandpa-finality-observer-637ffd42b3f96d8071f86f6ffb2e7aebfa68351a-linux-arm64 \
  /umi-grandpa-finality-observer
FROM finality-${TARGETARCH} AS finality
FROM ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff AS uv
FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

ARG TARGETPLATFORM
ARG UMI_GIT_REVISION
ARG UMI_SOURCE_TREE_SHA256
RUN case "${TARGETPLATFORM}" in linux/amd64|linux/arm64) ;; *) exit 2 ;; esac \
    && test "${#UMI_GIT_REVISION}" -eq 40 \
    && test "${#UMI_SOURCE_TREE_SHA256}" -eq 64 \
    && case "${UMI_GIT_REVISION}${UMI_SOURCE_TREE_SHA256}" in *[!0-9a-f]*) exit 2 ;; *) ;; esac

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
RUN test "$(uv --version | cut -d' ' -f1-2)" = "uv 0.12.9" \
    && uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev \
    && uv pip check --python /opt/umi/.venv/bin/python \
    && test "$(python -c 'from umi.policy import umi_source_tree_sha256; print(umi_source_tree_sha256())')" = "${UMI_SOURCE_TREE_SHA256}" \
    && printf '%s\n' "${UMI_GIT_REVISION}" > /opt/umi-image-revision \
    && chmod 0444 /opt/umi-image-revision \
    && install -d -o 65532 -g 65532 -m 0700 /home/umi \
    && ln -s /opt/umi/.venv/bin/umi-registration-bridge /usr/local/bin/umi-registration-bridge

COPY --from=finality /umi-grandpa-finality-observer /opt/umi/bin/umi-grandpa-finality-observer
ADD --checksum=sha256:f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105 \
  https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/host-artifacts/f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105/raw_spec_finney.json \
  /opt/umi/finney.json
RUN chmod 0555 /opt/umi/bin/umi-grandpa-finality-observer \
    && chmod 0444 /opt/umi/finney.json \
    && /opt/umi/bin/umi-grandpa-finality-observer --conformance-self-test \
    && /usr/local/bin/umi-registration-bridge --help >/dev/null

LABEL org.opencontainers.image.source="https://github.com/Umi-BitSign/umi" \
      org.opencontainers.image.revision="${UMI_GIT_REVISION}" \
      vision.umi.source-tree-sha256="${UMI_SOURCE_TREE_SHA256}" \
      vision.umi.entrypoint-profile="umi-registration-bridge-validator/1" \
      vision.umi.role="validator-supervisor-registration-bridge-worker"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/umi-registration-bridge"]
CMD ["--help"]
