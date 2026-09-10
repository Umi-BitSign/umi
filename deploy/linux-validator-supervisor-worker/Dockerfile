# syntax=docker/dockerfile:1.7

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS finality-builder

WORKDIR /build/finality
COPY rust/grandpa-finality-observer/Cargo.toml rust/grandpa-finality-observer/Cargo.lock ./
COPY rust/grandpa-finality-observer/build.rs ./
COPY rust/grandpa-finality-observer/rust-toolchain.toml ./
COPY rust/grandpa-finality-observer/src ./src
COPY rust/grandpa-finality-observer/fixtures ./fixtures
COPY rust/grandpa-finality-observer/vendor ./vendor
RUN cargo +1.98.0 build --locked --release \
    && target/release/umi-grandpa-finality-observer --conformance-self-test

FROM ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff AS uv
FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

ARG TARGETPLATFORM
ARG UMI_GIT_REVISION
ARG UMI_SOURCE_TREE_SHA256
RUN case "${TARGETPLATFORM}" in \
      linux/amd64|linux/arm64) ;; \
      *) echo "unsupported target platform: ${TARGETPLATFORM}" >&2; exit 2 ;; \
    esac \
    && test "${#UMI_GIT_REVISION}" -eq 40 \
    && test "${#UMI_SOURCE_TREE_SHA256}" -eq 64 \
    && case "${UMI_GIT_REVISION}${UMI_SOURCE_TREE_SHA256}" in \
      *[!0-9a-f]*) echo "revision and source-tree digest must be lowercase hexadecimal" >&2; exit 2 ;; \
      *) ;; \
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
RUN test "$(uv --version | cut -d' ' -f1-2)" = "uv 0.12.9" \
    && uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev \
    && uv pip check --python /opt/umi/.venv/bin/python \
    && test "$(python -c 'from umi.policy import umi_source_tree_sha256; print(umi_source_tree_sha256())')" = "${UMI_SOURCE_TREE_SHA256}" \
    && printf '%s\n' "${UMI_GIT_REVISION}" > /opt/umi-image-revision \
    && chmod 0444 /opt/umi-image-revision \
    && install -d -o 65532 -g 65532 -m 0700 /home/umi \
    && ln -s /opt/umi/.venv/bin/umi-validator-supervisor-worker \
      /usr/local/bin/umi-validator-supervisor-worker

COPY --from=finality-builder \
  /build/finality/target/release/umi-grandpa-finality-observer \
  /opt/umi/bin/umi-grandpa-finality-observer
ADD --checksum=sha256:f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105 \
  https://raw.githubusercontent.com/opentensor/subtensor/da06f033663896ef2fdbbfc3ecc68ca908fba0f5/chainspecs/raw_spec_finney.json \
  /opt/umi/finney.json
RUN chmod 0555 /opt/umi/bin/umi-grandpa-finality-observer \
    && chmod 0444 /opt/umi/finney.json \
    && printf '%s  %s\n' \
      f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105 \
      /opt/umi/finney.json | sha256sum --check \
    && /opt/umi/bin/umi-grandpa-finality-observer --conformance-self-test \
    && /usr/local/bin/umi-validator-supervisor-worker --help >/dev/null

LABEL org.opencontainers.image.source="https://github.com/Umi-BitSign/umi" \
      org.opencontainers.image.revision="${UMI_GIT_REVISION}" \
      vision.umi.source-tree-sha256="${UMI_SOURCE_TREE_SHA256}" \
      vision.umi.entrypoint-profile="umi-bootstrap-weight-validator/2" \
      vision.umi.role="validator-supervisor-bootstrap-worker"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/umi-validator-supervisor-worker"]
CMD ["--help"]
