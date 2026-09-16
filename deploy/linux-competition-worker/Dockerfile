# syntax=docker/dockerfile:1.7

FROM docker.io/library/rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS rust-builder

WORKDIR /build/finality
COPY rust/grandpa-finality-observer/Cargo.toml rust/grandpa-finality-observer/Cargo.lock ./
COPY rust/grandpa-finality-observer/build.rs ./
COPY rust/grandpa-finality-observer/rust-toolchain.toml ./
COPY rust/grandpa-finality-observer/src ./src
COPY rust/grandpa-finality-observer/fixtures ./fixtures
COPY rust/grandpa-finality-observer/vendor ./vendor
RUN cargo +1.98.0 build --locked --release \
    && target/release/umi-grandpa-finality-observer --conformance-self-test

WORKDIR /build/proof
COPY rust/substrate-proof-verifier/Cargo.toml rust/substrate-proof-verifier/Cargo.lock ./
COPY rust/substrate-proof-verifier/src ./src
COPY rust/substrate-proof-verifier/fixtures ./fixtures
RUN cargo +1.98.0 test --locked --release \
    && cargo +1.98.0 build --locked --release

WORKDIR /build/runtime-metadata
COPY rust/runtime-metadata/Cargo.toml rust/runtime-metadata/Cargo.lock ./
COPY rust/runtime-metadata/src ./src
COPY rust/grandpa-finality-observer/vendor /build/grandpa-finality-observer/vendor
RUN cargo +1.98.0 test --locked --release \
    && cargo +1.98.0 build --locked --release

FROM ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff AS uv
FROM docker.io/library/python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

ARG TARGETPLATFORM
ARG UMI_GIT_REVISION
ARG UMI_SOURCE_TREE_SHA256
ARG UMI_ENTRYPOINT_PROFILE
RUN case "${TARGETPLATFORM}" in \
      linux/amd64|linux/arm64) ;; \
      *) echo "unsupported target platform: ${TARGETPLATFORM}" >&2; exit 2 ;; \
    esac \
    && case "${UMI_ENTRYPOINT_PROFILE}" in \
      umi-competition-replay-worker/1|umi-competition-weight-worker/1) ;; \
      *) echo "unsupported successor entrypoint profile" >&2; exit 2 ;; \
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
    && test "$(/opt/umi/.venv/bin/python -c 'import platform; print(platform.python_version())')" = "3.12.14" \
    && test "$(python -c 'from umi.policy import umi_source_tree_sha256; print(umi_source_tree_sha256())')" = "${UMI_SOURCE_TREE_SHA256}" \
    && printf '%s\n' "${UMI_GIT_REVISION}" > /opt/umi-image-revision \
    && chmod 0444 /opt/umi-image-revision \
    && install -d -o 65532 -g 65532 -m 0700 /home/umi \
    && ln -s /opt/umi/.venv/bin/umi-competition-worker \
      /usr/local/bin/umi-competition-worker

COPY --from=rust-builder \
  /build/finality/target/release/umi-grandpa-finality-observer \
  /opt/umi/bin/umi-grandpa-finality-observer
COPY --from=rust-builder \
  /build/proof/target/release/umi-substrate-proof-verifier \
  /opt/umi/bin/umi-substrate-proof-verifier
COPY --from=rust-builder \
  /build/runtime-metadata/target/release/umi-runtime-metadata \
  /opt/umi/bin/umi-runtime-metadata
# Podman 4.9 does not support ADD --checksum. The next RUN verifies these bytes
# before either verifier executes or the image can finish building.
ADD https://raw.githubusercontent.com/opentensor/subtensor/da06f033663896ef2fdbbfc3ecc68ca908fba0f5/chainspecs/raw_spec_finney.json \
  /opt/umi/raw_spec_finney.json
RUN chmod 0555 \
      /opt/umi/bin/umi-grandpa-finality-observer \
      /opt/umi/bin/umi-substrate-proof-verifier \
      /opt/umi/bin/umi-runtime-metadata \
    && chmod 0444 /opt/umi/raw_spec_finney.json \
    && printf '%s  %s\n' \
      f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105 \
      /opt/umi/raw_spec_finney.json | sha256sum --check \
    && /opt/umi/bin/umi-grandpa-finality-observer --conformance-self-test \
    && printf '' | /opt/umi/bin/umi-substrate-proof-verifier \
    && /usr/local/bin/umi-competition-worker --help >/dev/null

LABEL org.opencontainers.image.source="https://github.com/Umi-BitSign/umi" \
      org.opencontainers.image.revision="${UMI_GIT_REVISION}" \
      vision.umi.source-tree-sha256="${UMI_SOURCE_TREE_SHA256}" \
      vision.umi.entrypoint-profile="${UMI_ENTRYPOINT_PROFILE}" \
      vision.umi.role="successor-competition-worker"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/umi-competition-worker"]
CMD ["--help"]
