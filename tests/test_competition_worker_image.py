from __future__ import annotations

from pathlib import Path
from typing import get_args

from umi.competition_supervisor import SuccessorEntrypointProfile

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deploy" / "linux-competition-worker"


def test_successor_image_has_fixed_runtime_and_entrypoint() -> None:
    dockerfile = (DEPLOYMENT / "Dockerfile").read_text(encoding="utf-8")

    assert (
        "python:3.12.14-slim-bookworm@sha256:"
        "782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254"
    ) in dockerfile
    assert (
        "ghcr.io/astral-sh/uv:0.12.9@sha256:"
        "8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff"
    ) in dockerfile
    assert "uv sync --locked --no-dev --no-install-project" in dockerfile
    assert "uv sync --locked --no-dev" in dockerfile
    assert 'platform.python_version())\')" = "3.12.14"' in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["/usr/local/bin/umi-competition-worker"]' in dockerfile
    assert 'CMD ["--help"]' in dockerfile
    assert "ln -s /opt/umi/.venv/bin/umi-competition-worker" in dockerfile
    assert 'ENTRYPOINT ["/bin/sh"' not in dockerfile


def test_successor_image_profiles_match_signed_contract_exactly() -> None:
    dockerfile = (DEPLOYMENT / "Dockerfile").read_text(encoding="utf-8")
    profiles = set(get_args(SuccessorEntrypointProfile))

    assert profiles == {
        "umi-competition-replay-worker/1",
        "umi-competition-weight-worker/1",
    }
    assert "umi-competition-replay-worker/1|umi-competition-weight-worker/1" in dockerfile
    assert 'vision.umi.entrypoint-profile="${UMI_ENTRYPOINT_PROFILE}"' in dockerfile
    assert 'org.opencontainers.image.revision="${UMI_GIT_REVISION}"' in dockerfile
    assert 'vision.umi.source-tree-sha256="${UMI_SOURCE_TREE_SHA256}"' in dockerfile
    assert "ARG UMI_ENTRYPOINT_PROFILE" in dockerfile
    assert "unsupported successor entrypoint profile" in dockerfile


def test_successor_image_contains_bounded_chain_verifiers_at_fixed_paths() -> None:
    dockerfile = (DEPLOYMENT / "Dockerfile").read_text(encoding="utf-8")

    assert "rust:1.98.0-bookworm@sha256:" in dockerfile
    assert dockerfile.count("cargo +1.98.0 build --locked --release") == 3
    assert "/opt/umi/bin/umi-runtime-metadata" in dockerfile
    assert (
        "COPY rust/grandpa-finality-observer/vendor /build/grandpa-finality-observer/vendor"
        in dockerfile
    )
    assert "cargo +1.98.0 test --locked --release" in dockerfile
    assert "/opt/umi/bin/umi-grandpa-finality-observer --conformance-self-test" in dockerfile
    assert "printf '' | /opt/umi/bin/umi-substrate-proof-verifier" in dockerfile
    assert "/opt/umi/raw_spec_finney.json" in dockerfile
    assert "f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105" in dockerfile
    assert "linux/amd64|linux/arm64" in dockerfile


def test_successor_image_sources_are_in_the_bounded_docker_context() -> None:
    patterns = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    required = (
        "!deploy/linux-competition-worker/Dockerfile",
        "!rust/substrate-proof-verifier/Cargo.toml",
        "!rust/substrate-proof-verifier/Cargo.lock",
        "!rust/substrate-proof-verifier/src/**",
        "!rust/substrate-proof-verifier/fixtures/**",
        "!rust/grandpa-finality-observer/Cargo.toml",
        "!rust/grandpa-finality-observer/Cargo.lock",
        "!rust/grandpa-finality-observer/src/**",
        "!rust/grandpa-finality-observer/fixtures/**",
        "!rust/grandpa-finality-observer/vendor/**",
        "!rust/runtime-metadata/Cargo.toml",
        "!rust/runtime-metadata/Cargo.lock",
        "!rust/runtime-metadata/src/**",
    )

    assert all(item in patterns for item in required)
    assert patterns.index("!rust/substrate-proof-verifier/fixtures/**") < patterns.index(
        "**/target/"
    )


def test_build_documentation_keeps_profiles_platforms_and_authority_separate() -> None:
    readme = (DEPLOYMENT / "README.md").read_text(encoding="utf-8")

    assert "linux/amd64 linux/arm64" in readme
    assert "umi-competition-replay-worker/1" in readme
    assert "umi-competition-weight-worker/1" in readme
    assert "--provenance=false" in readme
    assert "umi-successor-oci-release-manifest/1" in readme
    assert "does not sign it" in readme
    assert "permit chain submission" in readme
    assert "--push" not in readme
