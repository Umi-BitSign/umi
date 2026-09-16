# Successor competition worker image

This recipe builds the fixed `umi-competition-worker` image used by the v4
supervisor. It supports two separately identified image profiles:

- `umi-competition-replay-worker/1` runs the wallet-free replay command with no
  network or hotkey mount.
- `umi-competition-weight-worker/1` runs the chain-capable command only after
  the host validates a signed weight authorization and mounts the configured
  validator hotkey.

Both profiles contain the same reviewed program, CPython 3.12.14 environment,
locked Python dependencies, finality observer, storage-proof verifier, bounded
runtime-metadata executor and pinned
Finney chain specification. The signed release target and image label select one
profile. The host supplies the corresponding fixed CLI mode; neither the image
label nor a caller-provided command grants chain authority.

The worker paths are fixed:

```text
/usr/local/bin/umi-competition-worker
/opt/umi/.venv/bin/python
/opt/umi/bin/umi-grandpa-finality-observer
/opt/umi/bin/umi-substrate-proof-verifier
/opt/umi/bin/umi-runtime-metadata
/opt/umi/raw_spec_finney.json
```

Runtime-independent weight signing requires an explicit
`required_runtime_metadata_executor_sha256_by_target` map in the signed weight
authorization. The paired chain configuration fields `runtime_metadata_binary`
and `runtime_metadata_binary_sha256` must match that target, using the fixed path
above. The signed host artifact must also contain the executable at
`artifacts/umi-runtime-metadata` with mode `0555` and the same digest. Host observer
and worker configurations each bind their executor; neither may select an
arbitrary path. Runtime code is read with a storage proof from the owned finalized
header and executed locally. RPC metadata cannot select the signing codec.

An authorization without this map retains exact-runtime signing. Enabling the
configuration alone is rejected. A policy that requires execution cannot fall
back to exact-runtime or storage-only decoding. A failed proof, execution limit,
unsupported runtime or changed application constraint holds the submission.
Building the image does not change any deployed authorization.

The successor sandbox keeps `/tmp` non-executable. Hash-verified helper copies
use a separate 128 MiB executable tmpfs at `/run/umi-pinned-artifacts`; the
staging library creates and checks a private, worker-owned child directory.
`UMI_PINNED_ARTIFACT_STAGE` selects that child without changing the location of
ordinary temporary files. The inert installation rehearsal verifies these mount
properties and starts a staged proof helper without a wallet or network access.

## Build unsigned OCI archives

Use a clean checkout at the exact revision intended for review. Install uv
0.12.9 and CPython 3.12.14, create the locked environment, and calculate the
source-tree digest with repository code:

```sh
set -eu
test -z "$(git status --porcelain=v1 --untracked-files=all)"
revision="$(git rev-parse HEAD)"
test "$(printf '%s' "$revision" | wc -c | tr -d ' ')" = 40
uv sync --locked --no-dev --python 3.12.14
source_tree_sha256="$(.venv/bin/python -c \
  'from umi.policy import umi_source_tree_sha256; print(umi_source_tree_sha256())')"
repository=ghcr.io/umi-bitsign/umi-validator
```

Build every platform and profile as its own OCI archive. Native amd64 and arm64
builders are preferred; emulated output is not a substitute for the required
platform rehearsal.

```sh
set -eu
for platform in linux/amd64 linux/arm64; do
  case "$platform" in
    linux/amd64) architecture=amd64 ;;
    linux/arm64) architecture=arm64 ;;
  esac
  for profile in \
    umi-competition-replay-worker/1 \
    umi-competition-weight-worker/1
  do
    case "$profile" in
      umi-competition-replay-worker/1) profile_name=replay ;;
      umi-competition-weight-worker/1) profile_name=weight ;;
    esac
    tag="${repository}:competition-${profile_name}-${revision}-${architecture}"
    archive="umi-competition-${profile_name}-${revision}-linux-${architecture}.oci.tar"
    docker buildx build \
      --pull \
      --platform "$platform" \
      --build-arg "UMI_GIT_REVISION=$revision" \
      --build-arg "UMI_SOURCE_TREE_SHA256=$source_tree_sha256" \
      --build-arg "UMI_ENTRYPOINT_PROFILE=$profile" \
      --tag "$tag" \
      --provenance=false \
      --output "type=oci,name=$tag,dest=$archive" \
      --file deploy/linux-competition-worker/Dockerfile \
      .
  done
done
```

For each archive, verify that the OCI index contains exactly one manifest for
the requested platform. Record the manifest descriptor digest as
`oci_manifest_sha256`, and record the whole archive's SHA-256 and byte length as
`oci_archive_sha256` and `oci_archive_size_bytes`. Inspect the config blob and
require these exact values before preparing a release manifest:

```text
Config.User = 65532:65532
Config.Entrypoint = ["/usr/local/bin/umi-competition-worker"]
org.opencontainers.image.revision = <exact revision>
vision.umi.source-tree-sha256 = <exact source-tree digest>
vision.umi.entrypoint-profile = <exact profile used for this archive>
```

The release authority prepares and signs a canonical
`umi-successor-oci-release-manifest/1` only after those values and the state
schema range have been reviewed. Keep replay and weight manifests separate.
Building an archive does not sign it, publish it, load it into Podman, authorize
a directive or permit chain submission.
