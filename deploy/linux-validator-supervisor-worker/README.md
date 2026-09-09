# Validator supervisor worker image

This image provides the fixed
`/usr/local/bin/umi-validator-supervisor-worker` entrypoint used by the permanent
validator supervisor. It supports `linux/amd64` and `linux/arm64` as separate,
digest-pinned release artifacts.

The current bootstrap profile implements only the emergency direct UID 0 path in
`docs/EMERGENCY_DIRECT_BOOTSTRAP_CUTOVER_V1.md`. It submits the full 256-entry
`SubtensorModule.set_mechanism_weights` row with `WeightsVersionKey = 4294967296`,
`MinAllowedWeights = 256`, and commit-reveal disabled. It does not use the older
CRv4 bootstrap submission path.

The read-only bootstrap input mount must contain these canonical files:

```text
bootstrap/signed-manifest.json
bootstrap/direct-transition-authorization.json
bootstrap/drain-checkpoint.json
```

`drain-checkpoint.json` is the complete
`umi-bootstrap-direct-operational-preflight/1` output produced by the pinned
`umi-bootstrap-direct-weights preflight` command after the owner fence and legacy
row drain. The worker validates that checkpoint, repeats the complete preflight,
and requires the fresh snapshot to preserve the drained state before it writes a
durable effect intent.

The worker independently follows finalized Finney blocks with the bundled
smoldot-based observer. It refuses to begin unless two full eight-block
transaction eras fit before the exclusive directive expiry. If the lease expires
while a chain operation is unresolved, it
terminates the operation, records `ambiguous`, and never retries that directive.
It records `completed` only when the direct receipt, call material, and terminal
inner submission journal agree byte-for-byte. An operator must reconcile the inner
direct-submission journal and chain state after any ambiguous result.

`hold` starts no container. The worker rejects a manually invoked `run-hold`.
`run-inactive-shadow` and `run-translation-weights` also fail closed because those
profiles are not implemented in this image.

## Build release artifacts

Build each target separately so each signed release manifest names one platform
and one OCI manifest digest. Use a clean checkout and the exact revision named by
the direct-transition authorization:

```sh
set -euo pipefail
test -z "$(git status --porcelain=v1 --untracked-files=all)"
REVISION="$(git rev-parse HEAD)"
SOURCE_TREE_SHA256="$(PYTHONPATH=src .venv/bin/python -c \
  'from umi.policy import umi_source_tree_sha256; print(umi_source_tree_sha256())')"
OCI_REPOSITORY=ghcr.io/umi-bitsign/umi-validator

docker buildx build \
  --platform linux/amd64 \
  --build-arg UMI_GIT_REVISION="$REVISION" \
  --build-arg UMI_SOURCE_TREE_SHA256="$SOURCE_TREE_SHA256" \
  --tag "${OCI_REPOSITORY}:supervisor-worker-${REVISION}-amd64" \
  --provenance=false \
  --output "type=oci,name=${OCI_REPOSITORY}:supervisor-worker-${REVISION}-amd64,dest=umi-validator-supervisor-worker-linux-amd64.oci.tar" \
  -f deploy/linux-validator-supervisor-worker/Dockerfile .

docker buildx build \
  --platform linux/arm64 \
  --build-arg UMI_GIT_REVISION="$REVISION" \
  --build-arg UMI_SOURCE_TREE_SHA256="$SOURCE_TREE_SHA256" \
  --tag "${OCI_REPOSITORY}:supervisor-worker-${REVISION}-arm64" \
  --provenance=false \
  --output "type=oci,name=${OCI_REPOSITORY}:supervisor-worker-${REVISION}-arm64,dest=umi-validator-supervisor-worker-linux-arm64.oci.tar" \
  -f deploy/linux-validator-supervisor-worker/Dockerfile .
```

Hash and sign the two archives independently through the release-authority
procedure in `docs/PERMANENT_VALIDATOR_SUPERVISOR.md`. Building an image does not
authorize it and must not start a worker.
