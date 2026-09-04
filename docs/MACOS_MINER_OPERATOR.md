# Run a UMI miner on Apple Silicon

UMI supports `aarch64-apple-darwin` as a miner-only release target. The native
artifact is the GRANDPA finality observer used to admit validator requests. Model
inference for the initial reference model runs through its tested asynchronous
in-process translator and uses Metal Performance Shaders when available. The public
validator runtime remains limited to the signed static Linux targets.

This separation is deliberate. A miner receives already bounded request metadata,
fetches one policy-sized clip, checks finality, and returns a sealed response. A
validator must inspect adversarial media and reproduce the complete release
conformance suite. UMI's enforced FFmpeg address-space boundary and static media
runtime are Linux-specific. The Darwin miner target does not add a storage-proof
verifier, FFmpeg package, validator template, or validator capability.

## Current performance evidence

The reference pipeline has completed one eligible 14.1-second clip in about 30
seconds end to end on an M3 Ultra. That run used the Linux AMD64 Docker extractor
and native MPS inference. It shows that the architecture works on a Mac, but it
does not establish production concurrency or deadline headroom.

At the 28 delivered assignments per validator in a two-batch launch window, the
four validators can send 112 requests for 28 distinct videos. UMI's explicit,
signed scheduling layer can coalesce concurrent requests for the same video after
the outer miner admits them. The sealed reference-model inference code remains
unchanged. With a 30-second observed job time, outer concurrency 16 admits only
about four distinct videos at once and needs about seven waves, or 210 seconds. That
does not fit the signed validator transport timeout's current 90-second default.

Outer concurrency 64, allocated as 16 slots per validator, plus 16 backend workers
is the first plausible test configuration: it can admit 16 distinct jobs and then
the remaining 12. This is arithmetic, not production evidence. The reference-model
repository contains an opt-in 112-request capacity rehearsal in
`tests/test_umi_macos_capacity.py`, but no passing run is recorded for the final
signed release yet. Pass that harness under the final signed policy before
announcing production capacity. It must verify fair progress for every validator
and completion inside the shortest signed validator transport timeout. Do not
extend that timeout to hide insufficient capacity: a non-sealed timeout can be
retried, and two long attempts can consume the 300-second response interval before
the request-set freeze.

## 1. Build and seal the native finality observer

Use a clean checkout of the exact UMI revision selected for the release. Building
under `target/` does not dirty the checkout.

```bash
cd /absolute/path/to/umi
rustup toolchain install 1.98.0 --profile minimal
cargo +1.98.0 build --locked --release \
  --manifest-path rust/grandpa-finality-observer/Cargo.toml

umi-miner-finality-artifact \
  --repository-root /absolute/path/to/umi \
  --binary /absolute/path/to/umi/rust/grandpa-finality-observer/target/release/umi-grandpa-finality-observer \
  --output-dir /absolute/path/to/umi-darwin-finality
```

The command requires an ARM64 Darwin host. It checks the thin Mach-O executable
header, reruns the pinned finality fixture, binds the clean UMI Git revision and
source pins, and creates a target-resolved Rust license closure. It writes three
immutable files:

- `umi-grandpa-finality-observer`
- `miner-finality-build-report.json`
- `finality-third-party-licenses.zip`

The command also prints the SHA-256 of all three files. Record those digests and
confirm them with the release builder over a separate trusted channel. Transfer the
directory without changing the bytes or modes. A path received through the same
untrusted transfer channel is not provenance.

## 2. Include the target before release signing

Add this optional top-level member to the canonical
`umi-live-shadow-release-input/1` document. Use absolute paths on the Linux release
builder:

```json
{
  "miner_finality_targets": [
    {
      "target_triple": "aarch64-apple-darwin",
      "binary_path": "/absolute/import/umi-darwin-finality/umi-grandpa-finality-observer",
      "build_report_path": "/absolute/import/umi-darwin-finality/miner-finality-build-report.json",
      "license_closure_path": "/absolute/import/umi-darwin-finality/finality-third-party-licenses.zip",
      "expected_binary_sha256": "64-lowercase-hex-from-the-trusted-channel",
      "expected_build_report_sha256": "64-lowercase-hex-from-the-trusted-channel",
      "expected_license_closure_sha256": "64-lowercase-hex-from-the-trusted-channel"
    }
  ]
}
```

Do this before collecting publisher-capacity signatures and the two release
authority signatures. The normal release construction then:

- adds the Darwin binary digest to
  `implementation_pins.finality_verifier.release_sha256_by_target`;
- leaves `storage_proof_verifier.release_sha256_by_target` limited to the primary
  Linux validator target;
- includes all three Darwin files in both signed artifact indexes; and
- emits `miner-templates/aarch64-apple-darwin.json`.

When `miner_finality_targets` is absent, the canonical descriptor and release
retain the existing single-target behavior. Do not emit an explicit empty member;
canonical serialization omits it.

## 3. Verify and resolve the release on the Mac

Obtain the expected release-authority hotkey through a trusted channel. Do not
copy it from the candidate release itself. From a trusted UMI checkout or wheel,
run:

```bash
install -d -m 0700 /absolute/private/umi-resolved-releases
umi-shadow-release-resolve-miner /absolute/path/to/public-release \
  --expected-authority-hotkey 5ExpectedReleaseAuthorityAddress \
  --target-triple aarch64-apple-darwin \
  --output-dir /absolute/private/umi-resolved-releases/release-001
```

The resolver verifies both release-authority signatures, the complete artifact
tree, every digest and file mode, policy bindings, the Darwin build report and
license closure, and the native finality self-test. It then copies the authenticated
bytes into the previously nonexistent output directory with a mode-0555 root and
mode-0444 or mode-0555 files. It validates and executes only that private copy. It
does not execute the Linux validator binaries. The canonical resolved document is
`/absolute/private/umi-resolved-releases/release-001/resolved-miner-release.json`;
its paths all remain inside that tree. A missing target, changed byte, unexpected
file, invalid signature, unsafe output parent, existing output directory, or failed
native self-test stops resolution.

The resolved document also carries
`minimum_validator_transport_timeout_seconds` and
`minimum_validator_transport_concurrency`, recomputed from the complete signed
validator-template set. Capacity rehearsals use those fields instead of an assumed
timeout or an operator-supplied value.

## 4. Install and test the reference model runtime

Follow the Apple Silicon procedure in
[`umi-reference-model/docs/RUN_MINER_MACOS.md`](https://github.com/Umi-BitSign/umi-reference-model/blob/main/docs/RUN_MINER_MACOS.md).
It checks out the UMI revision named by this signed release, installs the model and
UMI locks into one Python 3.12 environment, binds the Linux AMD64 extractor image,
selects MPS or CPU, and runs the request-to-reveal E2E. Use
`umi-shadow-release-resolve-miner` for the signed UMI release check on Darwin. The
general validator release verifier executes Linux-only tools and is not the Darwin
entry point.

Keep the model runbook's environment variables in the same Bash process used to
start the miner, or store them in its owner-only runtime environment file. Stop if
the UMI checkout commit differs from `umi_git_revision`, its source-tree digest
differs from `umi_source_tree_sha256`, either checkout is dirty, or the model probe
or E2E fails. `umi_revision` is the signed composite display value, not an argument
to `git checkout`.

## 5. Prepare the public IP endpoint

UMI metagraph discovery constructs the miner origin as
`https://<advertised-ip>:<port>`. The `btcli serve-axon --ip` value is a literal
public IPv4 or IPv6 address, not a hostname. The Mac therefore needs one of these:

- a publicly routed address and port forwarded to its TLS proxy; or
- a real IP-level edge with a dedicated public address that forwards to the Mac.

The TLS certificate must be valid for that exact IP address. A hostname-only
Cloudflare Tunnel is not sufficient because validators will connect to the
literal address from the serving record. Do not announce the endpoint until an
external host can reach the advertised address, validate its IP certificate, and
complete a bounded request through the proxy. The proxy must preserve the exact
request target, authentication headers, and body bytes.

## 6. Create state and start the miner

The initial reference backend is the tested asynchronous module translator
`bitsign_motion.umi_reference_backend:translator`. It launches killable worker
processes for individual jobs. A Unix-socket sidecar remains available to model
implementations that ship a concrete compatible launcher, but it is not the initial
reference-model path.

Create private state directories and keep the hotkey on this host. Keep the coldkey
offline. Run this block in the Bash environment prepared by the reference-model
runbook:

```bash
install -d -m 0700 \
  /absolute/private/umi-miner-state \
  /absolute/private/umi-finality-state

export RESOLVED_MINER_RELEASE=/absolute/private/umi-resolved-releases/release-001/resolved-miner-release.json
SCORING_POLICY="$(jq -er .policy_path "$RESOLVED_MINER_RELEASE")"
TARGET_TRIPLE="$(jq -er .target_triple "$RESOLVED_MINER_RELEASE")"
FINALITY_VERIFIER="$(jq -er .finality_verifier_binary "$RESOLVED_MINER_RELEASE")"
FINALITY_CHAIN_SPEC="$(jq -er .finality_chain_spec_path "$RESOLVED_MINER_RELEASE")"
MIRROR_DISCOVERY="$(jq -er .mirror_discovery_rule_path "$RESOLVED_MINER_RELEASE")"
test "$TARGET_TRIPLE" = aarch64-apple-darwin

VIDEO_ORIGIN_ARGS=()
while IFS= read -r ORIGIN; do
  VIDEO_ORIGIN_ARGS+=(--video-origin "$ORIGIN")
done < <("$HOME/umi-miner/umi-reference-model/.venv/bin/python" - "$MIRROR_DISCOVERY" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_bytes())
for origin in document["delivery_origins"]:
    print(origin)
PY
)
test "${#VIDEO_ORIGIN_ARGS[@]}" -gt 0

export UMI_TESTED_INFERENCE_CONCURRENCY=64
export UMI_TESTED_BACKEND_WORKERS=16
test "$UMI_TESTED_INFERENCE_CONCURRENCY" -ge 64
test "$UMI_TESTED_BACKEND_WORKERS" -ge 16

"$HOME/umi-miner/umi-reference-model/.venv/bin/python" -m umi.miner \
  --wallet-name miner-wallet \
  --hotkey umi-miner \
  --wallet-path /absolute/private/wallets \
  --policy "$SCORING_POLICY" \
  --target-triple "$TARGET_TRIPLE" \
  --finality-verifier-binary "$FINALITY_VERIFIER" \
  --finality-chain-spec "$FINALITY_CHAIN_SPEC" \
  --finality-state /absolute/private/umi-finality-state/finality.sqlite3 \
  --translator bitsign_motion.umi_reference_backend:translator \
  --model-revision "$UMI_S1_INFERENCE_REVISION" \
  "${VIDEO_ORIGIN_ARGS[@]}" \
  --max-inference-concurrency "$UMI_TESTED_INFERENCE_CONCURRENCY" \
  --coalesce-window-video-inference \
  --max-backend-workers "$UMI_TESTED_BACKEND_WORKERS" \
  --inference-timeout 180 \
  --inference-admission-timeout 10 \
  --backend-lifecycle-timeout 60 \
  --nonce-db /absolute/private/umi-miner-state/nonces.sqlite3 \
  --assignment-db /absolute/private/umi-miner-state/assignments.sqlite3 \
  --listen-host 127.0.0.1 \
  --port 8091
```

The outer value 64 and backend value 16 are the first plausible settings for the
initial four-validator, 112-request scenario. They are not a readiness claim until
the reference-model capacity harness passes on this host against the final signed
release. Replace them with the outer and backend limits that produced that passing
result within the shortest signed validator transport timeout. The outer value
remains a positive multiple of the policy validator count. Do not lower it to the
four-slot E2E setting. The protocol's minimum check is not a throughput claim. Do not pass
`--allow-unsafe-sync-translator`: the reference translator is asynchronous.

The coalescing flag is an operator assertion about the selected in-process model.
It is valid for the signed reference backend because that backend depends only on
the verified video bytes and signed semantic fields. Do not use it with a backend
that depends on validator, challenge, issuance, deadline, URL, or other omitted
request metadata. UMI rejects this mode with the request-bound Unix-socket
transport.

Put TLS and public request filtering in front of the loopback listener. Disable
system sleep, supervise the miner with a restart delay, and test recovery without
deleting its SQLite files or lock files. Docker Desktop must be ready before the
miner starts. Close public ingress whenever `/healthz` is unhealthy.

After the service and TLS proxy pass the external reachability check, publish the
literal endpoint:

```bash
btcli tx serve-axon \
  --netuid 78 \
  --ip YOUR_PUBLIC_IP \
  --port 443 \
  --network finney \
  --wallet miner-wallet \
  --wallet-hotkey umi-miner \
  --no-mev-shield
```

This serving call is hotkey-signed. The UMI miner process itself makes no chain
write.

Before public use, exercise valid translation, exact retry, invalid signature,
late request, failed video fetch, model timeout, model restart, and finality
restart cases. Confirm that logs contain neither video bytes nor readable
hypotheses before reveal.

## Supported Mac Studio validator route

A Mac Studio can host a conforming validator inside a dedicated native ARM64
Linux virtual machine. This is a Linux validator deployment hosted by a Mac, not a
Darwin validator. Apple Virtualization through Colima is one workable route:

```bash
brew install colima
colima start \
  --profile umi-validator \
  --arch aarch64 \
  --vm-type vz \
  --cpu 16 \
  --memory 64 \
  --disk 250
colima ssh --profile umi-validator -- uname -m
```

Choose CPU, memory, and disk values from the validator capacity statement rather
than copying the example. `uname -m` inside the VM must report `aarch64`. Do not
enable Rosetta or use QEMU emulation for the validator.

Copy the signed `aarch64-unknown-linux-musl` release from the host mount into the
VM's own filesystem, then verify it inside the VM. Keep validator state, wallet,
mirror headers, databases, audit output, and temporary media on the VM disk, not
on a macOS shared mount. Build the Python environment and materialize the private
operator configuration inside the VM by following the
[shadow calibration operator guide](SHADOW_CALIBRATION_OPERATOR.md).

Every validator process stays inside that VM, including the Python runtime,
smoldot finality observer, storage-proof verifier, static FFmpeg and FFprobe,
mirror retrieval, transcript anchors, and audit publication. Before joining
public calibration, the operator still needs a registered validator hotkey with a
live permit, the authority-signed release and local bindings, a signed capacity
statement matching the VM resources, current in-VM conformance, and full in-VM
deadline and load evidence. Hosting Linux on the Mac waives none of those gates.

## Host-native validator boundary

Do not run `umi-validator-live` on macOS for public calibration. Startup now
rejects Darwin with `live_validator_target_unsupported`, even if a hand-edited
policy names a Darwin proof binary. A Mac can still run component tests and local
rehearsals, but those outputs are not a conforming installed validator result.

Adding a public Darwin validator later requires a separately reviewed media
containment design, target-specific static FFmpeg and FFprobe closure, storage
proof verifier, complete executable conformance evidence, release templates, and
load testing. The miner-only target does not imply any of those controls.
