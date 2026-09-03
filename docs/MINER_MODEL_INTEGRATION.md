# Miner model integration

The miner accepts a model through either an in-process async callable or an
owner-private Unix socket. Both paths receive the verified MP4 bytes and the
validated `TranslationRequest`. They return English text. UMI handles fetching,
hash checks, length checks, timelock sealing, hotkey signing, retry caching, and
the explicit error response.

Use the Unix socket when the model needs a Torch, Core ML, Python, or native
library stack that cannot share UMI's pinned environment. UMI supports Python
3.10 through 3.14 and pins its Bittensor packages. The socket keeps the model
dependencies and process lifetime separate from the protocol service.
The sidecar callback is trusted model code, not a sandbox for an untrusted model.
The adapter itself opens only the named Unix socket and does not consult HTTP
proxy variables. If the model must have no outbound network access, enforce that
at the sidecar supervisor or container boundary.

## Option 1: compatible in-process model

Export an async callable from an importable module:

```python
from umi.protocol import TranslationRequest


async def translate(video: bytes, request: TranslationRequest) -> str:
    # Decode and preprocess the exact verified MP4 in the model repository.
    # Return one English hypothesis with no JSON wrapper.
    return hypothesis
```

Start the miner with `--translator package.module:translate`. The callable must
not fetch the request URL again. The `video` argument is the body whose byte
length and SHA-256 match `request.video`.

An object backend MAY expose async `startup()` and `shutdown()` methods. The miner
runs them under `--backend-lifecycle-timeout` before accepting traffic and during
shutdown. A startup failure or timeout prevents the miner from serving. This is
the supported place to verify and load model artifacts, probe a device or isolated
worker, and release those resources.

When `--model-revision` is set for an in-process backend, the callable object MUST
expose a `model_revision` string with the same lowercase SHA-256 value. Startup is
rejected when the declared and configured revisions differ or either side is
missing. This prevents the encrypted response from naming a revision that the
loaded backend did not declare.

A synchronous callable requires `--allow-unsafe-sync-translator`. Python cannot
terminate a hung worker thread, so a timed-out synchronous call can keep using
memory or a device after the miner has returned an error. The supplied sidecar
helper accepts only cooperative async callbacks; a synchronous or non-cancellable
native runtime needs an operator-managed process boundary that is terminated and
restarted on deadline failure.

## Option 2: isolated model sidecar

`umi.model_sidecar` is a standard-library-only server helper. It can be imported
from the UMI wheel in a separate model environment without importing Bittensor.
The callback receives the exact verified MP4 and a `CanonicalModelRequest` with
both the canonical JSON bytes and the decoded document.

Install the built UMI wheel into that environment with `pip install --no-deps`
when its dependency set is intentionally separate. Import only
`umi.model_sidecar` and `umi.model_release` there. The model environment owns its
Torch, Core ML, decoder, and native-library versions; those versions belong in the
model repository's release metadata.

```python
import asyncio

from umi.model_sidecar import CanonicalModelRequest, start_model_sidecar

MODEL_REVISION = "<64 lowercase hexadecimal characters>"
SCORING_POLICY_SHA256 = "<64 lowercase hexadecimal characters>"
SOCKET_PATH = "/absolute/private/run/umi-model.sock"
VALIDATOR_SLOTS = 4  # Exact number of validators in the active policy registry.


async def translate(video: bytes, request: CanonicalModelRequest) -> str:
    task = request.document["task"]
    # Model-specific decoding, preprocessing, inference, and decoding stay here.
    return hypothesis


async def main() -> None:
    server = await start_model_sidecar(
        SOCKET_PATH,
        translate,
        model_revision=MODEL_REVISION,
        scoring_policy_sha256=SCORING_POLICY_SHA256,
        validator_slot_count=VALIDATOR_SLOTS,
        maximum_concurrency=VALIDATOR_SLOTS,
        maximum_inference_seconds=120,
    )
    try:
        await server.serve_forever()
    finally:
        await server.close()


asyncio.run(main())
```

Create the socket's parent directory with mode `0700`. The helper refuses to
replace an existing path and changes the socket to mode `0600`. Start the model
worker before the miner. Point the miner at it with
`--translator-unix-socket /absolute/private/run/umi-model.sock`. The miner checks
that the parent is a directory owned by its effective user with mode `0700`, and
that the path is a Unix socket owned by that user with mode `0600`. It checks at
startup and immediately before each connection. It does not use TCP, DNS, or proxy
settings for this path.

The helper writes an owner-only canonical capacity descriptor beside the socket.
It binds the live socket inode and process, model revision, scoring-policy hash,
validator count, enforced sidecar semaphore capacity, and server-side inference
deadline. The miner verifies the descriptor at startup and before every request.
Missing, stale, modified, undersized, or too-slow descriptors stop inference.

Set the sidecar's metadata, video, response, and concurrency ceilings to the same
values as, or tighter values than, the deployed scoring policy. The helper defaults
match the initial version 0.1 byte ceilings, but a later policy can differ.

The helper accepts only async callbacks. It cancels cooperative model work when the
miner closes the request socket and enforces `maximum_inference_seconds` on the
server side. That deadline is recorded in the capacity descriptor and must be no
greater than the miner's configured inference timeout. Native work started by an
async callback may ignore Python task cancellation, so run the worker and miner
under separate supervisors and give the worker a memory limit and restart policy.
A timeout never enables a placeholder hypothesis; the miner seals an
`inference_failed` response instead.

The capacity descriptor proves the UMI and sidecar scheduling limits. It cannot
prove that a model framework, GPU driver, or model callback runs requests in
parallel internally. Calibration must measure this behavior with one blocked
request per validator and enough deadline headroom before the model is offered as
a public baseline.

Run one async UMI protocol process for each hotkey, nonce database, and assignment
database. The assignment database holds an OS advisory lock until that process
exits. A second protocol process using the same database fails startup. The lock
file is a persistent coordination inode, not stale state: do not delete it during
restart handling. The OS releases its lock on both clean and unclean process exit.
Use `--max-inference-concurrency` inside the protocol process, and keep the model in
the separately supervised sidecar when process isolation is needed. The default is
the policy validator count. A lower value is rejected so work from one validator
cannot occupy another validator's model slot. The same minimum applies to the
in-process executor and isolated sidecar.

### Socket frame

Each connection carries one request and one response. Integers use unsigned
big-endian encoding.

Request:

```text
"umi-model-request-v1\0"
U32 metadata byte length
U64 video byte length
32 raw bytes: UMI request digest
32 raw bytes: model revision, or zero bytes when omitted
metadata bytes: exact RFC 8785 TranslationRequest
video bytes: exact verified MP4
```

Response:

```text
"umi-model-response-v1\0"
32 raw bytes: echoed UMI request digest
32 raw bytes: echoed model revision
U32 hypothesis byte length
hypothesis: UTF-8 English text
```

Both endpoints read the fixed prefix and validate its lengths before reading a
payload. The miner rejects a mismatched digest, mismatched revision, truncated
frame, invalid UTF-8, or response over the policy's hypothesis byte ceiling.
Using a new connection for every inference prevents a delayed reply from being
read as another request's result.

## Model revision

`model_revision` is optional in protocol version 0.1, but operators should set
it for every named baseline. Use the SHA-256 identity declared by an immutable
model release manifest. That manifest must bind the checkpoint,
architecture/config, tokenizer/vocabulary, preprocessing/decoder runtime, and
license/provenance material used for inference.

A model repository may define a stricter manifest and use its own verified
identity digest. The backend must prove that identity while loading its artifacts
and expose the same value through `model_revision`. UMI treats the value as an
opaque SHA-256 digest; it does not reinterpret a model repository's canonical
manifest.

For repositories without their own format, `umi.model_release` builds this
minimal canonical schema from five explicit digests without opening or packaging
model artifacts:

```json
{"architecture_config_sha256":"<sha256>","checkpoint_sha256":"<sha256>","license_provenance_sha256":"<sha256>","preprocessing_decoder_sha256":"<sha256>","schema":"umi-model-release/1","tokenizer_vocabulary_sha256":"<sha256>"}
```

```python
from umi.model_release import (
    build_model_release_manifest,
    model_release_revision,
)

manifest = build_model_release_manifest(
    checkpoint_sha256=CHECKPOINT_SHA256,
    architecture_config_sha256=ARCHITECTURE_CONFIG_SHA256,
    tokenizer_vocabulary_sha256=TOKENIZER_VOCABULARY_SHA256,
    preprocessing_decoder_sha256=PREPROCESSING_DECODER_SHA256,
    license_provenance_sha256=LICENSE_PROVENANCE_SHA256,
)
MODEL_REVISION = model_release_revision(manifest)
```

The model repository defines how each component digest is produced and retains
the component files. A component with several files should have its own canonical
manifest and use that manifest's SHA-256 in the release manifest. UMI deliberately
does not prescribe or copy checkpoint formats. The `umi-model-release/1` helper is
a default interoperability format, not a change to the protocol's opaque
`model_revision` field.

Store the release manifest as a regular, single-link, owner-held file, remove all
write bits, then call `read_model_release_manifest` to verify its exact canonical
bytes and revision. That reader refuses symlinks, hard links, writable files,
non-regular files, and a file that changes during the read. It never follows the
component digests to model or data bytes.

Pass the resulting revision to
`start_model_sidecar(..., model_revision=...)` and the miner's `--model-revision`
option. The socket exchange binds that value to each reply, and the miner includes
it only in a successful encrypted response.

For an in-process backend, expose the verified release identity as the callable
object's `model_revision` property and pass the object to `--translator`. The
miner verifies the equality before it runs the backend startup hook.

Changing the model or any inference-affecting artifact requires a new revision.
Cached retries keep the exact response produced by the prior revision, which is
the correct final response for that assignment.

## Handoff checklist

- The model entry point accepts MP4 `bytes`; it does not refetch the challenge.
- All preprocessing and output decoding needed for reproducibility are versioned
  in the model repository and covered by the release-manifest digest.
- The license/provenance record identifies every checkpoint ancestor and dataset
  class, states the permitted distribution and inference uses, and is covered by
  the release-manifest digest.
- The entry point returns one Python `str`. It has no synthetic or placeholder
  fallback.
- The model revision is a lowercase 64-character SHA-256 value and matches on
  both sides of the socket, or between the in-process callable and miner.
- Any in-process setup and teardown are async, bounded lifecycle hooks; the model
  cannot receive a request before its startup hook succeeds.
- The configured inference timeout leaves enough time for response sealing before
  `response_close_round`.
- The socket directory is mode `0700`, the socket is mode `0600`, and both
  processes run as the intended account.
- Exactly one UMI protocol process owns the hotkey and database pair; concurrency
  is at least the policy validator count in both the protocol and model process.
- A known clip succeeds through the miner and decrypts to the expected request,
  serving hotkey, video digest, text, and model revision.
- Timeout, model exception, non-text output, over-limit output, worker restart,
  and miner retry cases produce a sealed error or the original cached response.
- The model and protocol services have separate logs, resource limits, and
  restart policies. Neither log contains video bytes or hypotheses before reveal.

An inaccurate baseline can exercise this interface during shadow calibration.
Its accuracy does not satisfy the metric, positive-utility, soak, or weight
activation gates.
