# UMI

UMI is building a trust-minimized translation layer at the boundary between people
and machines. Its first subnet mechanism is deliberately narrow: miners translate
raw American Sign Language video into English, and validators score sealed, signed
responses against references that were fixed before assignment.

The longer-term protocol can expand to other directions and forms of human-machine
interaction only when each task has an independently useful output and a
reproducible, adversarially tested mechanism. Each later task requires a separate
protocol extension.

- [UMI whitepaper (PDF)](whitepaper/UMI-Whitepaper.pdf)
- [LaTeX publication source](whitepaper/main.tex)
- [Plain-text protocol source](whitepaper/README.md)
- [bitsign product MVP](roadmap/bitsign-mvp/README.md)

## Current status

SN78 is active on mainnet, but UMI translation weights are not. The repository is
ready for implementation review, miner integration, component tests, and offline
shadow rehearsal. It is not ready for weight activation.

There are two executable paths:

```text
component test
validator hotkey
  -> canonical btauth/1 request
  -> POST /v1/translate
  -> bounded video fetch + configured model
  -> timelocked, miner-signed response
  -> Quicknet reveal
  -> exact CER/WER
  -> content-addressed local replay bundle

offline shadow rehearsal
canonical window evidence
  -> policy and runtime-pin verification
  -> pool quorum and deterministic selection
  -> assignment, request, and sealed-response roots
  -> canary, spent-state, rolling-score, and weight projection
  -> bounded seven-stage audit bundle
  -> no chain write
```

Both paths target the `bittensor` v11 HTTP model. They do not use the removed
Axon/Dendrite/Synapse classes.

Implemented and adversarially tested offline primitives include canonical policy
hashing, runtime and imported-module pins, bounded media decoding, strict portable
timelock parsing, publisher pool certificates, post-close selection, three
pre-reveal anchor sets, copy-bound authentication evidence, canaries, spent-state
replay, rolling eligibility, exact weight projection, audit-bundle verification,
and unsigned chain-call/evidence helpers.

The remaining activation work is deliberately fail-closed:

- no active scoring policy can be constructed; `translation_weights_active` is
  fixed to `false` in the shipped schema;
- the offline shadow runner has no finalized chain collector, storage-proof
  verifier, real response timelocks, ground-truth decryption, or weight submission;
- resource accounting and preflight exist as tested primitives but are not wired
  through the shadow runner's HTTP stages;
- publisher-fault roots advance across empty windows, but nonempty strikes are
  disabled until a finalized-chain-bound objective classifier exists;
- shadow rolling and registry state starts at version genesis and is not a
  persistent multi-window validator state machine;
- the external publisher, miner-utility, metric-validity, challenge-supply,
  economics, and soak gates in the whitepaper have not passed.

`component_test_no_weight` and `shadow_rehearsal_no_weight` are local engineering
results. Neither is `calibration_no_weight`, protocol conformance, or activation
evidence. The component validator also lacks a finalized receipt-block proof, so
it checks the Quicknet response-close boundary without claiming the request's
earlier block deadline.

## Install

Python 3.10 through 3.14 is supported. FFmpeg and FFprobe are required for policy
construction, shadow rehearsal, media inspection, and the full test suite. Install
the `ffmpeg` package with your operating-system package manager first, for example
`brew install ffmpeg` on macOS or `sudo apt-get install ffmpeg` on Ubuntu.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

The runtime is pinned to `bittensor==11.1.0`; the SDK, wallet, and `btcli` now ship
as one package.

## Translation backend

The miner requires a trusted Python callable and has no placeholder fallback. Pass
it as `module:callable`. The callable receives verified video bytes and the parsed
request, may be synchronous or asynchronous, and must return an English string:

```python
async def translate(video: bytes, request) -> str:
    return await your_model.translate_asl(video)
```

If fetching, decoding, or inference fails, the miner emits a signed, timelocked
error response whose score is zero.

Inference concurrency defaults to one and can be changed with
`--max-inference-concurrency`. Synchronous plugins run in a dedicated bounded
thread pool. Python cannot terminate a hung worker thread, so a synchronous backend
must implement its own cancellation and the operator must restart a process whose
backend does not return.

The miner defaults to an in-memory `btauth/1` nonce store. Pass
`--nonce-db /var/lib/umi/nonces.sqlite3` for a transactional SQLite store shared by
processes on one host. Run one serving hotkey per database. A multi-host deployment
still needs an external atomic replay store, which this repository does not ship.

## Run an offline shadow rehearsal

The shadow input is one exact RFC 8785 `umi-shadow-rehearsal/1` object. Its strict
schema is `ShadowRehearsalEvidence` in `src/umi/shadow.py`. It contains the inactive
policy, three publisher pools, the availability quorum, a verified Quicknet pulse,
public and revealed batch material, a miner panel, validator-signed request
transcripts, and miner-signed rehearsal responses.

Run and independently verify it with:

```bash
umi-protocol run-shadow-rehearsal \
  --input window.json \
  --output shadow-runs/window-0

umi-protocol verify-rehearsal-bundle \
  --bundle shadow-runs/window-0
```

The command refuses noncanonical input, mismatched local dependency bytes,
import-shadowed modules, active policies, and a nonempty output directory. It
prints false values for translation-weight activation, protocol conformance, and
activation evidence.

A portable static fixture is intentionally not checked in because the local
rehearsal policy binds the exact UMI source tree, Python runtime, installed package
bytes, and FFmpeg binaries. The complete executable fixture constructor and
adversarial cases are in `tests/test_shadow.py`. To exercise that path on a new
checkout, run:

```bash
pytest -q tests/test_shadow.py
```

Other read-only protocol tools are discoverable with `umi-protocol --help`. They
hash inactive policies, inspect media, verify public batches and publisher-capacity
signatures, and verify rehearsal bundles. None signs or broadcasts a chain call.

## Run a component test

First run the local smoke flow. It uses development hotkeys, an
in-process HTTP transport, fixture video bytes, and a deterministic translator. It
makes no chain write and normally completes in under 20 seconds. Both the run and
replay need outbound access to fetch published Quicknet round signatures:

```bash
umi-demo --output component-runs/demo
umi-validator replay --bundle component-runs/demo/bundle
```

This checks signed requests, response and ground-truth timelocks, exact scoring,
bundle creation, and independent replay. It does not test media decoding or a real
translation model.

For a model-backed component test, create the named wallets and hotkeys with
`btcli`, then prepare a case from a JSON array of `umi-asl/0.1` requests and its
matching canonical `umi-ground-truth/1` object:

```bash
btcli subnets register \
  --netuid 78 \
  --network finney \
  --wallet umi \
  --wallet-hotkey miner \
  --mev-shield
```

Registration is needed only once per hotkey and spends the live registration cost.
The pinned client requires MEV Shield for this coldkey-signed registration intent.
Review the live cost before submitting it.

```bash
umi-validator prepare \
  --requests requests.json \
  --ground-truth ground-truth.json \
  --output component-runs/case-001
```

The prepared directory contains the public requests and encrypted ground truth;
it does not contain reference plaintext.

Start the miner with an explicit validator allowlist and video-host allowlist:

```bash
umi-miner \
  --wallet-name umi \
  --hotkey miner \
  --translator your_package.model:translate \
  --validator-hotkey 5F... \
  --video-host challenges.example.org \
  --listen-host 0.0.0.0 \
  --port 8091
```

HTTPS port 443 is allowed by default. Repeat `--video-port` to admit a different
port explicitly.

After the service is reachable, replace `YOUR_PUBLIC_IP` and publish its endpoint:

```bash
btcli tx serve-axon \
  --netuid 78 \
  --ip YOUR_PUBLIC_IP \
  --port 8091 \
  --network finney \
  --wallet umi \
  --wallet-hotkey miner \
  --no-mev-shield
```

The serving call is hotkey-signed, so this profile submits it without MEV Shield.
The miner process itself makes no chain call.

Run the validator. Omitting `--miner-url` performs read-only SN78 metagraph
discovery; an explicit origin is useful for a local component test:

```bash
umi-validator run-once \
  --case component-runs/case-001 \
  --output component-runs/run-001 \
  --wallet-name umi \
  --hotkey validator \
  --miner-hotkey 5F... \
  --miner-url http://127.0.0.1:8091
```

The runner waits for the common Quicknet round, opens ground truth and miner
responses together, retains every failed assignment as zero, and writes a local
content-addressed evidence bundle. The CLI prints the score summary and scoring
object hash. Replay checks the recorded Python, Unicode, regex, and scorer versions
before recomputing without contacting the miner or model. It still contacts
Quicknet for the public round signatures needed to open the timelocks:

```bash
umi-validator replay --bundle component-runs/run-001
```

## Verify

```bash
make check
python -m pip wheel . --no-deps --wheel-dir dist
```

## License

UMI is licensed under the [Apache License 2.0](LICENSE).
