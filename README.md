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

## Initial subnet implementation

This repository now contains the first executable protocol slice:

```text
validator hotkey
  -> canonical btauth/1 request
  -> POST /v1/translate
  -> bounded video fetch + configured model
  -> timelocked, miner-signed response
  -> Quicknet reveal
  -> exact CER/WER
  -> content-addressed local replay bundle
```

It targets the current `bittensor` v11 HTTP model. It does not use the removed
Axon/Dendrite/Synapse classes.

This slice is intentionally labeled `component_test_no_weight`. It contains no
weight-setting or extrinsic-submission code, never emits `calibration_no_weight`,
and cannot count as protocol conformance or activation evidence. The whitepaper's
publisher quorum, chain anchors, deterministic selection, canaries, spent state,
media-profile decoding, rolling eligibility, and activation gates remain to be
implemented. This component also lacks a finalized receipt-block proof, so it
enforces the Quicknet response-close boundary but does not claim to enforce the
request's earlier `deadline_block` boundary.

## Install

Python 3.10 through 3.14 is supported.

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

The component miner uses an in-memory `btauth/1` nonce store and starts one Uvicorn
worker. Run one miner process per serving hotkey. Replicated or multi-worker
deployment requires a shared atomic nonce store, which this slice does not provide.

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
ruff check src tests neurons
ruff format --check src tests neurons
pytest
```
