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
- [public observer API contract](docs/DASHBOARD_API.md)
- [miner model integration](docs/MINER_MODEL_INTEGRATION.md)
- [publisher batch operator](docs/PUBLISHER_BATCH_OPERATOR.md)
- [publisher availability operator](docs/PUBLISHER_AVAILABILITY_OPERATOR.md)
- [reference mirror and delivery service](docs/MIRROR_SERVICE_OPERATOR.md)
- [public validator audit-bundle publication](docs/AUDIT_BUNDLE_PUBLICATION_OPERATOR.md)
- [inactive live-shadow release operator](docs/SHADOW_CALIBRATION_OPERATOR.md)
- [inactive calibration launch checklist](docs/INACTIVE_LAUNCH_CHECKLIST.md)

## Current status

SN78 is active on mainnet, but UMI translation weights are not. The repository is
ready to share for implementation review, miner integration, component tests, and
offline shadow rehearsal. The calibration profile is published, but public
calibration has not started and the repository is not ready for weight activation.

There are three distinct executable paths:

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

offline release and conformance rehearsal
canonical window evidence
  -> policy and runtime-pin verification
  -> pool quorum and deterministic selection
  -> assignment, request, and sealed-response roots
  -> canary, spent-state, rolling-score, and weight projection
  -> bounded seven-stage audit bundle
  -> no chain write

installed inactive live shadow
signed, hash-pinned release + private operator bindings
  -> owned smoldot finality + proof-verified chain reads
  -> certified mirror retrieval and authenticated miner delivery
  -> three finalized transcript anchors and live btauth/1 requests
  -> response and ground-truth timelock reveal
  -> persistent spent, publisher-fault, rolling-score, and monitoring state
  -> exact projected row + signed calibration or incident bundle
  -> no weight-call capability
```

All three paths target the `bittensor` v11 HTTP model. They do not use the removed
Axon/Dendrite/Synapse classes.

The repository also supplies the publisher batch builder, availability workflow,
pool-anchor operator, and authenticated content-addressed mirror and delivery
service required by the live path. The validator's seven stages use durable
receipts and persistent protocol state. A quorum-certified mirror-child loss is a
terminal `certificate_breach`, not an infinite retry: after the signed incident is
published, an installed reconciliation command accepts only the originally
committed objects, applies the public retirement and objective-fault transition
without scoring the failed window, and releases only that incident's intake hold.

The protocol implementation is complete for the planned baseline demonstration.
The separately versioned `umi-reference-model` repository contains the
`umi-s1-baseline-v0` miner fixture and its release evidence. That model is
deliberately low-accuracy and is a replacement target for miners, not activation
evidence.

The remaining work before public calibration is deployment work: publish the
owner-approved model release, then create the signed inactive UMI release and
operator bindings for the exact policy, binaries, identities, mirrors, and
configuration that will be deployed. These steps do not require another mechanism
implementation.

On supported Linux release targets, every FFmpeg and FFprobe child enters a finite
address-space, CPU, and core-dump envelope before the pinned executable runs. A
wall-clock deadline kills the complete process group. Darwin reserves a very large
shared virtual-address region, so local component tooling on macOS still needs an
outer memory sandbox when it inspects untrusted media. Public validator releases
target Linux.

The remaining weight-activation gates are external evidence and governance work,
not missing inactive-validator code. They include independent publishers and
validators, miner implementation diversity and positive utility, consented
challenge supply, metric and canary studies, validator economics, the full shadow
soak and drills, and a later governed policy with
`translation_weights_active: true`. The shipped release schema fixes that field to
`false`, and the installed live runtime has no weight-call builder, signer, or
submitter.

`component_test_no_weight` and `shadow_rehearsal_no_weight` remain local engineering
results; neither is activation evidence. A correctly deployed installed path may
produce `calibration_no_weight` only after completing and replaying all seven live
stages under the signed inactive policy. The component validator also lacks a
finalized receipt-block proof, so it checks the Quicknet response-close boundary
without claiming the request's earlier block deadline.

## Install

Python 3.10 through 3.14 is supported. FFmpeg and FFprobe are required for policy
construction, shadow rehearsal, media inspection, and the full test suite. Install
the `ffmpeg` package with your operating-system package manager first, for example
`brew install ffmpeg` on macOS or `sudo apt-get install ffmpeg` on Ubuntu.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install uv==0.12.9
uv sync --locked --extra dev
```

The runtime is pinned to `bittensor==11.1.0`; the SDK, wallet, and `btcli` now ship
as one package. `uv.lock` is the reviewed dependency lock used by CI and release
verification.

## Owned Finney finality

The live operator does not trust a provider RPC's `finalized` label. Its pinned
Rust sidecar embeds smoldot and connects to Finney peers directly. Version 0.1
accepts only the official subtensor
`grandpaWarpSyncCheckpoint` at block 8,867,448, bound by exact chain-spec,
checkpoint, source, lockfile, fixture, and release-binary hashes. The sidecar
requires smoldot to select that exact checkpoint and to advance beyond it before
emitting an attestation. Genesis and legacy `lightSyncState` fallback are rejected.

This checkpoint is an explicit governed weak-subjectivity assumption. Subsequent
warp and GRANDPA verification is performed locally, but the emitted evidence is a
hash-pinned verifier attestation rather than portable GRANDPA proof bytes. Remote
storage reads are accepted only after the independent proof verifier binds them to
an attested state root. The unsigned transcript and local acceptance-receipt hash
chain are replay evidence, not standalone finality authority: activation evidence
must come directly from running the exact pinned sidecar over its peer-to-peer
path. See
[the finality observer notes](rust/grandpa-finality-observer/README.md) for the
exact assumptions, patches, and artifact pins.

## Build the inactive live-shadow release

The release builder produces the canonical weight-disabled calibration policy and
keeps wallet names, local paths, state directories, and private mirror headers out
of the public release. Publisher-capacity signing and each final artifact write run the
pinned smoldot observer and storage-proof collector directly; `--check` is strictly
offline and cannot authorize a release. Follow the complete two-pass workflow in
the [shadow calibration operator guide](docs/SHADOW_CALIBRATION_OPERATOR.md).

## Run the public observer API

The observer API gives `umi.vision` one read-only source for finalized SN78 state:

```bash
umi-observer \
  --listen-host 127.0.0.1 \
  --port 8092 \
  --trusted-host api.umi.vision \
  --bundle-feed-config /etc/umi/observer-bundle-feed.json
```

It collects one internally consistent finalized block in the background and
atomically publishes the last complete snapshot. Public requests read the cache;
they do not trigger chain calls, miner probes, or artifact fetches. The process
loads no wallet and contains no signing or transaction path.
Run it on an always-on host; the `umi.vision` Vercel route is a same-origin proxy,
not the background collector.

The API exposes network state and public participant economics. Existing
incentive, dividend, and emission values are labeled `unverified` until the required
UMI cutover audit classifies them. They are never presented as UMI translation
performance. Released validator bundles appear only after bounded HTTPS retrieval
and independent production replay. Their scores remain validator-local; they are
not merged into a consensus leaderboard. Feeds without conforming evidence remain
explicit empty states.
See the [dashboard API contract](docs/DASHBOARD_API.md) for endpoint schemas,
Vercel integration, exact number handling, and deployment controls.

## Run the certified mirror data plane

The repository includes a reference authenticated mirror and short-lived miner
delivery service for each certified window. It serves only the immutable certified
tree, gives each registered validator one private bearer and one durable issuance,
and exposes only deterministic opaque delivery tokens before their expiry. It has
no chain or weight-write capability. See the
[mirror service operator guide](docs/MIRROR_SERVICE_OPERATOR.md) for private config,
TLS/reverse-proxy isolation, offline checking, rotation, and the bounded selection
proof limitation.

## Translation backend

The miner requires a trusted model backend and has no placeholder fallback. A
compatible model can run as an in-process `module:callable`. A model with a separate
Torch, Core ML, Python, or native dependency stack can run behind the local Unix
socket adapter described in the [model integration guide](docs/MINER_MODEL_INTEGRATION.md).
Both paths receive verified video bytes and the parsed request and must return an
English string. An in-process callable must be asynchronous by default:

```python
async def translate(video: bytes, request) -> str:
    return await your_model.translate_asl(video)
```

If fetching, decoding, or inference fails, the miner emits a signed, timelocked
error response whose score is zero.

Inference concurrency defaults to the policy validator count. An explicit
`--max-inference-concurrency` below that count is rejected, which reserves one
runnable slot for each validator. A synchronous plugin requires the explicit
`--allow-unsafe-sync-translator` flag and runs in a dedicated bounded thread pool.
Python cannot terminate a hung worker thread, so such a backend must implement its
own cancellation and the operator must restart a process whose backend does not
return. The isolated sidecar helper accepts cooperative async callbacks and binds
its own inference deadline into the capacity descriptor. When the model artifact
is fixed, pass its lowercase SHA-256 digest through `--model-revision`; the value
is audit metadata and has no score weight. A versioned in-process callable must
declare the same digest through its `model_revision` property. It may also expose
async `startup()` and `shutdown()` hooks, which the miner runs under a bounded
lifecycle timeout before serving and during shutdown. Waiting for a model slot is
bounded separately from inference itself.

The miner requires a canonical inactive scoring policy and two durable SQLite
stores. The policy supplies the validator registry, authentication window, request
limits, and response limits. `--nonce-db` retains accepted `btauth/1` nonces, while
`--assignment-db` retains resource counters, verified clip bytes through response
close, and the first encrypted response for each assignment. An exact retry returns
the same signed ciphertext without fetching the clip or running inference again.
Store the policy in a directory owned by the miner account and not writable by
group or other users. The policy must be a regular, single-link file owned by that
account and not group- or world-writable. Put each SQLite store in an owner-only
mode-`0700` directory; the database, journal, shared-memory, and lock files must be
regular, single-link, owner-only mode-`0600` files. Startup rejects symlinks,
hardlinks, unsafe modes, owner mismatches, and replaced database files.
Run exactly one UMI protocol process for each serving hotkey and database pair.
The assignment database holds an OS advisory lock for that process's lifetime, and
a second process fails startup. Use `--max-inference-concurrency` for concurrency
inside the process and a separately supervised model sidecar for dependency or
process isolation. The lock file persists across restarts; do not delete it. The OS
releases the lock when the process exits, including after a crash. Same-host
multi-process and multi-host sharing are unsupported in version 0.1.

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
import-shadowed modules, active policies, and a nonempty output directory. The
bundle embeds its canonical source evidence, and verification reruns the complete
rehearsal into a fresh directory and requires an identical canonical manifest. It
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

Start the miner with the policy-bound validator registry and a narrow video-host
allowlist:

```bash
umi-miner \
  --wallet-name umi \
  --hotkey miner \
  --policy /absolute/config/shadow-policy.json \
  --target-triple x86_64-unknown-linux-musl \
  --finality-verifier-binary /absolute/release/artifacts/sha256/DIGEST/umi-grandpa-finality-observer \
  --finality-chain-spec /absolute/release/artifacts/sha256/DIGEST/finney-chain-spec.json \
  --finality-state /var/lib/umi/miner-finality.sqlite3 \
  --translator your_package.model:translator \
  --model-revision 64_LOWERCASE_HEX_CHARACTERS \
  --video-host delivery-a.example.org \
  --video-host delivery-b.example.org \
  --video-host delivery-c.example.org \
  --nonce-db /var/lib/umi/miner-nonces.sqlite3 \
  --assignment-db /var/lib/umi/miner-assignments.sqlite3 \
  --listen-host 127.0.0.1 \
  --port 8091
```

Take the target triple, finality binary, chain spec, and scoring policy from the
verified inactive release. Use one `--video-host` for every delivery origin in
that release's mirror-discovery rule and no other host. Start the miner early
enough for its owned finality observer to reach the policy activation block.
Use `--translator-unix-socket` instead of `--translator` when the model runs in
the isolated process described below.

Expose that loopback service through a TLS edge or reverse proxy with a publicly
trusted certificate for the exact advertised IP address, a 16 KiB header cap,
bounded connection and request rates, and finite header/body read timeouts. UMI
rejects cleartext transport to public miner endpoints. The proxy must forward the
exact request target, authentication headers, and body bytes without normalization.
Direct public Uvicorn listening leaves encryption, header-level slow connections,
and volumetric filtering outside the application boundary.

[Let's Encrypt IP-address certificates](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)
are publicly available but expire after roughly six days. Automate renewal and
proxy reload before serving. Certbot 5.4 or later can request one after port 80 is
routed to the proxy's ACME webroot:

```bash
sudo certbot certonly \
  --preferred-profile shortlived \
  --webroot \
  --webroot-path /var/www/acme \
  --ip-address YOUR_PUBLIC_IP \
  --deploy-hook 'systemctl reload your-umi-tls-proxy'
```

HTTPS port 443 is allowed by default. Repeat `--video-port` to admit a different
port explicitly. Production fetches resolve the allowlisted hostname once per
attempt, reject any non-public result, pin the connection to one deterministic IP,
and preserve the original Host authority and TLS SNI. Proxy environment variables
are ignored. Operators should use a controlled DNS resolver and keep the allowlist
narrow.

After the service is reachable, replace `YOUR_PUBLIC_IP` and publish its endpoint:

```bash
btcli tx serve-axon \
  --netuid 78 \
  --ip YOUR_PUBLIC_IP \
  --port 443 \
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

UMI-authored code is licensed under the [Apache License 2.0](LICENSE). The
[third-party notices](THIRD_PARTY_NOTICES.md) identify vendored components that
retain other upstream terms and describe the per-binary release license closures.
