# Bootstrap result intake and archival

This is the coordinator-side handoff after the permitted validator publishes an
applied direct-bootstrap result. The validator operator does not run these steps
and does not need to send another file or command output.

The intake command verifies the validator signature, replays the three relevant
finalized extrinsics from raw chain bytes, verifies the block-body roots and
`System.Events` read proofs, reconstructs the execution runtimes, and writes two
outputs:

- a complete content-addressed historical archive; and
- the existing `umi-bootstrap-direct-publication/2` directory consumed by the
  observer.

It does not submit a transaction, use a wallet, or change the c77 validator or
Worker wire formats.

The separate `umi-bootstrap-chain-capture` command produces the private chain
capture consumed by intake. It has a fixed read-only JSON-RPC method allowlist
and reads an existing coordinator-owned finality database. It has no
wallet-aware SDK client, signing, composition, or submission surface.

## Pre-stage before the validator is asked to install

Do all of this on the coordinator first:

1. Preserve Jack's exact owner-fence CLI response and the original RPC capture in
   coordinator-owned durable storage. The current files are
   `/home/sam/umi-validator-cutover-c77/owner-fence-source/sn78-owner-fence-btcli-result.json`
   and `block-9032509-raw-rpc.json`. Their SHA-256 values are, respectively,
   `2ebf9a30b07f79e306648349ecfbf59c0dd4eac9d449374a3289d401c732c1fe`
   and `98d35f1d9f9d4556b47fcf7856ef904499cffa775aa23ca27650350a89ad2e37`.
2. Stage the coordinator's pinned smoldot finality observer before the validator
   starts. Capture one owned-finality head immediately after the signed result is
   available. The capture may prove an earlier target with a contiguous sequence
   of locally hashed headers ending at that attested head.
3. Build the pinned `umi-substrate-proof-verifier` and
   `umi-grandpa-finality-observer` binaries and
   record their exact SHA-256 values. Retain the exact Finney chain spec and its
   SHA-256 alongside them.
4. Prepare a private, coordinator-owned capture directory. It must have enough
   room for three full block bodies, three runtime metadata blobs, and three
   `System.Events` proofs. The hard archive ceiling is 384 MiB.
5. Configure the result watcher for the immutable URL below. A successful GET is
   only an input; it is not launch evidence until `intake` succeeds.

For the current authorization:

```text
submission id: 8479a1d8cbcafa897ac5e6cceba385ae76afcb7f9f71e467116f7de1a2a9294d
result URL: https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-bootstrap-results/8479a1d8cbcafa897ac5e6cceba385ae76afcb7f9f71e467116f7de1a2a9294d.json
```

The current owner-fence block predates coordinator finality retention. Its proof
therefore needs the descendant-header bridge. Run the capture within 16,384
blocks of block `9,032,509`. After that point the bounded bridge cannot represent
the owner-fence ancestry and intake fails closed. An RPC provider's `finalized`
label is not a replacement for the smoldot-attested bridge endpoint.

## Coordinator chain-capture input

The private collector writes one RFC 8785 file with schema
`umi-bootstrap-chain-capture/1`. Its three block entries are ordered exactly as:

1. `owner_fence`, using the block and index in Jack's saved CLI response;
2. `manifest_anchor`, using `result.submission_receipt.anchor`; and
3. `weight_call`, using `result.submission_receipt.weight_call`.

Each `umi-bootstrap-chain-block-evidence/1` entry contains:

- the complete JSON-RPC header fields and the locally reproduced block hash;
- the adjacent execution-parent header;
- the complete ordered raw extrinsic vector, the target index, SHA-256, and
  Blake2-256 extrinsic hash;
- the exact parent-state runtime metadata, canonical runtime-version response,
  and runtime pin;
- the runtime-derived `System.Events` key, exact value, and every read-proof
  node; and
- the exact smoldot attestation, its replay binding, and its hash-chained local
  acceptance receipt; and
- the exact raw RPC capture plus, when the attestation names a later head, no
  more than 16,384 locally hash-verified descendant headers linking the target
  to that head.

Hex byte fields are lowercase, `0x`-prefixed, and even length. Hash fields are
lowercase. The top-level `submission_id` must equal the validator result. Use
`BootstrapChainCapture.model_json_schema()` as the machine-readable schema. Do
not reduce `extrinsics_hex` to the two interesting calls: the proof verifier
needs each complete ordered block body.

The collector must fetch runtime metadata and runtime version at the target
block's **parent hash**. That is the runtime which decoded and executed the
target block. It must fetch `System.Events` and its proof at the target block
hash. For owner block `9,032,509`, import the saved raw RPC file byte for byte,
then supplement its target-block responses with a parent-header query and
parent-state runtime metadata and version. The original capture queried the
target-state runtime; intake will not accept that as execution-runtime evidence.

After the signed validator result is downloaded, run the collector once. The
finality recorder must already contain an accepted head at or after the weight
block. Use the corrected observer binary installed for that recorder, not the
c77 binary with the stale Rust release identity.

```sh
sudo /opt/umi-bootstrap-chain-capture/.venv/bin/umi-bootstrap-chain-capture \
  --signed-result /var/lib/umi/bootstrap-intake/signed-result.json \
  --owner-cli-result /home/sam/umi-validator-cutover-c77/owner-fence-source/sn78-owner-fence-btcli-result.json \
  --owner-raw-rpc-capture /home/sam/umi-validator-cutover-c77/owner-fence-source/block-9032509-raw-rpc.json \
  --state-db /var/lib/umi-bootstrap-finality-recorder/finality.sqlite3 \
  --finality-verifier /opt/umi-bootstrap-finality-recorder/artifacts/umi-grandpa-finality-observer \
  --chain-spec /opt/umi-bootstrap-finality-recorder/artifacts/raw_spec_finney.json \
  --rpc-endpoint wss://entrypoint-finney.opentensor.ai:443 \
  --bridge-concurrency 32 \
  --output /var/lib/umi/bootstrap-intake/captured-chain-material.json
```

The output path is create-only and mode `0600`. A second run must use a new,
empty path. The collector cross-checks every target and parent header against
the canonical height-to-hash mapping, retains the complete ordered block body,
derives `System.Events` from the parent runtime, and includes its exact value
and read proof. The historical owner-fence bridge is capped at 16,384 headers.
The RPC transcript stores the exact decoded results in canonical form and embeds
the earlier owner RPC capture as opaque bytes with its SHA-256.

## Intake after the upload appears

Download create-only into a new path and verify the HTTP body is the exact body
returned on a second GET. Then run:

```sh
umi-bootstrap-result-intake intake \
  --signed-result /var/lib/umi/bootstrap-intake/signed-result.json \
  --owner-cli-result /var/lib/umi/bootstrap-cutover/owner-fence-btcli-result.json \
  --chain-capture /var/lib/umi/bootstrap-intake/captured-chain-material.json \
  --archive-root /var/lib/umi/bootstrap-archives/8479a1d8cbcafa897ac5e6cceba385ae76afcb7f9f71e467116f7de1a2a9294d \
  --observer-publication-root /var/lib/umi/observer/bootstrap-publications/8479a1d8cbcafa897ac5e6cceba385ae76afcb7f9f71e467116f7de1a2a9294d \
  --proof-verifier /opt/umi/bin/umi-substrate-proof-verifier \
  --proof-verifier-sha256 "$PROOF_VERIFIER_SHA256" \
  --finality-verifier /opt/umi/bin/umi-grandpa-finality-observer \
  --finality-verifier-sha256 "$FINALITY_VERIFIER_SHA256" \
  --chain-spec /opt/umi/finney.json \
  --chain-spec-sha256 "$FINNEY_CHAIN_SPEC_SHA256" \
  --genesis-hash 0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03 \
  --bootstrap-block-number 8867448 \
  --bootstrap-block-hash 0x511948e96e1d479d0a92d89bb976638780f2c65a93a5d5be710f22ee15c60200
```

The command fails before publishing either directory if any signature, hash,
reference, root, proof, runtime, signer, call argument, event, or byte limit is
wrong. It specifically decodes and checks:

- Jack's `Utility.batch_all` owner fence and its three ordered inner calls;
- the validator's `Commitments.set_commitment` SHA-256 anchor; and
- the validator's full 256-entry `set_mechanism_weights` call and matching
  `WeightsSet` event.

No seed phrase, wallet path, uploader credential, or validator access is used.

## Replay before publication

Run the verifier independently against the completed archive:

```sh
umi-bootstrap-result-intake verify \
  --archive-root /var/lib/umi/bootstrap-archives/8479a1d8cbcafa897ac5e6cceba385ae76afcb7f9f71e467116f7de1a2a9294d \
  --proof-verifier /opt/umi/bin/umi-substrate-proof-verifier \
  --proof-verifier-sha256 "$PROOF_VERIFIER_SHA256" \
  --finality-verifier /opt/umi/bin/umi-grandpa-finality-observer \
  --finality-verifier-sha256 "$FINALITY_VERIFIER_SHA256" \
  --chain-spec /opt/umi/finney.json \
  --chain-spec-sha256 "$FINNEY_CHAIN_SPEC_SHA256" \
  --genesis-hash 0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03 \
  --bootstrap-block-number 8867448 \
  --bootstrap-block-hash 0x511948e96e1d479d0a92d89bb976638780f2c65a93a5d5be710f22ee15c60200
```

Add the new observer-publication directory to the canonical
`umi-observer-bootstrap-service-feed-config/1` `bundle_roots` list, encode that
config with RFC 8785, and restart only the observer service. Confirm all of the
following before announcing the row:

```text
GET https://api.umi.vision/api/v1/bootstrap-service
GET https://api.umi.vision/api/v1/status
GET https://api.umi.vision/readyz
```

The bootstrap-service response must name the new submission and report active
only if the live chain still contains the exact applied row. The complete
archive remains separate from the narrower observer bundle; publish or mirror
it under its manifest SHA-256 before the launch announcement.

## Failure handling

- Never ask the validator to resubmit an issued authorization.
- Never edit an archive or publication directory in place. Correct a collector
  problem and run into new, empty output paths.
- A missing result means wait. An invalid signed result is a terminal incident,
  not permission to ask for a second weight call.
- A capture or proof failure is coordinator-side. Recollect the same finalized
  bytes and proofs; it does not require Dan to change or rerun anything.
- If the observer says the row is no longer current, preserve the archive but
  do not describe the service mechanism as active.

The retained smoldot records are verifier attestations, not portable GRANDPA
justifications. Replay checks their pinned format, transcript binding, header
and ancestry, while their acceptance receipts bind them to the coordinator's
durable owned-finality store. This matches the finality evidence boundary used
elsewhere in UMI.
