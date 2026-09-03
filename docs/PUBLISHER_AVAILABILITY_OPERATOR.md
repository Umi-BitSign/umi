# Publisher availability operator

`umi-publisher-availability` implements the publisher and validator handoff that
precedes pool anchoring. It is restricted to a policy whose
`translation_weights_active` value is `false`. Its authority-collection step has
a read-only chain client. The command has no transaction signer or
weight-submission path.

The workflow has seven steps:

1. Publishers prepare canonical pool bodies, public batch manifests, timelock
   envelopes, and videos. A coordinator assembles their exact union into one
   immutable candidate bundle.
2. Each active validator runs the planner-only `--prime-next-window` command from
   its signed live configuration. The command verifies finalized headers and
   records the deterministic window at `pool_and_selection`. It opens no wallet,
   mirror, anchor, transcript, or stage adapter.
3. Each active validator collects the complete permit set at the exact
   `announcement_block` from the validator's existing finality database and raw
   storage proofs.
4. Each active validator verifies and retains the same bundle before
   `proposal_close_block`, reserves its availability root durably, and signs the
   protocol availability digest. The validator returns a signed qualification
   receipt.
5. A publisher or mirror operator verifies a quorum of receipts and materializes
   the final pool manifests and static mirror tree. The output includes exact
   pool-anchor intents for an external hotkey operator.
6. Every availability signer deploys one independently administered mirror pair,
   checks its exact immutable service definition, and signs a readiness statement
   bound to its qualification receipt, certified release, and anchor intents.
7. The coordinator verifies one unique retrieval/delivery pair from every
   certificate signer and produces the readiness-set digest required before any
   pool anchor is submitted.

All paths below should be absolute. Run every `--check` form first. A check reads
and validates its inputs, including media decoding, but creates no wallet, state
directory, receipt, bundle, release, signature, or transaction.

Run every availability command with the exact media tools from the already
verified inactive release. They live in separate content-addressed directories,
so installing the Python wheel does not put them on `PATH`:

```sh
RELEASE="$(realpath /operator/local/path/to/public-release)"
FFMPEG_RELATIVE_PATH="$(
  jq -er '.external_artifacts[] | select(.label == "ffmpeg_binary") | .relative_path' \
    "$RELEASE/release-manifest.json"
)"
FFMPEG_SHA256="$(
  jq -er '.external_artifacts[] | select(.label == "ffmpeg_binary") | .sha256' \
    "$RELEASE/release-manifest.json"
)"
FFPROBE_RELATIVE_PATH="$(
  jq -er '.external_artifacts[] | select(.label == "ffprobe_binary") | .relative_path' \
    "$RELEASE/release-manifest.json"
)"
FFPROBE_SHA256="$(
  jq -er '.external_artifacts[] | select(.label == "ffprobe_binary") | .sha256' \
    "$RELEASE/release-manifest.json"
)"
case "$FFMPEG_RELATIVE_PATH" in "artifacts/sha256/$FFMPEG_SHA256/ffmpeg") ;; *) exit 1 ;; esac
case "$FFPROBE_RELATIVE_PATH" in "artifacts/sha256/$FFPROBE_SHA256/ffprobe") ;; *) exit 1 ;; esac
FFMPEG_PATH="$RELEASE/$FFMPEG_RELATIVE_PATH"
FFPROBE_PATH="$RELEASE/$FFPROBE_RELATIVE_PATH"
test "$(sha256sum "$FFMPEG_PATH" | cut -d ' ' -f 1)" = "$FFMPEG_SHA256"
test "$(sha256sum "$FFPROBE_PATH" | cut -d ' ' -f 1)" = "$FFPROBE_SHA256"
export PATH="$(dirname "$FFMPEG_PATH"):$(dirname "$FFPROBE_PATH"):$PATH"
test "$(command -v ffmpeg)" = "$FFMPEG_PATH"
test "$(command -v ffprobe)" = "$FFPROBE_PATH"
```

The coordinator and every validator keep this environment for `assemble`,
`qualify`, and `aggregate`. Do not copy, symlink, or substitute either executable.
Media inspection opens the resolved files, verifies their signed policy digests
and ownership constraints, copies them into a private execution directory, and
invokes only those copies.

## 1. Assemble the candidate bundle

Each publisher can produce its pool body, public manifest, timelock, and 14 videos
with the [publisher batch operator](PUBLISHER_BATCH_OPERATOR.md). Its
`availability-config` command combines one to three immutable publisher release
directories into the exact assembly file described below.

Create a canonical `umi-availability-assembly-config/1` JSON file. Its shape is:

```json
{
  "schema": "umi-availability-assembly-config/1",
  "protocol": "umi-asl/0.1",
  "window": {
    "window_id": "64-lowercase-hex",
    "window_index": 0,
    "scoring_policy_hash": "64-lowercase-hex",
    "announcement_block": 1000,
    "proposal_close_block": 1030,
    "closing_block": 1045,
    "selection_round": 123456,
    "issue_close_round": 123476,
    "response_close_round": 123496,
    "reveal_round": 123596
  },
  "pool_body_paths": [
    "/absolute/input/publisher-a-pool-body.json",
    "/absolute/input/publisher-b-pool-body.json"
  ],
  "public_manifest_paths": [
    "/absolute/input/batch-a-public.json",
    "/absolute/input/batch-b-public.json"
  ],
  "ground_truth_envelopes": [
    {"batch_id": "base64url-128-bit-id", "path": "/absolute/input/batch-a.tle"}
  ],
  "videos": [
    {
      "batch_id": "base64url-128-bit-id",
      "challenge_id": "base64url-128-bit-id",
      "path": "/absolute/input/clip.mp4"
    }
  ]
}
```

Path arrays must be unique and sorted. Envelope rows are sorted by decoded batch
ID. Video rows are sorted by decoded `(batch_id, challenge_id)`. The set must
contain every artifact referenced by every pool body and no extra artifact.

Check the input graph:

```sh
umi-publisher-availability assemble \
  --policy /absolute/config/shadow-policy.json \
  --assembly /absolute/config/assembly.json \
  --check
```

Create a new immutable bundle directory:

```sh
umi-publisher-availability assemble \
  --policy /absolute/config/shadow-policy.json \
  --assembly /absolute/config/assembly.json \
  --output /absolute/output/candidate-window-0
```

Distribute the complete output directory to every active validator. The
`candidate_set_sha256` printed by every validator must be identical.

## 2. Collect the announcement authority

Before the announcement block, start the planner with the signed validator
configuration alone:

```sh
VALIDATOR_CONFIG=/absolute/private/startup-config/operator-templates/VALIDATOR_ACCOUNT_ID32_HEX.validator.json
umi-validator-live \
  --config "$VALIDATOR_CONFIG" \
  --prime-next-window
```

The command waits for the policy-pinned finality observer to verify the exact next
announcement block. Starting it early lets that observer retain the required exact
header rather than connecting after it has passed. The command then records one
active `pool_and_selection` window and exits.
It refuses to record a new window once `proposal_close_block` is finalized. A
repeat returns `already_primed` only while that same active window remains at the
pool stage. An active later stage, a missing prior terminal bundle, inconsistent
protocol state, or a finality gap fails closed.

Do not pass `--operator-config` to this command. The mirror readiness set does not
exist yet, and the planner has no reason to load a wallet or private mirror
credentials. Full `--check` and serving startup still require the operator config,
verified readiness set, and all seven stage adapters. Use the same live-validator
`state_root` in the validator config and as `validator_state_root` in the authority
config. The later qualification `--state-root` is a separate owner-private
retention store and must not overlap the validator root or any input.

Use the state root initialized by the primer and reserved for the live validator.
Its finality database must already contain the exact `announcement_block` and its
parent. The collector
audits that database, binds raw RPC storage proofs to it, and calls the same
`ProofBackedClosingSnapshotCollector` implementation used at pool close. It does
not trust a metagraph response or an operator-written permit list.

Create a canonical `umi-availability-qualification-authority-config/1` file:

```json
{
  "schema": "umi-availability-qualification-authority-config/1",
  "protocol": "umi-asl/0.1",
  "network": "finney",
  "target_triple": "x86_64-unknown-linux-musl",
  "storage_proof_verifier_binary": "/absolute/bin/umi-substrate-proof-verifier",
  "finality_verifier_binary": "/absolute/bin/umi-grandpa-finality-observer",
  "finality_chain_spec_path": "/absolute/config/finney.json",
  "validator_state_root": "/absolute/validator-state",
  "finality_startup_timeout_seconds": 120
}
```

The state root must be the private root initialized by `--prime-next-window`. The
command requires its control-plane, stage-journal, protocol-state,
plan-observation, and GRANDPA stores at their standard paths. It refuses a
missing, replaceable, symlinked, foreign-owned, or writable-by-others tree and
does not create a new validator history from a misspelled path.

Check proof collection without writing an output directory. This check connects
to the read-only chain RPC and starts the policy-pinned smoldot observer:

```sh
umi-publisher-availability collect-authority \
  --policy /absolute/config/shadow-policy.json \
  --candidate-bundle /absolute/input/candidate-window-0 \
  --authority-config /absolute/config/availability-authority.json \
  --check
```

Collect the immutable evidence directory:

```sh
umi-publisher-availability collect-authority \
  --policy /absolute/config/shadow-policy.json \
  --candidate-bundle /absolute/input/candidate-window-0 \
  --authority-config /absolute/config/availability-authority.json \
  --output /absolute/evidence/window-0-announcement
```

The command takes a current smoldot observation before and after proof retrieval.
Both observations and the durable finality head must remain at or after
`announcement_block` and strictly before `proposal_close_block`. A missing exact
announcement record, a corrupt finality database, a runtime or proof mismatch, a
regressing observation, or a close reached during collection produces no complete
output bundle.

The output contains:

- `announcement-set.json`, the exact `umi-validator-announcement-set/1` object;
- `announcement-proof.json`, the exact
  `umi-announcement-validator-evidence/1` object;
- `collection-observation-before.json` and
  `collection-observation-after.json`, the exact smoldot records around proof
  collection;
- `authority-collection.json`, written last, with every digest and the observed
  pre-close interval.

An existing output directory is never replaced. A directory without
`authority-collection.json` is an incomplete forensic artifact and must not be
used.

## 3. Qualify and sign as a validator

Qualification consumes the exact `announcement-set.json` and
`announcement-proof.json` files above. It then opens every authority store below
the one configured live-validator state root. The plan-observation cache must
reproduce the control-plane's complete zero-based window history under the same
policy. The candidate must be that history's one active `pool_and_selection`
window.

For window zero only, the protocol-state operation log must reproduce exact
genesis: no prior window, spent leaf, publisher fault, rolling score, observation
count, or nonzero root. For every later window, qualification fully replays the
immediately preceding public calibration or incident bundle with the production
seven-stage verifier. The bundle's reveal receipt must reproduce the current
protocol-state digest and full spent root, its terminal receipt must match the
control plane and stage journal, and its exact audit-release block must be present
in the same policy-bound GRANDPA store. Missing or substituted bundle evidence,
a rolled-back state database, and an empty replacement database all fail before
the wallet is opened.

The command derives `umi-availability-qualification-context/1` itself. There is
no production `--context` option. A digest-only context or operator-selected
validator subset cannot reach the signer.

Check the proof replay, complete validator set, audited state, media, and candidate
graph. This form does not open a wallet or connect to peers:

```sh
umi-publisher-availability qualify \
  --policy /absolute/config/shadow-policy.json \
  --candidate-bundle /absolute/input/candidate-window-0 \
  --announcement-snapshot /absolute/evidence/window-0-announcement/announcement-set.json \
  --announcement-proof /absolute/evidence/window-0-announcement/announcement-proof.json \
  --authority-config /absolute/config/availability-authority.json \
  --validator-hotkey 5ValidatorAddress \
  --check
```

Sign and retain the set. The signing form starts the policy-pinned smoldot
observer. It refuses to sign unless the newest independently finalized block is
still below `proposal_close_block`, then repeats that check immediately before
calling the hotkey signer.

```sh
umi-publisher-availability qualify \
  --policy /absolute/config/shadow-policy.json \
  --candidate-bundle /absolute/input/candidate-window-0 \
  --announcement-snapshot /absolute/evidence/window-0-announcement/announcement-set.json \
  --announcement-proof /absolute/evidence/window-0-announcement/announcement-proof.json \
  --authority-config /absolute/config/availability-authority.json \
  --validator-hotkey 5ValidatorAddress \
  --state-root /absolute/state/availability-validator-a \
  --receipt-output /absolute/output/validator-a-receipt.json \
  --wallet-name validator \
  --wallet-hotkey-name default \
  --wallet-path /absolute/bittensor-wallets
```

The command performs these checks before signing:

- target-specific verifier, chain-spec, runtime, and policy pins;
- smoldot replay of the finalized announcement block;
- LayoutV1 replay of every validator permit, UID, and inverse-key storage claim;
- equality between the proven permit result and the complete policy registry;
- exact policy-bound replay of the cached announcement and control-plane history;
- replay of the validator protocol-state operation log and either the exact
  window-zero genesis exception or the immediately preceding public bundle,
  reveal transition, terminal receipt, and finalized audit-release block;
- RFC 8785 canonical pool bodies and public manifests;
- policy, publisher, window, batch, and round bindings;
- policy byte and candidate-count limits;
- strict portable timelock structure and batch commitment reproduction;
- H.264, MP4, duration, dimensions, frame rate, video digest, and frame digest;
- exact policy pins for both FFmpeg and FFprobe, copied from the file descriptors
  that are hashed into a private execution directory and invoked only from those
  staged paths;
- duplicate batch, video, and frame rejection;
- public spent-batch, spent-video, and spent-frame checks;
- active-validator registry membership and the live pre-proposal-close block
  bound.

The `ffmpeg` and `ffprobe` resolved on the validator's `PATH` must be the exact
release-pinned regular files. They must be owned by the validator account,
executable by that account, single-linked, and not writable by group or other
users. The inspection result carries both executed digests, and qualification
refuses to sign if either digest or the private-staging attestation is absent.

The state store reserves one availability root per window before calling the
hotkey signer. It retains the candidate manifest, qualification context, and all
candidate objects in a content-addressed store. It also retains the exact
announcement snapshot, announcement proof, protocol-state snapshot, prior-window
readiness or genesis evidence, and smoldot observation used by the signer. SQLite
uses a full synchronous transaction, and the object store is checked on every
restart. A different candidate root or common authority for the same window is
rejected.

If a process stops after reservation, rerun the same command with the candidate
bundle and proof inputs unchanged. A newer live finality observation may replace
the prior polling observation while the common proof authority stays fixed. Keep
the state directory intact through the window's `reveal_round`. The receipt is
written idempotently and an existing different receipt is never replaced.

## 4. Aggregate the quorum and materialize mirrors

Every receipt must name the same candidate hash, leaf set, availability root,
announcement evidence, active-validator set, prior-state continuity evidence,
spent state, and policy. Each
receipt carries the protocol signature over:

```text
SHA256("umi-availability-v1\0" || window_id || availability_set_root)
```

It also carries a second validator signature over the complete retention receipt.
The second signature prevents a collector from changing a validator's chain
context or retention claim while reusing its protocol signature.

Check the quorum and final output deterministically:

```sh
umi-publisher-availability aggregate \
  --policy /absolute/config/shadow-policy.json \
  --candidate-bundle /absolute/input/candidate-window-0 \
  --receipt /absolute/input/validator-a-receipt.json \
  --receipt /absolute/input/validator-b-receipt.json \
  --receipt /absolute/input/validator-c-receipt.json \
  --check
```

Materialize a new release directory:

```sh
umi-publisher-availability aggregate \
  --policy /absolute/config/shadow-policy.json \
  --candidate-bundle /absolute/input/candidate-window-0 \
  --receipt /absolute/input/validator-a-receipt.json \
  --receipt /absolute/input/validator-b-receipt.json \
  --receipt /absolute/input/validator-c-receipt.json \
  --output /absolute/output/certified-window-0
```

The quorum is `max(3, floor(2 * V / 3) + 1)`, where `V` is the complete active
validator set in the shared context. The command rejects duplicate signers,
non-active signers, invalid signatures, a short quorum, or any context mismatch.

The release contains:

- `certified-release.json`, a digest index and no-broadcast status record;
- `anchor-intents.json`, one exact `Commitments.set_commitment` intent per
  publisher;
- `qualification-receipts/<sha256>.json`, the complete signed validator
  retention receipts;
- `v1/umi/windows/<window_id>/pool-source.json`, the mirror discovery index;
- `v1/umi/objects/<sha256>`, the final pool manifests, public manifests,
  timelock envelopes, and videos.

Each availability signer should run the aggregation step over the same receipts
and host the resulting static tree through an origin allowed by the policy's
authenticated mirror rule. Preserve the exact bytes through `reveal_round`.
The authenticated object URLs are validator-only and must never be copied into a
miner request. The mirror deployment must also implement the rule's fixed
authenticated `POST /v1/umi/video-deliveries` endpoint. After selection, it returns
one credential-free, short-lived HTTPS URL under a policy-pinned public delivery
origin for every exact window, batch, challenge, video hash, and size in the
canonical request. Every URL path must be exactly
`/v1/umi/deliveries/<token>`, where `token` is the canonical unpadded base64url
encoding of the required 24-byte derived value. Do not put identifiers, labels,
prompts, names,
answers, queries, fragments, percent encoding, or extra path segments in the URL.
The 24-byte token is not chosen by the service: derive it with the exact
`umi-video-delivery-token-v1` formula in whitepaper Section 6.2 from the
validator-generated 256-bit seed and the complete selected media commitment.
Return a different token and the validator will reject the response before it can
become durable success.

## 5. Bind every signer to a checked mirror pair

The discovery rule must contain the same number of unique retrieval and delivery
origins and at least `max(3, floor(2 * V / 3) + 1)` of each. Each availability
signer operates one unique pair. Administrative independence is a policy and
control-disclosure assertion; the code enforces distinct normalized origins and
distinct independently administered validator signing keys.

After materializing the certified tree, create one owner-private
`umi-reference-mirror-service-config/1` file per signer as described in
[the mirror-service guide](MIRROR_SERVICE_OPERATOR.md). Each service has its own
state database and independently generated credential set. Run its offline exact
tree/config check, start it behind the two declared TLS origins, and confirm those
origins are reachable without redirects or rewriting.

The validator that signed the matching qualification receipt first performs the
no-wallet check:

```sh
umi-publisher-availability attest-mirror \
  --service-config /absolute/private/validator-a-mirror.json \
  --qualification-receipt /absolute/input/validator-a-receipt.json \
  --check
```

Then it signs the exact public projection of that check. The statement includes no
bearer, seed, token mapping, or private path:

```sh
umi-publisher-availability attest-mirror \
  --service-config /absolute/private/validator-a-mirror.json \
  --qualification-receipt /absolute/input/validator-a-receipt.json \
  --output /absolute/output/validator-a-mirror-readiness.json \
  --wallet-name validator \
  --wallet-hotkey-name default \
  --wallet-path /absolute/bittensor-wallets
```

Repeat for every certificate signer. The check cryptographically binds the exact
tree and configuration; external TLS reachability remains an operational
observation and must continue to be monitored through reveal.

Finally, verify the complete signer and origin-pair set. Supply every original
qualification receipt and every readiness statement:

```sh
umi-publisher-availability verify-mirrors \
  --policy /absolute/config/shadow-policy.json \
  --certified-tree /absolute/output/certified-window-0 \
  --mirror-discovery-rule /absolute/config/mirror-discovery.json \
  --qualification-receipt /absolute/input/validator-a-receipt.json \
  --qualification-receipt /absolute/input/validator-b-receipt.json \
  --qualification-receipt /absolute/input/validator-c-receipt.json \
  --statement /absolute/output/validator-a-mirror-readiness.json \
  --statement /absolute/output/validator-b-mirror-readiness.json \
  --statement /absolute/output/validator-c-mirror-readiness.json \
  --output /absolute/output/window-0-mirror-readiness-set.json
```

The command rejects a missing certificate signer, reused retrieval or delivery
origin, short discovery set, invalid signature, different receipt, different
release, different anchor intents, or different policy. The readiness-set output
must remain outside the certified tree because that tree has exact membership.
Record its printed SHA-256 in the operator log and require `status: anchor_ready`
before running any pool-anchor command.

Each validator enforces the same boundary. Its private
`umi-mirror-request-headers/2` file names the readiness-set path. Installed
validator startup verifies the embedded certified release, anchor intents, quorum,
origin uniqueness, and every readiness signature. The production pool source is
constructed with readiness enforcement enabled. A valid pool manifest is eligible
only when its publisher/digest appears in that release, and the validator
requires the pool certificate signer set to equal the readiness signer set. Thus a
publisher can broadcast without running this helper, but the resulting anchor is
ineligible at every conforming live validator.

## Pool anchoring boundary

`anchor-intents.json` contains the exact SHA-256 value for the sole
`Data::Sha256` commitment field. Every intent has
`broadcast_authorized: false`, `translation_weights_active: false`, and
`weight_submission_capability: false`.

Use the installed `umi-publisher-pool-anchor` command described in
[PUBLISHER_POOL_ANCHOR_OPERATOR.md](PUBLISHER_POOL_ANCHOR_OPERATOR.md). Its
read-only check binds one publisher to the certified release and prints the exact
operation ID. Its separately acknowledged execution mode submits only the matching
`Commitments.set_commitment` call before `closing_block`, reconciles finalized
inclusion, and retains the exact closing-block storage proof. The operator cannot
submit miner weights.

## Required external inputs

The workflow is ready to assemble, qualify, sign, retain, aggregate, and serve
exact artifacts. Deployment still requires these inputs from outside this
command:

- eligible consented videos, public manifests, and future-round ground-truth
  envelopes from registered publishers;
- an existing validator finality database that has continuously retained the
  exact announcement block and its parent;
- each validator's existing, reconciled protocol-state database;
- unlocked validator hotkeys for qualification signatures;
- authenticated HTTPS mirror origins and retention monitoring;
- the registered publisher hotkey wallet, policy-pinned finality and storage-proof
  verifier binaries, finality chain specification, and durable private state used
  by `umi-publisher-pool-anchor`.

Those inputs are security boundaries. The installed qualifier rejects placeholder
hashes, a locally selected validator subset, a stale finalized head, and a spent
set that did not come from the audited protocol-state database.
