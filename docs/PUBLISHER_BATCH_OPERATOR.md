# Publisher batch operator

`umi-publisher-batch` turns private, reviewed source material into one sealed UMI
launch batch. The result contains 12 scored clips, two canaries, one public batch
manifest, one ground-truth timelock, and one pool body. It can be passed directly
to `umi-publisher-availability`.

The command checks files and cryptographic bindings. It cannot establish consent,
reviewer independence, ASL fluency, or reference quality. Those facts remain the
publisher's responsibility. The source file binds the exact consent, provenance,
and review evidence bytes used for construction by path and SHA-256.

This path accepts only an inactive policy. It has no wallet, chain transaction, or
weight-submission capability. Each operation verifies the policy-pinned UMI source
tree, scoring runtime, timelock distributions, and Quicknet tuple before using
publisher material. The build also verifies the exact FFmpeg and FFprobe binary
hashes.

## Prepare the directories and public inputs

Create an owner-only working directory. Private JSON, evidence, and video files
must be regular, single-link, owner-held mode-`0400` files. Each private file's
immediate parent must be owner-held, readable and searchable by its owner, and
have no group or other permissions; mode `0700` and finalized mode `0500` are
accepted. Output parent directories must already exist with mode `0700`.

```sh
install -d -m 0700 /absolute/umi-publisher/window-42
install -d -m 0700 /absolute/umi-publisher/window-42/releases
install -d -m 0700 /absolute/umi-publisher/window-42/private-evidence
install -d -m 0700 /absolute/umi-publisher/window-42/private-videos
```

After populating each private input, remove all of its write and non-owner bits:

```sh
chmod 0400 /absolute/umi-publisher/window-42/private-source.json
chmod 0400 /absolute/umi-publisher/window-42/private-evidence/*
chmod 0400 /absolute/umi-publisher/window-42/private-videos/*.mp4
```

The policy and window files are public inputs. They may be mode `0400` or `0444`,
but must not be group- or other-writable. Paths passed to this command must be
absolute and normalized. Symlinks are rejected.

Obtain the announcement block hash and millisecond timestamp from an independently
finalized live-chain observation. Set `WINDOW_INDEX`, `ANNOUNCEMENT_BLOCK_HASH`,
and `ANNOUNCEMENT_TIMESTAMP_MS` to those exact values. Check the derivation without
writing a file:

```sh
umi-publisher-batch derive-window \
  --policy /absolute/config/shadow-policy.json \
  --window-index "$WINDOW_INDEX" \
  --announcement-block-hash "$ANNOUNCEMENT_BLOCK_HASH" \
  --announcement-timestamp-ms "$ANNOUNCEMENT_TIMESTAMP_MS" \
  --check
```

Then write the canonical window file:

```sh
umi-publisher-batch derive-window \
  --policy /absolute/config/shadow-policy.json \
  --window-index "$WINDOW_INDEX" \
  --announcement-block-hash "$ANNOUNCEMENT_BLOCK_HASH" \
  --announcement-timestamp-ms "$ANNOUNCEMENT_TIMESTAMP_MS" \
  --output /absolute/umi-publisher/window-42/window.json
```

`derive-window` does not query the chain or prove finality. Its result reports
`announcement_finality_verified: false`; the operator supplies the finalized
observation. Availability qualification later checks proof-backed announcement
authority. These batch commands also do not attest the current finalized height.
The publisher remains responsible for releasing the pool body before
`proposal_close_block`; the live availability authority rejects late material.
The output is canonical RFC 8785 JSON with this shape:

```json
{
  "window_id": "64-lowercase-hex",
  "window_index": 42,
  "scoring_policy_hash": "64-lowercase-hex",
  "announcement_block": 100000,
  "announcement_block_hash": "0x-plus-64-lowercase-hex",
  "announcement_timestamp_ms": 1788364800000,
  "proposal_close_block": 100030,
  "closing_block": 100045,
  "selection_round": 123456,
  "issue_close_round": 123476,
  "response_close_round": 123496,
  "reveal_round": 123596
}
```

The builder independently re-derives the complete schedule and `window_id` from
the policy, announcement hash, and announcement timestamp. It rejects a stale
response round.

## Allocate private identifiers

Check the public policy, exact schedule, publisher registry entry, and future
response round without creating an identifier file:

```sh
umi-publisher-batch initialize \
  --policy /absolute/config/shadow-policy.json \
  --window /absolute/umi-publisher/window-42/window.json \
  --publisher-hotkey 5PublisherAddress \
  --check
```

Allocate the identifiers once:

```sh
umi-publisher-batch initialize \
  --policy /absolute/config/shadow-policy.json \
  --window /absolute/umi-publisher/window-42/window.json \
  --publisher-hotkey 5PublisherAddress \
  --output /absolute/umi-publisher/window-42/identity.json
```

The command makes 15 independent 128-bit draws from the operating-system CSPRNG:
one batch ID and 14 challenge IDs. It writes `identity.json` atomically as mode
`0400`. Keep this file private because it labels the two canary roles before
reveal.

## Create the private source file

Compute `identity_sha256` over the exact `identity.json` bytes. On macOS or another
system with `shasum`:

```sh
shasum -a 256 /absolute/umi-publisher/window-42/identity.json
```

Create one canonical `umi-publisher-batch-source/1` document with items in this
order:

1. `ordinary_fingerspelling_1` through `ordinary_fingerspelling_2`
2. `ordinary_short_utterance_1` through `ordinary_short_utterance_4`
3. `ordinary_continuous_1` through `ordinary_continuous_6`
4. `canary_cer`
5. `canary_wer`

An ordinary item has this shape:

```json
{
  "role": "ordinary_short_utterance_1",
  "video_path": "/absolute/umi-publisher/window-42/private-videos/04.mp4",
  "signer_id_sha256": "64-lowercase-hex",
  "consent_manifest_sha256": "64-lowercase-hex",
  "consent_manifest_path": "/absolute/umi-publisher/window-42/private-evidence/consent-04.json",
  "provenance_manifest_sha256": "64-lowercase-hex",
  "provenance_manifest_path": "/absolute/umi-publisher/window-42/private-evidence/provenance-04.json",
  "review_manifest_sha256": "64-lowercase-hex",
  "review_manifest_path": "/absolute/umi-publisher/window-42/private-evidence/review-04.json",
  "script": "private prompted English text",
  "references": ["first", "second", "third"],
  "actual_references": null,
  "reserved_script": null,
  "mismatched_references": null
}
```

A canary sets `references` to `null` and supplies all three canary fields:

```json
{
  "role": "canary_cer",
  "video_path": "/absolute/umi-publisher/window-42/private-videos/12.mp4",
  "signer_id_sha256": "64-lowercase-hex",
  "consent_manifest_sha256": "64-lowercase-hex",
  "consent_manifest_path": "/absolute/umi-publisher/window-42/private-evidence/consent-12.json",
  "provenance_manifest_sha256": "64-lowercase-hex",
  "provenance_manifest_path": "/absolute/umi-publisher/window-42/private-evidence/provenance-12.json",
  "review_manifest_sha256": "64-lowercase-hex",
  "review_manifest_path": "/absolute/umi-publisher/window-42/private-evidence/review-12.json",
  "script": "private actual script",
  "references": null,
  "actual_references": ["actual one", "actual two", "actual three"],
  "reserved_script": "different reserved script",
  "mismatched_references": ["mismatch one", "mismatch two", "mismatch three"]
}
```

Each reference set must contain three to five entries that remain distinct after
Section 9.1 normalization. The builder enforces the policy byte, token, and
grapheme limits and the exact canary separation rule. All 16 script hashes in the
launch batch must be unique after normalization. The 14 items must cover at least
seven opaque signer IDs, with no signer used more than twice. A signer ID must be
randomly assigned or produced by a publisher-held keyed construction. Do not place
an unsalted hash of a name, contact address, wallet, or other guessable identifier
in the public manifest.

Before construction, compare all 16 normalized script hashes with the publisher's
replay of the reconciled spent registry. This local builder checks within-batch
uniqueness but cannot authenticate that an operator supplied a complete historical
registry. Validators perform the authoritative transition after reveal, and a
previously spent script makes the window void.

The top-level source object is:

```json
{
  "schema": "umi-publisher-batch-source/1",
  "protocol": "umi-asl/0.1",
  "identity_sha256": "sha256-of-exact-identity-json",
  "items": []
}
```

Put the 14 rows in `items`, encode the object with RFC 8785, and set the file to
mode `0400`. Evidence manifests remain opaque to the builder. Their content must
be maintained under the data policy; the builder only proves that the declared
digest matched an exact local file at construction time. Consent and provenance
digests enter the protocol manifest. The review digest remains in the immutable
private source record because version 0.1 has no public review-digest field. It is
construction evidence, not a claim that the network verified reviewer identity,
independence, or fluency.

## Inspect, seal, and publish the batch directory

Run the full read-only check first. It inspects all clips with private copies of
the policy-pinned FFmpeg and FFprobe binaries and performs a real ground-truth
timelock encryption. Encryption is randomized, so the discarded check digest will
differ from the later published build. The reported `state_mutated: false` means
that no durable operator, wallet, chain, or protocol state was changed. The check
does create owner-private temporary clip snapshots and ciphertext in process memory;
they are discarded before it exits.

```sh
umi-publisher-batch build \
  --policy /absolute/config/shadow-policy.json \
  --identity /absolute/umi-publisher/window-42/identity.json \
  --source /absolute/umi-publisher/window-42/private-source.json \
  --ffmpeg /absolute/pinned/bin/ffmpeg \
  --ffprobe /absolute/pinned/bin/ffprobe \
  --check
```

Create the immutable release:

```sh
umi-publisher-batch build \
  --policy /absolute/config/shadow-policy.json \
  --identity /absolute/umi-publisher/window-42/identity.json \
  --source /absolute/umi-publisher/window-42/private-source.json \
  --ffmpeg /absolute/pinned/bin/ffmpeg \
  --ffprobe /absolute/pinned/bin/ffprobe \
  --output /absolute/umi-publisher/window-42/releases/publisher-a
```

The output directory is mode `0500`; files are mode `0400`. It contains:

```text
ground-truth.tle
pool-body.json
public-manifest.json
publisher-batch-release.json
videos/<opaque-challenge-id>.mp4  (14 files)
```

`publisher-batch-release.json` is written last. Existing destinations are never
replaced. A crash before the final rename leaves no published destination, and a
retry may use the same identity and source files. Before it reports `created`, the
command reopens the installed tree and replays every digest and protocol binding.
The public tree contains no script, reference, role label, consent record,
provenance record, review record, or plaintext ground truth.

## Build the availability assembly input

After the other publisher groups produce their release directories, replay all
three and create the exact input accepted by `umi-publisher-availability`:

```sh
umi-publisher-batch availability-config \
  --policy /absolute/config/shadow-policy.json \
  --window /absolute/umi-publisher/window-42/window.json \
  --release-root /absolute/umi-publisher/window-42/releases/publisher-a \
  --release-root /absolute/umi-publisher/window-42/releases/publisher-b \
  --release-root /absolute/umi-publisher/window-42/releases/publisher-c \
  --output /absolute/umi-publisher/window-42/availability-assembly.json
```

The command replays every release digest, batch commitment, public manifest,
portable timelock, video identity, policy binding, and window binding. The output
is canonical `umi-availability-assembly-config/1` JSON. Run the availability
assembly check directly against it:

```sh
umi-publisher-availability assemble \
  --policy /absolute/config/shadow-policy.json \
  --assembly /absolute/umi-publisher/window-42/availability-assembly.json \
  --check
```

Then follow [the availability operator runbook](PUBLISHER_AVAILABILITY_OPERATOR.md)
to create the candidate bundle, collect proof-backed announcement authority,
obtain validator signatures, and materialize the certified mirror tree.
