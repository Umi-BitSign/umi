# SN78 seven-day bootstrap service-weight addendum

Status: temporary public bootstrap profile

Scope: Finney SN78, MechId 0

This addendum authorizes a temporary service-eligibility weight path on SN78. It
does not activate UMI translation weights and does not satisfy, waive, or count
toward any translation activation gate in Section 14 of the UMI whitepaper.

The path measures one binary property: whether a registered miner currently
serves the UMI public endpoint and has completed a replayable public endpoint
pilot. Every eligible miner receives the same weight.

## 1. Limits

This mechanism has reduced trust guarantees:

- The pilot clip and answer are public. A miner can hard-code the answer.
- The coordinator controls pilot admission, public evidence, health observations,
  and the frozen eligibility manifest.
- One registered hotkey receives one equal share. Common control is not detected,
  so the mechanism is Sybil-prone.
- All validators intentionally build the same row. Common-row copying is expected
  and is not evidence of independent translation evaluation.
- A successful pilot proves interoperability for one request. It does not prove
  sustained availability or ASL translation quality.
- Bootstrap chain evidence uses coherent finalized Bittensor SDK observations with
  block hashes and event or extrinsic references. The records are independently
  repeatable, but they are not portable storage proofs and still trust the selected
  chain provider to report finalized state correctly.
- Pilot CER, WER, hypothesis text, model revision, latency, and hardware have zero
  weight effect.
- No bootstrap policy, opt-in, pilot, manifest, epoch, or applied row receives
  Section 14 gate credit.

Every bootstrap status artifact or interface that claims the bootstrap's state
MUST identify the mechanism as `bootstrap_service_binary`. Once the first applied
row is public and while the fixed service interval remains open, it MUST report:

```json
{
  "translation_weights_active": false,
  "service_weights_active": true,
  "service_weight_kind": "bootstrap_service_binary",
  "section_14_gate_credit": false
}
```

The immutable public bootstrap index MUST carry these fields. A general UMI
observer MAY mirror the index later; it need not implement bootstrap status before
the first commit. Until it does, it may continue to report translation calibration
state, but it MUST NOT claim that its translation-only status describes the
bootstrap service mechanism. No interface or artifact may describe a bootstrap row
as a translation score, model ranking, or held-out benchmark result.

This addendum makes exactly two narrow exceptions to the whitepaper. First, it
overrides the Section 10.3 prohibition on every UMI weight commit while
`translation_weights_active` is false, solely to permit the exact service row
defined here. Second, because binary service eligibility and the resulting equal
row are already public inputs, it permits pre-reveal publication only of the signed
eligibility manifest and its expected service row. CRv4 remains mandatory as the
chain-conforming, anti-front-run commit path; it is not claimed to conceal this
already-known row. Miner hypotheses, translation outcomes, scores,
translation-derived vectors, the CRv4 ciphertext, and terminal evidence remain
subject to the whitepaper's ordinary release rules. All other CRv4, chain-mapping,
terminal-state, evidence-release, and incident requirements remain in force.
For this bootstrap only, the chain-evidence requirements below replace the
whitepaper's portable storage-proof requirements. Every chain observation records
the finalized block number and hash, the exact queried value, and any applicable
event or extrinsic reference. Another operator must be able to repeat each read at
the named block. Evidence objects report `storage_proofs_verified: false` and MUST
NOT present these observations as trustless state proofs. This evidence exception
does not apply to translation weights.

## 2. Bootstrap policy

The concrete policy uses the code-enforced `umi-bootstrap-weight-policy/1`
schema:

```json
{
  "schema": "umi-bootstrap-weight-policy/1",
  "network": "finney",
  "netuid": 78,
  "mechanism_id": 0,
  "translation_weights_active": false,
  "service_weights_active": true,
  "campaign_id": "hex-encoded-sha256",
  "public_evidence_origin": "https://api.umi.vision",
  "coordinator_hotkey": "ss58-coordinator-hotkey",
  "umi_git_revision": "40-character-lowercase-git-commit",
  "weights_version_key": 1,
  "published_at_block": 9000000,
  "activation_block": 9000360,
  "commit_stop_block": 9049320,
  "hard_sunset_block": 9050760,
  "health_ttl_blocks": 30,
  "manifest_ttl_blocks": 30
}
```

Unknown fields are forbidden. `umi_git_revision` is the exact 40-character
lowercase commit for the clean public UMI checkout used to verify the policy,
replay pilot evidence, and build the row. The policy is the external canonical
artifact published after that revision, so this binding does not require the
commit to contain its own future policy hash. Integers are nonnegative JSON-safe
integers, except that `weights_version_key`, `health_ttl_blocks`, and
`manifest_ttl_blocks` are positive. The policy MUST satisfy:

```text
published_at_block < activation_block < commit_stop_block < hard_sunset_block
health_ttl_blocks < hard_sunset_block - published_at_block
manifest_ttl_blocks < hard_sunset_block - activation_block
```

The policy hash is domain-separated:

```text
policy_sha256 = SHA256(
  "umi-bootstrap-weight-policy-v1\0" || RFC8785(policy)
)
```

The concrete seven-day profile MUST also satisfy:

```text
hard_sunset_block - activation_block == 50400
hard_sunset_block - commit_stop_block == 1440
```

This is at most seven days at the policy-publication target of 12 seconds per
block. A runtime change that alters the target interval, `Tempo`, activity cutoff,
CRv4 version, or reveal period stops new bootstrap commits. It does not extend or
recalculate the policy.

The policy artifact and `policy_sha256` MUST be public before any miner signs an
opt-in. The `published_at_block` number and its hash MUST identify a finalized
block observed before publication.

## 3. Cutover

Before the first service commit, validators publish one cutover record and record
all of these conditions at its single finalized block:

1. SN78 has exactly one mechanism and the service row targets MechId 0.
2. CRv4 is enabled and the live commit-reveal version is 4.
3. Live `Tempo`, `RevealPeriodEpochs`, and the factor-derived activity cutoff
   match the bootstrap schedule.
4. Live `WeightsVersionKey` equals `policy.weights_version_key`.
5. That key differs from the value at `published_at_block` and became final after
   policy publication.
6. Every pre-bootstrap MechId 0 pending entry is terminal and absent from its
   exact epoch key.
7. Every pre-bootstrap MechId 0 row is inactive.
8. Each participating validator has no unresolved MechId 0 entry in its event
   ledger.

The record contains the finalized publication and cutover block numbers and hashes,
the old and new `WeightsVersionKey`, mechanism and CRv4 state, schedule values, the
global pending-entry count, and the complete set of hotkeys whose MechId 0 rows are
still active. It sets `storage_proofs_verified` to `false`. Every value MUST be
independently repeatable through finalized SDK reads at the named blocks. This
bootstrap cutover does not claim a historical event-ledger proof: zero current
pending entries and zero active rows are the disclosed, reduced-trust cutover
boundary. An unresolved entry or active old row blocks the first service commit.
At every later submission preflight, the validator separately records and enforces
the current UID bounds, `MinAllowedWeights`, maximum-weight ratio, queue state, and
weight rate. Each new bootstrap submission still requires its own commit-to-removal
event and state observations under Section 9.

The fixed clearance reflects the launch values of `Tempo = 360`,
`RevealPeriodEpochs = 1`, and an activity cutoff of 360 blocks:

```text
terminal_clearance_blocks = 1440
policy.commit_stop_block = policy.hard_sunset_block - 1440
```

No bootstrap commit may be included at or after `policy.commit_stop_block`.

## 4. Miner opt-in

A prior pilot does not enroll a miner automatically. The miner MUST opt in after
the policy is public by signing `umi-bootstrap-opt-in/1` with the same hotkey named
by the pilot:

```json
{
  "schema": "umi-bootstrap-opt-in/1",
  "policy_sha256": "hex-encoded-sha256",
  "pilot_id": "hex-encoded-sha256",
  "miner_hotkey": "ss58-miner-hotkey",
  "signed_at_block": 9000100,
  "signature_scheme": "sr25519",
  "signature": "0x-lowercase-hex-64-byte-signature"
}
```

The miner signs this unsigned projection:

```json
{
  "schema": "umi-bootstrap-opt-in/1",
  "policy_sha256": "hex-encoded-sha256",
  "pilot_id": "hex-encoded-sha256",
  "miner_hotkey": "ss58-miner-hotkey",
  "signed_at_block": 9000100
}
```

The digest is:

```text
opt_in_digest = SHA256(
  "umi-bootstrap-opt-in-v1\0" || RFC8785(unsigned_opt_in)
)
```

The signature is over the raw 32-byte digest. Verification follows Section 6.3
of the whitepaper and uses only the declared scheme. The object is valid only
when:

```text
policy.published_at_block < signed_at_block < policy.commit_stop_block
opt_in.policy_sha256 == policy_sha256
opt_in.miner_hotkey == pilot miner hotkey
opt_in.pilot_id == public pilot identifier
```

The coordinator MUST retain and publish the exact RFC 8785 opt-in bytes. The
public receipt time and its surrounding finalized block establish when the
coordinator received it. This timing remains a coordinator assertion.

## 5. Eligibility

A miner is eligible for a frozen manifest only when all of these checks pass:

1. The opt-in signature and policy binding are valid.
2. The referenced public endpoint pilot is available from
   `policy.public_evidence_origin` under its `pilot_id`.
3. The content-addressed pilot bundle replays bit-exactly under
   `policy.umi_git_revision` and reaches terminal outcome `ok`.
4. Replay verifies the authenticated request, miner-signed response envelope,
   response timelock, revealed plaintext, and all inner bindings.
5. The pilot's `announced_origin` and `contacted_origin` are equal to the manifest
   entry `origin`.
6. At `frozen_at_block`, the hotkey remains registered on SN78, has no validator
   permit, resolves to the entry UID, and announces the same HTTPS origin.
7. A fresh coordinator check of `GET {origin}/healthz` returns status 200 with no
   redirect and a certificate valid for the normalized public-IP origin.

The pilot's diagnostic translation score is ignored. A zero diagnostic score is
eligible when the public pilot outcome is `ok`.

The health observation is fresh at block `B` only when:

```text
health_block <= B
B - health_block <= policy.health_ttl_blocks
```

The exact request target, response status, bounded response-body hash and length,
TLS certificate hash, observation block and hash, and coordinator receipt time
MUST be public with the manifest evidence.

## 6. Frozen eligibility manifest

The coordinator builds the strict `umi-bootstrap-eligibility-manifest/1` object.
Each entry has exactly these fields:

```json
{
  "pilot_id": "hex-encoded-sha256",
  "miner_hotkey": "ss58-miner-hotkey",
  "uid": 247,
  "origin": "https://203.0.113.10:443",
  "pilot_block": 9000001,
  "health_block": 9000358,
  "utility": 1,
  "opt_in": {
    "schema": "umi-bootstrap-opt-in/1",
    "policy_sha256": "hex-encoded-sha256",
    "pilot_id": "hex-encoded-sha256",
    "miner_hotkey": "ss58-miner-hotkey",
    "signed_at_block": 9000100,
    "signature_scheme": "sr25519",
    "signature": "0x-lowercase-hex-64-byte-signature"
  }
}
```

`origin` MUST be one normalized HTTPS public-IP origin with an explicit port.
The entry bindings are:

```text
entry.pilot_id == entry.opt_in.pilot_id
AccountId32(entry.miner_hotkey) == AccountId32(entry.opt_in.miner_hotkey)
pilot_block <= opt_in.signed_at_block <= health_block <= frozen_at_block
frozen_at_block - health_block <= policy.health_ttl_blocks
```

The coordinator declares that it includes every eligible post-publication opt-in
known at the freeze block. It MUST NOT choose a preferred subset. If chain limits
cannot fit the complete set, the manifest is not issued. The signed manifest
commits the entries and row it contains; it cannot cryptographically prove that the
coordinator omitted no opt-in. Completeness is an auditable coordinator assertion
checked against the public opt-in receipt log required by Section 4. A demonstrated
eligible omission is coordinator fault and terminates this policy.

Entries are sorted lexicographically by the raw AccountId32 decoded from
`miner_hotkey`. Miner hotkeys, UIDs, and pilot IDs MUST each be unique. The
quantized row is sorted by numeric UID ascending.

Eligibility is binary:

```text
utility_i = 1
N = entry_count
pre_quantization_weight_i = 1 / N
quantized_weight_i = 65535
```

The complete manifest schema is:

```json
{
  "schema": "umi-bootstrap-eligibility-manifest/1",
  "policy": {
    "schema": "umi-bootstrap-weight-policy/1"
  },
  "policy_sha256": "hex-encoded-sha256",
  "frozen_at_block": 9000360,
  "frozen_at_block_hash": "0x...",
  "entries": [],
  "quantized_row": [
    {"uid": 5, "value": 65535},
    {"uid": 6, "value": 65535},
    {"uid": 247, "value": 65535}
  ]
}
```

The `policy` member is the complete policy object, not the abbreviated example
shown above. `policy_sha256` MUST equal the domain-separated policy hash.
`frozen_at_block_hash` MUST be the finalized hash of `frozen_at_block`.

The manifest is usable at current block `C` only when:

```text
policy.activation_block <= frozen_at_block < policy.commit_stop_block
frozen_at_block <= C < policy.commit_stop_block
C - frozen_at_block <= policy.manifest_ttl_blocks
```

At `C`, each health observation MUST also remain within `health_ttl_blocks`.

The u16 row is max-upscaled, not fixed-sum. Three equal destinations therefore
produce three values of 65,535, not three values that add to 65,535. The logical
normalized share remains exactly `1 / N` for each destination.

The live row is admissible only when:

```text
N >= MinAllowedWeights
N * maximum_weight_limit_u16 >= 65535
N <= live maximum destination count
```

## 7. Coordinator signature

The manifest digest is:

```text
manifest_sha256 = SHA256(RFC8785(manifest))

manifest_digest = SHA256(
  "umi-bootstrap-eligibility-manifest-v1\0" ||
  RFC8785(manifest)
)
```

The coordinator signs the raw 32-byte `manifest_digest` and publishes:

```json
{
  "schema": "umi-bootstrap-eligibility-manifest-signature/1",
  "manifest": {},
  "manifest_sha256": "hex-encoded-sha256",
  "manifest_digest": "hex-encoded-sha256",
  "coordinator_hotkey": "ss58-coordinator-hotkey",
  "signature_scheme": "sr25519",
  "signature": "0x-lowercase-hex-64-byte-signature"
}
```

`manifest` is the complete strict manifest. `coordinator_hotkey` MUST equal
`policy.coordinator_hotkey`. The signature uses only its declared scheme.

The coordinator MUST NOT publish manifests with different rows whose validity
intervals overlap. It may replace an expired manifest with a new frozen manifest
after repeating all eligibility and health checks. Any two such overlapping,
differing coordinator-signed manifests are public equivocation and terminate the
bootstrap under that policy, whether or not they name the same `frozen_at_block`.

## 8. Validator anchor and CRv4 commit

For each manifest, a validator performs this exact sequence:

1. Verify the policy, pilot bundles, deterministic replays, opt-ins, chain state,
   endpoint bindings, health observations, entry ordering, equal row, manifest
   hashes, and coordinator signature.
2. Recheck the cutover record and confirm that the manifest remains within both
   TTLs and the service commit interval.
3. Submit one `Commitments.set_commitment` call containing exactly one
   `Data::Sha256(manifest_sha256)` field.
4. Retain the finalized anchor extrinsic and event references, then repeat the
   finalized SDK read at the named block to confirm the exact live anchor.
5. At one finalized weight-build block, recheck every hotkey, UID, permit, and
   serving-origin mapping. Repeat each HTTPS health check after the anchor.
6. If any entry fails, skip the whole row. Do not remove one entry or renormalize
   a local subset.
7. Record one current-head weight-schedule snapshot. Supply the manifest's
   UID-sorted list, its corresponding list of 65,535 values, the fresh
   `WeightsVersionKey`, and validator public key to the pinned CRv4 builder.
8. Submit the raw mechanism-aware
   `SubtensorModule.commit_timelocked_mechanism_weights` call with netuid 78,
   MechId 0, commit-reveal version 4, the returned ciphertext, and its returned
   reveal round.
9. Retain the finalized `TimelockedWeightsCommitted` event reference and the
   exact-epoch-key value returned by a finalized SDK read at that block. Do not
   retry.

A commit is eligible only when:

```text
policy.activation_block <= commit_inclusion_block
commit_inclusion_block < policy.commit_stop_block
commit_inclusion_block - manifest.frozen_at_block <= policy.manifest_ttl_blocks
live_WeightsVersionKey == policy.weights_version_key
```

The validator submits at most one bootstrap service commit in an observed epoch
and only after its previous MechId 0 entry is terminal. Plain `set_weights`, the
convenience `CommitWeights` intent, a locally edited row, and an unsigned manifest
are forbidden.

## 9. Terminal evidence

An accepted commit remains `pending` until a finalized SDK read observes that the
exact filed entry has left its recorded epoch key. Terminal classifications are:

- `applied`: the exact entry is removed, a finalized
  `TimelockedWeightsRevealed` event exists, the stored MechId 0 row byte-matches
  the expected equal row, destination mappings remain valid, and the live reveal
  period did not change.
- `failed`: the entry is removed without every `applied` condition, a mapping
  changed, the row differs, a duplicate commit exists, or runtime drift occurred.
- `skipped`: no finalized weight-commit event exists and the validator records the
  exact pre-commit reason.

The validator's canonical terminal record is the validator-signed
`umi-bootstrap-terminal-signature/1` wrapper produced by the pinned operator. Its
embedded `umi-bootstrap-terminal-observation/1` object binds the policy and
manifest hashes, call-material hash, validator hotkey, exact commit, filed epoch,
ciphertext hash, expected and observed rows, event interval, period history, queue
observations, mapping checks, terminal classification, and reason codes. The
wrapper binds that object by canonical SHA-256, a domain-separated digest, and the
validator-hotkey signature.

That signed terminal wrapper and the following bound files form the bootstrap
audit bundle; no separate packaging schema or upload program is required:

- the exact policy and publication block reference;
- cutover publication and checkpoint blocks, old and new `WeightsVersionKey`,
  global pending-entry count, and active-row hotkey set;
- all signed opt-ins considered for the frozen manifest;
- public pilot records, bundles, signatures, and deterministic replay reports;
- coordinator and validator health-check evidence;
- the signed manifest and its entry-order and row-build trace;
- finalized registration, permit, serving-origin, root, hotkey, and UID
  observations with their block numbers and hashes;
- the manifest-anchor call, inclusion extrinsic and event references, and repeated
  finalized read of the live anchor;
- the schedule snapshot, exact UID and u16 lists, core inputs, ciphertext, reveal
  round, and raw CRv4 call;
- the finalized commit event, exact-key inclusion and removal observations, period
  history, reveal event, and stored MechId 0 row, each bound to its finalized block
  and applicable event or extrinsic reference; and
- an exact reason object for any skipped or failed stage.

The set includes the canonical policy, signed eligibility manifest, cutover
checkpoint, submitted call material, submission receipt, pilot replay set, health
receipt set, and signed terminal wrapper. An applied or failed bundle is published
only after the terminal block records entry removal and the classification. A
skipped bundle is published after the applicable observed epoch closes.
Publication MUST occur within one tempo.

A public, immutable, content-addressed index MUST list every object by URL,
SHA-256, media type, and exact byte length. It MUST also expose `policy_sha256`,
`manifest_sha256`, the validator anchor, expected and applied raw rows, terminal
classification, replay links, `translation_weights_active: false`,
`service_weights_active: true`, `service_weight_kind: "bootstrap_service_binary"`,
and `section_14_gate_credit: false`. Manual
publication to GitHub or content-addressed R2 is sufficient for the initial
bootstrap. An observer MAY mirror this index. If it does, it MUST label each
destination `service_eligible`, not `translation_score` or `rank`.

## 10. Hard sunset

No bootstrap service commit may be included at or after
`policy.commit_stop_block`. The remaining clearance allows pending entries to
resolve and the last bootstrap-updated row to become inactive under the pinned
activity cutoff. At the commit stop, the coordinator MUST ask the authorized
Const/root operator to disable SN78 `subnet_emission_enabled` no later than the
hard sunset. The bootstrap coordinator cannot perform or attest to that
root-controlled operation on its own. A future governed mechanism requires a
separately published superseding amendment; it does not alter this policy's
sunset conditions.

At `policy.hard_sunset_block`:

1. `service_weights_active` is false by protocol, regardless of process or API
   configuration.
2. Coordinator manifest production and validator bootstrap workers stop.
3. Each validator records finalized SDK observations showing that its bootstrap
   pending ledger is empty and its last bootstrap row is inactive.
4. The coordinator publishes its signed `umi-bootstrap-sunset-signature/1` status,
   which binds the policy hash, one signed manifest hash, sunset block and hash,
   global pending-entry count, active-row hotkey set, and finalized
   `subnet_emission_enabled` value. That value MUST be false.
5. A separate immutable, content-addressed sunset index lists every final signed
   manifest, validator terminal wrapper, and signed sunset-status object by URL,
   SHA-256, media type, and byte length. The index is a public completeness record;
   it is not another protocol signature wrapper.
6. An unresolved entry, active MechId 0 row, or still-enabled subnet emission is
   a public unsupported-emission incident. It does not extend the policy or
   authorize another row.

The sunset-status command may be used before the hard sunset only as a private
timing and chain-state diagnostic. Its `service_weights_active: false` field means
that this observer does not ingest or attest to the published applied-terminal
index; it is not a pre-sunset service-status claim. A pre-sunset sunset-status
object MUST NOT be published as mechanism status. Until the hard sunset, the
immutable applied-terminal index is authoritative for the bootstrap's public live
status.

The bootstrap cannot be extended by changing a local date, reusing the
`WeightsVersionKey`, or publishing another manifest. Another service bootstrap
requires a new addendum, policy hash, fresh `WeightsVersionKey`, and complete
cutover. Translation weights still require `translation_weights_active: true` and
every applicable Section 14 gate.

## 11. Launch sequence

1. Publish this addendum, the concrete strict policy, `policy_sha256`, pinned UMI
   revision, and opt-in instructions.
2. Finalize a fresh SN78 `WeightsVersionKey` and publish the complete cutover
   record showing old MechId 0 entries terminal and rows inactive.
3. Collect post-publication miner-hotkey opt-ins for successful public endpoint
   pilots.
4. Snapshot finalized SN78 state, independently replay every pilot, perform fresh
   health checks, and build the complete equal-weight manifest.
5. Sign and publish the frozen manifest and all referenced evidence.
6. Each validator independently verifies it, anchors `manifest_sha256`, rechecks
   every entry, and submits one raw CRv4 commit for the exact equal row.
7. Each validator follows its entry through removal, verifies the reveal event and
   applied row, and publishes its signed terminal bundle.
8. Refresh expired manifests while commits remain before
   `policy.commit_stop_block`.
9. Stop all commits at the fixed cutoff, ask the authorized Const/root operator
   to disable SN78 subnet emission by the hard sunset, and publish the sunset
   checkpoint at `hard_sunset_block`. Any successor mechanism requires a
   separately published superseding amendment.

The first verified applied row makes the temporary service mechanism live. UMI
translation scoring remains inactive.
