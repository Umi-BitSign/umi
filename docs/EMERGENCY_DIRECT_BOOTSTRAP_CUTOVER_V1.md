# SN78 emergency direct-bootstrap cutover, version 1

Status: temporary owner-controlled service bootstrap

Scope: Finney SN78, MechId 0, `bootstrap_service_binary`

Operational profile: `umi-bootstrap-direct-cutover/1`

This addendum replaces only the CRv4 submission and clean-cutover procedure in
the seven-day bootstrap addendum. It does not activate UMI translation weights,
waive a translation activation gate, or turn a public endpoint pilot into a
translation ranking. Until the first direct row is verified in finalized state,
`service_weights_active` remains false.

The temporary fence has three owner-set parameters:

```text
WeightsVersionKey = 4294967296
MinAllowedWeights = 256
CommitRevealWeightsEnabled = false
```

The designated owner validator at UID 0 then submits one raw
`SubtensorModule.set_mechanism_weights` call for MechId 0. Its destination list is
exactly UIDs `0..255`. Eligible public-pilot miners receive `65535`; every other
UID receives `0`. Zero entries remain in the encoded call. This is a full
256-entry service-eligibility row, not a translation score vector.

The target version is `4294967296`, which is outside the 32-bit range used by
legacy validator clients. Each direct row uses a new, single-use,
coordinator-signed transition authorization that binds the target to the original
signed manifest and policy. It authorizes only this direct transport change; it
does not amend miner consent or turn the original manifest into a translation
policy. Commit-reveal must stay disabled and the minimum must stay at 256 while
un-migrated stock validators can still write SN78 weights. The later translation
mechanism requires a separate policy, all activation gates, and commit-reveal
re-enabled and verified before any translation-weight call.

## Safety boundary

This cutover is allowed only when all of these facts hold at one finalized block:

- the chain is Finney, the subnet is 78, and `MechanismCountCurrent` is 1;
- `MaxAllowedUids` is 256 and the participant snapshot contains each UID `0..255`
  exactly once;
- the designated signer resolves to UID 0 and has a validator permit;
- the live `WeightsVersionKey` is `4294967296` and equals the signed transition
  authorization;
- the transition authorization has schema
  `umi-bootstrap-direct-transition-authorization/1`, is signed by the original
  manifest's coordinator, binds the exact manifest and original policy hashes,
  names the running UMI revision, has a fresh 32-byte submission ID, declares
  `single_use: true`, and is active at the finalized block;
- the signed manifest and every included public pilot replay successfully;
- the exact endpoint-health observations are current under the bootstrap policy;
- `eligible_count * MaxWeightsLimit >= 65535`, so the raw row can encode a valid
  positive allocation without changing eligibility;
- no validator has a pending timelocked weight entry, and UID 0's weight rate has
  elapsed;
  and
- all old validator rows have completed the drain in Section 3.

The direct path does not call the ordinary SDK weight helper. That helper may
normalize or omit zero entries and may select a submission path from live state.
The pinned UMI command constructs and audits the full raw call instead.

If any check fails, do not submit a partial row, pad a missing chain participant,
change a UID, lower `MinAllowedWeights`, or turn commit-reveal back on.

## 1. Pin the operator release

Use the exact 40-character UMI revision published with this addendum. The native
environment must use the repository lock and Python version required by the main
bootstrap operator guide. Confirm the dedicated command before touching chain
state:

```sh
cd /absolute/path/to/pinned-clean-umi-checkout
test "$(git rev-parse HEAD)" = REPLACE_WITH_40_CHARACTER_UMI_REVISION
test -z "$(git status --porcelain=v1 --untracked-files=all)"
test "$(.venv/bin/btcli --version)" = 11.1.0
.venv/bin/umi-bootstrap-direct-weights --help
```

Keep the signed manifest, call material, receipts, and state outside the checkout.
Do not place an owner coldkey, validator hotkey, wallet password, or private path
in a public artifact.

## 2. Apply the owner fence

The subnet owner coldkey performs this section. First capture the complete current
hyperparameter output and the current observer snapshot. Preserve both byte-for-
byte with their observation times:

```sh
BTCLI=/absolute/path/to/pinned-clean-umi-checkout/.venv/bin/btcli
OWNER_WALLET=REPLACE_WITH_OWNER_WALLET_NAME
OWNER_WALLET_ROOT=/absolute/path/to/wallets

"$BTCLI" sudo get --network finney --netuid 78 --json \
  > sn78-hyperparameters-before.json
curl --fail --silent --show-error https://api.umi.vision/api/v1/network \
  > sn78-observer-before.json
```

Confirm the signer is the SN78 owner coldkey and review the current values. Abort
if the command reports another network or subnet, `MaxAllowedUids` or the live
participant count is not 256, the starting `(WeightsVersionKey,
MinAllowedWeights, CommitRevealWeightsEnabled)` tuple is not exactly
`(1, 1, true)`, or a parameter change is rate-limited.

Use btcli 11.1.0's [`tx batch`](https://www.bittensor.com/docs/tx/batch)
command. It constructs one `Utility.batch_all` extrinsic from three stock
`set_hyperparameter` intents. Define the ordered intent list once:

```sh
OWNER_FENCE_INTENTS='[
  {"op":"set_hyperparameter","netuid":78,"name":"weights_version","value":4294967296},
  {"op":"set_hyperparameter","netuid":78,"name":"min_allowed_weights","value":256},
  {"op":"set_hyperparameter","netuid":78,"name":"commit_reveal_weights_enabled","value":false}
]'
```

Preview the complete batch. This command does not submit anything:

```sh
"$BTCLI" tx batch \
  --network finney \
  --wallet "$OWNER_WALLET" \
  --wallet-path "$OWNER_WALLET_ROOT" \
  --intents "$OWNER_FENCE_INTENTS" \
  --proxy-for self \
  --no-mev-shield \
  --dry-run
```

The preview must describe one all-or-nothing batch with these inner calls in
this order:

```text
AdminUtils.sudo_set_weights_version_key(78, 4294967296)
AdminUtils.sudo_set_min_allowed_weights(78, 256)
AdminUtils.sudo_set_commit_reveal_weights_enabled(78, false)
```

Abort if btcli shows standalone calls, a different signer, another subnet, a
different value, `Utility.batch` instead of `Utility.batch_all`, or any failed
policy check. Never submit these parameters as three separate live commands.
The values are public owner configuration. `--proxy-for self` bypasses any saved
proxy default, and `--no-mev-shield` keeps the submitted outer call directly
identifiable as `Utility.batch_all` for this cutover.

After reviewing the preview, run this single live command. `--json` cannot open
an interactive confirmation, so `--yes` is explicit. The file captures btcli's
result and transaction identifier for the historical evidence archive:

```sh
"$BTCLI" tx batch \
  --network finney \
  --wallet "$OWNER_WALLET" \
  --wallet-path "$OWNER_WALLET_ROOT" \
  --intents "$OWNER_FENCE_INTENTS" \
  --proxy-for self \
  --no-mev-shield \
  --json \
  --yes \
  > sn78-owner-fence-btcli-result.json

test -s sn78-owner-fence-btcli-result.json
```

Stock btcli returns after inclusion rather than finalization. Its JSON records the
including `block_hash` and `extrinsic_id`; it does not report the extrinsic hash.
Do not run the live command a second time if btcli exits unexpectedly or the
inclusion result is unclear. Preserve `sn78-owner-fence-btcli-result.json` and
reconcile that exact `block_hash` and `extrinsic_id` before taking another action.
A pending weight entry does not block the fence; it remains subject to the drain
in Section 3.

The stock btcli result establishes the submitted transaction history. UMI records
a separate read-only finalized-state attestation. The attestation verifies the
owner mapping and all three storage values in one finalized snapshot. It does not
load the owner wallet, submit a call, or claim that it verified which external
extrinsic applied the values.

The preflight, material, receipt, and journal schemas are
`umi-bootstrap-owner-fence-preflight/1`,
`umi-bootstrap-owner-fence-call-material/1`,
`umi-bootstrap-owner-fence-receipt/1`, and
`umi-bootstrap-owner-fence-journal/1`.

After btcli reports successful inclusion, run the read-only attestation from a
clean pinned UMI checkout. It waits for finalized chain state and is the
authoritative finality check. `owner-coldkey` is the public SS58 address, not a
seed or wallet path:

```sh
DIRECT=.venv/bin/umi-bootstrap-direct-weights
OWNER_COLDKEY=REPLACE_WITH_SN78_OWNER_COLDKEY_SS58

"$DIRECT" attest-owner-fence \
  --owner-coldkey "$OWNER_COLDKEY" \
  --receipt-output /absolute/private/path/to/owner-fence-receipt.json \
  --call-material-output /absolute/private/path/to/owner-fence-attested-call-material.json \
  --state-dir /absolute/private/path/to/owner-fence-state
```

The receipt must have `classification: "already_applied"`, `extrinsic: null`,
and `batch_all_finalized_success: false`. Those fields state the evidence boundary:
the UMI command verified the finalized owner and tuple, while Jack's retained
btcli JSON `block_hash` and `extrinsic_id` identify the external batch inclusion.
`source_snapshot_pending_commit_count` and `observed_pending_commit_count` both
refer to that same read-only finalized attestation snapshot; neither claims a
pre-submission observation.
The journal must end at `phase: "already_applied"`. Any other result blocks the
drain.

Capture independent readbacks after the batch finalizes:

```sh
"$BTCLI" sudo get --network finney --netuid 78 --json \
  > sn78-hyperparameters-fenced.json
curl --fail --silent --show-error https://api.umi.vision/api/v1/network \
  > sn78-observer-fenced.json
```

The `btcli sudo get` output reads chain head and is an operator readback, not
finalized evidence. Do not declare the fence active until the independent UMI
attestation shows all three exact values at one finalized block.

## 3. Drain every legacy row once

Disabling commit-reveal prevents another timelocked commit. It does not cancel an
entry already accepted into a CRv4 queue. Those entries can still reach
auto-reveal; their short rows then fail the 256-entry minimum and leave the queue.
Requiring 256 entries also rejects the ordinary short direct rows used by the old
processes. None of these changes erases an already applied row.

At coherent finalized blocks, record every MechId 0 `LastUpdate`, row, permit,
pending queue, and weight event. For this cutover the audited activity cutoff is
360 blocks. Derive the clean-height lower bound as:

```text
legacy_expiry_height = max(non-UID-0 legacy LastUpdate) + 360
```

The clean finalized height must be strictly greater than
`legacy_expiry_height`, not equal to it. Recompute the maximum after every
finalized block that can change `LastUpdate`. A legacy commitment accepted before
the atomic fence can still auto-reveal afterward. The 256-entry minimum makes its
short row fail, and its queue entry clears, but its earlier acceptance may have
advanced `LastUpdate`.

The drain passes only when one finalized snapshot proves that no non-UID 0
permitted validator has an active `LastUpdate`, even when its stored row is empty;
no non-UID 0 row is active; every old pending entry has cleared; the finalized
height is strictly above the bound; and all three fenced values remain unchanged.
Publish the snapshot, the calculation, the complete event range, and the resulting
drain block. A local process stop report is supporting evidence, not a substitute
for this chain observation.

## 4. Authorize the narrow transition and build the row

The original manifest coordinator, not the owner or UID 0 validator, signs a new
transition authorization for each row. The authorization explicitly overrides
the original manifest TTL and commit-stop block for this direct transport only.
It does not override the original policy's hard sunset. The exact original signed
manifest and miner opt-ins remain the eligibility and consent inputs.

Use a current finalized block at or after the manifest's frozen block and before
the original hard sunset. The authorization expiry must be before that hard
sunset and at least eight blocks after the submission preflight so the mortal
extrinsic fits entirely inside the authorization. Generate a new random 32-byte
submission ID for every row or refresh. Never reuse one. The named UMI revision
must be the clean revision running every direct command:

```sh
DIRECT=.venv/bin/umi-bootstrap-direct-weights
MANIFEST=/absolute/path/to/signed-bootstrap-manifest.json
AUTHORIZATION=/absolute/path/to/direct-transition-authorization.json
CURRENT_FINALIZED_BLOCK=REPLACE_WITH_CURRENT_FINALIZED_BLOCK
AUTHORIZATION_EXPIRY_BLOCK=REPLACE_WITH_BLOCK_BEFORE_ORIGINAL_HARD_SUNSET
SUBMISSION_ID="$(openssl rand -hex 32)"

"$DIRECT" authorize-transition \
  --manifest "$MANIFEST" \
  --submission-id "$SUBMISSION_ID" \
  --weights-version-key 4294967296 \
  --umi-git-revision REPLACE_WITH_40_CHARACTER_UMI_REVISION \
  --signed-at-block "$CURRENT_FINALIZED_BLOCK" \
  --valid-from-block "$CURRENT_FINALIZED_BLOCK" \
  --expires-at-block "$AUTHORIZATION_EXPIRY_BLOCK" \
  --output "$AUTHORIZATION" \
  --wallet-name REPLACE_WITH_COORDINATOR_WALLET_NAME \
  --hotkey REPLACE_WITH_COORDINATOR_HOTKEY_NAME \
  --wallet-path /absolute/path/to/restricted-coordinator-wallets

"$DIRECT" verify-authorization \
  --manifest "$MANIFEST" \
  --authorization "$AUTHORIZATION" \
  --current-block "$CURRENT_FINALIZED_BLOCK"
```

Check that `SUBMISSION_ID` is exactly 64 lowercase hexadecimal characters. Publish
the authorization before UID 0 signs a weight call. Its signature and contents
are public; the wallet path and names are not.

Use the final signed bootstrap eligibility manifest and the public UID 0 validator
hotkey. The read-only preflight independently checks finalized chain state, pilot
evidence, endpoints, the fence, the signer mapping, and the complete UID set:

```sh
UID0_HOTKEY=REPLACE_WITH_UID0_VALIDATOR_HOTKEY_SS58

"$DIRECT" preflight \
  --manifest "$MANIFEST" \
  --authorization "$AUTHORIZATION" \
  --validator-hotkey "$UID0_HOTKEY" \
  --output /absolute/private/path/to/direct-preflight.json
```

Build the unsigned raw call material:

```sh
"$DIRECT" build-call \
  --manifest "$MANIFEST" \
  --authorization "$AUTHORIZATION" \
  --validator-hotkey "$UID0_HOTKEY" \
  --output /absolute/private/path/to/direct-call-preview.json
```

Review all 256 ordered UID and weight pairs. The UIDs must be exactly `0..255`,
the vector must contain exactly 256 values, every ineligible value must remain
zero, and every eligible value must be `65535`. Confirm Finney, netuid 78, MechId
0, version key `4294967296`, both signed-input hashes, the finalized build block,
and the raw `set_mechanism_weights` call before making the hotkey available.

## 5. Submit one authorized row from UID 0

The submit command repeats every preflight, anchors the signed manifest, rebuilds
the raw call from finalized state, signs with the UID 0 hotkey, submits it, and
waits for finalized inclusion. It then verifies the exact stored row and
`LastUpdate`. Use new output paths and one durable private state directory:

```sh
"$DIRECT" submit \
  --manifest "$MANIFEST" \
  --authorization "$AUTHORIZATION" \
  --wallet-name REPLACE_WITH_UID0_WALLET_NAME \
  --hotkey REPLACE_WITH_UID0_HOTKEY_NAME \
  --wallet-path /absolute/path/to/restricted-validator-wallets \
  --call-material-output /absolute/private/path/to/submitted-call-material.json \
  --receipt-output /absolute/private/path/to/direct-submission-receipt.json \
  --state-dir /absolute/private/path/to/direct-submission-state \
  --live-submit \
  --acknowledgement 'SUBMIT SN78 DIRECT FULL BOOTSTRAP ROW'
```

There is no later reveal phase. A successful transaction is still not sufficient:
the command succeeds only after finalized state byte-matches the expected full row
and `LastUpdate` at its inclusion block. The authorization is single-use. Do not
retry an uncertain submission with new output paths or a replacement
authorization. Reconcile the original transaction and its journal in the state
directory.

## 6. Publish and announce the terminal result

Before reporting service weights as active, publish a content-addressed evidence
set containing:

- this addendum, the exact UMI revision, and their hashes;
- the before, fenced, drain, preflight, and build observations;
- the stock btcli batch preview, retained JSON result with its `block_hash` and
  `extrinsic_id`, its independently verified finalized block and event record,
  the read-only atomic call material, finalized-state receipt, and readbacks;
- the signed direct-transition authorization and its independent verification;
- the signed eligibility manifest, every included and excluded UID with its public
  reason, every public pilot replay, endpoint observation, and miner solution;
- the exact 256-entry UID and weight vectors, raw call bytes, manifest anchor,
  submission receipt, and transaction event; and
- the finalized stored MechId 0 row, `LastUpdate`, live hyperparameters, and exact
  comparison with the submitted row.

For every row, retain and publish the authorization's submission ID and the
terminal journal classification. Do not publish wallet paths or other private
operator state.

Only after the complete archive is published, the canonical terminal records pass
validation, and the observer matches the row to current finalized chain state may
public status change to:

```json
{
  "mechanism": "bootstrap_service_binary",
  "service_weights_active": true,
  "translation_weights_active": false
}
```

Never describe the equal binary row as ASL accuracy, a translation leaderboard,
or completion of a whitepaper activation gate.

The observer bundle below is deliberately narrower than the complete historical
archive above. It publishes the canonical terminal records needed to bind the
signed eligibility decision to the exact row, then the observer independently
compares that row, `LastUpdate`, mappings, and fenced hyperparameters with current
finalized chain state. It reports `storage_proofs_verified: false`. Raw SCALE call
bytes, raw transaction events, dry-run previews, the addendum bytes, and the
excluded-UID ledger remain part of the separate complete Section 6 archive and
MUST be published before the launch announcement. The observer endpoint alone does
not claim to satisfy complete historical replay.

Build the current-state observer publication from the exact terminal files. The
journal is the `direct-*.json` file created in the submission state directory for
this authorization and UID 0 hotkey:

```sh
PUBLICATION_ROOT=/absolute/new/path/to/bootstrap-service-publication
DIRECT_JOURNAL=/absolute/private/path/to/direct-submission-state/direct-REPLACE.json

.venv/bin/umi-observer-bootstrap-service-publication \
  --owner-fence-receipt /absolute/private/path/to/owner-fence-receipt.json \
  --signed-manifest "$MANIFEST" \
  --authorization "$AUTHORIZATION" \
  --call-material /absolute/private/path/to/submitted-call-material.json \
  --submission-receipt /absolute/private/path/to/direct-submission-receipt.json \
  --submission-journal "$DIRECT_JOURNAL" \
  --output-root "$PUBLICATION_ROOT"

PUBLICATION_ID="$(sha256sum "$PUBLICATION_ROOT/manifest.json" | cut -d' ' -f1)"
test "${#PUBLICATION_ID}" -eq 64
```

The output path must not already exist. A repeat invocation fails instead of
replacing an immutable publication. Copy it into the observer-owned publication
root and atomically install one canonical feed config:

```sh
OBSERVER_PUBLICATION="/var/lib/umi-observer/bootstrap-service-publications/$PUBLICATION_ID"
sudo install -d -o umi-observer -g umi-observer -m 0700 \
  /var/lib/umi-observer/bootstrap-service-feed \
  /var/lib/umi-observer/bootstrap-service-publications \
  "$OBSERVER_PUBLICATION"
sudo cp -a "$PUBLICATION_ROOT/." "$OBSERVER_PUBLICATION/"
sudo chown -R umi-observer:umi-observer "$OBSERVER_PUBLICATION"
sudo find "$OBSERVER_PUBLICATION" -type d -exec chmod 0700 {} +
sudo find "$OBSERVER_PUBLICATION" -type f -exec chmod 0400 {} +

feed_config=/var/lib/umi-observer/bootstrap-service-feed/config.json
feed_candidate="${feed_config}.${PUBLICATION_ID}.new"
sudo test ! -e "$feed_candidate"
sudo -u umi-observer .venv/bin/python -c \
  'import sys; from pathlib import Path; from umi.observer_bootstrap_service_feed import BootstrapServiceFeedConfig; from umi.protocol import canonical_json_bytes; current=Path(sys.argv[1]); raw=current.read_bytes() if current.exists() else None; value={"schema":"umi-observer-bootstrap-service-feed-config/1","protocol":"umi-asl/0.1","mode":"bootstrap_service_binary","public_origin":"https://api.umi.vision","bundle_roots":[]} if raw is None else BootstrapServiceFeedConfig.model_validate_json(raw).model_dump(mode="json",by_alias=True); assert raw is None or canonical_json_bytes(value)==raw; value["bundle_roots"]=sorted(set([*value["bundle_roots"],sys.argv[3]])); Path(sys.argv[2]).write_bytes(canonical_json_bytes(BootstrapServiceFeedConfig.model_validate(value)))' \
  "$feed_config" "$feed_candidate" "$OBSERVER_PUBLICATION"
sudo -u umi-observer .venv/bin/python -c \
  'import sys; from umi.observer_bootstrap_service_feed import build_observer_bootstrap_service_feed; from umi.observer_pilot_feed import build_observer_pilot_feed; build_observer_bootstrap_service_feed(sys.argv[1],pilot_feed=build_observer_pilot_feed(sys.argv[2]))' \
  "$feed_candidate" \
  /var/lib/umi-observer/pilot-feed/observer-pilot-feed.json
sudo chmod 0400 "$feed_candidate"
sudo mv -f -- "$feed_candidate" "$feed_config"
```

After installing the matching observer release and systemd drop-in, restart it and
let the API independently compare the publication to a fresh finalized snapshot.
The combined drop-in preserves `UMI_OBSERVER_BUNDLE_FEED_CONFIG` when it is set.
An unset value passes an empty equals-form argument, which leaves that optional
feed disabled:

```sh
sudo install -o root -g root -m 0644 \
  deploy/public-pilot-automation/systemd/umi-observer-bootstrap-service.conf \
  /etc/systemd/system/umi-observer.service.d/30-bootstrap-service-read-only.conf
sudo systemctl daemon-reload
sudo systemctl restart umi-observer.service
curl --fail --silent --show-error https://api.umi.vision/api/v1/bootstrap-service \
  | tee /tmp/umi-bootstrap-service.json \
  | jq -e '.availability == "active" and
      .protocol_state.service_weights_active == true and
      .protocol_state.translation_weights_active == false and
      .current.evidence.publication_id == "'"$PUBLICATION_ID"'"'
```

Any failed assertion leaves public status inactive. Do not edit JSON to force the
flag; fix or publish the missing evidence and restart the observer.

## 7. Refresh without reopening the legacy path

One finalized direct row is one update, not a permanent background weight. A
refresh reuses the exact original signed manifest and miner opt-ins. This is
permitted only before the original policy's hard sunset. The coordinator creates
a new single-use transition authorization with a new random submission ID for
every refresh. That authorization provides a new, bounded validity interval and
overrides the original manifest TTL and commit-stop block only for the direct
transport.

Every refresh repeats finalized UID, origin, and owner mapping checks, the complete
pending-queue drain check, public-pilot replay, fresh HTTPS health checks,
authorization verification, call build, submission, finalized comparison, and
publication. Use new call-material and receipt paths. Keep the durable state
directory and all prior journals; the command keys each journal by the new
authorization hash and UID 0 hotkey. Never reuse an authorization, submission ID,
journal, or raw call. Never delete a journal to make a retry possible.

Schedule a refresh only after `WeightsSetRateLimit` has elapsed and with enough
headroom that the UID 0 row cannot cross `activity_cutoff_blocks` before the next
finalized update. This emergency profile does not change either chain cadence.
If a fresh authorization or verified update is unavailable, let the row become
inactive and set `service_weights_active` back to false. Do not improvise a
fallback row.

The original commit-stop block does not stop an authorized direct refresh. Stop
before the original hard sunset. No transition authorization may expire at or
after that block, and no direct call may be submitted at or after it.
Commit-reveal remains off after the last direct row until the separate
legacy-writer migration and re-enable procedure passes.

## Abort and recovery rules

- If the owner batch preview or the read-only atomic material is wrong, submit
  nothing.
- `Utility.batch_all` must apply all three changes or revert all three. If its
  terminal result is unknown, do not submit it again or attempt an individual
  repair. Reconcile the original btcli transaction first.
  Any observed partial state is an incident and blocks the direct row.
- If all three fenced values finalize but the drain or direct-row preflight
  fails, leave the three fenced values in place. They are the safe stopped state.
- If the version bump or transition authorization differs from `4294967296`, the
  original manifest, the original policy, or the pinned revision, do not build or
  submit a row.
- If the direct extrinsic has an unknown result, do not submit again. Resolve its
  finalized event and stored row first.
- If another validator applies a row, a legacy event resets the drain, a runtime
  upgrade changes the call, or the stored row differs from the expected row, mark
  the cutover failed and keep the fence in place.
- Do not lower `MinAllowedWeights` or re-enable commit-reveal merely to recover
  emissions. Re-enabling commit-reveal is a later reviewed migration after legacy
  stock writers have stopped or installed a complete pinned UMI release, their
  old state is terminal, and the target UMI release passes its own live checks.

These rules deliberately prefer a visible no-weight interval over an unaudited or
mixed mechanism.
