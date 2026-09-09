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

Preview the three owner changes in their required atomic order. Start with the
version fence:

```sh
"$BTCLI" sudo set \
  --network finney \
  --netuid 78 \
  --name weights_version \
  --value 4294967296 \
  --wallet "$OWNER_WALLET" \
  --wallet-path "$OWNER_WALLET_ROOT" \
  --dry-run
```

Then preview the full-row minimum:

```sh
"$BTCLI" sudo set \
  --network finney \
  --netuid 78 \
  --name min_allowed_weights \
  --value 256 \
  --wallet "$OWNER_WALLET" \
  --wallet-path "$OWNER_WALLET_ROOT" \
  --dry-run
```

Finally preview the commit-reveal fence:

```sh
"$BTCLI" sudo set \
  --network finney \
  --netuid 78 \
  --name commit_reveal_weights_enabled \
  --value false \
  --wallet "$OWNER_WALLET" \
  --wallet-path "$OWNER_WALLET_ROOT" \
  --dry-run
```

These are inspection commands. Do not remove `--dry-run` or submit the changes as
three extrinsics. A gap between standalone calls would leave an avoidable race.
The live cutover uses the pinned UMI operator to compose one
`Utility.batch_all`. Its inner calls must be exactly, and in this order:

```text
AdminUtils.sudo_set_weights_version_key(78, 4294967296)
AdminUtils.sudo_set_min_allowed_weights(78, 256)
AdminUtils.sudo_set_commit_reveal_weights_enabled(78, false)
```

The command must preflight a coherent finalized snapshot, record the pending
commit count before and after the call, sign with the SN78 owner coldkey, wait for
finalized `batch_all` success, and verify all three storage values. A pending entry
does not block the fence; it remains subject to the drain in Section 3. Retain the
call material, extrinsic hash, inclusion block and hash, events, finalized receipt,
and readback.
The preflight, material, receipt, and journal schemas are
`umi-bootstrap-owner-fence-preflight/1`,
`umi-bootstrap-owner-fence-call-material/1`,
`umi-bootstrap-owner-fence-receipt/1`, and
`umi-bootstrap-owner-fence-journal/1`.

Build and inspect the unsigned atomic call first. `owner-coldkey` is the public
SS58 address, not a seed or wallet path:

```sh
DIRECT=.venv/bin/umi-bootstrap-direct-weights
OWNER_COLDKEY=REPLACE_WITH_SN78_OWNER_COLDKEY_SS58

"$DIRECT" build-owner-fence \
  --owner-coldkey "$OWNER_COLDKEY" \
  --output /absolute/private/path/to/owner-fence-preview.json
```

Submit with new output paths and a durable private state directory. The command
resolves and signs with the named wallet's coldkey; there is no hotkey argument:

```sh
"$DIRECT" submit-owner-fence \
  --receipt-output /absolute/private/path/to/owner-fence-receipt.json \
  --call-material-output /absolute/private/path/to/owner-fence-submitted-call.json \
  --state-dir /absolute/private/path/to/owner-fence-state \
  --live-submit \
  --acknowledgement 'APPLY SN78 DIRECT BOOTSTRAP OWNER FENCE' \
  --wallet-name "$OWNER_WALLET" \
  --wallet-path "$OWNER_WALLET_ROOT"
```

Capture independent readbacks after the batch finalizes:

```sh
"$BTCLI" sudo get --network finney --netuid 78 --json \
  > sn78-hyperparameters-fenced.json
curl --fail --silent --show-error https://api.umi.vision/api/v1/network \
  > sn78-observer-fenced.json
```

The `btcli` output is an operator readback, not the finalized evidence by itself.
Do not declare the fence active until an independent finalized observation shows
all three exact values at one block.

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
- all three owner-call dry-run previews, the atomic call material, its single
  batch extrinsic, finalized block and events, terminal receipt, and readbacks;
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

Only after independent replay passes may public status change to:

```json
{
  "mechanism": "bootstrap_service_binary",
  "service_weights_active": true,
  "translation_weights_active": false
}
```

Never describe the equal binary row as ASL accuracy, a translation leaderboard,
or completion of a whitepaper activation gate.

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

- If any owner dry run or the unsigned atomic material is wrong, submit nothing.
- `Utility.batch_all` must apply all three changes or revert all three. If its
  terminal result is unknown, do not submit it again or attempt an individual
  repair. Reconcile the original transaction and private state directory first.
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
