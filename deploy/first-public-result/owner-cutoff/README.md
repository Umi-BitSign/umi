# SN78 owner activity-cutoff handoff

This handoff changes one owner-controlled SN78 hyperparameter:

```text
activity_cutoff_factor = 1000
```

At the current 360-block tempo, the runtime derives
`activity_cutoff_blocks = 360`. UMI's inactive launch profile requires the
derived cutoff to be no longer than one 360-block window.

Only the person controlling the SN78 owner coldkey may execute the live command.
The verifier in this directory performs one HTTPS `GET` request to the fixed public
observer endpoint. It has no wallet, RPC, signing, or chain-write path.

## 1. Check the current finalized value

From the UMI repository root, run:

```sh
python3 deploy/first-public-result/owner-cutoff/verify.py
```

If it reports `"status":"passed"`, retain the output and do not submit another
transaction. A failure with reason `activity_cutoff_blocks_mismatch` and actual
value `5000` is the state observed before this handoff.

## 2. Prepare the owner's verified btcli

These commands were checked against `btcli 11.1.0`. On the owner-controlled
machine, set the three local values and verify the executable before proceeding:

```sh
BTCLI=/absolute/path/to/verified/btcli
OWNER_WALLET=REPLACE_WITH_OWNER_WALLET_NAME
OWNER_WALLET_PATH=/absolute/path/to/owner/wallets

test -x "$BTCLI"
test "$("$BTCLI" --version)" = "11.1.0"
test -d "$OWNER_WALLET_PATH"
test "$BTCLI" != /absolute/path/to/verified/btcli
test "$OWNER_WALLET" != REPLACE_WITH_OWNER_WALLET_NAME
test "$OWNER_WALLET_PATH" != /absolute/path/to/owner/wallets
```

Do not send the wallet path, password, seed, or command output containing owner
details to another operator.

Run the change outside the runtime's final ten-block administrative freeze. This
read-only preflight requires more than 30 blocks of headroom:

```sh
curl --fail --silent --show-error \
  --header 'Accept: application/json' \
  --header 'Accept-Encoding: identity' \
  https://api.umi.vision/api/v1/network |
  jq -e '
    .schema == "umi-observer-network/1" and
    .freshness == "fresh" and
    .protocol_state.chain_identity_matches_expected == true and
    .network.netuid == 78 and
    .network.mechanism_id == 0 and
    .network.epoch.tempo_blocks == "360" and
    ((.network.epoch.blocks_remaining | tonumber) > 30)
  '
```

If this check fails, wait for the next epoch and rerun it. Do not substitute a
best-head read for the finalized observer check retained with the handoff.

## 3. Owner dry run

The owner runs this exact preview first:

```sh
"$BTCLI" tx set-hyperparameter \
  --network finney \
  --wallet "$OWNER_WALLET" \
  --wallet-path "$OWNER_WALLET_PATH" \
  --netuid 78 \
  --name activity_cutoff_factor \
  --value 1000 \
  --dry-run
```

Stop unless the preview identifies the expected owner signer, Finney, netuid 78,
`activity_cutoff_factor`, and raw value `1000`. The output must be a dry-run plan
and must not report a submitted extrinsic.

## 4. Owner live submission

After reviewing the preview, the owner runs:

```sh
"$BTCLI" tx set-hyperparameter \
  --network finney \
  --wallet "$OWNER_WALLET" \
  --wallet-path "$OWNER_WALLET_PATH" \
  --netuid 78 \
  --name activity_cutoff_factor \
  --value 1000
```

The command deliberately omits `--yes`, so the owner must review and confirm the
live submission. Retain the extrinsic hash, inclusion block, finalized block, and
success event. Do not retry while the first submission is pending or before its
terminal chain result is known.

## 5. Verify the finalized result

After the submission finalizes and the observer refreshes, run:

```sh
python3 deploy/first-public-result/owner-cutoff/verify.py
```

Success requires one fresh, finalized observer source for SN78, a 360-block tempo,
and exact `activity_cutoff_blocks: "360"`. The verifier prints a bounded JSON
receipt containing the observer generation time and finalized block. Retain that
receipt with the owner transaction evidence.

The public observer pins reads to a finalized block but currently reports
`storage_proofs_verified: false`. This receipt is the requested public operational
check. The first live UMI weight-build snapshot must still carry the policy-pinned
storage proof required by the protocol.
