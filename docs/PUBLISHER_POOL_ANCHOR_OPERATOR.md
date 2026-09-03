# Publisher pool-anchor operator

This operator is the narrow chain boundary between an availability-certified
publisher release and SN78 `Commitments.set_commitment`. It is for the shadow
calibration policy only. It cannot construct or submit validator weights.

## Inputs

Use the three canonical files from the same release:

- the active shadow scoring policy;
- `certified-release.json`;
- `anchor-intents.json`.

Also provide the publisher hotkey configured for the wallet that will sign. The
loader hashes the complete intent array and checks that hash against the certified
release. It then selects exactly one intent by decoded account ID and verifies its
pool-manifest hash against the matching released manifest. The accepted operation
is fixed to netuid 78, `Commitments.set_commitment`, and one `Data::Sha256` field.

Run the local preflight before opening a wallet or an RPC connection:

    umi-publisher-pool-anchor \
      --policy /absolute/path/policy.json \
      --certified-release /absolute/path/release/certified-release.json \
      --anchor-intents /absolute/path/release/anchor-intents.json \
      --publisher-hotkey 5... \
      --check

`--dry-run` emits the same exact operation ID and binding digest. Both modes are
read-only: they create no state, access no wallet, make no RPC request, sign
nothing, and broadcast nothing.

For execution, create a canonical `umi-publisher-pool-anchor-operator-config/1`
document naming the Finney network, publisher hotkey, wallet name and hotkey name,
wallet directory, private state root, target triple, pinned proof and finality
verifier binaries, and finality chain specification. Use the operation ID printed
by `--check` in both execution acknowledgements:

    {"finality_chain_spec_path":"/opt/umi/finney.json","finality_verifier_binary":"/opt/umi/bin/umi-grandpa-finality","maximum_advances":16,"network":"finney","poll_seconds":1,"protocol":"umi-asl/0.1","publisher_hotkey":"5...","schema":"umi-publisher-pool-anchor-operator-config/1","state_root":"/var/lib/umi/publisher-anchor","storage_proof_verifier_binary":"/opt/umi/bin/umi-substrate-proof","target_triple":"x86_64-unknown-linux-musl","translation_weights_active":false,"wallet_hotkey_name":"publisher","wallet_name":"umi","wallet_path":"/var/lib/bittensor/wallets","weight_submission_capability":false}

Validate the object with `PublisherPoolAnchorOperatorConfig`, serialize that model
with `umi.protocol.canonical_json_bytes`, and write those exact bytes. Pretty-printed
or key-reordered JSON is rejected. The file must be owned by the current operating
user and readable only by that user:

    chmod 0600 /absolute/path/publisher-anchor-operator.json

    umi-publisher-pool-anchor \
      --policy /absolute/path/policy.json \
      --certified-release /absolute/path/release/certified-release.json \
      --anchor-intents /absolute/path/release/anchor-intents.json \
      --publisher-hotkey 5... \
      --operator-config /absolute/path/publisher-anchor-operator.json \
      --execute \
      --acknowledgement submit-exact-publisher-pool-anchor \
      --ack-operation-id OPERATION_ID_FROM_CHECK

Execution refuses a wallet whose decoded hotkey differs from the configured
publisher. It validates the target-specific verifier binaries and chain spec
against the policy before connecting, starts the owned finality observer, and
opens only the publisher role of the commitment adapter. That role rejects the
assignment, request, and response anchor kinds as well as every weight call.

## Stateful execution

Production composition supplies three closed components to
`PublisherPoolAnchorOperator`: the existing durable extrinsic journal, an
operation-bound `BittensorAnchorPorts`, the owned finality port, and
`ProofBackedPublisherClosingPort`. No generic call or submission function is
accepted by the operator.

Call `advance()` until it returns `PoolAnchorEvidence`. Each call performs at most
one journal transition. The first call durably claims the exact tuple of window,
publisher, release, intent, and pool-manifest hash before signing can occur. A
restart replays that claim. A changed release or second intent for the same state
directory fails with `pool_anchor_equivocation`.

`maximum_advances` limits journal calls before finalized inclusion. It does not
turn a successful early inclusion into a failure while the closing block is still
in the future. After finalized inclusion, `advance()` reconstructs
`closing_finality_pending` from the durable binding and finalized journal receipt
whenever the owned finalized height is below `closing_block`. The installed command
then polls at `poll_seconds` without preparing, signing, or submitting again. The
chain-height boundary is exact: a pending result must name an observed finalized
height below `closing_block`. Once the owned observer reaches that block, the next
call must produce the exact closing proof or its existing proof failure reason.

There is no protocol wall-clock timeout for a stalled chain. Run the command under
an operator supervisor if a process deadline is required. Stopping the process does
not change the protocol outcome; restart it with the same files and state root.

The durable journal prepares and decodes the call, stores the unsigned bytes before
signing, derives the signed extrinsic hash, scans finalized blocks before any
retry, and accepts terminal success only after one successful inclusion and a
matching proof-backed commitment state. An inclusion carrying
`System.ExtrinsicFailed` is terminal failure, not success.

Start execution early in the certification interval. Before preparing, signing,
or submitting an operation that has not crossed the submission boundary, the
operator reads its owned finalized height and requires four blocks of headroom
through `closing_block`. It repeats that check inside the closed submit port
immediately before network submission. Publisher anchors use a four-block mortal
era, and the operator independently requires the persisted era's exclusive death
height to be no later than `closing_block`. The signed extrinsic therefore cannot
remain valid in the mempool after the window closes. A delayed first run or a
restart with only a prepared or signed receipt stops with
`pool_anchor_submission_window_closed` instead of overwriting live commitment
state after the useful window has passed. Once submission has happened or its
outcome is ambiguous, a restart may continue finalized-chain
reconciliation after close, but it may not broadcast the extrinsic again.

After the pending boundary closes, the closing-proof port reads
`Commitments.CommitmentOf(78, publisher_hotkey)` at the exact finalized
`closing_block`. It checks the policy-pinned runtime, verifies the storage proof,
and requires exactly the intended SHA-256 commitment. A later head value is not a
substitute for the closing-block proof.

Keep the following directories private, owner-controlled, and disjoint:

- the publisher binding and final evidence directory;
- the extrinsic journal;
- the finalized scan sidecar store;
- the finality observer store.

Retain `evidence.json`, every journal receipt, the scan sidecars, the certified
release, and the exact policy. Together they replay the release binding, prepared
call, signature, finalized dispatch result, and closing-block storage state.

## Failure handling

Do not delete state or switch to another release after an ambiguous submission.
Restart with the same inputs and let the journal reconcile the signed extrinsic
over its complete mortal era. Never use a general-purpose transaction tool as a
fallback. If the exact commitment is absent or different at close, the pool is not
anchored for that window.
