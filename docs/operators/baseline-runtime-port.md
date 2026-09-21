# Moving an unrewarded reference baseline to another runtime

`apply-runtime-port` appends a reviewed runtime port to the existing baseline
history. Use it when the operator-selected reference model needs a different
inference entrypoint for another runtime. An earned contributor model must use
the normal model-promotion path.

The port keeps the original baseline record and every submission receipt. It
adds a `umi-model-baseline/3` record with no contributor credit. Under a policy
with an unallocated model burn destination, that share continues to be burned.
The record's parent is the exact previous promotion hash. Signature order and
local observation time are retained separately and cannot change the shared
promotion hash.

## Prepare and review

Create and preserve a separate model bundle. Its parent must be the original
bundle digest. Only the declared file with role `inference` may change; its path
and role, all other files, the license and the bundle profile must remain the
same. Preserve both archives and review the entrypoint diff. Asset equality
alone does not prove that the changed program behaves equivalently.

Qualify the replacement on its intended host and runtime. Retain the raw
qualification results and source review, and bind their SHA-256 digests in a
`RuntimePortReview`. The certificate needs independent control-group quorums
from both the source policy and its immediate operational successor. The
successor must change the runtime and preserve the miner's deal. Set a narrow
application window between cohorts, after every retained round's validity has
ended and before the next roster boundary.

Prepare the replacement service configuration and immutable application
release. An intake config must pin the new promotion hash in
`retained_state.baseline_promotion_sha256`. Keep its existing ledger, submission
checkpoint and historical archive bindings. An evaluator config must retain its
existing review history and capacity limits. Migrating review history to another
host requires a coherent copy after its owning services have stopped.

The port authenticates any existing intake anchor and all retained receipts,
then carries only its policy and baseline digest forward in the same transaction
as the appended baseline. It preserves the original anchor as a recovery record
and keeps the exact required-submission list. The replacement intake configuration
can therefore reopen the completed transition without rebinding the ledger.

## Apply

Stop the services that own the affected ledger, take a coherent backup, and
verify that the replacement release can reopen a copy. Apply the same reviewed
decision to the intake and evaluator review stores. Each stores its own actual
observation block. The command uses an owned finalized-registration provider;
there is no operator-supplied block override.

```sh
python -m umi.competition_cli \
  --policy policy-next.json \
  --predecessor-policy policy-current.json \
  apply-runtime-port \
  --certificate runtime-port-certificate.json \
  --archive /absolute/preserved-model-archive \
  --chain-config runtime-port-chain.json \
  --intake-config intake-next.json \
  --confirm-quiesced-backup
```

Supply every admitted predecessor, newest first. For the evaluator, replace
`--intake-config` with `--evaluator-config`. Its chain state must be separate
from the review ledger and available for exclusive provider ownership.

The command rejects an early or late application before rolling the ledger to
the successor policy. It hashes both preserved bundles, collects another fresh
owned head before the append, and refuses active rounds, disputed history,
changed assets, a changed parent, and insufficient signatures. The record,
receipt, content identity and writer fences commit together. Older running
writers cannot mutate a ledger after the port is committed.

Policy rollover happens when the successor store opens. If a later check fails,
the backup and prepared successor config are still required for recovery; the
command does not promise a transaction spanning the external policy checkpoint
and the ledger. Never restore an old backup after new admissions or other
durable work have resumed. Reopen the completed port under the successor and
its full admitted lineage, verify the expected promotion head, then restart the
replacement services. This command cannot submit chain weights.
