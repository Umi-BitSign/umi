[Documentation](../README.md) / Launch configuration

# Competition launch configuration

This is the single launch checklist. It replaces the rolling execution diary
and separate launch-profile and allocation notes. Public endpoint intake is
live, but an admission receipt does not activate rewards. Assignment delivery
and model-artifact intake are not yet open. The registration bridge remains
separate until a signed successor is installed.

## Live first-round schedule

The authoritative cutoffs are blocks, not wall-clock estimates:

| Event | Block |
|---|---:|
| Public intake observed live | `9,085,463` |
| Guaranteed participant submission/replacement deadline | `9,135,843` |
| Latest operator roster close | `9,135,903` |
| Work-signing close | `9,135,963` |
| Evaluation close | `9,156,243` |
| Protected-reference reveal | `9,156,263` |
| Evidence cutoff | `9,156,383` |
| Round validity end | `9,156,983` |

The policy digest is
`81c118c5b45527650d7f304a6574d04223de30fbad76c69df09e7f2ae4897fa0`;
the accepted contribution-terms digest is
`61f333f6105c8e8a06db9d51a7a47a3cf0c5c0c72d7794fe1e5e6744eafcca62`.
Those are the version 1 live-intake bindings until the public status changes.
The prospective sequence 5 policy is published as
[`FIRST_ROUND_STAGED_POLICY.json`](FIRST_ROUND_STAGED_POLICY.json), with protocol
digest `eae2a709bd54468d7ea42c370867be77144115ec709c22e976320828a0e90e56`.
It binds [version 2 terms](../MODEL_CONTRIBUTION_TERMS_V2.md), SHA-256
`c8efb288f648e26f178e2e253c9c282a7500107371866f1ab7d62a9e80ef935b`,
and names the version 1 digest as its predecessor. The immutable version 1
policy is retained as
[`FIRST_ROUND_INTAKE_POLICY_V1.json`](FIRST_ROUND_INTAKE_POLICY_V1.json).
The live intake and bounded status API use `https://api.umi.vision`. The endpoint
has been publicly reachable since block `9,085,463`, and its accepted-submission
log is public. A first-round submission or replacement must be accepted at block
`9,085,463` or later and no later than block `9,135,843` to guarantee
consideration, and it
must remain valid through at least block
`9,156,243`. The coordinator may poll and close the roster at any later block
through `9,135,903`; acceptance in that interval is not guaranteed first-round
inclusion. The submitted hotkey must still be registered on SN78 in the
finalized roster-close snapshot. A higher-sequence replacement must satisfy the policy's 360-block
replacement interval. The intake receipt remains `accepted_no_weight` until
evaluation, settlement, signed release and finalized-row checks complete.

The [public status](https://api.umi.vision/v1/competition/status) is the
authoritative public record of the live intake policy. Its deployment object
names an operator-declared repository revision and the UMI source-tree digest.
The intake service refuses to start when that digest differs from its running
modules. The deployment procedure must separately verify that the declared
revision produced that exact tree. A commit is not live merely because it was
merged. Do not publish launch-facing claims on `main` until the exact revision
is installed, or label and gate the unfinished behavior explicitly. Coordinator
and evaluator behavior changes only after their reviewed artifacts are installed;
validator behavior changes only through the signed release channel; incentives
change only after a valid row is finalized on chain.

## Approved policy

Use `umi-open-competition-policy/3` with `umi-competition-suite/2`.
The required evaluator entry is:

```json
{
  "evaluators": [
    {
      "hotkey": "5Fk765B4CRBekwErwE5VxvveWhHztHSfsnsLt8cbDayDWsuk",
      "control_group": "umi-operated"
    }
  ],
  "required_evaluator_groups": 1,
  "endpoint_reward_bps": 7000,
  "model_reward_bps": 3000,
  "maximum_inference_ms": 120000
}
```

This is an excerpt, not a complete signed policy. UID 0 is the sole initial
evaluator. UID 54 shares its administration and does not count as an independent
vote. Disclose the single-operator trust model in the launch announcement.
Additional evaluators or a different quorum require a later signed policy.

The initial baseline is Michael's supplied model, preserved without a contributor
reward recipient. Score one authentic reference per clip: fingerspelling CER
weighted 3/13 and continuous-signing WER weighted 10/13. Meet the policy's minimum
case counts and resource limits. Do not invent labels or score a full source
video against a cropped interval's reference. See [private data](../operators/private-holdout.md).

Use `umi-competition-single-evaluator-transport/1` with the same evaluator hotkey
and actual administrator identity. `ScoringPolicy.competition_transport(...)`
leaves the retired publisher collateral, soak start, capacity-set root and cost
schedule absent together; publisher registries are empty. Do not fabricate
publishers or independent operators to satisfy the legacy calibration profile.
Old signed policies retain their original bytes and meaning.

## Rewards and first contribution round

Qualifying endpoints share 70%, proportional to their exact quality scores.
The unallocated 30% goes to the proved burn destination until a model qualifies.
It must remain in the full row; omitting it would redistribute it through
normalization. This does not burn validator dividends or the separate owner cut.
The chain and other validators determine the eventual economic outcome.

The exact first-round admission and evaluation cutoffs are published above.
Future rounds must publish their signed cutoffs before their intake windows.
The first round opens endpoint intake only. Assignment delivery is not yet
public, and model-artifact intake and evaluation remain closed until UMI
publishes the exact canonical runtime and an immutable, reconstructible
environment. Review a future round's strongest qualifying contributed artifact
with preservation, reconstruction, paired improvement, minimum quality and
rights checks. An endpoint result alone cannot promote a model. The imported
baseline has no founding-model exception.

Version 1 of the accepted contribution terms says that both reward tracks launch
together. The endpoint-only version 1 intake remains a no-weight admission
phase. Version 2 permits staged endpoint activation with the model share burned,
and the published sequence 5 policy binds it. Before that successor governs the
round, each affected miner must sign and receive acceptance for a new submission
under the exact successor policy and terms. Version 1 signatures and receipts
stay immutable and cannot be counted as version 2 acceptance. No row may pay a
model contributor until a model round passes the published reconstruction,
preservation, improvement, quality, and rights gates.

If no model qualifies, continue burning the unallocated share. There is no
retroactive award. After promotion, fresh evaluation and recipient eligibility
remain required. An awarded contributor becoming ineligible, or a round without
qualifying endpoint evidence, retains the existing hold; no silent fallback or
redistribution is authorized. Preserve both the
[version 1 terms](../MODEL_CONTRIBUTION_TERMS.md) and
[version 2 terms](../MODEL_CONTRIBUTION_TERMS_V2.md) byte-for-byte. Every
submission and policy must bind the version it actually accepted.
An exact tie between the highest qualifying new model candidates promotes
neither candidate; the share remains burned for that round.

### Version 1 to version 2 intake transition

Do not replace the version 1 intake database or reopen it with the sequence 5
policy. The store, baseline, retained submissions, checkpoint, and finality
cache are policy-bound. Opening those files under another digest either fails
closed or risks losing the distinction between the two acceptances.

Before advertising sequence 5, the operator must:

1. Quiesce writes long enough to take a consistent snapshot of the version 1
   ledger, write-ahead log, checkpoint, baseline, public deployment record, and
   finality cache. Retain the snapshot and its hashes off host.
2. Keep every version 1 signed submission and receipt retrievable at a stable,
   read-only archive route. Do not rewrite their policy or terms fields.
3. Initialize a separate version 2 intake state with the same launch identity
   and a separately recorded baseline under the sequence 5 policy. Its retained
   submission list is empty until the first version 2 acceptance; the external
   checkpoint must commit that exact empty head before the service starts.
4. Change public status and the writable intake route together so they expose
   `eae2a709bd54468d7ea42c370867be77144115ec709c22e976320828a0e90e56`
   and the version 2 terms digest before accepting successor submissions.
5. Give affected miners time to use the documented transition command, sign
   with the same hotkey, and receive a new receipt by block `9,135,843`. Build
   the reward roster only from accepted version 2 submissions. The version 1
   archive remains evidence, not implied consent or a reward roster.

With every version 1 writer stopped and its backup verified, export the
content-addressed public archive before starting the sequence 5 service:

```sh
umi-competition --policy /ABSOLUTE/PRIVATE/version-1-policy.json \
  export-intake-archive \
  --state /ABSOLUTE/PRIVATE/version-1-intake \
  --submission-head-checkpoint-directory /ABSOLUTE/PRIVATE/version-1-checkpoint \
  --deployment /ABSOLUTE/PRIVATE/version-1-deployment.json \
  --destination /ABSOLUTE/PRIVATE/version-1-public-archive \
  --confirm-quiesced-backup
```

Put the printed `manifest_sha256` and archive directory in the sequence 5
service configuration's `historical_archives` list. The service refuses an
archive that is not the policy's immediate predecessor, lacks the durable
external checkpoint commitment, belongs to another launch, or differs from the
pinned manifest. The sequence 5 service also refuses to start without exactly
one such archive. On first startup it writes the predecessor policy and manifest
digests into the successor ledger; later startups reject configuration drift.
Confirm the archived list, canonical manifest, and exact-record routes before
changing the writable intake route. Hash the response bytes from the manifest
and exact-record routes against their respective manifest commitments.

Create the successor ledger while both public routes still point at version 1.
Use the already preserved baseline archive; do not copy the old intake
database:

```sh
v2_policy=/ABSOLUTE/PRIVATE/version-2-policy.json
v2_state=/ABSOLUTE/PRIVATE/version-2-intake
v2_checkpoint=/ABSOLUTE/PRIVATE/version-2-checkpoint
v2_config=/ABSOLUTE/PRIVATE/version-2-service.json

test ! -e "$v2_state"
test ! -e "$v2_checkpoint"
install -d -m 0700 "$v2_checkpoint"
umi-competition --policy "$v2_policy" initialize-baseline \
  --state "$v2_state" \
  --manifest /ABSOLUTE/PRIVATE/baseline-manifest.json \
  --archive /ABSOLUTE/PRIVATE/preserved-baseline
umi-competition --policy "$v2_policy" status --state "$v2_state" \
  > /ABSOLUTE/PRIVATE/version-2-initial-status.json
```

Build `v2_config` with the printed baseline promotion digest,
`required_submission_sha256s: []`, the new checkpoint directory, and the pinned
version 1 archive. Back up the new database, verify that configuration, then
initialize its external empty-head commitment through the existing stopped-store
migration command:

```sh
umi-competition-store-migrate \
  --policy "$v2_policy" --state "$v2_state" \
  --service-config "$v2_config" --confirm-quiesced-backup \
  > /ABSOLUTE/PRIVATE/version-2-checkpoint-initialization.json
jq -e '
  .restart_services_without_migration == true and
  .retained_submission_head.record_count == 0 and
  .retained_submission_head.external_checkpoint_durable == true
' /ABSOLUTE/PRIVATE/version-2-checkpoint-initialization.json >/dev/null
```

Before the first version 2 acceptance, rollback may restore the version 1
service and its exact snapshot. Once version 2 has accepted anything, never
discard that ledger or reopen version 1 for writes; preserve both histories and
repair the successor deployment forward. Version 2 submissions cannot be copied
into version 1. If the public archive, atomic route switch, or retained-state
snapshot is not ready, keep version 1 intake live and do not advertise the
successor policy.

## Intake proof-cache retention

The intake collector keeps the complete registration proof for each accepted
submission, including replaced submissions. It also keeps all snapshots within
the policy's `maximum_snapshot_age_blocks` window. Older background-poll
snapshots with no admission receipt are pruned in the same transaction that
retains a new proof. The finalized high-water mark, runtime artifacts, accepted
submissions, receipts and their external checkpoint remain intact. SQLite
reuses freed pages; the file need not shrink.

This retention is specific to the intake service. Evaluator, endpoint and
validator evidence stores keep their existing retention rules. In intake,
`maximum_cache_bytes` covers runtime artifacts and unreferenced polling proofs;
receipt-bound proofs are a durable archive outside that working-cache budget.
The archive is limited by the admission ledger's record/byte bounds, individual
proof-size bounds, and available disk. Provision disk for the expected accepted
proof volume as well as the ledger and backups. A typical 220 KiB proof for
each of 65,536 distinct admission snapshots needs about 14 GiB before overhead.
The operational cache budget supports up to 20 GiB (`21474836480` bytes).
Existing serialized defaults stay unchanged. Set the budget explicitly; changing
it requires a stopped-service, backed-up cache-binding migration that verifies
the old configuration and preserves proofs and the finalized high-water mark.

Private logs report `registration_storage_pressure` when working-cache usage
reaches 80%, or free disk falls below 20% or 1 GiB. Warnings repeat on pressure
state changes, not every poll; recovery is logged separately. Monitor these
warnings and public readiness. If the working window itself exhausts its
budget, logs report `registration_refresh_failed error_type=RegistrationCacheFull`;
`registration_refresh_recovered` reports recovery. A real storage failure still
fails closed: readiness remains HTTP 503 once no fresh verified snapshot is
available. No unchecked registration is admitted to conceal a storage failure.

Back up the intake ledger, checkpoint and chain state before an upgrade. Do not
delete the ledger, weaken finality checks or edit signed submissions to clear a
cache error.

## Burn proof

The policy's `unallocated_model_burn` binds the destination UID, hotkey and
`mode: Burn`. Prove `SubnetOwnerHotkey`, `RecycleOrBurn` and both directions of
the UID/hotkey mapping at one owned finalized state root. Recheck before each
weight submission. The destination cannot also receive endpoint or model rewards.

An absent `RecycleOrBurn` requires a verified non-membership proof and a `Burn`
default decoded from the bound runtime metadata. Missing RPC data alone is
insufficient. A changed owner, mapping or unsupported mode holds submission.

## Activation checklist

Record evidence for each item against the exact deployed artifacts. Unit tests,
demo videos and private preparations do not substitute for these checks.

1. Publish the policy, accepted terms, baseline, supported workload, resource
   limits and contribution cutoffs. Check the evaluator hotkey's current permit.
2. Verify protected-suite provenance, split integrity and private backups.
   Keep labels out of execution and public storage until the committed reveal.
   Retire exposed cases; stop new rounds when the unused pool is exhausted.
3. Verify public intake, authenticated assignment discovery, actual model
   responses inside 120 seconds, deadline handling and retained evidence.
   Capacity must support the admitted roster. Missing work needs certified void
   evidence or a hold, never invented results or coordinator-caused miner faults.
4. Complete cutoff signing, reveal, settlement replay and signed publication.
   Preserve original windows and evidence across retries. Rehearse restart and
   interrupted delivery with the actual host and container sandbox.
5. Verify immutable release downloads, the signed feed and the stopped-state
   recovery preflight. Upgrade each validator separately, preserving keys,
   journals, directive history and unresolved transaction evidence.
6. Confirm the exact finalized competition row, then check consensus and
   incentive before announcing that miners are earning competition rewards.

Publication is part of each gate. Do not describe a source commit, local build,
staged service or unfinalized transaction as live. When source and production
differ, document the difference and treat the active signed policy, release and
chain row as authoritative until the deployment is completed and checked.

Until the exact signed feed configuration and a tested miner command are
published, assignment delivery remains unavailable. Placeholder examples are
not production configuration. Give miners operating lead time after publication;
a coordinator, feed or evaluator infrastructure delay cannot be scored as miner
failure. Follow the [incident and score-challenge rules](../OPEN_COMPETITION.md#incidents-and-score-challenges)
for objective defects.

The process runs recurring reviewed rounds. The coordinator does not invent
protected suites or move missed deadlines. Settled-row renewal has a bounded
lifetime and needs fresh recipient and burn checks; it is not permission to use
one benchmark forever. See [round operations](../operators/rounds.md),
[publication and renewal](../operators/settlement.md) and
[host upgrades](../validators/successor-upgrade.md).
