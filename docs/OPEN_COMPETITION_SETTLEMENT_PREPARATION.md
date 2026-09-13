# Automatic settlement preparation

The round coordinator can prepare an unsigned settlement proposal after a
round's evidence cutoff. It reads completed independent evidence from the same
competition store that the evaluator exchange writes. No operator assembles
the roster or chooses which successful miners to include.

This output still needs independent review and settlement signatures. It does
not activate a policy, change weights, or prove independent receipt timing.
The current bridge services are unaffected.

## Configuration

Add `settlement_directory` to the private
[`umi-round-coordinator-config/1` configuration](OPEN_COMPETITION_ROUND_COORDINATOR.md).
Use an absolute path owned by the service user, separate from every other
coordinator directory. Configure this when establishing the coordinator's state;
an existing journal is bound to its original configuration. Do not delete a
journal to enable the option. The output directory uses mode `0700` and files
use `0600`. Omit this setting to keep the existing preparation behavior.

The coordinator and evaluator exchange must use the same policy-bound intake
store. That store needs the preserved baseline, admitted roster, fixed cutoff,
and completed independent evidence received by cutoff. A model reward share
also requires a qualifying promoted contributor in the preserved history.
Importing Michael's baseline alone does not establish that attribution.

The existing private round plan supplies the committed suite and original
windows. The coordinator's owned finality provider supplies the current
registration snapshot; an HTTP caller cannot choose it.

## Output and retry behavior

For each usable complete round, the service writes:

```text
<round-digest>.settlement-proposal.json
```

Schema `umi-settlement-preparation/1` contains the signed cutoff, unsigned
settlement publication, exact signed roster and complete independent evidence.
The retained settlement includes the revealed suite, registration snapshot,
promotion-head binding and deterministic reward projection. Keep these files
private. They contain references and are excluded from cutoff/work discovery.

The store selects the earliest retained evidence per roster entry, with a
digest tie-break. Evidence received after cutoff cannot fill a missing entry.
Every frozen roster member must be represented. Missing work blocks the round
instead of becoming a scored miner failure or silently reducing the roster.

After the first settlement, retries use its exact evidence identities and
original snapshot. A newer snapshot or another signature ordering does not
rewrite history. A crash after the database commit can be repaired by publishing
the same retained proposal. Original round expiry still applies. The existing
70/30 projection rejects an absent model contributor; there is no automatic
endpoint-only fallback.

Each read uses one SQLite snapshot and checks stored sizes before loading
bodies. The existing replay limits also bound the combined roster and evidence;
the complete proposal has a 16 MiB ceiling. Configure filesystem quotas for
proposal files and the shared database. Four usable settlement rounds are
considered per poll, with a wrapping cursor so old rounds cannot monopolize it.

Poll summaries add `settlement_prepared`, `settlement_incomplete`, and
`settlement_held`. Alert on repeated incomplete/held rounds before expiry.
Do not delete a retained settlement to retry with more convenient inputs.

Later quorum conflicts hold subsequent preparation and mark the retained
settlement disputed. An existing file remains historical evidence. Its presence
must never override current conflict checks in the signer or successor worker.

## Remaining publication work

The [independent settlement signer](OPEN_COMPETITION_SETTLEMENT_SIGNING.md)
checks local execution receipts and reviewed promotion history, re-proves the
registration snapshot, and retains signing intent before signing. Its automatic
delivery connection and eligible-group certificate collection remain unfinished.
A coordinator proposal alone is insufficient.
Signed activation and finalized incentive checks follow that connection and
the reviewed-input gates in the [execution plan](OPEN_COMPETITION_EXECUTION_PLAN.md).
