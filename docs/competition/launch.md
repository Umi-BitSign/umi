[Documentation](../README.md) / Launch configuration

# Competition launch configuration

The active cohort runs under its signed policy, protected suite, installed
services and recoverable standing series. Published phase blocks are nominal
progression targets, not non-extendable deadlines, and do not advance the series
automatically. Public status, readiness and the current signed plan are the
authority for phase, admission and track availability.

The current scoring contract is `umi-open-competition-policy/3` with
`umi-competition-suite/2`. Public status and the signed plan bind the exact
policy and suite hashes used by the active cohort.

SN78 registration and a competition acceptance are separate. An intake receipt
does not promise selection, a score or a reward. The previous certified
allocation remains effective until the active cohort has a certified and
activated successor row. The public upgrade manifest and signed cohort plan
publish the canonical policy, transport and terms digests.

## Reward policy

When the signed plan enables both tracks, it records separate service and
public-model shares:

- **Service pool:** distributed across certified service work. Each job's credit
  is its certified work units multiplied by its normalized quality score.
- **Public-model pool:** eligible artifacts that match or beat the frozen
  baseline are placed in the quality bands selected by the policy. Each occupied
  band receives one credit, and the pool is distributed across those credits in
  proportion to their exact benchmark scores.

Duplicate model content counts once. The highest-scoring eligible artifact in a
band supplies its credit; an exact score tie is resolved by the earliest
certified complete acceptance. Small score variations within one band do not
create extra credits. A sole occupied band receives the complete model pool. If
all band-credit scores are zero, the pool is divided equally among occupied
bands. If no model qualifies, the pool goes to the policy's proved burn
destination. A participant may qualify independently for both pools.

Model-only plans disable endpoint/service participation and assign all 65,535 raw
competition units within the eligible public-model population using the same
baseline floor, deduplication and quality buckets. Read track selection and pool
shares from each signed cohort plan rather than inferring them from its number.
No unopened cohort profile is permanent; successor terms and a replacement
signed plan may change any of its settings before intake and miner consent. An
active cohort's plan is not changed retroactively.

Every submission must bind the exact immutable contribution terms and signed
policy advertised by its cohort plan. Earlier acceptance cannot be reused as
acceptance of successor terms. See [model
contributions](../contributors/models.md) for artifact, rights, provenance and
reconstruction requirements.

The signed plan identifies the frozen comparator bundle and execution runtime by
digest. Public discovery supplies those exact artifacts and their provenance.
Source archives do not replace the executable comparator identity.

## Scoring and video-dependence diagnostics

The active scoring profile, frozen suite and runtime determine the automatic
CER/WER benchmark scores. A plan may also compare a continuous-signing output
for its correct video with the same model's output for a matched unrelated
video. That comparison is diagnostic
unless its signed policy explicitly defines a qualified gate. A diagnostic-only
comparison cannot change a score, rank, eligibility decision, reward, settlement
or activation time, and a missing or unreliable diagnostic cannot hold
settlement.

Any future video-dependence payout gate requires published thresholds, a
qualified positive control, a newly signed successor policy and fresh participant
acceptance before its intake opens. The prospective procedure in
[private holdout operation](../operators/private-holdout.md) is not active merely
because its implementation exists.

## Timing and recovery

Published cohort dates are operating targets. Liveness failures do not expire a
cohort or authorize its evidence to be discarded.

- Every phase is journaled and replayable. A coordinator, evaluator or validator
  outage leaves unfinished work pending and resumes it from retained evidence.
- Request closure has an automatic miner-tail rule. Once at least 12 hours have
  elapsed from the original certified request opening, unfinished work can be
  recorded as skipped when at most 10% of distinct original selected
  miner identities remain unfinished. Benchmark and accepted paid-work miners
  count in one union; multiple entries, cases or retries cannot enlarge the
  denominator. Existing cohorts use their original opening, without a new grace
  period after an upgrade. The independently certified tail disposition can
  close an unavailable or uncompensated request window; original outage records
  and signed deadlines remain intact. The owner seals the exact accepted paid
  inventory only after this threshold qualifies. Before sealing individual
  queues, it publishes one durable cutoff under the first original catalog
  queue's journal directory (`cohort-tail-admission/tail.json`). Every catalog
  retains this directory binding: keep the file and directory with the existing
  journals during recovery or migration. A crash between publication and sealing
  still refuses fresh claims; accepted duplicate claims remain recoverable.
- Independent reviewers verify the original and closing chain timestamps, exact
  original inventory, genuine completed terminals and explicit skipped
  dispositions before certifying closure. Completed assignments and earned paid
  work retain their normal scoring and certification. Incomplete benchmark
  assignments have no aggregate score, and unperformed paid work earns no credit.
  Partial evidence is retained. The cutoff preserves work completed before its
  selection, including completions received after the first 12 hours. It does
  not rewrite signed attempt deadlines or create a miner retirement receipt.
  Each missing evaluator terminal requires that evaluator's signed inventory at
  a finalized block after the fixed cutoff and no later than closure. Reviewers
  replay that observation's native proof and the retained partial originals.
  An older partial export cannot establish that no newer work exists; a complete
  inventory still requires ordinary case or terminal certification. Retries keep
  the original cutoff while incorporating additional genuine completions.
  The owner requests these snapshots through its existing settlement history
  delivery only after selecting the cutoff. Each evaluator reuses the same
  signed snapshot for unchanged work, so a stalled cohort does not accumulate
  new inventory signatures or files on every poll. The cutoff request is
  advisory; it never authorizes closure or substitutes for independent quorum.
- The previous certified reward row remains effective until a newer cohort is
  certified and activated.
- A five-hour rest starts after request closure is certified. The next cohort
  cannot start requests earlier.
- Each designated validator must receive at least 24 hours of verified
  opportunity to submit the certified row. Offline time does not count toward
  that opportunity.
- Moving a service to another host preserves its journal, signed inputs and
  content-addressed evidence. Migration does not create a new cohort identity.
- Operation timeouts and retries detect stuck attempts. A timeout alone does not
  complete an obligation; recovery uses original evidence or the separately
  certified miner-tail disposition above.

Standing cohort authority carries these rules without periodic coordinator
renewal. A coordinator may be offline for longer than a nominal phase window;
recovery delays the cohort instead of losing it. Conflicting signed histories,
invalid signatures, changed immutable inputs and missing original evidence still
fail closed and require repair. Eventual completion does not weaken integrity
checks.

## Trust and evaluator profile

The signed plan lists evaluator identities, control groups and required quorum.
Public status distinguishes required evaluators from optional redundancy.
Signatures from validators in one administration count as one independent group.
Adding a control group, changing a required signer or increasing quorum requires
a successor policy and qualification of that exact profile.

## Protected inputs

The signed launch fixes the exact:

- policy, immutable terms digest and standing cohort authority;
- protected suite, references, strata and case provenance;
- frozen baseline and execution runtime;
- participant and model-artifact intake limits;
- evaluator set, control groups and chain/RPC configuration;
- service and model allocation rules; and
- publication, evidence-retention and recovery destinations.

Keep protected labels and private clips outside public storage and execution
requests. Candidate and baseline outputs use the same committed suite and
runtime. Do not repair labels, replace cases or alter scoring after candidate
outputs are known. See [private holdout operation](../operators/private-holdout.md).

## Activation checklist

Launch requires one retained evidence package for the exact production
configuration. Complete these checks in order:

1. **Policy and inputs:** Verify signatures, digests, baseline reconstruction,
   model-rights requirements, protected-suite integrity and available unused
   cases. Publish the miner-facing rules and tested commands.
2. **Installed predecessor handoff:** Install successor services beside the active
   services without selecting them. Rehearse the signed handoff and prove a failed
   successor boot leaves the predecessor active.
3. **Multi-cohort recovery:** Run the standing series with the tracks selected by
   each signed plan, alternating coordinator/evaluator outages, restart replay,
   five-hour rests, 24-hour validator opportunities and previous-row continuity.
4. **Capacity:** Run the intended host and container runtime with production-size
   evidence and generous test watchdogs. Verify the pinned CPU image and an actual
   bounded invocation as the evaluator service account under its exact systemd
   mount, namespace, privilege and cgroup settings. A successful shell invocation
   does not qualify a sandboxed service. Keep evaluator container storage separate
   from validator storage and wallets. Bound model concurrency across every
   evaluator on the host by their combined per-case memory limits, leaving
   headroom for chain observers and owner services. Include rootless case scopes
   when checking aggregate consumption; they may be outside the reviewer unit's
   cgroup. Test watchdogs may detect harness stalls;
   they must not define cohort expiry.
5. **Storage and publication:** Restore evidence and model artifacts from the
   private R2 copies, verify every digest, and publish bounded public discovery
   records without exposing private clips or credentials.
6. **Validator path:** Verify every required validator consumes the certified row,
   survives restart and RPC failover, retains uncertain transaction state, and
   receives the full verified reward opportunity. Verify optional validators
   separately; their absence or retirement must not hold the cohort.
7. **Selection:** Publish the canonical standing boot selector only after all
   preceding infrastructure evidence passes. Verify the selected services,
   public status and retained predecessor rollback boundary.
8. **Operator test enrollment:** Submit an operator-controlled baseline artifact
   through every enabled live track under the exact active policy and confirm its
   complete acceptance and durable object-store copy.
9. **Chain proof:** After settlement, confirm every required validator's fresh
   finalized row and resulting incentive before announcing reward activation.
   Record any optional validator rows separately.

Source tests, a merged commit, staged files, a running service and a submitted
transaction are intermediate evidence. None alone proves a live reward row.

## Operational references

- [Current miner operation](../CURRENT_MINER_OPERATION.md)
- [Submission commands](../reference/commands.md)
- [Round coordination](../operators/rounds.md)
- [Settlement and publication](../operators/settlement.md)
- [Validator successor handoff](../validators/successor-upgrade.md)
- [Public results API](../reference/competition-results-api.md)

Retain predecessor signed artifacts and evidence for replay. Remove obsolete
migration instructions after no installed service or recovery consumer depends
on them; Git history is the record of superseded launch plans.

Owned-finality collection budgets accept 1 through 600 seconds, with a
120-second default. Intake shares one background collection per refresh, using
at least 240 seconds or the configured budget when larger; callers wait through
that same collection. These operation budgets do not relax verified head age,
cohort authority or signed issue deadlines. Retain existing journal bindings and
use a qualified migration before changing a bound installed configuration;
never reset evidence to change a timeout.
