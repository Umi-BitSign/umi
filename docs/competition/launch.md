[Documentation](../README.md) / Launch configuration

# Competition launch configuration

C5 is the next cohort. Intake is held open while its signed policy, protected
suite, installed services and recovery behavior are qualified. The hold has no
submission deadline and does not advance automatically to C6. Public status
must continue to show C5 as preparing until the launch owner installs and
publishes the complete qualified configuration.

SN78 registration and a competition acceptance are separate. An intake receipt
does not promise selection, a score or a reward. C4 keeps its signed allocation
and remains the effective reward cohort until C5 has a certified successor row.

## C5 reward policy

C5 uses separate service and public-model pools:

- **50% service:** distributed across certified service work. Each job's credit
  is its certified work units multiplied by its normalized quality score.
- **50% public models:** distributed in proportion to exact benchmark score
  among distinct eligible public-model artifacts that match or beat the frozen
  baseline.

Duplicate model content counts once. The earliest certified complete acceptance
selects that content's recipient. A sole eligible model receives the complete
model pool. If no model qualifies, that pool goes to the policy's proved burn
destination. A participant may qualify independently for both pools.

The governing submission must bind
[version 3 contribution terms](../MODEL_CONTRIBUTION_TERMS_V3.md), SHA-256
`9b6b47d8f6ff0242a2bee97a643b318491f246120841b28ba80feb3953d0fdcd`,
and the exact signed C5 policy. Earlier acceptances do not imply version 3
acceptance. See [model contributions](../contributors/models.md) for artifact,
rights, provenance and reconstruction requirements.

## Scoring and video-dependence diagnostics

The C5 scoring profile uses `umi-open-competition-policy/3` with
`umi-competition-suite/2`. The frozen suite and runtime determine the automatic
CER/WER benchmark scores.
C5 may also compare a continuous-signing output for its correct video with the
same model's output for a matched unrelated video. That comparison is diagnostic
only. It cannot change a C5 score, rank, eligibility decision, reward, settlement
or activation time. A missing or unreliable diagnostic cannot hold settlement.

Any future video-dependence payout gate requires published thresholds, a
qualified positive control, a newly signed successor policy and fresh participant
acceptance before its intake opens. The prospective policy version 4 procedure
in [private holdout operation](../operators/private-holdout.md) is not the C5
policy.

## Timing and recovery

Published cohort dates are operating targets. Liveness failures do not expire a
cohort or authorize its evidence to be discarded.

- Every phase is journaled and replayable. A coordinator, evaluator or validator
  outage leaves unfinished work pending and resumes it from retained evidence.
- The previous certified reward row remains effective until a newer cohort is
  certified and activated.
- A five-hour rest starts after request closure is certified. The next cohort
  cannot start requests earlier.
- Each designated validator must receive at least 24 hours of verified
  opportunity to submit the certified row. Offline time does not count toward
  that opportunity.
- Moving a service to another host preserves its journal, signed inputs and
  content-addressed evidence. Migration does not create a new cohort identity.
- Operation timeouts and retries are bounded to detect a stuck attempt, but a
  timeout does not become a terminal cohort deadline. Recovery schedules another
  attempt with the original evidence.

Standing cohort authority carries these rules without periodic coordinator
renewal. A coordinator may be offline for longer than a nominal phase window;
recovery delays the cohort instead of losing it. Conflicting signed histories,
invalid signatures, changed immutable inputs and missing original evidence still
fail closed and require repair. Eventual completion does not weaken integrity
checks.

## Trust and evaluator profile

The initial C5 profile lists UID 0 and UID 54 as evaluators in the same
`umi-operated` control group, with one required evaluator group. Either can
continue the group's retained work after a state-preserving handoff, but their
signatures do not count as independent operator votes. This remains a
single-operator trust model. Adding another control group or increasing quorum
requires a successor policy and qualification of that exact profile.

## Protected inputs

Before intake leaves its hold, fix and sign the exact:

- C5 policy, version 3 terms digest and standing cohort authority;
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
2. **Installed C4-to-C5 handoff:** Install C5 services beside C4 without selecting
   them. Rehearse the signed handoff and prove a failed C5 boot leaves C4 active.
3. **Mixed six-cohort recovery:** Run C5 through C10 with service and model tracks,
   alternating coordinator/evaluator outages, restart replay, five-hour rests,
   24-hour validator opportunities and previous-row continuity.
4. **Capacity:** Run the intended host and container runtime with production-size
   evidence and generous test watchdogs. Test watchdogs may detect harness stalls;
   they must not define cohort expiry.
5. **Storage and publication:** Restore evidence and model artifacts from the
   private R2 copies, verify every digest, and publish bounded public discovery
   records without exposing private clips or credentials.
6. **Validator path:** Verify UID 0 and UID 54 independently consume the certified
   row, survive restart and RPC failover, and retain uncertain transaction state.
7. **Studio enrollment:** Submit the Studio baseline artifact to the public-model
   track under the exact C5 policy and confirm its complete acceptance and durable
   R2 copy.
8. **Selection:** Publish the canonical standing boot selector only after all
   preceding evidence passes. Verify the selected services, public status and
   retained C4 rollback boundary.
9. **Chain proof:** After settlement, confirm each intended validator's fresh
   finalized row and the resulting incentive before announcing reward activation.

Source tests, a merged commit, staged files, a running service and a submitted
transaction are intermediate evidence. None alone proves a live reward row.

## Operational references

- [Current miner operation](../CURRENT_MINER_OPERATION.md)
- [Submission commands](../reference/commands.md)
- [Round coordination](../operators/rounds.md)
- [Settlement and publication](../operators/settlement.md)
- [Validator successor handoff](../validators/successor-upgrade.md)
- [Public results API](../reference/competition-results-api.md)

Retain C4's signed artifacts and evidence for replay. Remove obsolete migration
instructions after no installed service or recovery consumer depends on them;
Git history is the record of superseded launch plans.
