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
together. The endpoint-only intake described here is therefore a no-weight
admission phase, not activation of either reward track. Before an endpoint-only
successor row can activate with the model share burned, UMI must publish
prospective terms that expressly allow that staged activation, bind them in a
new signed policy, and require affected miners to accept that exact version.
Alternatively, both tracks must open together under version 1. No row may pay a
model contributor until a model round passes the published reconstruction,
preservation, improvement, quality and rights gates.

If no model qualifies, continue burning the unallocated share. There is no
retroactive award. After promotion, fresh evaluation and recipient eligibility
remain required. An awarded contributor becoming ineligible, or a round without
qualifying endpoint evidence, retains the existing hold; no silent fallback or
redistribution is authorized. Preserve the [accepted terms](../MODEL_CONTRIBUTION_TERMS.md)
byte-for-byte, including their version and SHA-256 in submissions and policy.
An exact tie between the highest qualifying new model candidates promotes
neither candidate; the share remains burned for that round.

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
