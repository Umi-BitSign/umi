# Initial competition cohort: UID 0

The operator approved UID 0 as the sole evaluator for the initial 70/30 launch.
This is a single-operator trust model. It does not claim independent consensus,
independent model reproduction or protection from the selected operator's own
misconduct. The public launch announcement must state this limitation.

## Required policy binding

The competition policy must contain exactly this evaluator entry:

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
  "model_reward_bps": 3000
}
```

This excerpt is not a complete or signed policy. The validity interval, model
runtime, data, rights, terms, numerical limits and other required inputs must be
supplied and verified before signing. Recheck UID 0's hotkey and permit against
finalized chain state at deployment; do not infer identity from its UID alone.

Use `umi-competition-single-evaluator-transport/1` for the associated transport
document. It preserves the existing request clock, bounded resources, scoring
and finality fields, but requires exactly one validator entry with the same
hotkey as the competition evaluator. Its administrator ID must represent the
actual operator. The miner and dispatcher reject a mismatched cohort. The miner
requires competition mode for this transport; it cannot authorize legacy live
calibration or weights by itself.

The historical `umi-scoring-policy/1` profile still requires at least four
distinct validator administrators. Its serialized bytes and hashes are unchanged.
Do not fabricate additional keys or administrators to satisfy that old profile.
The transport's legacy publisher and publisher-control-group registries must be
empty. The signed competition assignment path supplies request authority; fake
publishers are not needed to satisfy the retired three-publisher launch gate.
Existing numerical transport ceilings remain unchanged.

## Operations and remaining gates

- UID 54 keeps its existing validator service during preparation. It is not a
  second evaluator, independent vote or substitute evaluator signer. At an
  authorized successor transition its weight worker can consume the same
  certified results without supplying an additional evaluation vote.
- UID 0 must execute the actual work and retain its signed run evidence.
  A one-signature threshold does not permit fabricated observations, missing
  cases, late publication, changed labels or missing finalized-state checks.
- Both reward tracks still launch together at 70/30. Model preservation,
  contribution rights and qualifying promotion are unchanged requirements.
- The Studio miner must still pass authenticated requests, supported-workload
  deadlines, recovery and capacity checks. This policy change does not extend
  its inference timeout or establish baseline accuracy.
- Intake and reward activation remain pending until the execution plan's
  remaining gates pass and the reviewed policy and transition are signed.

Additional evaluators, a larger quorum or a different evaluator key require a
later explicit signed policy. Never count two UMI-operated hotkeys as two
independent groups.
