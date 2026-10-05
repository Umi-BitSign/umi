[Documentation](../README.md) / Transport cadence

# Cohort request windows and recovery

Cohort progress and an individual execution attempt have different lifetimes.
An outage may expire a bounded attempt; it must not expire accepted cohort work.
Retain the original assignment, request, votes, responses and journals. Recover
an original response, or certify a fenced replacement for the same obligation.
Do not edit an issued request or its signed transport policy.

The source includes a cohort attempt-window extension. Deployment must select a
qualified reviewer and miner release before enabling it; the current public
miner manifest still selects the legacy window runtime. Enable
`request_window_version: 2` in the benchmark endpoint host and service dispatch
host only after qualifying those consumers. Omission retains version 1.

## Linked attempt deadlines

A version-2 cohort attempt uses the independently verified issuance block as its
single clock anchor. Its nominal block budget is:

```text
blocks = ceil((issue_allowance_seconds + response_window_seconds)
              / target_block_interval_seconds)
deadline_block = issuance.height + blocks
response_close_time = issuance.timestamp + blocks * target_block_interval_seconds
response_close_round = first Quicknet round at or after response_close_time
reveal_round = first Quicknet round at or after response_close_time + reveal_margin
```

Both representations derive from this one budget. Quicknet adds less than one
round of rounding. Actual chain speed can differ from its nominal interval;
recovery must therefore handle drift, rather than require the two clocks to
expire simultaneously. The new window identity binds the cohort, authorized
work, attempt number, transport digest and exact verified issuance. It does not
wait for a legacy selection-window opening. A fresh window is created only for
new work or a certified replacement; retained requests replay unchanged.

Each reviewer retains its independently verified issuance proof before signing.
The miner verifies its own issuance proof and current cohort authority before
inference. Request IDs, case/video binding, origin authentication, nonce freshness,
resource bounds and reviewer quorum remain mandatory. Per-item service work and
benchmark endpoint work use the same clock calculation.

## Preserve and fence old attempts

Legacy `/1` request witnesses and `/1` retirement receipts retain their exact
bytes and original interpretation. A `/1` no-response receipt still needs both
original expiry conditions. Keep their decoders while any accepted assignment,
recovery journal or replay consumer references them.

The explicit `umi-endpoint-retirement/2` receipt instead reports
`expired_response_opportunity`. Only the assigned miner may sign it, after the
original response round has expired, its exact grant is retained, protocol work
is durably fenced and the assignment lock has drained. Its no-response archive
and receipt intent are frozen atomically with the fence. Interrupted signing
recovers the same intent after restart without a new chain read. Retained
responses still use their original signed bytes and cannot become absence.

Reviewers independently verify the exact request/grant/miner binding, the expiry
observation, signature and fence before certifying a replacement. This extension
does not authorize cancellation of a live response opportunity, reward missing
work, or erase an unknown original transaction or execution outcome.

## Select the compatible release

Qualify delayed certification, legacy-window blackout, either clock expiring
first, interrupted fence/signing, miner and reviewer restart, exact retained
responses and completed native work. A process being active or a grant delivery
receipt is insufficient. Keep the old allocation until a correct successor row
is certified and its finalized submission is verified.

Update the canonical miner release manifest together with the compatible source
and current connection guide. Existing miners use the same updater and retain
their hotkey, model and private state. Do not issue extension requests to an old
runtime that cannot verify them. Health capability fields are diagnostics, not
proof of successful inference or admission.

For an unopened future policy, `ScoringPolicy.competition_transport` can set the
legacy stride and time allowances. Such a policy changes its digest and requires
new signed terms and binding inputs. It never alters accepted work from the
predecessor policy. A stride adjustment alone cannot repair delayed certification
or divergent expiry of an already retained request.
