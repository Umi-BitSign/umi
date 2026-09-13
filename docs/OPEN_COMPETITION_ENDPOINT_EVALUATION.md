# Paired endpoint evaluation

Each evaluator compares a miner's retained endpoint responses with actual runs
of the preserved incumbent model on the same assigned videos. The endpoint
track does not require the miner to disclose model weights. The incumbent runs
use the pinned offline CPU container, with no network, wallet, or references
mounted into it.

This path prepares unsigned evaluation evidence. It does not activate the
competition, award contributor attribution to the imported baseline, or submit
chain weights. The [execution-plan launch gates](OPEN_COMPETITION_EXECUTION_PLAN.md)
still apply, including the approved simultaneous 70/30 policy.

## Before reference reveal

Use the signed publication accepted by the [endpoint dispatcher](OPEN_COMPETITION_DISPATCH.md).
Prepare one local incumbent job for this evaluator and endpoint submission:

```sh
umi-competition --policy /ABSOLUTE/POLICY.json prepare-endpoint-incumbent \
  --legacy-policy /ABSOLUTE/TRANSPORT-POLICY.json \
  --publication /ABSOLUTE/PUBLICATION.json \
  --submission-sha256 ENDPOINT_SUBMISSION_DIGEST \
  --incumbent /ABSOLUTE/INCUMBENT-MANIFEST.json \
  --runtime /ABSOLUTE/CPU-RUNTIME.json \
  --evaluator-hotkey YOUR_PUBLIC_EVALUATOR_HOTKEY
```

Save that JSON privately as the job input. Preparation checks the publication's
independent signatures and derives its complete, reference-free case list. An
evaluator without those assignments cannot prepare the job.

Run the incumbent during the frozen evaluation interval, before references are
revealed. Videos must be available in the private source directory as
`<video-sha256>.mp4`; their bytes are checked against the assignments. The model
archive must already contain the hash-verified incumbent bundle.

```sh
umi-competition --policy /ABSOLUTE/POLICY.json run-endpoint-incumbent \
  --job /ABSOLUTE/ENDPOINT-INCUMBENT-JOB.json \
  --chain-config /ABSOLUTE/EVALUATOR-CHAIN.json \
  --archive /ABSOLUTE/PRIVATE/MODEL-ARCHIVE \
  --videos /ABSOLUTE/PRIVATE/VIDEOS \
  --state /ABSOLUTE/PRIVATE/INCUMBENT-EXECUTION
```

The command owns its finalized registration provider. Each actual invocation is
bounded by retained provider observations. The execution journal reserves the
job before starting the observer or container, retains stdout before awaiting
the finished boundary, and refuses an automatic rerun after failure or
cancellation. A complete retry returns the exact saved receipts without touching
the model archive or network. Never clear this journal to retry a case.

The output schema is `umi-endpoint-incumbent-evidence/1`. Save the complete JSON
privately. It contains only incumbent runs; endpoint responses remain in the
dispatcher journal. Existing model-contribution jobs and evidence retain their
original schemas and candidate/incumbent semantics.

## After reference reveal

Obtain the committed reference suite and matching Quicknet reveal pulses. The
pulse file has the form `{"pulses":[{"round":123,"randomness":"...","signature":"..."}]}`,
using actual retained records. Verification checks their pinned BLS signatures;
placeholder values cannot pass. Duplicate pulse rounds are rejected.

```sh
umi-competition --policy /ABSOLUTE/POLICY.json assemble-endpoint-execution \
  --incumbent-execution /ABSOLUTE/INCUMBENT-EVIDENCE.json \
  --dispatch-state /ABSOLUTE/PRIVATE/SCHEDULER \
  --publication-sha256 PUBLICATION_BODY_DIGEST \
  --legacy-policy /ABSOLUTE/TRANSPORT-POLICY.json \
  --suite /ABSOLUTE/REVEALED-SUITE.json \
  --reveal-pulses /ABSOLUTE/RETAINED-PULSES.json \
  --current-block OBSERVED_FINALIZED_BLOCK
```

The result is `umi-endpoint-paired-evidence/1`. Assembly requires all local
dispatches to be complete and to match their journal hashes. It replays exact
request signatures, authenticated response ciphertext and model-revision
bindings, then validates both roles against the committed suite. It never
resends a request or reruns the incumbent. Missing or uncertain dispatches
cannot be turned into miner failures. An unauthenticated transport outage voids
the evaluation under the existing scoring policy.

Each transcript is bounded to 1 MiB; a paired evidence object is bounded to
64 MiB. Keep it private: transport URLs can contain credentials. Retain the
scheduler, origin-proof cache and execution journal for review. Exported
signatures authenticate bytes; they do not independently prove publication
time, origin proofs, execution boundaries, or evaluator independence. Endpoint
elapsed time is evaluator-observed round-trip time. The paired record uses the
assigned request interval as a conservative endpoint block bound, alongside
the separately retained incumbent execution boundaries.

## Independent result agreement

Collect complete paired evidence from the required independent evaluator groups
in `{"executions":[...]}`. The existing `propose-execution-result` command now
accepts these endpoint records as well as model-execution records. It requires
matching round/submission/runtime assignments, exact outputs and compatible
resource eligibility. Disagreement cannot be averaged into an accepted result.

Each evaluator then runs `prepare-execution-record` against its own retained
paired evidence and the proposed result before signing. Both commands return
`signed: false` and `chain_submission_authorized: false`. The resulting signed
run records and shared result enter the existing independent-evaluation and
settlement flow. Multiple hotkeys controlled by one operator still count as
one evaluator group.

These commands handle one assigned endpoint job at a time. Production round
orchestration must schedule the incumbent work early enough, retain all
responses and publish the independently agreed settlement evidence. The
dispatcher alone does not perform those steps.
