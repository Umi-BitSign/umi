# Automatic settlement delivery

The round coordinator can collect independent settlement signatures and publish
an immutable replay package. Evaluators discover proposals through authenticated
HTTPS and sign only after the [local settlement checks](OPEN_COMPETITION_SETTLEMENT_SIGNING.md).
No separate upload key or manual certificate assembly is required.

This path does not approve model rights, import a promotion head, activate the
70/30 policy, or submit chain weights. It leaves the deployed bridge unchanged.

## Coordinator configuration

Enable `settlement_directory` as described in the
[preparation guide](OPEN_COMPETITION_SETTLEMENT_PREPARATION.md), then add a
`settlement_delivery` object to `umi-round-coordinator-config/1`:

- `state_directory`: private durable proposal, vote and certificate journal.
- `certificate_directory`: private certificate and package-reference output.
- `package_directory`: immutable content-addressed replay packages.
- `package_limits`: explicit `CompetitionPackageLimits` for every package file
  and the aggregate package. See [package rehearsal](OPEN_COMPETITION.md#immutable-settlement-package-rehearsal).
- `release_identity`: reviewed `CompetitionReleaseIdentity`, including the
  exact revision, release manifest and bundle digests, and target triple.

All directories must be absolute, owned, private, and separate from each other
and the existing coordinator paths. These settings become part of the durable
journal binding. Configure them when provisioning; never delete a journal to
change bindings or bypass an expired round. The coordinator needs no wallet.

Expose `POST /v1/competition/settlements` on the same credential-free HTTPS origin
as the round service. Disable body logging and caching. Enforce a 16 KiB request
limit and reject compression at the proxy. Discovery is restricted to policy
evaluators, with short-lived hotkey signatures and replay-protected nonces.
Unlike the pre-reveal work feed, these responses contain the revealed reference
suite. Do not expose them as public miner discovery or static downloads.

## Evaluator configuration

In each `umi-evaluator-config/1`, supply:

- `round_coordinator_origin`: the coordinator HTTPS origin.
- `settlement_review_directory`: this evaluator's independently reviewed
  `CompetitionStore`, separate from all other evaluator paths.
- `settlement_replay_limits`: reviewed `PublicationReplayLimits` for roster,
  evidence and certificates.

The worker polls, endorses and returns votes automatically. It uses its existing
hotkey and owned finality provider. Each endorsement still requires the worker's
own cutoff reservation, completed local execution for every roster member,
by-cutoff evidence receipts, and the exact locally reviewed promotion history.
An empty review store blocks signing. Copying the coordinator database is not
independent review. UID 0 and UID 54 under our administration count as one group.

## Delivery and recovery

The coordinator checks its current intake conflicts, retained settlement,
complete evidence and promotion head before accepting votes or publishing.
Independent eligible control groups must meet the policy quorum. The first
certificate is retained before package creation; later signatures cannot alter
its bytes. A failed write is retried by the coordinator's next preparation poll.

Discovery pages contain at most four current proposals, bounded at 16 MiB each.
The snapshot-age limit and original round expiry apply throughout collection.
Expired proposals remain historical records; their deadlines are never shifted.
An expired retry can acknowledge an already retained vote but cannot create a
new current publication. An outstanding local conflict holds further delivery.

Successful delivery writes:

```text
<publication-digest>.certificate.json
<publication-digest>.package.json
```

The digest is the domain-specific settlement publication digest. The package
reference points to the existing eight-file sealed replay package. Its
`chain_submission_authorized` flag remains false. Successor activation and its
weight-worker verification are separate from this publication step.

Provision filesystem quotas for package storage as well as the bounded journal.
Logical journal capacity does not include SQLite overhead or sealed packages.
Alert on repeated `settlement_held`, missed windows, insufficient signatures,
and disk exhaustion. Preserve journals and certificates during recovery.

## Verification scope

The delivery tests use synthetic keys and an in-process HTTP transport. They
exercise coordinator polling, a complete 70/30 settlement, two endorsements,
package replay, restart recovery and rejection paths. Their local-execution
fixture is isolated; they do not prove model quality or independent operators.
The complete protected-data scheduling-to-execution rehearsal, agreed promotion
history, reviewed rights, signed activation and finalized incentive evidence
remain launch requirements.
