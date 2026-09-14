# Per-round successor signing

The publisher signs a settled round's weight authorization and v4 supervisor
directive under explicit release-authority controls. It runs separately from
the wallet-free coordinator. It does not submit a chain transaction or change
the running validators.

This is a local signing command. Feed distribution and automatic selection of
completed rounds are not connected yet. Do not use it as a launch announcement
or a replacement for the signed initial supervisor upgrade.

## Inputs

Use a canonical, private `umi-successor-publisher-config/1` JSON file containing:

- `plan`: the fixed policy digest, supervisor trust configuration, operator
  consent, release identity, verifier pins, weight requirements and validity
  limits from `umi-successor-round-publication-plan/1`.
- `chain`: the process-owned finality/proof configuration. Its policy, chain
  family and selected verifier hashes must match the plan.
- `intake_directory`: the existing retained competition store. Missing intake
  history is an error; the command cannot create a replacement empty source.
- `publication_directory` and `replay_directory`: separate private state roots.
  They must not overlap each other, intake or finality state.
- `replay_capacity`, `maximum_rounds` and `maximum_journal_bytes`: explicit local
  storage limits. Existing records are retained when these limits are reached.
- `authorization_wallet` and `directive_wallets`: explicit release-authority
  wallet references (`wallet_name`, `hotkey_name`, `wallet_path`). The configured
  directive signature threshold must be met by distinct trusted hotkeys.

Supply the reviewed policy and the coordinator's canonical
`umi-prepared-competition-replay-package/1` descriptor separately. All three
input files must be owned private regular files in private directories.

```sh
python -m umi.competition_successor_publisher_cli \
  --config /absolute/private/publisher.json \
  --policy /absolute/private/policy.json \
  --prepared-package /absolute/private/settled-round.package.json
```

Stdout is the signed publication. Errors omit input payloads and wallet paths.
No coldkey is requested. These are release-authority signatures, not validator
weight transactions. Never mount these authority hotkeys into the coordinator
or a model-execution container.

## Current checks and recovery

The publisher fully replays the package and checks the current local intake
material, reviewed promotion head and retained publication conflicts. A fresh
owned finalized capture is collected after replay, before signing boundaries
and before retaining a complete publication. Head rollback, expiry, changed
source configuration or a newly observed conflict prevents current publication.
These are checks of retained local evidence, not a proof that no conflicting
certificate exists elsewhere.

Each authorization and directive signature is saved before the next signing
step. A retry reuses those exact bytes and the original validity window.
Incomplete attempts may be superseded by a later round only after strict expiry;
their records remain in the journal. Cancellation waits for the signing thread
to terminate before releasing the local service lock.

Historical publications remain readable from the signing journal. The current
publisher refuses to return an expired publication as an activation candidate.
It never extends a round or moves its original signing time forward to make it
usable again.

## Verification scope

The signing-core and current-gate tests passed 19 cases on the Studio's Linux
VM. They use synthetic authority keys and real replayed fixture packages. Tests
cover consecutive rounds, retained partial signatures, conflicts arriving during
an owned-head read, expiry, rollback, source changes and cancellation cleanup.
They do not establish production authority, model quality or feed delivery.

The command-wiring suite passed five additional cases on the Studio. It checks
provider cleanup on success and failure, explicit wallet selection after
readiness, missing intake history, overlapping state roots and private input
permissions. The chain and wallet ports in those tests are test doubles.
