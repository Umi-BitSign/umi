# Per-round successor signing

The publisher signs a settled round's weight authorization and v4 supervisor
directive under explicit release-authority controls. It runs separately from
the wallet-free coordinator. It does not submit a chain transaction or change
the running validators.

This is a local signing command with optional wallet-free feed delivery.
Automatic selection of completed rounds and the live host handoff remain to be
connected and rehearsed. Do not use this command as a launch announcement or a
replacement for the signed initial supervisor upgrade.

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

## Wallet-free delivery

Add `--feed-config /absolute/private/feed.json` to retain the signed result in
the delivery journal after the current signing checks. The canonical, private
`umi-successor-feed-config/1` file contains:

- `directory`: a private delivery journal separate from signing, replay, intake,
  finality and wallet directories.
- `plan`: the exact same approved publication plan.
- `execution` and `worker_limits`: fixed worker execution settings and ceilings.
- `maximum_rounds` and `maximum_journal_bytes`: bounded retained history.

The feed verifies the signed record, replays its complete package, validates
execution settings and requires a continuous predecessor chain before retaining
the export. Retries retain the same bytes. A different export at the same
sequence places the delivery journal on hold.

Run the wallet-free HTTP process separately:

```sh
python -m umi.competition_successor_feed \
  --config /absolute/private/feed.json --port 8094
```

It binds loopback only. The operator must route the installed directive origin's
`/successor` path to this service through HTTPS. Supply only its delivery journal,
configuration and the exact sealed package directories. Do not mount signing
wallets, authority state or the intake database into this process. Release
archives continue to use their separately signed immutable URLs.

GET serves cursor pages, hash-addressed authorizations, per-directive execution
settings and the nine declared replay-package files. The package descriptor and
its local filesystem paths are never served. There is no POST or HTTP signing
route. Cursor pages use `no-store`; immutable objects retain their exact bytes.
Concurrent reads are bounded; cancellation drains a read before releasing its
quota. Expired signed history remains available for validator catch-up and does
not renew an authorization.

If signing completed but delivery failed, recover the original signed export
without loading any wallet or collecting a new signing timestamp:

```sh
python -m umi.competition_successor_feed \
  --config /absolute/private/feed.json \
  --publication /absolute/private/original-signed-publication.json \
  --prepared-package /absolute/private/original-round.package.json
```

Recover missing predecessors in order. The source sealed packages must remain
available. No history or package is automatically evicted to free capacity.

Each directive's `page.json` supplies its exact immediate predecessor and signed
head. The host integration still needs to assemble the continuation from its
own root-sealed activation anchor, including catch-up across multiple feed
pages. A successful package download alone does not prove that host handoff.

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

The combined feed and publisher regression passed all 33 cases on the Studio's
Linux VM in 410.45 seconds. Nine new cases cover consecutive exports and restart,
missing predecessors, unsigned metadata changes, wallet-free recovery, export
cleanup, changed package files, the existing HTTPS consumer and canceled reads.
The HTTPS consumer uses an ASGI test transport and an inert hash-pinned release
archive. No production TLS route, OCI execution or host handoff is established
by those tests. Repository-wide Ruff and formatting checks also passed.
