[Documentation](../README.md) / Settle rounds and publish weights

# Settle rounds and publish weights

- [Automatic settlement preparation](#open-competition-settlement-preparation)
- [Independent settlement signing](#open-competition-settlement-signing)
- [Automatic settlement delivery](#open-competition-settlement-delivery)
- [Per-round successor signing](#open-competition-round-publisher)

## Lost coordinator outcomes

A dispatched claim without a durable response remains uncertain. Never resend it,
mark it completed, or synthesize a miner failure. The ordinary paired-evidence
path still requires every original transcript.

A successor verifier can accept an explicit `umi-coordinator-outcome-repair/1`
amendment signed by **every evaluator assigned to the original order**. This is
a separate authorization to issue a neutral `coordinator_outcome_unavailable`
void. It does not establish whether the request reached the miner. The amendment
binds the unchanged policy, round (including its complete roster), order,
publication, submission, original claim digest and times, bounded retention-search
audit, and predecessor/successor release identity digests. It may be signed only
after each affected request's deadline and no later than the existing evidence
cutoff, using a fresh owned finalized capture. The normal void and settlement
signatures and actual local receipt by cutoff remain mandatory.

The affected evaluator retains the signed amendment privately at
`<evaluator state_directory>/dispatch-repairs/<order digest>.json`. The evaluator
checks the original uncertain claim, replays every available transcript and the
actual incumbent execution, and signs an unavailable-evidence observation. Other
evaluators retain their complete observations. The new void and void-evidence
schemas use version 2. Unknown responses have no fabricated `CaseOutput` or score.
The original dispatcher claim remains unchanged, including its reserved proof
allowance. This path does not reclaim scheduling capacity or enlarge any window.

Build and qualify a compatible worker and host before obtaining the scoped repair
signatures. Existing workers reject the new evidence. For delivery, retain the
original queue configuration and journal binding, then place the exact successor
`CompetitionReleaseIdentity` at
`<settlement delivery state_directory>/repair-releases/<round digest>.json`.
The queue requires the amendment's predecessor to match its original configured
release and its successor to match this file. Package preparation and loading
also enforce the signed successor identity. No journal reset or ordinary release
substitution is permitted. Publisher plans and follower consent must separately
bind the new verified release; none of these files activates weights.

For future dispatch, optional `transcript_spool` in the dispatcher configuration
contains a separate absolute private `directory`, `maximum_assignments` (default
4096), and `maximum_bytes` (default 8 GiB). Capacity is reserved before claiming.
The dispatcher durably retains request intent before sending and the actual
outcome before completing the scheduling journal. Restart recovery consumes only
stored outcomes with their original claims and never contacts a miner. An intent
without an outcome remains uncertain. The spool retains private authentication
and response bytes, so keep it private and include it in bounded recovery searches.
Omitting the option preserves historical configuration bytes and behavior.

<a id="open-competition-settlement-preparation"></a>

## Automatic settlement preparation

The round coordinator can prepare an unsigned settlement proposal after a
round's evidence cutoff. It reads completed independent evidence from the same
competition store that the evaluator exchange writes. No operator assembles
the roster or chooses which successful miners to include.

This output still needs independent review and settlement signatures. It does
not activate a policy, change weights, or prove independent receipt timing.
The current bridge services are unaffected.

<a id="open-competition-settlement-preparation--configuration"></a>

### Configuration

Add `settlement_directory` to the private
[`umi-round-coordinator-config/2` configuration](rounds.md#open-competition-round-coordinator).
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

Settlement capacity follows the coordinator's `replay_limits` and the
evaluator's matching `settlement_replay_limits`. Profiles with at most 64 MiB
of evidence keep the existing 64 MiB proposal envelope and four-proposal page.
For larger profiles, the proposal envelope includes evidence, another roster,
two certificate allowances and 1 MiB of framing, rounded up to 64 MiB. The
maximum envelope is 512 MiB; configurations that exceed it are rejected.
For example, 256 MiB evidence with 4 MiB roster and certificate limits selects
a 320 MiB proposal envelope, one proposal per reply, and one active settlement
request through response transmission. The reply allows another 8192 bytes.
Private proposal files and settlement journals use the same envelope.

Package limits are configured separately: allow framing above the replay
evidence allowance and increase the aggregate package budget accordingly.
These changes do not increase native per-order reservations or total journal
budgets. Replay limits are part of retained configuration bindings; establish
the larger profile in newly staged state or use a separately reviewed migration.
Do not overwrite an existing journal's bound configuration or delete its state.

Byte envelopes are not process memory limits. Evidence is parsed, canonicalized
and replayed repeatedly, and request timeouts still apply. Qualify full-sized
structured evidence on the intended host, including concurrent model workloads,
before relying on a larger profile for settlement timing or memory headroom.

<a id="open-competition-settlement-preparation--output-and-retry-behavior"></a>

### Output and retry behavior

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
Every frozen roster member must have either a scored result or a certified void
received by cutoff. A void retains all assigned evaluators' signed observations
and a separate agreement on the reason. It gives no score or reward attribution.
Missing work or quorum still blocks the round; neither can silently reduce the
roster or become a scored miner failure.

Mixed outcomes use `umi-competition-settlement/2` and
`umi-competition-replay-evidence/2`. Each void binding includes the decision
digest, full evidence digest and first observed block. Scored-only records keep
their version-1 encoding and digests. Conflicting scored/void outcomes or distinct
void decisions hold the round and dispute any existing settlement. Valid
signature variants alone do not change the decision identity.

After the first settlement, retries use its exact evidence identities and
original snapshot. A newer snapshot or another signature ordering does not
rewrite history. A crash after the database commit can be repaired by publishing
the same retained proposal. Original round expiry still applies. The existing
version 1/2 projection rejects an absent model contributor. Version 3 supports
the explicit [unallocated-model burn](../competition/launch.md),
with finalized proof of its destination. There is no endpoint-only fallback.

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

<a id="open-competition-settlement-preparation--remaining-publication-work"></a>

### Remaining publication work

The [independent settlement signer](settlement.md#open-competition-settlement-signing)
checks local execution receipts and reviewed promotion history, re-proves the
registration snapshot, and retains signing intent before signing. Optional
[automatic delivery](settlement.md#open-competition-settlement-delivery) connects discovery,
eligible-group certificate collection and immutable replay packages.
A coordinator proposal alone is insufficient.
Signed activation and finalized incentive checks follow that connection and
the reviewed-input gates in the [execution plan](../competition/launch.md).


<a id="open-competition-settlement-signing"></a>

## Independent settlement signing

`IndependentSettlementSigner` reviews an unsigned settlement preparation using
one evaluator's own journals and finality provider. It returns one hotkey
endorsement. That endorsement alone is neither a quorum certificate nor
permission to submit weights.

The signer is used by the optional
[automatic delivery path](settlement.md#open-competition-settlement-delivery), which connects
proposal discovery, vote collection and replay-package publication. This code
does not change either deployed bridge validator.

<a id="open-competition-settlement-signing--inputs-and-local-checks"></a>

### Inputs and local checks

Construct the signer with the running `ContinuousEvaluator`, that evaluator's
cutoff-signing journal, its local `EvaluatorReviewStore`, and bounded
`PublicationReplayLimits`. Call `await signer.endorse(preparation)` with an
[`umi-settlement-preparation/1` proposal](settlement.md#open-competition-settlement-preparation).

The signer requires:

- Its own signed cutoff reservation, exact frozen roster and suite reservation.
- A completed local evaluator slot for every roster member, without a conflict
  hold. The retained independent evidence must match the proposal exactly.
- A local receipt showing that complete independent evidence was retained by
  cutoff. The matching signed execution announcement must reproduce the
  evaluator's run in the independent evidence.
- A promotion head matching the evaluator's local reviewed history. The
  proposal cannot initialize that history or import a contributor attribution.
- An exact registration snapshot re-proved through the evaluator's owned
  historical finality provider, and a fresh head inside the signing window.

The existing publication replay verifies the complete roster, result signatures
and deterministic 70/30 projection. A signer cannot be a roster submitter,
positive-weight recipient, promoted contributor, or a member of a policy
control group containing any of those identities. Quorum still requires the
configured number of distinct eligible groups. UID 0 and UID 54 operated by us
do not become two independent evaluators.

The [local review store](exchange.md#open-competition-review-history) receives cutoff and
roster history during independent work signing, at its actual receipt block.
Its baseline and promotions still require the preserved-bundle and signed
rights/quality review path. Copying the coordinator's SQLite database is rejected.
An empty promotion history blocks signing. This component provides no automatic
review approval. Known promotion and settlement conflicts remain blocking.

The reviewed histories must agree on the exact promotion record and parent link.
Legacy v1 records include an observation block, so creating similar records at
different blocks produces different digests. The versioned
[promotion agreement](promotion.md#open-competition-promotion-agreement) separates a shared
v2 decision from each operator's actual receipt block and full certificates.
The signer revalidates the bounded local receipt before using a v2 head.
The deployed review/distribution workflow still needs independent-operator
rehearsal; this signer never substitutes the coordinator's head to resolve a
mismatch.

<a id="open-competition-settlement-signing--evidence-timing-and-restart"></a>

### Evidence timing and restart

Before publishing completed independent evidence, the evaluator now saves an
`umi-independent-evidence-observation/1` receipt with its current owned finalized
boundary. A receipt is local provenance, not a proof of global network receipt
time. If a crash occurs after evidence retention but before receipt persistence,
recovery uses the actual restart observation. It never backdates a receipt from
an execution timestamp, relay claim or file modification time.

The coordinator's first-observation fields retain their existing meaning. A
signer checks its own evidence was also retained by cutoff; different operators
need not claim they first saw it at exactly the same block. The publication's
`finalized_receipt_timing_proven` field stays false.

The signer reserves the exact publication and suite before calling the hotkey.
A changed valid publication for the same round sequence creates a durable hold.
An exact retry returns the retained vote after checking current local state.
A missing vote after a crash can only be regenerated for the reserved bytes.
Never delete the journal to choose another settlement.

Owned finality is checked again after proof collection and evidence replay.
Missing evidence, a late local receipt, changed promotion history, an expired
snapshot, or a conflict discovered during collection blocks signing. No miner
is silently removed to make the remaining roster settle.

<a id="open-competition-settlement-signing--verification-scope-and-remaining-work"></a>

### Verification scope and remaining work

The tests exercise complete 70/30 publication signatures and signing-state
failure cases. Separate execution tests check model journals and the actual
authenticated endpoint-response path against the local-evidence verifier.
The combined service test additionally runs both tracks through scheduling,
execution, promotion and signed settlement using synthetic data and chain ports.
It does not establish real-model quality or independent administration.

The delivery tests additionally cover authenticated proposal discovery,
certificate collection and immutable package publication. The integrated
protected-data rehearsal, reviewed launch inputs, signed activation and finalized
incentive evidence remain launch requirements. The approved initial evaluator
cohort is UID 0 alone, with one disclosed operator group. Version 3 permits
70% endpoint allocation and 30% verified burn before the first promotion;
model-specific rights approval and a qualifying promotion are required before
paying the contributor share. Importing Michael's baseline grants no contributor
reward by itself. See the [allocation rule](../competition/launch.md).


<a id="open-competition-settlement-delivery"></a>

## Automatic settlement delivery

The round coordinator can collect independent settlement signatures and publish
an immutable replay package. Evaluators discover proposals through authenticated
HTTPS and sign only after the [local settlement checks](settlement.md#open-competition-settlement-signing).
No separate upload key or manual certificate assembly is required.

This path does not approve model rights, import a promotion head, activate the
70/30 policy, or submit chain weights. It leaves the deployed bridge unchanged.

<a id="open-competition-settlement-delivery--coordinator-configuration"></a>

### Coordinator configuration

Enable `settlement_directory` as described in the
[preparation guide](settlement.md#open-competition-settlement-preparation), then add a
`settlement_delivery` object to `umi-round-coordinator-config/2`:

- `state_directory`: private durable proposal, vote and certificate journal.
- `certificate_directory`: private certificate and package-reference output.
- `package_directory`: immutable content-addressed replay packages.
- `package_limits`: explicit `CompetitionPackageLimits` for every package file
  and the aggregate package. See [package rehearsal](../reference/commands.md#immutable-settlement-package-rehearsal).
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

<a id="open-competition-settlement-delivery--evaluator-configuration"></a>

### Evaluator configuration

In each `umi-evaluator-config/1`, supply:

- `round_coordinator_origin`: the coordinator HTTPS origin.
- `settlement_review_directory`: this evaluator's independently reviewed
  `CompetitionStore`, separate from all other evaluator paths.
- `settlement_replay_limits`: reviewed `PublicationReplayLimits` for roster,
  evidence and certificates.

For an evaluator on the coordinator host, an operator may explicitly configure
`settlement_loopback_port` (integer 1–65535) before initializing its journals.
Only settlement discovery and vote requests then connect to
`http://127.0.0.1:<port>/v1/competition/settlements`. The listener must be the
native coordinator service on that host. The public HTTPS origin remains the
logical coordinator identity and the connection used by cutoff and work signing.
The local port is retained in both evaluator configuration and settlement source
bindings; changing, adding or removing it on existing bound journals is rejected.
Do not rewrite those bindings or remove journals to enable this option.

This connection uses cleartext exclusively on literal IPv4 loopback. It is for
an explicitly authorized co-located deployment, with no DNS lookup, environment
proxy, redirect following, or fallback to the public origin. Native signed
queries, response bindings, independent evidence checks, finality, conflicts and
expiry still apply. Other hosts must use HTTPS and a route whose proxy deadlines
have been qualified for the complete query and certification operations.

Profiles with preparation capacity above 64 MiB allow 7,200 seconds for a server
operation, 7,260 seconds for a client read, and 7,320 seconds for a complete client
request. Legacy profiles retain 25/30/35 seconds. These budgets do not extend
protocol signing windows or upstream proxy deadlines. In particular, Cloudflare
documents a [125-second default proxy read timeout and a 30-second proxy write
timeout](https://developers.cloudflare.com/fundamentals/reference/connection-limits/);
increasing this client's budget alone cannot qualify that route.

Blocking settlement formation, journal replay, certificate/package work and
response serialization run in owned threads. Async finality providers and locks
stay on the service event loop. Background formation shares the settlement
queue lock with HTTP replay, so requests can authenticate promptly before
waiting without allocating a second full cohort. Cancellation or an operation
timeout drains the active worker before releasing its lock or request slot;
shutdown may therefore take longer than the requested timeout. Signed nonce
admission freshness, snapshot age, conflict checks and signing deadlines are
unchanged. The generous operational budgets do not extend those deadlines.

The worker polls, endorses and returns votes automatically. It uses its existing
hotkey and owned finality provider. Each endorsement still requires the worker's
own cutoff reservation, completed local execution for every roster member,
by-cutoff evidence receipts, and the exact locally reviewed promotion history.
An empty review store blocks signing. Copying the coordinator database is not
independent review. UID 0 and UID 54 under our administration count as one group.

<a id="open-competition-settlement-delivery--delivery-and-recovery"></a>

### Delivery and recovery

The coordinator checks its current intake conflicts, retained settlement,
complete evidence and promotion head before accepting votes or publishing.
Independent eligible control groups must meet the policy quorum. The first
certificate is retained before package creation; later signatures cannot alter
its bytes. A failed write is retried by the coordinator's next preparation poll.

Discovery page and preparation bounds follow the configured settlement capacity;
large profiles send one proposal per page.
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

<a id="open-competition-settlement-delivery--verification-scope"></a>

### Verification scope

The delivery tests use synthetic keys and an in-process HTTP transport. They
exercise coordinator polling, a complete 70/30 settlement, two endorsements,
package replay, restart recovery and rejection paths. Their local-execution
fixture is isolated; they do not prove model quality or independent operators.
The complete protected-data scheduling-to-execution rehearsal, agreed promotion
history, reviewed rights, signed activation and finalized incentive evidence
remain launch requirements.


<a id="open-competition-round-publisher"></a>

## Per-round successor signing

The publisher signs a settled round's weight authorization and v4 supervisor
directive under explicit release-authority controls. It runs separately from
the wallet-free coordinator. It does not submit a chain transaction or change
the running validators.

The local command supports one supplied package or polling completed coordinator
rounds with wallet-free feed delivery. Production HTTPS routing and the live
host handoff still need rehearsal. Do not use this command as a launch
announcement or a replacement for the signed initial supervisor upgrade.

When the retained store carries submissions from earlier policies, pass each
canonical private policy file with `--predecessor-policy`, from the immediate
predecessor to the oldest admitted policy. Both supplied-package and follow
modes accept the repeated option. The publisher checks the contiguous lineage
and preserves the existing contribution terms before opening the store or
loading authority wallets. A package's embedded lineage does not replace these
operator-selected inputs. Without the option, only the current policy is
admitted; another publisher invocation cannot supply its lineage implicitly.

<a id="open-competition-round-publisher--inputs"></a>

### Inputs

Use a canonical, private `umi-successor-publisher-config/2` JSON file containing:

- `plan`: the fixed policy digest, supervisor trust configuration, operator
  consent, release identity, verifier pins, weight requirements and validity
  limits from `umi-successor-round-publication-plan/1`, the renewal-enabled `/2`,
  or the bounded settlement-reuse `/3` described below.
- `public_launch`: the exact `umi-competition-public-launch/1` identity bound to
  the retained intake store. For the first public round, these config fields are:

  ```json
  {
    "schema": "umi-successor-publisher-config/2",
    "submission_head_checkpoint_directory": "/ABSOLUTE/PRIVATE/SUBMISSION-HEAD-CHECKPOINT",
    "public_launch": {
      "schema": "umi-competition-public-launch/1",
      "round_schedule": {
        "schema": "umi-public-round-schedule/1",
        "intake_opened_block": 9085463,
        "roster_close_earliest_block": 9135843,
        "roster_close_latest_block": 9135903,
        "work_signing_close_block": 9135963,
        "evaluation_close_block": 9156243,
        "protected_reference_reveal_block": 9156263,
        "evidence_cutoff_block": 9156383,
        "round_valid_through_block": 9156983
      },
      "eligible_tracks": ["endpoint"]
    }
  }
  ```

- `chain`: the process-owned finality/proof configuration. Its policy, chain
  family and selected verifier hashes must match the plan.
- `intake_directory`: the existing retained competition store. Missing intake
  history is an error; the command cannot create a replacement empty source.
- `submission_head_checkpoint_directory`: the exact external checkpoint used by
  intake, the coordinator, and any intake-enabled exchange. It must remain
  separate from every component state tree.
- `publication_directory` and `replay_directory`: separate private state roots.
  They must not overlap each other, intake, checkpoint, or finality state.
- `replay_capacity`, `maximum_rounds` and `maximum_journal_bytes`: explicit local
  storage limits. Existing records are retained when these limits are reached.
- `authorization_wallet` and `directive_wallets`: explicit release-authority
  wallet references (`wallet_name`, `hotkey_name`, `wallet_path`). The configured
  directive signature threshold must be met by distinct trusted hotkeys.

Supply the reviewed policy and the coordinator's canonical
`umi-prepared-competition-replay-package/1` descriptor separately. All three
input files must be owned private regular files in private directories.
Complete the [writer-generation cutover](../reference/commands.md#owned-finality-intake-v2-cutover)
before this publisher or any other version 2 process opens a legacy intake
database.

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

<a id="open-competition-round-publisher--wallet-free-delivery"></a>

### Wallet-free delivery

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
`/successor` path to this service through HTTPS. For configurations whose installed
origin is R2, use the disabled-by-default
[successor feed relay](../../deploy/successor-feed-relay/README.md) to copy this
service's public protocol objects to that existing address. Do not change an
installed trust configuration merely to point it at a new origin.
Supply only its delivery journal,
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

<a id="open-competition-round-publisher--automatic-completed-round-publishing"></a>

### Automatic completed-round publishing

Use `--follow-config` instead of `--prepared-package` to poll the coordinator's
completed-package directory. The canonical private `umi-successor-follow-config/1`
file contains:

- `certificate_directory` and `package_directory`: the exact separate roots
  used by the coordinator's settlement-delivery configuration. They must already
  exist and must not overlap authority, wallet or execution state.
- `maximum_rounds`: the retained source limit, no greater than the signing and
  delivery journals' limits. The default is 1024.
- `poll_interval_seconds`: 2 to 60 seconds, default 15.

```sh
python -m umi.competition_successor_publisher_cli \
  --config /absolute/private/publisher.json \
  --policy /absolute/private/policy.json \
  --follow-config /absolute/private/follow.json \
  --feed-config /absolute/private/feed.json
```

Add `--once` to perform one tick and exit. Stdout contains bounded status records,
not package paths or wallet material. The process owns one finalized provider;
it closes that provider on exit and drains active signing work on cancellation.
Invalid inputs, journal conflicts and provider failures stop the command. A
service manager may restart it with a delay; restarting cannot clear a durable
conflict hold. Reaching capacity stops new work without deleting history.

Discovery accepts canonical private `<settlement-digest>.package.json`
descriptors whose sealed manifests match the descriptor, filename, policy and
fixed package root. It checks at most `2 * maximum_rounds + 1` directory entries
per tick. Discovered round identities are retained across restart. A descriptor
is not sufficient to sign: the selected package is fully replayed and the
publisher still checks its current source and owned finalized head.

Each tick first repairs a missing signed export, one predecessor at a time,
without a new signature or timestamp. When delivery is caught up, the publisher
resumes an unexpired partial signing attempt, or selects the highest completed
round number newer than its last publication. It waits if that round has no
usable original activation window. It does not extend expired windows or fall
back to another package after a validation failure.

The feed remains a separate wallet-free process. Automatic signing does not
install a TLS route, activate a host or establish miner incentive on chain.

<a id="open-competition-round-publisher--bounded-renewal-of-an-unchanged-settlement"></a>

### Bounded renewal of an unchanged settlement

The default version 1 plan signs each completed round once. A validator's
single-use authorization cannot refresh that row a second time. Deployments
where evaluation takes longer than the chain activity window must account for
this before activation.

To permit recurring row refreshes, use `umi-successor-round-publication-plan/2`
and set `renewal_interval_blocks` in both the signing and delivery plans. This
is an explicit change to the plan's identity. Do not overwrite a version 1 plan
inside an existing journal. Version 1 canonical bytes and retry behavior remain
unchanged.

With `--follow-config`, the publisher first recovers incomplete delivery or an
unexpired partial signing attempt, then prefers a newer completed round. If no
newer round exists and the configured interval has elapsed since the last
authorization's signing block, it can renew the latest unchanged package.
Renewal performs package replay, current retained-source conflict checks and
fresh owned-finality checks before signing. Each renewal has a new directive
sequence, predecessor and single-use authorization ID. It does not resubmit an
old transaction or change the package's allocation.

For version 2, the validity limit remains the earliest of the plan, policy,
original round, snapshot-age limit and new authorization's maximum lifetime. Renewal never
extends the underlying round or snapshot. If the remaining window is too short,
the follower waits for a current completed round. A conflict or changed recipient
registration still blocks submission. This feature does not authorize a fallback
allocation after failed validation.

Choose an interval no shorter than the configured chain weight rate limit and
short enough to allow replay, feed delivery and finalization before the activity
cutoff. The plan requires mortality and activation headroom within its maximum
authorization lifetime; that check alone does not prove sufficient operating
margin. Measure the complete deployed path. The weight worker independently
checks the actual chain rate limit and allows at most one transaction per
authorization.

Signing, delivery and worker attempt journals retain every renewal. Include
renewals in their capacity budgets, even where a limit is named `maximum_rounds`.
Reaching a limit stops new work without deleting old receipts. Retain the exact
sealed package for retries and catch-up. Fresh evaluation rounds and their
original expiry schedule are still required for ongoing operation.

<a id="open-competition-round-publisher--reusing-a-settled-round-with-current-recipient-checks"></a>

### Reusing a settled round with current recipient checks

Version 2 cannot support a reward interval longer than the original settlement
registration snapshot's configured freshness window, regardless of how long the
signed round remains valid. Renewing its authorization does not remove that limit.

To use a completed round for an explicitly longer reward interval, select
`umi-successor-round-publication-plan/3` and supply both
`renewal_interval_blocks` and `maximum_settlement_reuse_blocks`. The latter is
measured from the original settlement observation, never from a restart or the
most recent renewal. It must fit the reviewed scoring cadence. Each new
authorization still expires at the earliest of this reuse limit, the original
round, policy, plan and per-authorization lifetime. It cannot revive an expired
round or change a retained allocation, score, label or signature.

The managed publisher obtains a new owned finalized registration capture after
replay and before each signature and final publication. Every projected
recipient must still have the same UID and hotkey, and the configured burn
destination must still match. A removed or reassigned recipient, changed burn
destination, stale proof or retained evidence conflict prevents publication.
Unrelated registration changes do not invalidate the unchanged recipient set.
The weight worker independently repeats its fresh registration, burn, permit,
runtime, rate-limit and authorization checks before a chain write.

Weight proof collection reuses exclusive, method-specific WebSocket connections
and fetches up to 512 requested storage values in batches of at most 256 keys.
Every batch must name the exact owned finalized block and contain every requested
key once. These are untrusted values until the existing complete trie multiproof
and runtime decoder accept them. Wrong-block, missing, duplicate and oversized
responses fail the collection. Connection reuse does not extend snapshot freshness,
retry a failed proof, or authorize a transaction. Runtime-code reads use separate
connections and retain their separate byte limits. Shutdown closes the sockets.

Version 3 requires the managed current-recipient gate even for the first
publication. The signing builder rejects ungated use. Versions 1 and 2 retain
their original serialization and snapshot-limited semantics; they cannot opt in
by adding the version 3 field. Do not replace a plan inside an existing journal.
Feed delivery must use exactly the same version 3 plan as the publisher.

This separates the age of scored results from the freshness of chain state.
It does not generate new evaluations or admit new miners into an already closed
roster. Publish the next roster-close and evaluation windows so new submissions
can enter a later round. A recipient change still requires a current settlement;
this mode does not invent replacement recipients or an alternative weight row.

<a id="open-competition-round-publisher--continuity-between-rounds"></a>

### Continuity between rounds

An expired round stops new authorizations. The follower reports
`waiting_for_current_round` and keeps polling; a later completed, replayable
package can resume publication with fresh recipient evidence and a new signature.
Retained signed history remains unchanged. The host can follow that continuation
after holding through expiry, including after restart. It does not automatically
return to the registration bridge.

A retained on-chain row alone does not establish reward continuity. Check the
deployed chain runtime's activity rule: once the validator becomes inactive,
its stored row may no longer contribute to score-directed consensus and ranks.
Other active validators and epoch state also affect emissions. Renewal cadence
must leave time for replay, proof collection, delivery and inclusion.

For future cohorts, an evaluator-signed `umi-competition-launch-amendment/2`
can lengthen the final round-validity window while preserving work, reveal and
cutoff times and cadence. A round end covering the next evidence cutoff plus
bounded delivery grace, together with a version 3 settlement-reuse limit covering
that same interval, permits automatic refreshes until the next certified result
arrives. Every refresh still uses current chain evidence. Missing certificates
beyond the grace period or changed recipients cause a hold.

This amendment cannot modify a prepared or active cohort. Apply it after the
preceding round's validity and before the next unused roster, under the native
history and checkpoint checks. Rebind future launch-dependent profiles and plans;
the replacement launch numbers its first future cohort as cycle zero. A changed
publication plan must be selected before journal initialization. After intake
migration, update the publisher's launch configuration and restart its service
with the same signing history. Longer outer consent or a configuration edit
cannot extend an already certified round.

Size retained weight evidence for the full consent horizon before initializing
the worker journal or installing its host limits. A normal write collects evidence
before signing, before broadcast and after submission; retries and stopped recovery
can add more. Account for runtime metadata, proof growth and filesystem overhead.
The worker's `maximum_evidence_bytes` must agree with its immutable journal binding
and fit the installed `maximum_weight_evidence_bytes` ceiling. A longer renewal
interval must still satisfy the rate limit, authorization headroom and current
chain activity cutoff. Capacity exhaustion preserves history and stops work.

During one stopped recovery audit, consecutive renewals may reuse an already
verified package only while its complete target, release and sealed file identities
remain unchanged. Every directive and weight authorization is checked separately.
This reuse ends with the audit; the final chain observation is collected afterward
and retains the usual freshness and finalized-head checks.

<a id="open-competition-round-publisher--current-checks-and-recovery"></a>

### Current checks and recovery

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
It never extends a round or changes a retained authorization's signing time.
A version 2 renewal creates a separate authorization only while the original
round remains usable.

<a id="open-competition-round-publisher--verification-scope"></a>

### Verification scope

Run the release publisher and these signing/feed tests on Linux. The unchanged
version 1 publisher reproduces a database-locking failure on the Studio's native
macOS environment; Linux guest tests do not qualify native macOS publishing.

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

The first automatic-publication batch passed 11 cases on the Studio's Linux VM
in 257.44 seconds. It covers completed-round selection, signed-export recovery,
expiry, late conflicts, descriptor bindings, scan limits and provider cleanup.
Two further cases cover unfinished-signature priority and cancellation during
discovery. All 46 cases in the combined publisher/feed regression passed on the
Studio Linux VM in 567.77 seconds, with two dependency deprecation warnings.
No live publisher service has been installed by this work.

### Forward reward continuity

A version 4 successor publication plan can opt into an independently signed
`umi-reward-continuity-authority/1`. This is new authority for future weight
writes. Original policies, rounds, evidence cutoffs, certificates and allocation
bytes remain unchanged. Older plans retain their original expiry behavior.

The control binds one policy, chain, compatible release identity, first round
identity and an explicit range of eligible cohort sequences. Its lifetime is
`until_superseded_or_revoked`. The last eligible certified allocation may keep
renewing after the range's last round ends. Expanding the eligible cohort range
requires another reviewed authority; no operator can supply a replacement row.

Before the original round and policy end, the publisher must replay the complete
certified package and retain a signed allocation admission with its current
owned finality boundary. A certificate first presented after that deadline
cannot be admitted for continuation, even if it claims an earlier observation.
Admission is an explicit trusted-authority attestation, not independent proof
of the historical wall-clock time at which every evaluator signed.

Each new write still needs a fresh, short, single-use authorization, fresh
recipient identities, validator permit, nonce, runtime and finality proofs.
Version 2 weight authorizations carry the exact control and admission. The
supervisor's local consent pins the control hash and final host manifest, with
an explicit until-superseded lifetime. A longer ordinary consent cannot enable
this mode. The host and worker retain the highest adopted round and exact
package across restart. A newer certified allocation replaces it; older rounds
cannot return. Pending or cryptographically invalid candidate packages confer
no replacement authority. Corrupt discovery metadata or conflicts remain holds.

The signed call retains the allocation's raw weights. Subtensor scales the
largest submitted weight to 65,535 before storing the row. Submission checks
and stopped-worker recovery apply that same fixed-point scaling and rounding
when comparing finalized storage, together with the nonce, last-update and
recipient identity checks. This lets recovery recognize an already-applied
transaction without changing the signed allocation or submitting it again.

If a recipient UID changes hotkey, the original rule holds the row. A separately
threshold-signed `umi-reward-recipient-amendment/1` can route listed recipients'
exact raw shares to the policy's existing burn destination. It binds the original
continuity authority, package and projection. It cannot choose replacement
miners, change other shares or rewrite scores. Version 2 continuations carry the
amendment alongside the original timely admission. Current burn registration and
mode remain mandatory at publication and submission. The publisher retains one
immutable amendment per package; retry and restart reuse it. Older continuations
retain their original bytes and whole-row hold behavior.

Apply an approved signed amendment through the publisher's
`--prepared-package <private-preparation.json> --recipient-amendment
<private-signed-amendment.json>` mode, with the existing `--config` and `--policy`.
The command retains the amendment; ordinary publication/renewal produces the new
authorization. It does not submit weights. All consumers must support the new
continuation before it is published. A valid newer certified package can still
replace a held row without changing the original evidence.

A threshold-signed continuity revocation durably stops new publisher leases.
Already issued leases expire within the configured maximum write-authorization
lifetime, normally 360 blocks. A native signed supervisor hold or local operator
stop can stop execution sooner. The host latches a continuity hold; resuming
requires a separately reviewed local consent transition. There is no automatic
return to the old bridge or an older cohort allocation.

Expired partial signing attempts remain immutable. A fresh owned head may
reserve another attempt for the same round and next unconsumed directive
sequence only after the prior lease expires. An expiry audit links the old
intent; authorization and signature bytes are never overwritten or reused.

Authority lifetime does not remove storage limits. Current weight journals are
bounded at 16 GiB of retained evidence and 65,536 attempts. At three 12 MiB
captures per write this permits at most 455 writes before overhead and retries,
about 7.6 days at a 120-block interval with 12-second blocks. Capacity exhaustion
holds without deleting history. Indefinite unattended operation additionally
requires qualified archival or compaction; this release does not claim it.
Archival must retain authenticated certificates, control/admission bindings,
unresolved effects, nonce/finality high-water marks, adopted allocation and
policy holds, and hash-linked durable evidence. An ordinary log rotation cannot
replace native recovery qualification.
