[Documentation](../README.md) / Upgrade an installed validator

# Upgrade an installed validator

- [Successor supervisor upgrade requirements](#successor-supervisor-upgrade)

<a id="successor-supervisor-upgrade"></a>

## Successor supervisor upgrade requirements

Status: implemented upgrade command with synthetic native Linux migration
coverage. This document does not approve production artifacts or a transition.
Keep the installed validator on its current authorized policy until a verified
transition, explicit replacement or revocation. Existing bridge and competition
policies keep their original validity rules during recovery.

<a id="successor-supervisor-upgrade--available-read-only-inspection"></a>

### Available read-only inspection

`competition_upgrade.inspect_successor_upgrade` checks installed configuration,
the exact retained signed directive and high-water binding, extracted release
bytes and an optional staged next directive under unchanged trust. It does not
read a wallet, open worker journals, stop a service or authorize an upgrade.

```sh
umi-competition --policy successor-policy.json inspect-host-upgrade \
  --config /ABSOLUTE/PRIVATE/supervisor.json \
  --accepted-directive accepted-signed-directive.json \
  --expected-hotkey PUBLIC_VALIDATOR_HOTKEY \
  --expected-platform linux/arm64 --service-uid NUMERIC_SERVICE_UID
```

Use the actual platform and service UID. Add
`--staged-directory /ABSOLUTE/PRIVATE/STAGED_RELEASE` for a staged artifact check.
The original signed configuration still determines the installed policy binding;
the command's successor policy does not replace it. The result always reports
`readiness: hold` and lists checks still requiring a real upgrade procedure.
Contract fixtures cover both architectures; they are not Linux sandbox rehearsals.

<a id="successor-supervisor-upgrade--components-and-dedicated-upgrade-command"></a>

### Components and dedicated upgrade command

<a id="successor-supervisor-upgrade--rolling-directive-history"></a>

#### Rolling directive history

After installation, the runtime assembles the complete signed continuation from
its retained journal and the newly verified cursor page. Artifact delivery uses
those local bytes instead of fetching the selected directive's one-hop page.
The host still verifies every predecessor and signature against the original
root-sealed v4 installation anchor. No later directive can replace that anchor.

Network pages remain limited to 64 records and 1 MiB; the feed currently returns
batches of 16. Local continuations use `umi-validator-supervisor-directive-history/1`
when they exceed either network-page limit. They are bounded by 65,536 records
and 64 MiB, with the runtime's configured journal limits enforced separately.
Smaller continuations keep the existing page encoding. HTTP delivery cannot
substitute a different local continuation, including through its cache.

Thirteen focused tests passed on the Studio Linux VM, covering 68-update
catch-up, restart, host verification and HTTP delivery. They took 751.00 seconds.
The separate Linux exchange test exposed an old page parser in the anchor
reader. That reader and the target observer now accept the bounded local history;
their integrated rerun passed four cases in 357.99 seconds. The broader
adapter/materializer regression passed 102 tests in 3246.16 seconds before the
shared-registry change below. Synthetic test authority keys are reused within
each generated chain. No live validator was upgraded.

<a id="successor-supervisor-upgrade--shared-recovery-registry-history"></a>

#### Shared recovery-registry history

New `umi-successor-adapter-run/2` records keep a reference to content-addressed
signed history nodes in the same private SQLite registry. A later run reuses
identical prefixes. Its reference binds the original page schema, cursor,
selected head, count, byte length and hash. Registry loading checks every stored
node's checksum and predecessor links, including unreferenced nodes, and checks
each run's head and cursor without expanding all histories together. Accessing
one run reconstructs its exact original bytes and checks the page binding.
The existing authority and signature verification still applies before use.

Run metadata and new nodes are committed in one transaction. Both count toward
the configured byte budget. A full registry stops retention; it never deletes
evidence to make room. Existing inline `/1` records remain unchanged and readable.
Older binaries cannot read `/2` runs, so do not roll back a supervisor over a
registry written by this version.

Stopped recovery audits each retained run, then retains only authorization
identities between audits. It reconstructs the relevant history again when
reconciling an unsettled transaction. No attempt or recovery source is discarded.

The first shared-storage snapshot passed 11 focused tests in 245.98 seconds,
including lossless 68-record reconstruction, prefix storage growth, legacy
record preservation and atomic insertion failure. The expanded link-validation
suite passed 11 tests in 476.15 seconds, including missing nodes, broken links
with recomputed storage checksums, reference/head mismatches and depth bounds.
The recovery regression passed 45 tests in 1391.01 seconds. The registry still
has its configured byte and record limits. All 18 repository checks passed for
`1448bba`, including the complete Python suites and both Linux architectures.

<a id="successor-supervisor-upgrade--download-history-bindings"></a>

#### Download history bindings

Hosts co-located with a private delivery service can include
`artifacts/successor-delivery.json` in their signed host artifact. The canonical
file uses schema `umi-successor-cohost-delivery/1`, an exact `https://HOST` origin
matching the installed directive URL, a `loopback_port` from 1024 through 65535,
and a `timeout_seconds` bound no greater than 300. The operator consent pins
the host manifest, which pins this root-owned, read-only file. A host without
this signed file retains public HTTPS delivery. Worker inputs and observer
configuration schemas remain unchanged.

Only the selected origin connects to `127.0.0.1` over HTTP. Signed logical URLs,
object sizes, hashes, signatures, continuation checks and redirect rejection
remain enforced. Other origins still require public-address HTTPS. Bind the
private feed to loopback, including the exact selected release archive route;
do not publish protected evidence to a public bucket. This transport choice
does not extend a reward authorization or a round's validity.

When preparing initial history through the same local service, pass
`fetch-initial-successor-history --signed-host-artifact PATH`. The signed
manifest must match the consent, and its optional delivery file must match the
staged host. Omitting the option keeps public HTTPS. Initial-history collection
still does not authorize or perform a validator switch.

When the runtime supplies its retained continuation, delivery stores only
`history-binding.json`, a bounded hash/size/selected-head binding. The full signed
records remain in the runtime journal and recovery registry. Delivery verifies
the supplied history before fetching a package, and the host checks its exact
bytes against the original root-sealed anchor before activation. The binding
file cannot substitute for the history or grant authority.

An existing `history.json` from an earlier version is preserved and checked
against the supplied bytes on every refetch. A changed continuation for an
already cached head, corrupt binding or differing legacy file fails closed.
Older delivery binaries reject the new cache filename; rollback over these
cache entries is unsupported. The focused delivery regression passed five tests
in 264.03 seconds. Package/object capacity limits remain in effect.

<a id="successor-supervisor-upgrade--retiring-redundant-materialized-inputs"></a>

#### Retiring redundant materialized inputs

After stopping the worker and reconciling its transactions, the host retires
cached input trees only when their exact bytes are reconstructable from its
audited recovery registry and a separately retained, verified delivery package.
Current inputs, the original root anchor, signed histories, transaction journals
and delivery packages are preserved. Unstarted, unmatched and partial stages
are preserved too. An equivalent but byte-different history does not authorize
removal of the original copy.

A private `retiring-<directive digest>-<random id>` directory records the cleanup
intent. The host fsyncs that rename before unlinking. Following interruption, it
revalidates the retained source and every surviving cached file before resuming.
Missing recovery inputs, extra or changed files, links, and aliases of current
or recovery inputs stop cleanup. All traversal and accounting limits remain.
Only exact redundant cache copies are removed; they can be reconstructed from
the retained sources. Cleanup does not grant weight or activation authority.

The initial 11-test interruption and repeated-round suite passed on the Studio
in 346.11 seconds. Additional bounded-rescan and inode-alias checks, plus the
surrounding materializer/adapter regression, are running. Full checks must pass
before deployment. Older binaries do not recognize an interrupted `retiring-*`
entry; complete recovery with this version before attempting a rollback.

<a id="successor-supervisor-upgrade--initial-history-after-multiple-feed-pages"></a>

#### Initial history after multiple feed pages

An initial install can now retain the full signed v3-to-v4 history using the same
65,536-record and 64 MiB local-history bounds. The root receipt binds its exact
bytes and size. Both receipt loading and pre-stop checks verify every predecessor
and signature against the original v3 anchor. The current head must still pass
the stopped checkpoint's validity checks. A new history file does not reset an
installed validator's high-water state.

On Linux, collect an inert preparation file into an existing private directory
owned by the invoking user (mode `0700`):

```sh
umi-competition --policy successor-policy.json fetch-initial-successor-history \
  --config /ABSOLUTE/PRIVATE/supervisor.json \
  --accepted-directive /ABSOLUTE/PRIVATE/accepted-signed-directive.json \
  --consent /ABSOLUTE/PRIVATE/operator-consent.json \
  --current-block FINALIZED_PREPARATION_BLOCK \
  --output /ABSOLUTE/PRIVATE/initial-successor-directive-page.json
```

Use the consent and retained directive for that exact installed configuration.
The collector follows bounded HTTPS pages from the configured origin, rejects
changed cursors and bad signatures, and enforces a total timeout and byte/record
budgets. It writes a `0400` file through a no-replace rename. A failed publication
can leave a private `.partial` file for inspection; it never overwrites the
destination. The printed result includes the content hash and size.

The supplied block only bounds preparation. This command has no owned-finality
capability, cannot stop a service, and grants no upgrade or weight authority.
The root upgrade must still verify the sealed inputs, consent, recovery archive,
actual sandbox and fresh stopped-host observations.

Six Linux tests passed in 507.12 seconds, covering receipt sealing and restart,
anchor materialization, and initial pre-stop authentication with both one and 69
signed records. Their ownership/mount ports are synthetic; directory and signed
history operations execute on Linux. Eight collector tests passed in 427.93
seconds, covering five-page catch-up, wrong cursors, forged signatures, missing
pages, budgets, cancellation and wrong legacy binding. Four CLI publication and
total-deadline tests passed in 203.47 seconds. Production initial installation
remains unperformed.

<a id="successor-supervisor-upgrade--worker-and-host-components"></a>

#### Worker and host components

Standing reward execution requires a separate local approval binding the exact
installation receipt, host manifest, validator, series, policy, replay manifest,
chain configuration and C4 handoff plan. `competition_reward_host` reads this
root-owned approval before stopping C4 and binds the transaction journal to the
original supervisor database. Startup must reopen that journal; missing state
cannot become an empty replacement. Capacity increases preserve its identity.

`competition_reward_service` owns proof providers and holds the original C4
handoff through executor shutdown. Transient failures retry with retained state;
an exited finality observer ends the service invocation so boot supervision can
construct a new provider. Startup reconstructs the first activation from complete
retained control history and replays its original reward package. A successor or
revocation in that history does not erase the initial handoff. Historical replay
uses the retained proofs and a fixed target block while catching up; it grants no
current submission authority. The executor checks fresh control before signing.
Cancellation drains owned signing work before releasing the writer locks.

The supervisor CLI accepts an explicit `--standing-config` for the same installed
service and process lock. It reads a canonical root-owned mode-0444
`umi-standing-reward-boot/1` configuration and its separate host approval before
the startup stop. The configuration selects the series, replay and opportunity
manifest, current and legacy chain configurations, eligibility runtime, handoff
plan, private input directories and resource capacities. It supplies no callbacks
or executable plugins. Without this option, the existing C4 path is unchanged.

During initial history/package replay, the original supervisor continues C4
reconciliation. The durable handoff intent stops that continuation before C5
signing, including after restart. A failed old feed does not prevent independent
C5 recovery. Status logs identify bootstrap progress, holds and transaction
progress without enabling HTTP-client logging.

Legacy configurations retain their original bytes and digests. Each selects
host-local `CompetitionChainResources` for tools, chain specification, optional
metadata and a separate cache; all verification hashes still come from the
original configuration. Mutable stores must be disjoint. Do not copy a live
SQLite cache or rewrite old signed inputs to relocate it.

The private delivery directory supplies canonical `packages/<sha>.json`,
`decisions/<sha>.json`, `opportunities/<sha>.json` and `witnesses/<sha>.json`.
Decisions use the signed body's digest; the other files use the complete object's
digest. These files are content, not authority. Native consumers verify the
signatures, original evidence, complete control history and current chain state.
Opportunity replay also requires original interval and endpoint proofs. The
independently populated promotion store must contain the authenticated model
assets and lineage required by package replay.

The installed service automatically discovers the effective activation from
complete finalized control history and collects opportunity evidence for every
designated validator. Each bounded pass retains progress; failures retry without
expiring the cohort. Original evidence must be replayed after restart. A durable
completion identity is retained before publishing its immutable certificate and
witnesses into the delivery directory, so interrupted publication retries the
same content. Collection and discovery retry independently: retained evidence
can finish even when new head discovery or the coordinator is unavailable.
Collection logs report pending coverage, retry causes and completion identities.
The service supervises the collector and drains its work before closing proof
providers. Completion establishes the configured opportunity, not a payment
receipt.

The explicit, disjoint `proof_export_directory` receives original proof objects
and frames automatically during history replay and interval collection. An
interrupted write retries the same bytes before advancing the local cursor or
crediting an interval. Objects are published before their frame. The separate
`proof_import_directory` accepts transferred frames; native readers verify every
proof before populating a recovery journal or crediting time. An imported block
number cannot choose the history target before its chain proof is verified.
Restart requires native replay even when all archive files are already present.

Private R2 replication uses the [copy service and timer templates](../../deploy/standing-reward-replication/)
with [rclone's R2 backend](https://developers.cloudflare.com/r2/examples/rclone/).
Stage a verified rclone executable and replace the template paths and service
account. Each upload/download job has its own root-owned environment file and
private credential file supplied through `LoadCredential`. Use a private bucket,
separate bucket-scoped publisher/read-only receiver credentials, and a distinct
series/producer prefix. Use separate jobs for `reward-proofs/v1/` and
`reward-inputs/v1/`. The latter carries packages, signed decisions, opportunity
certificates and witnesses into the configured `delivery_directory`; it is
separate from proof imports and native journals. Configure filesystem capacity
for all archive and delivery roots
in addition to the native journals; do not point replication at a journal,
wallet, model store or general home directory.

`review_reward_decision` checks the proposed admission or activation against
original native control history and the approved manifest. Admission requires
the reserved empty control history. Activation replays the reward package and
model evidence; successor activation also requires the preceding cohort's
natively verified minimum opportunity. The first activation binds the approved
legacy handoff plan; each validator still drains its own writer at execution.

`RewardDecisionSigner` retains that exact reviewed intent and reserves result
capacity before signing. Partial independent votes and the first valid quorum
survive restart. A retry cannot replace an unfinished decision or sign a fork;
cancellation drains signing and persistence before releasing the process lock.
Original proofs, packages and model assets must remain in their durable stores
so an unsigned intent can be reviewed again at its original block after restart.

The signer's `publish` operation retains quorum before calling
`retain_standing_reward_inputs`. That delivery boundary checks the complete
signed prefix and package identities, retains packages before decisions and
preserves the first valid signature envelope. Interrupted export retries the
original bytes; completed packages need no source fetch.
Model/promotion assets use their separate preservation and native import path.

`StandingControlPublisher` consumes that complete certified prefix and local
delivery readback. It proves the current reserved control slot and every write
since authority issuance, then retains the exact mortal transaction and its
original nonce, control and runtime evidence before transmission. A lost reply
holds the attempt until fresh finalized evidence consumes its nonce or passes
its mortality period. Recovery verifies retained proofs and signed bytes;
it cannot overwrite a different predecessor. `control_finalized` requires the
intended decision in the complete finalized history and does not assert weight
submission or miner payment.

Its recurring loop retries without renewing cohort authority. Initial series
admission still needs timely approval before intake opens; subsequent certified
cohorts have no processing expiry. The local process lock excludes another
publisher using the same state root. Installed host ownership must also prevent
another host or state root from using the reserved hotkey during migration.
`StandingRewardCoordinator` selects the next admitted cohort, performs native
review, retains its decision before requesting signatures, collects independent
votes and waits for separate delivery readback before using the publisher.
Invalid unreviewed offers cannot reserve a sequence. Once reviewed, an unfinished
decision retains its original block and signatures across retries and restarts.
While waiting for votes, the process reuses its completed review; after restart
it reconstructs the review from retained proofs. Certified ancestor decisions
can be delivered after migration without inventing new ancestor votes.

`umi-reward-coordinator check --config /etc/umi/reward-coordinator/NAME.json`
validates the root-owned, mode `0444`, canonical
`umi-reward-coordinator-config/1` document without loading keys or starting a
provider. `run` assembles native proof readers, durable journals and the selected
`coordinator` or `reviewer` role. Configuration binds the approved series, policy,
opportunity terms, handoff and chain context, explicit storage capacities and
the primary RPC plus two fallbacks. Each mutable store must have a distinct
private directory; named hotkey files must remain outside those stores.

The coordinator loads its evaluator key and the reserved control key. Reviewers
load only their evaluator key and independently replay the original proposal
before signing. The proposer retains its vote before exporting
`requests/SERIES/SEQUENCE.json`; peers export signed replies as
`votes/SERIES/SEQUENCE/ACCOUNT.json`. These paths carry approved fixed sequence
slots, authenticated canonical data and no executable callbacks. Missing delivery
retries indefinitely; a restart reuses the original intent and signature.

`CohortSettlement.advance` assembles native settlement from retained execution
evidence and independent evaluator votes. It retains partial votes, derives the
benchmark and service certificates, fixes the promotion attribution once, and
returns native progress for the existing cohort phase controller. Independent
phase signers replay each result. Missing votes wait; missing or
invalid source evidence raises for retry and never creates a scored zero.

After native certification, the owner publishes `CohortRewardPackage` as
`COHORT_SHA256.json` in the configured settlement directory. Packaging uses the
original certification prefix, so later phase advances or an arbitrarily late
restart preserve identical bytes. Each invocation first checks the currently
selected history, including revocation. Run it under the cohort service's
sole-writer lock with independently selected plan, authority, scoring terms,
catalogs and finality.

`CohortSettlementPhases` connects this owner to the recovery controller's durable
progress intent. The intent retains the original result and finalized boundary
before requesting signatures. `SettlementPeerReviewer` verifies the proposer's
signature, independently replays that original proof archive and metadata, then
replays the exact proposed result and transition. Each signer retains its intent,
vote and first complete certificate in its own journal. Late peers reuse that
observation; they do not resample the phase or select a newer promotion head.
Native replay runs in an owned worker thread without sharing the controller's
SQLite connection, and shutdown drains replay and signing before releasing
resources. Recurring startup and authenticated source/vote delivery still need
host wiring; these library ports are not an installed daemon.

The reward coordinator derives the next activation
from that package and the approved manifest. Initial activation names the
approved legacy handoff. A successor waits for the preceding allocation's
retained completion certificate; the native reviewer checks every original
opportunity interval before signing. No separately prepared activation file is
needed. Missing results or proofs remain pending without a cohort deadline.

The coordinator supervises coverage capture alongside decision publication.
Both tasks drain before the provider closes; an unexpected component exit fails
the invocation for supervised restart. Bounded proposal review keeps a fixed
chain target while it catches up. Invalid unreviewed input cannot reserve a
signing sequence. Its separate readback directory must be populated by the
independently authenticated receiver;
distinct local paths alone do not prove remote availability. Precreate input
directories as the service user with mode `0700`, and deliver private regular
files with mode `0600`. The systemd template in
`deploy/standing-reward-coordinator/` owns provider startup, retries and orderly
shutdown. It must select the qualified installed Python environment.

These services remain uninstalled. Recurring settlement startup, native
phase/vote delivery, full later-cohort replay, independent peer and artifact delivery, key provisioning,
migration ownership and combined Linux restart/effect qualification remain
required before deployment. Configuration
validation is not runtime qualification.

The timer retries failed copies indefinitely. `copy --immutable --checksum`
retains existing destination files and refuses conflicting bytes; it does not
delete objects absent from the source. The filters copy only the named proof,
reward-input and signed review-message directories, excluding lock and temporary
files. Transfers can arrive out of order;
missing referenced objects remain pending. Reading R2 uses the receiver's own
credential, so already uploaded proofs remain available when the coordinator is
offline. A copied file or successful transfer grants no reward authority.

These templates are uninstalled. Scoped S3 credentials, complete remote
publication/readback, model/promotion delivery, installed timer/restart
qualification and the full series simulation remain required before deployment.
Local archive checks do not establish remote durability or unattended readiness.

The successor has separate signed v4 directives for `competition_replay` and
`competition_weights`. The first v4 record extends the exact retained v3 record;
it does not reset or reinterpret the existing high-water mark. The weight profile
also requires a separately signed generic authorization and a verified local
recovery checkpoint. These components do not activate a live policy.

The fixed `umi-competition-worker` command accepts only those two mode names.
Replay has no wallet or chain adapter. The weight path obtains owned finalized
observations before loading the named hotkey, persists exact signed transaction
bytes before broadcast, and holds uncertain effects across restart. The CLI's
fixed mount paths are enforced by `competition_container`. Its Podman adapter
checks the signed image identity, runs an inert resource/isolation probe, and
requires the exact container's kernel cgroup to be empty before stop or removal
completes. A completed container is not treated as proof that weights applied.

The isolated arm64 rehearsal has built this image and passed its signed-archive
loading and inert sandbox test with a development key. That test did not run a
settlement worker, use a wallet, or exercise the complete host upgrade.

`competition_host_artifacts` verifies a separately signed replacement host tree
at `/opt/umi-validator-supervisor-hosts/<revision>`. The manifest covers source,
dependencies, the regular copied interpreter and fixed entrypoint. It rejects
unsigned entries, symlinks, writable files and non-root ownership. Every parent
directory must also remain root-owned and not group/world-writable. This verifies
staged bytes only; it does not prove a sandbox rehearsal or authorize a service stop.

The release host tree must include the interpreter's standard library and
required runtime libraries, not only a copied virtual-environment executable.
A system-Python venv can pass on its Ubuntu build host while failing on Debian.
Bind `pyvenv.cfg`, entrypoint shebangs and package import paths to the final
revision directory, and include those bytes in the manifest. Verify imports and
both host CLI entrypoints as an unprivileged user on the supported platforms
before signing. Use a self-contained interpreter and verify it on both Ubuntu
and Debian for each supported architecture. Packaging checks do not authorize
installation or replace the signed host transition.

`competition_host_bundle` stages those bytes without executing them. Its bounded
format is a fixed magic header followed by each signed manifest file in order;
the signed manifest supplies every path, length, hash and mode. The stager
checks the complete tree before a no-replace rename into the fixed revision
directory. An exact existing tree is verified and reused. Failed stages remain
for inspection and consume one of eight staging slots. This component does not
download, build, sign, switch or start a release. The isolated arm64 root-file
rehearsal passed nine filesystem cases and seven metadata checks; amd64 was not
rehearsed there.

`competition_release` verifies the successor OCI bundle under a separate signature
domain. It binds the installed authority, allowed repository/origin, architecture,
source revision, fixed worker profile, state schema and exact archive bytes. It
extracts only into an empty private content-addressed stage; no tar entries are
interpreted and no existing file is replaced. Interrupted staging remains
unverified. The host adapter must enforce cache quotas and verify the loaded image
digest before execution.

The stopped-host lease and recovery checkpoint preserve the old process lock,
directive, journal, claims and supporting bytes. Incomplete or uncertain effects
remain on hold. Source authentication, stopped recovery, local operator consent,
fresh chain checks and actual sandbox execution are separate acceptance checks.
Both-architecture rooted preflight and lifecycle checks pass. The combined
signed initial-migration and interrupted-command rehearsal also passed on
amd64 and arm64 at `aaf7689`, with the fixture boundaries described below.

`competition_upgrade_namespace` prepares the recovery observer's fixed helper
paths in a fresh root process's private Linux mount namespace. It disables mount
propagation before installing any overlay, checks the signed host tree again,
binds its helpers read-only, and binds a separate root-private finality cache.
The stopped observer still verifies consent, signatures and installation identity
before running a helper. Namespace setup alone grants no service-stop or signing
permission. It must run before threads start, once per process; after a partial
setup failure, exit that process. Existing host mount contents are preserved.
Only empty `/opt/umi` and `/var/lib/umi-competition` placeholders may be created
on the host if those directories did not exist. Never use this as a replacement
for the coordinator's separate RootDirectory service adapter. When that adapter
has established a verified private instance view, observer preparation reuses
its mount namespace once rather than discarding the existing aliases.

The wallet-free arm64 test host passed ten real-mount/filesystem cases, including
read-only helpers, writable private cache, invalid sources, partial setup failure,
process death and a source replaced during namespace creation. New placeholder
modes are explicit even under umask 077; existing directory modes stay unchanged.
The first run caught descriptors still referring to mounts in the old namespace.
Setup now reopens them after unsharing and requires the same inode and permissions
before binding them. CI uses dedicated root-owned fixture target paths and keeps
the production ownership checks enabled; the isolated VM tests the actual fixed
paths.

The development `umi-competition-host-upgrade upgrade` command now connects
generic host-namespace preparation, preflight, stop, checkpoint, publication
and start. It takes `--config`, `--unit`, `--controls`, `--host-bundle`,
`--oci-bundle`, `--recovery-root` and `--recovery-limits`; historical bootstrap
contexts can be supplied through `--historical-context`. All artifacts and
authorization controls must already be reviewed and signed. The command does
not fetch or create missing launch inputs.

An applied common-bootstrap journal requires its original signed manifest and
lease in that historical context, even when later bridge writes supersede its
weight row. The stopped observer requests the manifest commitment identified by
the authenticated retained effects and includes its proof in the final owned
chain observation. Missing context, absent or different commitments, and invalid
historical signatures keep recovery held. A snapshot requiring more than one
distinct historical manifest anchor is refused; the current observation format
proves one anchor. Historical authority never becomes current write permission.

Historical parsing can exceed the owned chain proof's freshness interval. The
upgrade therefore parses each locked snapshot before collecting its fresh proof,
once for archive preparation and again for verification. Within that snapshot
scope it reuses the authenticated bridge audit, checking original byte hashes,
file identities and parsed content before reuse. It still checks the current
installed policy, chain row and proof expiry on every acceptance. No historical
signature or current chain authority is inferred from a longer service timeout.

Its pre-stop child runs as the installed non-root account, verifies its complete
signed host tree and stages the signed OCI bundle before exercising the actual
Podman sandbox. The named wallet directory is inaccessible to that child.
Bounded progress records identify control, host, release and sandbox stages.
Wrong host resources, changed controls or a failed rehearsal leave the old
service running. If a failure happens after stop, the command preserves state
and does not restart the old writer.

Interrupted anchor writes are moved intact into root-private `retained-anchors`
beside `activation-source`, with eight retained slots and no overwrites.
Retrying requires fresh stopped-state reconciliation; a partial directory grants
no authorization. Unexpected entries or exhausted retention hold the operation.
Existing published anchors are checked before stopping the service and again
at the stopped acceptance boundary.

The signed-host/OCI preflight and root process-death retention test first passed
on the isolated arm64 VM. Native CI now also covers the combined initial migration
and interrupted-command recovery on both architectures. Production use still
requires reviewed release artifacts, approved activation inputs and a rehearsal
of the deployment-specific runtime and model. Do not use fixture keys, chain
observations or model bytes as those inputs.

The fixed `umi-competition-supervisor` entrypoint now connects the authenticated
root anchor, owned chain observer, bounded HTTPS delivery, atomic input selection
and durable runtime. Startup takes the original process lock before repairing an
interrupted input switch and passes that same descriptor to the runtime. The
runtime journal lives in `successor-v4/runtime`, separately from download and
input caches. It will not reinterpret a journal left at an older unshipped path.

`competition_host_service` renders the exact systemd override. The separate
`competition_host_switch` publisher writes it without replacement and reloads
the still-stopped unit while holding the old lock. Its first write consumes
legacy recovery authority. A failed or partial switch is retained for explicit
recovery; it does not restore the old executable or start either version.
Before any companion bytes are written, the publisher atomically installs the
main unit's drop-in directory containing a complete root-owned switch intent.
The intent binds the original unit, lock inode, config, recovery anchor and
signed replacement host. Legacy recovery rejects that directory even before
systemd has loaded a file. Failed staging directories are retained and bounded.

Systemd can reload an inactive instance when queried, exposing the published
successor command before an explicit `daemon-reload`. At that boundary the
publisher accepts either the unchanged legacy snapshot or the exact published
successor, with no running processes and the original lock still held. It
verifies the published files and repeats the checks after the explicit reload.
Unexpected commands, identities or additional drop-ins remain errors.
The interrupted-publication recovery command applies the same check when it
finishes writing a previously missing drop-in.

After startup, systemd adds execution timestamps and a PID to `ExecStart`.
Startup verification compares the configured executable, arguments and
ignore-errors flag separately from those runtime fields. Unknown fields or
additional commands are rejected. The main PID, cgroup and ownership of the
original process lock are verified independently.

The development command can resume that recorded switch:

```sh
sudo umi-competition-host-upgrade resume-publication \
  --config /etc/umi/validator-supervisor.json \
  --unit umi-validator-supervisor.service
```

This completes exact file publication and reloads the still-stopped unit. It
retains incomplete files without interpreting them, rejects changed controls
or legacy history, and leaves existing v4 journals untouched. It does not
reconstruct a legacy lease or grant checkpoint authority. A missing intent is
a hold, not permission to guess or overwrite the old installation.

`resume-start` performs the same checks, releases the recovery process lock,
then starts only the recorded successor. It verifies the main process's kernel
flock on the original inode. Failed startup invokes the exact cleanup unit;
an error report leaves service state unconfirmed, requiring inspection. Both
commands reject a running service and unsupported filesystem namespaces.
Neither command grants weight authorization or creates missing launch inputs.

Both operator commands retain a separate root-owned, per-unit upgrade mutex
through publication, writer-lock handoff, startup verification and any failed
start cleanup. A concurrent command fails before touching the service. The
empty mutex inode remains after release so another process cannot acquire a
replacement lock. Initial preparation must use this same mutex; the lower-level
planning and capability functions are not independent operator commands.

For the coordinator's exact `umi-validator@0.service` and
`umi-validator@54.service` names, these commands first prepare a process-private
view of that instance's preserved directories. Use the unchanged logical
`--config /etc/umi/validator-supervisor.json` path. Other template instances and
unreviewed RootDirectory layouts are rejected. The view neither stops a service
nor authorizes recovery. Running services still prevent stopped-state recovery.

The generated override retains the selected RootDirectory and slice, maps bind
sources to that instance's physical host directories, and mounts the signed
successor host tree inside the root at its original path. Cleanup uses the inner
`umi-validator` account while systemd retains the host-side instance account.
Its separate failure-cleanup unit has no activation-source bind dependency.
Neither operation changes the shared template or the other validator's roots.

Two real arm64 namespace tests passed with synthetic roots, including original
lock contention and cross-instance isolation. The extended tests prepare the
signed recovery observer in that same view. The CI-style arm64 batch passed
15 namespace and transient-service checks. The later
[native CI run at 8fe8483](https://github.com/Umi-BitSign/umi/actions/runs/34737773586)
passed the actual signed-host/OCI preflight in both roots and the two-instance
systemd/Podman lifecycle test on amd64 and arm64. The lifecycle test uses an
inert host launcher and synthetic capability issuers. It verifies kernel
resource limits, per-instance SIGKILL cleanup and restart, preservation of the
other instance, and teardown container absence. It does not execute the
complete signed initial migration or establish live chain authority.

The [combined migration run at aaf7689](https://github.com/Umi-BitSign/umi/actions/runs/34741778051)
passed on both architectures. It creates two distinct signed bridge installations,
performs the actual wallet-free signed-host/OCI preflight, archives and reconciles
their retained history, publishes their successor anchors and switches the units.
It interrupts the second command immediately after durable intent publication
and resumes in a fresh process. The first instance, both lock inodes, every
bridge-journal byte and both legacy high-water records remain intact.

The chain-observation port is synthetic. The started fixture entrypoint verifies
the real materialized anchor and holds the original process lock, but does not
run the production observation loop or submit weights. The separate lifecycle
test exercises actual Podman execution and cleanup. These results establish
the tested migration behavior; real model execution, independent evaluation and
production activation remain separate gates.

The successor uses a dedicated user systemd manager for rootless Podman.
`umi-competition-supervisor-cleanup` acquires the original lock and stops only
the exact labelled successor container. Noninteractive startup and SIGKILL
cleanup passed on Linux after exposing only the service user's runtime
directory. The same test found that `ExecStopPost`, even with the `+` prefix,
cannot run when an explicit activation bind mount fails on systemd 255.
A separate, mount-free failure-cleanup unit passed that test with automatic
restart enabled; the publisher now seals and verifies both unit files. A cold
user-namespace check then exposed a Podman manager-detection difference. The
adapter now explicitly selects systemd. The actual cold-start service test
passed with this fixed command, kernel resource checks and the cleanup paths.
It used synthetic inputs and an inert launcher. No live deployment is authorized
by these test results.

<a id="successor-supervisor-upgrade--why-an-image-update-is-insufficient"></a>

### Why an image update is insufficient

The installed host enforces these contracts before starting a worker:

- `SupervisorOperatorInputTarget` accepts only the two bootstrap input profiles.
  `SupervisorDirective` rejects operator inputs for `translation_weights`.
- `SupervisorWorkerActivation` repeats that restriction. The durable
  `SupervisorDirectiveState` requires an input digest exactly for bootstrap mode.
- The adapter parses and stages only bootstrap bundles. Other modes receive
  the existing local operator-input directory, not a successor settlement.
- The checked-in worker CLI rejects non-bootstrap execution with
  `worker_mode_unimplemented`. A permitted mode name does not implement its worker.

See [host contracts](../../src/umi/validator_supervisor.py),
[runtime](../../src/umi/validator_supervisor_runtime.py),
[adapter](../../src/umi/validator_supervisor_adapters.py), and
[worker](../../src/umi/validator_supervisor_worker.py).

The [current installer](../../deploy/linux-validator-supervisor/install.sh) refuses
an existing supervisor tree, config, service or loaded unit. It also refuses
`--legacy-unit umi-validator-supervisor.service`. Rerunning it is not a supported
upgrade. Do not delete those paths to bypass its checks.

<a id="successor-supervisor-upgrade--required-implementation"></a>

### Required implementation

Define the signed successor input contract first. Bind the policy, immutable
settlement, authority, activation interval, target chain and release profile.
Retain the settlement's no-weight status; a separately verified authorization
must permit chain submission. Do not relabel successor data as bootstrap input.

Update the host schemas, activation validation, immutable input staging and
fixed worker dispatch together. Preserve parsing and exact hashes of historical
signed directives. If schemas or signing domains change, implement an explicit
versioned transition. Preserve sequence, predecessor digest, finalized-block
high-water and accepted input identity. Never reset state to sequence zero.

Implement the successor worker and its durable transaction recovery separately.
Preserve all bootstrap journals and reconcile uncertain prior submissions before
another write. A directory shared across versions is insufficient unless the
new worker understands the relevant outstanding-effect records.

The common bootstrap profile runs `umi-simple-bootstrap-validator` and retains
`SimpleBootstrapJournal` in `journal.json`, with `service.lock`, under the worker
state root. Its unknown phases cover both manifest anchors and weight calls.
The older explicit-hotkey worker uses `SupervisorWorkerJournal` under
`bootstrap-transactions/<directive>/` and global claims under
`bootstrap-authorizations/`. Migration must account for both layouts.

Both historical recovery paths check authorization at the current block. A
finite common-service policy also exits at its hard sunset before reconciling
its journal. Add a
historical recovery wrapper that validates the original bindings without
granting permission for new work under an expired authorization.

For the common journal, retain its anchor and weight phases and use fresh owned
finalized observations to classify any unfinished attempt. Validate the frozen
submission/mortality assumptions before accepting an absence classification.
For the explicit worker, a `prepared` record with a matching global claim means
an effect was intended. An `effect_intent` can recover to completion only when
the exact retained output artifacts pass the existing validation. Incomplete
inner journals, unmatched claims and ambiguous effects remain on hold; do not
call the old submit function to resolve them.

Require a versioned stopped-state recovery checkpoint before successor chain
activation. Bind the validator hotkey, directive high-water, original journal
and claim hashes, reconciled classifications and owned finalized block/hash.
Keep original bytes available for audit. The checkpoint establishes the prior
state; successor authorization and fresh chain preflight are separate checks.

The legacy host input bundle is capped at 16 MiB. Larger successor replay
artifacts need a separate versioned package with explicit per-object and total
limits. The current adapter also mounts the named hotkey for every worker mode.
A wallet-free rehearsal profile must omit that mount; a no-weight status field
alone does not isolate the wallet.

Add a dedicated operator-invoked host upgrade. It must:

1. Identify the existing installation and stage a reviewed, platform-matched
   host release without modifying the running source tree.
2. Verify signed artifacts, dependencies, configuration compatibility and the
   production sandbox before stopping the current service. Report the exact
   changes to locally delegated profiles or trust.
3. Stop the exact service and confirm its worker and delegated cgroup are empty.
   Take a consistent private backup of the state and configuration at this
   boundary. Do not request the coldkey or recopy wallet material.
4. Switch the verified host release while retaining the selected hotkey,
   service account, filesystem permissions, wallet binding, trust configuration,
   directive history, finality state and worker journals.
5. Verify the new process lock, restart reconciliation and bounded status before
   accepting successor work. Interrupted upgrades must have an explicit recovery
   path and must never start two writers for one hotkey.

Host rollback before any successor acceptance may resume the previous release
only if its directive and policy remain valid, state is compatible, and uncertain
transactions have been reconciled. After a newer directive is accepted or new
chain effects are possible, retain the high-water state and hold for an explicit
recovery transition. Never restore an old state backup to revive an old writer.

<a id="successor-supervisor-upgrade--feed-and-platform-coordination"></a>

### Feed and platform coordination

An unsupported directive on the shared feed makes an older host fail closed.
The current runtime also stops its old worker when it accepts a newer directive,
even if the new directive's activation block is in the future. Publishing a
future directive therefore cannot be used as harmless pre-staging.

Stage artifacts first. Coordinate directive publication with the approved stop
and activation boundary. Any capability-specific feed needs an authenticated,
operator-consented transition that preserves history; changing a channel and
discarding its cursor is not sufficient.

Publish and verify separate `linux/amd64` and `linux/arm64` host artifacts and OCI
images. Both architectures need the same contract and migration tests. UID 0 and
UID 54 remain separate installations with separate hotkeys, state and service
lifecycles. Upgrade and verify one without stopping or changing the other.

<a id="successor-supervisor-upgrade--acceptance-checks"></a>

### Acceptance checks

Rehearse with synthetic keys in isolated Linux installations before live use:

- Existing bootstrap directives and state reload unchanged; successor inputs
  cannot enter through a bootstrap profile or an unapproved local configuration.
- Wrong policy, settlement, authority, architecture, artifact digest or state
  version fails before activation; no arbitrary command or mount is introduced.
- A failed pre-stop check leaves the old service untouched. Failure after stop
  preserves recovery evidence and cannot silently restore an invalid writer.
- Kill or restart at each migration and submission boundary; verify journal
  recovery, monotonic history and at most one writer per hotkey.
- A stale or unsupported feed, insufficient activation headroom, lost permit,
  conflicting evidence or expired policy holds without writing.
- Exercise both supported architectures under the actual systemd/Podman sandbox,
  including resource enforcement and repeated restart cleanup.
- With two isolated installations, transition one and verify the other remains
  healthy with unchanged configuration, hotkey binding and journals.

These checks do not authorize activation. The complete
[successor release gates](../../whitepaper/README.md#10-release-and-activation)
also require real evaluation evidence, finalized-chain preflight and an approved
signed transition. Historical finite bootstrap or policy expiry still applies
if successor work is delayed; this is separate from the current no-sunset
registration bridge.
